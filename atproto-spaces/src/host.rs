//! Server-side Space Authority & Space Host (`SpaceHost<B: SpaceHostBackend>`) for Option A.
//!
//! Implements `atproto#5187` Space-host endpoints:
//! - `getSpaceCredential` (60s single-use delegation `jti` replay cache + policy check + active `jti` tracking)
//! - `listRepos` (RFC 9421 + Space credential verification, ascending `spaceRev` pagination)
//! - `notifyWrite` (monotonic `repoRev` + clock-skew `FutureRev` check, monotonic `spaceRev` assignment)
//! - `removeWriter` (`NotSpaceOwner` check)
//! - `registerNotify` / `unregisterNotify`
//! - `getSpace`
//! - `revoke_user_credentials_and_build_notice` (`notifyCredentialRevoked`) & `build_notify_space_deleted`

use crate::http_signature::verify_credential_request;
use crate::kem::decode_p256_did_key;
use crate::tokens::{
    inspect_untrusted_space_token, mint_space_token, verify_space_token, SpaceKeyResolver,
    SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind, CREDENTIAL_DEFAULT_LIFETIME_SECS,
    DELEGATION_MAX_LIFETIME_SECS, EXPIRY_CLOCK_SKEW_SECS,
};
use crate::{is_valid_did, Result, SpaceUri, SpacesError};
use catbird_atproto::com_atproto::space::get_space::{
    GetSpace, GetSpaceOutput, GetSpaceOutputPolicy,
};
use catbird_atproto::com_atproto::space::get_space_credential::{
    GetSpaceCredential, GetSpaceCredentialOutput,
};
use catbird_atproto::com_atproto::space::list_repos::{ListRepos, ListReposOutput, Repo};
use catbird_atproto::com_atproto::space::notify_credential_revoked::NotifyCredentialRevoked;
use catbird_atproto::com_atproto::space::notify_space_deleted::NotifySpaceDeleted;
use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;
use catbird_atproto::com_atproto::space::register_notify::{RegisterNotify, RegisterNotifyOutput};
use catbird_atproto::com_atproto::space::remove_writer::RemoveWriter;
use catbird_atproto::com_atproto::space::unregister_notify::UnregisterNotify;
use http::HeaderMap;
use jacquard_common::deps::bytes::Bytes;
use jacquard_common::types::aturi::AtSpaceUri;
use jacquard_common::types::string::{Datetime, Did, Tid};
use jacquard_common::types::value::Data;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

pub const NOTIFY_SUBSCRIPTION_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_TID_FUTURE_SKEW_MICROS: u64 = 300 * 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceRecordPolicy {
    Members(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceWriterEntry {
    pub did: String,
    pub repo_rev: String,
    pub space_rev: String,
    pub data: [u8; 32],
}

pub trait SpaceHostBackend {
    fn authorize_credential(
        &self,
        space_uri: &str,
        requester_did: Option<&str>,
        app_id: Option<&str>,
    ) -> Result<()>;

    fn get_space_policy_json(&self, space_uri: &str) -> Result<serde_json::Value>;

    fn list_writers(
        &self,
        space_uri: &str,
        after_space_rev: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SpaceWriterEntry>>;

    fn all_writer_dids(&self, space_uri: &str) -> Result<Vec<String>>;

    fn record_writer_commit(
        &self,
        space_uri: &str,
        writer_did: &str,
        repo_rev: &str,
        data: [u8; 32],
        now_sec: u64,
    ) -> Result<(Option<String>, String)>; // (prev_space_rev, new_space_rev)

    fn remove_writer(&self, space_uri: &str, writer_did: &str) -> Result<()>;

    fn register_subscriber(
        &self,
        space_uri: &str,
        service: &str,
        expires_at_sec: u64,
    ) -> Result<()>;

    fn unregister_subscriber(&self, space_uri: &str, service: &str) -> Result<()>;

    fn list_active_subscribers(&self, space_uri: &str, now_sec: u64) -> Result<Vec<String>>;
}

#[derive(Default)]
pub struct InMemorySpaceHostBackend {
    spaces: RwLock<BTreeMap<String, InMemorySpaceState>>,
    tid_counter: std::sync::atomic::AtomicU64,
}

struct InMemorySpaceState {
    authority_did: String,
    deleted: bool,
    members: BTreeSet<String>,
    writers: BTreeMap<String, SpaceWriterEntry>, // keyed by writer DID
    subscribers: BTreeMap<String, u64>,          // service -> expires_at_sec
    latest_space_rev: Option<String>,
}

impl InMemorySpaceHostBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_space(&self, space_uri: &str, authority_did: &str, policy: SpaceRecordPolicy) {
        let SpaceRecordPolicy::Members(members) = policy;
        let state = InMemorySpaceState {
            authority_did: authority_did.to_string(),
            deleted: false,
            members: members.into_iter().collect(),
            writers: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            latest_space_rev: None,
        };
        self.spaces
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(space_uri.to_string(), state);
    }

    pub fn remove_member(&self, space_uri: &str, member_did: &str) {
        if let Some(sp) = self
            .spaces
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(space_uri)
        {
            sp.members.remove(member_did);
        }
    }

    pub fn mark_deleted(&self, space_uri: &str) {
        if let Some(sp) = self
            .spaces
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(space_uri)
        {
            sp.deleted = true;
        }
    }

    fn next_space_tid(&self, now_sec: u64) -> String {
        let seq = self
            .tid_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let micros = now_sec.saturating_mul(1_000_000).saturating_add(seq);
        encode_tid(micros, 0)
    }
}

impl SpaceHostBackend for InMemorySpaceHostBackend {
    fn authorize_credential(
        &self,
        space_uri: &str,
        requester_did: Option<&str>,
        _app_id: Option<&str>,
    ) -> Result<()> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        let Some(did) = requester_did else {
            return Err(SpacesError::Forbidden("delegation token required".into()));
        };
        if did == sp.authority_did || sp.members.contains(did) {
            Ok(())
        } else {
            Err(SpacesError::Forbidden(format!(
                "{did} is not an active member of {space_uri}"
            )))
        }
    }

    fn get_space_policy_json(&self, space_uri: &str) -> Result<serde_json::Value> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        Ok(serde_json::json!({
            "$type": "blue.catbird.labyrinth.conversationPolicy",
            "authority": sp.authority_did,
            "members": sp.members.iter().cloned().collect::<Vec<_>>(),
        }))
    }

    fn list_writers(
        &self,
        space_uri: &str,
        after_space_rev: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SpaceWriterEntry>> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        let mut entries: Vec<SpaceWriterEntry> = sp
            .writers
            .values()
            .filter(|w| {
                after_space_rev
                    .map(|cursor| w.space_rev.as_str() > cursor)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.space_rev.cmp(&b.space_rev));
        entries.truncate(limit);
        Ok(entries)
    }

    fn all_writer_dids(&self, space_uri: &str) -> Result<Vec<String>> {
        let writers = self.list_writers(space_uri, None, usize::MAX)?;
        Ok(writers.into_iter().map(|w| w.did).collect())
    }

    fn record_writer_commit(
        &self,
        space_uri: &str,
        writer_did: &str,
        repo_rev: &str,
        data: [u8; 32],
        now_sec: u64,
    ) -> Result<(Option<String>, String)> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        if writer_did != sp.authority_did && !sp.members.contains(writer_did) {
            return Err(SpacesError::Forbidden(format!(
                "{writer_did} is not authorized to write in {space_uri}"
            )));
        }
        if let Some(existing) = sp.writers.get(writer_did) {
            if repo_rev <= existing.repo_rev.as_str() {
                return Err(SpacesError::FutureRev(format!(
                    "non-monotonic repoRev {repo_rev} <= {}",
                    existing.repo_rev
                )));
            }
        }
        let prev_space_rev = sp.latest_space_rev.clone();
        let new_space_rev = self.next_space_tid(now_sec);
        sp.latest_space_rev = Some(new_space_rev.clone());
        sp.writers.insert(
            writer_did.to_string(),
            SpaceWriterEntry {
                did: writer_did.to_string(),
                repo_rev: repo_rev.to_string(),
                space_rev: new_space_rev.clone(),
                data,
            },
        );
        Ok((prev_space_rev, new_space_rev))
    }

    fn remove_writer(&self, space_uri: &str, writer_did: &str) -> Result<()> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        sp.writers.remove(writer_did);
        Ok(())
    }

    fn register_subscriber(
        &self,
        space_uri: &str,
        service: &str,
        expires_at_sec: u64,
    ) -> Result<()> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        sp.subscribers.insert(service.to_string(), expires_at_sec);
        Ok(())
    }

    fn unregister_subscriber(&self, space_uri: &str, service: &str) -> Result<()> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        sp.subscribers.remove(service);
        Ok(())
    }

    fn list_active_subscribers(&self, space_uri: &str, now_sec: u64) -> Result<Vec<String>> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        Ok(sp
            .subscribers
            .iter()
            .filter(|(_, &exp)| exp > now_sec)
            .map(|(svc, _)| svc.clone())
            .collect())
    }
}

#[async_trait::async_trait(?Send)]
impl<K: SpaceKeyResolver + ?Sized> SpaceKeyResolver for Rc<K> {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        force_refresh: bool,
    ) -> Result<crate::tokens::SpaceVerifyingKey> {
        (**self)
            .resolve_atproto_key(did_or_issuer, force_refresh)
            .await
    }
}

#[async_trait::async_trait(?Send)]
impl<K: SpaceKeyResolver + ?Sized> SpaceKeyResolver for Arc<K> {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        force_refresh: bool,
    ) -> Result<crate::tokens::SpaceVerifyingKey> {
        (**self)
            .resolve_atproto_key(did_or_issuer, force_refresh)
            .await
    }
}

#[async_trait::async_trait(?Send)]
impl<D: crate::did_resolver::SpaceDidResolver + ?Sized> crate::did_resolver::SpaceDidResolver
    for Rc<D>
{
    async fn resolve_did(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<crate::did_resolver::DidDocument> {
        (**self).resolve_did(did, force_refresh).await
    }
}

#[async_trait::async_trait(?Send)]
impl<D: crate::did_resolver::SpaceDidResolver + ?Sized> crate::did_resolver::SpaceDidResolver
    for Arc<D>
{
    async fn resolve_did(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<crate::did_resolver::DidDocument> {
        (**self).resolve_did(did, force_refresh).await
    }
}

#[derive(Debug, Clone)]
struct IssuedCredentialRecord {
    user_did: String,
    jti: String,
    exp: u64,
}

pub struct SpaceHost<
    B: SpaceHostBackend,
    K: SpaceKeyResolver = crate::did_resolver::StaticDidResolver,
> {
    authority_did: String,
    authority_signing_key: SpaceSigningKey,
    key_resolver: K,
    backend: B,
    delegation_replay_cache: RwLock<BTreeMap<String, u64>>, // (issuer + jti) -> exp_with_skew
    issued_credentials: RwLock<BTreeMap<String, Vec<IssuedCredentialRecord>>>, // space_uri -> active creds
    revoked_jtis: RwLock<BTreeMap<String, u64>>,                               // jti -> exp
}

impl<B: SpaceHostBackend, K: SpaceKeyResolver> SpaceHost<B, K> {
    pub fn new(
        authority_did: String,
        authority_signing_key: SpaceSigningKey,
        key_resolver: K,
        backend: B,
    ) -> Self {
        Self {
            authority_did,
            authority_signing_key,
            key_resolver,
            backend,
            delegation_replay_cache: RwLock::new(BTreeMap::new()),
            issued_credentials: RwLock::new(BTreeMap::new()),
            revoked_jtis: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// `com.atproto.space.getSpaceCredential`:
    /// Verifies single-use 60s delegation JWT + replay cache, optional client attestation,
    /// policy authorization, and mints a fresh `atproto-space-credential+jwt`.
    pub async fn handle_get_space_credential(
        &self,
        req: GetSpaceCredential,
        now_sec: u64,
    ) -> Result<GetSpaceCredentialOutput> {
        let space_str = req.space.as_str();
        let space = SpaceUri::parse(space_str)?;
        if space.authority != self.authority_did {
            return Err(SpacesError::SpaceNotFound(space_str.to_string()));
        }
        decode_p256_did_key(req.credential_kid.as_str())?;

        let requester_did = if let Some(delegation_jwt) = &req.delegation_token {
            let claims = verify_space_token(
                SpaceTokenKind::Delegation,
                delegation_jwt.as_str(),
                &self.key_resolver,
                now_sec,
            )
            .await?;
            if claims.sub != space_str {
                return Err(SpacesError::InvalidDelegationToken(
                    "delegation sub does not match requested space".into(),
                ));
            }
            let expected_aud = format!("{}#atproto_pds", self.authority_did);
            if claims.aud.as_deref() != Some(expected_aud.as_str()) {
                return Err(SpacesError::InvalidDelegationToken(
                    "delegation aud does not match Space authority".into(),
                ));
            }

            // Enforce single-use delegation `jti` replay cache!
            let replay_key = format!("{}::{}", claims.iss, claims.jti);
            let replay_expiry = claims
                .exp
                .saturating_add(DELEGATION_MAX_LIFETIME_SECS + EXPIRY_CLOCK_SKEW_SECS);
            {
                let mut cache = self
                    .delegation_replay_cache
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                cache.retain(|_, &mut exp| exp > now_sec);
                if cache.contains_key(&replay_key) {
                    return Err(SpacesError::InvalidDelegationToken(
                        "replayed delegation jti".into(),
                    ));
                }
                cache.insert(replay_key, replay_expiry);
            }
            Some(claims.iss)
        } else {
            None
        };

        let app_id = if let Some(att_jwt) = &req.client_attestation {
            let att_claims = verify_space_token(
                SpaceTokenKind::ClientAttestation,
                att_jwt.as_str(),
                &self.key_resolver,
                now_sec,
            )
            .await?;
            Some(att_claims.iss)
        } else {
            None
        };

        self.backend.authorize_credential(
            space_str,
            requester_did.as_deref(),
            app_id.as_deref(),
        )?;

        let jti = Uuid::new_v4().to_string();
        let exp = now_sec + CREDENTIAL_DEFAULT_LIFETIME_SECS;
        let cred_claims = SpaceTokenClaims {
            iss: self.authority_did.clone(),
            sub: space_str.to_string(),
            aud: None,
            iat: now_sec,
            exp,
            jti: jti.clone(),
            cnf_kid: Some(req.credential_kid.as_str().to_string()),
        };
        let jwt = mint_space_token(
            SpaceTokenKind::Credential,
            &self.authority_signing_key,
            &cred_claims,
        )?;

        if let Some(user_did) = requester_did {
            let mut issued = self
                .issued_credentials
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let list = issued.entry(space_str.to_string()).or_default();
            list.retain(|r| r.exp > now_sec);
            list.push(IssuedCredentialRecord { user_did, jti, exp });
        }

        Ok(GetSpaceCredentialOutput {
            credential: jwt.into(),
            extra_data: None,
        })
    }

    /// Verify RFC 9421 + `atproto-space-credential+jwt` presentation on a Space-host or Repo-host route.
    pub async fn verify_presentation(
        &self,
        headers: &HeaderMap,
        expected_space: &str,
        expected_audience_did: &str,
        now_sec: u64,
    ) -> Result<SpaceTokenClaims> {
        let auth_hdr = headers
            .get(http::header::AUTHORIZATION)
            .ok_or_else(|| SpacesError::BadSpaceSignature("missing Authorization".into()))?
            .to_str()
            .map_err(|_| SpacesError::BadSpaceSignature("non-ASCII Authorization".into()))?
            .trim_matches([' ', '\t']);
        let prefix = "atproto-space-credential ";
        if auth_hdr.len() <= prefix.len() || !auth_hdr[..prefix.len()].eq_ignore_ascii_case(prefix)
        {
            return Err(SpacesError::BadSpaceSignature(
                "Authorization must start with Atproto-Space-Credential".into(),
            ));
        }
        let raw_jwt = auth_hdr[prefix.len()..].trim_matches([' ', '\t']);
        let (_, untrusted_claims) =
            inspect_untrusted_space_token(SpaceTokenKind::Credential, raw_jwt, now_sec)?;
        let Some(cnf_kid) = untrusted_claims.cnf_kid.as_deref() else {
            return Err(SpacesError::InvalidSpaceCredential(
                "missing cnf.kid".into(),
            ));
        };

        let verified_sig = verify_credential_request(headers, cnf_kid, now_sec)?;
        if verified_sig.audience_did != expected_audience_did {
            return Err(SpacesError::BadSpaceSignature(format!(
                "Atproto-Space-Audience {:?} != expected {:?}",
                verified_sig.audience_did, expected_audience_did
            )));
        }

        let claims = verify_space_token(
            SpaceTokenKind::Credential,
            &verified_sig.credential_jwt,
            &self.key_resolver,
            now_sec,
        )
        .await?;
        if claims.sub != expected_space {
            return Err(SpacesError::InvalidSpaceCredential(
                "credential sub does not match target space".into(),
            ));
        }
        if self
            .revoked_jtis
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&claims.jti)
            .is_some_and(|&exp| exp > now_sec)
        {
            return Err(SpacesError::CredentialRevoked);
        }
        Ok(claims)
    }

    /// `com.atproto.space.listRepos`: returns writers ordered by ascending `spaceRev`.
    pub async fn handle_list_repos(
        &self,
        headers: &HeaderMap,
        req: ListRepos,
        now_sec: u64,
    ) -> Result<ListReposOutput> {
        let space_str = req.space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;

        let limit = req.limit.unwrap_or(100).clamp(1, 1000) as usize;
        let writers =
            self.backend
                .list_writers(space_str, req.cursor.as_ref().map(|c| c.as_str()), limit)?;
        let cursor = writers
            .last()
            .map(|w| jacquard_common::deps::smol_str::SmolStr::from(w.space_rev.as_str()));
        let repos = writers
            .into_iter()
            .map(|w| -> Result<Repo> {
                let did_str = w.did.clone();
                Ok(Repo {
                    did: Did::new(jacquard_common::deps::smol_str::SmolStr::from(w.did))
                        .map_err(|_| SpacesError::InvalidDid(did_str))?,
                    repo_rev: Tid::new(&w.repo_rev)
                        .map_err(|_| SpacesError::FutureRev(w.repo_rev.clone()))?,
                    space_rev: Tid::new(&w.space_rev)
                        .map_err(|_| SpacesError::FutureRev(w.space_rev.clone()))?,
                    data: Bytes::copy_from_slice(&w.data),
                    extra_data: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ListReposOutput {
            cursor,
            repos,
            extra_data: None,
        })
    }

    /// `com.atproto.space.notifyWrite`: validates caller == `req.repo`, checks TID skew + monotonicity,
    /// records writer commit, and returns `(forwarded_notify_write, active_subscriber_services)`.
    pub async fn handle_notify_write(
        &self,
        authenticated_caller_did: &str,
        req: NotifyWrite,
        now_sec: u64,
    ) -> Result<(NotifyWrite, Vec<String>)> {
        let space_str = req.space.as_str();
        let space = SpaceUri::parse(space_str)?;
        if space.authority != self.authority_did {
            return Err(SpacesError::SpaceNotFound(space_str.to_string()));
        }
        if authenticated_caller_did != req.repo.as_str() {
            return Err(SpacesError::Forbidden(
                "notifyWrite caller DID must match req.repo".into(),
            ));
        }
        let data: [u8; 32] = req
            .data
            .as_ref()
            .try_into()
            .map_err(|_| SpacesError::Sync("notifyWrite data must be 32 bytes".into()))?;

        if let Some(tid_micros) = decode_tid_micros(req.repo_rev.as_str()) {
            let max_allowed = now_sec
                .saturating_mul(1_000_000)
                .saturating_add(MAX_TID_FUTURE_SKEW_MICROS);
            if now_sec > 0 && tid_micros > max_allowed {
                return Err(SpacesError::FutureRev(format!(
                    "repoRev {} exceeds permitted clock skew",
                    req.repo_rev.as_str()
                )));
            }
        }

        let (prev_space_rev, new_space_rev) = self.backend.record_writer_commit(
            space_str,
            req.repo.as_str(),
            req.repo_rev.as_str(),
            data,
            now_sec,
        )?;
        let subscribers = self.backend.list_active_subscribers(space_str, now_sec)?;

        let forwarded = NotifyWrite {
            space: req.space,
            repo: req.repo,
            repo_rev: req.repo_rev,
            data: Bytes::copy_from_slice(&data),
            prev_space_rev: prev_space_rev.and_then(|s| Tid::new(&s).ok()),
            space_rev: Tid::new(&new_space_rev).ok(),
            extra_data: None,
        };
        Ok((forwarded, subscribers))
    }

    /// `com.atproto.space.removeWriter`: restricts removal to the Space authority / owner.
    pub async fn handle_remove_writer(
        &self,
        authenticated_caller_did: &str,
        req: RemoveWriter,
    ) -> Result<()> {
        let space_str = req.space.as_str();
        let space = SpaceUri::parse(space_str)?;
        if authenticated_caller_did != space.authority {
            return Err(SpacesError::Forbidden("NotSpaceOwner".into()));
        }
        self.backend.remove_writer(space_str, req.did.as_str())
    }

    /// `com.atproto.space.registerNotify`: registers a syncer notification target.
    pub async fn handle_register_notify(
        &self,
        headers: &HeaderMap,
        req: RegisterNotify,
        now_sec: u64,
    ) -> Result<RegisterNotifyOutput> {
        let space_str = req.space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;
        let svc_did = req.service.as_str().split('#').next().unwrap_or_default();
        if !is_valid_did(svc_did) {
            return Err(SpacesError::InvalidDid(req.service.as_str().to_string()));
        }
        let exp = now_sec.saturating_add(NOTIFY_SUBSCRIPTION_TTL_SECS);
        self.backend
            .register_subscriber(space_str, req.service.as_str(), exp)?;
        let iso = format_unix_iso8601(exp);
        let expires_at: Datetime = iso
            .parse()
            .map_err(|e| SpacesError::Sync(format!("invalid expiresAt datetime: {e}")))?;
        Ok(RegisterNotifyOutput {
            expires_at,
            extra_data: None,
        })
    }

    /// `com.atproto.space.unregisterNotify`: removes a syncer notification target.
    pub async fn handle_unregister_notify(
        &self,
        headers: &HeaderMap,
        req: UnregisterNotify,
        now_sec: u64,
    ) -> Result<()> {
        let space_str = req.space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;
        self.backend
            .unregister_subscriber(space_str, req.service.as_str())
    }

    /// `com.atproto.space.getSpace`: returns the Space URI and open-union policy document.
    pub async fn handle_get_space(
        &self,
        headers: &HeaderMap,
        req: GetSpace,
        now_sec: u64,
    ) -> Result<GetSpaceOutput> {
        let space_str = req.space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;
        let policy_json = self.backend.get_space_policy_json(space_str)?;
        let policy: GetSpaceOutputPolicy = serde_json::from_value(policy_json)
            .map_err(|e| SpacesError::Sync(format!("decode space policy union: {e}")))?;
        let _ = Data::<jacquard_common::DefaultStr>::Null;
        Ok(GetSpaceOutput {
            uri: req.space,
            policy,
            extra_data: None,
        })
    }

    /// Revoke all active Space credentials issued to `revoked_user_did` in `space_uri`,
    /// returning `(NotifyCredentialRevoked, target_writer_dids)`.
    pub fn revoke_user_credentials_and_build_notice(
        &self,
        space_uri: &str,
        revoked_user_did: &str,
        now_sec: u64,
    ) -> Result<(NotifyCredentialRevoked, Vec<String>)> {
        let writer_targets = self.backend.all_writer_dids(space_uri)?;
        let mut revoked_jtis = Vec::new();
        {
            let mut issued = self
                .issued_credentials
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(list) = issued.get_mut(space_uri) {
                let mut rev_map = self.revoked_jtis.write().unwrap_or_else(|e| e.into_inner());
                rev_map.retain(|_, &mut exp| exp > now_sec);
                list.retain(|rec| {
                    if rec.exp <= now_sec {
                        return false;
                    }
                    if rec.user_did == revoked_user_did {
                        rev_map.insert(rec.jti.clone(), rec.exp);
                        revoked_jtis.push(rec.jti.clone());
                        return false;
                    }
                    true
                });
            }
        }

        let notice = NotifyCredentialRevoked {
            space: AtSpaceUri::new(jacquard_common::deps::smol_str::SmolStr::from(space_uri))
                .map_err(|_| SpacesError::InvalidSpaceUri(space_uri.to_string()))?,
            credentials: revoked_jtis
                .into_iter()
                .map(jacquard_common::deps::smol_str::SmolStr::from)
                .collect(),
            extra_data: None,
        };
        Ok((notice, writer_targets))
    }

    /// Build `NotifySpaceDeleted` along with `(writer_dids, subscriber_services)` to fan out to.
    pub fn build_notify_space_deleted(
        &self,
        space_uri: &str,
        now_sec: u64,
    ) -> Result<(NotifySpaceDeleted, Vec<String>, Vec<String>)> {
        let writers = self.backend.all_writer_dids(space_uri)?;
        let subscribers = self.backend.list_active_subscribers(space_uri, now_sec)?;
        let notice = NotifySpaceDeleted {
            space: AtSpaceUri::new(jacquard_common::deps::smol_str::SmolStr::from(space_uri))
                .map_err(|_| SpacesError::InvalidSpaceUri(space_uri.to_string()))?,
            extra_data: None,
        };
        Ok((notice, writers, subscribers))
    }
}

const TID_CHARS: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

fn encode_tid(timestamp_micros: u64, clock_id: u16) -> String {
    let val = ((timestamp_micros & 0x1fff_ffff_ffff_ffff) << 10) | u64::from(clock_id & 0x3ff);
    let mut out = [b'2'; 13];
    for i in (0..13).rev() {
        let idx = ((val >> ((12 - i) * 5)) & 0x1f) as usize;
        out[i] = TID_CHARS[idx];
    }
    String::from_utf8(out.to_vec()).expect("ASCII TID")
}

fn decode_tid_micros(tid: &str) -> Option<u64> {
    if tid.len() != 13 {
        return None;
    }
    let mut val = 0u64;
    for b in tid.bytes() {
        let digit = match b {
            b'2'..=b'7' => u64::from(b - b'2'),
            b'a'..=b'z' => u64::from(b - b'a' + 6),
            _ => return None,
        };
        val = (val << 5) | digit;
    }
    Some(val >> 10)
}

fn format_unix_iso8601(secs: u64) -> String {
    // Civil-from-days (Howard Hinnant algorithm) — zero chrono dependency needed.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}
