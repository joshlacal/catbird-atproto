//! Server-side Space Authority & Space Host (`SpaceHost<B: SpaceHostBackend>`) for the November 12 Spaces alpha.
//!
//! Implements `atproto#5187` November 12 Space-host endpoints:
//! - `authorizeSpaceSync` (60s single-use delegation `jti` replay cache + policy check + inline `notify` registration + `spaceRev` return)
//! - `confirmRegistration` request/response challenge helper
//! - `listWriters` (RFC 9421 + Space credential verification, `#repoWrite` and `#repoRemoved` ordered by ascending `spaceRev`)
//! - `notifyRepoUpdate` -> `notifySpaceUpdate` (`#repoWrite` and `#registrationExpired` fanout)
//! - `removeWriter` (`req.repo`, `#repoRemoved` sequencing + fanout)
//! - `getSpace` (`space` + open-union `policy`)
//! - `revoke_user_credentials_and_build_notice` (`notifyCredentialsRevoked`) & `build_notify_space_deleted` (`notifySpaceUpdate#spaceDeleted`)

use crate::http_signature::verify_credential_request;
use crate::kem::decode_p256_did_key;
use crate::signature_replay::{
    check_presentation_replay, InMemorySignatureReplayCache, SignatureReplayStore,
};
use crate::tokens::{
    inspect_untrusted_space_token, mint_space_token, verify_space_token, SpaceKeyResolver,
    SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind, CREDENTIAL_DEFAULT_LIFETIME_SECS,
    DELEGATION_MAX_LIFETIME_SECS, EXPIRY_CLOCK_SKEW_SECS,
};
use crate::{Result, SpaceUri, SpacesError};
use catbird_atproto::com_atproto::space::authorize_space_sync::{
    AuthorizeSpaceSync, AuthorizeSpaceSyncOutput,
};
use catbird_atproto::com_atproto::space::confirm_registration::{
    ConfirmRegistration, ConfirmRegistrationOutput,
};
use catbird_atproto::com_atproto::space::get_space::{
    GetSpace, GetSpaceOutput, GetSpaceOutputPolicy,
};
use catbird_atproto::com_atproto::space::list_writers::{
    ListWriters, ListWritersOutput, ListWritersOutputReposItem,
};
use catbird_atproto::com_atproto::space::notify_credentials_revoked::NotifyCredentialsRevoked;
use catbird_atproto::com_atproto::space::notify_repo_update::NotifyRepoUpdate;
use catbird_atproto::com_atproto::space::notify_space_update::{
    NotifySpaceUpdate, NotifySpaceUpdateUpdate, RegistrationExpired, SpaceDeleted,
};
use catbird_atproto::com_atproto::space::remove_writer::RemoveWriter;
use catbird_atproto::com_atproto::space::{RepoRemoved, RepoWrite};
use http::HeaderMap;
use jacquard_common::deps::bytes::Bytes;
use jacquard_common::deps::smol_str::SmolStr;
use jacquard_common::types::aturi::AtSpaceUri;
use jacquard_common::types::string::{Did, Tid};
use jacquard_common::types::value::Data;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;
use uuid::Uuid;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceWriterEvent {
    Write(SpaceWriterEntry),
    Removed { did: String, space_rev: String },
}

impl SpaceWriterEvent {
    pub fn space_rev(&self) -> &str {
        match self {
            Self::Write(w) => &w.space_rev,
            Self::Removed { space_rev, .. } => space_rev,
        }
    }

    pub fn did(&self) -> &str {
        match self {
            Self::Write(w) => &w.did,
            Self::Removed { did, .. } => did,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceSubscriberEntry {
    pub endpoint: String,
    pub token: String,
    pub expires_at_sec: u64,
    pub notified_expired: bool,
}

pub trait SpaceHostBackend {
    fn authorize_credential(
        &self,
        space_uri: &str,
        requester_did: Option<&str>,
        app_id: Option<&str>,
    ) -> Result<()>;

    fn get_space_policy_json(&self, space_uri: &str) -> Result<serde_json::Value>;

    fn current_space_rev(&self, space_uri: &str) -> Result<Option<String>>;

    fn list_writers(
        &self,
        space_uri: &str,
        after_space_rev: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SpaceWriterEvent>>;

    fn all_writer_dids(&self, space_uri: &str) -> Result<Vec<String>>;

    fn record_writer_commit(
        &self,
        space_uri: &str,
        writer_did: &str,
        repo_rev: &str,
        data: [u8; 32],
        now_sec: u64,
    ) -> Result<(Option<String>, String)>; // (prev_space_rev, new_space_rev)

    fn remove_writer(
        &self,
        space_uri: &str,
        writer_did: &str,
        now_sec: u64,
    ) -> Result<(Option<String>, String)>; // (prev_space_rev, new_space_rev)

    fn register_subscriber(
        &self,
        space_uri: &str,
        endpoint: &str,
        token: &str,
        expires_at_sec: u64,
    ) -> Result<()>;

    fn collect_subscribers_for_update(
        &self,
        space_uri: &str,
        now_sec: u64,
    ) -> Result<SubscriberUpdateTargets>;

    fn list_all_subscribers(&self, space_uri: &str) -> Result<Vec<SubscriberTarget>>;
}

/// `(endpoint, token)` target for Space update delivery.
pub type SubscriberTarget = (String, String);
/// `(active_subscribers, newly_expired_subscribers)` returned by `collect_subscribers_for_update`.
pub type SubscriberUpdateTargets = (Vec<SubscriberTarget>, Vec<SubscriberTarget>);
/// `(writer_dids, subscriber_notices)` returned by `build_notify_space_deleted`.
pub type SpaceDeletedFanout = (Vec<String>, Vec<(String, NotifySpaceUpdate)>);

#[derive(Default)]
pub struct InMemorySpaceHostBackend {
    spaces: RwLock<BTreeMap<String, InMemorySpaceState>>,
    tid_counter: std::sync::atomic::AtomicU64,
}

struct InMemorySpaceState {
    authority_did: String,
    deleted: bool,
    members: BTreeSet<String>,
    writers: BTreeMap<String, SpaceWriterEvent>, // keyed by writer DID
    subscribers: BTreeMap<(String, String), SpaceSubscriberEntry>, // keyed by (endpoint, token)
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
            "$type": "com.atproto.memberspace.policy",
        }))
    }

    fn current_space_rev(&self, space_uri: &str) -> Result<Option<String>> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        Ok(sp.latest_space_rev.clone())
    }

    fn list_writers(
        &self,
        space_uri: &str,
        after_space_rev: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SpaceWriterEvent>> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        if sp.deleted {
            return Err(SpacesError::SpaceDeleted(space_uri.to_string()));
        }
        let mut entries: Vec<SpaceWriterEvent> = sp
            .writers
            .values()
            .filter(|w| {
                after_space_rev
                    .map(|cursor| w.space_rev() > cursor)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.space_rev().cmp(b.space_rev()));
        entries.truncate(limit);
        Ok(entries)
    }

    fn all_writer_dids(&self, space_uri: &str) -> Result<Vec<String>> {
        let writers = self.list_writers(space_uri, None, usize::MAX)?;
        Ok(writers
            .into_iter()
            .filter_map(|w| match w {
                SpaceWriterEvent::Write(entry) => Some(entry.did),
                SpaceWriterEvent::Removed { .. } => None,
            })
            .collect())
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
        if let Some(SpaceWriterEvent::Write(existing)) = sp.writers.get(writer_did) {
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
            SpaceWriterEvent::Write(SpaceWriterEntry {
                did: writer_did.to_string(),
                repo_rev: repo_rev.to_string(),
                space_rev: new_space_rev.clone(),
                data,
            }),
        );
        Ok((prev_space_rev, new_space_rev))
    }

    fn remove_writer(
        &self,
        space_uri: &str,
        writer_did: &str,
        now_sec: u64,
    ) -> Result<(Option<String>, String)> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        let prev_space_rev = sp.latest_space_rev.clone();
        let new_space_rev = self.next_space_tid(now_sec);
        sp.latest_space_rev = Some(new_space_rev.clone());
        sp.writers.insert(
            writer_did.to_string(),
            SpaceWriterEvent::Removed {
                did: writer_did.to_string(),
                space_rev: new_space_rev.clone(),
            },
        );
        Ok((prev_space_rev, new_space_rev))
    }

    fn register_subscriber(
        &self,
        space_uri: &str,
        endpoint: &str,
        token: &str,
        expires_at_sec: u64,
    ) -> Result<()> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        sp.subscribers.insert(
            (endpoint.to_string(), token.to_string()),
            SpaceSubscriberEntry {
                endpoint: endpoint.to_string(),
                token: token.to_string(),
                expires_at_sec,
                notified_expired: false,
            },
        );
        Ok(())
    }

    fn collect_subscribers_for_update(
        &self,
        space_uri: &str,
        now_sec: u64,
    ) -> Result<SubscriberUpdateTargets> {
        let mut guard = self.spaces.write().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get_mut(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        let mut active = Vec::new();
        let mut newly_expired = Vec::new();
        for sub in sp.subscribers.values_mut() {
            if sub.expires_at_sec > now_sec {
                active.push((sub.endpoint.clone(), sub.token.clone()));
            } else if !sub.notified_expired {
                sub.notified_expired = true;
                newly_expired.push((sub.endpoint.clone(), sub.token.clone()));
            }
        }
        Ok((active, newly_expired))
    }

    fn list_all_subscribers(&self, space_uri: &str) -> Result<Vec<(String, String)>> {
        let guard = self.spaces.read().unwrap_or_else(|e| e.into_inner());
        let Some(sp) = guard.get(space_uri) else {
            return Err(SpacesError::SpaceNotFound(space_uri.to_string()));
        };
        Ok(sp
            .subscribers
            .values()
            .map(|s| (s.endpoint.clone(), s.token.clone()))
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
    signature_replay_store: Arc<dyn SignatureReplayStore + Send + Sync>,
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
            signature_replay_store: Arc::new(InMemorySignatureReplayCache::new()),
        }
    }

    /// Replace the default per-process [`InMemorySignatureReplayCache`] with a
    /// store shared between host processes. Every host that accepts
    /// presentations for the same Spaces should use the same store.
    pub fn with_signature_replay_store(
        mut self,
        store: Arc<dyn SignatureReplayStore + Send + Sync>,
    ) -> Self {
        self.signature_replay_store = store;
        self
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Build a `com.atproto.space.confirmRegistration` challenge request for an unconfirmed `notify` endpoint.
    pub fn build_confirm_registration(
        space_uri: &str,
        token: &str,
        challenge: &str,
    ) -> Result<ConfirmRegistration> {
        let space = SpaceUri::parse_hedged(space_uri)?;
        Ok(ConfirmRegistration {
            space: AtSpaceUri::new(SmolStr::from(space.as_str()))
                .map_err(|_| SpacesError::InvalidSpaceUri(space_uri.to_string()))?,
            token: token.into(),
            challenge: challenge.into(),
            extra_data: None,
        })
    }

    /// Verify a `com.atproto.space.confirmRegistration` challenge echo in constant time.
    pub fn verify_confirm_registration_response(
        expected_challenge: &str,
        resp: &ConfirmRegistrationOutput,
    ) -> Result<()> {
        let actual = resp.challenge.as_str().as_bytes();
        let expected = expected_challenge.as_bytes();
        if actual.len() == expected.len() && bool::from(actual.ct_eq(expected)) {
            Ok(())
        } else {
            Err(SpacesError::RegistrationNotConfirmed(
                "confirmRegistration challenge mismatch".into(),
            ))
        }
    }

    /// `com.atproto.space.authorizeSpaceSync`:
    /// Verifies single-use 60s delegation JWT + replay cache, optional client attestation,
    /// policy authorization, optional inline `notify` registration, and mints a fresh
    /// `atproto-space-credential+jwt` alongside the Space's current `spaceRev`.
    pub async fn handle_authorize_space_sync(
        &self,
        req: AuthorizeSpaceSync,
        now_sec: u64,
    ) -> Result<AuthorizeSpaceSyncOutput> {
        let space = SpaceUri::parse_hedged(req.space.as_str())?;
        let space_str = space.as_str();
        if space.authority != self.authority_did {
            return Err(SpacesError::SpaceNotFound(space_str.to_string()));
        }
        decode_p256_did_key(req.credential_key.as_str())?;

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
            cnf_kid: Some(req.credential_key.as_str().to_string()),
        };
        let jwt = mint_space_token(
            SpaceTokenKind::Credential,
            &self.authority_signing_key,
            &cred_claims,
        )?;

        if let Some(notify) = &req.notify {
            let endpoint = notify.endpoint.as_str();
            if !endpoint.starts_with("https://") {
                return Err(SpacesError::RegistrationNotConfirmed(
                    "notify.endpoint must use https://".into(),
                ));
            }
            if notify.token.as_str().is_empty() {
                return Err(SpacesError::RegistrationNotConfirmed(
                    "notify.token must be non-empty".into(),
                ));
            }
            self.backend
                .register_subscriber(space_str, endpoint, notify.token.as_str(), exp)?;
        }

        if let Some(user_did) = requester_did {
            let mut issued = self
                .issued_credentials
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let list = issued.entry(space_str.to_string()).or_default();
            list.retain(|r| r.exp > now_sec);
            list.push(IssuedCredentialRecord { user_did, jti, exp });
        }

        let space_rev = self
            .backend
            .current_space_rev(space_str)?
            .map(|s| Tid::new(&s).map_err(|_| SpacesError::FutureRev(s)))
            .transpose()?;

        Ok(AuthorizeSpaceSyncOutput {
            credential: jwt.into(),
            space_rev,
            extra_data: None,
        })
    }

    /// Verify RFC 9421 + `atproto-space-credential+jwt` presentation on a Space-host or Repo-host route.
    ///
    /// A presentation that carries a signature `nonce` is recorded under the
    /// credential issuer once it fully verifies; the same `(issuer, nonce)`
    /// is refused for the rest of its freshness window.
    pub async fn verify_presentation(
        &self,
        headers: &HeaderMap,
        expected_space: &str,
        expected_audience_did: &str,
        now_sec: u64,
    ) -> Result<SpaceTokenClaims> {
        let space = SpaceUri::parse_hedged(expected_space)?;
        let expected_space = space.as_str();
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
        check_presentation_replay(
            &*self.signature_replay_store,
            &claims.iss,
            &verified_sig,
            now_sec,
        )?;
        Ok(claims)
    }

    /// `com.atproto.space.listWriters`: returns `#repoWrite` and `#repoRemoved` ordered by ascending `spaceRev`.
    pub async fn handle_list_writers(
        &self,
        headers: &HeaderMap,
        req: ListWriters,
        now_sec: u64,
    ) -> Result<ListWritersOutput> {
        let space = SpaceUri::parse_hedged(req.space.as_str())?;
        let space_str = space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;

        if let Some(c) = &req.cursor {
            if decode_tid_micros(c.as_str()).is_none() {
                return Err(SpacesError::InvalidCursor(format!(
                    "invalid listWriters cursor TID: {}",
                    c.as_str()
                )));
            }
        }

        let limit = req.limit.unwrap_or(100).clamp(1, 1000) as usize;
        let writers =
            self.backend
                .list_writers(space_str, req.cursor.as_ref().map(|c| c.as_str()), limit)?;
        let cursor = writers.last().map(|w| SmolStr::from(w.space_rev()));
        let repos = writers
            .into_iter()
            .map(|event| -> Result<ListWritersOutputReposItem> {
                match event {
                    SpaceWriterEvent::Write(w) => {
                        let did_str = w.did.clone();
                        Ok(ListWritersOutputReposItem::RepoWrite(Box::new(RepoWrite {
                            repo: Did::new(SmolStr::from(w.did))
                                .map_err(|_| SpacesError::InvalidDid(did_str))?,
                            repo_rev: Tid::new(&w.repo_rev)
                                .map_err(|_| SpacesError::FutureRev(w.repo_rev.clone()))?,
                            space_rev: Tid::new(&w.space_rev)
                                .map_err(|_| SpacesError::FutureRev(w.space_rev.clone()))?,
                            prev_space_rev: None,
                            data: Bytes::copy_from_slice(&w.data),
                            extra_data: None,
                        })))
                    }
                    SpaceWriterEvent::Removed { did, space_rev } => {
                        let did_str = did.clone();
                        Ok(ListWritersOutputReposItem::RepoRemoved(Box::new(
                            RepoRemoved {
                                repo: Did::new(SmolStr::from(did))
                                    .map_err(|_| SpacesError::InvalidDid(did_str))?,
                                space_rev: Tid::new(&space_rev)
                                    .map_err(|_| SpacesError::FutureRev(space_rev.clone()))?,
                                prev_space_rev: None,
                                extra_data: None,
                            },
                        )))
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ListWritersOutput {
            cursor,
            repos,
            extra_data: None,
        })
    }

    /// `com.atproto.space.notifyRepoUpdate`: validates caller == `req.repo`, checks TID skew + monotonicity,
    /// records writer commit, and builds outbound `(endpoint, NotifySpaceUpdate)` fanout messages.
    pub async fn handle_notify_repo_update(
        &self,
        authenticated_caller_did: &str,
        req: NotifyRepoUpdate,
        now_sec: u64,
    ) -> Result<Vec<(String, NotifySpaceUpdate)>> {
        let space = SpaceUri::parse_hedged(req.space.as_str())?;
        let space_str = space.as_str();
        if space.authority != self.authority_did {
            return Err(SpacesError::SpaceNotFound(space_str.to_string()));
        }
        if authenticated_caller_did != req.repo.as_str() {
            return Err(SpacesError::Forbidden(
                "notifyRepoUpdate caller DID must match req.repo".into(),
            ));
        }
        let data: [u8; 32] = req
            .data
            .as_ref()
            .try_into()
            .map_err(|_| SpacesError::Sync("notifyRepoUpdate data must be 32 bytes".into()))?;

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
        let new_tid =
            Tid::new(&new_space_rev).map_err(|_| SpacesError::FutureRev(new_space_rev.clone()))?;
        let prev_tid = prev_space_rev
            .as_deref()
            .map(|s| Tid::new(s).map_err(|_| SpacesError::FutureRev(s.to_string())))
            .transpose()?;
        let canonical_at_space = AtSpaceUri::new(SmolStr::from(space_str))
            .map_err(|_| SpacesError::InvalidSpaceUri(space_str.to_string()))?;

        let (active_subs, expired_subs) = self
            .backend
            .collect_subscribers_for_update(space_str, now_sec)?;
        let mut outbound = Vec::with_capacity(active_subs.len() + expired_subs.len());

        let write_update = NotifySpaceUpdateUpdate::RepoWrite(Box::new(RepoWrite {
            repo: req.repo,
            repo_rev: req.repo_rev,
            space_rev: new_tid.clone(),
            prev_space_rev: prev_tid,
            data: Bytes::copy_from_slice(&data),
            extra_data: None,
        }));
        for (endpoint, token) in active_subs {
            outbound.push((
                endpoint,
                NotifySpaceUpdate {
                    space: canonical_at_space.clone(),
                    token: token.into(),
                    update: write_update.clone(),
                    extra_data: None,
                },
            ));
        }
        let expired_update =
            NotifySpaceUpdateUpdate::RegistrationExpired(Box::new(RegistrationExpired {
                space_rev: new_tid,
                extra_data: None,
            }));
        for (endpoint, token) in expired_subs {
            outbound.push((
                endpoint,
                NotifySpaceUpdate {
                    space: canonical_at_space.clone(),
                    token: token.into(),
                    update: expired_update.clone(),
                    extra_data: None,
                },
            ));
        }

        Ok(outbound)
    }

    /// `com.atproto.space.removeWriter`: restricts removal to the Space authority / owner,
    /// sequences a `#repoRemoved` tombstone, and builds `NotifySpaceUpdate` fanout messages.
    pub async fn handle_remove_writer(
        &self,
        authenticated_caller_did: &str,
        req: RemoveWriter,
        now_sec: u64,
    ) -> Result<Vec<(String, NotifySpaceUpdate)>> {
        let space = SpaceUri::parse_hedged(req.space.as_str())?;
        let space_str = space.as_str();
        if authenticated_caller_did != space.authority {
            return Err(SpacesError::Forbidden("NotAuthorized".into()));
        }
        let (prev_space_rev, new_space_rev) =
            self.backend
                .remove_writer(space_str, req.repo.as_str(), now_sec)?;
        let new_tid =
            Tid::new(&new_space_rev).map_err(|_| SpacesError::FutureRev(new_space_rev.clone()))?;
        let prev_tid = prev_space_rev
            .as_deref()
            .map(|s| Tid::new(s).map_err(|_| SpacesError::FutureRev(s.to_string())))
            .transpose()?;
        let canonical_at_space = AtSpaceUri::new(SmolStr::from(space_str))
            .map_err(|_| SpacesError::InvalidSpaceUri(space_str.to_string()))?;

        let (active_subs, expired_subs) = self
            .backend
            .collect_subscribers_for_update(space_str, now_sec)?;
        let mut outbound = Vec::with_capacity(active_subs.len() + expired_subs.len());

        let removed_update = NotifySpaceUpdateUpdate::RepoRemoved(Box::new(RepoRemoved {
            repo: req.repo,
            space_rev: new_tid.clone(),
            prev_space_rev: prev_tid,
            extra_data: None,
        }));
        for (endpoint, token) in active_subs {
            outbound.push((
                endpoint,
                NotifySpaceUpdate {
                    space: canonical_at_space.clone(),
                    token: token.into(),
                    update: removed_update.clone(),
                    extra_data: None,
                },
            ));
        }
        let expired_update =
            NotifySpaceUpdateUpdate::RegistrationExpired(Box::new(RegistrationExpired {
                space_rev: new_tid,
                extra_data: None,
            }));
        for (endpoint, token) in expired_subs {
            outbound.push((
                endpoint,
                NotifySpaceUpdate {
                    space: canonical_at_space.clone(),
                    token: token.into(),
                    update: expired_update.clone(),
                    extra_data: None,
                },
            ));
        }

        Ok(outbound)
    }

    /// `com.atproto.space.getSpace`: returns the Space URI and open-union policy document.
    pub async fn handle_get_space(
        &self,
        headers: &HeaderMap,
        req: GetSpace,
        now_sec: u64,
    ) -> Result<GetSpaceOutput> {
        let space = SpaceUri::parse_hedged(req.space.as_str())?;
        let space_str = space.as_str();
        self.verify_presentation(headers, space_str, &self.authority_did, now_sec)
            .await?;
        let policy_json = self.backend.get_space_policy_json(space_str)?;
        let policy: GetSpaceOutputPolicy = serde_json::from_value(policy_json)
            .map_err(|e| SpacesError::Sync(format!("decode space policy union: {e}")))?;
        let _ = Data::<jacquard_common::DefaultStr>::Null;
        let canonical_at_space = AtSpaceUri::new(SmolStr::from(space_str))
            .map_err(|_| SpacesError::InvalidSpaceUri(space_str.to_string()))?;
        Ok(GetSpaceOutput {
            space: canonical_at_space,
            policy,
            extra_data: None,
        })
    }

    /// Revoke all active Space credentials issued to `revoked_user_did` in `space_uri`,
    /// returning `(NotifyCredentialsRevoked, target_writer_dids)`.
    pub fn revoke_user_credentials_and_build_notice(
        &self,
        space_uri: &str,
        revoked_user_did: &str,
        now_sec: u64,
    ) -> Result<(NotifyCredentialsRevoked, Vec<String>)> {
        let space = SpaceUri::parse_hedged(space_uri)?;
        let space_str = space.as_str();
        let writer_targets = self.backend.all_writer_dids(space_str)?;
        let mut revoked_jtis = Vec::new();
        {
            let mut issued = self
                .issued_credentials
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(list) = issued.get_mut(space_str) {
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

        let notice = NotifyCredentialsRevoked {
            space: AtSpaceUri::new(SmolStr::from(space_str))
                .map_err(|_| SpacesError::InvalidSpaceUri(space_str.to_string()))?,
            credentials: revoked_jtis.into_iter().map(SmolStr::from).collect(),
            extra_data: None,
        };
        Ok((notice, writer_targets))
    }

    /// Build `(writer_dids, subscriber_notices)` for Space deletion (`notifySpaceUpdate#spaceDeleted`),
    /// delivered even to expired registrations per November 12 `authorizeSpaceSync` contract.
    pub fn build_notify_space_deleted(&self, space_uri: &str) -> Result<SpaceDeletedFanout> {
        let space = SpaceUri::parse_hedged(space_uri)?;
        let space_str = space.as_str();
        let writers = self.backend.all_writer_dids(space_str)?;
        let subscribers = self.backend.list_all_subscribers(space_str)?;
        let canonical_at_space = AtSpaceUri::new(SmolStr::from(space_str))
            .map_err(|_| SpacesError::InvalidSpaceUri(space_str.to_string()))?;
        let deleted_update =
            NotifySpaceUpdateUpdate::SpaceDeleted(Box::new(SpaceDeleted { extra_data: None }));
        let notices = subscribers
            .into_iter()
            .map(|(endpoint, token)| {
                (
                    endpoint,
                    NotifySpaceUpdate {
                        space: canonical_at_space.clone(),
                        token: token.into(),
                        update: deleted_update.clone(),
                        extra_data: None,
                    },
                )
            })
            .collect();
        Ok((writers, notices))
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
