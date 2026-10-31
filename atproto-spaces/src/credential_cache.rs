//! Ephemeral P-256 Space credential cache (`CredentialCache`).
//!
//! - Generates 1 fresh ephemeral `P-256` keypair per minted Space credential.
//! - Verifies the returned `atproto-space-credential+jwt` signature + `iss`/`sub`/`exp`/`cnf.kid`
//!   against the Space authority's DID document BEFORE caching (Gate 7).
//! - Caches up to `min(exp - 30s, iat + 600s)` and evicts immediately on `401` / `CredentialRevoked`.

use crate::did_resolver::SpaceDidResolver;
use crate::http_signature::{sign_credential_request_minimal, SpaceRequestHeaders};
use crate::kem::{encode_p256_did_key, P256SecretKey};
use crate::sync_engine::SpaceTransport;
use crate::tokens::{verify_space_token, SpaceTokenKind};
use crate::{Result, SpaceUri, SpacesError};
use catbird_atproto::com_atproto::space::get_space_credential::{
    GetSpaceCredential, GetSpaceCredentialOutput,
};
use http::{HeaderMap, HeaderValue, Method};
use jacquard_common::types::aturi::AtSpaceUri;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

pub const CREDENTIAL_CACHE_MAX_TTL_SECS: u64 = 600;
pub const CREDENTIAL_EXPIRY_SAFETY_MARGIN_SECS: u64 = 30;

#[async_trait::async_trait(?Send)]
pub trait DelegationMinter {
    async fn mint_delegation_token(&self, space_uri: &str, authority_did: &str) -> Result<String>;
}

#[async_trait::async_trait(?Send)]
impl<M: DelegationMinter + ?Sized> DelegationMinter for Rc<M> {
    async fn mint_delegation_token(&self, space_uri: &str, authority_did: &str) -> Result<String> {
        (**self)
            .mint_delegation_token(space_uri, authority_did)
            .await
    }
}

#[async_trait::async_trait(?Send)]
impl<M: DelegationMinter + ?Sized> DelegationMinter for Arc<M> {
    async fn mint_delegation_token(&self, space_uri: &str, authority_did: &str) -> Result<String> {
        (**self)
            .mint_delegation_token(space_uri, authority_did)
            .await
    }
}

#[derive(Clone)]
struct CachedCredential {
    jwt: String,
    ephemeral_key: P256SecretKey,
    expires_at_sec: u64,
}

pub struct CredentialCache<T, R, M> {
    transport: T,
    did_resolver: R,
    delegation_minter: M,
    client_attestation: Option<String>,
    entries: RwLock<BTreeMap<String, CachedCredential>>,
}

impl<T, R, M> CredentialCache<T, R, M>
where
    T: SpaceTransport,
    R: SpaceDidResolver,
    M: DelegationMinter,
{
    pub fn new(transport: T, did_resolver: R, delegation_minter: M) -> Self {
        Self {
            transport,
            did_resolver,
            delegation_minter,
            client_attestation: None,
            entries: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn with_client_attestation(mut self, jwt: impl Into<String>) -> Self {
        self.client_attestation = Some(jwt.into());
        self
    }

    pub fn evict(&self, space_uri: &str) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(space_uri);
    }

    /// Obtain signed RFC 9421 request headers for `space_uri` bound to `audience_did`,
    /// minting and Gate-7-verifying a fresh Space credential if missing or expiring.
    pub async fn signed_headers_for_request(
        &self,
        space_uri: &str,
        audience_did: &str,
        now_sec: u64,
    ) -> Result<SpaceRequestHeaders> {
        let cred = self.get_or_mint(space_uri, now_sec).await?;
        sign_credential_request_minimal(&cred.ephemeral_key, &cred.jwt, audience_did)
    }

    async fn get_or_mint(&self, space_uri: &str, now_sec: u64) -> Result<CachedCredential> {
        {
            let guard = self.entries.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.get(space_uri) {
                if now_sec < entry.expires_at_sec {
                    return Ok(entry.clone());
                }
            }
        }

        let space = SpaceUri::parse(space_uri)?;
        let authority_doc = self
            .did_resolver
            .resolve_did(&space.authority, false)
            .await?;
        let host_endpoint = authority_doc.space_host_endpoint()?.to_string();

        // Fresh ephemeral P-256 keypair per minted credential
        let ephemeral_key = P256SecretKey::random(&mut rand::rngs::OsRng);
        let cnf_did_key = encode_p256_did_key(&ephemeral_key.public_key());
        let delegation_jwt = self
            .delegation_minter
            .mint_delegation_token(space_uri, &space.authority)
            .await?;

        let req_body = GetSpaceCredential {
            space: AtSpaceUri::new(jacquard_common::deps::smol_str::SmolStr::from(space_uri))
                .map_err(|_| SpacesError::InvalidSpaceUri(space_uri.to_string()))?,
            credential_kid: cnf_did_key.as_str().into(),
            delegation_token: Some(delegation_jwt.as_str().into()),
            client_attestation: self.client_attestation.as_deref().map(Into::into),
            extra_data: None,
        };
        let payload = serde_json::to_vec(&req_body).map_err(|e| {
            SpacesError::InvalidSpaceCredential(format!("encode getSpaceCredential: {e}"))
        })?;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let url = format!("{host_endpoint}/xrpc/com.atproto.space.getSpaceCredential");
        let resp = self
            .transport
            .send_http(Method::POST, &url, &headers, Some(&payload))
            .await?;
        if resp.status != 200 {
            return Err(parse_xrpc_error(resp.status, &resp.body));
        }

        let out: GetSpaceCredentialOutput = serde_json::from_slice(&resp.body).map_err(|e| {
            SpacesError::InvalidSpaceCredential(format!("decode getSpaceCredential response: {e}"))
        })?;
        let jwt = out.credential.as_str().to_string();

        // Gate 7: Verify Space credential JWT signature + iss/sub/exp/cnf.kid BEFORE caching!
        let verified_claims = verify_space_token(
            SpaceTokenKind::Credential,
            &jwt,
            &self.did_resolver,
            now_sec,
        )
        .await?;
        if verified_claims.iss != space.authority
            || verified_claims.sub != space_uri
            || verified_claims.cnf_kid.as_deref() != Some(cnf_did_key.as_str())
        {
            return Err(SpacesError::InvalidSpaceCredential(
                "minted Space credential failed iss/sub/cnf.kid binding check".into(),
            ));
        }

        let safe_exp = verified_claims
            .exp
            .saturating_sub(CREDENTIAL_EXPIRY_SAFETY_MARGIN_SECS);
        let capped_exp = verified_claims
            .iat
            .saturating_add(CREDENTIAL_CACHE_MAX_TTL_SECS)
            .min(safe_exp)
            .max(now_sec.saturating_add(1));

        let cached = CachedCredential {
            jwt,
            ephemeral_key,
            expires_at_sec: capped_exp,
        };
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(space_uri.to_string(), cached.clone());
        Ok(cached)
    }
}

pub(crate) fn parse_xrpc_error(status: u16, body: &[u8]) -> SpacesError {
    #[derive(serde::Deserialize)]
    struct WireErr {
        error: Option<String>,
        message: Option<String>,
    }
    let parsed: Option<WireErr> = serde_json::from_slice(body).ok();
    let code = parsed.as_ref().and_then(|p| p.error.clone());
    let msg = parsed
        .as_ref()
        .and_then(|p| p.message.clone())
        .unwrap_or_else(|| format!("HTTP {status}"));

    match (status, code.as_deref()) {
        (401, Some("CredentialRevoked")) | (401, _) => SpacesError::CredentialRevoked,
        (_, Some("SpaceNotFound")) => SpacesError::SpaceNotFound(msg),
        (_, Some("SpaceDeleted")) => SpacesError::SpaceDeleted(msg),
        (_, Some("InvalidDelegationToken")) => SpacesError::InvalidDelegationToken(msg),
        (_, Some("InvalidClientAttestation")) => SpacesError::InvalidClientAttestation(msg),
        (_, Some("BadSpaceMac")) => SpacesError::MacMismatch(msg),
        (_, Some("BadSpaceSignature")) => SpacesError::BadSpaceSignature(msg),
        (_, Some("FutureRev")) => SpacesError::FutureRev(msg),
        (403, _)
        | (_, Some("UserNotAuthorized"))
        | (_, Some("AppNotAuthorized"))
        | (_, Some("NotAuthorized")) => SpacesError::Forbidden(msg),
        _ => SpacesError::Transport {
            status: Some(status),
            code,
            message: msg,
        },
    }
}
