//! ATProto Spaces (`atproto#5187` / Proposal 0016) shared Rust implementation.
//!
//! Designed to compile cleanly on both native targets and `wasm32-unknown-unknown`
//! with zero `tokio` dependencies.

pub mod credential_cache;
pub mod did_resolver;
pub mod host;
pub mod http_signature;
pub mod kem;
pub mod lthash;
pub mod mac;
pub mod star;
pub mod sync_engine;
pub mod tokens;
pub mod vectors;

use thiserror::Error;

/// Unified error type for `atproto-spaces` cryptographic, token, sync, and Space-host operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpacesError {
    #[error("invalid space URI: {0}")]
    InvalidSpaceUri(String),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("invalid did:key: {0}")]
    InvalidDidKey(String),

    #[error("HPKE KEM error: {0}")]
    Kem(String),

    #[error("Space MAC mismatch or malformed header: {0}")]
    MacMismatch(String),

    #[error("LtHash set-hash mismatch: {0}")]
    SetHashMismatch(String),

    #[error("RFC 9421 HTTP signature error: {0}")]
    BadSpaceSignature(String),

    #[error("invalid delegation token: {0}")]
    InvalidDelegationToken(String),

    #[error("invalid space credential: {0}")]
    InvalidSpaceCredential(String),

    #[error("invalid client attestation: {0}")]
    InvalidClientAttestation(String),

    #[error("credential revoked")]
    CredentialRevoked,

    #[error("space not found: {0}")]
    SpaceNotFound(String),

    #[error("space deleted: {0}")]
    SpaceDeleted(String),

    #[error("future or non-monotonic repo revision: {0}")]
    FutureRev(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("STAR-lite archive error: {0}")]
    StarFormat(String),

    #[error("DID resolution error: {0}")]
    DidResolution(String),

    #[error("transport error (status={status:?}, code={code:?}): {message}")]
    Transport {
        status: Option<u16>,
        code: Option<String>,
        message: String,
    },

    #[error("sync error: {0}")]
    Sync(String),
}

pub type Result<T> = std::result::Result<T, SpacesError>;

/// Parsed `at://{authority}/space/{space_type}/{rkey}` Space URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpaceUri {
    pub raw: String,
    pub authority: String,
    pub space_type: String,
    pub rkey: String,
}

impl SpaceUri {
    pub fn new(authority: &str, space_type: &str, skey: &str) -> Result<Self> {
        Self::parse(&format!("at://{authority}/space/{space_type}/{skey}"))
    }

    pub fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty()
            || raw.len() > 2048
            || raw.bytes().any(|b| b <= 0x20 || b == 0x7f)
            || raw.contains('?')
            || raw.contains('#')
        {
            return Err(SpacesError::InvalidSpaceUri(raw.to_string()));
        }
        let Some(rest) = raw.strip_prefix("at://") else {
            return Err(SpacesError::InvalidSpaceUri(raw.to_string()));
        };
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 4 || parts[1] != "space" || parts.iter().any(|p| p.is_empty()) {
            return Err(SpacesError::InvalidSpaceUri(raw.to_string()));
        }
        let authority = parts[0];
        let space_type = parts[2];
        let rkey = parts[3];
        if !is_valid_did(authority) || !is_valid_nsid(space_type) || !is_valid_rkey(rkey) {
            return Err(SpacesError::InvalidSpaceUri(raw.to_string()));
        }
        jacquard_common::types::aturi::AtSpaceUri::new(
            jacquard_common::deps::smol_str::SmolStr::from(raw),
        )
        .map_err(|_| SpacesError::InvalidSpaceUri(raw.to_string()))?;
        Ok(Self {
            raw: raw.to_string(),
            authority: authority.to_string(),
            space_type: space_type.to_string(),
            rkey: rkey.to_string(),
        })
    }

    /// Canonical `SpaceRecordURI` (`at://{authority}/space/{space_type}/{skey}/{author_did}/{collection}/{rkey}`).
    pub fn record_uri(&self, author_did: &str, collection: &str, rkey: &str) -> Result<String> {
        if !is_valid_did(author_did) || !is_valid_nsid(collection) || !is_valid_rkey(rkey) {
            return Err(SpacesError::InvalidSpaceUri(format!(
                "{}/{author_did}/{collection}/{rkey}",
                self.raw
            )));
        }
        Ok(format!("{}/{author_did}/{collection}/{rkey}", self.raw))
    }
}

pub fn is_valid_did(did: &str) -> bool {
    if did.len() < 8 || did.len() > 2048 || did.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return false;
    }
    let Some(rest) = did.strip_prefix("did:") else {
        return false;
    };
    let Some((method, specific)) = rest.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_lowercase())
        || specific.is_empty()
        || specific.ends_with(':')
        || specific.contains('#')
        || specific.contains('?')
        || specific.contains('/')
    {
        return false;
    }
    true
}

pub fn is_valid_nsid(nsid: &str) -> bool {
    if nsid.is_empty() || nsid.len() > 317 {
        return false;
    }
    let segments: Vec<&str> = nsid.split('.').collect();
    if segments.len() < 3 {
        return false;
    }
    segments.iter().all(|seg| {
        !seg.is_empty()
            && seg.len() <= 63
            && !seg.starts_with('-')
            && !seg.ends_with('-')
            && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

pub fn is_valid_rkey(rkey: &str) -> bool {
    !rkey.is_empty()
        && rkey.len() <= 512
        && rkey != "."
        && rkey != ".."
        && rkey
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b':'))
}
