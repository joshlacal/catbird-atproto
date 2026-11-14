//! ATProto Spaces (`atproto#5187` / November 12, 2026 alpha) shared Rust implementation.
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

use cid::Cid;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Unified error type for `atproto-spaces` cryptographic, token, sync, and Space-host operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpacesError {
    #[error("invalid space URI: {0}")]
    InvalidSpaceUri(String),

    #[error("invalid space blob locator: {0}")]
    InvalidBlobLocator(String),

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

    #[error("registration not confirmed: {0}")]
    RegistrationNotConfirmed(String),

    #[error("invalid pagination cursor: {0}")]
    InvalidCursor(String),

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

    #[error("STAR archive error: {0}")]
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

impl SpacesError {
    /// Canonical November 12 `com.atproto.space.*` XRPC error code name.
    pub fn atproto_error_name(&self) -> &'static str {
        match self {
            Self::MacMismatch(_) => "InvalidSpaceMac",
            Self::BadSpaceSignature(_) | Self::InvalidSpaceCredential(_) => "InvalidSpaceSignature",
            Self::Forbidden(_) => "AccountNotAuthorized",
            Self::CredentialRevoked => "CredentialRevoked",
            Self::SpaceNotFound(_) => "SpaceNotFound",
            Self::SpaceDeleted(_) => "SpaceDeleted",
            Self::InvalidDelegationToken(_) => "InvalidDelegationToken",
            Self::InvalidClientAttestation(_) => "InvalidClientAttestation",
            Self::RegistrationNotConfirmed(_) => "RegistrationNotConfirmed",
            Self::FutureRev(_) => "FutureRev",
            Self::InvalidCursor(_) => "InvalidCursor",
            Self::InvalidSpaceUri(_)
            | Self::InvalidBlobLocator(_)
            | Self::InvalidDid(_)
            | Self::InvalidDidKey(_)
            | Self::Kem(_)
            | Self::SetHashMismatch(_)
            | Self::StarFormat(_)
            | Self::DidResolution(_)
            | Self::Transport { .. }
            | Self::Sync(_) => "InvalidRequest",
        }
    }
}

pub type Result<T> = std::result::Result<T, SpacesError>;

/// Parsed canonical `at://{authority}/space/{space_type}/{rkey}` Space URI.
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

    /// Parse a canonical `at://{did}/space/{type}/{skey}` Space URI or normalize hedged
    /// `at:space/{did}/{type}/{skey}` / `at://space/{did}/{type}/{skey}` forms onto canonical form.
    pub fn parse_hedged(raw: &str) -> Result<Self> {
        let rest = if let Some(s) = raw.strip_prefix("at:space/") {
            Some(s)
        } else {
            raw.strip_prefix("at://space/")
        };
        if let Some(rest) = rest {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
                return Err(SpacesError::InvalidSpaceUri(raw.to_string()));
            }
            return Self::new(parts[0], parts[1], parts[2]);
        }
        Self::parse(raw)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
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

impl fmt::Display for SpaceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for SpaceUri {
    type Err = SpacesError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for SpaceUri {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for SpaceUri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_hedged(&s).map_err(serde::de::Error::custom)
    }
}

/// Application-local locator for fetching an encrypted Space blob via `com.atproto.space.getBlob`.
///
/// Canonical encoding uses pipe delimiters (`{spaceURI}|{repoDID}|{cid}`). Parsing also accepts
/// the transitional `{spaceURI}/{repoDID}#{cid}` encoding and hedged `at:space/...` Space URIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceBlobLocator {
    pub space: SpaceUri,
    pub repo: String,
    pub cid: Cid,
}

impl SpaceBlobLocator {
    pub fn new(space: SpaceUri, repo: impl Into<String>, cid: Cid) -> Result<Self> {
        let repo = repo.into();
        if !is_atproto_did(&repo) {
            return Err(SpacesError::InvalidBlobLocator(format!(
                "invalid ATProto repo DID in blob locator: {repo}"
            )));
        }
        Ok(Self { space, repo, cid })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        if raw.contains('|') {
            if raw.contains('#') {
                return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
            }
            let parts: Vec<&str> = raw.split('|').collect();
            if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
                return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
            }
            let space = SpaceUri::parse_hedged(parts[0])
                .map_err(|_| SpacesError::InvalidBlobLocator(raw.to_string()))?;
            let repo = parts[1];
            let cid = parse_canonical_cid(parts[2])
                .ok_or_else(|| SpacesError::InvalidBlobLocator(raw.to_string()))?;
            return Self::new(space, repo, cid);
        }

        let Some((before_hash, raw_cid)) = raw.split_once('#') else {
            return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
        };
        if raw_cid.is_empty() || raw_cid.contains('#') {
            return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
        }
        let Some((raw_space, repo)) = before_hash.rsplit_once('/') else {
            return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
        };
        if raw_space.is_empty() || repo.is_empty() {
            return Err(SpacesError::InvalidBlobLocator(raw.to_string()));
        }
        let space = SpaceUri::parse_hedged(raw_space)
            .map_err(|_| SpacesError::InvalidBlobLocator(raw.to_string()))?;
        let cid = parse_canonical_cid(raw_cid)
            .ok_or_else(|| SpacesError::InvalidBlobLocator(raw.to_string()))?;
        Self::new(space, repo, cid)
    }

    pub fn encoded(&self) -> String {
        format!("{}|{}|{}", self.space.raw, self.repo, self.cid)
    }
}

impl fmt::Display for SpaceBlobLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}|{}|{}", self.space.raw, self.repo, self.cid)
    }
}

impl FromStr for SpaceBlobLocator {
    type Err = SpacesError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for SpaceBlobLocator {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encoded())
    }
}

impl<'de> Deserialize<'de> for SpaceBlobLocator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

fn parse_canonical_cid(raw: &str) -> Option<Cid> {
    let cid: Cid = raw.parse().ok()?;
    if cid.to_string() == raw {
        Some(cid)
    } else {
        None
    }
}

pub fn is_atproto_did(did: &str) -> bool {
    is_valid_did(did) && (did.starts_with("did:plc:") || did.starts_with("did:web:"))
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
