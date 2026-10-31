//! ATProto Spaces JOSE token minting and verification (`delegation`, `credential`, `clientAttestation`).
//!
//! Conforms to `atproto#5187` (`d0097360` / `SwanOAuth.PermissionedDataJWT`):
//! - Supports `ES256` (`P-256`) and `ES256K` (`secp256k1`) for `#atproto` DID keys (`did:plc` & `did:web`).
//! - Performs bounded structural + claims validation BEFORE any DID key lookup.
//! - Retries `SpaceKeyResolver::resolve_atproto_key(..., force_refresh = true)` **once** on signature mismatch.

use crate::kem::decode_p256_did_key;
use crate::{is_valid_did, Result, SpaceUri, SpacesError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};
use url::Url;

pub const DELEGATION_JWT_TYP: &str = "atproto-space-delegation+jwt";
pub const CREDENTIAL_JWT_TYP: &str = "atproto-space-credential+jwt";
pub const CLIENT_ATTESTATION_JWT_TYP: &str = "atproto-client-attestation+jwt";
pub const ATPROTO_KEY_ID: &str = "#atproto";

pub const DELEGATION_MAX_LIFETIME_SECS: u64 = 60;
pub const CREDENTIAL_DEFAULT_LIFETIME_SECS: u64 = 600;
pub const CREDENTIAL_MAX_LIFETIME_SECS: u64 = 3600;
pub const CLIENT_ATTESTATION_MAX_LIFETIME_SECS: u64 = 600;
pub const MAX_IAT_LEAD_SECS: u64 = 5;
pub const EXPIRY_CLOCK_SKEW_SECS: u64 = 60;
pub const MAX_COMPACT_JWT_BYTES: usize = 8 * 1024;
pub const MAX_JTI_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceTokenKind {
    Delegation,
    Credential,
    ClientAttestation,
}

impl SpaceTokenKind {
    pub const fn expected_typ(self) -> &'static str {
        match self {
            Self::Delegation => DELEGATION_JWT_TYP,
            Self::Credential => CREDENTIAL_JWT_TYP,
            Self::ClientAttestation => CLIENT_ATTESTATION_JWT_TYP,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf_kid: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SpaceSigningKey {
    P256 {
        signing_key: p256::ecdsa::SigningKey,
        kid: String,
    },
    K256 {
        signing_key: k256::ecdsa::SigningKey,
        kid: String,
    },
}

impl SpaceSigningKey {
    pub fn random_p256() -> Self {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        Self::from_p256_secret(&sk, ATPROTO_KEY_ID)
    }

    pub fn from_p256_secret(secret: &p256::SecretKey, kid: impl Into<String>) -> Self {
        Self::P256 {
            signing_key: p256::ecdsa::SigningKey::from(secret),
            kid: kid.into(),
        }
    }

    pub fn from_k256_secret(secret: &k256::SecretKey, kid: impl Into<String>) -> Self {
        Self::K256 {
            signing_key: k256::ecdsa::SigningKey::from(secret),
            kid: kid.into(),
        }
    }

    pub fn alg(&self) -> &'static str {
        match self {
            Self::P256 { .. } => "ES256",
            Self::K256 { .. } => "ES256K",
        }
    }

    pub fn kid(&self) -> &str {
        match self {
            Self::P256 { kid, .. } | Self::K256 { kid, .. } => kid,
        }
    }

    pub fn verifying_key(&self) -> SpaceVerifyingKey {
        match self {
            Self::P256 { signing_key, .. } => SpaceVerifyingKey::P256(*signing_key.verifying_key()),
            Self::K256 { signing_key, .. } => SpaceVerifyingKey::K256(*signing_key.verifying_key()),
        }
    }

    fn sign_bytes(&self, signing_input: &[u8]) -> Vec<u8> {
        match self {
            Self::P256 { signing_key, .. } => {
                let sig: p256::ecdsa::Signature = signing_key.sign(signing_input);
                let norm = sig.normalize_s().unwrap_or(sig);
                norm.to_bytes().to_vec()
            }
            Self::K256 { signing_key, .. } => {
                let sig: k256::ecdsa::Signature = signing_key.sign(signing_input);
                let norm = sig.normalize_s().unwrap_or(sig);
                norm.to_bytes().to_vec()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    K256(k256::ecdsa::VerifyingKey),
}

impl SpaceVerifyingKey {
    pub fn expected_alg(&self) -> &'static str {
        match self {
            Self::P256(_) => "ES256",
            Self::K256(_) => "ES256K",
        }
    }

    pub fn verify_raw(&self, alg: &str, signing_input: &[u8], sig_bytes: &[u8]) -> bool {
        if sig_bytes.len() != 64 || alg != self.expected_alg() {
            return false;
        }
        match self {
            Self::P256(vk) => {
                let Ok(sig) = p256::ecdsa::Signature::from_slice(sig_bytes) else {
                    return false;
                };
                let norm = sig.normalize_s().unwrap_or(sig);
                vk.verify(signing_input, &norm).is_ok()
            }
            Self::K256(vk) => {
                let Ok(sig) = k256::ecdsa::Signature::from_slice(sig_bytes) else {
                    return false;
                };
                let norm = sig.normalize_s().unwrap_or(sig);
                vk.verify(signing_input, &norm).is_ok()
            }
        }
    }
}

#[async_trait::async_trait(?Send)]
pub trait SpaceKeyResolver {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey>;
}

#[derive(Debug, Serialize, Deserialize)]
struct JoseHeader {
    alg: String,
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing)]
    jwk: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    crit: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    b64: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireCnf {
    kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireClaims {
    iss: String,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    iat: i64,
    exp: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<WireCnf>,
}

/// Mint a signed compact JWT for `Delegation`, `Credential`, or `ClientAttestation`.
pub fn mint_space_token(
    kind: SpaceTokenKind,
    signing_key: &SpaceSigningKey,
    claims: &SpaceTokenClaims,
) -> Result<String> {
    validate_claims_shape(kind, signing_key.alg(), Some(signing_key.kid()), claims)?;

    let header = JoseHeader {
        alg: signing_key.alg().to_string(),
        typ: kind.expected_typ().to_string(),
        kid: Some(signing_key.kid().to_string()),
        jwk: None,
        crit: None,
        b64: None,
    };
    let wire_claims = WireClaims {
        iss: claims.iss.clone(),
        sub: claims.sub.clone(),
        aud: claims.aud.clone(),
        iat: i64::try_from(claims.iat).map_err(|_| token_err(kind, "iat overflows i64"))?,
        exp: i64::try_from(claims.exp).map_err(|_| token_err(kind, "exp overflows i64"))?,
        jti: claims.jti.clone(),
        cnf: claims
            .cnf_kid
            .as_ref()
            .map(|kid| WireCnf { kid: kid.clone() }),
    };

    let hdr_b64 = BASE64URL.encode(
        serde_json::to_vec(&header).map_err(|e| token_err(kind, format!("header encode: {e}")))?,
    );
    let claims_b64 = BASE64URL.encode(
        serde_json::to_vec(&wire_claims)
            .map_err(|e| token_err(kind, format!("claims encode: {e}")))?,
    );
    let signing_input = format!("{hdr_b64}.{claims_b64}");
    let sig_b64 = BASE64URL.encode(signing_key.sign_bytes(signing_input.as_bytes()));
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Inspect and structurally validate an untrusted compact Space token before key lookup.
pub fn inspect_untrusted_space_token(
    kind: SpaceTokenKind,
    jwt: &str,
    now_sec: u64,
) -> Result<(String, SpaceTokenClaims)> {
    let parsed = parse_and_validate_untrusted(kind, jwt, now_sec)?;
    Ok((parsed.header.alg, parsed.claims))
}

/// Verify a compact Space token (`Delegation`, `Credential`, or `ClientAttestation`),
/// retrying `resolver.resolve_atproto_key(..., true)` **once** on signature mismatch.
pub async fn verify_space_token(
    kind: SpaceTokenKind,
    jwt: &str,
    resolver: &dyn SpaceKeyResolver,
    now_sec: u64,
) -> Result<SpaceTokenClaims> {
    let parsed = parse_and_validate_untrusted(kind, jwt, now_sec)?;
    let key_lookup_id = match kind {
        SpaceTokenKind::ClientAttestation => {
            let kid = parsed.header.kid.as_deref().unwrap_or_default();
            format!("{}#{kid}", parsed.claims.iss)
        }
        SpaceTokenKind::Delegation | SpaceTokenKind::Credential => parsed.claims.iss.clone(),
    };

    let vk = resolver.resolve_atproto_key(&key_lookup_id, false).await?;
    if vk.verify_raw(
        &parsed.header.alg,
        parsed.signing_input.as_bytes(),
        &parsed.sig_bytes,
    ) {
        return Ok(parsed.claims);
    }

    // Retry ONCE with forced refresh (handles rotated did:web / did:plc signing keys).
    let refreshed_vk = resolver.resolve_atproto_key(&key_lookup_id, true).await?;
    if refreshed_vk.verify_raw(
        &parsed.header.alg,
        parsed.signing_input.as_bytes(),
        &parsed.sig_bytes,
    ) {
        return Ok(parsed.claims);
    }

    Err(token_err(
        kind,
        "JWT signature verification failed even after key refresh",
    ))
}

struct UntrustedTokenParts {
    header: JoseHeader,
    claims: SpaceTokenClaims,
    signing_input: String,
    sig_bytes: Vec<u8>,
}

fn parse_and_validate_untrusted(
    kind: SpaceTokenKind,
    jwt: &str,
    now_sec: u64,
) -> Result<UntrustedTokenParts> {
    if jwt.is_empty() || jwt.len() > MAX_COMPACT_JWT_BYTES {
        return Err(token_err(kind, "empty or oversized compact JWT"));
    }
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(token_err(
            kind,
            "JWT must have 3 non-empty dot-separated parts",
        ));
    }
    if parts[0].len() > 4096 || parts[1].len() > 4096 {
        return Err(token_err(kind, "JWT header or payload exceeds 4 KiB"));
    }

    let hdr_bytes = BASE64URL
        .decode(parts[0])
        .map_err(|e| token_err(kind, format!("invalid header base64url: {e}")))?;
    let payload_bytes = BASE64URL
        .decode(parts[1])
        .map_err(|e| token_err(kind, format!("invalid payload base64url: {e}")))?;
    let sig_bytes = BASE64URL
        .decode(parts[2])
        .map_err(|e| token_err(kind, format!("invalid signature base64url: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(token_err(kind, "JWT signature must be 64 raw bytes"));
    }

    let header: JoseHeader = serde_json::from_slice(&hdr_bytes)
        .map_err(|e| token_err(kind, format!("malformed JOSE header JSON: {e}")))?;
    if header.typ != kind.expected_typ() {
        return Err(token_err(
            kind,
            format!(
                "unexpected JOSE typ {:?}, expected {}",
                header.typ,
                kind.expected_typ()
            ),
        ));
    }
    if header.jwk.is_some() || header.crit.is_some() || header.b64.is_some() {
        return Err(token_err(
            kind,
            "embedded jwk, crit, and b64 headers are forbidden",
        ));
    }

    let wire: WireClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| token_err(kind, format!("malformed JWT claims JSON: {e}")))?;
    if wire.iat < 0 || wire.exp <= wire.iat {
        return Err(token_err(kind, "JWT must have 0 <= iat < exp"));
    }
    let claims = SpaceTokenClaims {
        iss: wire.iss,
        sub: wire.sub,
        aud: wire.aud,
        iat: wire.iat as u64,
        exp: wire.exp as u64,
        jti: wire.jti,
        cnf_kid: wire.cnf.map(|c| c.kid),
    };

    validate_claims_shape(kind, &header.alg, header.kid.as_deref(), &claims)?;
    validate_claims_timestamps(kind, &claims, now_sec)?;

    Ok(UntrustedTokenParts {
        header,
        claims,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        sig_bytes,
    })
}

fn validate_claims_shape(
    kind: SpaceTokenKind,
    alg: &str,
    kid: Option<&str>,
    claims: &SpaceTokenClaims,
) -> Result<()> {
    if !is_valid_jti(&claims.jti) {
        return Err(token_err(kind, "invalid or oversized jti"));
    }
    if claims.exp <= claims.iat {
        return Err(token_err(kind, "exp must be greater than iat"));
    }
    let lifetime = claims.exp - claims.iat;

    match kind {
        SpaceTokenKind::Delegation => {
            if !matches!(alg, "ES256" | "ES256K") {
                return Err(token_err(kind, format!("unsupported delegation alg {alg}")));
            }
            if kid != Some(ATPROTO_KEY_ID) && !kid.is_some_and(|k| k.ends_with(ATPROTO_KEY_ID)) {
                return Err(token_err(kind, "delegation kid must be #atproto"));
            }
            if !is_valid_did(&claims.iss) {
                return Err(token_err(kind, "delegation iss must be a valid DID"));
            }
            let space = SpaceUri::parse(&claims.sub)
                .map_err(|_| token_err(kind, "delegation sub must be a valid Space URI"))?;
            let expected_aud = format!("{}#atproto_pds", space.authority);
            if claims.aud.as_deref() != Some(expected_aud.as_str()) {
                return Err(token_err(
                    kind,
                    format!("delegation aud must equal {expected_aud}"),
                ));
            }
            if claims.cnf_kid.is_some() {
                return Err(token_err(kind, "delegation must not carry cnf"));
            }
            if lifetime > DELEGATION_MAX_LIFETIME_SECS {
                return Err(token_err(
                    kind,
                    format!(
                        "delegation lifetime {lifetime}s exceeds {DELEGATION_MAX_LIFETIME_SECS}s"
                    ),
                ));
            }
        }
        SpaceTokenKind::Credential => {
            if !matches!(alg, "ES256" | "ES256K") {
                return Err(token_err(kind, format!("unsupported credential alg {alg}")));
            }
            if kid != Some(ATPROTO_KEY_ID) && !kid.is_some_and(|k| k.ends_with(ATPROTO_KEY_ID)) {
                return Err(token_err(kind, "space credential kid must be #atproto"));
            }
            let space = SpaceUri::parse(&claims.sub)
                .map_err(|_| token_err(kind, "credential sub must be a valid Space URI"))?;
            if claims.iss != space.authority {
                return Err(token_err(
                    kind,
                    "credential iss must match Space authority DID",
                ));
            }
            if claims.aud.is_some() {
                return Err(token_err(kind, "space credential must not carry aud"));
            }
            let Some(cnf_kid) = claims.cnf_kid.as_deref() else {
                return Err(token_err(kind, "space credential requires cnf.kid"));
            };
            decode_p256_did_key(cnf_kid)
                .map_err(|_| token_err(kind, "credential cnf.kid must be a P-256 did:key"))?;
            if lifetime > CREDENTIAL_MAX_LIFETIME_SECS {
                return Err(token_err(
                    kind,
                    format!(
                        "credential lifetime {lifetime}s exceeds {CREDENTIAL_MAX_LIFETIME_SECS}s"
                    ),
                ));
            }
        }
        SpaceTokenKind::ClientAttestation => {
            if alg != "ES256" {
                return Err(token_err(kind, "client attestation alg must be ES256"));
            }
            let Some(kid_val) = kid else {
                return Err(token_err(kind, "client attestation requires JOSE kid"));
            };
            if kid_val.is_empty()
                || kid_val.len() > 1024
                || kid_val.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(token_err(kind, "invalid client attestation JOSE kid"));
            }
            if claims.iss != claims.sub {
                return Err(token_err(kind, "client attestation iss must equal sub"));
            }
            let parsed_url = Url::parse(&claims.iss)
                .map_err(|_| token_err(kind, "client attestation iss must be a URL"))?;
            if parsed_url.scheme() != "https" || parsed_url.as_str() != claims.iss {
                return Err(token_err(
                    kind,
                    "client attestation iss must be a canonical https URL",
                ));
            }
            let Some(aud) = claims.aud.as_deref() else {
                return Err(token_err(kind, "client attestation requires aud"));
            };
            let Some(authority_did) = aud.strip_suffix("#atproto_pds") else {
                return Err(token_err(
                    kind,
                    "client attestation aud must end with #atproto_pds",
                ));
            };
            if !is_valid_did(authority_did) {
                return Err(token_err(
                    kind,
                    "client attestation aud authority must be a valid DID",
                ));
            }
            if lifetime > CLIENT_ATTESTATION_MAX_LIFETIME_SECS {
                return Err(token_err(kind, "client attestation lifetime exceeds 600s"));
            }
        }
    }
    Ok(())
}

fn validate_claims_timestamps(
    kind: SpaceTokenKind,
    claims: &SpaceTokenClaims,
    now_sec: u64,
) -> Result<()> {
    if now_sec == 0 {
        return Ok(());
    }
    let max_lead = match kind {
        SpaceTokenKind::ClientAttestation => EXPIRY_CLOCK_SKEW_SECS,
        SpaceTokenKind::Delegation | SpaceTokenKind::Credential => MAX_IAT_LEAD_SECS,
    };
    if claims.iat > now_sec.saturating_add(max_lead) {
        return Err(token_err(
            kind,
            "JWT iat is in the future beyond allowed lead",
        ));
    }
    let skew = match kind {
        SpaceTokenKind::Delegation => MAX_IAT_LEAD_SECS,
        SpaceTokenKind::Credential | SpaceTokenKind::ClientAttestation => EXPIRY_CLOCK_SKEW_SECS,
    };
    if now_sec > claims.exp.saturating_add(skew) {
        return Err(token_err(kind, "JWT is expired"));
    }
    Ok(())
}

fn is_valid_jti(jti: &str) -> bool {
    !jti.is_empty() && jti.len() <= MAX_JTI_BYTES && jti.bytes().all(|b| b > 0x20 && b != 0x7f)
}

fn token_err(kind: SpaceTokenKind, msg: impl Into<String>) -> SpacesError {
    let m = msg.into();
    match kind {
        SpaceTokenKind::Delegation => SpacesError::InvalidDelegationToken(m),
        SpaceTokenKind::Credential => SpacesError::InvalidSpaceCredential(m),
        SpaceTokenKind::ClientAttestation => SpacesError::InvalidClientAttestation(m),
    }
}
