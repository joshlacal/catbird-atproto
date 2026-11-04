//! WASM-compatible `did:plc` and `did:web` DID document resolver for ATProto Spaces.
//!
//! Extracts `#atproto` signing keys (`ES256` / `ES256K`), `#atproto_kem` HPKE `did:key:zDn...`
//! keys, and `#atproto_pds` / `#atproto_space_host` / `#atproto_mls` service endpoints.

use crate::kem::{decode_p256_did_key, encode_p256_did_key};
use crate::sync_engine::SpaceTransport;
use crate::tokens::{SpaceKeyResolver, SpaceVerifyingKey};
use crate::{is_valid_did, Result, SpacesError};
use http::{HeaderMap, Method};
use multibase::Base;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::RwLock;
use web_time::{Duration, Instant};

pub const DEFAULT_PLC_DIRECTORY_URL: &str = "https://plc.directory";
pub const DEFAULT_DID_CACHE_TTL_SECS: u64 = 300;
const K256_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDocument {
    pub id: String,
    pub atproto_key: Option<SpaceVerifyingKey>,
    pub atproto_kem_did_key: Option<String>,
    pub services: BTreeMap<String, String>, // fragment (e.g. "#atproto_pds") -> endpoint URL
}

impl DidDocument {
    pub fn with_keys(
        id: &str,
        atproto_key: SpaceVerifyingKey,
        atproto_kem_did_key: Option<String>,
        pds_endpoint: &str,
    ) -> Self {
        let mut services = BTreeMap::new();
        services.insert(
            "#atproto_pds".to_string(),
            pds_endpoint.trim_end_matches('/').to_string(),
        );
        Self {
            id: id.to_string(),
            atproto_key: Some(atproto_key),
            atproto_kem_did_key,
            services,
        }
    }

    pub fn pds_endpoint(&self) -> Result<&str> {
        self.services
            .get("#atproto_pds")
            .map(String::as_str)
            .ok_or_else(|| {
                SpacesError::DidResolution(format!("DID {} has no #atproto_pds service", self.id))
            })
    }

    pub fn space_host_endpoint(&self) -> Result<&str> {
        self.services
            .get("#atproto_space_host")
            .or_else(|| self.services.get("#atproto_pds"))
            .map(String::as_str)
            .ok_or_else(|| {
                SpacesError::DidResolution(format!(
                    "DID {} has neither #atproto_space_host nor #atproto_pds service",
                    self.id
                ))
            })
    }

    pub fn service_endpoint(&self, fragment: &str) -> Option<&str> {
        let normalized = if fragment.starts_with('#') {
            fragment.to_string()
        } else {
            format!("#{fragment}")
        };
        self.services.get(&normalized).map(String::as_str)
    }

    pub fn parse_json(expected_did: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 256 * 1024 {
            return Err(SpacesError::DidResolution(
                "DID document exceeds 256 KiB".into(),
            ));
        }
        let wire: WireDidDoc = serde_json::from_slice(bytes)
            .map_err(|e| SpacesError::DidResolution(format!("invalid DID document JSON: {e}")))?;
        if wire.id != expected_did {
            return Err(SpacesError::DidResolution(format!(
                "DID document id {:?} != expected {:?}",
                wire.id, expected_did
            )));
        }

        let mut atproto_key: Option<SpaceVerifyingKey> = None;
        let mut atproto_kem_did_key: Option<String> = None;

        for vm in wire.verification_method {
            let frag = extract_fragment(&wire.id, &vm.id);
            match frag {
                Some("#atproto") if atproto_key.is_none() => {
                    atproto_key = Some(parse_verification_key(&vm)?);
                }
                Some("#atproto_kem") if atproto_kem_did_key.is_none() => {
                    atproto_kem_did_key = Some(parse_kem_did_key(&vm)?);
                }
                _ => {}
            }
        }

        let mut services = BTreeMap::new();
        for svc in wire.service {
            if let Some(frag) = extract_fragment(&wire.id, &svc.id) {
                if let Some(endpoint) = svc.service_endpoint.as_str() {
                    let trimmed = endpoint.trim_end_matches('/');
                    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
                        services.insert(frag.to_string(), trimmed.to_string());
                    }
                }
            }
        }

        Ok(Self {
            id: wire.id,
            atproto_key,
            atproto_kem_did_key,
            services,
        })
    }
}

#[async_trait::async_trait(?Send)]
pub trait SpaceDidResolver: SpaceKeyResolver {
    async fn resolve_did(&self, did: &str, force_refresh: bool) -> Result<DidDocument>;
}

/// Deterministic in-memory DID resolver for unit and integration tests.
#[derive(Default)]
pub struct StaticDidResolver {
    docs: RwLock<BTreeMap<String, DidDocument>>,
}

impl StaticDidResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, doc: DidDocument) {
        self.docs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(doc.id.clone(), doc);
    }
}

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for StaticDidResolver {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        _force_refresh: bool,
    ) -> Result<SpaceVerifyingKey> {
        let did = did_or_issuer.split('#').next().unwrap_or(did_or_issuer);
        let guard = self.docs.read().unwrap_or_else(|e| e.into_inner());
        let doc = guard.get(did).ok_or_else(|| {
            SpacesError::DidResolution(format!("DID not found in StaticDidResolver: {did}"))
        })?;
        doc.atproto_key
            .clone()
            .ok_or_else(|| SpacesError::DidResolution(format!("DID {did} has no #atproto key")))
    }
}

#[async_trait::async_trait(?Send)]
impl SpaceDidResolver for StaticDidResolver {
    async fn resolve_did(&self, did: &str, _force_refresh: bool) -> Result<DidDocument> {
        let guard = self.docs.read().unwrap_or_else(|e| e.into_inner());
        guard.get(did).cloned().ok_or_else(|| {
            SpacesError::DidResolution(format!("DID not found in StaticDidResolver: {did}"))
        })
    }
}

/// HTTP-backed `did:plc` + `did:web` resolver over any `SpaceTransport` (WASM `fetch` or `reqwest`).
pub struct HttpDidResolver<T: SpaceTransport> {
    transport: T,
    plc_directory_url: String,
    allow_insecure_http_did_web: bool,
    ttl: Duration,
    cache: RwLock<BTreeMap<String, (Instant, DidDocument)>>,
}

impl<T: SpaceTransport> HttpDidResolver<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
            allow_insecure_http_did_web: false,
            ttl: Duration::from_secs(DEFAULT_DID_CACHE_TTL_SECS),
            cache: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn with_plc_directory_url(mut self, url: impl Into<String>) -> Self {
        self.plc_directory_url = url.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_allow_insecure_http_did_web(mut self, allow: bool) -> Self {
        self.allow_insecure_http_did_web = allow;
        self
    }

    fn resolution_url(&self, did: &str) -> Result<String> {
        if !is_valid_did(did) {
            return Err(SpacesError::InvalidDid(did.to_string()));
        }
        if did.starts_with("did:plc:") {
            return Ok(format!("{}/{did}", self.plc_directory_url));
        }
        if let Some(web_specific) = did.strip_prefix("did:web:") {
            if web_specific.contains(':')
                && !web_specific.contains("%3A")
                && !web_specific.contains("%3a")
            {
                return Err(SpacesError::InvalidDid(
                    "subpath did:web identifiers are not supported in ATProto".into(),
                ));
            }
            let host = web_specific.replace("%3A", ":").replace("%3a", ":");
            if !self.allow_insecure_http_did_web && is_loopback_or_private_host(&host) {
                return Err(SpacesError::DidResolution(format!(
                    "refusing loopback/private did:web host: {host}"
                )));
            }
            let scheme = if self.allow_insecure_http_did_web
                && (host.starts_with("localhost") || host.starts_with("127."))
            {
                "http"
            } else {
                "https"
            };
            return Ok(format!("{scheme}://{host}/.well-known/did.json"));
        }
        Err(SpacesError::DidResolution(format!(
            "unsupported DID method: {did}"
        )))
    }
}

#[async_trait::async_trait(?Send)]
impl<T: SpaceTransport> SpaceKeyResolver for HttpDidResolver<T> {
    async fn resolve_atproto_key(
        &self,
        did_or_issuer: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey> {
        let did = did_or_issuer.split('#').next().unwrap_or(did_or_issuer);
        let doc = self.resolve_did(did, force_refresh).await?;
        doc.atproto_key.ok_or_else(|| {
            SpacesError::DidResolution(format!("DID {did} has no #atproto verification key"))
        })
    }
}

#[async_trait::async_trait(?Send)]
impl<T: SpaceTransport> SpaceDidResolver for HttpDidResolver<T> {
    async fn resolve_did(&self, did: &str, force_refresh: bool) -> Result<DidDocument> {
        if !force_refresh {
            let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((expires_at, doc)) = guard.get(did) {
                if Instant::now() < *expires_at {
                    return Ok(doc.clone());
                }
            }
        }
        let url = self.resolution_url(did)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/did+ld+json, application/json"),
        );
        let resp = self
            .transport
            .send_http(Method::GET, &url, &headers, None)
            .await?;
        if resp.status != 200 {
            return Err(SpacesError::DidResolution(format!(
                "DID resolution HTTP {} for {did}",
                resp.status
            )));
        }
        let doc = DidDocument::parse_json(did, &resp.body)?;
        self.cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(did.to_string(), (Instant::now() + self.ttl, doc.clone()));
        Ok(doc)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireDidDoc {
    id: String,
    #[serde(default)]
    verification_method: Vec<WireVerificationMethod>,
    #[serde(default)]
    service: Vec<WireService>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireVerificationMethod {
    id: String,
    #[serde(rename = "type")]
    method_type: String,
    #[serde(default)]
    controller: Option<String>,
    #[serde(default)]
    public_key_multibase: Option<String>,
    #[serde(default)]
    public_key_jwk: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireService {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    service_endpoint: serde_json::Value,
}

fn extract_fragment<'a>(did: &str, method_id: &'a str) -> Option<&'a str> {
    if method_id.starts_with('#') {
        Some(method_id)
    } else {
        method_id
            .strip_prefix(did)
            .filter(|rest| rest.starts_with('#'))
    }
}

fn parse_verification_key(vm: &WireVerificationMethod) -> Result<SpaceVerifyingKey> {
    if let Some(mb) = &vm.public_key_multibase {
        let (_, raw) = multibase::decode(mb).map_err(|e| {
            SpacesError::DidResolution(format!("invalid #atproto publicKeyMultibase: {e}"))
        })?;
        if raw.len() >= 35 && raw[..2] == [0x80, 0x24] {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..]).map_err(|e| {
                SpacesError::DidResolution(format!("invalid P-256 #atproto key: {e}"))
            })?;
            return Ok(SpaceVerifyingKey::P256(vk));
        }
        if raw.len() >= 35 && raw[..2] == K256_MULTICODEC_PREFIX {
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..]).map_err(|e| {
                SpacesError::DidResolution(format!("invalid secp256k1 #atproto key: {e}"))
            })?;
            return Ok(SpaceVerifyingKey::K256(vk));
        }
        return Err(SpacesError::DidResolution(
            "unsupported multicodec prefix on #atproto key".into(),
        ));
    }
    if let Some(jwk_val) = &vm.public_key_jwk {
        let jwk_str = serde_json::to_string(jwk_val)
            .map_err(|e| SpacesError::DidResolution(format!("JWK serialize: {e}")))?;
        let crv = jwk_val
            .get("crv")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        return match crv {
            // `FromStr` on these key types parses PEM, never JWK.
            "P-256" => {
                let pk = p256::PublicKey::from_jwk_str(&jwk_str)
                    .map_err(|e| SpacesError::DidResolution(format!("invalid P-256 JWK: {e}")))?;
                Ok(SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(
                    &pk,
                )))
            }
            "secp256k1" => {
                let pk = k256::PublicKey::from_jwk_str(&jwk_str).map_err(|e| {
                    SpacesError::DidResolution(format!("invalid secp256k1 JWK: {e}"))
                })?;
                Ok(SpaceVerifyingKey::K256(k256::ecdsa::VerifyingKey::from(
                    &pk,
                )))
            }
            other => Err(SpacesError::DidResolution(format!(
                "unsupported #atproto JWK curve: {other}"
            ))),
        };
    }
    Err(SpacesError::DidResolution(
        "#atproto verificationMethod lacks publicKeyMultibase and publicKeyJwk".into(),
    ))
}

fn parse_kem_did_key(vm: &WireVerificationMethod) -> Result<String> {
    if let Some(mb) = &vm.public_key_multibase {
        let did_key = format!("did:key:{mb}");
        let pk = decode_p256_did_key(&did_key)?;
        return Ok(encode_p256_did_key(&pk));
    }
    if let Some(jwk_val) = &vm.public_key_jwk {
        let jwk_str = serde_json::to_string(jwk_val)
            .map_err(|e| SpacesError::DidResolution(format!("KEM JWK serialize: {e}")))?;
        let pk = p256::PublicKey::from_jwk_str(&jwk_str)
            .map_err(|e| SpacesError::DidResolution(format!("invalid P-256 KEM JWK: {e}")))?;
        return Ok(encode_p256_did_key(&pk));
    }
    if vm.id.starts_with("did:key:zDn") {
        let pk = decode_p256_did_key(&vm.id)?;
        return Ok(encode_p256_did_key(&pk));
    }
    let (_, raw) = multibase::decode(vm.public_key_multibase.as_deref().unwrap_or_default())
        .map_err(|_| SpacesError::DidResolution("missing #atproto_kem public key".into()))?;
    if raw.starts_with(&[0x80, 0x24]) {
        return Ok(format!(
            "did:key:{}",
            multibase::encode(Base::Base58Btc, raw)
        ));
    }
    Err(SpacesError::DidResolution(
        "invalid #atproto_kem verificationMethod".into(),
    ))
}

fn is_loopback_or_private_host(host_with_optional_port: &str) -> bool {
    let host = host_with_optional_port
        .split(':')
        .next()
        .unwrap_or(host_with_optional_port)
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `JsonWebKey2020` keys are read as JWK. A key's PEM-only `FromStr`
    /// rejects every JWK as "crypto error" (e2e federation_spaces_full_cutover
    /// `native_space_did_document`).
    #[test]
    fn json_web_key_2020_atproto_and_kem_keys_parse() {
        let did = "did:plc:alicesdkfederated24chars";
        let signing = p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key();
        let kem = p256::SecretKey::from_slice(&[9; 32]).unwrap().public_key();
        let k256 = k256::SecretKey::from_slice(&[5; 32]).unwrap().public_key();
        let jwk = |text: String| serde_json::from_str::<serde_json::Value>(&text).unwrap();
        let method = |fragment: &str, key: serde_json::Value| {
            serde_json::json!({
                "id": format!("{did}{fragment}"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": key,
            })
        };
        let document = |atproto: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "id": did,
                "verificationMethod": [
                    method("#atproto", atproto),
                    method("#atproto_kem", jwk(kem.to_jwk_string())),
                ],
                "service": [],
            }))
            .unwrap()
        };

        let parsed = DidDocument::parse_json(did, &document(jwk(signing.to_jwk_string()))).unwrap();
        assert_eq!(
            parsed.atproto_key,
            Some(SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(
                &signing
            )))
        );
        assert_eq!(parsed.atproto_kem_did_key, Some(encode_p256_did_key(&kem)));
        let parsed = DidDocument::parse_json(did, &document(jwk(k256.to_jwk_string()))).unwrap();
        assert_eq!(
            parsed.atproto_key,
            Some(SpaceVerifyingKey::K256(k256::ecdsa::VerifyingKey::from(
                &k256
            )))
        );
    }
}
