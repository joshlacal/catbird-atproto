//! RFC 9180 HPKE Base-mode Export-only (`DHKEM(P-256, HKDF-SHA256)` `0x0010`, `HKDF-SHA256` `0x0001`,
//! `Export-only` `0xFFFF`, `info = "atproto-mac"`, `exporter_context = ""`, `L = 32`)
//! and `#atproto_kem` `did:key:zDn...` codec.

use crate::{Result, SpacesError};
use hkdf::Hkdf;
use multibase::Base;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::Sha256;

/// Multicodec varint prefix for compressed P-256 public keys (`0x1200` -> `[0x80, 0x24]`).
pub const P256_MULTICODEC_PREFIX: [u8; 2] = [0x80, 0x24];

/// RFC 9180 §4.1 suite ID for `DHKEM(P-256, HKDF-SHA256)` (`"KEM" || 0x0010`).
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x10";
/// RFC 9180 §5.1 suite ID for `(KEM=0x0010, KDF=0x0001, AEAD=0xFFFF)` (`"HPKE" || 0x0010 || 0x0001 || 0xFFFF`).
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\xff\xff";
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";
const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_MAC_INFO: &[u8] = b"atproto-mac";
const NSECRET: usize = 32;

pub type P256SecretKey = SecretKey;
pub type P256PublicKey = PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemEncapsulation {
    pub shared_secret: [u8; 32],
    pub key_share_did_key: String,
}

/// Encode a P-256 public key as a canonical `did:key:zDn...` (`base58btc([0x80, 0x24] || compressed_sec1)`).
pub fn encode_p256_did_key(public_key: &PublicKey) -> String {
    let compressed = public_key.to_encoded_point(true);
    let mut payload = Vec::with_capacity(2 + 33);
    payload.extend_from_slice(&P256_MULTICODEC_PREFIX);
    payload.extend_from_slice(compressed.as_bytes());
    format!("did:key:{}", multibase::encode(Base::Base58Btc, payload))
}

/// Decode a canonical `did:key:zDn...` compressed P-256 public key.
pub fn decode_p256_did_key(did_key: &str) -> Result<PublicKey> {
    let Some(encoded) = did_key.strip_prefix("did:key:") else {
        return Err(SpacesError::InvalidDidKey(
            "missing did:key: prefix".to_string(),
        ));
    };
    let (base, raw) = multibase::decode(encoded)
        .map_err(|e| SpacesError::InvalidDidKey(format!("multibase decode failed: {e}")))?;
    if base != Base::Base58Btc {
        return Err(SpacesError::InvalidDidKey(
            "did:key must use base58btc ('z')".to_string(),
        ));
    }
    if raw.len() != 35 || raw[..2] != P256_MULTICODEC_PREFIX {
        return Err(SpacesError::InvalidDidKey(
            "expected compressed P-256 multicodec prefix 0x80 0x24 (35 bytes)".to_string(),
        ));
    }
    let point = EncodedPoint::from_bytes(&raw[2..])
        .map_err(|e| SpacesError::InvalidDidKey(format!("invalid SEC1 point: {e}")))?;
    if !point.is_compressed() {
        return Err(SpacesError::InvalidDidKey(
            "P-256 did:key point must be compressed".to_string(),
        ));
    }
    Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))
        .ok_or_else(|| SpacesError::InvalidDidKey("point is not on P-256 curve".to_string()))
}

/// RFC 9180 HPKE Base-mode Export-only `SetupBaseS` + `Export("", 32)` using a fresh random P-256 keypair.
pub fn encapsulate_p256(author_kem_did_key: &str) -> Result<KemEncapsulation> {
    let sk_e = SecretKey::random(&mut rand::rngs::OsRng);
    encapsulate_p256_deterministic(author_kem_did_key, &sk_e)
}

/// Deterministic RFC 9180 HPKE Base-mode Export-only `SetupBaseS(pkR, "atproto-mac")` + `Export("", 32)`.
pub fn encapsulate_p256_deterministic(
    author_kem_did_key: &str,
    ephemeral_secret: &SecretKey,
) -> Result<KemEncapsulation> {
    let pk_r = decode_p256_did_key(author_kem_did_key)?;
    let pk_e = ephemeral_secret.public_key();

    let dh = diffie_hellman(ephemeral_secret.to_nonzero_scalar(), pk_r.as_affine());
    let enc_uncompressed = pk_e.to_encoded_point(false);
    let pk_rm_uncompressed = pk_r.to_encoded_point(false);

    let mut kem_context = Vec::with_capacity(65 + 65);
    kem_context.extend_from_slice(enc_uncompressed.as_bytes());
    kem_context.extend_from_slice(pk_rm_uncompressed.as_bytes());

    let shared_secret = derive_hpke_mac_secret(dh.raw_secret_bytes(), &kem_context)?;
    Ok(KemEncapsulation {
        shared_secret,
        key_share_did_key: encode_p256_did_key(&pk_e),
    })
}

/// RFC 9180 HPKE Base-mode Export-only `SetupBaseR(enc, skR, "atproto-mac")` + `Export("", 32)`
/// where `enc` is encoded as `keyShare` `did:key:zDn...` on the wire and expanded to uncompressed
/// 65-byte SEC1 inside `kem_context` per RFC 9180 §7.1.1.
pub fn decapsulate_p256(secret: &SecretKey, key_share_did_key: &str) -> Result<[u8; 32]> {
    let pk_e = decode_p256_did_key(key_share_did_key)?;
    let pk_r = secret.public_key();

    let dh = diffie_hellman(secret.to_nonzero_scalar(), pk_e.as_affine());
    let enc_uncompressed = pk_e.to_encoded_point(false);
    let pk_rm_uncompressed = pk_r.to_encoded_point(false);

    let mut kem_context = Vec::with_capacity(65 + 65);
    kem_context.extend_from_slice(enc_uncompressed.as_bytes());
    kem_context.extend_from_slice(pk_rm_uncompressed.as_bytes());

    derive_hpke_mac_secret(dh.raw_secret_bytes(), &kem_context)
}

fn derive_hpke_mac_secret(dh: &[u8], kem_context: &[u8]) -> Result<[u8; 32]> {
    // 1. DHKEM(P-256, HKDF-SHA256) ExtractAndExpand -> 32-byte kem_shared_secret
    let (_, eae_prk) = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh);
    let kem_shared_secret = labeled_expand(KEM_SUITE_ID, &eae_prk, b"shared_secret", kem_context)?;

    // 2. HPKE Base-mode Export-only KeySchedule (AEAD = 0xFFFF, info = "atproto-mac", exporter_context = "")
    let (psk_id_hash, _) = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"");
    let (info_hash, _) = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", HPKE_MAC_INFO);

    let mut ks_context = [0u8; 1 + 32 + 32];
    ks_context[0] = HPKE_MODE_BASE;
    ks_context[1..33].copy_from_slice(&psk_id_hash);
    ks_context[33..65].copy_from_slice(&info_hash);

    let (_, secret_prk) = labeled_extract(HPKE_SUITE_ID, &kem_shared_secret, b"secret", b"");
    let exporter_secret = labeled_expand(HPKE_SUITE_ID, &secret_prk, b"exp", &ks_context)?;
    let exporter_prk = Hkdf::<Sha256>::from_prk(&exporter_secret)
        .map_err(|e| SpacesError::Kem(format!("HKDF from_prk failed: {e}")))?;

    labeled_expand(HPKE_SUITE_ID, &exporter_prk, b"sec", b"")
}

fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> ([u8; 32], Hkdf<Sha256>) {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut prk_arr = [0u8; 32];
    prk_arr.copy_from_slice(&prk);
    (prk_arr, hkdf)
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &Hkdf<Sha256>,
    label: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let mut labeled_info = Vec::with_capacity(
        2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&(NSECRET as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let mut out = [0u8; 32];
    prk.expand(&labeled_info, &mut out)
        .map_err(|e| SpacesError::Kem(format!("HKDF-Expand failed: {e}")))?;
    Ok(out)
}
