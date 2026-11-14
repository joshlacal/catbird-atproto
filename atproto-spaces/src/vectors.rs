//! Deterministic cross-language conformance vectors (`atproto_spaces_v1.json` and `atproto_spaces_v2.json`)
//! shared across Rust (`atproto-spaces` + `circle-appview` + `catbird-mls` + `mls-ds`),
//! Swift client (`Petrel`), and Swift PDS (`Swan`).

use crate::http_signature::sign_credential_request;
use crate::kem::{encapsulate_p256_deterministic, encode_p256_did_key};
use crate::lthash::{compute_dagcbor_cid, compute_record_element_hash, LtHash};
use crate::mac::{
    format_accept_signature, sign_commit_mac, sign_record_mac, MacProfile, DEFAULT_MAC_LABEL,
};
use crate::star::{write_star_repo, StarRecordEntry};
use crate::tokens::{
    mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind, ATPROTO_KEY_ID,
};
use crate::{Result, SpaceBlobLocator, SpaceUri, SpacesError};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ipld_core::ipld::Ipld;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// P-256 curve order `n` (big-endian 32 bytes).
const P256_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtprotoSpacesVectorsV1 {
    pub version: u32,
    pub lthash: LtHashVectors,
    pub kem_p256: KemP256Vector,
    pub commit_mac: CommitMacVector,
    pub record_mac: RecordMacVector,
    pub rfc9421_low_s: Rfc9421Vector,
    pub rfc9421_high_s: Rfc9421Vector,
    pub delegation_jwt_did_plc: DelegationJwtVector,
    pub credential_jwt_did_web: CredentialJwtVector,
    pub star_repo: StarRepoVectors,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtprotoSpacesVectorsV2 {
    pub version: u32,
    pub lthash: LtHashVectors,
    pub kem_p256: KemP256Vector,
    pub hpke_rfc9180_export: HpkeRfc9180ExportVector,
    pub commit_mac: CommitMacVector,
    pub record_mac: RecordMacVector,
    pub rfc9421_low_s: Rfc9421Vector,
    pub rfc9421_high_s: Rfc9421Vector,
    pub delegation_jwt_did_plc: DelegationJwtVector,
    pub credential_jwt_did_web: CredentialJwtVector,
    pub star_repo: StarRepoVectors,
    pub star_v02_cid_link: StarCidLinkVector,
    pub uri_and_blob_locator: UriAndBlobLocatorVector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtHashRecordFixture {
    pub collection: String,
    pub rkey: String,
    pub path: String,
    pub dagcbor_hex: String,
    pub cid: String,
    pub cid_bytes_hex: String,
    pub element_key: String,
    pub element_hash_first32_hex: String,
    pub element_hash_sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtHashVectors {
    pub record_a: LtHashRecordFixture,
    pub record_b: LtHashRecordFixture,
    pub empty_commitment_hex: String,
    pub only_a_commitment_hex: String,
    pub only_b_commitment_hex: String,
    pub combined_ab_commitment_hex: String,
    pub after_remove_a_commitment_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemP256Vector {
    pub author_secret_hex: String,
    pub author_kem_did_key: String,
    pub ephemeral_secret_hex: String,
    pub key_share_did_key: String,
    pub shared_secret_hex: String,
    pub want_commit_mac_header: String,
    pub want_record_mac_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeRfc9180ExportVector {
    pub sender_secret_hex: String,
    pub author_secret_hex: String,
    pub author_kem_did_key: String,
    pub key_share_did_key: String,
    pub shared_secret_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMacVector {
    pub shared_secret_hex: String,
    pub space: String,
    pub repo: String,
    pub rev: String,
    pub data_hex: String,
    pub mac_hex: String,
    pub covered_header: String,
    pub signature_input: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMacVector {
    pub shared_secret_hex: String,
    pub record_uri: String,
    pub cid: String,
    pub cid_bytes_hex: String,
    pub mac_hex: String,
    pub covered_header: String,
    pub signature_input: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc9421Vector {
    pub cnf_secret_hex: String,
    pub cnf_did_key: String,
    pub credential_jwt: String,
    pub audience_did: String,
    pub created: u64,
    pub nonce: String,
    pub authorization: String,
    pub atproto_space_audience: String,
    pub signature_input: String,
    pub signature: String,
    pub raw_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationJwtVector {
    pub signer_secret_hex: String,
    pub signer_did_key: String,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub verify_now_sec: u64,
    pub jwt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialJwtVector {
    pub authority_secret_hex: String,
    pub authority_did_key: String,
    pub iss: String,
    pub sub: String,
    pub cnf_kid: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub verify_now_sec: u64,
    pub jwt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarRepoVectors {
    pub empty_swan_space: String,
    pub empty_swan_repo: String,
    pub empty_swan_rev: String,
    pub empty_swan_archive_hex: String,
    pub populated_space: String,
    pub populated_repo: String,
    pub populated_rev: String,
    pub populated_data_hex: String,
    pub populated_archive_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarCidLinkVector {
    pub space: String,
    pub repo: String,
    pub rev: String,
    pub archive_base64: String,
    pub expected_path: String,
    pub expected_cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UriAndBlobLocatorVector {
    pub canonical_space_uri: String,
    pub hedged_at_space: String,
    pub hedged_at_slash_space: String,
    pub repo: String,
    pub cid: String,
    pub canonical_blob_locator: String,
    pub legacy_blob_locator: String,
}

/// Generate the canonical deterministic `atproto_spaces_v1` vector suite (November 12 wire format,
/// byte-identical to `Petrel/Tests/PetrelTests/Vectors/atproto_spaces_v1.json`).
pub fn generate_v1_vectors() -> Result<AtprotoSpacesVectorsV1> {
    let space_str = "at://did:web:ds.catbird.blue/space/blue.catbird.mlsChat/3l2aaaaaaaaaa";
    let space = SpaceUri::parse(space_str)?;
    let alice_did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    let pds_did = "did:plc:z72i7hdynmk6r22z27h6tvur";

    // 1. LtHash records (strictly ascending path order: "app.bsky.feed.post/..." < "blue.catbird.mlsChat.message/...")
    let mut map_a = BTreeMap::new();
    map_a.insert(
        "$type".to_string(),
        Ipld::String("app.bsky.feed.post".to_string()),
    );
    map_a.insert("text".to_string(), Ipld::String("hello space".to_string()));
    let bytes_a = serde_ipld_dagcbor::to_vec(&Ipld::Map(map_a))
        .map_err(|e| SpacesError::StarFormat(e.to_string()))?;
    let cid_a = compute_dagcbor_cid(&bytes_a);
    let rkey_a = "3l2aaaaaaaaab";
    let elem_a = compute_record_element_hash("app.bsky.feed.post", rkey_a, &cid_a);

    let mut map_b = BTreeMap::new();
    map_b.insert(
        "$type".to_string(),
        Ipld::String("blue.catbird.mlsChat.message".to_string()),
    );
    map_b.insert(
        "ciphertext".to_string(),
        Ipld::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
    );
    map_b.insert("epoch".to_string(), Ipld::Integer(1));
    let bytes_b = serde_ipld_dagcbor::to_vec(&Ipld::Map(map_b))
        .map_err(|e| SpacesError::StarFormat(e.to_string()))?;
    let cid_b = compute_dagcbor_cid(&bytes_b);
    let rkey_b = "3l2aaaaaaaaac";
    let elem_b = compute_record_element_hash("blue.catbird.mlsChat.message", rkey_b, &cid_b);

    let empty_lt = LtHash::empty();
    let mut only_a = LtHash::empty();
    only_a.add(&elem_a);
    let mut only_b = LtHash::empty();
    only_b.add(&elem_b);
    let mut combined_ab = LtHash::empty();
    combined_ab.add(&elem_a);
    combined_ab.add(&elem_b);
    let mut after_remove_a = combined_ab.clone();
    after_remove_a.remove(&elem_a);

    let lthash = LtHashVectors {
        record_a: LtHashRecordFixture {
            collection: "app.bsky.feed.post".to_string(),
            rkey: rkey_a.to_string(),
            path: format!("app.bsky.feed.post/{rkey_a}"),
            dagcbor_hex: hex_encode(&bytes_a),
            cid: cid_a.to_string(),
            cid_bytes_hex: hex_encode(&cid_a.to_bytes()),
            element_key: format!("app.bsky.feed.post/{rkey_a}/{cid_a}"),
            element_hash_first32_hex: hex_encode(&elem_a[..32]),
            element_hash_sha256_hex: hex_encode(&Sha256::digest(elem_a)),
        },
        record_b: LtHashRecordFixture {
            collection: "blue.catbird.mlsChat.message".to_string(),
            rkey: rkey_b.to_string(),
            path: format!("blue.catbird.mlsChat.message/{rkey_b}"),
            dagcbor_hex: hex_encode(&bytes_b),
            cid: cid_b.to_string(),
            cid_bytes_hex: hex_encode(&cid_b.to_bytes()),
            element_key: format!("blue.catbird.mlsChat.message/{rkey_b}/{cid_b}"),
            element_hash_first32_hex: hex_encode(&elem_b[..32]),
            element_hash_sha256_hex: hex_encode(&Sha256::digest(elem_b)),
        },
        empty_commitment_hex: hex_encode(&empty_lt.commitment()),
        only_a_commitment_hex: hex_encode(&only_a.commitment()),
        only_b_commitment_hex: hex_encode(&only_b.commitment()),
        combined_ab_commitment_hex: hex_encode(&combined_ab.commitment()),
        after_remove_a_commitment_hex: hex_encode(&after_remove_a.commitment()),
    };

    // 2. KEM P-256 (HPKE Base-mode Export-only)
    let author_sk_bytes: [u8; 32] = [0x11; 32];
    let eph_sk_bytes: [u8; 32] = [0x22; 32];
    let author_sk = SecretKey::from_slice(&author_sk_bytes)
        .map_err(|e| SpacesError::Kem(format!("author_sk: {e}")))?;
    let eph_sk = SecretKey::from_slice(&eph_sk_bytes)
        .map_err(|e| SpacesError::Kem(format!("eph_sk: {e}")))?;
    let author_kem_did_key = encode_p256_did_key(&author_sk.public_key());
    let encap = encapsulate_p256_deterministic(&author_kem_did_key, &eph_sk)?;
    let want_commit_mac_header =
        format_accept_signature(MacProfile::Commit, &encap.key_share_did_key)?;
    let want_record_mac_header =
        format_accept_signature(MacProfile::Record, &encap.key_share_did_key)?;

    // 3. Commit MAC (RFC 9421 / RFC 9651 structured-field MAC)
    let data_32 = combined_ab.commitment();
    let rev = rkey_b;
    let (commit_headers, commit_mac_bytes) = sign_commit_mac(
        &encap.shared_secret,
        &encap.key_share_did_key,
        DEFAULT_MAC_LABEL,
        space_str,
        alice_did,
        rev,
        &data_32,
    )?;
    let commit_mac = CommitMacVector {
        shared_secret_hex: hex_encode(&encap.shared_secret),
        space: space_str.to_string(),
        repo: alice_did.to_string(),
        rev: rev.to_string(),
        data_hex: hex_encode(&data_32),
        mac_hex: hex_encode(&commit_mac_bytes),
        covered_header: commit_headers.covered_header,
        signature_input: commit_headers.signature_input,
        signature: commit_headers.signature,
    };

    // 4. Record MAC (RFC 9421 / RFC 9651 structured-field MAC)
    let record_uri = space.record_uri(alice_did, "blue.catbird.mlsChat.message", rkey_b)?;
    let cid_b_str = cid_b.to_string();
    let cid_b_bytes = cid_b.to_bytes();
    let (record_headers, record_mac_bytes) = sign_record_mac(
        &encap.shared_secret,
        &encap.key_share_did_key,
        DEFAULT_MAC_LABEL,
        &record_uri,
        &cid_b_str,
    )?;
    let record_mac = RecordMacVector {
        shared_secret_hex: hex_encode(&encap.shared_secret),
        record_uri,
        cid: cid_b_str,
        cid_bytes_hex: hex_encode(&cid_b_bytes),
        mac_hex: hex_encode(&record_mac_bytes),
        covered_header: record_headers.covered_header,
        signature_input: record_headers.signature_input,
        signature: record_headers.signature,
    };

    let kem_p256 = KemP256Vector {
        author_secret_hex: hex_encode(&author_sk_bytes),
        author_kem_did_key,
        ephemeral_secret_hex: hex_encode(&eph_sk_bytes),
        key_share_did_key: encap.key_share_did_key,
        shared_secret_hex: hex_encode(&encap.shared_secret),
        want_commit_mac_header,
        want_record_mac_header,
    };

    // 5. Delegation JWT (did:plc user -> did:web Space authority) & Credential JWT (did:web Space authority)
    let user_signing_bytes: [u8; 32] = [0x33; 32];
    let authority_signing_bytes: [u8; 32] = [0x44; 32];
    let cnf_secret_bytes: [u8; 32] = [0x55; 32];

    let user_sk = SecretKey::from_slice(&user_signing_bytes)
        .map_err(|e| SpacesError::InvalidDelegationToken(e.to_string()))?;
    let authority_sk = SecretKey::from_slice(&authority_signing_bytes)
        .map_err(|e| SpacesError::InvalidSpaceCredential(e.to_string()))?;
    let cnf_sk = SecretKey::from_slice(&cnf_secret_bytes)
        .map_err(|e| SpacesError::BadSpaceSignature(e.to_string()))?;

    let user_signing_key = SpaceSigningKey::from_p256_secret(&user_sk, ATPROTO_KEY_ID);
    let authority_signing_key = SpaceSigningKey::from_p256_secret(&authority_sk, ATPROTO_KEY_ID);
    let cnf_did_key = encode_p256_did_key(&cnf_sk.public_key());

    let base_now: u64 = 1_793_462_400; // 2026-10-31T16:00:00Z
    let delegation_claims = SpaceTokenClaims {
        iss: alice_did.to_string(),
        sub: space_str.to_string(),
        aud: Some(format!("{}#atproto_pds", space.authority)),
        iat: base_now,
        exp: base_now + 60,
        jti: "delegation-vector-jti-0001".to_string(),
        cnf_kid: None,
    };
    let delegation_jwt = mint_space_token(
        SpaceTokenKind::Delegation,
        &user_signing_key,
        &delegation_claims,
    )?;
    let delegation_jwt_did_plc = DelegationJwtVector {
        signer_secret_hex: hex_encode(&user_signing_bytes),
        signer_did_key: encode_p256_did_key(&user_sk.public_key()),
        iss: delegation_claims.iss,
        sub: delegation_claims.sub,
        aud: delegation_claims.aud.unwrap(),
        iat: delegation_claims.iat,
        exp: delegation_claims.exp,
        jti: delegation_claims.jti,
        verify_now_sec: base_now + 10,
        jwt: delegation_jwt,
    };

    let credential_claims = SpaceTokenClaims {
        iss: space.authority.clone(),
        sub: space_str.to_string(),
        aud: None,
        iat: base_now,
        exp: base_now + 600,
        jti: "credential-vector-jti-0001".to_string(),
        cnf_kid: Some(cnf_did_key.clone()),
    };
    let credential_jwt = mint_space_token(
        SpaceTokenKind::Credential,
        &authority_signing_key,
        &credential_claims,
    )?;
    let credential_jwt_did_web = CredentialJwtVector {
        authority_secret_hex: hex_encode(&authority_signing_bytes),
        authority_did_key: encode_p256_did_key(&authority_sk.public_key()),
        iss: credential_claims.iss,
        sub: credential_claims.sub,
        cnf_kid: cnf_did_key.clone(),
        iat: credential_claims.iat,
        exp: credential_claims.exp,
        jti: credential_claims.jti,
        verify_now_sec: base_now + 10,
        jwt: credential_jwt.clone(),
    };

    // 6. RFC 9421 Low-S and WebCrypto High-S vectors
    let nonce = "vector-nonce-0001";
    let signed_headers =
        sign_credential_request(&cnf_sk, &credential_jwt, pds_did, base_now, nonce)?;
    let low_s_b64 = signed_headers
        .signature
        .strip_prefix("atproto-space-credential=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| SpacesError::BadSpaceSignature("unexpected signature format".into()))?;
    let low_s_raw = BASE64_STANDARD
        .decode(low_s_b64)
        .map_err(|e| SpacesError::BadSpaceSignature(e.to_string()))?;
    let low_s_arr: [u8; 64] = low_s_raw
        .as_slice()
        .try_into()
        .map_err(|_| SpacesError::BadSpaceSignature("expected 64-byte sig".into()))?;
    let high_s_arr = flip_p256_signature_s(&low_s_arr);
    let high_s_signature = format!(
        "atproto-space-credential=:{}:",
        BASE64_STANDARD.encode(high_s_arr)
    );

    let rfc9421_low_s = Rfc9421Vector {
        cnf_secret_hex: hex_encode(&cnf_secret_bytes),
        cnf_did_key: cnf_did_key.clone(),
        credential_jwt: credential_jwt.clone(),
        audience_did: pds_did.to_string(),
        created: base_now,
        nonce: nonce.to_string(),
        authorization: signed_headers.authorization.clone(),
        atproto_space_audience: signed_headers.atproto_space_audience.clone(),
        signature_input: signed_headers.signature_input.clone(),
        signature: signed_headers.signature,
        raw_signature_hex: hex_encode(&low_s_arr),
    };

    let rfc9421_high_s = Rfc9421Vector {
        cnf_secret_hex: hex_encode(&cnf_secret_bytes),
        cnf_did_key,
        credential_jwt,
        audience_did: pds_did.to_string(),
        created: base_now,
        nonce: nonce.to_string(),
        authorization: signed_headers.authorization,
        atproto_space_audience: signed_headers.atproto_space_audience,
        signature_input: signed_headers.signature_input,
        signature: high_s_signature,
        raw_signature_hex: hex_encode(&high_s_arr),
    };

    // 7. STAR v0.2 repo vectors (empty Swan fixture + populated 2-record fixture)
    let empty_swan_space = "at://did:plc:alice/space/app.bsky.bookmarks/self";
    let empty_swan_repo = "did:plc:alice";
    let empty_swan_rev = "2222222222222";
    let empty_archive = write_star_repo(
        empty_swan_space,
        empty_swan_repo,
        empty_swan_rev,
        &empty_lt.commitment(),
        &[],
    )?;

    let populated_archive = write_star_repo(
        space_str,
        alice_did,
        rev,
        &data_32,
        &[
            StarRecordEntry {
                path: format!("app.bsky.feed.post/{rkey_a}"),
                record_dagcbor: bytes_a,
            },
            StarRecordEntry {
                path: format!("blue.catbird.mlsChat.message/{rkey_b}"),
                record_dagcbor: bytes_b,
            },
        ],
    )?;

    let star_repo = StarRepoVectors {
        empty_swan_space: empty_swan_space.to_string(),
        empty_swan_repo: empty_swan_repo.to_string(),
        empty_swan_rev: empty_swan_rev.to_string(),
        empty_swan_archive_hex: hex_encode(&empty_archive),
        populated_space: space_str.to_string(),
        populated_repo: alice_did.to_string(),
        populated_rev: rev.to_string(),
        populated_data_hex: hex_encode(&data_32),
        populated_archive_hex: hex_encode(&populated_archive),
    };

    Ok(AtprotoSpacesVectorsV1 {
        version: 1,
        lthash,
        kem_p256,
        commit_mac,
        record_mac,
        rfc9421_low_s,
        rfc9421_high_s,
        delegation_jwt_did_plc,
        credential_jwt_did_web,
        star_repo,
    })
}

/// Generate the extended `atproto_spaces_v2` vector suite (adds RFC 9180 HPKE export-only P-256 vector,
/// independent Python cbor2/BLAKE3 STAR v0.2 CID-link vector, and hedged `SpaceUri` + `SpaceBlobLocator` vectors).
pub fn generate_v2_vectors() -> Result<AtprotoSpacesVectorsV2> {
    let v1 = generate_v1_vectors()?;

    let sender_secret_hex = "2f18b059576a0ec5a17121c0fe7ec8f00ea86f7b046fa3889ac8f21f89dbd484";
    let author_secret_hex = "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346";
    let sender_sk = SecretKey::from_slice(&hex_decode(sender_secret_hex)?)
        .map_err(|e| SpacesError::Kem(format!("rfc9180 sender_sk: {e}")))?;
    let author_sk = SecretKey::from_slice(&hex_decode(author_secret_hex)?)
        .map_err(|e| SpacesError::Kem(format!("rfc9180 author_sk: {e}")))?;
    let author_kem_did_key = encode_p256_did_key(&author_sk.public_key());
    let encap = encapsulate_p256_deterministic(&author_kem_did_key, &sender_sk)?;
    let hpke_rfc9180_export = HpkeRfc9180ExportVector {
        sender_secret_hex: sender_secret_hex.to_string(),
        author_secret_hex: author_secret_hex.to_string(),
        author_kem_did_key,
        key_share_did_key: encap.key_share_did_key,
        shared_secret_hex: hex_encode(&encap.shared_secret),
    };

    let star_v02_cid_link = StarCidLinkVector {
        space: "at://did:example:space/space/app.bsky.group/test".to_string(),
        repo: "did:example:alice".to_string(),
        rev: "3kbcq3p7ad422".to_string(),
        archive_base64: "KmwBAKcBpmNyZXZtM2tiY3EzcDdhZDQyMmN2ZXIBZGRhdGFYIAPti/dnzI3Ij07mC2HCTa1QGHC6pGj8nXzGZVYsfhnaZHJlcG9xZGlkOmV4YW1wbGU6YWxpY2VlJHR5cGVyYXRwcm90by1zcGFjZS1yZXBvZXNwYWNleDBhdDovL2RpZDpleGFtcGxlOnNwYWNlL3NwYWNlL2FwcC5ic2t5Lmdyb3VwL3Rlc3QBF2FwcC5ic2t5LmZlZWQucG9zdC9zZWxmQKNjcmVm2CpYJQABcRIgZCjwIwS424yxB8iTNkgfD+rXKL83TKgBaNLHGTjO+udkdGV4dGVoZWxsb2Vjb3VudAEA".to_string(),
        expected_path: "app.bsky.feed.post/self".to_string(),
        expected_cid: "bafyreidpnhlqcmg7f3bbn6zd7kr2p3x3ciaqgpy7333hlp3gc4vluyuzvm".to_string(),
    };

    let canonical_space_uri =
        "at://did:web:ds.catbird.blue/space/blue.catbird.labyrinth.conversation/01980a11-gen1";
    let hedged_at_space =
        "at:space/did:web:ds.catbird.blue/blue.catbird.labyrinth.conversation/01980a11-gen1";
    let hedged_at_slash_space =
        "at://space/did:web:ds.catbird.blue/blue.catbird.labyrinth.conversation/01980a11-gen1";
    let locator_space = SpaceUri::parse(canonical_space_uri)?;
    let locator_repo = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    let locator_cid: cid::Cid = v1
        .lthash
        .record_b
        .cid
        .parse()
        .map_err(|e| SpacesError::InvalidBlobLocator(format!("cid: {e}")))?;
    let locator = SpaceBlobLocator::new(locator_space, locator_repo, locator_cid)?;
    let uri_and_blob_locator = UriAndBlobLocatorVector {
        canonical_space_uri: canonical_space_uri.to_string(),
        hedged_at_space: hedged_at_space.to_string(),
        hedged_at_slash_space: hedged_at_slash_space.to_string(),
        repo: locator_repo.to_string(),
        cid: locator_cid.to_string(),
        canonical_blob_locator: locator.encoded(),
        legacy_blob_locator: format!("{canonical_space_uri}/{locator_repo}#{locator_cid}"),
    };

    Ok(AtprotoSpacesVectorsV2 {
        version: 2,
        lthash: v1.lthash,
        kem_p256: v1.kem_p256,
        hpke_rfc9180_export,
        commit_mac: v1.commit_mac,
        record_mac: v1.record_mac,
        rfc9421_low_s: v1.rfc9421_low_s,
        rfc9421_high_s: v1.rfc9421_high_s,
        delegation_jwt_did_plc: v1.delegation_jwt_did_plc,
        credential_jwt_did_web: v1.credential_jwt_did_web,
        star_repo: v1.star_repo,
        star_v02_cid_link,
        uri_and_blob_locator,
    })
}

/// Flip `(r, s)` -> `(r, n - s)` on the P-256 scalar field.
pub fn flip_p256_signature_s(sig: &[u8; 64]) -> [u8; 64] {
    let mut out = *sig;
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = i16::from(P256_ORDER_BE[i]) - i16::from(sig[32 + i]) - borrow;
        if diff < 0 {
            out[32 + i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[32 + i] = diff as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0);
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(SpacesError::StarFormat("odd-length hex string".into()));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(SpacesError::StarFormat(format!(
            "invalid hex character: {:?}",
            b as char
        ))),
    }
}
