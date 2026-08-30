#![cfg(feature = "namespace-atproto-space")]

use bytes::Bytes;
use catbird_atproto::com_atproto::space::SignedCommit;
use jacquard_common::types::aturi::AtUri;
use jacquard_common::types::cid::Cid;
use jacquard_common::types::did::Did;
use jacquard_common::types::tid::Tid;
use std::str::FromStr;

#[test]
fn space_namespace_is_publicly_reachable() {
    fn assert_public_type<T>() {}

    assert_public_type::<catbird_atproto::com_atproto::space::SignedCommit>();
    assert_public_type::<catbird_atproto::com_atproto::space::get_latest_commit::GetLatestCommitOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_repo_ops::ListRepoOpsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_records::ListRecordsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_spaces::ListSpacesOutput>();
}

#[test]
fn signed_commit_v2_contract_roundtrip() {
    let commit = SignedCommit {
        action: Some("create".into()),
        cid: Some(Cid::from_str("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454").unwrap()),
        did: Some(Did::new_owned("did:plc:author1234567890123456").unwrap()),
        hash: Bytes::from_static(&[0x42; 32]),
        ikm: None,
        mac: None,
        path: Some("com.example.record/r1".into()),
        prev_cid: None,
        prev_hash: Some(Bytes::from_static(&[0x41; 32])),
        prev_rev: Some(Tid::new("3jzfcijpj2m22").unwrap()),
        rev: Tid::new("3jzfcijpj2m2a").unwrap(),
        sig: Bytes::from_static(&[0x99; 64]),
        space: Some(AtUri::new_owned("at://did:plc:space/space/com.example.type/demo").unwrap()),
        val: Some(Bytes::from_static(b"{\"test\":\"data\"}")),
        ver: 2,
        extra_data: None,
    };

    let json = serde_json::to_string(&commit).unwrap();
    let parsed: SignedCommit = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.ver, 2);
    assert_eq!(parsed.did.as_ref().map(|d| d.as_str()), Some("did:plc:author1234567890123456"));
    assert_eq!(parsed.rev.as_str(), "3jzfcijpj2m2a");
    assert_eq!(parsed.prev_rev.as_ref().map(|r| r.as_str()), Some("3jzfcijpj2m22"));
    assert_eq!(parsed.hash.as_ref(), &[0x42; 32]);
    assert_eq!(parsed.prev_hash.as_ref().map(|h| h.as_ref()), Some(&[0x41; 32][..]));
    assert_eq!(parsed.path.as_deref(), Some("com.example.record/r1"));
    assert_eq!(parsed.action.as_deref(), Some("create"));
    assert_eq!(parsed.cid.as_ref().map(|c| c.as_str()), Some("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"));
    assert_eq!(parsed.val.as_ref().map(|v| v.as_ref()), Some(&b"{\"test\":\"data\"}"[..]));
    assert_eq!(parsed.sig.as_ref(), &[0x99; 64]);
}

#[test]
fn signed_commit_v1_backward_compatibility() {
    let raw_v1_json = r#"{
        "ver": 1,
        "rev": "3jzfcijpj2m2a",
        "hash": {"$bytes": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="},
        "ikm": {"$bytes": "ISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISE="},
        "mac": {"$bytes": "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="},
        "sig": {"$bytes": "mZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmQ=="}
    }"#;

    let parsed: SignedCommit = serde_json::from_str(raw_v1_json).unwrap();
    assert_eq!(parsed.ver, 1);
    assert!(parsed.did.is_none());
    assert_eq!(parsed.rev.as_str(), "3jzfcijpj2m2a");
    assert!(parsed.ikm.is_some());
    assert!(parsed.mac.is_some());
    assert!(parsed.prev_rev.is_none());
    assert!(parsed.prev_hash.is_none());
    assert!(parsed.path.is_none());
    assert!(parsed.action.is_none());
    assert!(parsed.cid.is_none());
    assert!(parsed.prev_cid.is_none());
    assert!(parsed.val.is_none());
    assert!(parsed.ikm.is_some());
    assert!(parsed.mac.is_some());
    assert!(parsed.prev_rev.is_none());
    assert!(parsed.prev_hash.is_none());
    assert!(parsed.path.is_none());
}

#[test]
fn signed_commit_v2_matches_shared_fixture_artifact_and_cbor_transcript_signature() {
    const FIXTURE_JSON: &str = include_str!("fixtures/commit_v2_vectors.json");
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    assert_eq!(fixture["domain"], "atproto-space-v2");
    let ctx = &fixture["context"];

    // 1. Validate transcript against transcript_hex
    let mut expected_transcript = b"atproto-space-v2".to_vec();
    let space_str = ctx["space"].as_str().unwrap();
    let author_str = ctx["author"].as_str().unwrap();
    let rev_str = ctx["rev"].as_str().unwrap();
    let prev_rev_str = ctx["prevRev"].as_str().unwrap();
    let hash_bytes = hex_decode(ctx["hash"].as_str().unwrap());
    let prev_hash_bytes = hex_decode(ctx["prevHash"].as_str().unwrap());
    let path_str = ctx["path"].as_str().unwrap();
    let action_str = ctx["action"].as_str().unwrap();
    let cid_str = ctx["cid"].as_str().unwrap_or("");
    let prev_cid_str = ctx["prevCid"].as_str().unwrap_or("");
    let val_bytes = ctx["val"].as_str().unwrap().as_bytes();

    let fields: [&[u8]; 11] = [
        space_str.as_bytes(),
        author_str.as_bytes(),
        rev_str.as_bytes(),
        prev_rev_str.as_bytes(),
        &hash_bytes,
        &prev_hash_bytes,
        path_str.as_bytes(),
        action_str.as_bytes(),
        cid_str.as_bytes(),
        prev_cid_str.as_bytes(),
        val_bytes,
    ];

    for field in fields {
        expected_transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
        expected_transcript.extend_from_slice(field);
    }

    let fixture_transcript_bytes = hex_decode(fixture["transcript_hex"].as_str().unwrap());
    assert_eq!(expected_transcript, fixture_transcript_bytes);

    // 2. Validate DAG-CBOR decode, context fields, signatures, and CBOR re-encoding across all 3 curves
    let curves = fixture["curves"].as_object().unwrap();
    for (curve_name, curve_val) in curves {
        let cbor_hex = curve_val["cbor_hex"].as_str().unwrap();
        let sig_hex = curve_val["signature_hex"].as_str().unwrap();
        let cbor_bytes = hex_decode(cbor_hex);
        let sig_bytes = hex_decode(sig_hex);

        // Deserialize directly from CBOR bytes
        let commit: SignedCommit = serde_ipld_dagcbor::from_slice(&cbor_bytes)
            .unwrap_or_else(|e| panic!("Failed to decode CBOR for curve {curve_name}: {e}"));

        assert_eq!(commit.ver, 2, "Curve {curve_name} ver mismatch");
        assert_eq!(commit.rev.as_str(), rev_str, "Curve {curve_name} rev mismatch");
        assert_eq!(
            commit.prev_rev.as_ref().map(|r| r.as_str()),
            Some(prev_rev_str),
            "Curve {curve_name} prev_rev mismatch"
        );
        assert_eq!(
            commit.did.as_ref().map(|d| d.as_str()),
            Some(author_str),
            "Curve {curve_name} did mismatch"
        );
        assert_eq!(
            commit.space.as_ref().map(|s| s.as_str()),
            Some(space_str),
            "Curve {curve_name} space mismatch"
        );
        assert_eq!(commit.hash.as_ref(), hash_bytes.as_slice(), "Curve {curve_name} hash mismatch");
        assert_eq!(
            commit.prev_hash.as_ref().map(|h| h.as_ref()),
            Some(prev_hash_bytes.as_slice()),
            "Curve {curve_name} prev_hash mismatch"
        );
        assert_eq!(commit.path.as_deref(), Some(path_str), "Curve {curve_name} path mismatch");
        assert_eq!(commit.action.as_deref(), Some(action_str), "Curve {curve_name} action mismatch");
        assert_eq!(
            commit.cid.as_ref().map(|c| c.as_str()),
            Some(cid_str),
            "Curve {curve_name} cid mismatch"
        );
        assert!(commit.prev_cid.is_none(), "Curve {curve_name} prev_cid should be None");
        assert_eq!(
            commit.val.as_ref().map(|v| v.as_ref()),
            Some(val_bytes),
            "Curve {curve_name} val mismatch"
        );
        assert_eq!(commit.sig.as_ref(), sig_bytes.as_slice(), "Curve {curve_name} sig mismatch");

        // Re-encode to CBOR and verify exact roundtrip matching
        let reencoded_cbor = serde_ipld_dagcbor::to_vec(&commit)
            .unwrap_or_else(|e| panic!("Failed to re-encode CBOR for curve {curve_name}: {e}"));
        assert_eq!(reencoded_cbor, cbor_bytes, "Curve {curve_name} CBOR re-encoding mismatch");
    }
}

#[test]
fn signed_commit_v2_omission_vectors_descriptor_validation() {
    const FIXTURE_JSON: &str = include_str!("fixtures/commit_v2_vectors.json");
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).unwrap();
    let omissions = fixture["omission_vectors"].as_array().unwrap();
    assert_eq!(omissions.len(), 13, "Expected 13 omission vector descriptors");

    for omission in omissions {
        let name = omission["name"].as_str().expect("name required");
        let expected_err = omission["expected_error"].as_str().expect("expected_error required");
        assert!(!name.is_empty());
        assert!(!expected_err.is_empty());

        let has_omitted = omission.get("omitted_field").is_some();
        let has_illegal = omission.get("illegal_field").is_some();
        assert!(
            has_omitted ^ has_illegal,
            "Descriptor {name} must have either omitted_field or illegal_field"
        );

        if let Some(omitted) = omission.get("omitted_field").and_then(|f| f.as_str()) {
            assert!(
                ["did", "space", "prev_rev", "prev_hash", "path", "action", "cid", "prev_cid", "val"]
                    .contains(&omitted),
                "Unknown omitted_field: {omitted}"
            );
        }
        if let Some(illegal) = omission.get("illegal_field").and_then(|f| f.as_str()) {
            assert!(
                ["prev_cid", "cid"].contains(&illegal),
                "Unknown illegal_field: {illegal}"
            );
        }
    }
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect()
}
