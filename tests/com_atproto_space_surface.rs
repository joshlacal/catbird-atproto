#![cfg(feature = "namespace-atproto-space")]

use bytes::Bytes;
use catbird_atproto::com_atproto::space::SignedCommit;
use jacquard_common::types::tid::Tid;

#[test]
fn space_namespace_is_publicly_reachable() {
    fn assert_public_type<T>() {}

    assert_public_type::<catbird_atproto::com_atproto::space::SignedCommit>();
    assert_public_type::<
        catbird_atproto::com_atproto::space::get_latest_commit::GetLatestCommitOutput,
    >();
    assert_public_type::<catbird_atproto::com_atproto::space::list_repo_ops::ListRepoOpsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_records::ListRecordsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_spaces::ListSpacesOutput>();
    assert_public_type::<
        catbird_atproto::com_atproto::space::notify_credential_revoked::NotifyCredentialRevoked,
    >();
    assert_public_type::<catbird_atproto::com_atproto::simplespace::put_member::PutMember>();
}

const UPSTREAM_V1_JSON: &str = r#"{
    "ver": 1,
    "rev": "3jzfcijpj2m2a",
    "hash": {"$bytes": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="},
    "ikm": {"$bytes": "ISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISE="},
    "mac": {"$bytes": "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI="},
    "sig": {"$bytes": "mZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmQ=="}
}"#;

#[test]
fn signed_commit_upstream_v1_json_roundtrip() {
    let parsed: SignedCommit = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
    assert_eq!(parsed.ver, 1);
    assert_eq!(parsed.rev.as_str(), "3jzfcijpj2m2a");
    assert_eq!(parsed.hash.as_ref(), &[0x42; 32]);
    assert_eq!(parsed.ikm.as_ref(), &[0x21; 32]);
    assert_eq!(parsed.mac.as_ref(), &[0x32; 32]);
    assert_eq!(parsed.sig.as_ref(), &[0x99; 64]);
    assert!(parsed.extra_data.is_none());

    let reencoded = serde_json::to_value(&parsed).unwrap();
    let original: serde_json::Value = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
    assert_eq!(reencoded, original);
}

#[test]
fn signed_commit_upstream_v1_dag_cbor_roundtrip() {
    let commit = SignedCommit {
        hash: Bytes::from_static(&[0x42; 32]),
        ikm: Bytes::from_static(&[0x21; 32]),
        mac: Bytes::from_static(&[0x32; 32]),
        rev: Tid::new("3jzfcijpj2m2a").unwrap(),
        sig: Bytes::from_static(&[0x99; 64]),
        ver: 1,
        extra_data: None,
    };

    let cbor = serde_ipld_dagcbor::to_vec(&commit).unwrap();
    let decoded: SignedCommit = serde_ipld_dagcbor::from_slice(&cbor).unwrap();
    assert_eq!(decoded, commit);
    assert_eq!(serde_ipld_dagcbor::to_vec(&decoded).unwrap(), cbor);
}

#[test]
fn signed_commit_requires_ikm_and_mac() {
    for missing in ["ikm", "mac"] {
        let mut value: serde_json::Value = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        let result = serde_json::from_value::<SignedCommit>(value);
        assert!(
            result.is_err(),
            "SignedCommit without {missing} must not deserialize"
        );
    }
}
