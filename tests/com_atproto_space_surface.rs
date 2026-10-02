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
        // Decode via a JSON string: `from_value` fails on `rev` (Tid needs a
        // borrowed string) before it ever reaches the field under test.
        let err = decode::<SignedCommit>(&value).unwrap_err().to_string();
        assert!(
            err.contains(&format!("missing field `{missing}`")),
            "SignedCommit without {missing} must not deserialize: {err}"
        );
    }
}

// --- atproto Spaces October 1, 2026 alpha (atproto 679724ad) wire shapes ---

/// Decode through a JSON string (not `from_value`): Jacquard's `Tid` only
/// deserializes from borrowed strings, as on the real wire.
fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> serde_json::Result<T> {
    serde_json::from_str(&value.to_string())
}

const SPACE_URI: &str = "at://did:plc:space/space/app.bsky.group/demo";
const HASH_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

#[test]
fn notify_write_repo_host_body_uses_repo_rev_without_space_revs() {
    use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;

    let body = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "repoRev": "3jzfcijpj2m2a",
        "hash": {"$bytes": HASH_B64},
    });
    let parsed: NotifyWrite = decode(&body).unwrap();
    assert_eq!(parsed.repo_rev.as_str(), "3jzfcijpj2m2a");
    assert!(parsed.space_rev.is_none());
    assert!(parsed.prev_space_rev.is_none());
    assert_eq!(parsed.hash.as_ref(), &[0x42; 32]);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
}

#[test]
fn notify_write_forwarded_body_carries_space_revs() {
    use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;

    let first = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "repoRev": "3jzfcijpj2m2a",
        "hash": {"$bytes": HASH_B64},
        "spaceRev": "3jzfcijpj2m2b",
    });
    let parsed: NotifyWrite = decode(&first).unwrap();
    assert_eq!(parsed.space_rev.as_ref().unwrap().as_str(), "3jzfcijpj2m2b");
    assert!(parsed.prev_space_rev.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), first);

    let mut next = first;
    next["spaceRev"] = "3jzfcijpj2m2c".into();
    next["prevSpaceRev"] = "3jzfcijpj2m2b".into();
    let parsed: NotifyWrite = decode(&next).unwrap();
    assert_eq!(
        parsed.prev_space_rev.as_ref().unwrap().as_str(),
        "3jzfcijpj2m2b"
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), next);
}

#[test]
fn notify_write_rejects_pre_oct1_rev_field() {
    use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;

    let legacy = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "rev": "3jzfcijpj2m2a",
        "hash": {"$bytes": HASH_B64},
    });
    let err = decode::<NotifyWrite>(&legacy).unwrap_err().to_string();
    assert!(err.contains("missing field `repoRev`"), "{err}");
}

#[test]
fn notify_write_declares_space_not_found_and_future_rev_errors() {
    use catbird_atproto::com_atproto::space::notify_write::{
        NotifyWriteError, NotifyWriteResponse,
    };
    use jacquard_common::xrpc::XrpcResp;

    fn assert_err_type<R: XrpcResp<Err = NotifyWriteError>>() {}
    assert_err_type::<NotifyWriteResponse>();

    let future: NotifyWriteError =
        serde_json::from_str(r#"{"error":"FutureRev","message":"too far ahead"}"#).unwrap();
    assert_eq!(
        future,
        NotifyWriteError::FutureRev(Some("too far ahead".into()))
    );
    let missing: NotifyWriteError = serde_json::from_str(r#"{"error":"SpaceNotFound"}"#).unwrap();
    assert_eq!(missing, NotifyWriteError::SpaceNotFound(None));
}

#[test]
fn list_repos_entries_carry_repo_rev_and_space_rev() {
    use catbird_atproto::com_atproto::space::list_repos::ListReposOutput;

    let page = serde_json::json!({
        "repos": [
            {"did": "did:plc:a", "repoRev": "3jzfcijpj2m2a", "hash": {"$bytes": HASH_B64}, "spaceRev": "3jzfcijpj2m2b"},
            {"did": "did:plc:b", "repoRev": "3jzfcijpj2m2a", "hash": {"$bytes": HASH_B64}, "spaceRev": "3jzfcijpj2m2c"},
        ],
        "cursor": "3jzfcijpj2m2c",
    });
    let parsed: ListReposOutput = decode(&page).unwrap();
    assert_eq!(parsed.repos.len(), 2);
    assert_eq!(parsed.repos[0].repo_rev.as_str(), "3jzfcijpj2m2a");
    assert_eq!(parsed.repos[1].space_rev.as_str(), "3jzfcijpj2m2c");
    assert_eq!(parsed.cursor.as_deref(), Some("3jzfcijpj2m2c"));
    assert_eq!(serde_json::to_value(&parsed).unwrap(), page);
}

#[test]
fn list_repos_empty_page_omits_cursor() {
    use catbird_atproto::com_atproto::space::list_repos::ListReposOutput;

    let empty = serde_json::json!({"repos": []});
    let parsed: ListReposOutput = decode(&empty).unwrap();
    assert!(parsed.repos.is_empty());
    assert!(parsed.cursor.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), empty);
}

#[test]
fn list_repos_rejects_pre_oct1_entry_shape() {
    use catbird_atproto::com_atproto::space::list_repos::ListReposOutput;

    let legacy = serde_json::json!({
        "repos": [{"did": "did:plc:a", "rev": "3jzfcijpj2m2a", "hash": {"$bytes": HASH_B64}}],
        "cursor": "did:plc:a",
    });
    let err = decode::<ListReposOutput>(&legacy).unwrap_err().to_string();
    assert!(err.contains("missing field `repoRev`"), "{err}");
}

#[test]
fn list_repos_cursor_param_is_an_opaque_string() {
    use catbird_atproto::com_atproto::space::list_repos::ListRepos;

    // Merged implementation accepts arbitrary cursor strings; no TID format.
    let params: ListRepos = decode(&serde_json::json!({
        "space": SPACE_URI,
        "cursor": "not-a-tid",
    }))
    .unwrap();
    assert_eq!(params.cursor.as_deref(), Some("not-a-tid"));
}

#[test]
fn list_spaces_filter_is_space_type() {
    use catbird_atproto::com_atproto::space::list_spaces::ListSpaces;

    let params: ListSpaces = decode(&serde_json::json!({"spaceType": "app.bsky.group"})).unwrap();
    assert_eq!(
        params.space_type.as_ref().map(|nsid| nsid.as_str()),
        Some("app.bsky.group")
    );
    let encoded = serde_json::to_value(&params).unwrap();
    assert_eq!(encoded["spaceType"], "app.bsky.group");
    assert!(encoded.get("type").is_none());

    let legacy: ListSpaces = decode(&serde_json::json!({"type": "app.bsky.group"})).unwrap();
    assert!(legacy.space_type.is_none());
}

#[test]
fn create_space_requires_space_type() {
    use catbird_atproto::com_atproto::simplespace::create_space::CreateSpace;

    let body = serde_json::json!({
        "spaceType": "app.bsky.group",
        "readPolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
        "writePolicy": {"$type": "com.atproto.simplespace.defs#memberListPolicy"},
        "appAccess": {"$type": "com.atproto.simplespace.defs#open"},
    });
    let parsed: CreateSpace = decode(&body).unwrap();
    assert_eq!(parsed.space_type.as_str(), "app.bsky.group");
    let encoded = serde_json::to_value(&parsed).unwrap();
    assert_eq!(encoded["spaceType"], "app.bsky.group");
    assert!(encoded.get("type").is_none());

    let mut legacy = body;
    let space_type = legacy.as_object_mut().unwrap().remove("spaceType").unwrap();
    legacy["type"] = space_type;
    let err = decode::<CreateSpace>(&legacy).unwrap_err().to_string();
    assert!(err.contains("missing field `spaceType`"), "{err}");
}
