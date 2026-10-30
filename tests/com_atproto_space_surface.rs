#![cfg(feature = "namespace-atproto-space")]

use catbird_atproto::com_atproto::space::Commit;

#[test]
fn space_namespace_is_publicly_reachable() {
    fn assert_public_type<T>() {}
    assert_public_type::<Commit>();
    assert_public_type::<
        catbird_atproto::com_atproto::space::get_latest_commit::GetLatestCommitOutput,
    >();
    assert_public_type::<catbird_atproto::com_atproto::space::list_repo_ops::ListRepoOpsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_records::ListRecordsOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::list_spaces::ListSpacesOutput>();
    assert_public_type::<
        catbird_atproto::com_atproto::space::notify_credential_revoked::NotifyCredentialRevoked,
    >();
    assert_public_type::<catbird_atproto::com_atproto::memberspace::put_member::PutMember>();
    assert_public_type::<catbird_atproto::com_atproto::memberspace::member::Member>();
    assert_public_type::<catbird_atproto::com_atproto::space::policy::Policy>();
    assert_public_type::<catbird_atproto::com_atproto::space::clear_records::ClearRecords>();
    assert_public_type::<catbird_atproto::com_atproto::space::remove_writer::RemoveWriter>();
    assert_public_type::<catbird_atproto::com_atproto::personalspace::policy::Policy>();
}

const UPSTREAM_V1_JSON: &str = r#"{
    "ver": 1,
    "repo": "did:plc:writer",
    "space": "at://did:plc:space/space/app.bsky.group/demo",
    "rev": "3jzfcijpj2m2a",
    "data": {"$bytes": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="}
}"#;

#[test]
fn commit_oct22_json_roundtrip() {
    let parsed: Commit = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
    assert_eq!(parsed.ver, 1);
    assert_eq!(parsed.repo.as_str(), "did:plc:writer");
    assert_eq!(parsed.space.as_str(), SPACE_URI);
    assert_eq!(parsed.rev.as_str(), "3jzfcijpj2m2a");
    assert_eq!(parsed.data.as_ref(), &[0x42; 32]);
    assert!(parsed.extra_data.is_none());
    let reencoded = serde_json::to_value(&parsed).unwrap();
    let original: serde_json::Value = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
    assert_eq!(reencoded, original);
    for absent in ["hash", "sig", "ikm", "mac"] {
        assert!(reencoded.get(absent).is_none());
    }
}

#[test]
fn commit_oct22_dag_cbor_roundtrip() {
    let commit: Commit = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
    let cbor = serde_ipld_dagcbor::to_vec(&commit).unwrap();
    let decoded: Commit = serde_ipld_dagcbor::from_slice(&cbor).unwrap();
    assert_eq!(decoded, commit);
    assert_eq!(serde_ipld_dagcbor::to_vec(&decoded).unwrap(), cbor);
}

#[test]
fn commit_requires_all_authenticated_context_fields() {
    for missing in ["ver", "repo", "space", "rev", "data"] {
        let mut value: serde_json::Value = serde_json::from_str(UPSTREAM_V1_JSON).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        let err = decode::<Commit>(&value).unwrap_err().to_string();
        assert!(err.contains(&format!("missing field `{missing}`")), "{err}");
    }
}

#[test]
fn credential_exchange_carries_binding_and_optional_assertions_in_body() {
    use catbird_atproto::com_atproto::space::get_space_credential::GetSpaceCredential;
    let minimal = serde_json::json!({"space": SPACE_URI, "credentialKid": "did:key:zExample"});
    let parsed: GetSpaceCredential = decode(&minimal).unwrap();
    assert_eq!(parsed.credential_kid.as_str(), "did:key:zExample");
    assert!(parsed.delegation_token.is_none());
    assert!(parsed.client_attestation.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), minimal);
    let private = serde_json::json!({"space": SPACE_URI, "credentialKid": "did:key:zExample", "delegationToken": "user-jwt", "clientAttestation": "app-jwt"});
    let parsed: GetSpaceCredential = decode(&private).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), private);
    let err = decode::<GetSpaceCredential>(&serde_json::json!({"space": SPACE_URI}))
        .unwrap_err()
        .to_string();
    assert!(err.contains("missing field `credentialKid`"), "{err}");
}

#[test]
fn permissioned_repo_export_declares_octet_stream() {
    use catbird_atproto::com_atproto::space::get_repo::GetRepoResponse;
    use jacquard_common::xrpc::XrpcResp;
    assert_eq!(GetRepoResponse::ENCODING, "application/octet-stream");
}

// --- atproto Spaces October 22, 2026 alpha (atproto ac0c9f15) wire shapes ---

/// Decode through a JSON string (not `from_value`): Jacquard's `Tid` only
/// deserializes from borrowed strings, as on the real wire.
fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> serde_json::Result<T> {
    serde_json::from_str(&value.to_string())
}

const SPACE_URI: &str = "at://did:plc:space/space/app.bsky.group/demo";
const DATA_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

#[test]
fn notify_write_repo_host_body_uses_repo_rev_without_space_revs() {
    use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;

    let body = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "repoRev": "3jzfcijpj2m2a",
        "data": {"$bytes": DATA_B64},
    });
    let parsed: NotifyWrite = decode(&body).unwrap();
    assert_eq!(parsed.repo_rev.as_str(), "3jzfcijpj2m2a");
    assert!(parsed.space_rev.is_none());
    assert!(parsed.prev_space_rev.is_none());
    assert_eq!(parsed.data.as_ref(), &[0x42; 32]);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
}

#[test]
fn notify_write_forwarded_body_carries_space_revs() {
    use catbird_atproto::com_atproto::space::notify_write::NotifyWrite;

    let first = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "repoRev": "3jzfcijpj2m2a",
        "data": {"$bytes": DATA_B64},
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
        "data": {"$bytes": DATA_B64},
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
            {"did": "did:plc:a", "repoRev": "3jzfcijpj2m2a", "data": {"$bytes": DATA_B64}, "spaceRev": "3jzfcijpj2m2b"},
            {"did": "did:plc:b", "repoRev": "3jzfcijpj2m2a", "data": {"$bytes": DATA_B64}, "spaceRev": "3jzfcijpj2m2c"},
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
        "repos": [{"did": "did:plc:a", "rev": "3jzfcijpj2m2a", "data": {"$bytes": DATA_B64}}],
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
    use catbird_atproto::com_atproto::space::create_space::CreateSpace;

    let body = serde_json::json!({
        "spaceType": "app.bsky.group",
        "policy": {"$type": "com.atproto.memberspace.policy"},
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

// --- atproto Spaces October 29, 2026 alpha (atproto 5d88b414) wire shapes ---

#[test]
fn space_policy_union_keeps_each_policy_type_tag() {
    use catbird_atproto::com_atproto::space::create_space::{CreateSpace, CreateSpacePolicy};

    let cases = [
        serde_json::json!({"$type": "com.atproto.personalspace.policy"}),
        serde_json::json!({
            "$type": "com.atproto.memberspace.policy",
            "publicRead": true,
            "allowedApps": ["did:web:app.example#forum"],
        }),
        serde_json::json!({
            "$type": "com.atproto.managedspace.policy",
            "managingApp": "did:web:app.example#forum",
        }),
    ];
    for policy in cases {
        let body = serde_json::json!({"spaceType": "app.bsky.group", "policy": policy});
        let parsed: CreateSpace = decode(&body).unwrap();
        match (&parsed.policy, policy["$type"].as_str().unwrap()) {
            (CreateSpacePolicy::PersonalspacePolicy(_), "com.atproto.personalspace.policy") => {}
            (CreateSpacePolicy::MemberspacePolicy(p), "com.atproto.memberspace.policy") => {
                assert_eq!(p.public_read, Some(true));
                let apps = p.allowed_apps.as_ref().unwrap();
                assert_eq!(apps[0].as_str(), "did:web:app.example#forum");
            }
            (CreateSpacePolicy::ManagedspacePolicy(p), "com.atproto.managedspace.policy") => {
                assert_eq!(p.managing_app.as_str(), "did:web:app.example#forum");
            }
            (other, tag) => panic!("{tag} decoded as {other:?}"),
        }
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded["policy"]["$type"], policy["$type"]);
    }
}

#[test]
fn get_space_returns_uri_and_policy() {
    use catbird_atproto::com_atproto::space::get_space::{GetSpaceOutput, GetSpaceOutputPolicy};

    let body = serde_json::json!({
        "uri": SPACE_URI,
        "policy": {"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:app.example"},
    });
    let parsed: GetSpaceOutput = decode(&body).unwrap();
    assert_eq!(parsed.uri.as_str(), SPACE_URI);
    assert!(matches!(
        parsed.policy,
        GetSpaceOutputPolicy::ManagedspacePolicy(_)
    ));
}

#[test]
fn moved_member_and_access_methods_use_their_new_nsids() {
    use catbird_atproto::com_atproto::managedspace::check_user_access::CheckUserAccess;
    use catbird_atproto::com_atproto::memberspace::put_member::PutMember;
    use jacquard_common::xrpc::XrpcRequest;

    assert_eq!(
        <CheckUserAccess as XrpcRequest>::NSID,
        "com.atproto.managedspace.checkUserAccess"
    );
    assert_eq!(
        <PutMember as XrpcRequest>::NSID,
        "com.atproto.memberspace.putMember"
    );
}

#[test]
fn get_space_credential_keeps_its_error_names() {
    use catbird_atproto::com_atproto::space::get_space_credential::GetSpaceCredentialError;

    for name in ["SpaceNotFound", "UserNotAuthorized"] {
        let body = serde_json::json!({"error": name, "message": "denied"});
        let parsed: GetSpaceCredentialError = decode(&body).unwrap();
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded["error"], name);
    }
}
