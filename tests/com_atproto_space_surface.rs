#![cfg(feature = "namespace-atproto-space")]

use catbird_atproto::com_atproto::space::Commit;

#[test]
fn space_namespace_is_publicly_reachable() {
    fn assert_public_type<T>() {}
    assert_public_type::<Commit>();
    assert_public_type::<catbird_atproto::com_atproto::space::RepoRemoved>();
    assert_public_type::<catbird_atproto::com_atproto::space::RepoWrite>();
    assert_public_type::<
        catbird_atproto::com_atproto::space::authorize_space_sync::AuthorizeSpaceSync,
    >();
    assert_public_type::<
        catbird_atproto::com_atproto::space::confirm_registration::ConfirmRegistration,
    >();
    assert_public_type::<
        catbird_atproto::com_atproto::space::notify_credentials_revoked::NotifyCredentialsRevoked,
    >();
    assert_public_type::<catbird_atproto::com_atproto::space::list_writers::ListWritersOutput>();
    assert_public_type::<catbird_atproto::com_atproto::space::notify_repo_update::NotifyRepoUpdate>(
    );
    assert_public_type::<catbird_atproto::com_atproto::space::notify_space_update::NotifySpaceUpdate>(
    );
    assert_public_type::<catbird_atproto::com_atproto::memberspace::put_members::PutMembers>();
    assert_public_type::<catbird_atproto::com_atproto::memberspace::remove_members::RemoveMembers>(
    );
    assert_public_type::<catbird_atproto::com_atproto::managedspace::check_access::CheckAccess>();
    assert_public_type::<catbird_atproto::com_atproto::memberspace::Member>();
    assert_public_type::<catbird_atproto::com_atproto::space::policy::Policy>();
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
fn authorize_space_sync_carries_binding_and_optional_registration() {
    use catbird_atproto::com_atproto::space::authorize_space_sync::AuthorizeSpaceSync;

    let minimal = serde_json::json!({"space": SPACE_URI, "credentialKey": "did:key:zExample"});
    let parsed: AuthorizeSpaceSync = decode(&minimal).unwrap();
    assert_eq!(parsed.credential_key.as_str(), "did:key:zExample");
    assert!(parsed.delegation_token.is_none());
    assert!(parsed.client_attestation.is_none());
    assert!(parsed.notify.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), minimal);

    let registered = serde_json::json!({
        "space": SPACE_URI,
        "credentialKey": "did:key:zExample",
        "delegationToken": "user-jwt",
        "clientAttestation": "app-jwt",
        "notify": {"endpoint": "https://syncer.example/xrpc", "token": "opaque-token"},
    });
    let parsed: AuthorizeSpaceSync = decode(&registered).unwrap();
    assert_eq!(
        parsed.notify.as_ref().unwrap().token.as_str(),
        "opaque-token"
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), registered);
}

#[test]
fn permissioned_repo_export_declares_star() {
    use catbird_atproto::com_atproto::space::get_repo::GetRepoResponse;
    use jacquard_common::xrpc::XrpcResp;
    assert_eq!(GetRepoResponse::ENCODING, "application/vnd.dasl.star");
}

// --- atproto Spaces November 12, 2026 alpha (atproto d4def6e9) wire shapes ---

/// Decode through a JSON string (not `from_value`): Jacquard's `Tid` only
/// deserializes from borrowed strings, as on the real wire.
fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> serde_json::Result<T> {
    serde_json::from_str(&value.to_string())
}

const SPACE_URI: &str = "at://did:plc:space/space/app.bsky.group/demo";
const DATA_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

#[test]
fn notify_repo_update_carries_only_the_writer_revision() {
    use catbird_atproto::com_atproto::space::notify_repo_update::NotifyRepoUpdate;

    let body = serde_json::json!({
        "space": SPACE_URI,
        "repo": "did:plc:writer",
        "repoRev": "3jzfcijpj2m2a",
        "data": {"$bytes": DATA_B64},
    });
    let parsed: NotifyRepoUpdate = decode(&body).unwrap();
    assert_eq!(parsed.repo_rev.as_str(), "3jzfcijpj2m2a");
    assert_eq!(parsed.data.as_ref(), &[0x42; 32]);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
}

#[test]
fn notify_repo_update_declares_space_not_found_and_future_rev_errors() {
    use catbird_atproto::com_atproto::space::notify_repo_update::{
        NotifyRepoUpdateError, NotifyRepoUpdateResponse,
    };
    use jacquard_common::xrpc::XrpcResp;

    fn assert_err_type<R: XrpcResp<Err = NotifyRepoUpdateError>>() {}
    assert_err_type::<NotifyRepoUpdateResponse>();

    let future: NotifyRepoUpdateError =
        serde_json::from_str(r#"{"error":"FutureRev","message":"too far ahead"}"#).unwrap();
    assert_eq!(
        future,
        NotifyRepoUpdateError::FutureRev(Some("too far ahead".into()))
    );
    let missing: NotifyRepoUpdateError =
        serde_json::from_str(r#"{"error":"SpaceNotFound"}"#).unwrap();
    assert_eq!(missing, NotifyRepoUpdateError::SpaceNotFound(None));
}

#[test]
fn list_writers_distinguishes_repo_writes_and_removals() {
    use catbird_atproto::com_atproto::space::list_writers::{
        ListWritersOutput, ListWritersOutputReposItem,
    };

    let page = serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": "did:plc:a",
                "repoRev": "3jzfcijpj2m2a",
                "data": {"$bytes": DATA_B64},
                "spaceRev": "3jzfcijpj2m2b"
            },
            {
                "$type": "com.atproto.space.defs#repoRemoved",
                "repo": "did:plc:b",
                "spaceRev": "3jzfcijpj2m2c"
            }
        ],
        "cursor": "3jzfcijpj2m2c",
    });
    let parsed: ListWritersOutput = decode(&page).unwrap();
    match &parsed.repos[0] {
        ListWritersOutputReposItem::RepoWrite(update) => {
            assert_eq!(update.repo_rev.as_str(), "3jzfcijpj2m2a");
            assert_eq!(update.data.as_ref(), &[0x42; 32]);
        }
        other => panic!("repoWrite decoded as {other:?}"),
    }
    match &parsed.repos[1] {
        ListWritersOutputReposItem::RepoRemoved(update) => {
            assert_eq!(update.repo.as_str(), "did:plc:b");
            assert_eq!(update.space_rev.as_str(), "3jzfcijpj2m2c");
        }
        other => panic!("repoRemoved decoded as {other:?}"),
    }
    assert_eq!(serde_json::to_value(&parsed).unwrap(), page);
}

#[test]
fn list_writers_cursor_param_is_an_opaque_string() {
    use catbird_atproto::com_atproto::space::list_writers::ListWriters;

    let params: ListWriters = decode(&serde_json::json!({
        "space": SPACE_URI,
        "cursor": "not-a-tid",
    }))
    .unwrap();
    assert_eq!(params.cursor.as_deref(), Some("not-a-tid"));
}

#[test]
fn list_writers_empty_page_omits_cursor() {
    use catbird_atproto::com_atproto::space::list_writers::ListWritersOutput;

    let empty = serde_json::json!({"repos": []});
    let parsed: ListWritersOutput = decode(&empty).unwrap();
    assert!(parsed.repos.is_empty());
    assert!(parsed.cursor.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), empty);
}

#[test]
fn member_batches_use_members_and_dids_arrays() {
    use catbird_atproto::com_atproto::memberspace::put_members::PutMembers;
    use catbird_atproto::com_atproto::memberspace::remove_members::RemoveMembers;

    let put = serde_json::json!({
        "space": SPACE_URI,
        "members": [{"did": "did:plc:member", "read": true, "write": false}],
    });
    let parsed: PutMembers = decode(&put).unwrap();
    assert_eq!(parsed.members[0].did.as_str(), "did:plc:member");
    assert!(parsed.members[0].read);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), put);

    let remove = serde_json::json!({"space": SPACE_URI, "dids": ["did:plc:member"]});
    let parsed: RemoveMembers = decode(&remove).unwrap();
    assert_eq!(parsed.dids[0].as_str(), "did:plc:member");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), remove);
}

#[test]
fn registration_confirmation_roundtrips_the_challenge() {
    use catbird_atproto::com_atproto::space::confirm_registration::ConfirmRegistration;

    let body = serde_json::json!({
        "space": SPACE_URI,
        "token": "opaque-token",
        "challenge": "opaque-challenge",
    });
    let parsed: ConfirmRegistration = decode(&body).unwrap();
    assert_eq!(parsed.challenge.as_str(), "opaque-challenge");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
}

#[test]
fn notify_space_update_keeps_repo_update_type_tags() {
    use catbird_atproto::com_atproto::space::notify_space_update::{
        NotifySpaceUpdate, NotifySpaceUpdateUpdate,
    };

    let body = serde_json::json!({
        "space": SPACE_URI,
        "token": "opaque-token",
        "update": {
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": "did:plc:a",
            "repoRev": "3jzfcijpj2m2a",
            "data": {"$bytes": DATA_B64},
            "spaceRev": "3jzfcijpj2m2b"
        }
    });
    let parsed: NotifySpaceUpdate = decode(&body).unwrap();
    assert!(matches!(
        &parsed.update,
        NotifySpaceUpdateUpdate::RepoWrite(_)
    ));
    assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
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
fn get_space_returns_space_and_policy() {
    use catbird_atproto::com_atproto::space::get_space::{GetSpaceOutput, GetSpaceOutputPolicy};

    let body = serde_json::json!({
        "space": SPACE_URI,
        "policy": {"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:app.example"},
    });
    let parsed: GetSpaceOutput = decode(&body).unwrap();
    assert_eq!(parsed.space.as_str(), SPACE_URI);
    assert!(matches!(
        parsed.policy,
        GetSpaceOutputPolicy::ManagedspacePolicy(_)
    ));
}

#[test]
fn batched_member_and_access_methods_use_their_new_nsids() {
    use catbird_atproto::com_atproto::managedspace::check_access::CheckAccess;
    use catbird_atproto::com_atproto::memberspace::put_members::PutMembers;
    use catbird_atproto::com_atproto::memberspace::remove_members::RemoveMembers;
    use jacquard_common::xrpc::XrpcRequest;

    assert_eq!(
        <CheckAccess as XrpcRequest>::NSID,
        "com.atproto.managedspace.checkAccess"
    );
    assert_eq!(
        <PutMembers as XrpcRequest>::NSID,
        "com.atproto.memberspace.putMembers"
    );
    assert_eq!(
        <RemoveMembers as XrpcRequest>::NSID,
        "com.atproto.memberspace.removeMembers"
    );
}

#[test]
fn authorize_space_sync_keeps_its_error_names() {
    use catbird_atproto::com_atproto::space::authorize_space_sync::AuthorizeSpaceSyncError;

    for name in [
        "SpaceNotFound",
        "AccountNotAuthorized",
        "AppNotAuthorized",
        "NotAuthorized",
        "RegistrationNotConfirmed",
    ] {
        let body = serde_json::json!({"error": name, "message": "denied"});
        let parsed: AuthorizeSpaceSyncError = decode(&body).unwrap();
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded["error"], name);
    }
}
