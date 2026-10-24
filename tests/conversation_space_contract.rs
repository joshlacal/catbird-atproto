use catbird_atproto::blue_catbird::labyrinth::{
    delete_space_generation::{DeleteSpaceGeneration, DeleteSpaceGenerationOutput},
    find_meks::FindMeksError,
    get_attachment_blob::GetAttachmentBlobError,
    get_space_membership::GetSpaceMembershipOutput,
    get_thread_storage::GetThreadStorageOutput,
    list_space_batches::ListSpaceBatches,
    SpaceBatchView,
};

const GENERATION: &str = "a4c334f4-1581-4f8c-9767-e6e7e23e70e2";
const SPACE: &str = "at://did:plc:authority/space/blue.catbird.labyrinth.thread/conversation";

fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> serde_json::Result<T> {
    serde_json::from_str(&value.to_string())
}

#[test]
fn placement_preserves_space_and_immutable_generation() {
    let value = serde_json::json!({
        "placement": "space", "generation": GENERATION, "space": SPACE
    });
    let parsed: GetThreadStorageOutput = decode(&value).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    let legacy = serde_json::json!({"placement": "mlsds", "generation": GENERATION});
    let parsed: GetThreadStorageOutput = decode(&legacy).unwrap();
    assert!(parsed.space.is_none());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), legacy);
}

#[test]
fn reference_pages_require_the_selected_generation() {
    let params = serde_json::json!({"threadId": "conversation", "generation": GENERATION, "actorDeviceId": GENERATION});
    let parsed: ListSpaceBatches = decode(&params).unwrap();
    assert_eq!(parsed.generation.as_str(), GENERATION);
    assert_eq!(parsed.actor_device_id.as_str(), GENERATION);
    let missing_device = serde_json::json!({"threadId": "conversation", "generation": GENERATION});
    assert!(decode::<ListSpaceBatches>(&missing_device)
        .unwrap_err()
        .to_string()
        .contains("actorDeviceId"));
    let error = decode::<ListSpaceBatches>(
        &serde_json::json!({"threadId": "conversation", "actorDeviceId": GENERATION}),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("missing field `generation`"), "{error}");
}

#[test]
fn immutable_reference_preserves_order_and_redaction_overlay() {
    let value = serde_json::json!({
        "author": "did:plc:author",
        "rkey": "e33325af1ea2ff20a2e4adb3bc57a67e603222f4202931345c9c1ff47187fa90",
        "space": SPACE,
        "generation": GENERATION,
        "itemCount": 1,
        "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
        "order": {"seq": 9, "chatSeq": 11, "receivedAt": "2026-10-23T12:00:00Z"},
        "redactions": [{
            "messageId": "message", "timestamp": 1792756800000_i64,
            "redaction": {"by": "did:web:chat.example", "reason": "accountDeleted", "redactedAt": "2026-10-23T12:01:00Z"}
        }]
    });
    let parsed: SpaceBatchView = decode(&value).unwrap();
    assert_eq!(parsed.order.seq, 9);
    assert_eq!(parsed.redactions.len(), 1);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    let mut missing = value;
    missing.as_object_mut().unwrap().remove("redactions");
    let error = decode::<SpaceBatchView>(&missing).unwrap_err().to_string();
    assert!(error.contains("missing field `redactions`"), "{error}");
}

#[test]
fn authority_membership_preserves_generation_and_current_chat_position() {
    let value = serde_json::json!({"space": SPACE, "generation": GENERATION,
        "user": "did:plc:member", "chatGeneration": 2, "chatSeq": 11});
    let parsed: GetSpaceMembershipOutput = decode(&value).unwrap();
    assert_eq!(parsed.chat_generation, 2);
    assert_eq!(parsed.chat_seq, 11);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
}

#[test]
fn permanent_deletion_is_bound_to_the_exact_space_generation() {
    let request = serde_json::json!({"space": SPACE, "generation": GENERATION});
    let parsed: DeleteSpaceGeneration = decode(&request).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), request);
    assert!(decode::<DeleteSpaceGeneration>(&serde_json::json!({"space": SPACE})).is_err());

    let response = serde_json::json!({"space": SPACE, "generation": GENERATION, "deleted": true});
    let parsed: DeleteSpaceGenerationOutput = decode(&response).unwrap();
    assert!(parsed.deleted);
    assert_eq!(serde_json::to_value(parsed).unwrap(), response);
}

#[test]
fn deleted_generation_is_a_typed_error_on_both_remaining_read_paths() {
    let wire =
        serde_json::json!({"error": "SpaceDeleted", "message": "generation permanently deleted"});
    let meks: FindMeksError = decode(&wire).unwrap();
    let attachment: GetAttachmentBlobError = decode(&wire).unwrap();
    assert!(matches!(meks, FindMeksError::SpaceDeleted(_)));
    assert!(matches!(
        attachment,
        GetAttachmentBlobError::SpaceDeleted(_)
    ));
    assert_eq!(serde_json::to_value(meks).unwrap(), wire);
    assert_eq!(serde_json::to_value(attachment).unwrap(), wire);
}
