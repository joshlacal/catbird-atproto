use catbird_atproto::generated::blue_catbird::chat::BlobUploadPreparationBody;
use catbird_atproto::jacquard_common::DefaultStr;
use jacquard_lexicon::schema::LexiconSchema;
use serde_json::{json, Value};

#[test]
fn blob_prepare_body_exposes_media_and_plaintext_sizes() {
    // These fields are part of the signed preparation contract.  Keep this
    // compile-time tripwire next to the generated surface so a lexicon/source
    // regression cannot silently fall back to a server-side default.
    let _ = BlobUploadPreparationBody::<DefaultStr>::builder()
        .media_type("image/png")
        .plaintext_size(1);
}

fn valid_body() -> Value {
    json!({
        "actorDeviceId": "3b241101-e2bb-4255-8caf-4136c566a962",
        "actorDid": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
        "authGeneration": 1,
        "blobId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "ciphertextSha256": vec![0_u8; 32],
        "ciphertextSize": 17,
        "conversationId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "idempotencyKey": "8cb4f5d2-0d31-4b6f-a9c2-7e18f5403d61",
        "keyId": "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk",
        "mediaType": "image/png",
        "plaintextSize": 1,
        "prior": {
            "conversationId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
            "generation": 0,
            "stateVersion": 0,
            "groupId": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            "epoch": 0,
            "groupContextHash": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            "confirmationTag": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            "lifecycle": "active"
        },
        "purpose": "attachment",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\u{0000}",
        "signedAt": "2026-07-22T14:05:09.123Z"
    })
}

#[test]
fn blob_prepare_body_rejects_missing_media_metadata() {
    for field in ["mediaType", "plaintextSize"] {
        let mut value = valid_body();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_slice::<BlobUploadPreparationBody>(
            &serde_json::to_vec(&value).unwrap()
        )
        .is_err());
    }
}

#[test]
fn blob_prepare_body_validates_media_metadata_bounds() {
    for (field, invalid) in [
        ("mediaType", json!("")),
        ("mediaType", json!("x".repeat(129))),
        ("plaintextSize", json!(0)),
        ("plaintextSize", json!(10_485_745)),
    ] {
        let mut value = valid_body();
        value[field] = invalid;
        let body: BlobUploadPreparationBody =
            serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(body.validate().is_err(), "accepted invalid {field}");
    }
}
