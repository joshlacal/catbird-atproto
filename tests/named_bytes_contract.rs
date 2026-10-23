#![cfg(feature = "namespace-bluecatbird")]

use catbird_atproto::generated::blue_catbird::chat::{
    ApplicationAttachmentBinding, DirectRequestWelcomeBundle,
};

#[test]
fn named_bytes_decode_atproto_json_and_encode_real_dag_cbor_bytes() {
    let fixture = serde_json::json!({
        "blobId": "11111111-1111-4111-8111-111111111111",
        "ciphertextSha256": {"$bytes": "AQID"},
        "ciphertextSize": 3,
        "purpose": "attachment"
    });
    let binding: ApplicationAttachmentBinding = serde_json::from_value(fixture).unwrap();
    assert_eq!(binding.ciphertext_sha256.as_ref(), &[1, 2, 3]);

    let cbor = serde_ipld_dagcbor::to_vec(&binding).unwrap();
    let value: jacquard_common::types::value::Data =
        serde_ipld_dagcbor::from_slice(&cbor).unwrap();
    let encoded_json = serde_json::to_value(value).unwrap();
    assert_eq!(encoded_json["ciphertextSha256"], serde_json::json!({"$bytes": "AQID"}));
    let restored: ApplicationAttachmentBinding = serde_ipld_dagcbor::from_slice(&cbor).unwrap();
    assert_eq!(binding, restored);
}

#[test]
fn direct_bytes_and_named_bytes_share_the_same_wire_codec() {
    let bundle: DirectRequestWelcomeBundle = serde_json::from_value(serde_json::json!({
        "opaqueWelcome": {"$bytes": "AQID"},
        "sha256": {"$bytes": "BAUG"}
    })).unwrap();
    let cbor = serde_ipld_dagcbor::to_vec(&bundle).unwrap();
    let restored: DirectRequestWelcomeBundle = serde_ipld_dagcbor::from_slice(&cbor).unwrap();
    assert_eq!(bundle, restored);
    let json = serde_json::to_value(&bundle).unwrap();
    assert!(json["opaqueWelcome"].is_array());
    assert!(json["sha256"].is_array());
    let json_restored: DirectRequestWelcomeBundle = serde_json::from_value(json).unwrap();
    assert_eq!(bundle, json_restored);
}
