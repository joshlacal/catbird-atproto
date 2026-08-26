use catbird_atproto::generated::blue_catbird::mlsDS::get_convo_events::{
    ConvoEventEntry, ConvoEventEntryEntryKind,
};
use jacquard_lexicon::lexicon::{LexObjectProperty, LexUserType};
use jacquard_lexicon::schema::LexiconSchema;
use serde_json::{json, Value};

fn clean_event_json() -> Value {
    json!({
        "seq": 1,
        "epoch": 0,
        "msgId": "msg-1",
        "messageType": "app",
        "ciphertext": {"$bytes": "AQ=="},
        "paddedSize": 1,
        "createdAt": "2026-08-21T12:00:00.000Z",
        "entryId": "00112233-4455-4677-8899-aabbccddeeff",
        "entryKind": "blue.catbird.chat.defs#applicationEntry",
        "acceptedPayloadSha256": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        "signedRequest": {"$bytes": "AQ=="},
        "outerFingerprint": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    })
}

fn legacy_event_json() -> Value {
    json!({
        "seq": 1,
        "epoch": 0,
        "msgId": "msg-1",
        "messageType": "app",
        "ciphertext": {"$bytes": "AQ=="},
        "paddedSize": 1,
        "createdAt": "2026-08-21T12:00:00.000Z"
    })
}

#[test]
fn complete_clean_event_decodes_sealed_evidence() {
    let raw = serde_json::to_vec(&clean_event_json()).unwrap();
    let entry: ConvoEventEntry = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        entry.entry_id.as_deref(),
        Some("00112233-4455-4677-8899-aabbccddeeff")
    );
    assert_eq!(
        entry.entry_kind.as_ref().map(|k| k.as_str()),
        Some("blue.catbird.chat.defs#applicationEntry")
    );
    assert_eq!(
        entry.entry_kind.as_ref(),
        Some(&ConvoEventEntryEntryKind::ApplicationEntry)
    );
    assert_eq!(entry.accepted_payload_sha256.as_ref().unwrap().len(), 32);
    assert_eq!(entry.signed_request.as_ref().unwrap().as_ref(), &[1]);
    assert_eq!(entry.outer_fingerprint.as_ref().unwrap().len(), 32);
    assert!(entry.validate().is_ok());
}

#[test]
fn legacy_event_without_clean_fields_decodes() {
    let raw = serde_json::to_vec(&legacy_event_json()).unwrap();
    let entry: ConvoEventEntry = serde_json::from_slice(&raw).unwrap();
    assert_eq!(entry.seq, 1);
    assert_eq!(entry.entry_id, None);
    assert_eq!(entry.entry_kind, None);
    assert_eq!(entry.accepted_payload_sha256, None);
    assert_eq!(entry.signed_request, None);
    assert_eq!(entry.outer_fingerprint, None);
    assert!(entry.validate().is_ok());
}

fn validate_convo_event_bounds(entry: &ConvoEventEntry) -> Result<(), &'static str> {
    if let Some(hash) = &entry.accepted_payload_sha256 {
        if hash.len() != 32 {
            return Err("acceptedPayloadSha256 must be 32 bytes");
        }
    }
    if let Some(fp) = &entry.outer_fingerprint {
        if fp.len() != 32 {
            return Err("outerFingerprint must be 32 bytes");
        }
    }
    if let Some(req) = &entry.signed_request {
        if req.is_empty() || req.len() > 1_048_576 {
            return Err("signedRequest must be between 1 and 1048576 bytes");
        }
    }
    Ok(())
}

#[test]
fn convo_event_entry_validates_hash_and_fingerprint_length() {
    let b64_31 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let b64_33 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    for field in ["acceptedPayloadSha256", "outerFingerprint"] {
        for (invalid_len, b64_val) in [(31, b64_31), (33, b64_33)] {
            let mut value = clean_event_json();
            value[field] = json!({"$bytes": b64_val});
            let raw = serde_json::to_vec(&value).unwrap();
            let entry: ConvoEventEntry = serde_json::from_slice(&raw).unwrap();
            assert!(
                validate_convo_event_bounds(&entry).is_err(),
                "accepted invalid length {invalid_len} for {field}"
            );
        }
    }
}

#[test]
fn convo_event_entry_validates_signed_request_bounds() {
    let b64_empty = "";
    let b64_over_1mib = "A".repeat(1_398_104);

    for (name, b64_val) in [
        ("empty", b64_empty.to_string()),
        ("over-1-MiB", b64_over_1mib),
    ] {
        let mut value = clean_event_json();
        value["signedRequest"] = json!({"$bytes": b64_val});
        let raw = serde_json::to_vec(&value).unwrap();
        let entry: ConvoEventEntry = serde_json::from_slice(&raw).unwrap();
        assert!(
            validate_convo_event_bounds(&entry).is_err(),
            "accepted invalid signedRequest: {name}"
        );
    }
}

#[test]
fn convo_event_entry_lexicon_schema_doc_declares_exact_bounds() {
    let doc = ConvoEventEntry::<jacquard_common::DefaultStr>::lexicon_doc();
    let def = doc
        .defs
        .get("convoEventEntry")
        .expect("convoEventEntry def");
    let LexUserType::Object(obj) = def else {
        panic!("expected Object user type");
    };

    let accepted_sha = obj.properties.get("acceptedPayloadSha256").unwrap();
    let LexObjectProperty::Bytes(b) = accepted_sha else {
        panic!("expected Bytes property for acceptedPayloadSha256");
    };
    assert_eq!(b.min_length, Some(32));
    assert_eq!(b.max_length, Some(32));

    let outer_fp = obj.properties.get("outerFingerprint").unwrap();
    let LexObjectProperty::Bytes(b) = outer_fp else {
        panic!("expected Bytes property for outerFingerprint");
    };
    assert_eq!(b.min_length, Some(32));
    assert_eq!(b.max_length, Some(32));

    let signed_req = obj.properties.get("signedRequest").unwrap();
    let LexObjectProperty::Bytes(b) = signed_req else {
        panic!("expected Bytes property for signedRequest");
    };
    assert_eq!(b.min_length, Some(1));
    assert_eq!(b.max_length, Some(1048576));
}
