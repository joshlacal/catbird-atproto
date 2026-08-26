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
        "acceptedPayloadSha256": {"$bytes": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
        "signedRequest": {"$bytes": "QUJDRA=="},
        "outerFingerprint": {"$bytes": "oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8A="}
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

    let expected_sha: Vec<u8> = (1_u8..=32).collect();
    let expected_signed_req: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44];
    let expected_fingerprint: Vec<u8> = (0xa1_u8..=0xc0).collect();

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
    assert_eq!(
        entry.accepted_payload_sha256.as_deref(),
        Some(expected_sha.as_slice())
    );
    assert_eq!(
        entry.signed_request.as_deref(),
        Some(expected_signed_req.as_slice())
    );
    assert_eq!(
        entry.outer_fingerprint.as_deref(),
        Some(expected_fingerprint.as_slice())
    );
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

#[test]
fn convo_event_entry_kind_table_driven_mapping_and_round_trip() {
    let cases: [(&str, ConvoEventEntryEntryKind); 14] = [
        (
            "blue.catbird.chat.defs#applicationEntry",
            ConvoEventEntryEntryKind::ApplicationEntry,
        ),
        (
            "blue.catbird.chat.defs#commitEntry",
            ConvoEventEntryEntryKind::CommitEntry,
        ),
        (
            "blue.catbird.chat.defs#policyEntry",
            ConvoEventEntryEntryKind::PolicyEntry,
        ),
        (
            "blue.catbird.chat.defs#metadataEntry",
            ConvoEventEntryEntryKind::MetadataEntry,
        ),
        (
            "blue.catbird.chat.defs#creationEntry",
            ConvoEventEntryEntryKind::CreationEntry,
        ),
        (
            "blue.catbird.chat.defs#participantAcceptanceEntry",
            ConvoEventEntryEntryKind::ParticipantAcceptanceEntry,
        ),
        (
            "blue.catbird.chat.defs#conversationCloseEntry",
            ConvoEventEntryEntryKind::ConversationCloseEntry,
        ),
        (
            "blue.catbird.chat.defs#resetRequestEntry",
            ConvoEventEntryEntryKind::ResetRequestEntry,
        ),
        (
            "blue.catbird.chat.defs#resetActivationEntry",
            ConvoEventEntryEntryKind::ResetActivationEntry,
        ),
        (
            "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
            ConvoEventEntryEntryKind::LeafRecoveryFulfillmentEntry,
        ),
        (
            "blue.catbird.chat.defs#leaveRequestEntry",
            ConvoEventEntryEntryKind::LeaveRequestEntry,
        ),
        (
            "blue.catbird.chat.defs#zeroLeafLeaveEntry",
            ConvoEventEntryEntryKind::ZeroLeafLeaveEntry,
        ),
        (
            "blue.catbird.chat.defs#leaveCancellationEntry",
            ConvoEventEntryEntryKind::LeaveCancellationEntry,
        ),
        (
            "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
            ConvoEventEntryEntryKind::LeaveCommitFulfillmentEntry,
        ),
    ];

    for (raw_str, expected_variant) in cases {
        // Direct from_value construction
        let constructed =
            ConvoEventEntryEntryKind::from_value(jacquard_common::DefaultStr::from(raw_str));
        assert_eq!(
            constructed, expected_variant,
            "from_value mismatch for {raw_str}"
        );
        assert_eq!(
            constructed.as_str(),
            raw_str,
            "as_str mismatch for {raw_str}"
        );

        // Also test &str variant construction
        let constructed_borrowed = ConvoEventEntryEntryKind::from_value(raw_str);
        assert_eq!(
            constructed_borrowed.as_str(),
            raw_str,
            "borrowed as_str mismatch for {raw_str}"
        );

        // JSON deserialization into enum
        let json_val = json!(raw_str);
        let decoded: ConvoEventEntryEntryKind = serde_json::from_value(json_val.clone()).unwrap();
        assert_eq!(
            decoded, expected_variant,
            "JSON deserialize mismatch for {raw_str}"
        );
        assert_eq!(
            decoded.as_str(),
            raw_str,
            "decoded as_str mismatch for {raw_str}"
        );

        // JSON serialization round-trip
        let serialized = serde_json::to_value(&decoded).unwrap();
        assert_eq!(
            serialized, json_val,
            "JSON serialize round-trip mismatch for {raw_str}"
        );

        // Deserialization within a ConvoEventEntry
        let mut entry_val = clean_event_json();
        entry_val["entryKind"] = json!(raw_str);
        let raw_entry = serde_json::to_vec(&entry_val).unwrap();
        let entry: ConvoEventEntry = serde_json::from_slice(&raw_entry).unwrap();
        assert_eq!(
            entry.entry_kind.as_ref(),
            Some(&expected_variant),
            "entry.entry_kind mismatch for {raw_str}"
        );
    }

    // Unknown forward-compatible variant
    let unknown_str = "blue.catbird.chat.defs#futureExtensionEntry";
    let unknown_constructed =
        ConvoEventEntryEntryKind::from_value(jacquard_common::DefaultStr::from(unknown_str));
    assert_eq!(
        unknown_constructed,
        ConvoEventEntryEntryKind::Other(jacquard_common::DefaultStr::from(unknown_str))
    );
    assert_eq!(unknown_constructed.as_str(), unknown_str);

    let unknown_json = json!(unknown_str);
    let unknown_decoded: ConvoEventEntryEntryKind =
        serde_json::from_value(unknown_json.clone()).unwrap();
    assert_eq!(
        unknown_decoded,
        ConvoEventEntryEntryKind::Other(jacquard_common::DefaultStr::from(unknown_str))
    );
    assert_eq!(unknown_decoded.as_str(), unknown_str);

    let unknown_serialized = serde_json::to_value(&unknown_decoded).unwrap();
    assert_eq!(unknown_serialized, unknown_json);

    let mut entry_val = clean_event_json();
    entry_val["entryKind"] = json!(unknown_str);
    let raw_entry = serde_json::to_vec(&entry_val).unwrap();
    let entry: ConvoEventEntry = serde_json::from_slice(&raw_entry).unwrap();
    assert_eq!(
        entry.entry_kind.as_ref(),
        Some(&ConvoEventEntryEntryKind::Other(
            jacquard_common::DefaultStr::from(unknown_str)
        ))
    );
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

    let entry_id = obj.properties.get("entryId").unwrap();
    assert!(matches!(entry_id, LexObjectProperty::String(_)));

    let entry_kind = obj.properties.get("entryKind").unwrap();
    assert!(matches!(entry_kind, LexObjectProperty::String(_)));

    let required = obj.required.as_ref().expect("required properties");
    for optional_field in [
        "entryId",
        "entryKind",
        "acceptedPayloadSha256",
        "signedRequest",
        "outerFingerprint",
    ] {
        assert!(
            !required.iter().any(|r| r.as_str() == optional_field),
            "{optional_field} must not be in required properties"
        );
    }
}
