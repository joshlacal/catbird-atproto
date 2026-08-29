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
    let entry: ConvoEventEntry<jacquard_common::DefaultStr> =
        serde_json::from_str(&clean_event_json().to_string()).unwrap();
    let expected_sha: Vec<u8> = (1_u8..=32).collect();
    let expected_signed_req = [0x41, 0x42, 0x43, 0x44];
    let expected_fingerprint: Vec<u8> = (0xa1_u8..=0xc0).collect();

    assert_eq!(
        (
            entry.entry_id.as_deref(),
            entry.entry_kind.as_ref(),
            entry.accepted_payload_sha256.as_deref(),
            entry.signed_request.as_deref(),
            entry.outer_fingerprint.as_deref(),
        ),
        (
            Some("00112233-4455-4677-8899-aabbccddeeff"),
            Some(&ConvoEventEntryEntryKind::ApplicationEntry),
            Some(expected_sha.as_slice()),
            Some(expected_signed_req.as_slice()),
            Some(expected_fingerprint.as_slice()),
        )
    );
    assert!(entry.validate().is_ok());
}

#[test]
fn legacy_event_without_clean_fields_decodes() {
    let entry: ConvoEventEntry<jacquard_common::DefaultStr> =
        serde_json::from_str(&legacy_event_json().to_string()).unwrap();
    assert!(entry.validate().is_ok());
    assert_eq!(entry.seq, 1);
    assert_eq!(
        (
            entry.entry_id,
            entry.entry_kind,
            entry.accepted_payload_sha256,
            entry.signed_request,
            entry.outer_fingerprint,
        ),
        (None, None, None, None, None)
    );
}

#[test]
fn convo_event_entry_kind_table_driven_mapping_and_round_trip() {
    let cases: [(&str, ConvoEventEntryEntryKind<jacquard_common::DefaultStr>); 14] = [
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

    for (raw, expected) in cases {
        let decoded: ConvoEventEntryEntryKind = serde_json::from_value(json!(raw)).unwrap();
        assert_eq!(
            ConvoEventEntryEntryKind::from_value(jacquard_common::DefaultStr::from(raw)),
            expected,
            "from_value mismatch for {raw}"
        );
        assert_eq!(decoded, expected, "JSON mapping mismatch for {raw}");
        assert_eq!(decoded.as_str(), raw, "as_str mismatch for {raw}");
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            json!(raw),
            "JSON round-trip mismatch for {raw}"
        );

        let mut event = clean_event_json();
        event["entryKind"] = json!(raw);
        let event: ConvoEventEntry<jacquard_common::DefaultStr> =
            serde_json::from_str(&event.to_string()).unwrap();
        assert_eq!(
            event.entry_kind,
            Some(expected),
            "event entryKind mismatch for {raw}"
        );
    }

    let raw = "blue.catbird.chat.defs#futureExtensionEntry";
    let expected = ConvoEventEntryEntryKind::<jacquard_common::DefaultStr>::Other(
        jacquard_common::DefaultStr::from(raw),
    );
    let decoded: ConvoEventEntryEntryKind = serde_json::from_value(json!(raw)).unwrap();
    assert_eq!(
        ConvoEventEntryEntryKind::from_value(raw).as_str(),
        expected.as_str()
    );
    assert_eq!(decoded, expected);
    assert_eq!(decoded.as_str(), raw);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json!(raw));

    let mut event = clean_event_json();
    event["entryKind"] = json!(raw);
    let event: ConvoEventEntry<jacquard_common::DefaultStr> =
        serde_json::from_str(&event.to_string()).unwrap();
    assert_eq!(event.entry_kind, Some(expected));
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

    for (name, min, max) in [
        ("acceptedPayloadSha256", 32, 32),
        ("outerFingerprint", 32, 32),
        ("signedRequest", 1, 1_048_576),
    ] {
        let LexObjectProperty::Bytes(bytes) = obj.properties.get(name).unwrap() else {
            panic!("expected Bytes property for {name}");
        };
        assert_eq!(
            (bytes.min_length, bytes.max_length),
            (Some(min), Some(max)),
            "bounds mismatch for {name}"
        );
    }

    for name in ["entryId", "entryKind"] {
        assert!(
            matches!(obj.properties.get(name), Some(LexObjectProperty::String(_))),
            "expected String property for {name}"
        );
    }

    let required = obj.required.as_ref().expect("required properties");
    for optional_field in [
        "entryId",
        "entryKind",
        "acceptedPayloadSha256",
        "signedRequest",
        "outerFingerprint",
    ] {
        assert!(
            required.iter().all(|name| name.as_str() != optional_field),
            "{optional_field} must not be in required properties"
        );
    }
}
