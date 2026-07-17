#![cfg(feature = "namespace-bluecatbird")]

use catbird_atproto::catbird::mls_chat::commit_group_change::{Input, InputData};
use catbird_atproto::generated::blue_catbird::{mlsChat, mlsDS};

const RECEIPT: &str = r#"{
  "convoId":"convo-1",
  "epoch":8,
  "sequencerTerm":3,
  "commitHash":{"$bytes":"AQID"},
  "sequencerDid":"did:web:sequencer.example",
  "issuedAt":1710000000,
  "signature":{"$bytes":"BAUG"}
}"#;

fn receipt_with_unknown_security_field() -> serde_json::Value {
    let mut receipt = serde_json::from_str::<serde_json::Value>(RECEIPT).unwrap();
    receipt.as_object_mut().unwrap().insert(
        "futureSignedSecurityField".to_owned(),
        serde_json::json!(true),
    );
    receipt
}

#[test]
fn commit_group_change_output_rejects_unknown_nested_receipt_properties() {
    let fixture = serde_json::json!({
        "success": true,
        "newEpoch": 8,
        "receipt": receipt_with_unknown_security_field()
    });

    let result = serde_json::from_str::<mlsChat::commit_group_change::CommitGroupChangeOutput>(
        &fixture.to_string(),
    );
    assert!(
        result.is_err(),
        "strict receipt carrier accepted an unsigned nested property"
    );
}

#[test]
fn submit_commit_output_rejects_unknown_nested_receipt_properties() {
    let fixture = serde_json::json!({
        "accepted": true,
        "assignedEpoch": 8,
        "receipt": receipt_with_unknown_security_field(),
        "sequencerTerm": 3
    });

    let result =
        serde_json::from_str::<mlsDS::submit_commit::SubmitCommitOutput>(&fixture.to_string());
    assert!(
        result.is_err(),
        "strict receipt carrier accepted an unsigned nested property"
    );
}

#[test]
fn optional_strict_receipt_carriers_preserve_absent_null_and_clean_values() {
    for receipt in [None, Some(serde_json::Value::Null)] {
        let mut commit_fixture = serde_json::json!({"success": true, "newEpoch": 8});
        if let Some(receipt) = receipt.clone() {
            commit_fixture["receipt"] = receipt;
        }
        let commit_output = serde_json::from_str::<
            mlsChat::commit_group_change::CommitGroupChangeOutput,
        >(&commit_fixture.to_string())
        .unwrap();
        assert!(commit_output.receipt.is_none());

        let mut submit_fixture = serde_json::json!({
            "accepted": true,
            "assignedEpoch": 8,
            "sequencerTerm": 3
        });
        if let Some(receipt) = receipt {
            submit_fixture["receipt"] = receipt;
        }
        let submit_output = serde_json::from_str::<mlsDS::submit_commit::SubmitCommitOutput>(
            &submit_fixture.to_string(),
        )
        .unwrap();
        assert!(submit_output.receipt.is_none());
    }

    let clean_receipt = serde_json::from_str::<serde_json::Value>(RECEIPT).unwrap();
    let commit_output =
        serde_json::from_str::<mlsChat::commit_group_change::CommitGroupChangeOutput>(
            &serde_json::json!({
                "success": true,
                "newEpoch": 8,
                "receipt": clean_receipt.clone()
            })
            .to_string(),
        )
        .unwrap();
    assert_eq!(commit_output.receipt.unwrap().sequencer_term, 3);

    let submit_output = serde_json::from_str::<mlsDS::submit_commit::SubmitCommitOutput>(
        &serde_json::json!({
            "accepted": true,
            "assignedEpoch": 8,
            "receipt": clean_receipt,
            "sequencerTerm": 3
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(submit_output.receipt.unwrap().sequencer_term, 3);
}

#[test]
fn direct_receipt_decode_remains_forward_compatible() {
    let receipt = serde_json::from_str::<mlsChat::commit_group_change::SequencerReceipt>(
        &receipt_with_unknown_security_field().to_string(),
    )
    .unwrap();

    assert!(receipt
        .extra_data
        .as_ref()
        .unwrap()
        .contains_key("futureSignedSecurityField"));
}

#[test]
fn typed_receipt_and_exact_wire_carriers_round_trip_losslessly() {
    let receipt: serde_json::Value = serde_json::from_str(RECEIPT).unwrap();
    let submit_output_fixture = serde_json::json!({
        "accepted": true,
        "assignedEpoch": 8,
        "receipt": receipt,
        "receiptWire": {"$bytes": "CQgHBg=="},
        "sequencerTerm": 3
    });
    let submit_output_json = submit_output_fixture.to_string();
    let output: mlsDS::submit_commit::SubmitCommitOutput =
        serde_json::from_str(&submit_output_json).unwrap();
    let typed = output.receipt.as_ref().unwrap();
    assert_eq!(typed.convo_id.as_str(), "convo-1");
    assert_eq!(typed.epoch, 8);
    assert_eq!(typed.sequencer_term, 3);
    assert_eq!(typed.commit_hash.as_ref(), &[1, 2, 3]);
    assert_eq!(typed.signature.as_ref(), &[4, 5, 6]);
    assert_eq!(output.receipt_wire.as_deref(), Some(&[9, 8, 7, 6][..]));

    let round_trip = serde_json::to_value(&output).unwrap();
    assert_eq!(round_trip["receipt"]["epoch"], 8);
    assert_eq!(round_trip["receipt"]["sequencerTerm"], 3);
    assert_eq!(round_trip["receiptWire"]["$bytes"], "CQgHBg==");

    let commit_output_fixture = serde_json::json!({
        "success": true,
        "newEpoch": 8,
        "receipt": serde_json::from_str::<serde_json::Value>(RECEIPT).unwrap()
    })
    .to_string();
    let commit_output: mlsChat::commit_group_change::CommitGroupChangeOutput =
        serde_json::from_str(&commit_output_fixture).unwrap();
    assert_eq!(commit_output.receipt.unwrap().sequencer_term, 3);
}

#[test]
fn receipt_wire_and_reset_generation_survive_message_transports() {
    let message_fixture = serde_json::json!({
        "ciphertext": {"$bytes": "AQI="},
        "convoId": "convo-1",
        "createdAt": "2026-07-17T12:00:00Z",
        "epoch": 8,
        "id": "message-1",
        "messageType": "commit",
        "receiptWire": {"$bytes": "CQgHBg=="},
        "resetGeneration": 5,
        "seq": 42
    });
    let message_json = message_fixture.to_string();
    let message: mlsChat::MessageView = serde_json::from_str(&message_json).unwrap();
    assert_eq!(message.epoch, 8);
    assert_eq!(message.receipt_wire.as_deref(), Some(&[9, 8, 7, 6][..]));
    assert_eq!(message.reset_generation, Some(5));

    let event_fixture = serde_json::json!({
        "ciphertext": {"$bytes": "AQI="},
        "createdAt": "2026-07-17T12:00:00Z",
        "epoch": 8,
        "messageType": "commit",
        "msgId": "message-1",
        "paddedSize": 64,
        "receiptWire": {"$bytes": "CQgHBg=="},
        "resetGeneration": 5,
        "seq": 42
    });
    let event_json = event_fixture.to_string();
    let event: mlsDS::get_convo_events::ConvoEventEntry =
        serde_json::from_str(&event_json).unwrap();
    assert_eq!(event.epoch, 8);
    assert_eq!(event.receipt_wire.as_deref(), Some(&[9, 8, 7, 6][..]));
    assert_eq!(event.reset_generation, Some(5));

    let encoded = serde_json::to_value((message, event)).unwrap();
    assert_eq!(encoded[0]["receiptWire"]["$bytes"], "CQgHBg==");
    assert_eq!(encoded[0]["resetGeneration"], 5);
    assert_eq!(encoded[1]["receiptWire"]["$bytes"], "CQgHBg==");
    assert_eq!(encoded[1]["resetGeneration"], 5);
}

#[test]
fn submit_commit_preserves_epoch_term_generation_and_idempotency_identity() {
    let fixture = serde_json::json!({
        "commitData": {"$bytes": "AQI="},
        "commitHash": {"$bytes": "AwQ="},
        "convoId": "convo-1",
        "epoch": 7,
        "idempotencyKey": "550e8400-e29b-41d4-a716-446655440000",
        "proposedEpoch": 8,
        "resetGeneration": 5,
        "senderDsDid": "did:web:sender.example",
        "sequencerTerm": 3
    });
    let request_json = fixture.to_string();
    let request: mlsDS::submit_commit::SubmitCommit = serde_json::from_str(&request_json).unwrap();
    assert_eq!(request.epoch, 7);
    assert_eq!(request.proposed_epoch, 8);
    assert_eq!(request.reset_generation, 5);
    assert_eq!(request.sequencer_term, 3);
    assert_eq!(
        request.idempotency_key.as_str(),
        "550e8400-e29b-41d4-a716-446655440000"
    );

    let encoded = serde_json::to_value(request).unwrap();
    assert_eq!(encoded["epoch"], 7);
    assert_eq!(encoded["proposedEpoch"], 8);
    assert_eq!(encoded["resetGeneration"], 5);
    assert_eq!(encoded["sequencerTerm"], 3);
    assert_eq!(
        encoded["idempotencyKey"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
}

fn input_data(
    transition_challenge_id: Option<String>,
    transition_signature: Option<Vec<u8>>,
) -> InputData {
    InputData {
        action: "refreshGroupInfo".to_owned(),
        commit: None,
        confirmation_tag: None,
        convo_id: "convo-1".to_owned(),
        device_id: None,
        epoch_authenticator: None,
        group_info: None,
        idempotency_key: None,
        key_package_hashes: None,
        member_dids: None,
        pending_addition_id: None,
        transition_challenge_id,
        transition_signature,
        welcome: None,
    }
}

#[test]
fn handwritten_conversion_preserves_absent_transition_attestation() {
    let input: Input = input_data(None, None).into();
    assert!(input.transition_challenge_id.is_none());
    assert!(input.transition_signature.is_none());
}

#[test]
fn handwritten_conversion_preserves_present_transition_attestation_bytes() {
    let input: Input = input_data(
        Some("550e8400-e29b-41d4-a716-446655440001".to_owned()),
        Some(vec![0, 1, 2, 127, 128, 255]),
    )
    .into();
    assert_eq!(
        input.transition_challenge_id.as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440001")
    );
    assert_eq!(
        input.transition_signature.as_deref(),
        Some(&[0, 1, 2, 127, 128, 255][..])
    );
}
