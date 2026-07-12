use catbird_atproto::generated::blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput;

#[test]
fn legacy_output_decodes_without_receipt() {
    let output: CommitGroupChangeOutput<'_> =
        serde_json::from_str(r#"{"success":true,"newEpoch":7}"#).unwrap();
    assert!(output.receipt.is_none());
}

#[test]
fn full_receipt_decodes_and_round_trips_losslessly() {
    let fixture = r#"{"success":true,"newEpoch":8,"receipt":{"convoId":"convo-1","epoch":8,"sequencerTerm":3,"commitHash":{"$bytes":"AQID"},"sequencerDid":"did:web:sequencer.example","issuedAt":1710000000,"signature":{"$bytes":"BAUG"}}}"#;
    let output: CommitGroupChangeOutput<'_> = serde_json::from_str(fixture).unwrap();
    let receipt = output.receipt.as_ref().unwrap();
    assert_eq!(receipt.convo_id.as_ref(), "convo-1");
    assert_eq!(receipt.epoch, 8);
    assert_eq!(receipt.sequencer_term, 3);
    assert_eq!(receipt.commit_hash.as_ref(), &[1, 2, 3]);
    assert_eq!(receipt.sequencer_did.as_ref(), "did:web:sequencer.example");
    assert_eq!(receipt.issued_at, 1_710_000_000);
    assert_eq!(receipt.signature.as_ref(), &[4, 5, 6]);

    let encoded = serde_json::to_string(&output).unwrap();
    let round_trip: CommitGroupChangeOutput<'_> = serde_json::from_str(&encoded).unwrap();
    let round_trip_receipt = round_trip.receipt.unwrap();
    assert_eq!(round_trip_receipt.sequencer_term, 3);
    assert_eq!(round_trip_receipt.commit_hash.as_ref(), &[1, 2, 3]);
    assert_eq!(round_trip_receipt.signature.as_ref(), &[4, 5, 6]);
}

#[test]
fn malformed_present_receipts_are_rejected() {
    let malformed = [
        r#"{"success":true,"receipt":{"convoId":"convo-1","epoch":8,"commitHash":{"$bytes":"AQID"},"sequencerDid":"did:web:sequencer.example","issuedAt":1710000000,"signature":{"$bytes":"BAUG"}}}"#,
        r#"{"success":true,"receipt":{"convoId":"convo-1","epoch":8,"sequencerTerm":3,"commitHash":{"$bytes":"AQID"},"sequencerDid":"not-a-did","issuedAt":1710000000,"signature":{"$bytes":"BAUG"}}}"#,
        r#"{"success":true,"receipt":{"convoId":"convo-1","epoch":8,"sequencerTerm":3,"commitHash":{"$bytes":"%%%"},"sequencerDid":"did:web:sequencer.example","issuedAt":1710000000,"signature":{"$bytes":"BAUG"}}}"#,
        r#"{"success":true,"receipt":{"convoId":"convo-1","epoch":"eight","sequencerTerm":3,"commitHash":{"$bytes":"AQID"},"sequencerDid":"did:web:sequencer.example","issuedAt":1710000000,"signature":{"$bytes":"BAUG"}}}"#,
    ];
    for fixture in malformed {
        assert!(
            serde_json::from_str::<CommitGroupChangeOutput<'_>>(fixture).is_err(),
            "expected deserialization to fail for fixture: {fixture}"
        );
    }
}
