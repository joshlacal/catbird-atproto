use catbird_atproto::blue_catbird::circle::defs::CircleSummary;

#[test]
fn circle_summary_keeps_space_uri() {
    let value = serde_json::json!({
        "uri": "at://did:plc:owner/space/blue.catbird.circle/3abc",
        "name": "Family",
        "owner": "did:plc:owner",
        "accessState": "active"
    });
    let summary: CircleSummary = serde_json::from_value(value).unwrap();
    assert_eq!(summary.name.as_str(), "Family");
}

#[test]
fn circle_closed_enums_reject_unknown_values() {
    assert!(
        serde_json::from_str::<catbird_atproto::blue_catbird::circle::defs::AccessState>(
            r#"\"unknown\""#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<catbird_atproto::blue_catbird::circle::defs::OperationStatus>(
            r#"\"unknown\""#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<catbird_atproto::blue_catbird::circle::defs::NotificationReason>(
            r#"\"unknown\""#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<catbird_atproto::blue_catbird::circle::defs::ReportReason>(
            r#"\"unknown\""#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<catbird_atproto::blue_catbird::circle::defs::MemberAction>(
            r#"\"unknown\""#
        )
        .is_err()
    );
}

#[test]
fn space_ref_rejects_malformed_did_and_nsid_components() {
    use catbird_atproto::blue_catbird::circle::defs::SpaceRef;

    for uri in [
        "at://did::owner/space/blue.catbird.circle/3abc",
        "at://did:plc:owner/space/-bad.example/3abc",
    ] {
        assert!(
            SpaceRef::new(uri.to_owned()).is_err(),
            "malformed SpaceRef should be rejected: {uri}"
        );
    }
}
