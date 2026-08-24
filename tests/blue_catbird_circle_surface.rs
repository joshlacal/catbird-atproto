use catbird_atproto::blue_catbird::circle::CircleSummary;

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
