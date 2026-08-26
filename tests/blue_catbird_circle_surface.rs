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
fn space_ref_validates_exact_uri_shape_did_nsid_and_canonical_record_key() {
    use catbird_atproto::blue_catbird::circle::defs::SpaceRef;

    // Valid space references
    let valid_uris = [
        "at://did:m:v/space/com.example.group/default",
        "at://did:plc:asdf123/space/com.example.group/default",
        "at://did:plc:owner/space/blue.catbird.circle/3abc",
        "at://did:web:example.com/space/blue.catbird.circle/3abc",
        "at://did:plc:owner/space/com.atproto.simplespace.space/tid123",
        "at://did:plc:auth123/space/com.example.drive/self",
        "at://did:plc:asdf123/space/com.example.group/test-key_123",
        "at://did:plc:asdf123/space/com.example.group/2024-01-01",
        "at://did:plc:asdf123/space/com.example.group/rkey:~._-",
    ];

    for uri in valid_uris {
        let space_ref = SpaceRef::new(uri.to_owned()).expect("valid SpaceRef should parse");
        assert_eq!(space_ref.as_str(), uri);

        // Round-trip through serde
        let json = format!("\"{uri}\"");
        let deserialized: SpaceRef = serde_json::from_str(&json).expect("serde roundtrip");
        assert_eq!(deserialized.as_str(), uri);
    }

    let did_2048 = format!("did:plc:{}", "a".repeat(2040));
    let valid_did_2048 = format!("at://{did_2048}/space/com.example.group/default");
    assert!(SpaceRef::new(valid_did_2048.clone()).is_ok());
    let deserialized: SpaceRef = serde_json::from_str(&format!("\"{valid_did_2048}\"")).unwrap();
    assert_eq!(deserialized.as_str(), valid_did_2048);

    let nsid_317 = format!(
        "com.example.{}.{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(49)
    );
    let valid_nsid_317 = format!("at://did:plc:asdf123/space/{nsid_317}/default");
    assert!(SpaceRef::new(valid_nsid_317.clone()).is_ok());
    let deserialized: SpaceRef = serde_json::from_str(&format!("\"{valid_nsid_317}\"")).unwrap();
    assert_eq!(deserialized.as_str(), valid_nsid_317);

    let valid_512 = format!(
        "at://did:plc:asdf123/space/com.example.group/{}",
        "a".repeat(512)
    );
    assert!(SpaceRef::new(valid_512.clone()).is_ok());
    let deserialized: SpaceRef = serde_json::from_str(&format!("\"{valid_512}\"")).unwrap();
    assert_eq!(deserialized.as_str(), valid_512);

    let did_2049 = format!("did:plc:{}", "a".repeat(2041));
    let nsid_318 = format!(
        "com.example.{}.{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(50)
    );

    // Malformed space references - rejected by both constructor and serde deserializer
    let malformed_uris = [
        // Scheme / prefix errors
        "https://example.com/space/blue.catbird.circle/3abc".to_string(),
        "at:/did:plc:asdf123/space/com.example.group/default".to_string(),
        "AT://did:plc:asdf123/space/com.example.group/default".to_string(),
        // Segment count and structure errors
        "at://did:plc:asdf123".to_string(),
        "at://did:plc:asdf123/space".to_string(),
        "at://did:plc:asdf123/space/com.example.group".to_string(),
        "at://did:plc:asdf123/space/com.example.group/default/extra".to_string(),
        "at://did:plc:asdf123/space/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc123".to_string(),
        "at://did:plc:asdf123/com.atproto.feed.post/abc".to_string(),
        "at://did:plc:asdf123/space//default".to_string(),
        "at://did:plc:asdf123/space/com.example.group/".to_string(),
        "at:///space/com.example.group/default".to_string(),
        "at://did:plc:asdf123//com.example.group/default".to_string(),
        "at://did:plc:asdf123/other/com.example.group/default".to_string(),
        // Authority DID errors
        "at://user.bsky.social/space/com.example.group/default".to_string(),
        "at://did::owner/space/blue.catbird.circle/3abc".to_string(),
        "at://did:plc:/space/blue.catbird.circle/3abc".to_string(),
        "at://invalid-did/space/blue.catbird.circle/3abc".to_string(),
        "at://did:plc:ünicode/space/com.example.group/default".to_string(),
        format!("at://{did_2049}/space/com.example.group/default"),
        // SpaceType NSID errors
        "at://did:plc:asdf123/space/short/default".to_string(),
        "at://did:plc:asdf123/space/-bad.example/3abc".to_string(),
        "at://did:plc:asdf123/space/com.example.-group/default".to_string(),
        "at://did:plc:asdf123/space/com.example..group/default".to_string(),
        "at://did:plc:asdf123/space/1com.example.group/default".to_string(),
        format!("at://did:plc:asdf123/space/{nsid_318}/default"),
        // Skey RecordKey errors
        "at://did:plc:asdf123/space/com.example.group/.".to_string(),
        "at://did:plc:asdf123/space/com.example.group/..".to_string(),
        "at://did:plc:asdf123/space/com.example.group/has space".to_string(),
        "at://did:plc:asdf123/space/com.example.group/has/slash".to_string(),
        "at://did:plc:asdf123/space/com.example.group/has@invalid".to_string(),
        "at://did:plc:asdf123/space/com.example.group/has%percent".to_string(),
    ];

    for uri in malformed_uris {
        assert!(
            SpaceRef::new(uri.to_owned()).is_err(),
            "SpaceRef::new should reject malformed URI: {uri}"
        );
        let json = format!("\"{uri}\"");
        assert!(
            serde_json::from_str::<SpaceRef>(&json).is_err(),
            "serde deserialization should reject malformed URI: {uri}"
        );
    }

    // Length over 512 for skey
    let overlength_skey = format!(
        "at://did:plc:asdf123/space/com.example.group/{}",
        "a".repeat(513)
    );
    assert!(SpaceRef::new(overlength_skey.clone()).is_err());
    assert!(serde_json::from_str::<SpaceRef>(&format!("\"{overlength_skey}\"")).is_err());

    // Length over 8192 for total URI
    let overlength_uri = format!(
        "at://did:plc:asdf123/space/com.example.group/{}",
        "a".repeat(8200)
    );
    assert!(SpaceRef::new(overlength_uri.clone()).is_err());
    assert!(serde_json::from_str::<SpaceRef>(&format!("\"{overlength_uri}\"")).is_err());
}
