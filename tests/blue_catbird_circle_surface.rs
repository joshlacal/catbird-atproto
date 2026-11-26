use catbird_atproto::blue_catbird::circle::CircleSummary;

#[test]
fn circle_summary_keeps_space_uri() {
    let json_str = r#"{
        "uri": "at:space/did:plc:owner/blue.catbird.circle/3abc",
        "circleId": "3abcdefghijkl",
        "name": "Family",
        "owner": "did:plc:owner",
        "memberCount": 5
    }"#;
    let summary: CircleSummary = serde_json::from_str(json_str).unwrap();
    assert_eq!(summary.name.as_str(), "Family");
    assert_eq!(
        summary.uri.as_str(),
        "at:space/did:plc:owner/blue.catbird.circle/3abc"
    );
    assert_eq!(summary.circle_id.as_str(), "3abcdefghijkl");
    assert_eq!(summary.owner.as_str(), "did:plc:owner");
    assert_eq!(summary.member_count, Some(5));
}

#[test]
fn space_ref_validates_exact_uri_shape_did_nsid_and_canonical_record_key() {
    use jacquard_common::types::aturi::AtSpaceUri;
    use jacquard_common::DefaultStr;
    type SpaceRef = AtSpaceUri<DefaultStr>;

    let valid_uris = [
        "at:space/did:m:v/com.example.group/default",
        "at:space/did:plc:asdf123/com.example.group/default",
        "at:space/did:plc:owner/blue.catbird.circle/3abc",
        "at:space/did:web:example.com/blue.catbird.circle/3abc",
        "at:space/did:plc:owner/com.atproto.simplespace.space/tid123",
        "at:space/did:plc:auth123/com.example.drive/self",
        "at:space/did:plc:asdf123/com.example.group/test-key_123",
        "at:space/did:plc:asdf123/com.example.group/2024-01-01",
        "at:space/did:plc:asdf123/com.example.group/rkey:~._-",
        // Permissioned record form (7 segments) is also a valid AtSpaceUri
        "at:space/did:plc:asdf123/com.example.group/default/did:plc:user1/com.atproto.feed.post/abc123",
    ];

    for uri in valid_uris {
        let space_ref = SpaceRef::new_owned(uri).expect("valid SpaceRef should parse");
        assert_eq!(space_ref.as_str(), uri);

        // Round-trip through serde
        let json = format!("\"{uri}\"");
        let deserialized: SpaceRef = serde_json::from_str(&json).expect("serde roundtrip");
        assert_eq!(deserialized.as_str(), uri);
    }

    let did_2048 = format!("did:plc:{}", "a".repeat(2040));
    let valid_did_2048 = format!("at:space/{did_2048}/com.example.group/default");
    assert!(SpaceRef::new_owned(valid_did_2048.clone()).is_ok());
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
    let valid_nsid_317 = format!("at:space/did:plc:asdf123/{nsid_317}/default");
    assert!(SpaceRef::new_owned(valid_nsid_317.clone()).is_ok());
    let deserialized: SpaceRef = serde_json::from_str(&format!("\"{valid_nsid_317}\"")).unwrap();
    assert_eq!(deserialized.as_str(), valid_nsid_317);

    let valid_512 = format!(
        "at:space/did:plc:asdf123/com.example.group/{}",
        "a".repeat(512)
    );
    assert!(SpaceRef::new_owned(valid_512.clone()).is_ok());
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
        // Spaces alpha form: strict space-ref validation accepts only `at:space/`
        "at://did:plc:asdf123/space/com.example.group/default".to_string(),
        "at://did:plc:owner/space/blue.catbird.circle/3abc".to_string(),
        "AT:SPACE/did:plc:asdf123/com.example.group/default".to_string(),
        "https://example.com/space/blue.catbird.circle/3abc".to_string(),
        "at:/did:plc:asdf123/space/com.example.group/default".to_string(),
        "AT://did:plc:asdf123/space/com.example.group/default".to_string(),
        // Segment count and structure errors
        "at://did:plc:asdf123".to_string(),
        "at:space/did:plc:asdf123".to_string(),
        "at:space/did:plc:asdf123/com.example.group".to_string(),
        "at:space/did:plc:asdf123/com.example.group/default/extra".to_string(),
        "at:space/did:plc:asdf123/com.example.group/default/did:plc:user1/com.atproto.feed.post"
            .to_string(),
        "at://did:plc:asdf123/com.atproto.feed.post/abc".to_string(),
        "at:space/did:plc:asdf123//default".to_string(),
        "at:space/did:plc:asdf123/com.example.group/".to_string(),
        "at:space//com.example.group/default".to_string(),
        "at://did:plc:asdf123//com.example.group/default".to_string(),
        "at://did:plc:asdf123/other/com.example.group/default".to_string(),
        // Authority DID errors
        "at:space/user.bsky.social/com.example.group/default".to_string(),
        "at:space/did::owner/blue.catbird.circle/3abc".to_string(),
        "at:space/did:plc:/blue.catbird.circle/3abc".to_string(),
        "at:space/invalid-did/blue.catbird.circle/3abc".to_string(),
        "at:space/did:plc:ünicode/com.example.group/default".to_string(),
        format!("at:space/{did_2049}/com.example.group/default"),
        // SpaceType NSID errors
        "at:space/did:plc:asdf123/short/default".to_string(),
        "at:space/did:plc:asdf123/-bad.example/3abc".to_string(),
        "at:space/did:plc:asdf123/com.example.-group/default".to_string(),
        "at:space/did:plc:asdf123/com.example..group/default".to_string(),
        "at:space/did:plc:asdf123/1com.example.group/default".to_string(),
        format!("at:space/did:plc:asdf123/{nsid_318}/default"),
        // Skey RecordKey errors
        "at:space/did:plc:asdf123/com.example.group/.".to_string(),
        "at:space/did:plc:asdf123/com.example.group/..".to_string(),
        "at:space/did:plc:asdf123/com.example.group/has space".to_string(),
        "at:space/did:plc:asdf123/com.example.group/has/slash".to_string(),
        "at:space/did:plc:asdf123/com.example.group/has@invalid".to_string(),
        "at:space/did:plc:asdf123/com.example.group/has%percent".to_string(),
    ];

    for uri in malformed_uris {
        assert!(
            SpaceRef::new_owned(uri.clone()).is_err(),
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
        "at:space/did:plc:asdf123/com.example.group/{}",
        "a".repeat(513)
    );
    assert!(SpaceRef::new_owned(overlength_skey.clone()).is_err());
    assert!(serde_json::from_str::<SpaceRef>(&format!("\"{overlength_skey}\"")).is_err());

    // Length over 8192 for total URI
    let overlength_uri = format!(
        "at:space/did:plc:asdf123/com.example.group/{}",
        "a".repeat(8200)
    );
    assert!(SpaceRef::new_owned(overlength_uri.clone()).is_err());
    assert!(serde_json::from_str::<SpaceRef>(&format!("\"{overlength_uri}\"")).is_err());
}
