#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn generated_owned_type_is_deserialize_owned() {
    fn assert_deserialize_owned<T: serde::de::DeserializeOwned>() {}

    assert_deserialize_owned::<
        catbird_atproto::generated::blue_catbird::chat::send_message::SendMessageOutput,
    >();
}

#[cfg(feature = "namespace-site-standard")]
#[test]
fn open_union_preserves_unknown_type_and_payload() {
    use catbird_atproto::generated::site_standard::document::Document;

    let fixture = serde_json::json!({
        "$type": "site.standard.document",
        "content": {
            "$type": "com.example.richText",
            "body": {
                "blocks": [{"text": "hello"}],
                "version": 2
            },
            "futureFlag": true
        },
        "publishedAt": "2026-07-16T12:00:00Z",
        "site": "https://example.com",
        "title": "Forward-compatible document"
    });

    let document: Document = serde_json::from_value(fixture.clone()).unwrap();
    let encoded = serde_json::to_value(document).unwrap();

    assert_eq!(encoded["content"], fixture["content"]);
}
