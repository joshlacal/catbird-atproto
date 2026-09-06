#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn clean_chat_namespace_exports_representative_dtos() {
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}

    assert_serde::<
        catbird_atproto::generated::blue_catbird::chat::DeviceView<jacquard_common::DefaultStr>,
    >();
    assert_serde::<
        catbird_atproto::blue_catbird::chat::get_devices::GetDevicesOutput<
            jacquard_common::DefaultStr,
        >,
    >();
}

#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn signed_operation_expiry_is_typed_and_preserves_its_message() {
    use catbird_atproto::blue_catbird::chat::submit_transition::SubmitTransitionError;

    let wire = serde_json::json!({"error": "SignedOperationExpired", "message": "expired"});
    let error: SubmitTransitionError = serde_json::from_value(wire.clone()).unwrap();

    assert!(
        matches!(&error, SubmitTransitionError::SignedOperationExpired(Some(message)) if message == "expired")
    );
    assert_eq!(error.to_string(), "SignedOperationExpired: expired");
    assert_eq!(serde_json::to_value(error).unwrap(), wire);
}

#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn signed_operation_expiry_accepts_absent_message_and_roundtrips() {
    use catbird_atproto::blue_catbird::chat::submit_transition::SubmitTransitionError;

    let wire = serde_json::json!({"error": "SignedOperationExpired"});
    let error: SubmitTransitionError = serde_json::from_value(wire.clone()).unwrap();

    assert!(matches!(
        error,
        SubmitTransitionError::SignedOperationExpired(None)
    ));
    assert_eq!(error.to_string(), "SignedOperationExpired");
    let encoded = serde_json::to_value(error).unwrap();
    // Adjacent-tag error enums preserve the existing explicit-null wire form.
    assert_eq!(
        encoded,
        serde_json::json!({"error": "SignedOperationExpired", "message": null})
    );
    assert!(matches!(
        serde_json::from_value::<SubmitTransitionError>(encoded).unwrap(),
        SubmitTransitionError::SignedOperationExpired(None)
    ));
}
