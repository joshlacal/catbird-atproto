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

#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn participant_view_carries_optional_labyrinth_head() {
    use catbird_atproto::generated::blue_catbird::chat::ParticipantView;

    let head = [7u8; 32];
    let wire = serde_json::json!({
        "userDid": "did:plc:alice",
        "role": "member",
        "status": "active",
        "leafCount": 1,
        "labyrinthHead": {
            "epochNumber": 3,
            "epochHead": {"$bytes": base64_std(&head)},
            "attestationKeyId": "key-1",
        },
    });
    let view: ParticipantView = serde_json::from_value(wire.clone()).unwrap();
    let decoded = view.labyrinth_head.as_ref().expect("labyrinthHead decoded");
    assert_eq!(decoded.epoch_number, 3);
    assert_eq!(decoded.epoch_head.as_ref(), &head[..]);
    assert_eq!(decoded.attestation_key_id.as_str(), "key-1");
    assert_eq!(serde_json::to_value(&view).unwrap(), wire);

    let mut without = wire;
    without.as_object_mut().unwrap().remove("labyrinthHead");
    let view: ParticipantView = serde_json::from_value(without.clone()).unwrap();
    assert!(view.labyrinth_head.is_none());
    assert_eq!(serde_json::to_value(&view).unwrap(), without);
}

#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn declaration_protocol_version_two_is_known() {
    use catbird_atproto::generated::blue_catbird::chat::declaration::DeclarationProtocolVersion;

    let version: DeclarationProtocolVersion =
        serde_json::from_value(serde_json::json!("2")).unwrap();
    assert!(matches!(version, DeclarationProtocolVersion::_2));
    assert_eq!(version.as_str(), "2");
}

#[cfg(feature = "namespace-bluecatbird")]
#[test]
fn labyrinth_namespace_exports_representative_dtos() {
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}

    assert_serde::<
        catbird_atproto::blue_catbird::labyrinth::get_epoch_head::GetEpochHeadOutput<
            jacquard_common::DefaultStr,
        >,
    >();
    assert_serde::<
        catbird_atproto::blue_catbird::labyrinth::EpochPublic<jacquard_common::DefaultStr>,
    >();
}

#[cfg(feature = "namespace-bluecatbird")]
fn base64_std(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}
