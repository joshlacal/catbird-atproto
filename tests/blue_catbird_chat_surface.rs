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
