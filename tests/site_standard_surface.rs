#![cfg(feature = "namespace-site-standard")]

#[test]
fn site_standard_namespace_is_publicly_reachable() {
    fn assert_public_type<T>() {}

    assert_public_type::<catbird_atproto::site_standard::document::Contributor<'static>>();
    assert_public_type::<catbird_atproto::site_standard::publication::Publication<'static>>();
    assert_public_type::<catbird_atproto::site_standard::theme::color::Rgb<'static>>();

    let rgb: catbird_atproto::site_standard::theme::color::Rgb<'_> =
        serde_json::from_str(r#"{"r":17,"g":34,"b":51}"#).unwrap();
    assert_eq!((rgb.r, rgb.g, rgb.b), (17, 34, 51));
}
