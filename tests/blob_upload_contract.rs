use catbird_atproto::generated::blue_catbird::chat::BlobUploadPreparationBody;

#[test]
fn blob_prepare_body_exposes_media_and_plaintext_sizes() {
    // These fields are part of the signed preparation contract.  Keep this
    // compile-time tripwire next to the generated surface so a lexicon/source
    // regression cannot silently fall back to a server-side default.
    let _ = BlobUploadPreparationBody::builder()
        .media_type("image/png")
        .plaintext_size(1);
}
