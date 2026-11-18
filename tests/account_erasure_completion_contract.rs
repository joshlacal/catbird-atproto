use catbird_atproto::generated::blue_catbird::labyrinth::delete_account_data::{
    DeleteAccountDataOutputErasureCompletion, DeleteAccountDataResponse,
};
use catbird_atproto::jacquard_common::{xrpc::XrpcResp, DefaultStr};

#[test]
fn only_an_explicit_confirmed_value_proves_completion() {
    let decode = DeleteAccountDataResponse::decode_output::<DefaultStr>;
    let legacy = decode(b"{}").unwrap();
    let future = decode(br#"{"erasureCompletion":"queued"}"#).unwrap();
    let complete = decode(br#"{"erasureCompletion":"confirmed"}"#).unwrap();

    assert!(legacy.erasure_completion.is_none());
    assert!(matches!(
        future.erasure_completion,
        Some(DeleteAccountDataOutputErasureCompletion::Other(_))
    ));
    assert_eq!(
        complete.erasure_completion,
        Some(DeleteAccountDataOutputErasureCompletion::Confirmed)
    );
}
