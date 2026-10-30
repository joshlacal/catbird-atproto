use catbird_atproto::generated::blue_catbird::labyrinth::labyrinth_relay::LabyrinthRelayResponse;
use catbird_atproto::jacquard_common::xrpc::XrpcResp;
use catbird_atproto::jacquard_common::DefaultStr;

/// `labyrinthRelay` returns the relayed endpoint's JSON body byte for byte,
/// so the output must not go through the JSON codec.
#[test]
fn relay_output_is_the_relayed_body_byte_for_byte() {
    let relayed: &[u8] = br#"{"threads":[],"cursor":"3l2b"}"#;
    let output = LabyrinthRelayResponse::decode_output::<DefaultStr>(relayed)
        .expect("a relayed JSON body decodes as raw bytes");
    assert_eq!(&output.body[..], relayed);
    let encoded = LabyrinthRelayResponse::encode_output::<DefaultStr>(&output)
        .expect("a relayed body encodes as raw bytes");
    assert_eq!(encoded, relayed);
}
