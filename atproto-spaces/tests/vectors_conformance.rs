use atproto_spaces::did_resolver::StaticDidResolver;
use atproto_spaces::http_signature::{verify_credential_request, SpaceRequestHeaders};
use atproto_spaces::kem::{decapsulate_p256, decode_p256_did_key, encapsulate_p256_deterministic};
use atproto_spaces::lthash::{compute_dagcbor_cid, compute_record_element_hash, LtHash};
use atproto_spaces::mac::{
    parse_accept_signature, verify_commit_mac, verify_record_mac, MacProfile,
    SpaceMacResponseHeaders, COMMIT_MAC_HEADER, DEFAULT_MAC_LABEL, RECORD_MAC_HEADER,
};
use atproto_spaces::star::read_star_repo;
use atproto_spaces::tokens::{verify_space_token, SpaceTokenKind, SpaceVerifyingKey};
use atproto_spaces::vectors::{
    generate_v1_vectors, generate_v2_vectors, hex_decode, hex_encode, AtprotoSpacesVectorsV1,
    AtprotoSpacesVectorsV2,
};
use atproto_spaces::{SpaceBlobLocator, SpaceUri};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use p256::SecretKey;
use std::path::PathBuf;

const SWAN_EMPTY_STAR_V02_VECTOR: &str = "2a6c0100a301a6637265766d32323232323232323232323232637665720164646174615820e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad647265706f6d6469643a706c633a616c69636565247479706572617470726f746f2d73706163652d7265706f657370616365783061743a2f2f6469643a706c633a616c6963652f73706163652f6170702e62736b792e626f6f6b6d61726b732f73656c6600";

fn vector_v1_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/atproto_spaces_v1.json")
}

fn vector_v2_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/atproto_spaces_v2.json")
}

#[test]
fn v1_and_v2_vectors_match_on_disk_fixtures_and_all_primitives() {
    let generated_v1 = generate_v1_vectors().expect("generate_v1_vectors");
    let expected_v1_json =
        serde_json::to_string_pretty(&generated_v1).expect("serialize v1 vectors") + "\n";

    let generated_v2 = generate_v2_vectors().expect("generate_v2_vectors");
    let expected_v2_json =
        serde_json::to_string_pretty(&generated_v2).expect("serialize v2 vectors") + "\n";

    let path_v1 = vector_v1_file_path();
    let path_v2 = vector_v2_file_path();
    if std::env::var("ATPROTO_SPACES_WRITE_VECTORS").as_deref() == Ok("1") {
        if let Some(parent) = path_v1.parent() {
            std::fs::create_dir_all(parent).expect("create tests/vectors");
        }
        std::fs::write(&path_v1, &expected_v1_json).expect("write atproto_spaces_v1.json");
        std::fs::write(&path_v2, &expected_v2_json).expect("write atproto_spaces_v2.json");
    }

    let on_disk_v1 = std::fs::read_to_string(&path_v1).expect("read atproto_spaces_v1.json");
    assert_eq!(
        on_disk_v1, expected_v1_json,
        "atproto_spaces_v1.json drifted from generate_v1_vectors()"
    );
    let vectors: AtprotoSpacesVectorsV1 =
        serde_json::from_str(&on_disk_v1).expect("parse atproto_spaces_v1.json");

    let on_disk_v2 = std::fs::read_to_string(&path_v2).expect("read atproto_spaces_v2.json");
    assert_eq!(
        on_disk_v2, expected_v2_json,
        "atproto_spaces_v2.json drifted from generate_v2_vectors()"
    );
    let v2: AtprotoSpacesVectorsV2 =
        serde_json::from_str(&on_disk_v2).expect("parse atproto_spaces_v2.json");

    // 1. Swan independent empty STAR v0.2 vector byte-for-byte match
    assert_eq!(
        vectors.star_repo.empty_swan_archive_hex,
        SWAN_EMPTY_STAR_V02_VECTOR
    );
    let parsed_empty = read_star_repo(
        &hex_decode(&vectors.star_repo.empty_swan_archive_hex).unwrap(),
        &vectors.star_repo.empty_swan_space,
        &vectors.star_repo.empty_swan_repo,
    )
    .expect("read empty swan STAR v0.2");
    assert!(parsed_empty.records.is_empty());
    assert_eq!(
        hex_encode(&parsed_empty.data),
        vectors.lthash.empty_commitment_hex
    );

    // 2. LtHash order independence & removal
    let cid_a = compute_dagcbor_cid(&hex_decode(&vectors.lthash.record_a.dagcbor_hex).unwrap());
    let cid_b = compute_dagcbor_cid(&hex_decode(&vectors.lthash.record_b.dagcbor_hex).unwrap());
    assert_eq!(cid_a.to_string(), vectors.lthash.record_a.cid);
    assert_eq!(cid_b.to_string(), vectors.lthash.record_b.cid);

    let mut reverse_lt = LtHash::empty();
    reverse_lt.add(&compute_record_element_hash(
        &vectors.lthash.record_b.collection,
        &vectors.lthash.record_b.rkey,
        &cid_b,
    ));
    reverse_lt.add(&compute_record_element_hash(
        &vectors.lthash.record_a.collection,
        &vectors.lthash.record_a.rkey,
        &cid_a,
    ));
    assert_eq!(
        hex_encode(&reverse_lt.commitment()),
        vectors.lthash.combined_ab_commitment_hex
    );
    assert_eq!(
        vectors.lthash.after_remove_a_commitment_hex,
        vectors.lthash.only_b_commitment_hex
    );

    // 3. KEM P-256 HPKE export decapsulation + Accept-Signature parsing
    let author_sk =
        SecretKey::from_slice(&hex_decode(&vectors.kem_p256.author_secret_hex).unwrap()).unwrap();
    let (commit_label, want_ks_commit) =
        parse_accept_signature(&vectors.kem_p256.want_commit_mac_header, MacProfile::Commit)
            .unwrap();
    let (record_label, want_ks_record) =
        parse_accept_signature(&vectors.kem_p256.want_record_mac_header, MacProfile::Record)
            .unwrap();
    assert_eq!(commit_label, DEFAULT_MAC_LABEL);
    assert_eq!(record_label, DEFAULT_MAC_LABEL);
    assert_eq!(want_ks_commit, vectors.kem_p256.key_share_did_key);
    assert_eq!(want_ks_record, vectors.kem_p256.key_share_did_key);
    let decapped = decapsulate_p256(&author_sk, &want_ks_commit).unwrap();
    assert_eq!(hex_encode(&decapped), vectors.kem_p256.shared_secret_hex);

    // 4. Commit MAC & Record MAC verification
    let data_32: [u8; 32] = hex_decode(&vectors.commit_mac.data_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let commit_hdrs = SpaceMacResponseHeaders {
        covered_header_name: COMMIT_MAC_HEADER,
        covered_header: vectors.commit_mac.covered_header.clone(),
        signature_input: vectors.commit_mac.signature_input.clone(),
        signature: vectors.commit_mac.signature.clone(),
    }
    .to_header_map()
    .unwrap();
    verify_commit_mac(
        &decapped,
        &want_ks_commit,
        &commit_hdrs,
        &vectors.commit_mac.space,
        &vectors.commit_mac.repo,
        &vectors.commit_mac.rev,
        &data_32,
    )
    .expect("verify_commit_mac");

    let record_hdrs = SpaceMacResponseHeaders {
        covered_header_name: RECORD_MAC_HEADER,
        covered_header: vectors.record_mac.covered_header.clone(),
        signature_input: vectors.record_mac.signature_input.clone(),
        signature: vectors.record_mac.signature.clone(),
    }
    .to_header_map()
    .unwrap();
    verify_record_mac(
        &decapped,
        &want_ks_record,
        &record_hdrs,
        &vectors.record_mac.record_uri,
        &vectors.record_mac.cid,
    )
    .expect("verify_record_mac");

    // 5. RFC 9421 Low-S AND WebCrypto High-S verification
    for (label, vec9421) in [
        ("low_s", &vectors.rfc9421_low_s),
        ("high_s", &vectors.rfc9421_high_s),
    ] {
        let headers = SpaceRequestHeaders {
            authorization: vec9421.authorization.clone(),
            atproto_space_audience: vec9421.atproto_space_audience.clone(),
            signature_input: vec9421.signature_input.clone(),
            signature: vec9421.signature.clone(),
        }
        .to_header_map()
        .unwrap();
        let verified =
            verify_credential_request(&headers, &vec9421.cnf_did_key, vec9421.created + 5)
                .unwrap_or_else(|e| panic!("{label} RFC 9421 verify failed: {e}"));
        assert_eq!(verified.credential_jwt, vec9421.credential_jwt);
        assert_eq!(verified.audience_did, vec9421.audience_did);
    }

    // 6. Delegation JWT (did:plc) & Credential JWT (did:web) verification
    let resolver = StaticDidResolver::default();
    let user_pk = decode_p256_did_key(&vectors.delegation_jwt_did_plc.signer_did_key).unwrap();
    let auth_pk = decode_p256_did_key(&vectors.credential_jwt_did_web.authority_did_key).unwrap();
    resolver.insert(atproto_spaces::did_resolver::DidDocument::with_keys(
        &vectors.delegation_jwt_did_plc.iss,
        SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(&user_pk)),
        None,
        "https://pds.example.test",
    ));
    resolver.insert(atproto_spaces::did_resolver::DidDocument::with_keys(
        &vectors.credential_jwt_did_web.iss,
        SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(&auth_pk)),
        None,
        "https://ds.catbird.blue",
    ));

    block_on(async {
        let del = verify_space_token(
            SpaceTokenKind::Delegation,
            &vectors.delegation_jwt_did_plc.jwt,
            &resolver,
            vectors.delegation_jwt_did_plc.verify_now_sec,
        )
        .await
        .expect("verify delegation JWT");
        assert_eq!(del.jti, vectors.delegation_jwt_did_plc.jti);

        let cred = verify_space_token(
            SpaceTokenKind::Credential,
            &vectors.credential_jwt_did_web.jwt,
            &resolver,
            vectors.credential_jwt_did_web.verify_now_sec,
        )
        .await
        .expect("verify credential JWT");
        assert_eq!(
            cred.cnf_kid.as_deref(),
            Some(vectors.credential_jwt_did_web.cnf_kid.as_str())
        );
    });

    // 7. Populated STAR v0.2 archive + LtHash commitment check
    let parsed_pop = read_star_repo(
        &hex_decode(&vectors.star_repo.populated_archive_hex).unwrap(),
        &vectors.star_repo.populated_space,
        &vectors.star_repo.populated_repo,
    )
    .expect("read populated STAR v0.2");
    assert_eq!(parsed_pop.records.len(), 2);

    // 8. v2 extras: RFC 9180 HPKE export vector, Python CID-link STAR v0.2 archive, hedged URI & blob locator
    assert_eq!(
        v2.hpke_rfc9180_export.shared_secret_hex,
        "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d"
    );
    let rfc_sender =
        SecretKey::from_slice(&hex_decode(&v2.hpke_rfc9180_export.sender_secret_hex).unwrap())
            .unwrap();
    let rfc_author =
        SecretKey::from_slice(&hex_decode(&v2.hpke_rfc9180_export.author_secret_hex).unwrap())
            .unwrap();
    let rfc_encap =
        encapsulate_p256_deterministic(&v2.hpke_rfc9180_export.author_kem_did_key, &rfc_sender)
            .unwrap();
    assert_eq!(
        hex_encode(&rfc_encap.shared_secret),
        v2.hpke_rfc9180_export.shared_secret_hex
    );
    let rfc_decap =
        decapsulate_p256(&rfc_author, &v2.hpke_rfc9180_export.key_share_did_key).unwrap();
    assert_eq!(
        hex_encode(&rfc_decap),
        v2.hpke_rfc9180_export.shared_secret_hex
    );

    let cid_link_archive = BASE64_STANDARD
        .decode(&v2.star_v02_cid_link.archive_base64)
        .unwrap();
    let parsed_cid_link = read_star_repo(
        &cid_link_archive,
        &v2.star_v02_cid_link.space,
        &v2.star_v02_cid_link.repo,
    )
    .expect("read independent Python cbor2/BLAKE3 STAR v0.2 archive");
    assert_eq!(parsed_cid_link.rev, v2.star_v02_cid_link.rev);
    assert_eq!(parsed_cid_link.records.len(), 1);
    assert_eq!(
        parsed_cid_link.records[0].path,
        v2.star_v02_cid_link.expected_path
    );
    assert_eq!(
        parsed_cid_link.records[0].cid.to_string(),
        v2.star_v02_cid_link.expected_cid
    );

    let hedged_1 = SpaceUri::parse_hedged(&v2.uri_and_blob_locator.hedged_at_space).unwrap();
    let hedged_2 = SpaceUri::parse_hedged(&v2.uri_and_blob_locator.hedged_at_slash_space).unwrap();
    assert_eq!(
        hedged_1.as_str(),
        v2.uri_and_blob_locator.canonical_space_uri
    );
    assert_eq!(
        hedged_2.as_str(),
        v2.uri_and_blob_locator.canonical_space_uri
    );

    let loc_canon =
        SpaceBlobLocator::parse(&v2.uri_and_blob_locator.canonical_blob_locator).unwrap();
    let loc_legacy = SpaceBlobLocator::parse(&v2.uri_and_blob_locator.legacy_blob_locator).unwrap();
    assert_eq!(loc_canon, loc_legacy);
    assert_eq!(
        loc_legacy.encoded(),
        v2.uri_and_blob_locator.canonical_blob_locator
    );
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("unexpected pending future in synchronous test"),
    }
}
