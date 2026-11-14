use atproto_spaces::http_signature::{
    sign_credential_request, sign_credential_request_minimal, verify_credential_request,
    SpaceRequestHeaders,
};
use atproto_spaces::kem::{
    decapsulate_p256, decode_p256_did_key, encapsulate_p256, encapsulate_p256_deterministic,
    encode_p256_did_key, P256SecretKey,
};
use atproto_spaces::lthash::{
    compute_dagcbor_cid, compute_record_element_hash, LtHash, LTHASH_BYTES,
};
use atproto_spaces::mac::{
    format_accept_signature, parse_accept_signature, sign_commit_mac, sign_record_mac,
    verify_commit_mac, verify_record_mac, MacProfile, DEFAULT_MAC_LABEL,
};
use atproto_spaces::star::{read_star_repo, write_star_repo, StarRecordEntry};
use atproto_spaces::tokens::{
    mint_space_token, verify_space_token, SpaceKeyResolver, SpaceSigningKey, SpaceTokenClaims,
    SpaceTokenKind, SpaceVerifyingKey,
};
use atproto_spaces::{SpaceBlobLocator, SpaceUri};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use http::{HeaderMap, HeaderValue};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::FieldBytes;
use p256::{NistP256, Scalar};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn lthash_is_order_independent_and_reversible() {
    let cid_a = compute_dagcbor_cid(b"\xa1a\x01");
    let cid_b = compute_dagcbor_cid(b"\xa1b\x02");
    let cid_c = compute_dagcbor_cid(b"\xa1c\x03");

    let elem_a = compute_record_element_hash("blue.catbird.labyrinth.batch", "3l2aaaa", &cid_a);
    let elem_b = compute_record_element_hash("blue.catbird.labyrinth.batch", "3l2bbbb", &cid_b);
    let elem_c = compute_record_element_hash("blue.catbird.labyrinth.device", "dev-1", &cid_c);
    assert_eq!(elem_a.len(), LTHASH_BYTES);

    let mut order_1 = LtHash::empty();
    order_1.add(&elem_a);
    order_1.add(&elem_b);
    order_1.add(&elem_c);

    let mut order_2 = LtHash::empty();
    order_2.add(&elem_c);
    order_2.add(&elem_a);
    order_2.add(&elem_b);

    assert_eq!(order_1.checksum(), order_2.checksum());
    assert_eq!(order_1.commitment(), order_2.commitment());

    order_2.remove(&elem_b);
    let mut expected_ac = LtHash::empty();
    expected_ac.add(&elem_a);
    expected_ac.add(&elem_c);
    assert_eq!(order_2.commitment(), expected_ac.commitment());

    order_2.remove(&elem_a);
    order_2.remove(&elem_c);
    assert_eq!(order_2.checksum(), [0u8; LTHASH_BYTES]);
    assert_eq!(order_2.commitment(), LtHash::empty().commitment());
}

#[test]
fn rfc9180_hpke_export_only_p256_encapsulate_and_decapsulate_roundtrip_and_vector() {
    // RFC 9180 export-only DHKEM(P-256, HKDF-SHA256) vector with info="atproto-mac" & context=""
    let sk_e_bytes = hex_decode("2f18b059576a0ec5a17121c0fe7ec8f00ea86f7b046fa3889ac8f21f89dbd484");
    let sk_r_bytes = hex_decode("62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346");
    let expected_shared =
        hex_decode("2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d");

    let sk_r = P256SecretKey::from_slice(&sk_r_bytes).expect("valid sk_r");
    let sk_e = P256SecretKey::from_slice(&sk_e_bytes).expect("valid sk_e");
    let author_did_key = encode_p256_did_key(&sk_r.public_key());
    assert!(author_did_key.starts_with("did:key:zDn"));
    assert_eq!(
        decode_p256_did_key(&author_did_key).expect("decode did:key"),
        sk_r.public_key()
    );

    let encap =
        encapsulate_p256_deterministic(&author_did_key, &sk_e).expect("deterministic encap");
    assert_eq!(encap.shared_secret.as_slice(), expected_shared.as_slice());

    let decap = decapsulate_p256(&sk_r, &encap.key_share_did_key).expect("decap");
    assert_eq!(decap, encap.shared_secret);

    // Random ephemeral encapsulation round-trip
    let random_encap = encapsulate_p256(&author_did_key).expect("random encap");
    let random_decap = decapsulate_p256(&sk_r, &random_encap.key_share_did_key).expect("decap");
    assert_eq!(random_decap, random_encap.shared_secret);
}

#[test]
fn structured_commit_and_record_macs_verify_canonicalize_and_reject_tampering() {
    let secret = [0x42u8; 32];
    let eph = P256SecretKey::random(&mut rand::rngs::OsRng);
    let key_share = encode_p256_did_key(&eph.public_key());
    let space = "at://did:web:mls.catbird.blue/space/blue.catbird.labyrinth.conversation/01980a11";
    let repo = "did:plc:alice00000000000000000000";
    let rev = "3l2xyz0000001";
    let data = [0xabu8; 32];

    // Custom non-"mac" label + Accept-Signature round-trip
    let custom_accept = format!(
        "  sig1=(\"atproto-space-commit\"; sf); keyid=\"{key_share}\"; alg=\"hmac-sha256\"; tag=\"atproto-space-commit\"  "
    );
    let (parsed_label, parsed_ks) =
        parse_accept_signature(&custom_accept, MacProfile::Commit).expect("parse custom label");
    assert_eq!(parsed_label, "sig1");
    assert_eq!(parsed_ks, key_share);

    let (commit_resp, _) = sign_commit_mac(&secret, &key_share, "sig1", space, repo, rev, &data)
        .expect("sign commit mac");
    let mut commit_hdrs = commit_resp.to_header_map().unwrap();
    verify_commit_mac(&secret, &key_share, &commit_hdrs, space, repo, rev, &data)
        .expect("verify commit mac with custom label");

    // Flipping a bit or changing repo/rev/keyShare fails verification
    let mut bad_data = data;
    bad_data[0] ^= 0x01;
    assert!(verify_commit_mac(
        &secret,
        &key_share,
        &commit_hdrs,
        space,
        repo,
        rev,
        &bad_data
    )
    .is_err());
    assert!(verify_commit_mac(
        &secret,
        &key_share,
        &commit_hdrs,
        space,
        "did:plc:mallory",
        rev,
        &data
    )
    .is_err());
    assert!(verify_commit_mac(
        &secret,
        "did:key:zDnaeWrongKeyShare",
        &commit_hdrs,
        space,
        repo,
        rev,
        &data
    )
    .is_err());

    // Duplicate tagged inner list in Signature-Input must be rejected
    let dup_sig_input = format!(
        "{}, dup=(\"atproto-space-commit\";sf);keyid=\"{key_share}\";tag=\"atproto-space-commit\"",
        commit_resp.signature_input
    );
    commit_hdrs.insert(
        "signature-input",
        HeaderValue::from_str(&dup_sig_input).unwrap(),
    );
    assert!(verify_commit_mac(&secret, &key_share, &commit_hdrs, space, repo, rev, &data).is_err());

    // Record MAC round-trip + profile separation
    let accept_rec = format_accept_signature(MacProfile::Record, &key_share).unwrap();
    assert!(parse_accept_signature(&accept_rec, MacProfile::Commit).is_err());

    let uri = format!("{space}/{repo}/blue.catbird.labyrinth.batch/3l2xyz0000001");
    let cid = compute_dagcbor_cid(b"\xa1dtest");
    let (record_resp, _) = sign_record_mac(
        &secret,
        &key_share,
        DEFAULT_MAC_LABEL,
        &uri,
        &cid.to_string(),
    )
    .expect("sign record mac");
    let record_hdrs = record_resp.to_header_map().unwrap();
    verify_record_mac(&secret, &key_share, &record_hdrs, &uri, &cid.to_string())
        .expect("verify record mac");

    // Commit headers cannot pass as record headers and vice-versa
    assert!(verify_record_mac(
        &secret,
        &key_share,
        &commit_resp.to_header_map().unwrap(),
        &uri,
        &cid.to_string()
    )
    .is_err());
    assert!(verify_commit_mac(&secret, &key_share, &record_hdrs, space, repo, rev, &data).is_err());
}

#[test]
fn hedged_space_uris_and_space_blob_locators_roundtrip_and_reject_malformed_inputs() {
    let canonical =
        "at://did:web:mls.catbird.blue/space/blue.catbird.labyrinth.conversation/01980a11-2";
    for input in [
        canonical,
        "at:space/did:web:mls.catbird.blue/blue.catbird.labyrinth.conversation/01980a11-2",
        "at://space/did:web:mls.catbird.blue/blue.catbird.labyrinth.conversation/01980a11-2",
    ] {
        let parsed = SpaceUri::parse_hedged(input).expect("parse_hedged");
        assert_eq!(parsed.as_str(), canonical);
    }

    let cid = compute_dagcbor_cid(b"\xa1dblob\x01");
    let space = SpaceUri::parse(canonical).unwrap();
    let repo = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    let locator = SpaceBlobLocator::new(space, repo, cid).unwrap();
    let encoded = locator.encoded();
    assert_eq!(encoded, format!("{canonical}|{repo}|{cid}"));
    assert_eq!(SpaceBlobLocator::parse(&encoded).unwrap(), locator);

    let legacy = format!("{canonical}/{repo}#{cid}");
    assert_eq!(SpaceBlobLocator::parse(&legacy).unwrap(), locator);

    // Mixed | and # or non-ATProto DID must fail closed
    assert!(SpaceBlobLocator::parse(&format!("{canonical}|{repo}#{cid}")).is_err());
    assert!(SpaceBlobLocator::parse(&format!("{canonical}|did:key:zDnae123|{cid}")).is_err());
}

#[test]
fn verify_credential_request_accepts_webcrypto_high_s_signature() {
    let ephemeral_key = P256SecretKey::random(&mut rand::rngs::OsRng);
    let cnf_did_key = encode_p256_did_key(&ephemeral_key.public_key());
    let credential_jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhdDovL2RpZDpwbGM6YWxpY2UvYmx1ZS5jYXRiaXJkLmxhYnlyaW50aC5tYWlsYm94L3NlbGYifQ.c2ln";
    let audience_did = "did:plc:alice00000000000000000000";
    let now_sec = 1_762_000_000u64;

    let signed: SpaceRequestHeaders = sign_credential_request(
        &ephemeral_key,
        credential_jwt,
        audience_did,
        now_sec,
        "nonce-abc-123",
    )
    .expect("sign credential request");

    let low_s_map = signed.to_header_map().expect("to header map");
    let verified = verify_credential_request(&low_s_map, &cnf_did_key, now_sec)
        .expect("low-S signature verifies");
    assert_eq!(verified.credential_jwt, credential_jwt);
    assert_eq!(verified.audience_did, audience_did);

    let b64 = signed
        .signature
        .strip_prefix("atproto-space-credential=:")
        .and_then(|s| s.strip_suffix(':'))
        .expect("structured byte sequence signature");
    let raw = BASE64_STANDARD.decode(b64).expect("decode signature b64");
    assert_eq!(raw.len(), 64);

    let r_bytes = &raw[..32];
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(&raw[32..]);
    let s_fb = FieldBytes::<NistP256>::from(s_arr);
    let s_scalar = <Scalar as Reduce<p256::U256>>::reduce_bytes(&s_fb);
    assert!(
        !bool::from(p256::elliptic_curve::scalar::IsHigh::is_high(&s_scalar)),
        "sign_credential_request must emit low-S signature"
    );
    let high_s_scalar = -s_scalar;
    assert!(
        bool::from(p256::elliptic_curve::scalar::IsHigh::is_high(
            &high_s_scalar
        )),
        "negated non-zero low-S scalar mod n is high-S"
    );

    let mut high_s_raw = Vec::with_capacity(64);
    high_s_raw.extend_from_slice(r_bytes);
    let high_s_bytes: [u8; 32] = high_s_scalar.to_bytes().into();
    high_s_raw.extend_from_slice(&high_s_bytes);

    let mut high_s_headers = signed.clone();
    high_s_headers.signature = format!(
        "atproto-space-credential=:{}:",
        BASE64_STANDARD.encode(&high_s_raw)
    );
    let high_s_map = high_s_headers.to_header_map().expect("high-S header map");
    let verified_high = verify_credential_request(&high_s_map, &cnf_did_key, now_sec)
        .expect("WebCrypto high-S signature MUST verify");
    assert_eq!(verified_high.credential_jwt, credential_jwt);
    assert_eq!(verified_high.audience_did, audience_did);

    let minimal =
        sign_credential_request_minimal(&ephemeral_key, credential_jwt, audience_did).unwrap();
    let minimal_map = minimal.to_header_map().unwrap();
    verify_credential_request(&minimal_map, &cnf_did_key, now_sec)
        .expect("minimal RFC 9421 form verifies");

    let other_key = P256SecretKey::random(&mut rand::rngs::OsRng);
    let other_did_key = encode_p256_did_key(&other_key.public_key());
    assert!(verify_credential_request(&high_s_map, &other_did_key, now_sec).is_err());

    let mut tampered: HeaderMap = high_s_map.clone();
    tampered.insert("atproto-space-audience", "did:plc:mallory".parse().unwrap());
    assert!(verify_credential_request(&tampered, &cnf_did_key, now_sec).is_err());
}

struct RotatingDidWebResolver {
    stale_key: SpaceVerifyingKey,
    rotated_key: SpaceVerifyingKey,
    calls: AtomicUsize,
}

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for RotatingDidWebResolver {
    async fn resolve_atproto_key(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<SpaceVerifyingKey, atproto_spaces::SpacesError> {
        assert_eq!(did, "did:web:mls.catbird.blue");
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if force_refresh {
            Ok(self.rotated_key.clone())
        } else {
            assert_eq!(n, 0, "unforced lookup should only happen first");
            Ok(self.stale_key.clone())
        }
    }
}

#[test]
fn verify_space_token_retries_once_on_rotated_did_web_key() {
    pollster_block_on(async {
        let old_sk = SpaceSigningKey::random_p256();
        let new_sk = SpaceSigningKey::random_p256();
        let ephemeral = P256SecretKey::random(&mut rand::rngs::OsRng);
        let cnf_kid = encode_p256_did_key(&ephemeral.public_key());

        let now_sec = 1_762_000_000u64;
        let claims = SpaceTokenClaims {
            iss: "did:web:mls.catbird.blue".to_string(),
            sub: "at://did:web:mls.catbird.blue/space/blue.catbird.labyrinth.conversation/01980a11"
                .to_string(),
            aud: None,
            iat: now_sec,
            exp: now_sec + 600,
            jti: "cred-jti-001".to_string(),
            cnf_kid: Some(cnf_kid.clone()),
        };

        let jwt = mint_space_token(SpaceTokenKind::Credential, &new_sk, &claims)
            .expect("mint credential jwt");

        let resolver = RotatingDidWebResolver {
            stale_key: old_sk.verifying_key(),
            rotated_key: new_sk.verifying_key(),
            calls: AtomicUsize::new(0),
        };

        let verified = verify_space_token(SpaceTokenKind::Credential, &jwt, &resolver, now_sec)
            .await
            .expect("should retry once with force_refresh=true and succeed");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.cnf_kid.as_deref(), Some(cnf_kid.as_str()));

        let always_wrong = RotatingDidWebResolver {
            stale_key: old_sk.verifying_key(),
            rotated_key: old_sk.verifying_key(),
            calls: AtomicUsize::new(0),
        };
        let err = verify_space_token(SpaceTokenKind::Credential, &jwt, &always_wrong, now_sec)
            .await
            .expect_err("wrong key after refresh must fail");
        assert_eq!(always_wrong.calls.load(Ordering::SeqCst), 2);
        let _ = err;
    });
}

#[test]
fn star_v02_roundtrips_canonical_sorted_records_and_rejects_violations() {
    let space = "at://did:plc:alice00000000000000000000/space/blue.catbird.labyrinth.mailbox/self";
    let repo = "did:plc:alice00000000000000000000";
    let rev = "3l2xyz0000009";

    let rec_1_bytes = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "$type": "blue.catbird.labyrinth.batch",
        "seq": 1
    }))
    .unwrap();
    let rec_2_bytes = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "$type": "blue.catbird.labyrinth.device",
        "deviceId": "dev-1"
    }))
    .unwrap();

    let mut lt = LtHash::empty();
    let cid_1 = compute_dagcbor_cid(&rec_1_bytes);
    let cid_2 = compute_dagcbor_cid(&rec_2_bytes);
    lt.add(&compute_record_element_hash(
        "blue.catbird.labyrinth.batch",
        "3l2xyz0000001",
        &cid_1,
    ));
    lt.add(&compute_record_element_hash(
        "blue.catbird.labyrinth.device",
        "dev-1",
        &cid_2,
    ));
    let data = lt.commitment();

    let entries = vec![
        StarRecordEntry {
            path: "blue.catbird.labyrinth.batch/3l2xyz0000001".to_string(),
            record_dagcbor: rec_1_bytes,
        },
        StarRecordEntry {
            path: "blue.catbird.labyrinth.device/dev-1".to_string(),
            record_dagcbor: rec_2_bytes,
        },
    ];

    let star_bytes = write_star_repo(space, repo, rev, &data, &entries).expect("write star");
    assert_eq!(&star_bytes[..4], &[0x2a, 0x6c, 0x01, 0x00]);
    assert_eq!(*star_bytes.last().unwrap(), 0x00);

    let parsed = read_star_repo(&star_bytes, space, repo).expect("read star");
    assert_eq!(parsed.rev, rev);
    assert_eq!(parsed.data, data);
    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.records[0].cid, cid_1);
    assert_eq!(parsed.records[1].cid, cid_2);

    // Mismatched expected space or repo must fail
    assert!(read_star_repo(&star_bytes, "at://did:plc:other/space/x.y.z/1", repo).is_err());
    assert!(read_star_repo(&star_bytes, space, "did:plc:other").is_err());

    // Wrong LtHash commitment in metadata must fail closed inside read_star_repo!
    let wrong_archive = write_star_repo(space, repo, rev, &[0xff; 32], &entries).unwrap();
    assert!(matches!(
        read_star_repo(&wrong_archive, space, repo),
        Err(atproto_spaces::SpacesError::SetHashMismatch(_))
    ));

    // Unsorted entries must be rejected
    let reversed = vec![entries[1].clone(), entries[0].clone()];
    assert!(write_star_repo(space, repo, rev, &data, &reversed).is_err());

    // Missing end marker, invalid control byte, or trailing garbage byte must fail closed
    assert!(read_star_repo(&star_bytes[..star_bytes.len() - 1], space, repo).is_err());
    let mut bad_ctrl = star_bytes.clone();
    *bad_ctrl.last_mut().unwrap() = 0x02;
    assert!(read_star_repo(&bad_ctrl, space, repo).is_err());
    let mut with_garbage = star_bytes;
    with_garbage.push(0x00);
    assert!(read_star_repo(&with_garbage, space, repo).is_err());
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn pollster_block_on<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn dummy_raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            dummy_raw_waker()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::thread::yield_now();
    }
}
