//! A Space host refuses a second presentation of the same signature `nonce`
//! from the same credential issuer within the freshness window.

use atproto_spaces::did_resolver::{DidDocument, StaticDidResolver};
use atproto_spaces::host::{InMemorySpaceHostBackend, SpaceHost, SpaceRecordPolicy};
use atproto_spaces::http_signature::{sign_credential_request, sign_credential_request_minimal};
use atproto_spaces::kem::{encode_p256_did_key, P256SecretKey};
use atproto_spaces::signature_replay::{InMemorySignatureReplayCache, SignatureReplayStore};
use atproto_spaces::tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind};
use atproto_spaces::SpacesError;
use petrel_api::generated::com::atproto::space::authorize_space_sync::Input as AuthorizeSpaceSync;
use petrel_core::SpaceRef;
use std::rc::Rc;
use std::sync::Arc;

const NOW: u64 = 1_800_000_000;
const AUTHORITY: &str = "did:web:mls.catbird.blue";
const ALICE: &str = "did:plc:alice00000000000000000000";
const SPACE: &str =
    "at:space/did:web:mls.catbird.blue/blue.catbird.labyrinth.conversation/replay01";

struct Fixture {
    host: SpaceHost<InMemorySpaceHostBackend, Rc<StaticDidResolver>>,
    alice_sk: SpaceSigningKey,
    credential_jwt: String,
    ephemeral: P256SecretKey,
}

async fn fixture() -> Fixture {
    fixture_with_store(None).await
}

async fn fixture_with_store(store: Option<Arc<dyn SignatureReplayStore + Send + Sync>>) -> Fixture {
    let authority_sk = SpaceSigningKey::random_p256();
    let alice_sk = SpaceSigningKey::random_p256();
    let resolver = StaticDidResolver::new();
    resolver.insert(DidDocument::with_keys(
        AUTHORITY,
        authority_sk.verifying_key(),
        None,
        "https://mls.catbird.blue",
    ));
    resolver.insert(DidDocument::with_keys(
        ALICE,
        alice_sk.verifying_key(),
        None,
        "https://pds-alice.example",
    ));
    let backend = InMemorySpaceHostBackend::new();
    backend.create_space(
        SPACE,
        AUTHORITY,
        SpaceRecordPolicy::Members(vec![ALICE.to_string()]),
    );
    let mut host = SpaceHost::new(
        AUTHORITY.to_string(),
        authority_sk,
        Rc::new(resolver),
        backend,
    );
    if let Some(store) = store {
        host = host.with_signature_replay_store(store);
    }
    let (credential_jwt, ephemeral) = mint_credential(&host, &alice_sk, "a").await;
    Fixture {
        host,
        alice_sk,
        credential_jwt,
        ephemeral,
    }
}

/// Mints a Space credential bound to a fresh ephemeral key.
async fn mint_credential(
    host: &SpaceHost<InMemorySpaceHostBackend, Rc<StaticDidResolver>>,
    alice_sk: &SpaceSigningKey,
    tag: &str,
) -> (String, P256SecretKey) {
    let delegation = mint_space_token(
        SpaceTokenKind::Delegation,
        alice_sk,
        &SpaceTokenClaims {
            iss: ALICE.to_string(),
            sub: SPACE.to_string(),
            aud: Some(format!("{AUTHORITY}#atproto_pds")),
            iat: NOW,
            exp: NOW + 60,
            jti: format!("presentation-replay-delegation-{tag}"),
            cnf_kid: None,
        },
    )
    .unwrap();
    let ephemeral = P256SecretKey::random(&mut rand::rngs::OsRng);
    let out = host
        .handle_authorize_space_sync(
            AuthorizeSpaceSync {
                space: SpaceRef::parse(SPACE).unwrap(),
                credential_key: encode_p256_did_key(&ephemeral.public_key()),
                delegation_token: Some(delegation.as_str().into()),
                client_attestation: None,
                notify: None,
            },
            NOW,
        )
        .await
        .expect("credential minted");
    (out.credential.as_str().to_string(), ephemeral)
}

#[test]
fn repeated_nonce_is_refused_within_the_freshness_window() {
    block_on(async {
        let f = fixture().await;
        let headers = sign_credential_request(
            &f.ephemeral,
            &f.credential_jwt,
            AUTHORITY,
            NOW,
            "presentation-nonce-0001",
        )
        .unwrap()
        .to_header_map()
        .unwrap();

        f.host
            .verify_presentation(&headers, SPACE, AUTHORITY, NOW + 1)
            .await
            .expect("first presentation is accepted");
        let replay = f
            .host
            .verify_presentation(&headers, SPACE, AUTHORITY, NOW + 2)
            .await
            .expect_err("a repeated nonce must be refused");
        assert!(
            matches!(replay, SpacesError::BadSpaceSignature(ref m) if m.contains("replayed")),
            "unexpected error: {replay:?}"
        );

        // A fresh nonce on the same credential is accepted.
        let other = sign_credential_request(
            &f.ephemeral,
            &f.credential_jwt,
            AUTHORITY,
            NOW + 3,
            "presentation-nonce-0002",
        )
        .unwrap()
        .to_header_map()
        .unwrap();
        f.host
            .verify_presentation(&other, SPACE, AUTHORITY, NOW + 3)
            .await
            .expect("a new nonce is accepted");

        // After the freshness window the old presentation is stale, not replayable.
        let late = f
            .host
            .verify_presentation(&headers, SPACE, AUTHORITY, NOW + 331)
            .await
            .expect_err("a stale presentation must be refused");
        assert!(matches!(late, SpacesError::BadSpaceSignature(_)));
    });
}

#[test]
fn one_credential_key_cannot_exhaust_the_nonce_store_for_others() {
    block_on(async {
        let store: Arc<dyn SignatureReplayStore + Send + Sync> =
            Arc::new(InMemorySignatureReplayCache::with_capacity(32));
        let f = fixture_with_store(Some(store)).await;
        let (other_jwt, other_key) = mint_credential(&f.host, &f.alice_sk, "b").await;

        // Both credentials come from the same authority; only the bound key
        // differs. The first key presents far more nonces than the store holds.
        let mut refused = 0;
        for i in 0..40 {
            let headers = sign_credential_request(
                &f.ephemeral,
                &f.credential_jwt,
                AUTHORITY,
                NOW,
                &format!("flood-nonce-{i:04}"),
            )
            .unwrap()
            .to_header_map()
            .unwrap();
            if f.host
                .verify_presentation(&headers, SPACE, AUTHORITY, NOW + 1)
                .await
                .is_err()
            {
                refused += 1;
            }
        }
        assert!(refused > 0, "one key must not record unbounded nonces");

        let headers = sign_credential_request(
            &other_key,
            &other_jwt,
            AUTHORITY,
            NOW,
            "other-key-nonce-0001",
        )
        .unwrap()
        .to_header_map()
        .unwrap();
        f.host
            .verify_presentation(&headers, SPACE, AUTHORITY, NOW + 1)
            .await
            .expect("another credential key still has room in the store");
    });
}

#[test]
fn presentations_without_a_nonce_are_not_tracked() {
    block_on(async {
        let f = fixture().await;
        let headers = sign_credential_request_minimal(&f.ephemeral, &f.credential_jwt, AUTHORITY)
            .unwrap()
            .to_header_map()
            .unwrap();
        for offset in 1..=3 {
            f.host
                .verify_presentation(&headers, SPACE, AUTHORITY, NOW + offset)
                .await
                .expect("minimal presentations carry no nonce to track");
        }
    });
}

fn block_on<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    // SAFETY: the waker's vtable functions are no-ops over a null pointer.
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is never moved after being pinned here.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// One verified presentation offered to a replay store, in order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ReplayStep {
    issuer: String,
    nonce: Option<String>,
    created: Option<u64>,
    expires: Option<u64>,
    /// The verified credential token's `exp`, in Unix seconds.
    credential_exp: u64,
    now_sec: u64,
    /// `accept` or `reject`.
    expect: String,
    note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ReplayVectorFile {
    version: u32,
    description: String,
    max_signature_age_secs: u64,
    max_clock_skew_secs: u64,
    credential_expiry_skew_secs: u64,
    steps: Vec<ReplayStep>,
}

fn replay_vectors() -> ReplayVectorFile {
    let step = |issuer: &str,
                nonce: Option<&str>,
                created: Option<u64>,
                expires: Option<u64>,
                credential_exp: u64,
                now_sec: u64,
                accept: bool,
                note: &str| ReplayStep {
        issuer: issuer.into(),
        nonce: nonce.map(str::to_string),
        created,
        expires,
        credential_exp,
        now_sec,
        expect: if accept { "accept" } else { "reject" }.into(),
        note: note.into(),
    };
    let a = "did:web:authority-a.example.com";
    let b = "did:web:authority-b.example.com";
    const EXP: u64 = NOW + 3_600;
    ReplayVectorFile {
        version: 1,
        description: "Ordered presentations, already signature- and token-verified, offered to one replay store keyed on (credential issuer, nonce). Each step's created/expires/nonce passed the freshness checks at now_sec, and its credential token (exp = credential_exp) passed the token checks. A nonce is remembered while the presentation could still verify: until created + max_signature_age_secs, expires + max_clock_skew_secs, or credential_exp + credential_expiry_skew_secs, whichever comes first.".into(),
        max_signature_age_secs: atproto_spaces::http_signature::MAX_SIGNATURE_AGE_SECS,
        max_clock_skew_secs: atproto_spaces::http_signature::MAX_CLOCK_SKEW_SECS,
        credential_expiry_skew_secs: atproto_spaces::tokens::EXPIRY_CLOCK_SKEW_SECS,
        steps: vec![
            step(a, Some("n-1"), Some(NOW), None, EXP, NOW, true, "first use"),
            step(a, Some("n-1"), Some(NOW), None, EXP, NOW + 1, false, "same issuer and nonce inside the window"),
            step(b, Some("n-1"), Some(NOW), None, EXP, NOW + 1, true, "same nonce under another issuer"),
            step(a, Some("n-2"), Some(NOW), None, EXP, NOW + 2, true, "new nonce"),
            step(a, None, Some(NOW), None, EXP, NOW + 2, true, "no nonce: untracked"),
            step(a, None, Some(NOW), None, EXP, NOW + 3, true, "no nonce again: still untracked"),
            step(a, Some("n-1"), Some(NOW), None, EXP, NOW + 300, false, "last second the created window accepts"),
            step(a, Some("n-3"), None, None, NOW + 1_000, NOW + 10, true, "no created: first use"),
            step(a, Some("n-3"), None, None, NOW + 1_000, NOW + 339, false, "no created: seen 329 s ago"),
            step(a, Some("n-3"), None, None, NOW + 1_000, NOW + 340, false, "no created: the credential is still valid, so the nonce is still remembered"),
            step(a, Some("n-3"), None, None, NOW + 1_000, NOW + 1_060, false, "no created: last second the credential (+60 s skew) accepts"),
            step(a, Some("n-4"), Some(NOW + 400), Some(NOW + 410), EXP, NOW + 400, true, "expires bounds the window"),
            step(a, Some("n-4"), Some(NOW + 400), Some(NOW + 410), EXP, NOW + 440, false, "last second expires (+30 s skew) accepts"),
        ],
    }
}

#[test]
fn replay_sequence_vectors_match_fixture_and_in_memory_store() {
    use atproto_spaces::http_signature::VerifiedSpaceHeaders;
    use atproto_spaces::signature_replay::check_presentation_replay;

    let generated = replay_vectors();
    let expected_json = serde_json::to_string_pretty(&generated).expect("serialize") + "\n";
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/space_credential_replay_v1.json");
    if std::env::var("ATPROTO_SPACES_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &expected_json).expect("write fixture");
    }
    let on_disk = std::fs::read_to_string(&path).expect("read space_credential_replay_v1.json");
    assert_eq!(
        on_disk, expected_json,
        "space_credential_replay_v1.json drifted"
    );
    let file: ReplayVectorFile = serde_json::from_str(&on_disk).expect("parse fixture");

    let store = InMemorySignatureReplayCache::new();
    for (i, s) in file.steps.iter().enumerate() {
        let verified = VerifiedSpaceHeaders {
            credential_jwt: "a.b.c".into(),
            audience_did: "did:web:space-host.example.com".into(),
            cnf_did_key: "did:key:zDnae".into(),
            created: s.created,
            expires: s.expires,
            nonce: s.nonce.clone(),
        };
        let credential = SpaceTokenClaims {
            iss: s.issuer.clone(),
            sub: SPACE.to_string(),
            aud: Some(AUTHORITY.to_string()),
            iat: NOW,
            exp: s.credential_exp,
            jti: format!("replay-step-{i}"),
            cnf_kid: Some("did:key:zDnae".to_string()),
        };
        let accepted = check_presentation_replay(&store, &credential, &verified, s.now_sec).is_ok();
        assert_eq!(
            accepted,
            s.expect == "accept",
            "step {i} ({}) expected {}",
            s.note,
            s.expect
        );
    }
}
