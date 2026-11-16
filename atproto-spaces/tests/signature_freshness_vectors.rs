//! Shared RFC 9421 `atproto-space-credential` freshness and structured-field
//! vectors (`tests/vectors/space_credential_signature_v1.json`).
//!
//! The fixture is generated deterministically here (RFC 6979 signatures over a
//! fixed key) and replayed against [`verify_credential_request`]. Swan's Swift
//! verifier replays the same file, so both implementations must agree on every
//! accept / reject outcome.
//!
//! Regenerate with `ATPROTO_SPACES_WRITE_VECTORS=1 cargo test -p atproto-spaces
//! --test signature_freshness_vectors`.

use atproto_spaces::http_signature::{
    verify_credential_request, SpaceRequestHeaders, MAX_CLOCK_SKEW_SECS, MAX_NONCE_BYTES,
    MAX_SIGNATURE_AGE_SECS, SPACE_CREDENTIAL_LABEL,
};
use atproto_spaces::kem::encode_p256_did_key;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const NOW: u64 = 1_800_000_000;
const TEST_ONLY_CNF_SECRET_HEX: &str =
    "5ec4e7f1d2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d";
const AUTHORIZATION: &str =
    "Atproto-Space-Credential eyJhbGciOiJFUzI1NiJ9.eyJ2ZWN0b3IiOiJmcmVzaG5lc3MifQ.c2lnbmF0dXJl";
const AUDIENCE: &str = "did:web:space-host.example.com";
const COMPONENTS: &str = "(\"authorization\" \"atproto-space-audience\")";
const TAG: &str = ";tag=\"atproto-space-credential\"";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignatureVectorFile {
    version: u32,
    description: String,
    /// Deterministic signing key for these vectors only; never a deployed key.
    test_only_cnf_secret_hex: String,
    cnf_did_key: String,
    authorization: String,
    atproto_space_audience: String,
    max_signature_age_secs: u64,
    max_clock_skew_secs: u64,
    max_nonce_bytes: usize,
    cases: Vec<SignatureCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignatureCase {
    name: String,
    note: String,
    /// `Signature-Input` field lines exactly as sent.
    signature_input: Vec<String>,
    /// `Signature` field lines exactly as sent.
    signature: Vec<String>,
    /// The verifier's clock, in Unix seconds.
    now_sec: u64,
    /// `accept` or `reject`.
    expect: String,
    /// Swan's `SpaceHTTPSignatureError` case for a rejection, where it is fixed
    /// by the freshness rules (`staleSignature` / `malformedSignature`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    swan_error: Option<String>,
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/space_credential_signature_v1.json")
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn signing_key() -> (SigningKey, String) {
    let secret = SecretKey::from_slice(&hex_decode(TEST_ONLY_CNF_SECRET_HEX)).expect("secret");
    let did_key = encode_p256_did_key(&secret.public_key());
    (SigningKey::from(&secret), did_key)
}

/// Signs the profiled base whose `@signature-params` line is
/// `COMPONENTS + canonical_params` and returns the base64 `(r || s)`.
fn sign_b64(key: &SigningKey, canonical_params: &str) -> String {
    let base = format!(
        "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {COMPONENTS}{canonical_params}"
    );
    let sig: Signature = key.sign(base.as_bytes());
    let sig = sig.normalize_s().unwrap_or(sig);
    BASE64_STANDARD.encode(sig.to_bytes())
}

struct CaseSpec<'a> {
    name: &'a str,
    note: &'a str,
    /// Parameters as sent on the wire, after the covered components.
    wire_params: String,
    /// Parameters after RFC 8941 parsing and re-serialization (what is signed).
    canonical_params: String,
    now_sec: u64,
    accept: bool,
    swan_error: Option<&'a str>,
}

fn simple<'a>(
    name: &'a str,
    note: &'a str,
    params: String,
    now_sec: u64,
    accept: bool,
    swan_error: Option<&'a str>,
) -> CaseSpec<'a> {
    CaseSpec {
        name,
        note,
        wire_params: params.clone(),
        canonical_params: params,
        now_sec,
        accept,
        swan_error,
    }
}

fn build_case(key: &SigningKey, spec: CaseSpec<'_>) -> SignatureCase {
    let sig = sign_b64(key, &spec.canonical_params);
    SignatureCase {
        name: spec.name.to_string(),
        note: spec.note.to_string(),
        signature_input: vec![format!(
            "{SPACE_CREDENTIAL_LABEL}={COMPONENTS}{}",
            spec.wire_params
        )],
        signature: vec![format!("{SPACE_CREDENTIAL_LABEL}=:{sig}:")],
        now_sec: spec.now_sec,
        expect: if spec.accept { "accept" } else { "reject" }.to_string(),
        swan_error: spec.swan_error.map(str::to_string),
    }
}

fn generate() -> SignatureVectorFile {
    let (key, cnf_did_key) = signing_key();
    let stale = Some("staleSignature");
    let malformed = Some("malformedSignature");
    let max_nonce = "n".repeat(MAX_NONCE_BYTES);
    let over_nonce = "n".repeat(MAX_NONCE_BYTES + 1);
    let mut cases = vec![
        simple("minimal_profile", "no created, expires or nonce: no freshness constraint", TAG.into(), NOW, true, None),
        simple("created_now", "created equal to the verifier clock", format!("{TAG};created={NOW}"), NOW, true, None),
        simple("created_skew_edge", "created 30 s ahead is inside the skew allowance", format!("{TAG};created={}", NOW + 30), NOW, true, None),
        simple("created_future", "created 31 s ahead is rejected", format!("{TAG};created={}", NOW + 31), NOW, false, stale),
        simple("created_age_edge", "created exactly 300 s old is accepted", format!("{TAG};created={}", NOW - 300), NOW, true, None),
        simple("created_too_old", "created 301 s old is rejected", format!("{TAG};created={}", NOW - 301), NOW, false, stale),
        simple("created_with_zero_clock", "a zero verifier clock is a real clock, not a switch that disables freshness", format!("{TAG};created={NOW}"), 0, false, stale),
        simple("expires_skew_edge", "expires passed by 30 s is accepted", format!("{TAG};expires={}", NOW - 30), NOW, true, None),
        simple("expires_passed", "expires passed by 31 s is rejected", format!("{TAG};expires={}", NOW - 31), NOW, false, stale),
        simple("expires_with_zero_clock_future", "expires in the future against a zero clock is accepted", format!("{TAG};expires={NOW}"), 0, true, None),
        simple("all_fresh", "created, expires and nonce together", format!("{TAG};created={NOW};expires={};nonce=\"r-0001\"", NOW + 60), NOW + 10, true, None),
        simple("nonce_max_length", "512-byte nonce is accepted", format!("{TAG};nonce=\"{max_nonce}\""), NOW, true, None),
        simple("nonce_too_long", "513-byte nonce is rejected", format!("{TAG};nonce=\"{over_nonce}\""), NOW, false, malformed),
        simple("nonce_empty", "empty nonce is rejected", format!("{TAG};nonce=\"\""), NOW, false, malformed),
        simple("nonce_token", "nonce must be a string, not a token", format!("{TAG};nonce=abc"), NOW, false, malformed),
        simple("nonce_integer", "nonce must be a string, not an integer", format!("{TAG};nonce=7"), NOW, false, malformed),
        simple("created_negative", "created must be non-negative", format!("{TAG};created=-1"), NOW, false, malformed),
        simple("created_string", "created must be an integer", format!("{TAG};created=\"{NOW}\""), NOW, false, malformed),
        simple("created_decimal", "created must be an integer", format!("{TAG};created={NOW}.5"), NOW, false, malformed),
        simple("expires_boolean", "expires must be an integer", format!("{TAG};expires=?1"), NOW, false, malformed),
        CaseSpec {
            name: "duplicate_param_last_fresh",
            note: "RFC 8941: a repeated parameter overwrites the earlier value in place; the fresh last value is what is checked and signed",
            wire_params: format!("{TAG};created={};created={NOW}", NOW - 10_000),
            canonical_params: format!("{TAG};created={NOW}"),
            now_sec: NOW,
            accept: true,
            swan_error: None,
        },
        CaseSpec {
            name: "duplicate_param_last_stale",
            note: "RFC 8941: the stale last value wins, so the presentation is stale",
            wire_params: format!("{TAG};created={NOW};created={}", NOW - 10_000),
            canonical_params: format!("{TAG};created={}", NOW - 10_000),
            now_sec: NOW,
            accept: false,
            swan_error: stale,
        },
        CaseSpec {
            name: "duplicate_param_keeps_first_position",
            note: "the overwritten parameter keeps its first position in the re-serialized @signature-params",
            wire_params: format!("{TAG};created={};nonce=\"a\";created={NOW}", NOW - 10_000),
            canonical_params: format!("{TAG};created={NOW};nonce=\"a\""),
            now_sec: NOW,
            accept: true,
            swan_error: None,
        },
        CaseSpec {
            name: "duplicate_param_signed_as_sent",
            note: "a signature over the raw duplicated text does not verify, because the base uses the re-serialized parameters",
            wire_params: format!("{TAG};created={};created={NOW}", NOW - 10_000),
            canonical_params: format!("{TAG};created={};created={NOW}", NOW - 10_000),
            now_sec: NOW,
            accept: false,
            swan_error: None,
        },
    ]
    .into_iter()
    .map(|spec| build_case(&key, spec))
    .collect::<Vec<_>>();

    // Duplicate dictionary keys: the last member with a given key wins.
    let valid = sign_b64(&key, TAG);
    let valid_input = format!("{SPACE_CREDENTIAL_LABEL}={COMPONENTS}{TAG}");
    cases.push(SignatureCase {
        name: "duplicate_signature_key_last_valid".into(),
        note: "RFC 8941: a repeated Signature dictionary key keeps the last value; here the last value is the valid signature".into(),
        signature_input: vec![valid_input.clone()],
        signature: vec![format!(
            "{SPACE_CREDENTIAL_LABEL}=:YWJj:, {SPACE_CREDENTIAL_LABEL}=:{valid}:"
        )],
        now_sec: NOW,
        expect: "accept".into(),
        swan_error: None,
    });
    cases.push(SignatureCase {
        name: "duplicate_signature_key_last_invalid".into(),
        note: "RFC 8941: the last value wins, so an earlier valid signature is ignored".into(),
        signature_input: vec![valid_input.clone()],
        signature: vec![format!(
            "{SPACE_CREDENTIAL_LABEL}=:{valid}:, {SPACE_CREDENTIAL_LABEL}=:YWJj:"
        )],
        now_sec: NOW,
        expect: "reject".into(),
        swan_error: None,
    });
    cases.push(SignatureCase {
        name: "duplicate_signature_key_across_field_lines".into(),
        note: "field lines combine before parsing (RFC 9110 5.3), so a later line overrides an earlier one".into(),
        signature_input: vec![valid_input.clone()],
        signature: vec![
            format!("{SPACE_CREDENTIAL_LABEL}=:YWJj:"),
            format!("{SPACE_CREDENTIAL_LABEL}=:{valid}:"),
        ],
        now_sec: NOW,
        expect: "accept".into(),
        swan_error: None,
    });
    cases.push(SignatureCase {
        name: "duplicate_signature_input_key_last_valid".into(),
        note: "a repeated Signature-Input key keeps the last inner list; the earlier untagged list is discarded".into(),
        signature_input: vec![format!(
            "{SPACE_CREDENTIAL_LABEL}=(\"authorization\"), {valid_input}"
        )],
        signature: vec![format!("{SPACE_CREDENTIAL_LABEL}=:{valid}:")],
        now_sec: NOW,
        expect: "accept".into(),
        swan_error: None,
    });
    cases.push(SignatureCase {
        name: "duplicate_signature_input_key_last_untagged".into(),
        note:
            "the last inner list for the key has no tag, so no tagged credential signature remains"
                .into(),
        signature_input: vec![format!(
            "{valid_input}, {SPACE_CREDENTIAL_LABEL}=(\"authorization\" \"atproto-space-audience\")"
        )],
        signature: vec![format!("{SPACE_CREDENTIAL_LABEL}=:{valid}:")],
        now_sec: NOW,
        expect: "reject".into(),
        swan_error: None,
    });

    SignatureVectorFile {
        version: 1,
        description: "RFC 9421 atproto-space-credential verifier vectors: created / expires / nonce bounds and RFC 8941 duplicate-key handling. Each case is verified against cnf_did_key with the given verifier clock.".into(),
        test_only_cnf_secret_hex: TEST_ONLY_CNF_SECRET_HEX.into(),
        cnf_did_key,
        authorization: AUTHORIZATION.into(),
        atproto_space_audience: AUDIENCE.into(),
        max_signature_age_secs: MAX_SIGNATURE_AGE_SECS,
        max_clock_skew_secs: MAX_CLOCK_SKEW_SECS,
        max_nonce_bytes: MAX_NONCE_BYTES,
        cases,
    }
}

fn headers_for(file: &SignatureVectorFile, case: &SignatureCase) -> http::HeaderMap {
    let mut map = SpaceRequestHeaders {
        authorization: file.authorization.clone(),
        atproto_space_audience: file.atproto_space_audience.clone(),
        signature_input: case.signature_input[0].clone(),
        signature: case.signature[0].clone(),
    }
    .to_header_map()
    .expect("header map");
    for extra in &case.signature_input[1..] {
        map.append("signature-input", extra.parse().expect("header value"));
    }
    if case.signature.len() > 1 {
        map.remove("signature");
        for line in &case.signature {
            map.append("signature", line.parse().expect("header value"));
        }
    }
    map
}

#[test]
fn signature_freshness_vectors_match_fixture_and_verifier() {
    let generated = generate();
    let expected_json = serde_json::to_string_pretty(&generated).expect("serialize") + "\n";
    let path = fixture_path();
    if std::env::var("ATPROTO_SPACES_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &expected_json).expect("write fixture");
    }
    let on_disk = std::fs::read_to_string(&path).expect("read space_credential_signature_v1.json");
    assert_eq!(
        on_disk, expected_json,
        "space_credential_signature_v1.json drifted from the generator"
    );
    let file: SignatureVectorFile = serde_json::from_str(&on_disk).expect("parse fixture");

    let mut failures = Vec::new();
    for case in &file.cases {
        let outcome =
            verify_credential_request(&headers_for(&file, case), &file.cnf_did_key, case.now_sec);
        let accepted = outcome.is_ok();
        if accepted != (case.expect == "accept") {
            failures.push(format!(
                "{}: expected {}, got {:?}",
                case.name, case.expect, outcome
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "vector mismatches:\n{}",
        failures.join("\n")
    );
}
