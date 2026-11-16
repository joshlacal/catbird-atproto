//! RFC 9421 HTTP Message Signatures (`atproto-space-credential` profile).
//!
//! Signers always emit canonical low-S P-256 ECDSA signatures (`normalize_s()`).
//! Verifiers accept **both** low-S and high-S 64-byte `(r || s)` signatures so
//! browser WebCrypto (`catbird-mls-web`) and native clients interoperate cleanly.

use crate::is_valid_did;
use crate::kem::{decode_p256_did_key, P256SecretKey};
use crate::{Result, SpacesError};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use http::{HeaderMap, HeaderName, HeaderValue};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub const SPACE_CREDENTIAL_LABEL: &str = "atproto-space-credential";
pub const SPACE_SIGNATURE_ALG: &str = "ecdsa-p256-sha256";
pub const SPACE_AUDIENCE_HEADER: &str = "atproto-space-audience";
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
pub const SIGNATURE_HEADER: &str = "signature";
pub const MAX_SIGNATURE_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;
pub const MAX_SIGNATURE_AGE_SECS: u64 = 300;
/// Longest accepted `nonce` signature parameter, in bytes.
pub const MAX_NONCE_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRequestHeaders {
    pub authorization: String,
    pub atproto_space_audience: String,
    pub signature_input: String,
    pub signature: String,
}

impl SpaceRequestHeaders {
    pub fn to_header_map(&self) -> Result<HeaderMap> {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&self.authorization)
                .map_err(|e| SpacesError::BadSpaceSignature(format!("bad authorization: {e}")))?,
        );
        map.insert(
            HeaderName::from_static(SPACE_AUDIENCE_HEADER),
            HeaderValue::from_str(&self.atproto_space_audience)
                .map_err(|e| SpacesError::BadSpaceSignature(format!("bad audience: {e}")))?,
        );
        map.insert(
            HeaderName::from_static(SIGNATURE_INPUT_HEADER),
            HeaderValue::from_str(&self.signature_input)
                .map_err(|e| SpacesError::BadSpaceSignature(format!("bad signature-input: {e}")))?,
        );
        map.insert(
            HeaderName::from_static(SIGNATURE_HEADER),
            HeaderValue::from_str(&self.signature)
                .map_err(|e| SpacesError::BadSpaceSignature(format!("bad signature: {e}")))?,
        );
        Ok(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpaceHeaders {
    pub credential_jwt: String,
    pub audience_did: String,
    pub cnf_did_key: String,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub nonce: Option<String>,
}

/// Sign a Space credential presentation with `created` and `nonce` RFC 9421 parameters.
/// Emits canonical low-S P-256 ECDSA (`r || s`).
pub fn sign_credential_request(
    ephemeral_key: &P256SecretKey,
    credential_jwt: &str,
    audience_did: &str,
    created: u64,
    nonce: &str,
) -> Result<SpaceRequestHeaders> {
    if nonce.is_empty()
        || nonce.len() > 256
        || nonce
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b'"' || b == b'\\')
    {
        return Err(SpacesError::BadSpaceSignature(
            "invalid RFC 9421 signature nonce".to_string(),
        ));
    }
    let params = format!(
        "(\"authorization\" \"atproto-space-audience\");created={created};nonce=\"{nonce}\";tag=\"{SPACE_CREDENTIAL_LABEL}\""
    );
    sign_with_params(ephemeral_key, credential_jwt, audience_did, &params)
}

/// Sign a minimal `atproto#5187` Space credential presentation (`Swan` / `Petrel` minimal profile).
pub fn sign_credential_request_minimal(
    ephemeral_key: &P256SecretKey,
    credential_jwt: &str,
    audience_did: &str,
) -> Result<SpaceRequestHeaders> {
    let params =
        format!("(\"authorization\" \"atproto-space-audience\");tag=\"{SPACE_CREDENTIAL_LABEL}\"");
    sign_with_params(ephemeral_key, credential_jwt, audience_did, &params)
}

fn sign_with_params(
    ephemeral_key: &P256SecretKey,
    credential_jwt: &str,
    audience_did: &str,
    signature_params: &str,
) -> Result<SpaceRequestHeaders> {
    let jwt = credential_jwt.trim();
    if jwt.is_empty() || jwt.contains(['\r', '\n', ' ']) {
        return Err(SpacesError::BadSpaceSignature(
            "invalid credential JWT in Authorization".to_string(),
        ));
    }
    if !is_valid_did(audience_did) {
        return Err(SpacesError::BadSpaceSignature(format!(
            "invalid Atproto-Space-Audience DID: {audience_did}"
        )));
    }
    let authorization = format!("Atproto-Space-Credential {jwt}");
    let base = build_signature_base(&authorization, audience_did, signature_params);

    let signing_key = SigningKey::from(ephemeral_key);
    let raw_sig: Signature = signing_key.sign(base.as_bytes());
    let low_s_sig = raw_sig.normalize_s().unwrap_or(raw_sig);
    let sig_b64 = BASE64_STANDARD.encode(low_s_sig.to_bytes());

    Ok(SpaceRequestHeaders {
        authorization,
        atproto_space_audience: audience_did.to_string(),
        signature_input: format!("{SPACE_CREDENTIAL_LABEL}={signature_params}"),
        signature: format!("{SPACE_CREDENTIAL_LABEL}=:{sig_b64}:"),
    })
}

/// Verify an RFC 9421 `atproto-space-credential` request against `expected_cnf_did_key`.
/// Accepts **both** low-S and WebCrypto high-S ECDSA P-256 signatures.
///
/// The optional `created`, `expires` and `nonce` signature parameters are
/// enforced against `now_sec` (Unix seconds) whenever they are present:
/// `created` may be at most [`MAX_SIGNATURE_AGE_SECS`] old and at most
/// [`MAX_CLOCK_SKEW_SECS`] ahead, `expires` may have passed by at most
/// [`MAX_CLOCK_SKEW_SECS`], and `nonce` must be a non-empty string of at most
/// [`MAX_NONCE_BYTES`] bytes. A presentation without them carries no freshness
/// constraint here. This function is stateless: it does not detect a repeated
/// `nonce`. Callers that keep state record verified nonces with
/// [`check_presentation_replay`](crate::signature_replay::check_presentation_replay).
///
/// Structured fields follow RFC 8941: a repeated dictionary key or parameter
/// key overwrites the earlier value in place, and the signature base uses the
/// re-serialized parameters. Swan's verifier behaves identically; the shared
/// vectors in `tests/vectors/space_credential_signature_v1.json` pin this.
pub fn verify_credential_request(
    headers: &HeaderMap,
    expected_cnf_did_key: &str,
    now_sec: u64,
) -> Result<VerifiedSpaceHeaders> {
    let public_key = decode_p256_did_key(expected_cnf_did_key)?;
    let verifying_key = VerifyingKey::from(&public_key);

    let auth_values: Vec<&HeaderValue> = headers
        .get_all(http::header::AUTHORIZATION)
        .iter()
        .collect();
    if auth_values.len() != 1 {
        return Err(SpacesError::BadSpaceSignature(
            "expected exactly one Authorization header".to_string(),
        ));
    }
    let authorization = auth_values[0]
        .to_str()
        .map_err(|_| SpacesError::BadSpaceSignature("non-ASCII Authorization header".into()))?
        .trim_matches([' ', '\t']);

    let prefix_len = "atproto-space-credential ".len();
    if authorization.len() <= prefix_len
        || !authorization[..prefix_len].eq_ignore_ascii_case("atproto-space-credential ")
    {
        return Err(SpacesError::BadSpaceSignature(
            "Authorization must use Atproto-Space-Credential scheme".to_string(),
        ));
    }
    let credential_jwt = authorization[prefix_len..].trim_matches([' ', '\t']);
    if credential_jwt.is_empty() || credential_jwt.contains([' ', '\t', '\r', '\n']) {
        return Err(SpacesError::BadSpaceSignature(
            "malformed credential token in Authorization".to_string(),
        ));
    }

    let aud_values: Vec<&HeaderValue> = headers.get_all(SPACE_AUDIENCE_HEADER).iter().collect();
    if aud_values.len() != 1 {
        return Err(SpacesError::BadSpaceSignature(
            "expected exactly one Atproto-Space-Audience header".to_string(),
        ));
    }
    let audience_did = aud_values[0]
        .to_str()
        .map_err(|_| SpacesError::BadSpaceSignature("non-ASCII Atproto-Space-Audience".into()))?
        .trim_matches([' ', '\t']);
    if !is_valid_did(audience_did) {
        return Err(SpacesError::BadSpaceSignature(
            "invalid Atproto-Space-Audience DID".to_string(),
        ));
    }

    let combined_sig_input = combine_header_lines(headers, SIGNATURE_INPUT_HEADER)?;
    let combined_sig = combine_header_lines(headers, SIGNATURE_HEADER)?;

    let input_dict = SfParser::parse_dictionary(&combined_sig_input)?;
    let sig_dict = SfParser::parse_dictionary(&combined_sig)?;

    let tagged: Vec<&(String, SfMember)> = input_dict
        .entries
        .iter()
        .filter(|(_, member)| match member {
            SfMember::InnerList(list) => {
                list.params.get("tag") == Some(&SfBareItem::String(SPACE_CREDENTIAL_LABEL.into()))
            }
            SfMember::Item(_) => false,
        })
        .collect();

    if tagged.len() != 1 {
        return Err(SpacesError::BadSpaceSignature(
            "Signature-Input must contain uniquely one tag=\"atproto-space-credential\" inner list"
                .into(),
        ));
    }

    let (sig_label, SfMember::InnerList(parsed_input)) = tagged[0] else {
        return Err(SpacesError::BadSpaceSignature(
            "tagged Signature-Input member must be an inner list".into(),
        ));
    };

    let Some(SfMember::Item(sig_item)) = sig_dict.get(sig_label) else {
        return Err(SpacesError::BadSpaceSignature(
            "Signature dictionary missing matching entry for tagged Signature-Input member".into(),
        ));
    };
    if !sig_item.params.is_empty() {
        return Err(SpacesError::BadSpaceSignature(
            "Signature byte-sequence item must not carry parameters".into(),
        ));
    }
    let SfBareItem::ByteSequence(sig_bytes) = &sig_item.value else {
        return Err(SpacesError::BadSpaceSignature(
            "Signature member must be an RFC 8941 byte sequence".into(),
        ));
    };

    let mut components = Vec::with_capacity(parsed_input.items.len());
    for item in &parsed_input.items {
        if !item.params.is_empty() {
            return Err(SpacesError::BadSpaceSignature(
                "component parameters are not supported in atproto-space-credential".into(),
            ));
        }
        let SfBareItem::String(comp) = &item.value else {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input covered components must be structured-field strings".into(),
            ));
        };
        components.push(comp.as_str());
    }
    if components != ["authorization", "atproto-space-audience"] {
        return Err(SpacesError::BadSpaceSignature(
            "Signature-Input must cover (\"authorization\" \"atproto-space-audience\")".into(),
        ));
    }

    let mut seen_tag = false;
    let mut created: Option<u64> = None;
    let mut expires: Option<u64> = None;
    let mut nonce: Option<String> = None;

    for (k, v) in &parsed_input.params.entries {
        match k.as_str() {
            "tag" => match v {
                SfBareItem::String(s) if s == SPACE_CREDENTIAL_LABEL => seen_tag = true,
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "tag must equal \"atproto-space-credential\"".into(),
                    ))
                }
            },
            "alg" => match v {
                SfBareItem::String(s) if s == SPACE_SIGNATURE_ALG => {}
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "unsupported RFC 9421 alg".into(),
                    ))
                }
            },
            "keyid" => match v {
                SfBareItem::String(s) if s == expected_cnf_did_key => {}
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "Signature-Input keyid does not match credential cnf.kid".into(),
                    ))
                }
            },
            "created" => match v {
                SfBareItem::Integer(ts) if *ts >= 0 => created = Some(*ts as u64),
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "created parameter must be a non-negative integer".into(),
                    ))
                }
            },
            "expires" => match v {
                SfBareItem::Integer(ts) if *ts >= 0 => expires = Some(*ts as u64),
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "expires parameter must be a non-negative integer".into(),
                    ))
                }
            },
            "nonce" => match v {
                SfBareItem::String(s) if !s.is_empty() && s.len() <= MAX_NONCE_BYTES => {
                    nonce = Some(s.clone())
                }
                _ => {
                    return Err(SpacesError::BadSpaceSignature(
                        "nonce parameter must be a non-empty bounded string".into(),
                    ))
                }
            },
            _ => {}
        }
    }

    if !seen_tag {
        return Err(SpacesError::BadSpaceSignature(
            "missing tag=\"atproto-space-credential\" in Signature-Input".into(),
        ));
    }

    // Freshness is checked against the caller's clock on every call; a zero
    // clock is the Unix epoch, not a switch that turns the checks off.
    if let Some(c) = created {
        if c > now_sec.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input created is in the future".into(),
            ));
        }
        if now_sec > c.saturating_add(MAX_SIGNATURE_AGE_SECS) {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input created is expired".into(),
            ));
        }
    }
    if let Some(exp) = expires {
        if now_sec > exp.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input expires has passed".into(),
            ));
        }
    }

    let canonical_params = serialize_inner_list(parsed_input);
    let base = build_signature_base(authorization, audience_did, &canonical_params);

    if sig_bytes.len() != 64 {
        return Err(SpacesError::BadSpaceSignature(format!(
            "expected 64-byte P-256 signature, got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| SpacesError::BadSpaceSignature(format!("malformed ECDSA signature: {e}")))?;
    // Normalize high-S -> low-S before verification so WebCrypto high-S signatures pass cleanly!
    let normalized = sig.normalize_s().unwrap_or(sig);
    verifying_key
        .verify(base.as_bytes(), &normalized)
        .map_err(|_| {
            SpacesError::BadSpaceSignature("RFC 9421 signature verification failed".into())
        })?;

    Ok(VerifiedSpaceHeaders {
        credential_jwt: credential_jwt.to_string(),
        audience_did: audience_did.to_string(),
        cnf_did_key: expected_cnf_did_key.to_string(),
        created,
        expires,
        nonce,
    })
}

fn build_signature_base(authorization: &str, audience: &str, signature_params: &str) -> String {
    format!(
        "\"authorization\": {authorization}\n\"atproto-space-audience\": {audience}\n\"@signature-params\": {signature_params}"
    )
}

fn combine_header_lines(headers: &HeaderMap, name: &str) -> Result<String> {
    let vals: Vec<&HeaderValue> = headers.get_all(name).iter().collect();
    if vals.is_empty() {
        return Err(SpacesError::BadSpaceSignature(format!(
            "missing required header {name}"
        )));
    }
    let mut parts = Vec::with_capacity(vals.len());
    let mut total = 0usize;
    for v in vals {
        let s = v
            .to_str()
            .map_err(|_| SpacesError::BadSpaceSignature(format!("non-ASCII {name}")))?;
        let sep = if parts.is_empty() { 0 } else { 2 };
        total = total.saturating_add(sep).saturating_add(s.len());
        if total > MAX_SIGNATURE_HEADER_BYTES {
            return Err(SpacesError::BadSpaceSignature(format!(
                "{name} exceeds {MAX_SIGNATURE_HEADER_BYTES} bytes"
            )));
        }
        parts.push(s);
    }
    Ok(parts.join(", "))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SfBareItem {
    Integer(i64),
    Decimal(String),
    String(String),
    Token(String),
    ByteSequence(Vec<u8>),
    Boolean(bool),
}

/// RFC 8941 parameters in insertion order. A repeated key overwrites the
/// earlier value and keeps its first position (RFC 8941 §4.2.3.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SfParams {
    entries: Vec<(String, SfBareItem)>,
}

impl SfParams {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn get(&self, key: &str) -> Option<&SfBareItem> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn set(&mut self, key: String, val: SfBareItem) {
        if let Some(existing) = self.entries.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = val;
        } else {
            self.entries.push((key, val));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SfItem {
    value: SfBareItem,
    params: SfParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SfInnerList {
    items: Vec<SfItem>,
    params: SfParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SfMember {
    Item(SfItem),
    InnerList(SfInnerList),
}

/// RFC 8941 dictionary in insertion order. A repeated key overwrites the
/// earlier member and keeps its first position (RFC 8941 §4.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SfDictionary {
    entries: Vec<(String, SfMember)>,
}

impl SfDictionary {
    fn get(&self, key: &str) -> Option<&SfMember> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn set(&mut self, key: String, val: SfMember) {
        if let Some(existing) = self.entries.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = val;
        } else {
            self.entries.push((key, val));
        }
    }
}

/// Strict RFC 8941 §4.2 dictionary parser matching `Swan`'s `StructuredFieldParser`.
struct SfParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> SfParser<'a> {
    fn parse_dictionary(text: &'a str) -> Result<SfDictionary> {
        let mut parser = Self {
            bytes: text.as_bytes(),
            index: 0,
        };
        parser.discard_spaces();
        let dict = parser.dictionary()?;
        parser.discard_spaces();
        if !parser.is_at_end() {
            return Err(SpacesError::BadSpaceSignature(
                "trailing bytes in structured-field dictionary".into(),
            ));
        }
        Ok(dict)
    }

    fn is_at_end(&self) -> bool {
        self.index >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.index += 1;
        Some(b)
    }

    fn discard_spaces(&mut self) {
        while self.peek() == Some(b' ') {
            self.index += 1;
        }
    }

    fn discard_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.index += 1;
        }
    }

    fn dictionary(&mut self) -> Result<SfDictionary> {
        let mut dict = SfDictionary::default();
        while !self.is_at_end() {
            let key = self.key()?;
            let member = if self.peek() == Some(b'=') {
                self.index += 1;
                self.item_or_inner_list()?
            } else {
                SfMember::Item(SfItem {
                    value: SfBareItem::Boolean(true),
                    params: self.parameters()?,
                })
            };
            dict.set(key, member);
            self.discard_ows();
            if self.is_at_end() {
                return Ok(dict);
            }
            if self.consume() != Some(b',') {
                return Err(SpacesError::BadSpaceSignature(
                    "malformed dictionary separator".into(),
                ));
            }
            self.discard_ows();
            if self.is_at_end() {
                return Err(SpacesError::BadSpaceSignature(
                    "trailing comma in structured-field dictionary".into(),
                ));
            }
        }
        Ok(dict)
    }

    fn item_or_inner_list(&mut self) -> Result<SfMember> {
        if self.peek() == Some(b'(') {
            Ok(SfMember::InnerList(self.inner_list()?))
        } else {
            Ok(SfMember::Item(self.item()?))
        }
    }

    fn inner_list(&mut self) -> Result<SfInnerList> {
        if self.consume() != Some(b'(') {
            return Err(SpacesError::BadSpaceSignature(
                "expected '(' starting inner list".into(),
            ));
        }
        let mut items = Vec::new();
        while !self.is_at_end() {
            self.discard_spaces();
            if self.peek() == Some(b')') {
                self.index += 1;
                let params = self.parameters()?;
                return Ok(SfInnerList { items, params });
            }
            items.push(self.item()?);
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return Err(SpacesError::BadSpaceSignature(
                    "expected space or ')' in inner list".into(),
                ));
            }
        }
        Err(SpacesError::BadSpaceSignature(
            "unterminated inner list".into(),
        ))
    }

    fn item(&mut self) -> Result<SfItem> {
        let value = self.bare_item()?;
        let params = self.parameters()?;
        Ok(SfItem { value, params })
    }

    fn parameters(&mut self) -> Result<SfParams> {
        let mut params = SfParams::default();
        while self.peek() == Some(b';') {
            self.index += 1;
            self.discard_spaces();
            let key = self.key()?;
            let val = if self.peek() == Some(b'=') {
                self.index += 1;
                self.bare_item()?
            } else {
                SfBareItem::Boolean(true)
            };
            params.set(key, val);
        }
        Ok(params)
    }

    fn key(&mut self) -> Result<String> {
        let Some(first) = self.peek() else {
            return Err(SpacesError::BadSpaceSignature(
                "unexpected end of structured-field key".into(),
            ));
        };
        if !(first.is_ascii_lowercase() || first == b'*') {
            return Err(SpacesError::BadSpaceSignature(
                "invalid structured-field key start".into(),
            ));
        }
        let start = self.index;
        while let Some(b) = self.peek() {
            if b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'-' | b'.' | b'*')
            {
                self.index += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.index]).into_owned())
    }

    fn bare_item(&mut self) -> Result<SfBareItem> {
        let Some(first) = self.peek() else {
            return Err(SpacesError::BadSpaceSignature(
                "empty structured-field item".into(),
            ));
        };
        if first == b'-' || first.is_ascii_digit() {
            return self.integer_or_decimal();
        }
        if first == b'"' {
            return Ok(SfBareItem::String(self.string()?));
        }
        if first.is_ascii_alphabetic() || first == b'*' {
            return Ok(SfBareItem::Token(self.token()));
        }
        if first == b':' {
            return Ok(SfBareItem::ByteSequence(self.byte_sequence()?));
        }
        if first == b'?' {
            return Ok(SfBareItem::Boolean(self.boolean()?));
        }
        Err(SpacesError::BadSpaceSignature(
            "unsupported structured-field bare item".into(),
        ))
    }

    fn integer_or_decimal(&mut self) -> Result<SfBareItem> {
        let mut is_decimal = false;
        let mut negative = false;
        let mut digits = Vec::new();
        if self.peek() == Some(b'-') {
            self.index += 1;
            negative = true;
        }
        let Some(first) = self.peek() else {
            return Err(SpacesError::BadSpaceSignature("invalid number".into()));
        };
        if !first.is_ascii_digit() {
            return Err(SpacesError::BadSpaceSignature("invalid number".into()));
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                digits.push(b);
                self.index += 1;
            } else if !is_decimal && b == b'.' {
                if digits.len() > 12 {
                    return Err(SpacesError::BadSpaceSignature(
                        "decimal integer part too long".into(),
                    ));
                }
                digits.push(b);
                self.index += 1;
                is_decimal = true;
            } else {
                break;
            }
            if !is_decimal && digits.len() > 15 {
                return Err(SpacesError::BadSpaceSignature(
                    "integer exceeds 15 digits".into(),
                ));
            }
            if is_decimal && digits.len() > 16 {
                return Err(SpacesError::BadSpaceSignature(
                    "decimal exceeds 16 characters".into(),
                ));
            }
        }
        let text = std::str::from_utf8(&digits)
            .map_err(|_| SpacesError::BadSpaceSignature("invalid UTF-8 digits".into()))?;
        if !is_decimal {
            let mag: i64 = text
                .parse()
                .map_err(|_| SpacesError::BadSpaceSignature("invalid integer".into()))?;
            return Ok(SfBareItem::Integer(if negative { -mag } else { mag }));
        }
        if digits.last() == Some(&b'.') {
            return Err(SpacesError::BadSpaceSignature(
                "decimal ends with '.'".into(),
            ));
        }
        let Some((int_raw, frac_raw)) = text.split_once('.') else {
            return Err(SpacesError::BadSpaceSignature("malformed decimal".into()));
        };
        if frac_raw.len() > 3 || frac_raw.contains('.') {
            return Err(SpacesError::BadSpaceSignature(
                "decimal fractional part exceeds 3 digits".into(),
            ));
        }
        let int_trimmed = int_raw.trim_start_matches('0');
        let frac_trimmed = frac_raw.trim_end_matches('0');
        let int_text = if int_trimmed.is_empty() {
            "0"
        } else {
            int_trimmed
        };
        let frac_text = if frac_trimmed.is_empty() {
            "0"
        } else {
            frac_trimmed
        };
        let is_zero = int_text == "0" && frac_text == "0";
        let sign = if negative && !is_zero { "-" } else { "" };
        Ok(SfBareItem::Decimal(format!("{sign}{int_text}.{frac_text}")))
    }

    fn string(&mut self) -> Result<String> {
        if self.consume() != Some(b'"') {
            return Err(SpacesError::BadSpaceSignature("expected '\"'".into()));
        }
        let mut out = Vec::new();
        while let Some(b) = self.consume() {
            if b == b'\\' {
                let Some(escaped) = self.consume() else {
                    return Err(SpacesError::BadSpaceSignature("unterminated escape".into()));
                };
                if escaped != b'"' && escaped != b'\\' {
                    return Err(SpacesError::BadSpaceSignature(
                        "invalid structured-field string escape".into(),
                    ));
                }
                out.push(escaped);
            } else if b == b'"' {
                return String::from_utf8(out).map_err(|_| {
                    SpacesError::BadSpaceSignature("non-UTF8 structured-field string".into())
                });
            } else if !(0x20..=0x7e).contains(&b) {
                return Err(SpacesError::BadSpaceSignature(
                    "control or non-ASCII byte in structured-field string".into(),
                ));
            } else {
                out.push(b);
            }
        }
        Err(SpacesError::BadSpaceSignature(
            "unterminated structured-field string".into(),
        ))
    }

    fn token(&mut self) -> String {
        let start = self.index;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                        | b':'
                        | b'/'
                )
            {
                self.index += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.bytes[start..self.index]).into_owned()
    }

    fn byte_sequence(&mut self) -> Result<Vec<u8>> {
        if self.consume() != Some(b':') {
            return Err(SpacesError::BadSpaceSignature(
                "expected ':' starting byte sequence".into(),
            ));
        }
        let start = self.index;
        while let Some(b) = self.consume() {
            if b == b':' {
                let raw_b64 = std::str::from_utf8(&self.bytes[start..self.index - 1])
                    .map_err(|_| SpacesError::BadSpaceSignature("non-ASCII base64".into()))?;
                let pad = (4 - raw_b64.len() % 4) % 4;
                let mut padded = String::with_capacity(raw_b64.len() + pad);
                padded.push_str(raw_b64);
                for _ in 0..pad {
                    padded.push('=');
                }
                return BASE64_STANDARD.decode(padded).map_err(|e| {
                    SpacesError::BadSpaceSignature(format!("bad byte-sequence base64: {e}"))
                });
            }
            if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
                return Err(SpacesError::BadSpaceSignature(
                    "invalid base64 character in byte sequence".into(),
                ));
            }
        }
        Err(SpacesError::BadSpaceSignature(
            "unterminated byte sequence".into(),
        ))
    }

    fn boolean(&mut self) -> Result<bool> {
        if self.consume() != Some(b'?') {
            return Err(SpacesError::BadSpaceSignature("expected '?'".into()));
        }
        match self.consume() {
            Some(b'1') => Ok(true),
            Some(b'0') => Ok(false),
            _ => Err(SpacesError::BadSpaceSignature("invalid boolean".into())),
        }
    }
}

fn serialize_inner_list(list: &SfInnerList) -> String {
    let mut out = String::from("(");
    for (i, item) in list.items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        serialize_item_into(&mut out, item);
    }
    out.push(')');
    serialize_params_into(&mut out, &list.params);
    out
}

fn serialize_item_into(out: &mut String, item: &SfItem) {
    serialize_bare_item_into(out, &item.value);
    serialize_params_into(out, &item.params);
}

fn serialize_params_into(out: &mut String, params: &SfParams) {
    for (k, v) in &params.entries {
        out.push(';');
        out.push_str(k);
        if v != &SfBareItem::Boolean(true) {
            out.push('=');
            serialize_bare_item_into(out, v);
        }
    }
}

fn serialize_bare_item_into(out: &mut String, val: &SfBareItem) {
    match val {
        SfBareItem::Integer(n) => out.push_str(&n.to_string()),
        SfBareItem::Decimal(d) => out.push_str(d),
        SfBareItem::String(s) => {
            out.push('"');
            for ch in s.chars() {
                if ch == '"' || ch == '\\' {
                    out.push('\\');
                }
                out.push(ch);
            }
            out.push('"');
        }
        SfBareItem::Token(t) => out.push_str(t),
        SfBareItem::ByteSequence(bytes) => {
            out.push(':');
            out.push_str(&BASE64_STANDARD.encode(bytes));
            out.push(':');
        }
        SfBareItem::Boolean(flag) => out.push_str(if *flag { "?1" } else { "?0" }),
    }
}
