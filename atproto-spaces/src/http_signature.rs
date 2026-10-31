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

    let parsed_input = parse_labeled_signature_input(&combined_sig_input)?;
    let sig_bytes = parse_labeled_signature_bytes(&combined_sig)?;

    if parsed_input.components != ["authorization", "atproto-space-audience"] {
        return Err(SpacesError::BadSpaceSignature(
            "Signature-Input must cover (\"authorization\" \"atproto-space-audience\")".into(),
        ));
    }

    let mut seen_tag = false;
    let mut created: Option<u64> = None;
    let mut expires: Option<u64> = None;
    let mut nonce: Option<String> = None;

    for (k, v) in &parsed_input.params {
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
                SfBareItem::String(s) if !s.is_empty() && s.len() <= 512 => nonce = Some(s.clone()),
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

    if now_sec > 0 {
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
    }

    let canonical_params = serialize_inner_list(&parsed_input.components, &parsed_input.params);
    let base = build_signature_base(authorization, audience_did, &canonical_params);

    if sig_bytes.len() != 64 {
        return Err(SpacesError::BadSpaceSignature(format!(
            "expected 64-byte P-256 signature, got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_slice(&sig_bytes)
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
            .map_err(|_| SpacesError::BadSpaceSignature(format!("non-ASCII {name}")))?
            .trim_matches([' ', '\t']);
        total = total.saturating_add(s.len() + 2);
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
    String(String),
    Token(String),
    Boolean(bool),
}

struct ParsedInnerList {
    components: Vec<String>,
    params: Vec<(String, SfBareItem)>,
}

fn parse_labeled_signature_input(raw: &str) -> Result<ParsedInnerList> {
    let mut rest = raw.trim_matches([' ', '\t']);
    while !rest.is_empty() {
        let key = take_sf_key(&mut rest)?;
        rest = rest.trim_start_matches([' ', '\t']);
        if !rest.starts_with('=') {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input member must have '='".into(),
            ));
        }
        rest = &rest[1..];
        rest = rest.trim_start_matches([' ', '\t']);
        if !rest.starts_with('(') {
            return Err(SpacesError::BadSpaceSignature(
                "Signature-Input member value must be an inner list".into(),
            ));
        }
        rest = &rest[1..];
        let mut components = Vec::new();
        loop {
            rest = rest.trim_start_matches(' ');
            if rest.starts_with(')') {
                rest = &rest[1..];
                break;
            }
            if rest.is_empty() {
                return Err(SpacesError::BadSpaceSignature(
                    "unterminated inner list in Signature-Input".into(),
                ));
            }
            let comp = take_sf_string(&mut rest)?;
            if rest.starts_with(';') {
                return Err(SpacesError::BadSpaceSignature(
                    "component parameters are not supported in atproto-space-credential".into(),
                ));
            }
            components.push(comp);
            if !rest.starts_with(' ') && !rest.starts_with(')') {
                return Err(SpacesError::BadSpaceSignature(
                    "expected space or ')' in inner list".into(),
                ));
            }
        }
        let params = take_sf_params(&mut rest)?;
        rest = rest.trim_start_matches([' ', '\t']);
        if key == SPACE_CREDENTIAL_LABEL {
            return Ok(ParsedInnerList { components, params });
        }
        if rest.starts_with(',') {
            rest = rest[1..].trim_start_matches([' ', '\t']);
        } else if !rest.is_empty() {
            return Err(SpacesError::BadSpaceSignature(
                "malformed dictionary separator in Signature-Input".into(),
            ));
        }
    }
    Err(SpacesError::BadSpaceSignature(
        "missing atproto-space-credential entry in Signature-Input".into(),
    ))
}

fn parse_labeled_signature_bytes(raw: &str) -> Result<Vec<u8>> {
    let mut rest = raw.trim_matches([' ', '\t']);
    while !rest.is_empty() {
        let key = take_sf_key(&mut rest)?;
        rest = rest.trim_start_matches([' ', '\t']);
        if !rest.starts_with('=') {
            return Err(SpacesError::BadSpaceSignature(
                "Signature member must have '='".into(),
            ));
        }
        rest = rest[1..].trim_start_matches([' ', '\t']);
        if !rest.starts_with(':') {
            return Err(SpacesError::BadSpaceSignature(
                "Signature member must be a byte sequence".into(),
            ));
        }
        rest = &rest[1..];
        let Some(end_colon) = rest.find(':') else {
            return Err(SpacesError::BadSpaceSignature(
                "unterminated byte sequence in Signature".into(),
            ));
        };
        let b64 = &rest[..end_colon];
        rest = &rest[end_colon + 1..];
        let params = take_sf_params(&mut rest)?;
        if key == SPACE_CREDENTIAL_LABEL {
            if !params.is_empty() {
                return Err(SpacesError::BadSpaceSignature(
                    "Signature item must not carry parameters".into(),
                ));
            }
            return BASE64_STANDARD
                .decode(b64)
                .map_err(|e| SpacesError::BadSpaceSignature(format!("bad Signature base64: {e}")));
        }
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.starts_with(',') {
            rest = rest[1..].trim_start_matches([' ', '\t']);
        } else if !rest.is_empty() {
            return Err(SpacesError::BadSpaceSignature(
                "malformed dictionary separator in Signature".into(),
            ));
        }
    }
    Err(SpacesError::BadSpaceSignature(
        "missing atproto-space-credential entry in Signature".into(),
    ))
}

fn take_sf_key(rest: &mut &str) -> Result<String> {
    let bytes = rest.as_bytes();
    if bytes.is_empty() || !(bytes[0].is_ascii_lowercase() || bytes[0] == b'*') {
        return Err(SpacesError::BadSpaceSignature(
            "invalid structured-field key start".into(),
        ));
    }
    let mut idx = 1;
    while idx < bytes.len() {
        let b = bytes[idx];
        if b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*') {
            idx += 1;
        } else {
            break;
        }
    }
    let key = rest[..idx].to_string();
    *rest = &rest[idx..];
    Ok(key)
}

fn take_sf_string(rest: &mut &str) -> Result<String> {
    if !rest.starts_with('"') {
        return Err(SpacesError::BadSpaceSignature(
            "expected structured-field string".into(),
        ));
    }
    *rest = &rest[1..];
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((idx, ch)) = chars.next() {
        if ch == '"' {
            *rest = &rest[idx + 1..];
            return Ok(out);
        }
        if ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                return Err(SpacesError::BadSpaceSignature("unterminated escape".into()));
            };
            if escaped != '"' && escaped != '\\' {
                return Err(SpacesError::BadSpaceSignature(
                    "invalid structured-field escape".into(),
                ));
            }
            out.push(escaped);
        } else if ('\x20'..='\x7e').contains(&ch) {
            out.push(ch);
        } else {
            return Err(SpacesError::BadSpaceSignature(
                "control or non-ASCII char in structured-field string".into(),
            ));
        }
    }
    Err(SpacesError::BadSpaceSignature(
        "unterminated structured-field string".into(),
    ))
}

fn take_sf_params(rest: &mut &str) -> Result<Vec<(String, SfBareItem)>> {
    let mut params: Vec<(String, SfBareItem)> = Vec::new();
    loop {
        *rest = rest.trim_start_matches(' ');
        if !rest.starts_with(';') {
            break;
        }
        *rest = rest[1..].trim_start_matches(' ');
        let key = take_sf_key(rest)?;
        let val = if rest.starts_with('=') {
            *rest = &rest[1..];
            take_sf_bare_item(rest)?
        } else {
            SfBareItem::Boolean(true)
        };
        if let Some(existing) = params.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = val;
        } else {
            params.push((key, val));
        }
    }
    Ok(params)
}

fn take_sf_bare_item(rest: &mut &str) -> Result<SfBareItem> {
    let bytes = rest.as_bytes();
    if bytes.is_empty() {
        return Err(SpacesError::BadSpaceSignature(
            "empty parameter value".into(),
        ));
    }
    if bytes[0] == b'"' {
        return Ok(SfBareItem::String(take_sf_string(rest)?));
    }
    if bytes[0] == b'?' {
        if rest.starts_with("?1") {
            *rest = &rest[2..];
            return Ok(SfBareItem::Boolean(true));
        } else if rest.starts_with("?0") {
            *rest = &rest[2..];
            return Ok(SfBareItem::Boolean(false));
        }
        return Err(SpacesError::BadSpaceSignature("invalid boolean".into()));
    }
    if bytes[0] == b'-' || bytes[0].is_ascii_digit() {
        let mut idx = if bytes[0] == b'-' { 1 } else { 0 };
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let num_str = &rest[..idx];
        let val: i64 = num_str
            .parse()
            .map_err(|_| SpacesError::BadSpaceSignature("invalid integer parameter".into()))?;
        *rest = &rest[idx..];
        return Ok(SfBareItem::Integer(val));
    }
    if bytes[0].is_ascii_alphabetic() || bytes[0] == b'*' {
        let mut idx = 1;
        while idx < bytes.len() {
            let b = bytes[idx];
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
                idx += 1;
            } else {
                break;
            }
        }
        let tok = rest[..idx].to_string();
        *rest = &rest[idx..];
        return Ok(SfBareItem::Token(tok));
    }
    Err(SpacesError::BadSpaceSignature(
        "unsupported structured-field bare item".into(),
    ))
}

fn serialize_inner_list(components: &[String], params: &[(String, SfBareItem)]) -> String {
    let mut out = String::from("(");
    for (i, comp) in components.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('"');
        for ch in comp.chars() {
            if ch == '"' || ch == '\\' {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
    }
    out.push(')');
    for (k, v) in params {
        out.push(';');
        out.push_str(k);
        match v {
            SfBareItem::Boolean(true) => {}
            SfBareItem::Boolean(false) => out.push_str("=?0"),
            SfBareItem::Integer(n) => {
                out.push('=');
                out.push_str(&n.to_string());
            }
            SfBareItem::String(s) => {
                out.push_str("=\"");
                for ch in s.chars() {
                    if ch == '"' || ch == '\\' {
                        out.push('\\');
                    }
                    out.push(ch);
                }
                out.push('"');
            }
            SfBareItem::Token(t) => {
                out.push('=');
                out.push_str(t);
            }
        }
    }
    out
}
