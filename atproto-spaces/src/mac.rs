//! November 12 RFC 9421 / RFC 9651 structured-field MAC authenticators for ATProto Spaces:
//! - Request negotiation: `Accept-Signature: mac=("<profile>";sf);keyid="<did:key:zDn...>";tag="<profile>"`
//! - Commit response: `Atproto-Space-Commit` + `Signature-Input` + `Signature` (`tag="atproto-space-commit"`)
//! - Record response: `Atproto-Space-Record` + `Signature-Input` + `Signature` (`tag="atproto-space-record"`)

use crate::{Result, SpacesError};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderName, HeaderValue};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const ACCEPT_SIGNATURE_HEADER: &str = "accept-signature";
pub const COMMIT_MAC_HEADER: &str = "atproto-space-commit";
pub const RECORD_MAC_HEADER: &str = "atproto-space-record";
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
pub const SIGNATURE_HEADER: &str = "signature";

pub const COMMIT_MAC_PROFILE: &str = "atproto-space-commit";
pub const RECORD_MAC_PROFILE: &str = "atproto-space-record";
pub const DEFAULT_MAC_LABEL: &str = "mac";

const MAX_STRUCTURED_HEADER_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProfile {
    Commit,
    Record,
}

impl MacProfile {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Commit => COMMIT_MAC_PROFILE,
            Self::Record => RECORD_MAC_PROFILE,
        }
    }

    pub const fn response_header(&self) -> &'static str {
        match self {
            Self::Commit => COMMIT_MAC_HEADER,
            Self::Record => RECORD_MAC_HEADER,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceMacResponseHeaders {
    pub covered_header_name: &'static str,
    pub covered_header: String,
    pub signature_input: String,
    pub signature: String,
}

impl SpaceMacResponseHeaders {
    pub fn apply_to(&self, headers: &mut HeaderMap) -> Result<()> {
        let covered_name = HeaderName::from_static(self.covered_header_name);
        let covered_val = HeaderValue::from_str(&self.covered_header)
            .map_err(|e| SpacesError::MacMismatch(format!("invalid covered MAC header: {e}")))?;
        let sig_input_val = HeaderValue::from_str(&self.signature_input)
            .map_err(|e| SpacesError::MacMismatch(format!("invalid Signature-Input: {e}")))?;
        let sig_val = HeaderValue::from_str(&self.signature)
            .map_err(|e| SpacesError::MacMismatch(format!("invalid Signature: {e}")))?;

        headers.insert(covered_name, covered_val);
        headers.insert(
            HeaderName::from_static(SIGNATURE_INPUT_HEADER),
            sig_input_val,
        );
        headers.insert(HeaderName::from_static(SIGNATURE_HEADER), sig_val);
        Ok(())
    }

    pub fn to_header_map(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        self.apply_to(&mut headers)?;
        Ok(headers)
    }
}

/// Format `Accept-Signature` header (`mac=("<profile>";sf);keyid="<key_share>";tag="<profile>"`).
pub fn format_accept_signature(profile: MacProfile, key_share_did_key: &str) -> Result<String> {
    validate_sf_string(key_share_did_key, "keyid")?;
    let component = SfItem {
        bare: SfBare::String(profile.as_str().to_string()),
        parameters: vec![("sf".to_string(), SfBare::Boolean(true))],
    };
    let params = vec![
        (
            "keyid".to_string(),
            SfBare::String(key_share_did_key.to_string()),
        ),
        (
            "tag".to_string(),
            SfBare::String(profile.as_str().to_string()),
        ),
    ];
    Ok(format!(
        "{DEFAULT_MAC_LABEL}={}",
        serialize_member(&SfMember::InnerList(vec![component], params))
    ))
}

/// Parse `Accept-Signature` header and return `(label, key_share_did_key)` for `expected_profile`.
pub fn parse_accept_signature(
    header_value: &str,
    expected_profile: MacProfile,
) -> Result<(String, String)> {
    let dict = parse_sf_dictionary(header_value)?;
    let (label, _components, params) = extract_single_tagged_inner_list(&dict, expected_profile)?;
    let Some(SfBare::String(key_share)) = find_param(&params, "keyid") else {
        return Err(SpacesError::MacMismatch(
            "Accept-Signature missing string keyid parameter".into(),
        ));
    };
    if key_share.is_empty() {
        return Err(SpacesError::MacMismatch(
            "Accept-Signature keyid must be non-empty".into(),
        ));
    }
    Ok((label, key_share.clone()))
}

/// Sign `Atproto-Space-Commit` + `Signature-Input` + `Signature` for `(space, repo, rev, data_32)`.
pub fn sign_commit_mac(
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    label: &str,
    space: &str,
    repo: &str,
    rev: &str,
    data_32: &[u8; 32],
) -> Result<(SpaceMacResponseHeaders, [u8; 32])> {
    validate_sf_key(label)?;
    validate_sf_string(key_share_did_key, "keyid")?;
    validate_sf_string(repo, "repo")?;
    validate_sf_string(space, "space")?;
    validate_sf_string(rev, "rev")?;

    let fields = SfDictionary {
        members: vec![
            (
                "ver".to_string(),
                SfMember::Item(SfItem::bare(SfBare::Integer(1))),
            ),
            (
                "repo".to_string(),
                SfMember::Item(SfItem::bare(SfBare::String(repo.to_string()))),
            ),
            (
                "space".to_string(),
                SfMember::Item(SfItem::bare(SfBare::String(space.to_string()))),
            ),
            (
                "rev".to_string(),
                SfMember::Item(SfItem::bare(SfBare::String(rev.to_string()))),
            ),
            (
                "data".to_string(),
                SfMember::Item(SfItem::bare(SfBare::Bytes(data_32.to_vec()))),
            ),
        ],
    };
    sign_mac_profile(
        MacProfile::Commit,
        shared_secret,
        key_share_did_key,
        label,
        &fields,
    )
}

/// Sign `Atproto-Space-Record` + `Signature-Input` + `Signature` for `(record_uri, cid_str)`.
pub fn sign_record_mac(
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    label: &str,
    record_uri: &str,
    cid_str: &str,
) -> Result<(SpaceMacResponseHeaders, [u8; 32])> {
    validate_sf_key(label)?;
    validate_sf_string(key_share_did_key, "keyid")?;
    validate_sf_string(record_uri, "uri")?;
    if cid_str.is_empty() {
        return Err(SpacesError::MacMismatch("cid must be non-empty".into()));
    }
    validate_sf_string(cid_str, "cid")?;

    let fields = SfDictionary {
        members: vec![
            (
                "uri".to_string(),
                SfMember::Item(SfItem::bare(SfBare::String(record_uri.to_string()))),
            ),
            (
                "cid".to_string(),
                SfMember::Item(SfItem::bare(SfBare::String(cid_str.to_string()))),
            ),
        ],
    };
    sign_mac_profile(
        MacProfile::Record,
        shared_secret,
        key_share_did_key,
        label,
        &fields,
    )
}

/// Verify `Atproto-Space-Commit` + `Signature-Input` + `Signature` against `(space, repo, rev, data_32)`.
pub fn verify_commit_mac(
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    headers: &HeaderMap,
    space: &str,
    repo: &str,
    rev: &str,
    data_32: &[u8; 32],
) -> Result<()> {
    let fields = verify_mac_profile(
        MacProfile::Commit,
        shared_secret,
        key_share_did_key,
        headers,
    )?;
    if fields.bare("ver") != Some(&SfBare::Integer(1))
        || fields.bare("repo") != Some(&SfBare::String(repo.to_string()))
        || fields.bare("space") != Some(&SfBare::String(space.to_string()))
        || fields.bare("rev") != Some(&SfBare::String(rev.to_string()))
        || fields.bare("data").and_then(SfBare::as_bytes) != Some(data_32.as_slice())
    {
        return Err(SpacesError::MacMismatch(
            "Atproto-Space-Commit covered fields do not match commit metadata".into(),
        ));
    }
    Ok(())
}

/// Verify `Atproto-Space-Record` + `Signature-Input` + `Signature` against `(record_uri, cid_str)`.
pub fn verify_record_mac(
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    headers: &HeaderMap,
    record_uri: &str,
    cid_str: &str,
) -> Result<()> {
    let fields = verify_mac_profile(
        MacProfile::Record,
        shared_secret,
        key_share_did_key,
        headers,
    )?;
    if fields.bare("uri") != Some(&SfBare::String(record_uri.to_string()))
        || fields.bare("cid") != Some(&SfBare::String(cid_str.to_string()))
    {
        return Err(SpacesError::MacMismatch(
            "Atproto-Space-Record covered fields do not match record URI/CID".into(),
        ));
    }
    Ok(())
}

fn sign_mac_profile(
    profile: MacProfile,
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    label: &str,
    fields: &SfDictionary,
) -> Result<(SpaceMacResponseHeaders, [u8; 32])> {
    let covered_header = serialize_dictionary(fields);
    let component = SfItem {
        bare: SfBare::String(profile.as_str().to_string()),
        parameters: vec![("sf".to_string(), SfBare::Boolean(true))],
    };
    let params = vec![
        (
            "keyid".to_string(),
            SfBare::String(key_share_did_key.to_string()),
        ),
        (
            "tag".to_string(),
            SfBare::String(profile.as_str().to_string()),
        ),
    ];
    let signature_params = serialize_member(&SfMember::InnerList(vec![component], params));
    let base = format!(
        "\"{}\";sf: {covered_header}\n\"@signature-params\": {signature_params}",
        profile.as_str()
    );
    let mac_bytes = compute_hmac_sha256(shared_secret, base.as_bytes())?;
    let signature_input = format!("{label}={signature_params}");
    let signature = format!("{label}=:{}:", BASE64_STANDARD.encode(mac_bytes));

    Ok((
        SpaceMacResponseHeaders {
            covered_header_name: profile.response_header(),
            covered_header,
            signature_input,
            signature,
        },
        mac_bytes,
    ))
}

fn verify_mac_profile(
    profile: MacProfile,
    shared_secret: &[u8; 32],
    key_share_did_key: &str,
    headers: &HeaderMap,
) -> Result<SfDictionary> {
    let sig_input_raw = get_required_ascii_header(headers, SIGNATURE_INPUT_HEADER)?;
    let sig_raw = get_required_ascii_header(headers, SIGNATURE_HEADER)?;
    let covered_raw = get_required_ascii_header(headers, profile.response_header())?;

    let inputs = parse_sf_dictionary(sig_input_raw)?;
    let signatures = parse_sf_dictionary(sig_raw)?;
    let (label, components, params) = extract_single_tagged_inner_list(&inputs, profile)?;

    if let Some(keyid) = find_param(&params, "keyid") {
        if keyid != &SfBare::String(key_share_did_key.to_string()) {
            return Err(SpacesError::MacMismatch(
                "Signature-Input keyid does not match request keyShare".into(),
            ));
        }
    }

    let Some(SfMember::Item(sig_item)) = signatures.member(&label) else {
        return Err(SpacesError::MacMismatch(
            "Signature dictionary missing matching MAC label item".into(),
        ));
    };
    if !sig_item.parameters.is_empty() {
        return Err(SpacesError::MacMismatch(
            "Signature item must not carry parameters".into(),
        ));
    }
    let SfBare::Bytes(auth_code) = &sig_item.bare else {
        return Err(SpacesError::MacMismatch(
            "Signature item must be a structured byte sequence".into(),
        ));
    };
    let auth_code_32: [u8; 32] = auth_code.as_slice().try_into().map_err(|_| {
        SpacesError::MacMismatch("Space MAC authentication code must be 32 bytes".into())
    })?;

    let fields = parse_sf_dictionary(covered_raw)?;
    let canonical_fields = serialize_dictionary(&fields);
    let signature_params = serialize_member(&SfMember::InnerList(components, params));
    let base = format!(
        "\"{}\";sf: {canonical_fields}\n\"@signature-params\": {signature_params}",
        profile.as_str()
    );
    let expected = compute_hmac_sha256(shared_secret, base.as_bytes())?;
    if !bool::from(auth_code_32.ct_eq(&expected)) {
        return Err(SpacesError::MacMismatch(
            "Space MAC verification failed".into(),
        ));
    }
    Ok(fields)
}

fn extract_single_tagged_inner_list(
    dict: &SfDictionary,
    profile: MacProfile,
) -> Result<(String, Vec<SfItem>, SfParameters)> {
    let mut matches = Vec::new();
    for (label, member) in &dict.members {
        if let SfMember::InnerList(components, params) = member {
            if find_param(params, "tag") == Some(&SfBare::String(profile.as_str().to_string())) {
                matches.push((label.clone(), components.clone(), params.clone()));
            }
        }
    }
    if matches.len() != 1 {
        return Err(SpacesError::MacMismatch(format!(
            "expected exactly 1 inner list tagged {:?}, found {}",
            profile.as_str(),
            matches.len()
        )));
    }
    let (label, components, params) = matches.pop().unwrap();
    if components.len() != 1
        || components[0].bare != SfBare::String(profile.as_str().to_string())
        || components[0].parameters.len() != 1
        || components[0].parameters[0].0 != "sf"
        || components[0].parameters[0].1 != SfBare::Boolean(true)
    {
        return Err(SpacesError::MacMismatch(
            "tagged MAC inner list must cover exactly (\"<profile>\";sf)".into(),
        ));
    }
    if let Some(alg) = find_param(&params, "alg") {
        if alg != &SfBare::String("hmac-sha256".to_string()) {
            return Err(SpacesError::MacMismatch(
                "unsupported Space MAC alg parameter".into(),
            ));
        }
    }
    Ok((label, components, params))
}

fn compute_hmac_sha256(key: &[u8; 32], message: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| SpacesError::MacMismatch(format!("HMAC init failed: {e}")))?;
    mac.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

fn get_required_ascii_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.is_empty() {
        return Err(SpacesError::MacMismatch(format!("missing {name} header")));
    }
    if values.len() > 1 {
        return Err(SpacesError::MacMismatch(format!(
            "multiple {name} header lines are not supported; combine before parsing"
        )));
    }
    values[0]
        .to_str()
        .map_err(|_| SpacesError::MacMismatch(format!("non-ASCII {name} header")))
}

fn validate_sf_string(value: &str, name: &str) -> Result<()> {
    if value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        Ok(())
    } else {
        Err(SpacesError::MacMismatch(format!(
            "invalid structured-field string in {name}"
        )))
    }
}

fn validate_sf_key(key: &str) -> Result<()> {
    let bytes = key.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err(SpacesError::MacMismatch(
            "empty structured-field key".into(),
        ));
    };
    if !(first == b'*' || first.is_ascii_lowercase()) {
        return Err(SpacesError::MacMismatch(format!(
            "invalid structured-field key: {key}"
        )));
    }
    if bytes[1..].iter().all(|&b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*')
    }) {
        Ok(())
    } else {
        Err(SpacesError::MacMismatch(format!(
            "invalid structured-field key: {key}"
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SfBare {
    String(String),
    Integer(i64),
    Bytes(Vec<u8>),
    Boolean(bool),
    Token(String),
}

impl SfBare {
    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }
}

type SfParameters = Vec<(String, SfBare)>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SfItem {
    bare: SfBare,
    parameters: SfParameters,
}

impl SfItem {
    fn bare(bare: SfBare) -> Self {
        Self {
            bare,
            parameters: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SfMember {
    Item(SfItem),
    InnerList(Vec<SfItem>, SfParameters),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SfDictionary {
    members: Vec<(String, SfMember)>,
}

impl SfDictionary {
    fn member(&self, key: &str) -> Option<&SfMember> {
        self.members.iter().find(|(k, _)| k == key).map(|(_, m)| m)
    }

    fn bare(&self, key: &str) -> Option<&SfBare> {
        match self.member(key)? {
            SfMember::Item(item) if item.parameters.is_empty() => Some(&item.bare),
            SfMember::Item(item) => Some(&item.bare),
            SfMember::InnerList(_, _) => None,
        }
    }
}

fn find_param<'a>(params: &'a SfParameters, name: &str) -> Option<&'a SfBare> {
    params.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn serialize_dictionary(dict: &SfDictionary) -> String {
    dict.members
        .iter()
        .map(|(key, member)| match member {
            SfMember::Item(item) if item.bare == SfBare::Boolean(true) => {
                format!("{key}{}", serialize_parameters(&item.parameters))
            }
            _ => format!("{key}={}", serialize_member(member)),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn serialize_member(member: &SfMember) -> String {
    match member {
        SfMember::Item(item) => serialize_item(item),
        SfMember::InnerList(items, params) => {
            let inner = items
                .iter()
                .map(serialize_item)
                .collect::<Vec<_>>()
                .join(" ");
            format!("({inner}){}", serialize_parameters(params))
        }
    }
}

fn serialize_item(item: &SfItem) -> String {
    format!(
        "{}{}",
        serialize_bare(&item.bare),
        serialize_parameters(&item.parameters)
    )
}

fn serialize_parameters(params: &SfParameters) -> String {
    let mut out = String::new();
    for (name, val) in params {
        if val == &SfBare::Boolean(true) {
            out.push(';');
            out.push_str(name);
        } else {
            out.push(';');
            out.push_str(name);
            out.push('=');
            out.push_str(&serialize_bare(val));
        }
    }
    out
}

fn serialize_bare(bare: &SfBare) -> String {
    match bare {
        SfBare::String(s) => {
            let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        SfBare::Integer(n) => n.to_string(),
        SfBare::Bytes(b) => format!(":{}:", BASE64_STANDARD.encode(b)),
        SfBare::Boolean(b) => {
            if *b {
                "?1".to_string()
            } else {
                "?0".to_string()
            }
        }
        SfBare::Token(t) => t.clone(),
    }
}

fn parse_sf_dictionary(header: &str) -> Result<SfDictionary> {
    if header.len() > MAX_STRUCTURED_HEADER_BYTES {
        return Err(SpacesError::MacMismatch(
            "structured header exceeds 8192-byte limit".into(),
        ));
    }
    let mut parser = SfParser {
        bytes: header.as_bytes(),
        index: 0,
    };
    parser.dictionary()
}

struct SfParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> SfParser<'a> {
    fn current(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn dictionary(&mut self) -> Result<SfDictionary> {
        let mut members: Vec<(String, SfMember)> = Vec::new();
        self.ows();
        if self.current().is_none() {
            return Err(SpacesError::MacMismatch(
                "empty structured dictionary header".into(),
            ));
        }
        loop {
            let name = self.key()?;
            if members.iter().any(|(k, _)| k == &name) {
                return Err(SpacesError::MacMismatch(format!(
                    "duplicate structured dictionary key {name:?}"
                )));
            }
            let parsed_member = if self.current() == Some(b'=') {
                self.index += 1;
                self.member()?
            } else {
                SfMember::Item(SfItem {
                    bare: SfBare::Boolean(true),
                    parameters: self.parameters()?,
                })
            };
            members.push((name, parsed_member));
            self.ows();
            if self.current().is_none() {
                break;
            }
            self.take(b',')?;
            self.ows();
            if self.current().is_none() {
                return Err(SpacesError::MacMismatch(
                    "trailing comma in structured dictionary".into(),
                ));
            }
        }
        Ok(SfDictionary { members })
    }

    fn member(&mut self) -> Result<SfMember> {
        if self.current() == Some(b'(') {
            self.index += 1;
            let mut items = Vec::new();
            loop {
                while self.current() == Some(b' ') {
                    self.index += 1;
                }
                if self.current() == Some(b')') {
                    self.index += 1;
                    let params = self.parameters()?;
                    return Ok(SfMember::InnerList(items, params));
                }
                if !items.is_empty() && self.bytes.get(self.index.wrapping_sub(1)) != Some(&b' ') {
                    return Err(SpacesError::MacMismatch(
                        "missing space separator in structured inner list".into(),
                    ));
                }
                items.push(self.item()?);
                if !matches!(self.current(), Some(b' ') | Some(b')')) {
                    return Err(SpacesError::MacMismatch(
                        "unterminated structured inner list".into(),
                    ));
                }
            }
        }
        Ok(SfMember::Item(self.item()?))
    }

    fn item(&mut self) -> Result<SfItem> {
        let bare = self.bare()?;
        let parameters = self.parameters()?;
        Ok(SfItem { bare, parameters })
    }

    fn parameters(&mut self) -> Result<SfParameters> {
        let mut params: SfParameters = Vec::new();
        while self.current() == Some(b';') {
            self.index += 1;
            while self.current() == Some(b' ') {
                self.index += 1;
            }
            let name = self.key()?;
            if params.iter().any(|(k, _)| k == &name) {
                return Err(SpacesError::MacMismatch(format!(
                    "duplicate structured parameter {name:?}"
                )));
            }
            let val = if self.current() == Some(b'=') {
                self.index += 1;
                self.bare()?
            } else {
                SfBare::Boolean(true)
            };
            params.push((name, val));
        }
        Ok(params)
    }

    fn bare(&mut self) -> Result<SfBare> {
        let Some(byte) = self.current() else {
            return Err(SpacesError::MacMismatch(
                "unexpected EOF in structured item".into(),
            ));
        };
        match byte {
            b'"' => self.string(),
            b':' => self.byte_sequence(),
            b'?' => {
                self.index += 1;
                let Some(flag) = self.current() else {
                    return Err(SpacesError::MacMismatch("truncated boolean".into()));
                };
                if flag != b'0' && flag != b'1' {
                    return Err(SpacesError::MacMismatch("invalid boolean".into()));
                }
                self.index += 1;
                Ok(SfBare::Boolean(flag == b'1'))
            }
            b'-' | b'0'..=b'9' => self.integer(),
            _ => self.token(),
        }
    }

    fn string(&mut self) -> Result<SfBare> {
        self.take(b'"')?;
        let mut out = Vec::new();
        while let Some(b) = self.current() {
            if b == b'"' {
                break;
            }
            self.index += 1;
            if b == b'\\' {
                let Some(esc) = self.current() else {
                    return Err(SpacesError::MacMismatch(
                        "unterminated string escape".into(),
                    ));
                };
                if esc != b'"' && esc != b'\\' {
                    return Err(SpacesError::MacMismatch(
                        "invalid escape in structured string".into(),
                    ));
                }
                out.push(esc);
                self.index += 1;
            } else if (0x20..=0x7e).contains(&b) {
                out.push(b);
            } else {
                return Err(SpacesError::MacMismatch(
                    "control character in structured string".into(),
                ));
            }
        }
        self.take(b'"')?;
        let s = String::from_utf8(out)
            .map_err(|_| SpacesError::MacMismatch("non-UTF-8 structured string".into()))?;
        Ok(SfBare::String(s))
    }

    fn byte_sequence(&mut self) -> Result<SfBare> {
        self.take(b':')?;
        let start = self.index;
        while let Some(b) = self.current() {
            if b == b':' {
                break;
            }
            if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
                return Err(SpacesError::MacMismatch(
                    "invalid character in structured byte sequence".into(),
                ));
            }
            self.index += 1;
        }
        let mut encoded = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SpacesError::MacMismatch("non-ASCII base64".into()))?
            .to_string();
        while encoded.len() % 4 != 0 {
            encoded.push('=');
        }
        self.take(b':')?;
        let data = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| SpacesError::MacMismatch(format!("invalid base64 byte sequence: {e}")))?;
        Ok(SfBare::Bytes(data))
    }

    fn integer(&mut self) -> Result<SfBare> {
        let start = self.index;
        if self.current() == Some(b'-') {
            self.index += 1;
        }
        let digits = self.index;
        while matches!(self.current(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
        let digit_len = self.index - digits;
        if digit_len == 0 || digit_len > 15 {
            return Err(SpacesError::MacMismatch(
                "invalid structured integer length".into(),
            ));
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SpacesError::MacMismatch("non-ASCII integer".into()))?;
        let val: i64 = raw
            .parse()
            .map_err(|_| SpacesError::MacMismatch("invalid structured integer".into()))?;
        Ok(SfBare::Integer(val))
    }

    fn token(&mut self) -> Result<SfBare> {
        let start = self.index;
        let Some(first) = self.current() else {
            return Err(SpacesError::MacMismatch("empty token".into()));
        };
        if !(first == b'*' || first.is_ascii_alphabetic()) {
            return Err(SpacesError::MacMismatch("invalid token start".into()));
        }
        self.index += 1;
        while let Some(b) = self.current() {
            if b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&b) {
                self.index += 1;
            } else {
                break;
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SpacesError::MacMismatch("non-ASCII token".into()))?;
        Ok(SfBare::Token(raw.to_string()))
    }

    fn key(&mut self) -> Result<String> {
        let start = self.index;
        let Some(first) = self.current() else {
            return Err(SpacesError::MacMismatch("missing key".into()));
        };
        if !(first == b'*' || first.is_ascii_lowercase()) {
            return Err(SpacesError::MacMismatch("invalid key start".into()));
        }
        self.index += 1;
        while let Some(b) = self.current() {
            if b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'-' | b'.' | b'*')
            {
                self.index += 1;
            } else {
                break;
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SpacesError::MacMismatch("non-ASCII key".into()))?;
        Ok(raw.to_string())
    }

    fn ows(&mut self) {
        while matches!(self.current(), Some(b' ') | Some(b'\t')) {
            self.index += 1;
        }
    }

    fn take(&mut self, expected: u8) -> Result<()> {
        if self.current() == Some(expected) {
            self.index += 1;
            Ok(())
        } else {
            Err(SpacesError::MacMismatch(format!(
                "expected {:?} in structured header",
                expected as char
            )))
        }
    }
}
