//! `Atproto-Space-Mac` commit (`atproto-space-repo`) and record (`atproto-space-record`) authenticators.

use crate::{Result, SpacesError};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const SPACE_MAC_HEADER_NAME: &str = "atproto-space-mac";
pub const SPACE_WANT_MAC_HEADER_NAME: &str = "atproto-space-want-mac";
pub const COMMIT_MAC_TYPE: &str = "atproto-space-repo";
pub const RECORD_MAC_TYPE: &str = "atproto-space-record";
pub const COMMIT_MAC_DOMAIN: &[u8] = b"atproto-space-repo-v1";
pub const RECORD_MAC_DOMAIN: &[u8] = b"atproto-space-record-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpaceMacHeader {
    pub mac_type: String,
    pub ver: u64,
    pub mac: [u8; 32],
}

/// Compute 32-byte commit MAC:
/// `HMAC-SHA256(shared_secret, "atproto-space-repo-v1" || u16_be(space) || u16_be(repo) || u16_be(rev) || data_32)`
pub fn compute_commit_mac(
    shared_secret: &[u8; 32],
    space: &str,
    repo: &str,
    rev: &str,
    data_32: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(shared_secret)
        .map_err(|e| SpacesError::MacMismatch(format!("HMAC init failed: {e}")))?;
    mac.update(COMMIT_MAC_DOMAIN);
    update_len_prefixed(&mut mac, space.as_bytes(), "space")?;
    update_len_prefixed(&mut mac, repo.as_bytes(), "repo")?;
    update_len_prefixed(&mut mac, rev.as_bytes(), "rev")?;
    mac.update(data_32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// Format an `Atproto-Space-Mac` header value for a Space repo commit.
pub fn format_commit_mac_header(mac: &[u8; 32]) -> String {
    format!(
        "type=\"{COMMIT_MAC_TYPE}\", ver=1, mac=:{}:",
        BASE64_STANDARD.encode(mac)
    )
}

/// Verify an `Atproto-Space-Mac` header on `listRepoOps` / `getRepo` against `(space, repo, rev, data_32)`.
pub fn verify_commit_mac(
    shared_secret: &[u8; 32],
    header_value: &str,
    space: &str,
    repo: &str,
    rev: &str,
    data_32: &[u8; 32],
) -> Result<()> {
    let parsed = parse_space_mac_header(header_value)?;
    if parsed.mac_type != COMMIT_MAC_TYPE || parsed.ver != 1 {
        return Err(SpacesError::MacMismatch(format!(
            "expected type={COMMIT_MAC_TYPE} ver=1, got type={} ver={}",
            parsed.mac_type, parsed.ver
        )));
    }
    let expected = compute_commit_mac(shared_secret, space, repo, rev, data_32)?;
    if bool::from(parsed.mac.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(SpacesError::MacMismatch(
            "commit MAC verification failed".to_string(),
        ))
    }
}

/// Compute 32-byte record MAC:
/// `HMAC-SHA256(shared_secret, "atproto-space-record-v1" || u16_be(uri) || cid_bytes)`
pub fn compute_record_mac(
    shared_secret: &[u8; 32],
    record_uri_with_space_query: &str,
    cid_bytes: &[u8],
) -> Result<[u8; 32]> {
    if cid_bytes.is_empty() {
        return Err(SpacesError::MacMismatch(
            "record CID bytes must not be empty".to_string(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(shared_secret)
        .map_err(|e| SpacesError::MacMismatch(format!("HMAC init failed: {e}")))?;
    mac.update(RECORD_MAC_DOMAIN);
    update_len_prefixed(&mut mac, record_uri_with_space_query.as_bytes(), "uri")?;
    mac.update(cid_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// Format an `Atproto-Space-Mac` header value for a single Space record (`getRecord`).
pub fn format_record_mac_header(mac: &[u8; 32]) -> String {
    format!(
        "type=\"{RECORD_MAC_TYPE}\", ver=1, mac=:{}:",
        BASE64_STANDARD.encode(mac)
    )
}

/// Verify an `Atproto-Space-Mac` header on `getRecord` against `(uri, cid_bytes)`.
pub fn verify_record_mac(
    shared_secret: &[u8; 32],
    header_value: &str,
    record_uri_with_space_query: &str,
    cid_bytes: &[u8],
) -> Result<()> {
    let parsed = parse_space_mac_header(header_value)?;
    if parsed.mac_type != RECORD_MAC_TYPE || parsed.ver != 1 {
        return Err(SpacesError::MacMismatch(format!(
            "expected type={RECORD_MAC_TYPE} ver=1, got type={} ver={}",
            parsed.mac_type, parsed.ver
        )));
    }
    let expected = compute_record_mac(shared_secret, record_uri_with_space_query, cid_bytes)?;
    if bool::from(parsed.mac.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(SpacesError::MacMismatch(
            "record MAC verification failed".to_string(),
        ))
    }
}

/// Parse RFC 8941 structured dictionary `type="...", ver=1, mac=:<b64>:` (up to 4 KiB).
pub fn parse_space_mac_header(header_value: &str) -> Result<ParsedSpaceMacHeader> {
    if header_value.is_empty() || header_value.len() > 4096 {
        return Err(SpacesError::MacMismatch(
            "empty or oversized Atproto-Space-Mac header".to_string(),
        ));
    }

    let mut mac_type: Option<String> = None;
    let mut ver: Option<u64> = None;
    let mut mac_bytes: Option<[u8; 32]> = None;

    for member in header_value.split(',') {
        let member = member.trim_matches([' ', '\t']);
        if member.is_empty() {
            return Err(SpacesError::MacMismatch(
                "empty dictionary member in Atproto-Space-Mac".to_string(),
            ));
        }
        // Strip any member parameters (`;...` outside quotes/colons — none are permitted here)
        let Some((key, raw_val)) = member.split_once('=') else {
            return Err(SpacesError::MacMismatch(format!(
                "malformed Atproto-Space-Mac member: {member}"
            )));
        };
        let key = key.trim_matches([' ', '\t']);
        let raw_val = raw_val.trim_matches([' ', '\t']);
        if raw_val.contains(';') {
            return Err(SpacesError::MacMismatch(
                "unexpected parameters in Atproto-Space-Mac member".to_string(),
            ));
        }
        match key {
            "type" => {
                if mac_type.is_some() {
                    return Err(SpacesError::MacMismatch("duplicate type key".to_string()));
                }
                let unquoted = raw_val
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or_else(|| {
                        SpacesError::MacMismatch("type must be an RFC 8941 string".to_string())
                    })?;
                if unquoted
                    .bytes()
                    .any(|b| b < 0x20 || b == 0x7f || b == b'"' || b == b'\\')
                {
                    return Err(SpacesError::MacMismatch(
                        "invalid characters in type string".to_string(),
                    ));
                }
                mac_type = Some(unquoted.to_string());
            }
            "ver" => {
                if ver.is_some() {
                    return Err(SpacesError::MacMismatch("duplicate ver key".to_string()));
                }
                let parsed_ver: u64 = raw_val
                    .parse()
                    .map_err(|_| SpacesError::MacMismatch("ver must be an integer".to_string()))?;
                ver = Some(parsed_ver);
            }
            "mac" => {
                if mac_bytes.is_some() {
                    return Err(SpacesError::MacMismatch("duplicate mac key".to_string()));
                }
                let b64 = raw_val
                    .strip_prefix(':')
                    .and_then(|s| s.strip_suffix(':'))
                    .ok_or_else(|| {
                        SpacesError::MacMismatch(
                            "mac must be an RFC 8941 byte sequence (:base64:)".to_string(),
                        )
                    })?;
                let decoded = BASE64_STANDARD
                    .decode(b64)
                    .map_err(|e| SpacesError::MacMismatch(format!("invalid mac base64: {e}")))?;
                let arr: [u8; 32] = decoded.try_into().map_err(|_| {
                    SpacesError::MacMismatch("mac must decode to 32 bytes".to_string())
                })?;
                mac_bytes = Some(arr);
            }
            other => {
                return Err(SpacesError::MacMismatch(format!(
                    "unknown Atproto-Space-Mac key: {other}"
                )));
            }
        }
    }

    Ok(ParsedSpaceMacHeader {
        mac_type: mac_type
            .ok_or_else(|| SpacesError::MacMismatch("missing type in Atproto-Space-Mac".into()))?,
        ver: ver
            .ok_or_else(|| SpacesError::MacMismatch("missing ver in Atproto-Space-Mac".into()))?,
        mac: mac_bytes
            .ok_or_else(|| SpacesError::MacMismatch("missing mac in Atproto-Space-Mac".into()))?,
    })
}

fn update_len_prefixed(mac: &mut HmacSha256, bytes: &[u8], field: &str) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| {
        SpacesError::MacMismatch(format!(
            "{field} exceeds u16 length prefix ({} bytes)",
            bytes.len()
        ))
    })?;
    mac.update(&len.to_be_bytes());
    mac.update(bytes);
    Ok(())
}

/// Format `Atproto-Space-Want-Mac` structured header (`type="...", ver=1, key_share="did:key:zDn..."`).
pub fn format_want_mac_header(key_share_did_key: &str, mac_type: &str) -> Result<String> {
    if key_share_did_key.is_empty()
        || !key_share_did_key
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(SpacesError::MacMismatch(
            "invalid key_share for Atproto-Space-Want-Mac".into(),
        ));
    }
    let escaped = key_share_did_key.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        "type=\"{mac_type}\", ver=1, key_share=\"{escaped}\""
    ))
}

/// Parse `Atproto-Space-Want-Mac` structured header and return `key_share` `did:key:zDn...`.
pub fn parse_want_mac_header(header_value: &str, expected_type: &str) -> Result<String> {
    if header_value.is_empty() || header_value.len() > 8192 {
        return Err(SpacesError::MacMismatch(
            "empty or oversized Atproto-Space-Want-Mac header".into(),
        ));
    }
    let mut mac_type: Option<String> = None;
    let mut ver: Option<u64> = None;
    let mut key_share: Option<String> = None;

    for member in header_value.split(',') {
        let member = member.trim_matches([' ', '\t']);
        let Some((k, raw_v)) = member.split_once('=') else {
            return Err(SpacesError::MacMismatch(
                "malformed Atproto-Space-Want-Mac member".into(),
            ));
        };
        let k = k.trim_matches([' ', '\t']);
        let raw_v = raw_v.trim_matches([' ', '\t']);
        match k {
            "type" => {
                let s = raw_v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or_else(|| {
                        SpacesError::MacMismatch("Want-Mac type must be quoted".into())
                    })?;
                mac_type = Some(s.to_string());
            }
            "ver" => {
                ver = Some(raw_v.parse().map_err(|_| {
                    SpacesError::MacMismatch("Want-Mac ver must be integer".into())
                })?);
            }
            "key_share" => {
                let s = raw_v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or_else(|| {
                        SpacesError::MacMismatch("Want-Mac key_share must be quoted".into())
                    })?;
                if s.is_empty() {
                    return Err(SpacesError::MacMismatch("empty key_share".into()));
                }
                key_share = Some(s.to_string());
            }
            _ => {
                return Err(SpacesError::MacMismatch(
                    "unknown key in Atproto-Space-Want-Mac".into(),
                ));
            }
        }
    }

    if mac_type.as_deref() != Some(expected_type) || ver != Some(1) {
        return Err(SpacesError::MacMismatch(
            "Atproto-Space-Want-Mac type or ver mismatch".into(),
        ));
    }
    key_share.ok_or_else(|| SpacesError::MacMismatch("missing key_share".into()))
}
