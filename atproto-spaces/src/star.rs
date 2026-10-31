//! `STAR-lite` (`[0x2a, 0x6c, 0x01, 0x00]`) Space repository archive reader and writer.
//!
//! Format (`atproto#5187` / `SpaceSTARCodec`):
//! - 4-byte magic `[0x2a, 0x6c, 0x01, 0x00]`
//! - LEB128-framed canonical DAG-CBOR metadata map:
//!   `{"$type": "atproto-space-repo", "ver": 1, "repo": <did>, "space": <uri>, "rev": <tid>, "data": <bytes32>}`
//! - Zero or more strictly ascending byte-lexicographic `(path_utf8_frame, record_dagcbor_frame)` pairs.

use crate::lthash::compute_dagcbor_cid;
use crate::{is_valid_nsid, is_valid_rkey, Result, SpacesError};
use cid::Cid;
use serde::{Deserialize, Serialize};

pub const STAR_LITE_MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
pub const STAR_METADATA_TYPE: &str = "atproto-space-repo";
pub const MAX_STAR_FRAME_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_STAR_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarRecordEntry {
    pub path: String,
    pub record_dagcbor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStarRecord {
    pub path: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Cid,
    pub record_dagcbor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarCommitMetadata {
    pub space: String,
    pub repo: String,
    pub rev: String,
    pub data: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStarRepo {
    pub space: String,
    pub repo: String,
    pub rev: String,
    pub data: [u8; 32],
    pub records: Vec<VerifiedStarRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StarMetadata<'a> {
    #[serde(rename = "$type")]
    record_type: String,
    ver: u64,
    repo: String,
    space: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    data: &'a [u8],
}

#[derive(Debug, Deserialize)]
struct StarMetadataOwned {
    #[serde(rename = "$type")]
    record_type: String,
    ver: u64,
    repo: String,
    space: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

/// Serialize a canonical `STAR-lite` repository archive.
/// Entries MUST already be in strictly ascending UTF-8 byte-lexicographic order by `path`.
pub fn write_star_repo(
    space: &str,
    repo: &str,
    rev: &str,
    data: &[u8; 32],
    entries: &[StarRecordEntry],
) -> Result<Vec<u8>> {
    if space.is_empty() || repo.is_empty() || rev.is_empty() {
        return Err(SpacesError::StarFormat(
            "space, repo, and rev must be non-empty".into(),
        ));
    }
    let meta = StarMetadata {
        record_type: STAR_METADATA_TYPE.to_string(),
        ver: 1,
        repo: repo.to_string(),
        space: space.to_string(),
        rev: rev.to_string(),
        data: data.as_slice(),
    };
    let meta_bytes = serde_ipld_dagcbor::to_vec(&meta)
        .map_err(|e| SpacesError::StarFormat(format!("encode STAR metadata: {e}")))?;

    let mut out = Vec::new();
    out.extend_from_slice(&STAR_LITE_MAGIC);
    write_varint_frame(&mut out, &meta_bytes);

    let mut prev_path: Option<&[u8]> = None;
    for entry in entries {
        validate_record_path(&entry.path)?;
        if let Some(prev) = prev_path {
            if entry.path.as_bytes() <= prev {
                return Err(SpacesError::StarFormat(format!(
                    "STAR entries must be strictly sorted by UTF-8 path bytes: {:?} <= {:?}",
                    entry.path,
                    String::from_utf8_lossy(prev)
                )));
            }
        }
        validate_canonical_dagcbor_record(&entry.record_dagcbor)?;
        prev_path = Some(entry.path.as_bytes());
        write_varint_frame(&mut out, entry.path.as_bytes());
        write_varint_frame(&mut out, &entry.record_dagcbor);
    }

    Ok(out)
}

/// Parse and validate ONLY the leading `STAR-lite` metadata frame (`<= 64 KiB`) without
/// deserializing any record frames, allowing callers to verify `Atproto-Space-Mac` FIRST.
pub fn read_star_metadata(
    bytes: &[u8],
    expected_space: &str,
    expected_repo: &str,
) -> Result<StarCommitMetadata> {
    let (meta, _) = read_star_metadata_with_cursor(bytes, expected_space, expected_repo)?;
    Ok(meta)
}

fn read_star_metadata_with_cursor<'a>(
    bytes: &'a [u8],
    expected_space: &str,
    expected_repo: &str,
) -> Result<(StarCommitMetadata, &'a [u8])> {
    if bytes.len() < 4 || bytes.len() > MAX_STAR_ARCHIVE_BYTES {
        return Err(SpacesError::StarFormat(
            "truncated or oversized STAR-lite archive".into(),
        ));
    }
    if bytes[..4] != STAR_LITE_MAGIC {
        return Err(SpacesError::StarFormat(
            "invalid STAR-lite magic header".into(),
        ));
    }
    let mut cursor = &bytes[4..];
    let meta_frame = read_varint_frame(&mut cursor)?;
    if meta_frame.len() > 64 * 1024 {
        return Err(SpacesError::StarFormat(
            "STAR-lite metadata frame exceeds 64 KiB".into(),
        ));
    }
    validate_no_cbor_floats_and_canonical(meta_frame, true)?;

    let meta: StarMetadataOwned = serde_ipld_dagcbor::from_slice(meta_frame)
        .map_err(|e| SpacesError::StarFormat(format!("invalid STAR metadata DAG-CBOR: {e}")))?;
    if meta.record_type != STAR_METADATA_TYPE || meta.ver != 1 {
        return Err(SpacesError::StarFormat(format!(
            "unexpected STAR metadata $type={} ver={}",
            meta.record_type, meta.ver
        )));
    }
    if meta.space != expected_space {
        return Err(SpacesError::StarFormat(format!(
            "STAR metadata space {:?} != expected {:?}",
            meta.space, expected_space
        )));
    }
    if meta.repo != expected_repo {
        return Err(SpacesError::StarFormat(format!(
            "STAR metadata repo {:?} != expected {:?}",
            meta.repo, expected_repo
        )));
    }
    if meta.rev.is_empty() {
        return Err(SpacesError::StarFormat("empty rev in STAR metadata".into()));
    }
    let data: [u8; 32] = meta
        .data
        .as_slice()
        .try_into()
        .map_err(|_| SpacesError::StarFormat("STAR metadata data must be 32 bytes".into()))?;

    // Verify metadata map had no extra unknown keys and was encoded in canonical DAG-CBOR key order
    let reencoded = serde_ipld_dagcbor::to_vec(&StarMetadata {
        record_type: meta.record_type,
        ver: meta.ver,
        repo: meta.repo.clone(),
        space: meta.space.clone(),
        rev: meta.rev.clone(),
        data: &data,
    })
    .map_err(|e| SpacesError::StarFormat(format!("re-encode metadata: {e}")))?;
    if reencoded.as_slice() != meta_frame {
        return Err(SpacesError::StarFormat(
            "non-canonical or unknown-key STAR metadata DAG-CBOR".into(),
        ));
    }

    Ok((
        StarCommitMetadata {
            space: meta.space,
            repo: meta.repo,
            rev: meta.rev,
            data,
        },
        cursor,
    ))
}

/// Parse and structurally validate a `STAR-lite` archive against `(expected_space, expected_repo)`.
/// Note: Callers MUST verify `Atproto-Space-Mac` (e.g. via `read_star_metadata`) and compare `LtHash` commitment against `parsed.data`!
pub fn read_star_repo(
    bytes: &[u8],
    expected_space: &str,
    expected_repo: &str,
) -> Result<ParsedStarRepo> {
    let (meta, mut cursor) = read_star_metadata_with_cursor(bytes, expected_space, expected_repo)?;
    let data = meta.data;

    let mut records = Vec::new();
    let mut prev_path: Option<String> = None;

    while !cursor.is_empty() {
        let path_bytes = read_varint_frame(&mut cursor)?;
        if cursor.is_empty() {
            return Err(SpacesError::StarFormat(
                "dangling path frame without record frame in STAR-lite".into(),
            ));
        }
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| SpacesError::StarFormat("non-UTF-8 record path in STAR-lite".into()))?;
        let (collection, rkey) = validate_record_path(path)?;
        if let Some(prev) = &prev_path {
            if path.as_bytes() <= prev.as_bytes() {
                return Err(SpacesError::StarFormat(format!(
                    "STAR-lite paths out of strict byte-lexicographic order: {path:?} <= {prev:?}"
                )));
            }
        }
        prev_path = Some(path.to_string());

        let record_bytes = read_varint_frame(&mut cursor)?;
        validate_canonical_dagcbor_record(record_bytes)?;
        let cid = compute_dagcbor_cid(record_bytes);
        records.push(VerifiedStarRecord {
            path: path.to_string(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid,
            record_dagcbor: record_bytes.to_vec(),
        });
    }

    Ok(ParsedStarRepo {
        space: meta.space,
        repo: meta.repo,
        rev: meta.rev,
        data,
        records,
    })
}

fn validate_record_path(path: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 2 || !is_valid_nsid(parts[0]) || !is_valid_rkey(parts[1]) {
        return Err(SpacesError::StarFormat(format!(
            "invalid Space record path: {path:?}"
        )));
    }
    Ok((parts[0], parts[1]))
}

pub fn validate_canonical_dagcbor_record(bytes: &[u8]) -> Result<()> {
    validate_no_cbor_floats_and_canonical(bytes, true)
}

fn validate_no_cbor_floats_and_canonical(bytes: &[u8], require_map_root: bool) -> Result<()> {
    if bytes.is_empty() {
        return Err(SpacesError::StarFormat("empty DAG-CBOR frame".into()));
    }
    let mut reader = bytes;
    let cbor_val: ciborium::Value = ciborium::from_reader(&mut reader)
        .map_err(|e| SpacesError::StarFormat(format!("CBOR parse error: {e}")))?;
    if !reader.is_empty() {
        return Err(SpacesError::StarFormat(
            "trailing bytes inside DAG-CBOR frame".into(),
        ));
    }
    if require_map_root && !matches!(cbor_val, ciborium::Value::Map(_)) {
        return Err(SpacesError::StarFormat(
            "DAG-CBOR root must be a map".into(),
        ));
    }
    reject_cbor_floats(&cbor_val, 0)?;

    let ipld: ipld_core::ipld::Ipld = serde_ipld_dagcbor::from_slice(bytes)
        .map_err(|e| SpacesError::StarFormat(format!("DAG-CBOR strict decode failed: {e}")))?;
    let canonical = serde_ipld_dagcbor::to_vec(&ipld)
        .map_err(|e| SpacesError::StarFormat(format!("DAG-CBOR canonical encode failed: {e}")))?;
    if canonical.as_slice() != bytes {
        return Err(SpacesError::StarFormat(
            "non-canonical DAG-CBOR encoding".into(),
        ));
    }
    Ok(())
}

fn reject_cbor_floats(val: &ciborium::Value, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(SpacesError::StarFormat(
            "DAG-CBOR nesting depth exceeds 64".into(),
        ));
    }
    match val {
        ciborium::Value::Float(_) => Err(SpacesError::StarFormat(
            "floating-point values are forbidden in ATProto DAG-CBOR".into(),
        )),
        ciborium::Value::Array(items) => {
            for item in items {
                reject_cbor_floats(item, depth + 1)?;
            }
            Ok(())
        }
        ciborium::Value::Map(entries) => {
            for (k, v) in entries {
                if !matches!(k, ciborium::Value::Text(_)) {
                    return Err(SpacesError::StarFormat(
                        "DAG-CBOR map keys must be strings".into(),
                    ));
                }
                reject_cbor_floats(v, depth + 1)?;
            }
            Ok(())
        }
        ciborium::Value::Tag(tag, inner) => {
            if *tag != 42 {
                return Err(SpacesError::StarFormat(format!(
                    "unsupported CBOR tag {tag} (only CID tag 42 allowed)"
                )));
            }
            reject_cbor_floats(inner, depth + 1)
        }
        _ => Ok(()),
    }
}

fn write_varint_frame(out: &mut Vec<u8>, payload: &[u8]) {
    let mut n = payload.len();
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(payload);
}

fn read_varint_frame<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    let mut len: usize = 0;
    let mut shift = 0u32;
    let mut idx = 0usize;
    loop {
        if idx >= cursor.len() || idx >= 9 {
            return Err(SpacesError::StarFormat(
                "truncated or overflowed LEB128 varint".into(),
            ));
        }
        let byte = cursor[idx];
        idx += 1;
        if idx > 1 && byte == 0 {
            return Err(SpacesError::StarFormat(
                "non-minimal LEB128 varint encoding".into(),
            ));
        }
        len |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if len > MAX_STAR_FRAME_BYTES {
        return Err(SpacesError::StarFormat(format!(
            "STAR-lite frame length {len} exceeds {MAX_STAR_FRAME_BYTES}"
        )));
    }
    let after_varint = &cursor[idx..];
    if after_varint.len() < len {
        return Err(SpacesError::StarFormat(
            "STAR-lite frame truncated before declared length".into(),
        ));
    }
    let frame = &after_varint[..len];
    *cursor = &after_varint[len..];
    Ok(frame)
}
