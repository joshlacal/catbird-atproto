//! Homomorphic set hash (`LtHash`) for ATProto Spaces (`atproto#5187` / Proposal 0016).
//!
//! 1,024 little-endian `u16` lanes (`2,048` bytes total). Each record contributes
//! `BLAKE3_XOF_2048("{collection}/{rkey}/{cid}")` added lane-wise mod `2^16`.
//! The 32-byte commit `data` digest is `SHA-256(state_bytes)`.

use crate::{Result, SpacesError};
use cid::Cid;
use multihash::Multihash;
use sha2::{Digest, Sha256};

pub const LTHASH_LANES: usize = 1024;
pub const LTHASH_BYTES: usize = LTHASH_LANES * 2;
pub const LTHASH_COMMITMENT_BYTES: usize = 32;

const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_MULTIHASH: u64 = 0x12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtHash {
    lanes: [u16; LTHASH_LANES],
}

impl Default for LtHash {
    fn default() -> Self {
        Self::empty()
    }
}

impl LtHash {
    pub const fn empty() -> Self {
        Self {
            lanes: [0u16; LTHASH_LANES],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != LTHASH_BYTES {
            return Err(SpacesError::SetHashMismatch(format!(
                "expected {LTHASH_BYTES}-byte LtHash state, got {}",
                bytes.len()
            )));
        }
        let mut lanes = [0u16; LTHASH_LANES];
        for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
            lanes[i] = u16::from_le_bytes(*chunk);
        }
        Ok(Self { lanes })
    }

    /// Add a 2,048-byte element hash (`compute_record_element_hash(...)`) into the state.
    pub fn add(&mut self, entry_bytes: &[u8]) {
        assert_eq!(
            entry_bytes.len(),
            LTHASH_BYTES,
            "LtHash::add requires {LTHASH_BYTES} element bytes"
        );
        for (lane, chunk) in self.lanes.iter_mut().zip(entry_bytes.as_chunks::<2>().0) {
            let rhs = u16::from_le_bytes(*chunk);
            *lane = lane.wrapping_add(rhs);
        }
    }

    /// Remove a 2,048-byte element hash (`compute_record_element_hash(...)`) from the state.
    pub fn remove(&mut self, entry_bytes: &[u8]) {
        assert_eq!(
            entry_bytes.len(),
            LTHASH_BYTES,
            "LtHash::remove requires {LTHASH_BYTES} element bytes"
        );
        for (lane, chunk) in self.lanes.iter_mut().zip(entry_bytes.as_chunks::<2>().0) {
            let rhs = u16::from_le_bytes(*chunk);
            *lane = lane.wrapping_sub(rhs);
        }
    }

    /// Add a record directly by `(collection, rkey, cid)`.
    pub fn add_record(&mut self, collection: &str, rkey: &str, cid: &Cid) {
        let elem = compute_record_element_hash(collection, rkey, cid);
        self.add(&elem);
    }

    /// Add one canonical Space writer-inventory entry.
    pub fn add_inventory_entry(
        &mut self,
        did: &str,
        repo_rev: &str,
        space_rev: &str,
        data_32: &[u8; LTHASH_COMMITMENT_BYTES],
    ) -> Result<()> {
        self.add(&compute_inventory_element_hash(
            did, repo_rev, space_rev, data_32,
        )?);
        Ok(())
    }

    /// Remove a record directly by `(collection, rkey, cid)`.
    pub fn remove_record(&mut self, collection: &str, rkey: &str, cid: &Cid) {
        let elem = compute_record_element_hash(collection, rkey, cid);
        self.remove(&elem);
    }

    /// Raw 2,048-byte little-endian lane checksum.
    pub fn checksum(&self) -> [u8; LTHASH_BYTES] {
        let mut out = [0u8; LTHASH_BYTES];
        for (i, &lane) in self.lanes.iter().enumerate() {
            let le = lane.to_le_bytes();
            out[i * 2] = le[0];
            out[i * 2 + 1] = le[1];
        }
        out
    }

    /// 32-byte `SHA-256(checksum)` commit `data` digest used in Space commits and `STAR-lite`.
    pub fn commitment(&self) -> [u8; LTHASH_COMMITMENT_BYTES] {
        let state = self.checksum();
        let digest = Sha256::digest(state);
        let mut out = [0u8; LTHASH_COMMITMENT_BYTES];
        out.copy_from_slice(&digest);
        out
    }
}

/// Compute the 2,048-byte `BLAKE3` XOF element hash for `"{collection}/{rkey}/{cid}"`.
pub fn compute_record_element_hash(collection: &str, rkey: &str, cid: &Cid) -> [u8; LTHASH_BYTES] {
    let key = format!("{collection}/{rkey}/{cid}");
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    let mut out = [0u8; LTHASH_BYTES];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Domain-separated canonical element hash for one writer-inventory row.
///
/// Each text field is UTF-8 prefixed by its big-endian `u16` byte length,
/// followed by the exact 32-byte repository LtHash commitment. The enclosing
/// [`LtHash`] makes the full inventory a set commitment, while callers still
/// enforce canonical DID order and uniqueness on the paged wire.
pub fn compute_inventory_element_hash(
    did: &str,
    repo_rev: &str,
    space_rev: &str,
    data_32: &[u8; LTHASH_COMMITMENT_BYTES],
) -> Result<[u8; LTHASH_BYTES]> {
    const DOMAIN: &[u8] = b"atproto-space-writer-inventory-v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    for (name, value) in [
        ("did", did.as_bytes()),
        ("repoRev", repo_rev.as_bytes()),
        ("spaceRev", space_rev.as_bytes()),
    ] {
        let len = u16::try_from(value.len()).map_err(|_| {
            SpacesError::SetHashMismatch(format!("inventory {name} exceeds 65535 bytes"))
        })?;
        hasher.update(&len.to_be_bytes());
        hasher.update(value);
    }
    hasher.update(data_32);
    let mut out = [0u8; LTHASH_BYTES];
    hasher.finalize_xof().fill(&mut out);
    Ok(out)
}

/// Compute CIDv1 (`dag-cbor` `0x71`, `sha2-256` `0x12`) over canonical DAG-CBOR bytes.
pub fn compute_dagcbor_cid(dagcbor_bytes: &[u8]) -> Cid {
    let digest = Sha256::digest(dagcbor_bytes);
    let mh = Multihash::<64>::wrap(SHA2_256_MULTIHASH, &digest)
        .expect("32-byte SHA-256 digest always fits 64-byte Multihash");
    Cid::new_v1(DAG_CBOR_CODEC, mh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_commitment_is_order_independent_and_binds_every_field() {
        let rows = [
            ("did:plc:alice", "3m2aaaaaaaaa2", "3m2aaaaaaaab2", [1; 32]),
            ("did:plc:bob", "3m2aaaaaaaac2", "3m2aaaaaaaad2", [2; 32]),
        ];
        let commitment = |rows: &[(&str, &str, &str, [u8; 32])]| {
            let mut hash = LtHash::empty();
            for (did, repo_rev, space_rev, data) in rows {
                hash.add_inventory_entry(did, repo_rev, space_rev, data)
                    .unwrap();
            }
            hash.commitment()
        };
        let mut reversed = rows;
        reversed.reverse();
        assert_eq!(commitment(&rows), commitment(&reversed));

        let mut changed = rows;
        changed[1].3[0] ^= 1;
        assert_ne!(commitment(&rows), commitment(&changed));
    }
}
