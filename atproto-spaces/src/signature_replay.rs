//! Replay tracking for RFC 9421 `atproto-space-credential` signature nonces.
//!
//! [`verify_credential_request`](crate::http_signature::verify_credential_request)
//! is stateless. A verifier that keeps state records each verified `nonce`
//! with [`check_presentation_replay`], keyed on `(credential issuer, nonce)`,
//! for as long as the presentation could still pass the freshness checks.
//! A second presentation of the same pair inside that window is refused.
//!
//! [`SignatureReplayStore`] lets a host supply a store shared between
//! processes. [`InMemorySignatureReplayCache`] is the bounded per-process
//! default that [`SpaceHost`](crate::host::SpaceHost) uses.
//!
//! Presentations without a `nonce` are not tracked. When a nonce-bearing
//! presentation omits `created`, the window is measured from the moment the
//! verifier first saw it, because nothing in the presentation dates it.

use crate::http_signature::{VerifiedSpaceHeaders, MAX_CLOCK_SKEW_SECS, MAX_SIGNATURE_AGE_SECS};
use crate::{Result, SpacesError};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

/// Default number of unexpired nonces [`InMemorySignatureReplayCache`] holds.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 65_536;

/// Storage for `(issuer, nonce)` pairs already presented.
pub trait SignatureReplayStore {
    /// Records `nonce` as presented under `issuer` until `expires_at_sec`
    /// (exclusive, Unix seconds).
    ///
    /// Returns [`SpacesError::BadSpaceSignature`] when the pair is already
    /// recorded with an expiry later than `now_sec`, or when the store cannot
    /// record it. A store that cannot record a pair must refuse it.
    fn record_nonce(
        &self,
        issuer: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()>;
}

impl<S: SignatureReplayStore + ?Sized> SignatureReplayStore for Arc<S> {
    fn record_nonce(
        &self,
        issuer: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        (**self).record_nonce(issuer, nonce, expires_at_sec, now_sec)
    }
}

impl<S: SignatureReplayStore + ?Sized> SignatureReplayStore for Box<S> {
    fn record_nonce(
        &self,
        issuer: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        (**self).record_nonce(issuer, nonce, expires_at_sec, now_sec)
    }
}

/// The first Unix second at which `verified` can no longer pass the freshness
/// checks, so its nonce no longer needs to be remembered.
///
/// With `created`, that is `created + MAX_SIGNATURE_AGE_SECS + 1`; without it,
/// `now_sec + MAX_SIGNATURE_AGE_SECS + MAX_CLOCK_SKEW_SECS`. With `expires`,
/// the window also ends at `expires + MAX_CLOCK_SKEW_SECS + 1`.
pub fn replay_window_end(verified: &VerifiedSpaceHeaders, now_sec: u64) -> u64 {
    let by_created = match verified.created {
        Some(created) => created
            .saturating_add(MAX_SIGNATURE_AGE_SECS)
            .saturating_add(1),
        None => now_sec
            .saturating_add(MAX_SIGNATURE_AGE_SECS)
            .saturating_add(MAX_CLOCK_SKEW_SECS),
    };
    match verified.expires {
        Some(expires) => by_created.min(
            expires
                .saturating_add(MAX_CLOCK_SKEW_SECS)
                .saturating_add(1),
        ),
        None => by_created,
    }
}

/// Records the nonce of a verified presentation under the credential
/// `issuer`, refusing a pair seen before inside its freshness window.
///
/// Call this only after the signature and the credential token have both
/// verified, so unauthenticated requests cannot occupy the store. A
/// presentation without a nonce passes unchanged.
pub fn check_presentation_replay<S: SignatureReplayStore + ?Sized>(
    store: &S,
    issuer: &str,
    verified: &VerifiedSpaceHeaders,
    now_sec: u64,
) -> Result<()> {
    let Some(nonce) = verified.nonce.as_deref() else {
        return Ok(());
    };
    store.record_nonce(issuer, nonce, replay_window_end(verified, now_sec), now_sec)
}

type ReplayKey = [u8; 32];

#[derive(Default)]
struct ReplayEntries {
    expiry_by_key: HashMap<ReplayKey, u64>,
    by_expiry: BTreeSet<(u64, ReplayKey)>,
}

impl ReplayEntries {
    fn purge_expired(&mut self, now_sec: u64) {
        while let Some(&(expiry, key)) = self.by_expiry.first() {
            if expiry > now_sec {
                break;
            }
            self.by_expiry.pop_first();
            self.expiry_by_key.remove(&key);
        }
    }
}

/// Bounded in-memory [`SignatureReplayStore`].
///
/// Each entry is a SHA-256 digest of the length-prefixed issuer and the nonce,
/// so memory per entry is fixed whatever the nonce length. Expired entries are
/// dropped on every call. When `capacity` unexpired entries are held, new
/// nonces are refused until some expire.
pub struct InMemorySignatureReplayCache {
    capacity: usize,
    entries: Mutex<ReplayEntries>,
}

impl Default for InMemorySignatureReplayCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_REPLAY_CACHE_CAPACITY)
    }
}

impl InMemorySignatureReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache holding at most `capacity` unexpired nonces (minimum 1).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(ReplayEntries::default()),
        }
    }

    /// Number of nonces currently held, including any not yet purged.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .expiry_by_key
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn key(issuer: &str, nonce: &str) -> ReplayKey {
        let mut hasher = Sha256::new();
        hasher.update((issuer.len() as u64).to_be_bytes());
        hasher.update(issuer.as_bytes());
        hasher.update(nonce.as_bytes());
        hasher.finalize().into()
    }
}

impl SignatureReplayStore for InMemorySignatureReplayCache {
    fn record_nonce(
        &self,
        issuer: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        let key = Self::key(issuer, nonce);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.purge_expired(now_sec);
        if entries.expiry_by_key.contains_key(&key) {
            return Err(SpacesError::BadSpaceSignature(
                "replayed RFC 9421 signature nonce".into(),
            ));
        }
        if expires_at_sec <= now_sec {
            // Outside its window already; the freshness checks govern it.
            return Ok(());
        }
        if entries.expiry_by_key.len() >= self.capacity {
            return Err(SpacesError::BadSpaceSignature(
                "signature nonce store is full".into(),
            ));
        }
        entries.expiry_by_key.insert(key, expires_at_sec);
        entries.by_expiry.insert((expires_at_sec, key));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified(
        created: Option<u64>,
        expires: Option<u64>,
        nonce: Option<&str>,
    ) -> VerifiedSpaceHeaders {
        VerifiedSpaceHeaders {
            credential_jwt: "a.b.c".into(),
            audience_did: "did:web:host.example.com".into(),
            cnf_did_key: "did:key:z".into(),
            created,
            expires,
            nonce: nonce.map(str::to_string),
        }
    }

    #[test]
    fn same_pair_is_refused_until_its_window_ends() {
        let cache = InMemorySignatureReplayCache::new();
        cache.record_nonce("did:web:a", "n1", 110, 100).unwrap();
        assert!(cache.record_nonce("did:web:a", "n1", 120, 109).is_err());
        cache.record_nonce("did:web:b", "n1", 110, 100).unwrap();
        cache.record_nonce("did:web:a", "n2", 110, 100).unwrap();
        // At the window end the entry is gone.
        cache.record_nonce("did:web:a", "n1", 220, 110).unwrap();
    }

    #[test]
    fn issuer_and_nonce_are_not_concatenated_ambiguously() {
        let cache = InMemorySignatureReplayCache::new();
        cache.record_nonce("did:web:ab", "c", 200, 100).unwrap();
        cache.record_nonce("did:web:a", "bc", 200, 100).unwrap();
    }

    #[test]
    fn full_cache_refuses_new_nonces_until_entries_expire() {
        let cache = InMemorySignatureReplayCache::with_capacity(2);
        cache.record_nonce("i", "a", 150, 100).unwrap();
        cache.record_nonce("i", "b", 200, 100).unwrap();
        let err = cache.record_nonce("i", "c", 200, 100).unwrap_err();
        assert!(matches!(err, SpacesError::BadSpaceSignature(ref m) if m.contains("full")));
        // Once "a" expires there is room again.
        cache.record_nonce("i", "c", 300, 150).unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn window_follows_created_and_expires() {
        assert_eq!(
            replay_window_end(&verified(Some(1_000), None, Some("n")), 1_100),
            1_301
        );
        assert_eq!(
            replay_window_end(&verified(None, None, Some("n")), 1_100),
            1_430
        );
        assert_eq!(
            replay_window_end(&verified(Some(1_000), Some(1_010), Some("n")), 1_005),
            1_041
        );
        assert_eq!(
            replay_window_end(&verified(None, Some(5_000), Some("n")), 1_100),
            1_430
        );
    }

    #[test]
    fn presentations_without_nonce_pass_untracked() {
        let cache = InMemorySignatureReplayCache::with_capacity(1);
        for _ in 0..3 {
            check_presentation_replay(&cache, "i", &verified(Some(100), None, None), 100).unwrap();
        }
        assert!(cache.is_empty());
        check_presentation_replay(&cache, "i", &verified(Some(100), None, Some("n")), 100).unwrap();
        assert!(
            check_presentation_replay(&cache, "i", &verified(Some(100), None, Some("n")), 200)
                .is_err()
        );
    }
}
