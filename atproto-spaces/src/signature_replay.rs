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
//! default that [`SpaceHost`](crate::host::SpaceHost) uses. Stores also
//! receive the key the credential is bound to (its `cnf` did:key) so they can
//! bound how many nonces any one credential key holds at a time.
//!
//! Presentations without a `nonce` are not tracked. A nonce is remembered
//! until the first second at which the presentation can no longer verify:
//! `created` plus the maximum signature age, `expires` plus the clock skew,
//! or the credential token's `exp` plus its expiry skew, whichever is first.
//! A presentation that omits both `created` and `expires` is therefore
//! remembered for the rest of its credential's lifetime.

use crate::http_signature::{VerifiedSpaceHeaders, MAX_CLOCK_SKEW_SECS, MAX_SIGNATURE_AGE_SECS};
use crate::tokens::{SpaceTokenClaims, EXPIRY_CLOCK_SKEW_SECS};
use crate::{Result, SpacesError};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

/// Default number of unexpired nonces [`InMemorySignatureReplayCache`] holds.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 65_536;

/// Default number of unexpired nonces [`InMemorySignatureReplayCache`] holds
/// for any one `(issuer, credential key)` pair.
pub const DEFAULT_REPLAY_CACHE_PER_HOLDER: usize = DEFAULT_REPLAY_CACHE_CAPACITY / 16;

/// Storage for `(issuer, nonce)` pairs already presented.
pub trait SignatureReplayStore {
    /// Records `nonce` as presented under `issuer` until `expires_at_sec`
    /// (exclusive, Unix seconds). `holder` is the did:key the credential is
    /// bound to; it is not part of the replay key, but a store may use it to
    /// limit how many nonces one credential key holds.
    ///
    /// Returns [`SpacesError::BadSpaceSignature`] when the pair is already
    /// recorded with an expiry later than `now_sec`, or when the store cannot
    /// record it. A store that cannot record a pair must refuse it.
    fn record_nonce(
        &self,
        issuer: &str,
        holder: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()>;
}

impl<S: SignatureReplayStore + ?Sized> SignatureReplayStore for Arc<S> {
    fn record_nonce(
        &self,
        issuer: &str,
        holder: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        (**self).record_nonce(issuer, holder, nonce, expires_at_sec, now_sec)
    }
}

impl<S: SignatureReplayStore + ?Sized> SignatureReplayStore for Box<S> {
    fn record_nonce(
        &self,
        issuer: &str,
        holder: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        (**self).record_nonce(issuer, holder, nonce, expires_at_sec, now_sec)
    }
}

/// The first Unix second at which a presentation can no longer verify, so
/// its nonce no longer needs to be remembered.
///
/// That is the earliest of `created + MAX_SIGNATURE_AGE_SECS + 1`,
/// `expires + MAX_CLOCK_SKEW_SECS + 1` and
/// `credential_exp + EXPIRY_CLOCK_SKEW_SECS + 1`, counting only the
/// signature parameters that are present.
pub fn replay_window_end(verified: &VerifiedSpaceHeaders, credential_exp: u64) -> u64 {
    let mut end = credential_exp
        .saturating_add(EXPIRY_CLOCK_SKEW_SECS)
        .saturating_add(1);
    if let Some(created) = verified.created {
        end = end.min(
            created
                .saturating_add(MAX_SIGNATURE_AGE_SECS)
                .saturating_add(1),
        );
    }
    if let Some(expires) = verified.expires {
        end = end.min(
            expires
                .saturating_add(MAX_CLOCK_SKEW_SECS)
                .saturating_add(1),
        );
    }
    end
}

/// Records the nonce of a verified presentation under the credential issuer
/// (`credential.iss`), refusing a pair seen before inside its window.
///
/// Call this after the signature and the credential token have both
/// verified, with the token's verified claims, so unauthenticated requests
/// cannot occupy the store. A presentation without a nonce passes unchanged.
pub fn check_presentation_replay<S: SignatureReplayStore + ?Sized>(
    store: &S,
    credential: &SpaceTokenClaims,
    verified: &VerifiedSpaceHeaders,
    now_sec: u64,
) -> Result<()> {
    let Some(nonce) = verified.nonce.as_deref() else {
        return Ok(());
    };
    store.record_nonce(
        &credential.iss,
        &verified.cnf_did_key,
        nonce,
        replay_window_end(verified, credential.exp),
        now_sec,
    )
}

type ReplayKey = [u8; 32];
type HolderKey = [u8; 32];

#[derive(Default)]
struct ReplayEntries {
    by_key: HashMap<ReplayKey, (u64, HolderKey)>,
    by_expiry: BTreeSet<(u64, ReplayKey)>,
    per_holder: HashMap<HolderKey, usize>,
}

impl ReplayEntries {
    fn purge_expired(&mut self, now_sec: u64) {
        while let Some(&(expiry, key)) = self.by_expiry.first() {
            if expiry > now_sec {
                break;
            }
            self.by_expiry.pop_first();
            if let Some((_, holder)) = self.by_key.remove(&key) {
                if let Some(count) = self.per_holder.get_mut(&holder) {
                    *count -= 1;
                    if *count == 0 {
                        self.per_holder.remove(&holder);
                    }
                }
            }
        }
    }
}

/// Bounded in-memory [`SignatureReplayStore`].
///
/// Each entry is a SHA-256 digest of the length-prefixed issuer and the nonce,
/// so memory per entry is fixed whatever the nonce length. Expired entries are
/// dropped on every call. New nonces are refused while one `(issuer, holder)`
/// pair already holds `per_holder` unexpired nonces, or while the cache holds
/// `capacity` in total, until some expire. The per-holder limit keeps one
/// credential key from filling the cache for every other key.
pub struct InMemorySignatureReplayCache {
    capacity: usize,
    per_holder: usize,
    entries: Mutex<ReplayEntries>,
}

impl Default for InMemorySignatureReplayCache {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_REPLAY_CACHE_CAPACITY,
            DEFAULT_REPLAY_CACHE_PER_HOLDER,
        )
    }
}

impl InMemorySignatureReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache holding at most `capacity` unexpired nonces (minimum 1), with a
    /// per-holder limit of `capacity / 16` (minimum 1).
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(capacity, capacity / 16)
    }

    /// A cache holding at most `capacity` unexpired nonces in total and at
    /// most `per_holder` for any one `(issuer, holder)` pair (each minimum 1;
    /// `per_holder` is capped at `capacity`).
    pub fn with_limits(capacity: usize, per_holder: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            per_holder: per_holder.clamp(1, capacity),
            entries: Mutex::new(ReplayEntries::default()),
        }
    }

    /// Number of nonces currently held, including any not yet purged.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_key
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn digest(issuer: &str, second: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update((issuer.len() as u64).to_be_bytes());
        hasher.update(issuer.as_bytes());
        hasher.update(second.as_bytes());
        hasher.finalize().into()
    }
}

impl SignatureReplayStore for InMemorySignatureReplayCache {
    fn record_nonce(
        &self,
        issuer: &str,
        holder: &str,
        nonce: &str,
        expires_at_sec: u64,
        now_sec: u64,
    ) -> Result<()> {
        let key = Self::digest(issuer, nonce);
        let holder_key = Self::digest(issuer, holder);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.purge_expired(now_sec);
        if entries.by_key.contains_key(&key) {
            return Err(SpacesError::BadSpaceSignature(
                "replayed RFC 9421 signature nonce".into(),
            ));
        }
        if expires_at_sec <= now_sec {
            // Outside its window already; the freshness checks govern it.
            return Ok(());
        }
        let held = entries.per_holder.get(&holder_key).copied().unwrap_or(0);
        if held >= self.per_holder {
            return Err(SpacesError::BadSpaceSignature(
                "too many outstanding signature nonces for this credential key".into(),
            ));
        }
        if entries.by_key.len() >= self.capacity {
            return Err(SpacesError::BadSpaceSignature(
                "signature nonce store is full".into(),
            ));
        }
        entries.by_key.insert(key, (expires_at_sec, holder_key));
        entries.by_expiry.insert((expires_at_sec, key));
        *entries.per_holder.entry(holder_key).or_insert(0) += 1;
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
        cache
            .record_nonce("did:web:a", "h", "n1", 110, 100)
            .unwrap();
        assert!(cache
            .record_nonce("did:web:a", "h", "n1", 120, 109)
            .is_err());
        cache
            .record_nonce("did:web:b", "h", "n1", 110, 100)
            .unwrap();
        cache
            .record_nonce("did:web:a", "h", "n2", 110, 100)
            .unwrap();
        // At the window end the entry is gone.
        cache
            .record_nonce("did:web:a", "h", "n1", 220, 110)
            .unwrap();
    }

    #[test]
    fn issuer_and_nonce_are_not_concatenated_ambiguously() {
        let cache = InMemorySignatureReplayCache::new();
        cache
            .record_nonce("did:web:ab", "h", "c", 200, 100)
            .unwrap();
        cache
            .record_nonce("did:web:a", "h", "bc", 200, 100)
            .unwrap();
    }

    #[test]
    fn full_cache_refuses_new_nonces_until_entries_expire() {
        let cache = InMemorySignatureReplayCache::with_limits(2, 2);
        // Three different holders, so only the total limit applies.
        cache.record_nonce("i", "h1", "a", 150, 100).unwrap();
        cache.record_nonce("i", "h2", "b", 200, 100).unwrap();
        let err = cache.record_nonce("i", "h3", "c", 200, 100).unwrap_err();
        assert!(matches!(err, SpacesError::BadSpaceSignature(ref m) if m.contains("full")));
        // Once "a" expires there is room again.
        cache.record_nonce("i", "h3", "c", 300, 150).unwrap();
        assert_eq!(cache.len(), 2);
    }

    fn credential(exp: u64) -> SpaceTokenClaims {
        SpaceTokenClaims {
            iss: "i".into(),
            sub: "at:space/did:web:i/x/y".into(),
            aud: None,
            iat: 0,
            exp,
            jti: "j".into(),
            cnf_kid: None,
        }
    }

    #[test]
    fn one_holder_is_limited_without_blocking_another() {
        let cache = InMemorySignatureReplayCache::with_limits(8, 2);
        cache.record_nonce("i", "key-a", "a1", 200, 100).unwrap();
        cache.record_nonce("i", "key-a", "a2", 150, 100).unwrap();
        let err = cache
            .record_nonce("i", "key-a", "a3", 200, 100)
            .unwrap_err();
        assert!(matches!(err, SpacesError::BadSpaceSignature(ref m) if m.contains("too many")));
        cache.record_nonce("i", "key-b", "b1", 200, 100).unwrap();
        // The same key under another issuer is a separate holder.
        cache.record_nonce("j", "key-a", "a3", 200, 100).unwrap();
        // A replay is still reported as a replay, not as the limit.
        let err = cache
            .record_nonce("i", "key-a", "a1", 200, 101)
            .unwrap_err();
        assert!(matches!(err, SpacesError::BadSpaceSignature(ref m) if m.contains("replayed")));
        // Once "a2" expires key-a has room again.
        cache.record_nonce("i", "key-a", "a3", 300, 150).unwrap();
        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn default_limits_are_consistent() {
        let cache = InMemorySignatureReplayCache::new();
        assert_eq!(cache.capacity, DEFAULT_REPLAY_CACHE_CAPACITY);
        assert_eq!(cache.per_holder, DEFAULT_REPLAY_CACHE_PER_HOLDER);
        let tiny = InMemorySignatureReplayCache::with_capacity(4);
        assert_eq!((tiny.capacity, tiny.per_holder), (4, 1));
        let capped = InMemorySignatureReplayCache::with_limits(2, 10);
        assert_eq!((capped.capacity, capped.per_holder), (2, 2));
    }

    #[test]
    fn window_ends_at_the_first_freshness_bound() {
        let far = 1_000_000;
        assert_eq!(
            replay_window_end(&verified(Some(1_000), None, Some("n")), far),
            1_301
        );
        assert_eq!(
            replay_window_end(&verified(None, None, Some("n")), 5_000),
            5_061
        );
        assert_eq!(
            replay_window_end(&verified(Some(1_000), Some(1_010), Some("n")), far),
            1_041
        );
        assert_eq!(
            replay_window_end(&verified(None, Some(5_000), Some("n")), far),
            5_031
        );
        assert_eq!(
            replay_window_end(&verified(Some(1_000), None, Some("n")), 1_100),
            1_161
        );
    }

    #[test]
    fn presentations_without_nonce_pass_untracked() {
        let cache = InMemorySignatureReplayCache::with_capacity(1);
        for _ in 0..3 {
            check_presentation_replay(
                &cache,
                &credential(1_000),
                &verified(Some(100), None, None),
                100,
            )
            .unwrap();
        }
        assert!(cache.is_empty());
        let nonced = verified(Some(100), None, Some("n"));
        check_presentation_replay(&cache, &credential(1_000), &nonced, 100).unwrap();
        assert!(check_presentation_replay(&cache, &credential(1_000), &nonced, 200).is_err());
    }
}
