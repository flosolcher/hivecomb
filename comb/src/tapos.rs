//! The TaPoS cache: a block reference kept fresh in the background so that signing
//! never waits on the network.
//!
//! # Why this exists
//!
//! A transaction needs a reference to a recent block. Fetching one costs a JSON-RPC
//! round trip, and if that round trip happens inside the signing path then signing is
//! only as fast and as reliable as the slowest node you happen to ask.
//!
//! But a block reference stays usable far longer than a single submit: hived accepts a
//! transaction whose reference is within the last 64 thousand blocks (roughly two
//! days), and the practical constraint is the transaction's own expiration window, not
//! the reference. So one background refresh can serve every signature in between.
//!
//! # The one new failure mode, and how it fails
//!
//! Caching a block reference introduces a risk that fetching it fresh does not: a
//! reference that has aged past usefulness produces a transaction the relay accepts
//! and the chain later rejects. That is a silent failure, which is the kind this crate
//! exists to remove.
//!
//! So the cache **refuses rather than serves stale**. [`TaposCache::block_ref`]
//! returns [`Error::StaleTapos`] once the cached value is older than
//! [`TaposCache::max_age`]. A caller that gets an error can retry, fall back, or fail
//! loudly; a caller that gets a stale reference cannot tell anything is wrong.

use crate::error::{Error, Result};
use crate::transaction::BlockRef;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long a cached block reference stays usable by default.
///
/// Well inside hived's own limit. The bound that matters in practice is that the
/// reference should be newer than the transaction's expiration window, so that a
/// transaction signed now and broadcast a moment later still refers to a block the
/// node has.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy)]
struct Entry {
    block_ref: BlockRef,
    fetched_at: Instant,
}

/// A block reference with an explicit staleness bound.
///
/// Cheap to read and safe to share across threads. Refreshing is the caller's job —
/// this type deliberately owns no transport, so the signing path has no way to
/// accidentally acquire one.
#[derive(Debug)]
pub struct TaposCache {
    entry: Mutex<Option<Entry>>,
    max_age: Duration,
}

impl TaposCache {
    /// A cache with the default staleness bound.
    pub fn new() -> Self {
        Self::with_max_age(DEFAULT_MAX_AGE)
    }

    /// A cache with an explicit staleness bound.
    pub fn with_max_age(max_age: Duration) -> Self {
        TaposCache {
            entry: Mutex::new(None),
            max_age,
        }
    }

    /// The configured staleness bound.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Store a freshly fetched block reference.
    pub fn store(&self, block_ref: BlockRef) {
        let mut guard = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = Some(Entry {
            block_ref,
            fetched_at: Instant::now(),
        });
    }

    /// The cached block reference, if it is still within the staleness bound.
    ///
    /// Returns [`Error::StaleTapos`] rather than a stale value. That is the whole
    /// point of the type.
    pub fn block_ref(&self) -> Result<BlockRef> {
        let guard = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = guard
            .as_ref()
            .ok_or_else(|| Error::StaleTapos("no block reference has been fetched yet".into()))?;
        let age = entry.fetched_at.elapsed();
        if age > self.max_age {
            return Err(Error::StaleTapos(format!(
                "cached block reference is {}s old, limit is {}s",
                age.as_secs(),
                self.max_age.as_secs()
            )));
        }
        Ok(entry.block_ref)
    }

    /// How old the cached reference is, or `None` if nothing is cached.
    pub fn age(&self) -> Option<Duration> {
        let guard = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map(|e| e.fetched_at.elapsed())
    }

    /// Whether a usable reference is available right now.
    pub fn is_fresh(&self) -> bool {
        self.block_ref().is_ok()
    }

    /// Drop the cached reference, forcing the next read to fail until a refresh.
    pub fn invalidate(&self) {
        let mut guard = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = None;
    }
}

impl Default for TaposCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_ref() -> BlockRef {
        BlockRef {
            ref_block_num: 1,
            ref_block_prefix: 2,
            block_num: 3,
        }
    }

    #[test]
    fn an_empty_cache_refuses_rather_than_guessing() {
        let cache = TaposCache::new();
        assert!(!cache.is_fresh());
        assert!(matches!(cache.block_ref(), Err(Error::StaleTapos(_))));
        assert!(cache.age().is_none());
    }

    #[test]
    fn a_stored_reference_is_served() {
        let cache = TaposCache::new();
        cache.store(a_ref());
        assert_eq!(cache.block_ref().unwrap(), a_ref());
        assert!(cache.is_fresh());
        assert!(cache.age().unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn a_stale_reference_is_refused_not_served() {
        // The failure this whole type exists to prevent.
        let cache = TaposCache::with_max_age(Duration::from_nanos(1));
        cache.store(a_ref());
        std::thread::sleep(Duration::from_millis(2));
        match cache.block_ref() {
            Err(Error::StaleTapos(msg)) => assert!(msg.contains("old")),
            other => panic!("expected a staleness refusal, got {other:?}"),
        }
        assert!(!cache.is_fresh());
    }

    #[test]
    fn invalidate_forces_a_refresh() {
        let cache = TaposCache::new();
        cache.store(a_ref());
        assert!(cache.is_fresh());
        cache.invalidate();
        assert!(!cache.is_fresh());
    }

    #[test]
    fn is_shareable_across_threads() {
        use std::sync::Arc;
        let cache = Arc::new(TaposCache::new());
        cache.store(a_ref());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || cache.block_ref().unwrap())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), a_ref());
        }
    }
}
