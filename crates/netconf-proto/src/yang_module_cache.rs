// Copyright (C) 2026-present The NetCalyx Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Global YANG module text cache.
//!
//! The YANG specification guarantees that a `(module_name, revision)` pair
//! identifies stable content: any published change to a module MUST add a new
//! revision date ([RFC 7950], §11).  A single instance of
//! [`YangModuleCache`] can therefore be shared across all routers and all SSH
//! sessions: once a module is fetched from any device, subsequent calls to
//! [`NetConfSshClient::get_yang_module`](crate::client::NetConfSshClient::get_yang_module)
//! skip the NETCONF `get-schema` RPC entirely.
//!
//! Note: the NETCONF RPC is still called `get-schema` (per [RFC 6022]), but
//! what it returns — and what we cache — is a YANG **module** text, not a
//! schema.
//!
//! ## Metrics
//!
//! [`YangModuleCache`] exposes three plain counters via [`YangModuleCacheStats`]:
//!
//! | field | meaning |
//! |-------|---------|
//! | [`YangModuleCacheStats::hits`]   | `get-schema` RPC avoided (module already cached) |
//! | [`YangModuleCacheStats::misses`] | `get-schema` RPC issued (module not yet cached)  |
//! | [`YangModuleCacheStats::size`]   | number of distinct modules currently cached      |
//!
//! These are `AtomicU64` so they can be read from any thread without holding
//! the cache lock.  Higher-level crates that own an OTel meter can poll them
//! and record gauges / counters as needed.
//!
//! ## References
//!
//! - [RFC 6022]: YANG Module for NETCONF Monitoring — defines the `get-schema`
//!   operation used to fetch module texts.
//! - [RFC 7950]: The YANG 1.1 Data Modeling Language — §11 "Updating a Module"
//!   (any published change MUST add a new revision date).
//!
//! [RFC 6022]: https://www.rfc-editor.org/rfc/rfc6022
//! [RFC 7950]: https://www.rfc-editor.org/rfc/rfc7950

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

type ModuleCacheInner = Arc<RwLock<HashMap<String, Arc<str>>>>;

/// Metrics counters exposed by [`YangModuleCache`].
#[derive(Debug, Default)]
pub struct YangModuleCacheStats {
    /// Number of `get-schema` RPCs avoided because the module was already
    /// cached.
    pub hits: AtomicU64,
    /// Number of `get-schema` RPCs issued because the module was not yet
    /// cached.
    pub misses: AtomicU64,
    /// Current number of distinct `(name, revision)` entries in the cache.
    pub size: AtomicU64,
}

/// A thread-safe, globally-shared cache of raw YANG module texts.
///
/// Keyed by `(module_name, revision)`.  The value is the raw module text as
/// returned by a NETCONF `get-schema` RPC, stored as `Arc<str>` so that cache
/// hits — and the value handed back by
/// [`NetConfSshClient::get_yang_module`](crate::client::NetConfSshClient::get_yang_module)
/// — are cheap pointer clones rather than full string copies.  (Feeding a
/// module into the `ModuleSetBuilder` still costs one copy, because the builder
/// takes an owned `Box<str>`.)
///
/// Clone is cheap — clones share the same backing store and stats.
#[derive(Debug, Clone, Default)]
pub struct YangModuleCache {
    inner: ModuleCacheInner,
    stats: Arc<YangModuleCacheStats>,
}

impl YangModuleCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &Arc<YangModuleCacheStats> {
        &self.stats
    }

    /// Return the cached module text for `(name, revision)`, or `None` on miss.
    /// Increments the appropriate stats counter.
    pub fn get(&self, name: &str, revision: &str) -> Option<Arc<str>> {
        let key = Self::make_key(name, revision);
        let result = self
            .inner
            .read()
            .expect("yang module cache lock poisoned")
            .get(&key)
            .cloned();
        if result.is_some() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Insert a module text.  First writer wins: if `(name, revision)` is
    /// already present the call is a no-op.  This is safe because identical
    /// `(name, revision)` always has identical content per the YANG spec.
    pub fn insert(&self, name: &str, revision: &str, text: Arc<str>) {
        let key = Self::make_key(name, revision);
        let mut map = self.inner.write().expect("yang module cache lock poisoned");
        let prev_len = map.len();
        map.entry(key).or_insert(text);
        if map.len() > prev_len {
            self.stats.size.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("yang module cache lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .expect("yang module cache lock poisoned")
            .is_empty()
    }

    fn make_key(name: &str, revision: &str) -> String {
        format!("{name}@{revision}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let c = YangModuleCache::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.stats().size.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_miss_increments_miss_counter() {
        let c = YangModuleCache::new();
        assert!(c.get("ietf-interfaces", "2018-02-20").is_none());
        assert_eq!(c.stats().misses.load(Ordering::Relaxed), 1);
        assert_eq!(c.stats().hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_insert_and_hit_increments_hit_counter() {
        let c = YangModuleCache::new();
        c.insert(
            "ietf-interfaces",
            "2018-02-20",
            Arc::from("module ietf-interfaces { }"),
        );
        assert_eq!(c.stats().size.load(Ordering::Relaxed), 1);

        let result = c.get("ietf-interfaces", "2018-02-20");
        assert_eq!(result.as_deref(), Some("module ietf-interfaces { }"));
        assert_eq!(c.stats().hits.load(Ordering::Relaxed), 1);
        assert_eq!(c.stats().misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_first_writer_wins() {
        let c = YangModuleCache::new();
        c.insert("mod", "2024-01-01", Arc::from("first"));
        c.insert("mod", "2024-01-01", Arc::from("second"));
        assert_eq!(c.get("mod", "2024-01-01").as_deref(), Some("first"));
        assert_eq!(c.stats().size.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_different_revisions_are_distinct_keys() {
        let c = YangModuleCache::new();
        c.insert("mod", "2023-01-01", Arc::from("old"));
        c.insert("mod", "2024-01-01", Arc::from("new"));
        assert_eq!(c.get("mod", "2023-01-01").as_deref(), Some("old"));
        assert_eq!(c.get("mod", "2024-01-01").as_deref(), Some("new"));
        assert_eq!(c.stats().size.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_clone_shares_state() {
        let a = YangModuleCache::new();
        let b = a.clone();
        a.insert("mod", "2024-01-01", Arc::from("value"));
        assert_eq!(b.get("mod", "2024-01-01").as_deref(), Some("value"));
        // hit recorded on `b` is visible via `a.stats` (same Arc)
        assert_eq!(a.stats().hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_concurrent_insert_and_get() {
        use std::thread;

        let cache = YangModuleCache::new();
        let n_threads = 8;
        let n_modules = 20;

        let handles: Vec<_> = (0..n_threads)
            .map(|t| {
                let c = cache.clone();
                thread::spawn(move || {
                    for i in 0..n_modules {
                        let name = format!("mod-{i}");
                        let rev = format!("2024-{i:02}-01");
                        let text = Arc::from(format!("text-{i}").as_str());
                        c.insert(&name, &rev, text);
                        assert!(c.get(&name, &rev).is_some());
                        let _ = c.len();
                    }
                    for i in 0..n_modules {
                        let name = format!("mod-{i}");
                        let rev = format!("2024-{i:02}-01");
                        c.insert(
                            &name,
                            &rev,
                            Arc::from(format!("other-text-{t}-{i}").as_str()),
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // All modules must be present and have the first-writer value.
        assert_eq!(cache.len(), n_modules);
        for i in 0..n_modules {
            let name = format!("mod-{i}");
            let rev = format!("2024-{i:02}-01");
            let expected = format!("text-{i}");
            assert_eq!(cache.get(&name, &rev).as_deref(), Some(expected.as_str()));
        }
        assert_eq!(cache.stats().size.load(Ordering::Relaxed), n_modules as u64);
    }
}
