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
//! [`YangModuleCache`] exposes four plain counters via [`YangModuleCacheStats`]:
//!
//! | field | meaning |
//! |-------|---------|
//! | [`YangModuleCacheStats::hits`]      | `get-schema` RPC avoided (module already cached) |
//! | [`YangModuleCacheStats::misses`]    | `get-schema` RPC issued (module not yet cached)  |
//! | [`YangModuleCacheStats::coalesced`] | `get-schema` RPC avoided by waiting on an in-flight fetch started by another session |
//! | [`YangModuleCacheStats::size`]      | number of distinct modules currently cached      |
//!
//! These are `AtomicU64` so they can be read from any thread without holding
//! the cache lock.  Higher-level crates that own an OTel meter can poll them
//! and record gauges / counters as needed.
//!
//! ## Single-flight
//!
//! To avoid a thundering herd at collector startup — where many subscriptions
//! request the same module before any fetch has completed — the cache
//! de-duplicates **in-flight** fetches, not just completed ones.  The first
//! caller for a `(name, revision)` becomes the *leader* and performs the
//! `get-schema` RPC on its own session; concurrent callers become *waiters* and
//! await the leader's result instead of issuing their own RPC.  If the leader
//! fails, waiters fall back and re-race so one of them becomes a new leader.
//! This is exposed through [`YangModuleCache::begin_fetch`].
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
use std::collections::hash_map::Entry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::watch;

/// An entry in the module cache: either a fully-fetched module text, or a
/// placeholder for a fetch that a *leader* session is currently performing.
/// Waiters clone the [`watch::Receiver`] and await the published result.
#[derive(Debug)]
enum ModuleEntry {
    /// The module text is cached and ready to serve.
    Ready(Arc<str>),
    /// A leader is fetching this module; the value is published here on success
    /// (or the channel is closed on failure, signalling waiters to fall back).
    InFlight(watch::Receiver<Option<Arc<str>>>),
}

/// Cache key: a `(module_name, revision)` pair. Kept as a tuple rather than a
/// concatenated string so the two components can never be mixed (e.g. a
/// name or revision containing the separator).
type ModuleCacheKey = (String, String);

type ModuleCacheInner = Arc<RwLock<HashMap<ModuleCacheKey, ModuleEntry>>>;

/// Metrics counters exposed by [`YangModuleCache`].
#[derive(Debug, Default)]
pub struct YangModuleCacheStats {
    /// Number of `get-schema` RPCs avoided because the module was already
    /// cached.
    pub hits: AtomicU64,
    /// Number of `get-schema` RPCs issued because the module was not yet
    /// cached.
    pub misses: AtomicU64,
    /// Number of `get-schema` RPCs avoided by waiting on an in-flight fetch
    /// started by another session (single-flight de-duplication).
    pub coalesced: AtomicU64,
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

/// Outcome of [`YangModuleCache::begin_fetch`]: the caller's role for a given
/// `(name, revision)`.
#[derive(Debug)]
pub enum ModuleFetch {
    /// The module is already cached; use this text and skip the RPC.
    Cached(Arc<str>),
    /// Another session is already fetching this module; await it via
    /// [`ModuleFetchWaiter::wait`] instead of issuing a duplicate RPC.
    Wait(ModuleFetchWaiter),
    /// No one is fetching this module yet; the caller is the leader and must
    /// perform the `get-schema` RPC, then call [`ModuleFetchLease::fulfil`]
    /// with the result (or drop the lease to abort, freeing waiters to retry).
    Lead(ModuleFetchLease),
}

/// Handle for a waiter to await the leader's in-flight fetch.
#[derive(Debug)]
pub struct ModuleFetchWaiter {
    rx: watch::Receiver<Option<Arc<str>>>,
    stats: Arc<YangModuleCacheStats>,
}

impl ModuleFetchWaiter {
    /// Await the leader's fetch.
    ///
    /// Returns `Some(text)` once the leader publishes its result (a coalesced
    /// hit), or `None` if the leader failed/aborted — in which case the caller
    /// should retry via [`YangModuleCache::begin_fetch`] and will become a new
    /// leader or waiter.
    pub async fn wait(mut self) -> Option<Arc<str>> {
        loop {
            // Read the current value first so we never miss a result that was
            // published before we started awaiting (watch retains the latest).
            if let Some(text) = self.rx.borrow().clone() {
                self.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                return Some(text);
            }
            if self.rx.changed().await.is_err() {
                // Leader dropped the sender without publishing -> fall back.
                return None;
            }
        }
    }
}

/// A lease held by the leader session while it fetches a module.
///
/// On success the leader calls [`fulfil`](Self::fulfil) to store the text and
/// wake waiters.  If the lease is dropped without fulfilment (e.g. the fetch
/// errored), the in-flight placeholder is removed so a future caller can lead,
/// and the closed watch channel signals current waiters to retry.
#[derive(Debug)]
pub struct ModuleFetchLease {
    inner: ModuleCacheInner,
    stats: Arc<YangModuleCacheStats>,
    key: ModuleCacheKey,
    tx: watch::Sender<Option<Arc<str>>>,
    fulfilled: bool,
}

impl ModuleFetchLease {
    /// Store the fetched module text in the cache and wake all waiters.
    pub fn fulfil(mut self, text: Arc<str>) {
        {
            let mut map = self.inner.write().expect("yang module cache lock poisoned");
            map.insert(self.key.clone(), ModuleEntry::Ready(Arc::clone(&text)));
        }
        self.stats.size.fetch_add(1, Ordering::Relaxed);
        // Publish to waiters; ignore send errors (no waiters is fine).
        let _ = self.tx.send(Some(text));
        self.fulfilled = true;
    }
}

impl Drop for ModuleFetchLease {
    fn drop(&mut self) {
        if self.fulfilled {
            return;
        }
        // Aborted fetch: remove our placeholder so the next caller re-leads.
        // Dropping `tx` right after closes the watch, waking waiters to retry.
        let mut map = self.inner.write().expect("yang module cache lock poisoned");
        if matches!(map.get(&self.key), Some(ModuleEntry::InFlight(_))) {
            map.remove(&self.key);
        }
    }
}

impl YangModuleCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &Arc<YangModuleCacheStats> {
        &self.stats
    }

    /// Begin a single-flight fetch for `(name, revision)`.
    ///
    /// Returns the caller's [`ModuleFetch`] role: a
    /// [`Cached`](ModuleFetch::Cached) hit, a [`Wait`](ModuleFetch::Wait)
    /// on another session's in-flight fetch,
    /// or a [`Lead`](ModuleFetch::Lead) lease obliging the caller to fetch.
    ///
    /// Stats: a cache hit increments `hits`; leadership increments `misses`
    /// (an RPC will be issued); waiting increments neither here — the coalesced
    /// counter is bumped by [`ModuleFetchWaiter::wait`] on success.
    pub fn begin_fetch(&self, name: &str, revision: &str) -> ModuleFetch {
        let key = Self::make_key(name, revision);
        let mut map = self.inner.write().expect("yang module cache lock poisoned");
        match map.get(&key) {
            Some(ModuleEntry::Ready(text)) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                ModuleFetch::Cached(Arc::clone(text))
            }
            Some(ModuleEntry::InFlight(rx)) => ModuleFetch::Wait(ModuleFetchWaiter {
                rx: rx.clone(),
                stats: Arc::clone(&self.stats),
            }),
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = watch::channel(None);
                map.insert(key.clone(), ModuleEntry::InFlight(rx));
                ModuleFetch::Lead(ModuleFetchLease {
                    inner: Arc::clone(&self.inner),
                    stats: Arc::clone(&self.stats),
                    key,
                    tx,
                    fulfilled: false,
                })
            }
        }
    }

    /// Return the cached module text for `(name, revision)`, or `None` on miss.
    /// Increments the appropriate stats counter.  An in-flight (not yet
    /// published) fetch counts as a miss.
    pub fn get(&self, name: &str, revision: &str) -> Option<Arc<str>> {
        let key = Self::make_key(name, revision);
        let result = match self
            .inner
            .read()
            .expect("yang module cache lock poisoned")
            .get(&key)
        {
            Some(ModuleEntry::Ready(text)) => Some(Arc::clone(text)),
            Some(ModuleEntry::InFlight(_)) | None => None,
        };
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
        if let Entry::Vacant(entry) = map.entry(key) {
            entry.insert(ModuleEntry::Ready(text));
            self.stats.size.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of ready (fully-fetched) modules currently in the cache.
    /// In-flight placeholders are not counted.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("yang module cache lock poisoned")
            .values()
            .filter(|entry| matches!(entry, ModuleEntry::Ready(_)))
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn make_key(name: &str, revision: &str) -> ModuleCacheKey {
        (name.to_owned(), revision.to_owned())
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

    #[tokio::test]
    async fn test_single_flight_coalesces_concurrent_fetches() {
        let cache = YangModuleCache::new();

        // First caller leads.
        let lease = match cache.begin_fetch("mod", "2024-01-01") {
            ModuleFetch::Lead(lease) => lease,
            other => panic!("first caller should lead, got {other:?}"),
        };

        // While the leader holds the lease, every concurrent caller must wait.
        let n = 8;
        let mut waiters = Vec::new();
        for _ in 0..n {
            match cache.begin_fetch("mod", "2024-01-01") {
                ModuleFetch::Wait(waiter) => {
                    waiters.push(tokio::spawn(async move { waiter.wait().await }));
                }
                other => panic!("expected wait while a fetch is in flight, got {other:?}"),
            }
        }

        // Publish the result; all waiters should observe it (no extra RPCs).
        let text: Arc<str> = Arc::from("module mod { }");
        lease.fulfil(Arc::clone(&text));

        for waiter in waiters {
            let got = waiter.await.expect("waiter task panicked");
            assert_eq!(got.as_deref(), Some("module mod { }"));
        }

        assert_eq!(cache.stats().coalesced.load(Ordering::Relaxed), n as u64);
        assert_eq!(cache.stats().misses.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 0);
        assert_eq!(cache.stats().size.load(Ordering::Relaxed), 1);
        assert_eq!(cache.len(), 1);

        // A later caller now takes the fast path.
        assert!(matches!(
            cache.begin_fetch("mod", "2024-01-01"),
            ModuleFetch::Cached(_)
        ));
        assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_leader_failure_lets_waiters_retry() {
        let cache = YangModuleCache::new();

        let lease = match cache.begin_fetch("mod", "2024-01-01") {
            ModuleFetch::Lead(lease) => lease,
            other => panic!("first caller should lead, got {other:?}"),
        };
        let waiter = match cache.begin_fetch("mod", "2024-01-01") {
            ModuleFetch::Wait(waiter) => waiter,
            other => panic!("expected wait, got {other:?}"),
        };

        // Leader aborts (e.g. its RPC failed) by dropping the lease.
        drop(lease);

        // The waiter is told to fall back, and no coalesced hit is recorded.
        assert_eq!(waiter.wait().await, None);
        assert_eq!(cache.stats().coalesced.load(Ordering::Relaxed), 0);
        assert_eq!(cache.stats().size.load(Ordering::Relaxed), 0);

        // The key is free again, so the next caller re-leads.
        assert!(matches!(
            cache.begin_fetch("mod", "2024-01-01"),
            ModuleFetch::Lead(_)
        ));
        assert_eq!(cache.stats().misses.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_distinct_keys_lead_independently() {
        let cache = YangModuleCache::new();
        assert!(matches!(
            cache.begin_fetch("a", "2024-01-01"),
            ModuleFetch::Lead(_)
        ));
        assert!(matches!(
            cache.begin_fetch("b", "2024-01-01"),
            ModuleFetch::Lead(_)
        ));
        // Two distinct modules -> two leaders -> two RPCs.
        assert_eq!(cache.stats().misses.load(Ordering::Relaxed), 2);
    }
}
