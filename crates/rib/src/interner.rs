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

//! Attribute interning strategies independent of the RIB's trie layout.
//!
//! [`AttrStore`] retains strong references until an explicit sweep.
//! [`WeakAttrStore`] lets values drop with their last owner. Its pools still
//! sweep dead weak entries before growing; this can pause the writer.
//! Dead weak pointers retain backing allocations (including inline slice
//! storage) until removed. Without subsequent inserts, dead entries can remain
//! indefinitely. Pool capacity is not reduced by cleanup.

use std::hash::{BuildHasher, Hash};
use std::net::Ipv4Addr;
use std::sync::{Arc, Weak};

use hashbrown::HashTable;
use rustc_hash::FxBuildHasher;

use crate::attrs::{AsPathSegment, AttrStore, RouteAttributes};

/// Deduplicates attributes without prescribing their retention policy.
pub trait AttrInterner: Default {
    /// Whether callers need to schedule explicit attribute sweeps.
    const NEEDS_GC: bool;

    fn intern(&mut self, attrs: RouteAttributes) -> Arc<RouteAttributes>;

    /// Release entries retained only by the interner, if applicable.
    fn gc(&mut self);
}

impl AttrInterner for AttrStore {
    const NEEDS_GC: bool = true;

    fn intern(&mut self, attrs: RouteAttributes) -> Arc<RouteAttributes> {
        AttrStore::intern(self, attrs)
    }

    fn gc(&mut self) {
        AttrStore::gc(self);
    }
}

struct WeakPool<T: ?Sized> {
    // Cached hashes allow rehashing even after the value has been dropped.
    table: HashTable<(u64, Weak<T>)>,
}

impl<T: ?Sized> Default for WeakPool<T> {
    fn default() -> Self {
        Self {
            table: HashTable::new(),
        }
    }
}

impl<T: ?Sized + Hash + Eq> WeakPool<T> {
    fn find(&self, hash: u64, value: &T) -> Option<Arc<T>> {
        let mut found = None;
        self.table.find(hash, |(h, weak)| {
            if *h == hash
                && let Some(existing) = weak.upgrade()
                && *existing == *value
            {
                found = Some(existing);
                return true;
            }
            false
        });
        found
    }

    fn insert(&mut self, hash: u64, value: &Arc<T>) {
        if self.table.len() == self.table.capacity() && self.table.capacity() > 0 {
            self.table.retain(|(_, weak)| weak.strong_count() > 0);
            let capacity = self.table.capacity();
            if self.table.len() > capacity * 3 / 4 {
                self.table.reserve(capacity, |(h, _)| *h);
            }
        }
        self.table
            .insert_unique(hash, (hash, Arc::downgrade(value)), |(h, _)| *h);
    }
}

impl<T: Hash + Eq> WeakPool<T> {
    fn intern(&mut self, value: T) -> Arc<T> {
        let hash = FxBuildHasher.hash_one(&value);
        if let Some(existing) = self.find(hash, &value) {
            return existing;
        }
        let value = Arc::new(value);
        self.insert(hash, &value);
        value
    }
}

impl<T: Hash + Eq + Clone> WeakPool<[T]> {
    fn intern_slice(&mut self, value: &[T]) -> Arc<[T]> {
        let hash = FxBuildHasher.hash_one(value);
        if let Some(existing) = self.find(hash, value) {
            return existing;
        }
        let value = Arc::from(value);
        self.insert(hash, &value);
        value
    }
}

/// Two-level interner whose pools do not own their attribute values.
///
/// Routes and retained snapshots own attributes through `Arc`. Values drop
/// when those owners release them; dead weak entries are removed only when
/// insertion into their pool would otherwise require growth.
#[derive(Default)]
pub struct WeakAttrStore {
    as_path: WeakPool<[AsPathSegment]>,
    cluster_list: WeakPool<[Ipv4Addr]>,
    communities: WeakPool<[Box<str>]>,
    ext_communities: WeakPool<[Box<str>]>,
    ext_communities_ipv6: WeakPool<[Box<str>]>,
    large_communities: WeakPool<[Box<str>]>,
    attrs: WeakPool<RouteAttributes>,
}

impl AttrInterner for WeakAttrStore {
    const NEEDS_GC: bool = false;

    fn intern(&mut self, mut attrs: RouteAttributes) -> Arc<RouteAttributes> {
        attrs.as_path = self.as_path.intern_slice(&attrs.as_path);
        attrs.as4_path = attrs
            .as4_path
            .as_deref()
            .map(|p| self.as_path.intern_slice(p));
        attrs.cluster_list = self.cluster_list.intern_slice(&attrs.cluster_list);
        attrs.communities = attrs
            .communities
            .as_deref()
            .map(|p| self.communities.intern_slice(p));
        attrs.ext_communities = attrs
            .ext_communities
            .as_deref()
            .map(|p| self.ext_communities.intern_slice(p));
        attrs.ext_communities_ipv6 = attrs
            .ext_communities_ipv6
            .as_deref()
            .map(|p| self.ext_communities_ipv6.intern_slice(p));
        attrs.large_communities = attrs
            .large_communities
            .as_deref()
            .map(|p| self.large_communities.intern_slice(p));
        self.attrs.intern(attrs)
    }

    fn gc(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RibStore;

    #[test]
    fn weak_store_deduplicates_whole_attrs_and_subcomponents() {
        let mut rib = RibStore::<WeakAttrStore>::default();
        let attrs = RouteAttributes {
            communities: Some(Arc::from(vec![Box::from("65000:1")])),
            ..Default::default()
        };
        let a = rib.attr_store.intern(attrs.clone());
        let b = rib.attr_store.intern(attrs.clone());
        assert!(Arc::ptr_eq(&a, &b));
        let c = rib.attr_store.intern(RouteAttributes {
            local_pref: Some(100),
            ..attrs
        });
        assert!(!Arc::ptr_eq(&a, &c));
        assert!(Arc::ptr_eq(
            a.communities.as_ref().unwrap(),
            c.communities.as_ref().unwrap()
        ));
        let weak = Arc::downgrade(&a);
        drop(a);
        assert!(weak.upgrade().is_some());
        drop(b);
        assert!(weak.upgrade().is_none());
        let component = Arc::downgrade(c.communities.as_ref().unwrap());
        drop(c);
        assert!(component.upgrade().is_none());
    }

    #[test]
    fn growth_reclaims_dead_entries_and_preserves_live_values() {
        let mut pool = WeakPool::<u64>::default();
        let kept = pool.intern(42);
        let dead = pool.intern(0);
        let dead_weak = Arc::downgrade(&dead);
        drop(dead);
        for i in 100..10_000 {
            drop(pool.intern(i));
        }
        assert!(Arc::ptr_eq(&kept, &pool.intern(42)));
        assert!(!pool.table.iter().any(|(_, w)| Weak::ptr_eq(w, &dead_weak)));
        assert!(pool.table.capacity() < 64);
        let fresh = pool.intern(0);
        assert_eq!(*fresh, 0);
        assert!(!Weak::ptr_eq(&Arc::downgrade(&fresh), &dead_weak));
    }

    #[test]
    fn hash_collisions_do_not_merge_distinct_values() {
        #[derive(PartialEq, Eq)]
        struct Collision(u32);
        impl Hash for Collision {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                0u32.hash(state);
            }
        }
        let mut pool = WeakPool::default();
        let a = pool.intern(Collision(1));
        let b = pool.intern(Collision(2));
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&a, &pool.intern(Collision(1))));
        drop(a);
        assert!(Arc::ptr_eq(&b, &pool.intern(Collision(2))));
    }
}
