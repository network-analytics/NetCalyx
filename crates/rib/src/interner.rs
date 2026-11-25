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
//! [`StrongAttrStore`] retains strong references until an explicit sweep.
//! [`WeakAttrStore`] lets values drop with their last owner. Its pools still
//! sweep dead weak entries before growing or when `gc()` is called; this can
//! pause the writer. Explicit cleanup is optional for value reclamation but
//! removes dead weak pointers and their backing allocations. Pool capacity is
//! not reduced by cleanup.

use std::hash::{BuildHasher, Hash};
use std::net::Ipv4Addr;
use std::sync::{Arc, Weak};

use hashbrown::HashTable;
use rustc_hash::FxBuildHasher;

use crate::attrs::{AsPathSegment, AttrSubPools, RouteAttributes, SlicePool, StrongAttrStore};

const MAX_POST_SWEEP_LOAD: (usize, usize) = (3, 4);

/// Deduplicates attributes without prescribing their retention policy.
pub trait AttrInterner: Default {
    /// Whether this interner typically needs scheduled explicit sweeps.
    const NEEDS_SCHEDULED_GC: bool;

    fn intern(&mut self, attrs: RouteAttributes) -> Arc<RouteAttributes>;

    /// Remove entries no longer owned by callers, if applicable.
    fn gc(&mut self);
}

impl AttrInterner for StrongAttrStore {
    const NEEDS_SCHEDULED_GC: bool = true;

    fn intern(&mut self, attrs: RouteAttributes) -> Arc<RouteAttributes> {
        StrongAttrStore::intern(self, attrs)
    }

    fn gc(&mut self) {
        StrongAttrStore::gc(self);
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
            self.gc();
            let capacity = self.table.capacity();
            let (numerator, denominator) = MAX_POST_SWEEP_LOAD;
            if self.table.len() > capacity * numerator / denominator {
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

impl<T: Hash + Eq + Clone> SlicePool<T> for WeakPool<[T]> {
    fn intern_slice(&mut self, value: &[T]) -> Arc<[T]> {
        let hash = FxBuildHasher.hash_one(value);
        if let Some(existing) = self.find(hash, value) {
            return existing;
        }
        let value = Arc::from(value);
        self.insert(hash, &value);
        value
    }

    fn gc(&mut self) {
        WeakPool::gc(self);
    }

    #[cfg(test)]
    fn pool_len(&self) -> usize {
        self.table.len()
    }
}

impl<T: ?Sized> WeakPool<T> {
    fn gc(&mut self) {
        self.table.retain(|(_, weak)| weak.strong_count() > 0);
    }
}

type WeakAttrSubPools =
    AttrSubPools<WeakPool<[AsPathSegment]>, WeakPool<[Ipv4Addr]>, WeakPool<[Box<str>]>>;

/// Two-level interner whose pools do not own their attribute values.
///
/// Routes and retained snapshots own attributes through `Arc`. Values drop
/// when those owners release them. Dead weak entries are removed when an
/// insertion would otherwise require growth or when `gc()` is called.
#[derive(Default)]
pub struct WeakAttrStore {
    sub_pools: WeakAttrSubPools,
    attrs: WeakPool<RouteAttributes>,
}

impl AttrInterner for WeakAttrStore {
    const NEEDS_SCHEDULED_GC: bool = false;

    fn intern(&mut self, mut attrs: RouteAttributes) -> Arc<RouteAttributes> {
        self.sub_pools.intern(&mut attrs);
        self.attrs.intern(attrs)
    }

    fn gc(&mut self) {
        self.attrs.gc();
        self.sub_pools.gc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RibStore;

    #[test]
    fn weak_store_normalizes_empty_slices() {
        let mut store = WeakAttrStore::default();
        let empty = store.intern(RouteAttributes {
            as_path: Some(Arc::new([])),
            as4_path: Some(Arc::new([])),
            cluster_list: Some(Arc::new([])),
            communities: Some(Arc::new([])),
            ext_communities: Some(Arc::new([])),
            ext_communities_ipv6: Some(Arc::new([])),
            large_communities: Some(Arc::new([])),
            ..Default::default()
        });
        let absent = store.intern(RouteAttributes::default());
        assert_eq!(*empty, RouteAttributes::default());
        assert!(Arc::ptr_eq(&empty, &absent));
        assert_eq!(store.sub_pools.pool_lens(), [0; 6]);
    }

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
    fn weak_store_gc_removes_dead_entries_from_every_pool() {
        use netcalyx_bgp_pkt::path_attribute::AsPathSegmentType;

        let mut store = WeakAttrStore::default();
        let as_path: Arc<[AsPathSegment]> = Arc::from(vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            as_numbers: Box::new([65000]),
        }]);
        let cluster_list: Arc<[Ipv4Addr]> = Arc::from(vec![Ipv4Addr::LOCALHOST]);
        let communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:1")]);
        let ext_communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:2")]);
        let ext_communities_ipv6: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:3")]);
        let large_communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:4")]);
        let attrs = store.intern(RouteAttributes {
            as_path: Some(Arc::clone(&as_path)),
            as4_path: Some(Arc::clone(&as_path)),
            cluster_list: Some(Arc::clone(&cluster_list)),
            communities: Some(Arc::clone(&communities)),
            ext_communities: Some(Arc::clone(&ext_communities)),
            ext_communities_ipv6: Some(Arc::clone(&ext_communities_ipv6)),
            large_communities: Some(Arc::clone(&large_communities)),
            ..Default::default()
        });

        drop(attrs);
        drop(as_path);
        drop(cluster_list);
        drop(communities);
        drop(ext_communities);
        drop(ext_communities_ipv6);
        drop(large_communities);

        assert_eq!(store.attrs.table.len(), 1);
        assert_eq!(store.sub_pools.pool_lens(), [1; 6]);

        store.gc();

        assert!(store.attrs.table.is_empty());
        assert_eq!(store.sub_pools.pool_lens(), [0; 6]);
    }

    #[test]
    fn explicit_gc_sweeps_all_weak_pools_and_preserves_live_values() {
        use netcalyx_bgp_pkt::path_attribute::AsPathSegmentType;

        fn attrs(id: u8) -> RouteAttributes {
            let component: Arc<[Box<str>]> = Arc::from(vec![format!("65000:{id}").into()]);
            RouteAttributes {
                as_path: Some(Arc::from(vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    as_numbers: Box::new([u32::from(id)]),
                }])),
                cluster_list: Some(Arc::from(vec![Ipv4Addr::new(192, 0, 2, id)])),
                communities: Some(Arc::clone(&component)),
                ext_communities: Some(Arc::clone(&component)),
                ext_communities_ipv6: Some(Arc::clone(&component)),
                large_communities: Some(component),
                ..Default::default()
            }
        }

        let mut store = WeakAttrStore::default();
        let live = store.intern(attrs(1));
        let dead = store.intern(attrs(2));
        drop(dead);
        assert_eq!(store.attrs.table.len(), 2);
        store.gc();

        assert_eq!(store.attrs.table.len(), 1);
        assert_eq!(store.sub_pools.pool_lens(), [1; 6]);
        assert!(Arc::ptr_eq(&live, &store.intern(attrs(1))));

        drop(live);
        store.gc();
        assert_eq!(store.attrs.table.len(), 0);
        assert_eq!(store.sub_pools.pool_lens(), [0; 6]);
    }

    #[test]
    fn full_pool_grows_only_above_post_sweep_load_limit() {
        for grow in [false, true] {
            // A small table avoids tombstones reducing capacity during retain.
            let mut pool = WeakPool {
                table: HashTable::with_capacity(3),
            };
            let capacity = pool.table.capacity();
            let limit = capacity * 75 / 100;
            let mut owners: Vec<_> = (0..capacity).map(|i| pool.intern(i)).collect();
            owners.truncate(limit + usize::from(grow));

            let _new_owner = pool.intern(capacity);
            assert_eq!(pool.table.capacity() > capacity, grow);
        }
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
