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

//! Path attributes and the interning store that deduplicates them.
//!
//! Usage:
//! ```ignore
//! let mut store = AttrStore::new();
//! let shared = store.intern(attrs);        // Arc<RouteAttributes>
//! rib.insert(prefix, Route { attrs: Arc::clone(&shared), .. });
//! rib.remove(&prefix);                     // refcount drops
//! store.gc();                              // evicts Arcs only the store holds
//! ```

use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rustc_hash::FxHashSet;

use netcalyx_bgp_pkt::path_attribute::{As2Aggregator, As4Aggregator, AsPathSegmentType, Origin};

/// Flattened route attributes for fast enricher field access.
/// Arc-wrapped collections enable sharing across routes with identical sets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteAttributes {
    pub origin: Origin,
    pub as_path: Arc<[AsPathSegment]>,
    pub as4_path: Option<Arc<[AsPathSegment]>>,

    pub next_hop: Option<IpAddr>,
    pub link_local_next_hop: Option<Ipv6Addr>,

    pub med: Option<u32>,
    pub local_pref: Option<u32>,

    pub aggregator: Option<As2Aggregator>,
    pub aggregator4: Option<As4Aggregator>,
    pub atomic_aggregate: bool,

    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Arc<[Ipv4Addr]>,
    pub aigp_metric: Option<u64>,
    pub otc: Option<u32>,
    pub psid_label_index: Option<u32>,

    // TODO: consider more compact storage (Arc<[u32]> / Arc<[[u8; 8]]>)
    //       (but would require more work when matching).
    pub communities: Option<Arc<[Box<str>]>>,
    pub ext_communities: Option<Arc<[Box<str>]>>,
    pub ext_communities_ipv6: Option<Arc<[Box<str>]>>,
    pub large_communities: Option<Arc<[Box<str>]>>,
}

impl Default for RouteAttributes {
    fn default() -> Self {
        Self {
            origin: Origin::Incomplete,
            as_path: Arc::new([]),
            as4_path: None,
            next_hop: None,
            link_local_next_hop: None,
            med: None,
            local_pref: None,
            aggregator: None,
            aggregator4: None,
            atomic_aggregate: false,
            originator_id: None,
            cluster_list: Arc::new([]),
            aigp_metric: None,
            communities: None,
            ext_communities: None,
            ext_communities_ipv6: None,
            large_communities: None,
            otc: None,
            psid_label_index: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsPathSegment {
    pub segment_type: AsPathSegmentType,
    /// Normalized to u32 even for AS2 paths.
    pub as_numbers: Box<[u32]>,
}

/// Attribute store with interning for common sub-components (AS paths,
/// communities, etc.) and whole-attribute sets.
#[derive(Default)]
pub struct AttrStore {
    // as_path and as4_path share one pool: same element type, segments are often identical
    as_path: SliceInterner<AsPathSegment>,
    cluster_list: SliceInterner<Ipv4Addr>,
    communities: SliceInterner<Box<str>>,
    ext_communities: SliceInterner<Box<str>>,
    ext_communities_ipv6: SliceInterner<Box<str>>,
    large_communities: SliceInterner<Box<str>>,

    /// Whole-attribute pool. Sub-components are interned first so equal attrs
    /// deduplicate here too.
    attrs: FxHashSet<Arc<RouteAttributes>>,
}

impl AttrStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `attrs`, deduplicating sub-components and the whole struct.
    pub fn intern(&mut self, mut attrs: RouteAttributes) -> Arc<RouteAttributes> {
        attrs.as_path = self.as_path.intern(&attrs.as_path);
        attrs.as4_path = attrs.as4_path.as_deref().map(|p| self.as_path.intern(p));
        attrs.cluster_list = self.cluster_list.intern(&attrs.cluster_list);
        attrs.communities = attrs
            .communities
            .as_deref()
            .map(|c| self.communities.intern(c));
        attrs.ext_communities = attrs
            .ext_communities
            .as_deref()
            .map(|e| self.ext_communities.intern(e));
        attrs.ext_communities_ipv6 = attrs
            .ext_communities_ipv6
            .as_deref()
            .map(|e| self.ext_communities_ipv6.intern(e));
        attrs.large_communities = attrs
            .large_communities
            .as_deref()
            .map(|l| self.large_communities.intern(l));

        if let Some(existing) = self.attrs.get(&attrs) {
            return Arc::clone(existing);
        }
        let arc = Arc::new(attrs);
        self.attrs.insert(Arc::clone(&arc));
        arc
    }

    /// Evict unreachable entries. Call after a peer reset or bulk withdrawals.
    /// Order matters: drop whole-attr Arcs first so sub-component refcounts
    /// fall before the sub-pools are scanned.
    pub fn gc(&mut self) {
        self.attrs.retain(|a| Arc::strong_count(a) > 1);
        self.as_path.gc();
        self.cluster_list.gc();
        self.communities.gc();
        self.ext_communities.gc();
        self.ext_communities_ipv6.gc();
        self.large_communities.gc();
    }

    /// Number of distinct interned attribute sets currently held.
    pub fn unique_attrs(&self) -> usize {
        self.attrs.len()
    }
}

/// Interns `Arc<[T]>` slices, deduplicating equal slices into a single
/// allocation. Eviction is explicit via `gc()`.
pub struct SliceInterner<T> {
    pool: FxHashSet<Arc<[T]>>,
}

impl<T: Hash + Eq + Clone> Default for SliceInterner<T> {
    fn default() -> Self {
        Self {
            pool: FxHashSet::default(),
        }
    }
}

impl<T: Hash + Eq + Clone> SliceInterner<T> {
    pub fn intern(&mut self, slice: &[T]) -> Arc<[T]> {
        if let Some(existing) = self.pool.get(slice) {
            Arc::clone(existing)
        } else {
            let arc: Arc<[T]> = Arc::from(slice);
            self.pool.insert(Arc::clone(&arc));
            arc
        }
    }

    /// Evict entries whose only strong reference is this pool.
    pub fn gc(&mut self) {
        self.pool.retain(|a| Arc::strong_count(a) > 1);
    }

    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_deduplicates_equal_attrs() {
        let mut store = AttrStore::new();
        let a = store.intern(RouteAttributes {
            local_pref: Some(100),
            ..Default::default()
        });
        let b = store.intern(RouteAttributes {
            local_pref: Some(100),
            ..Default::default()
        });
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(store.unique_attrs(), 1);
    }

    #[test]
    fn intern_keeps_distinct_attrs_separate() {
        let mut store = AttrStore::new();
        let a = store.intern(RouteAttributes {
            local_pref: Some(100),
            ..Default::default()
        });
        let b = store.intern(RouteAttributes {
            local_pref: Some(200),
            ..Default::default()
        });
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(store.unique_attrs(), 2);
    }

    #[test]
    fn gc_evicts_only_unreferenced_entries() {
        let mut store = AttrStore::new();
        let kept = store.intern(RouteAttributes {
            local_pref: Some(1),
            ..Default::default()
        });
        store.intern(RouteAttributes {
            local_pref: Some(2),
            ..Default::default()
        });
        assert_eq!(store.unique_attrs(), 2);

        store.gc();
        assert_eq!(store.unique_attrs(), 1);
        assert_eq!(kept.local_pref, Some(1));
    }

    #[test]
    fn slice_interner_dedups_and_gcs() {
        let mut interner = SliceInterner::<u32>::default();
        let a = interner.intern(&[1, 2, 3]);
        let b = interner.intern(&[1, 2, 3]);
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(interner.pool_len(), 1);

        drop(a);
        drop(b);
        interner.gc();
        assert_eq!(interner.pool_len(), 0);
    }
}
