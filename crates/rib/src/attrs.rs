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
//! let mut store = StrongAttrStore::new();
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
/// Absent collections default to `None`; interning also normalizes empty
/// slices.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteAttributes {
    pub origin: Origin,
    pub as_path: Option<Arc<[AsPathSegment]>>,
    pub as4_path: Option<Arc<[AsPathSegment]>>,

    pub next_hop: Option<IpAddr>,
    pub link_local_next_hop: Option<Ipv6Addr>,

    pub med: Option<u32>,
    pub local_pref: Option<u32>,

    pub aggregator: Option<As2Aggregator>,
    pub aggregator4: Option<As4Aggregator>,
    pub atomic_aggregate: bool,

    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Option<Arc<[Ipv4Addr]>>,
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
            as_path: None,
            as4_path: None,
            next_hop: None,
            link_local_next_hop: None,
            med: None,
            local_pref: None,
            aggregator: None,
            aggregator4: None,
            atomic_aggregate: false,
            originator_id: None,
            cluster_list: None,
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

pub(crate) trait SlicePool<T> {
    fn intern_slice(&mut self, slice: &[T]) -> Arc<[T]>;
    fn gc(&mut self);
    #[cfg(test)]
    fn pool_len(&self) -> usize;
}

#[derive(Default)]
pub(crate) struct AttrSubPools<A, C, S> {
    as_path: A,
    cluster_list: C,
    communities: S,
    ext_communities: S,
    ext_communities_ipv6: S,
    large_communities: S,
}

impl<A, C, S> AttrSubPools<A, C, S>
where
    A: SlicePool<AsPathSegment>,
    C: SlicePool<Ipv4Addr>,
    S: SlicePool<Box<str>>,
{
    pub(crate) fn intern(&mut self, attrs: &mut RouteAttributes) {
        attrs.as_path = attrs
            .as_path
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|p| self.as_path.intern_slice(p));
        attrs.as4_path = attrs
            .as4_path
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|p| self.as_path.intern_slice(p));
        attrs.cluster_list = attrs
            .cluster_list
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| self.cluster_list.intern_slice(c));
        attrs.communities = attrs
            .communities
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| self.communities.intern_slice(c));
        attrs.ext_communities = attrs
            .ext_communities
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| self.ext_communities.intern_slice(c));
        attrs.ext_communities_ipv6 = attrs
            .ext_communities_ipv6
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| self.ext_communities_ipv6.intern_slice(c));
        attrs.large_communities = attrs
            .large_communities
            .as_deref()
            .filter(|c| !c.is_empty())
            .map(|c| self.large_communities.intern_slice(c));
    }

    pub(crate) fn gc(&mut self) {
        self.as_path.gc();
        self.cluster_list.gc();
        self.communities.gc();
        self.ext_communities.gc();
        self.ext_communities_ipv6.gc();
        self.large_communities.gc();
    }

    #[cfg(test)]
    pub(crate) fn pool_lens(&self) -> [usize; 6] {
        [
            self.as_path.pool_len(),
            self.cluster_list.pool_len(),
            self.communities.pool_len(),
            self.ext_communities.pool_len(),
            self.ext_communities_ipv6.pool_len(),
            self.large_communities.pool_len(),
        ]
    }
}

/// Attribute store with interning for common sub-components (AS paths,
/// communities, etc.) and whole-attribute sets.
#[derive(Default)]
pub struct StrongAttrStore {
    sub_pools: AttrSubPools<
        SliceInterner<AsPathSegment>,
        SliceInterner<Ipv4Addr>,
        SliceInterner<Box<str>>,
    >,

    /// Whole-attribute pool. Sub-components are interned first so equal attrs
    /// deduplicate here too.
    attrs: FxHashSet<Arc<RouteAttributes>>,
}

impl StrongAttrStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `attrs`, deduplicating sub-components and the whole struct.
    /// Empty optional slices are normalized to `None` before interning.
    pub fn intern(&mut self, mut attrs: RouteAttributes) -> Arc<RouteAttributes> {
        self.sub_pools.intern(&mut attrs);

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
        self.sub_pools.gc();
    }

    /// Number of distinct interned attribute sets currently held.
    pub fn unique_attrs(&self) -> usize {
        self.attrs.len()
    }

    #[cfg(test)]
    fn as_path_pool_len(&self) -> usize {
        self.sub_pools.as_path.pool_len()
    }
}

/// Interns `Arc<[T]>` slices, deduplicating equal slices into a single
/// allocation. Eviction is explicit via `gc()`.
pub struct SliceInterner<T> {
    pool: FxHashSet<Arc<[T]>>,
}

impl<T: Hash + Eq + Clone> SlicePool<T> for SliceInterner<T> {
    fn intern_slice(&mut self, slice: &[T]) -> Arc<[T]> {
        self.intern(slice)
    }

    fn gc(&mut self) {
        SliceInterner::gc(self);
    }

    #[cfg(test)]
    fn pool_len(&self) -> usize {
        SliceInterner::pool_len(self)
    }
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
        let mut store = StrongAttrStore::new();
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
    fn intern_normalizes_empty_optional_slices() {
        for empty_first in [false, true] {
            let mut store = StrongAttrStore::new();
            let empty = RouteAttributes {
                as_path: Some(Arc::new([])),
                as4_path: Some(Arc::new([])),
                cluster_list: Some(Arc::new([])),
                communities: Some(Arc::new([])),
                ext_communities: Some(Arc::new([])),
                ext_communities_ipv6: Some(Arc::new([])),
                large_communities: Some(Arc::new([])),
                ..Default::default()
            };
            let absent = RouteAttributes::default();
            let (first, second) = if empty_first {
                (empty, absent)
            } else {
                (absent, empty)
            };
            let a = store.intern(first);
            let b = store.intern(second);

            assert!(a.as4_path.is_none());
            assert!(a.communities.is_none());
            assert!(a.ext_communities.is_none());
            assert!(a.ext_communities_ipv6.is_none());
            assert!(a.large_communities.is_none());
            assert!(a.as_path.is_none());
            assert!(a.cluster_list.is_none());
            assert!(Arc::ptr_eq(&a, &b));
            assert_eq!(store.unique_attrs(), 1);
            assert_eq!(store.sub_pools.pool_lens(), [0; 6]);
        }
    }

    #[test]
    fn intern_preserves_and_deduplicates_nonempty_optional_slices() {
        let mut store = StrongAttrStore::new();
        let attrs = RouteAttributes {
            as_path: Some(Arc::from([AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                as_numbers: Box::new([65000]),
            }])),
            as4_path: Some(Arc::from([AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                as_numbers: Box::new([65000]),
            }])),
            cluster_list: Some(Arc::from([Ipv4Addr::new(1, 1, 1, 1)])),
            communities: Some(Arc::from([Box::from("65000:1")])),
            ext_communities: Some(Arc::from([Box::from("rt:65000:1")])),
            ext_communities_ipv6: Some(Arc::from([Box::from("rt:2001:db8::1:1")])),
            large_communities: Some(Arc::from([Box::from("65000:1:1")])),
            ..Default::default()
        };
        let a = store.intern(attrs.clone());
        let b = store.intern(RouteAttributes {
            local_pref: Some(100),
            ..attrs.clone()
        });

        assert_eq!(*a, attrs);
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(
            a.as_path.as_ref().unwrap(),
            b.as_path.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            a.cluster_list.as_ref().unwrap(),
            b.cluster_list.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            a.as4_path.as_ref().unwrap(),
            b.as4_path.as_ref().unwrap()
        ));
        for (left, right) in [
            (&a.communities, &b.communities),
            (&a.ext_communities, &b.ext_communities),
            (&a.ext_communities_ipv6, &b.ext_communities_ipv6),
            (&a.large_communities, &b.large_communities),
        ] {
            assert!(Arc::ptr_eq(left.as_ref().unwrap(), right.as_ref().unwrap()));
        }
    }

    #[test]
    fn intern_keeps_distinct_attrs_separate() {
        let mut store = StrongAttrStore::new();
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
        let mut store = StrongAttrStore::new();
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
    fn intern_dedupes_as_path_and_shares_pool_with_as4_path() {
        let mut store = StrongAttrStore::new();
        let as_path: Arc<[AsPathSegment]> = Arc::from(vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            as_numbers: Box::new([65000, 65001]),
        }]);

        let a = store.intern(RouteAttributes {
            local_pref: Some(1),
            as_path: Some(Arc::clone(&as_path)),
            ..Default::default()
        });
        let b = store.intern(RouteAttributes {
            local_pref: Some(2),
            as4_path: Some(Arc::clone(&as_path)),
            ..Default::default()
        });

        // Distinct whole-attrs sets (different local_pref), but `as_path` and
        // `as4_path` share one interning pool, so content-equal segments
        // collapse to the same allocation regardless of which field they
        // came in on.
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(
            a.as_path.as_ref().unwrap(),
            b.as4_path.as_ref().unwrap()
        ));
    }

    #[test]
    fn intern_dedupes_cluster_list_and_communities_across_attrs() {
        let mut store = StrongAttrStore::new();
        let cluster_list: Arc<[Ipv4Addr]> = Arc::from(vec![Ipv4Addr::new(1, 1, 1, 1)]);
        let communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:100")]);

        let a = store.intern(RouteAttributes {
            local_pref: Some(1),
            cluster_list: Some(Arc::clone(&cluster_list)),
            communities: Some(Arc::clone(&communities)),
            ..Default::default()
        });
        let b = store.intern(RouteAttributes {
            local_pref: Some(2),
            cluster_list: Some(Arc::clone(&cluster_list)),
            communities: Some(Arc::clone(&communities)),
            ..Default::default()
        });

        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(
            a.cluster_list.as_ref().unwrap(),
            b.cluster_list.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            a.communities.as_ref().unwrap(),
            b.communities.as_ref().unwrap()
        ));
    }

    #[test]
    fn interner_wires_every_slice_field_to_its_pool() {
        fn assert_slice_fields_are_interned(interner: &mut impl crate::interner::AttrInterner) {
            let as_path: Arc<[AsPathSegment]> = Arc::from(vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                as_numbers: Box::new([65000]),
            }]);
            let cluster_list: Arc<[Ipv4Addr]> = Arc::from(vec![Ipv4Addr::new(1, 1, 1, 1)]);
            let communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:1")]);
            let ext_communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:2")]);
            let ext_communities_ipv6: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:3")]);
            let large_communities: Arc<[Box<str>]> = Arc::from(vec![Box::from("65000:4")]);

            let attrs = RouteAttributes {
                as_path: Some(Arc::clone(&as_path)),
                as4_path: Some(Arc::clone(&as_path)),
                cluster_list: Some(Arc::clone(&cluster_list)),
                communities: Some(Arc::clone(&communities)),
                ext_communities: Some(Arc::clone(&ext_communities)),
                ext_communities_ipv6: Some(Arc::clone(&ext_communities_ipv6)),
                large_communities: Some(Arc::clone(&large_communities)),
                ..Default::default()
            };
            let a = interner.intern(attrs.clone());
            let b = interner.intern(RouteAttributes {
                local_pref: Some(100),
                ..attrs
            });

            assert!(!Arc::ptr_eq(&a, &b));
            assert!(Arc::ptr_eq(
                a.as_path.as_ref().unwrap(),
                b.as_path.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.as4_path.as_ref().unwrap(),
                b.as4_path.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.as_path.as_ref().unwrap(),
                a.as4_path.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.cluster_list.as_ref().unwrap(),
                b.cluster_list.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.communities.as_ref().unwrap(),
                b.communities.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.ext_communities.as_ref().unwrap(),
                b.ext_communities.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.ext_communities_ipv6.as_ref().unwrap(),
                b.ext_communities_ipv6.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                a.large_communities.as_ref().unwrap(),
                b.large_communities.as_ref().unwrap()
            ));

            let community_fields = [
                a.communities.as_ref().unwrap(),
                a.ext_communities.as_ref().unwrap(),
                a.ext_communities_ipv6.as_ref().unwrap(),
                a.large_communities.as_ref().unwrap(),
            ];
            for i in 0..community_fields.len() {
                for j in i + 1..community_fields.len() {
                    assert!(!Arc::ptr_eq(community_fields[i], community_fields[j]));
                }
            }
        }

        assert_slice_fields_are_interned(&mut StrongAttrStore::new());
        assert_slice_fields_are_interned(&mut crate::interner::WeakAttrStore::default());
    }

    #[test]
    fn gc_evicts_sub_pools_only_after_the_whole_attrs_arc_is_dropped() {
        let mut store = StrongAttrStore::new();
        let as_path: Arc<[AsPathSegment]> = Arc::from(vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            as_numbers: Box::new([65000]),
        }]);
        let attrs = store.intern(RouteAttributes {
            as_path: Some(as_path),
            ..Default::default()
        });
        assert_eq!(store.as_path_pool_len(), 1);

        // `attrs` still references the sub-pool entry (through the store's
        // own whole-attrs copy), so neither gc pass may evict it yet.
        store.gc();
        assert_eq!(store.unique_attrs(), 1);
        assert_eq!(store.as_path_pool_len(), 1);

        drop(attrs);
        store.gc();
        assert_eq!(store.unique_attrs(), 0);
        assert_eq!(store.as_path_pool_len(), 0);
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
