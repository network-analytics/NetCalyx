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

//! Prefix trie RIB (<https://github.com/tiborschneider/prefix-trie>) with
//! `Arc` + `make_mut` copy-on-write.
//!
//! `Arc` sits at four levels — `Arc<RouterRib>` in the store,
//! `Arc<AfiSafiTable>` per table, `Arc<T>` per RIB view, and `Arc<PrefixMap>`
//! per RD for VPN tables — so a write after a publish clones only the path down
//! to the one trie it touches. Every level above that trie is a shallow clone
//! of a map of `Arc`s; only the final `PrefixMap` is deep-copied.
//!
//! A "RIB view" is one of the five perspectives on a table's routes: `loc-rib`
//! (best-path selected) plus the four adj-ribs (`in`/`out` x `pre`/`post`
//! policy) held per peer in [`PeerRibs`].

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use netcalyx_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netcalyx_bmp_pkt::PeerKey;
use netcalyx_bmp_pkt::v4::PathMarking;

use crate::attrs::RouteAttributes;
use crate::peers::PeerIndex;
use crate::types::{AfiSafiType, LabeledRouteExtra, RibContext, TableId};

/// Resolves a neighbor address to a peer within one RIB context.
pub type PeerAddrIndex = PeerIndex<(RibContext, IpAddr), PeerKey>;

/// Main RIB store: maps router IPs to their RIBs.
#[derive(Default)]
pub struct RibStore {
    pub attr_store: crate::attrs::AttrStore,
    pub ribs: FxHashMap<IpAddr, Arc<RouterRib>>,
}

/// Per-router RIB.
///
/// `Arc` sits on each table and each RIB view, not just on `RouterRib`: a write
/// after a publish then clones only the one trie it touches, instead of every
/// trie the router owns.
#[derive(Default)]
pub struct RouterRib {
    /// A single flat map of every table the router has
    pub tables: FxHashMap<TableId, Arc<AfiSafiTable>>,
    pub peers_by_addr: PeerAddrIndex,
}

impl Clone for RouterRib {
    fn clone(&self) -> Self {
        Self {
            tables: self.tables.clone(),
            peers_by_addr: self.peers_by_addr.clone(),
        }
    }
}

/// A wrapper for any AFI-SAFI RIB
// TODO: extend for other afi-safi tables we want to support
#[derive(Clone)]
pub enum AfiSafiTable {
    Ipv4Unicast(AfiSafiRib<Routes<Ipv4Net>>),
    Ipv6Unicast(AfiSafiRib<Routes<Ipv6Net>>),
    Ipv4LabeledUnicast(AfiSafiRib<LabeledRoutes<Ipv4Net>>),
    Ipv6LabeledUnicast(AfiSafiRib<LabeledRoutes<Ipv6Net>>),
    L3VpnIpv4Unicast(AfiSafiRib<VpnRoutes<Ipv4Net>>),
    L3VpnIpv6Unicast(AfiSafiRib<VpnRoutes<Ipv6Net>>),
}

/// Per-router, per-AFI-SAFI RIB state. Each view is behind its own `Arc` so
/// copy-on-write is per trie.
#[derive(Clone)]
pub struct AfiSafiRib<T: Clone> {
    pub loc_rib: Option<Arc<T>>,
    pub peers: FxHashMap<PeerKey, PeerRibs<T>>,
}

impl<T: Clone> Default for AfiSafiRib<T> {
    fn default() -> Self {
        Self {
            loc_rib: None,
            peers: FxHashMap::default(),
        }
    }
}

impl<T: Clone> AfiSafiRib<T> {
    pub fn loc_rib_ref(&self) -> Option<&T> {
        self.loc_rib.as_deref()
    }
}

impl<T: Default + Clone> AfiSafiRib<T> {
    pub fn loc_rib_mut(&mut self) -> &mut T {
        Arc::make_mut(self.loc_rib.get_or_insert_with(|| Arc::new(T::default())))
    }
}

#[derive(Clone)]
pub struct PeerRibs<T: Clone> {
    pub adj_rib_in_pre: Option<Arc<T>>,
    pub adj_rib_in_post: Option<Arc<T>>,
    pub adj_rib_out_pre: Option<Arc<T>>,
    pub adj_rib_out_post: Option<Arc<T>>,
}

impl<T: Clone> Default for PeerRibs<T> {
    fn default() -> Self {
        Self {
            adj_rib_in_pre: None,
            adj_rib_in_post: None,
            adj_rib_out_pre: None,
            adj_rib_out_post: None,
        }
    }
}

impl<T: Clone> PeerRibs<T> {
    pub fn adj_rib_in_pre_ref(&self) -> Option<&T> {
        self.adj_rib_in_pre.as_deref()
    }
    pub fn adj_rib_in_post_ref(&self) -> Option<&T> {
        self.adj_rib_in_post.as_deref()
    }
    pub fn adj_rib_out_pre_ref(&self) -> Option<&T> {
        self.adj_rib_out_pre.as_deref()
    }
    pub fn adj_rib_out_post_ref(&self) -> Option<&T> {
        self.adj_rib_out_post.as_deref()
    }
}

impl<T: Default + Clone> PeerRibs<T> {
    pub fn adj_rib_view_mut(&mut self, post_policy: bool, adj_rib_out: bool) -> &mut T {
        let view = match (post_policy, adj_rib_out) {
            (false, false) => &mut self.adj_rib_in_pre,
            (true, false) => &mut self.adj_rib_in_post,
            (false, true) => &mut self.adj_rib_out_pre,
            (true, true) => &mut self.adj_rib_out_post,
        };
        Arc::make_mut(view.get_or_insert_with(|| Arc::new(T::default())))
    }
}

/// All known paths for one prefix within an AFI-SAFI table.
#[derive(Debug, Clone)]
pub struct MultiRoute<E = ()> {
    pub paths: SmallVec<[Route<E>; 1]>,
}

impl<E> Default for MultiRoute<E> {
    fn default() -> Self {
        Self {
            paths: SmallVec::default(),
        }
    }
}

impl<E: Clone> MultiRoute<E> {
    /// Returns the "active" path for correlation.
    /// Priority:
    /// 1. Path marked as BEST
    /// 2. Any path marked as PRIMARY (useful for ECMP)
    /// 3. Fallback to lowest Path-ID
    pub fn active_path(&self) -> Option<&Route<E>> {
        use netcalyx_bmp_pkt::v4::PathStatus;

        self.find_by_status(PathStatus::BEST)
            .or_else(|| self.find_by_status(PathStatus::PRIMARY))
            .or_else(|| self.lowest_id_path())
    }

    /// All traffic-carrying paths (ECMP).
    pub fn forwarding_paths(&self) -> impl Iterator<Item = &Route<E>> {
        self.filter_by_status(netcalyx_bmp_pkt::v4::PathStatus::PRIMARY)
    }

    /// Access a specific path by its BGP Path-ID
    pub fn find_by_path_id(&self, path_id: u32) -> Option<&Route<E>> {
        self.paths.iter().find(|r| r.path_id == path_id)
    }

    /// Returns the first path matching a specific status flag (e.g.,
    /// `PathStatus::BACKUP`). Use carefully if multiple paths might share
    /// the same status (like ECMP).
    pub fn find_by_status(&self, status: netcalyx_bmp_pkt::v4::PathStatus) -> Option<&Route<E>> {
        self.paths
            .iter()
            .find(|r| r.path_marking.path_status().contains(status))
    }

    /// Returns an iterator over all paths matching a specific status bitmask
    pub fn filter_by_status(
        &self,
        status: netcalyx_bmp_pkt::v4::PathStatus,
    ) -> impl Iterator<Item = &Route<E>> {
        self.paths
            .iter()
            .filter(move |r| r.path_marking.path_status().contains(status))
    }

    /// Returns the route with the lowest numerical path-id (RFC 7911).
    /// Used as a deterministic fallback when best-path metadata is missing.
    pub fn lowest_id_path(&self) -> Option<&Route<E>> {
        self.paths.iter().min_by_key(|r| r.path_id)
    }

    /// Check if any path for this prefix is marked as Invalid
    pub fn has_invalid_path(&self) -> bool {
        self.paths.iter().any(|r| {
            r.path_marking
                .path_status()
                .contains(netcalyx_bmp_pkt::v4::PathStatus::INVALID)
        })
    }
}

/// Generic route node
#[derive(Debug, Clone)]
pub struct Route<E = ()> {
    pub attrs: Arc<RouteAttributes>,
    pub path_id: u32,
    /// BMP Path Marking Information
    pub path_marking: PathMarking,
    /// Extra attributes, only relevant for certain route types (e.g. labels)
    pub extra: E,
}

// Routing table types
#[derive(Debug, Clone)]
pub struct Routes<P: prefix_trie::Prefix> {
    pub routes: PrefixMap<P, MultiRoute>,
}

impl<P: prefix_trie::Prefix> Default for Routes<P> {
    fn default() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LabeledRoutes<P: prefix_trie::Prefix> {
    pub routes: PrefixMap<P, MultiRoute<LabeledRouteExtra>>,
}

impl<P: prefix_trie::Prefix> Default for LabeledRoutes<P> {
    fn default() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }
}

/// One trie per route distinguisher, each behind its own `Arc` so a write to
/// one VRF does not clone the rest.
#[derive(Debug, Clone)]
pub struct VpnRoutes<P: prefix_trie::Prefix> {
    pub tables: FxHashMap<RouteDistinguisher, Arc<PrefixMap<P, MultiRoute<LabeledRouteExtra>>>>,
}

impl<P: prefix_trie::Prefix> Default for VpnRoutes<P> {
    fn default() -> Self {
        Self {
            tables: FxHashMap::default(),
        }
    }
}

impl MultiRoute<LabeledRouteExtra> {
    /// Find a path matching a specific label set (works for both MPLS and SRv6
    /// variants)
    pub fn find_by_labels(&self, labels: &[MplsLabel]) -> Option<&Route<LabeledRouteExtra>> {
        self.paths.iter().find(|r| match &r.extra {
            LabeledRouteExtra::Mpls(s) => s.as_ref() == labels,
            LabeledRouteExtra::Srv6(s) => s.label_stack.as_ref() == labels,
        })
    }

    /// Find a path matching a specific SRv6 SID
    pub fn find_by_srv6_sid(&self, sid: Ipv6Addr) -> Option<&Route<LabeledRouteExtra>> {
        self.paths.iter().find(|r| match &r.extra {
            LabeledRouteExtra::Srv6(s) => s.sid == sid,
            _ => false,
        })
    }
}

// AfiSafiTable helpers

impl AfiSafiTable {
    pub fn clear_loc_rib(&mut self) {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => f.loc_rib = None,
            AfiSafiTable::Ipv6Unicast(f) => f.loc_rib = None,
            AfiSafiTable::Ipv4LabeledUnicast(f) => f.loc_rib = None,
            AfiSafiTable::Ipv6LabeledUnicast(f) => f.loc_rib = None,
            AfiSafiTable::L3VpnIpv4Unicast(f) => f.loc_rib = None,
            AfiSafiTable::L3VpnIpv6Unicast(f) => f.loc_rib = None,
        }
    }

    pub fn remove_peer(&mut self, peer_key: &PeerKey) {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => {
                f.peers.remove(peer_key);
            }
            AfiSafiTable::Ipv6Unicast(f) => {
                f.peers.remove(peer_key);
            }
            AfiSafiTable::Ipv4LabeledUnicast(f) => {
                f.peers.remove(peer_key);
            }
            AfiSafiTable::Ipv6LabeledUnicast(f) => {
                f.peers.remove(peer_key);
            }
            AfiSafiTable::L3VpnIpv4Unicast(f) => {
                f.peers.remove(peer_key);
            }
            AfiSafiTable::L3VpnIpv6Unicast(f) => {
                f.peers.remove(peer_key);
            }
        }
    }

    /// Total path count across loc_rib and all peer adj-rib views.
    pub fn route_count(&self) -> usize {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => count_rib_routes(f, count_paths),
            AfiSafiTable::Ipv6Unicast(f) => count_rib_routes(f, count_paths),
            AfiSafiTable::Ipv4LabeledUnicast(f) => count_rib_routes(f, count_labeled_paths),
            AfiSafiTable::Ipv6LabeledUnicast(f) => count_rib_routes(f, count_labeled_paths),
            AfiSafiTable::L3VpnIpv4Unicast(f) => count_rib_routes(f, count_vpn_paths),
            AfiSafiTable::L3VpnIpv6Unicast(f) => count_rib_routes(f, count_vpn_paths),
        }
    }

    /// Total prefix (trie node) count across loc_rib and all peer adj-rib
    /// views.
    pub fn prefix_count(&self) -> usize {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => count_rib_routes(f, |t| t.routes.len()),
            AfiSafiTable::Ipv6Unicast(f) => count_rib_routes(f, |t| t.routes.len()),
            AfiSafiTable::Ipv4LabeledUnicast(f) => count_rib_routes(f, |t| t.routes.len()),
            AfiSafiTable::Ipv6LabeledUnicast(f) => count_rib_routes(f, |t| t.routes.len()),
            AfiSafiTable::L3VpnIpv4Unicast(f) => count_rib_routes(f, |t: &VpnRoutes<_>| {
                t.tables.values().map(|m| m.len()).sum()
            }),
            AfiSafiTable::L3VpnIpv6Unicast(f) => count_rib_routes(f, |t: &VpnRoutes<_>| {
                t.tables.values().map(|m| m.len()).sum()
            }),
        }
    }

    pub fn afi_safi_type(&self) -> AfiSafiType {
        match self {
            AfiSafiTable::Ipv4Unicast(_) => AfiSafiType::Ipv4Unicast,
            AfiSafiTable::Ipv6Unicast(_) => AfiSafiType::Ipv6Unicast,
            AfiSafiTable::Ipv4LabeledUnicast(_) => AfiSafiType::Ipv4LabeledUnicast,
            AfiSafiTable::Ipv6LabeledUnicast(_) => AfiSafiType::Ipv6LabeledUnicast,
            AfiSafiTable::L3VpnIpv4Unicast(_) => AfiSafiType::L3VpnIpv4Unicast,
            AfiSafiTable::L3VpnIpv6Unicast(_) => AfiSafiType::L3VpnIpv6Unicast,
        }
    }

    /// Entries per RIB view.
    pub fn view_counts(&self) -> RibViewCounts {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => view_counts_of(f, count_paths),
            AfiSafiTable::Ipv6Unicast(f) => view_counts_of(f, count_paths),
            AfiSafiTable::Ipv4LabeledUnicast(f) => view_counts_of(f, count_labeled_paths),
            AfiSafiTable::Ipv6LabeledUnicast(f) => view_counts_of(f, count_labeled_paths),
            AfiSafiTable::L3VpnIpv4Unicast(f) => view_counts_of(f, count_vpn_paths),
            AfiSafiTable::L3VpnIpv6Unicast(f) => view_counts_of(f, count_vpn_paths),
        }
    }

    pub fn peer_keys(&self) -> Vec<PeerKey> {
        match self {
            AfiSafiTable::Ipv4Unicast(f) => f.peers.keys().copied().collect(),
            AfiSafiTable::Ipv6Unicast(f) => f.peers.keys().copied().collect(),
            AfiSafiTable::Ipv4LabeledUnicast(f) => f.peers.keys().copied().collect(),
            AfiSafiTable::Ipv6LabeledUnicast(f) => f.peers.keys().copied().collect(),
            AfiSafiTable::L3VpnIpv4Unicast(f) => f.peers.keys().copied().collect(),
            AfiSafiTable::L3VpnIpv6Unicast(f) => f.peers.keys().copied().collect(),
        }
    }
}

fn count_paths<P: prefix_trie::Prefix>(t: &Routes<P>) -> usize {
    t.routes.iter().map(|(_, m)| m.paths.len()).sum()
}

fn count_labeled_paths<P: prefix_trie::Prefix>(t: &LabeledRoutes<P>) -> usize {
    t.routes.iter().map(|(_, m)| m.paths.len()).sum()
}

fn count_vpn_paths<P: prefix_trie::Prefix>(t: &VpnRoutes<P>) -> usize {
    t.tables
        .values()
        .map(|m| m.iter().map(|(_, r)| r.paths.len()).sum::<usize>())
        .sum()
}

fn count_rib_routes<T: Clone>(rib: &AfiSafiRib<T>, count: impl Fn(&T) -> usize + Copy) -> usize {
    let loc = rib.loc_rib_ref().map(count).unwrap_or(0);
    let peers: usize = rib
        .peers
        .values()
        .map(|pr| {
            pr.adj_rib_in_pre_ref().map(count).unwrap_or(0)
                + pr.adj_rib_in_post_ref().map(count).unwrap_or(0)
                + pr.adj_rib_out_pre_ref().map(count).unwrap_or(0)
                + pr.adj_rib_out_post_ref().map(count).unwrap_or(0)
        })
        .sum();
    loc + peers
}

/// Entries per RIB view: `loc-rib` plus the four adj-ribs, summed over every
/// peer for the adj-rib side.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RibViewCounts {
    pub loc: usize,
    pub adj_out_pre: usize,
    pub adj_out_post: usize,
    pub adj_in_post: usize,
    pub adj_in_pre: usize,
}

fn view_counts_of<T: Clone>(
    rib: &AfiSafiRib<T>,
    count: impl Fn(&T) -> usize + Copy,
) -> RibViewCounts {
    let mut out = RibViewCounts {
        loc: rib.loc_rib_ref().map(count).unwrap_or(0),
        ..Default::default()
    };
    for pr in rib.peers.values() {
        out.adj_out_pre += pr.adj_rib_out_pre_ref().map(count).unwrap_or(0);
        out.adj_out_post += pr.adj_rib_out_post_ref().map(count).unwrap_or(0);
        out.adj_in_post += pr.adj_rib_in_post_ref().map(count).unwrap_or(0);
        out.adj_in_pre += pr.adj_rib_in_pre_ref().map(count).unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use netcalyx_bmp_pkt::BmpPeerType;
    use netcalyx_bmp_pkt::v4::PathStatus;

    use super::*;
    use crate::types::Srv6RouteExtra;

    fn route(local_pref: u32) -> Route {
        Route {
            attrs: Arc::new(RouteAttributes {
                local_pref: Some(local_pref),
                ..Default::default()
            }),
            path_id: 0,
            path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
            extra: (),
        }
    }

    fn labeled_route() -> Route<LabeledRouteExtra> {
        Route {
            attrs: Arc::new(RouteAttributes::default()),
            path_id: 0,
            path_marking: PathMarking::new(PathStatus::BEST, None),
            extra: LabeledRouteExtra::default(),
        }
    }

    fn peer_key(asn: u32) -> PeerKey {
        PeerKey::new(
            None,
            BmpPeerType::GlobalInstancePeer {
                ipv6: false,
                post_policy: false,
                asn2: false,
                adj_rib_out: false,
            },
            None,
            asn,
            Ipv4Addr::new(1, 1, 1, 1),
        )
    }

    #[test]
    fn router_rib_default_is_empty() {
        let rib = RouterRib::default();
        assert!(rib.tables.is_empty());
        assert!(rib.peers_by_addr.is_empty());
    }

    #[test]
    fn loc_rib_mut_inserts_into_fresh_table_and_counts_are_consistent() {
        let mut table = AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default());
        let AfiSafiTable::Ipv4Unicast(rib) = &mut table else {
            unreachable!()
        };
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        rib.loc_rib_mut().routes.insert(
            prefix,
            MultiRoute {
                paths: [route(100)].into(),
            },
        );

        assert_eq!(table.route_count(), 1);
        assert_eq!(table.prefix_count(), 1);
        assert_eq!(
            table.view_counts(),
            RibViewCounts {
                loc: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn clear_loc_rib_removes_loc_rib_only() {
        let mut table = AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default());
        let AfiSafiTable::Ipv4Unicast(rib) = &mut table else {
            unreachable!()
        };
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        rib.loc_rib_mut().routes.insert(
            prefix,
            MultiRoute {
                paths: [route(100)].into(),
            },
        );

        table.clear_loc_rib();
        assert_eq!(table.route_count(), 0);
    }

    #[test]
    fn multi_route_active_path_prefers_best_over_lowest_id() {
        let best = Route {
            path_id: 5,
            path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
            ..route(100)
        };
        let other = Route {
            path_id: 1,
            path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::empty(), None),
            ..route(200)
        };
        let multi = MultiRoute {
            paths: SmallVec::from_vec(vec![other, best]),
        };
        assert_eq!(multi.active_path().unwrap().path_id, 5);
    }

    #[test]
    fn active_path_falls_back_to_lowest_id_when_nothing_is_best_or_primary() {
        let a = Route {
            path_id: 5,
            path_marking: PathMarking::new(PathStatus::empty(), None),
            ..route(100)
        };
        let b = Route {
            path_id: 2,
            path_marking: PathMarking::new(PathStatus::empty(), None),
            ..route(100)
        };
        let multi = MultiRoute {
            paths: SmallVec::from_vec(vec![a, b]),
        };
        assert_eq!(multi.active_path().unwrap().path_id, 2);
    }

    #[test]
    fn find_by_path_id_returns_the_matching_route() {
        let a = Route {
            path_id: 1,
            ..route(100)
        };
        let b = Route {
            path_id: 2,
            ..route(100)
        };
        let multi = MultiRoute {
            paths: SmallVec::from_vec(vec![a, b]),
        };
        assert_eq!(multi.find_by_path_id(2).unwrap().path_id, 2);
        assert!(multi.find_by_path_id(3).is_none());
    }

    #[test]
    fn filter_by_status_returns_every_primary_path_for_ecmp() {
        let make = |path_id, status| Route {
            path_id,
            path_marking: PathMarking::new(status, None),
            ..route(100)
        };
        let multi = MultiRoute {
            paths: SmallVec::from_vec(vec![
                make(1, PathStatus::PRIMARY),
                make(2, PathStatus::PRIMARY),
                make(3, PathStatus::BACKUP),
            ]),
        };
        let ids: Vec<u32> = multi.forwarding_paths().map(|r| r.path_id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn has_invalid_path_detects_any_path_marked_invalid() {
        let clean = MultiRoute {
            paths: SmallVec::from_vec(vec![Route {
                path_marking: PathMarking::new(PathStatus::BEST, None),
                ..route(100)
            }]),
        };
        assert!(!clean.has_invalid_path());

        let with_invalid = MultiRoute {
            paths: SmallVec::from_vec(vec![
                Route {
                    path_marking: PathMarking::new(PathStatus::BEST, None),
                    ..route(100)
                },
                Route {
                    path_id: 2,
                    path_marking: PathMarking::new(PathStatus::INVALID, None),
                    ..route(100)
                },
            ]),
        };
        assert!(with_invalid.has_invalid_path());
    }

    #[test]
    fn find_by_labels_and_srv6_sid_match_the_right_variant() {
        let mpls_route = Route {
            extra: LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, 1])])),
            ..labeled_route()
        };
        let srv6_route = Route {
            path_id: 2,
            extra: LabeledRouteExtra::Srv6(Box::new(Srv6RouteExtra {
                sid: Ipv6Addr::LOCALHOST,
                endpoint_behaviour: 0,
                label_stack: Box::new([MplsLabel::new([0, 0, 2])]),
            })),
            ..labeled_route()
        };
        let multi = MultiRoute {
            paths: SmallVec::from_vec(vec![mpls_route, srv6_route]),
        };

        assert_eq!(
            multi
                .find_by_labels(&[MplsLabel::new([0, 0, 1])])
                .unwrap()
                .path_id,
            0
        );
        assert_eq!(
            multi.find_by_srv6_sid(Ipv6Addr::LOCALHOST).unwrap().path_id,
            2
        );
        assert!(multi.find_by_srv6_sid(Ipv6Addr::UNSPECIFIED).is_none());
    }

    #[test]
    fn router_rib_clone_shares_table_and_view_arcs_until_write_touches_them() {
        let table_id = TableId {
            context: RibContext::Global,
            afi_safi: AfiSafiType::Ipv4Unicast,
        };
        let peer = peer_key(1);

        // Seed two views before publishing: loc-rib and one peer's
        // adj-rib-in-pre.
        let mut table = AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default());
        {
            let AfiSafiTable::Ipv4Unicast(rib) = &mut table else {
                unreachable!()
            };
            let loc_prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
            rib.loc_rib_mut().routes.insert(
                loc_prefix,
                MultiRoute {
                    paths: [route(100)].into(),
                },
            );
            let adj_prefix: Ipv4Net = "10.0.1.0/24".parse().unwrap();
            rib.peers
                .entry(peer)
                .or_default()
                .adj_rib_view_mut(false, false)
                .routes
                .insert(
                    adj_prefix,
                    MultiRoute {
                        paths: [route(100)].into(),
                    },
                );
        }

        let mut original = RouterRib::default();
        original.tables.insert(table_id, Arc::new(table));

        let mut published = original.clone();
        assert!(Arc::ptr_eq(
            original.tables.get(&table_id).unwrap(),
            published.tables.get(&table_id).unwrap()
        ));
        assert_eq!(
            Arc::strong_count(original.tables.get(&table_id).unwrap()),
            2
        );

        // Table-level publish clones only the outer Arc; both views are
        // still shared with `original` at this point.
        let AfiSafiTable::Ipv4Unicast(pub_rib) =
            Arc::make_mut(published.tables.get_mut(&table_id).unwrap())
        else {
            unreachable!()
        };
        let AfiSafiTable::Ipv4Unicast(orig_rib) = original.tables.get(&table_id).unwrap().as_ref()
        else {
            unreachable!()
        };
        let loc_before = Arc::clone(pub_rib.loc_rib.as_ref().unwrap());
        let adj_before = Arc::clone(pub_rib.peers[&peer].adj_rib_in_pre.as_ref().unwrap());
        assert!(Arc::ptr_eq(&loc_before, orig_rib.loc_rib.as_ref().unwrap()));
        assert!(Arc::ptr_eq(
            &adj_before,
            orig_rib.peers[&peer].adj_rib_in_pre.as_ref().unwrap()
        ));

        // Write to loc-rib only, through `published`.
        let new_prefix: Ipv4Net = "10.0.2.0/24".parse().unwrap();
        pub_rib.loc_rib_mut().routes.insert(
            new_prefix,
            MultiRoute {
                paths: [route(100)].into(),
            },
        );

        // The touched view is now private, and `original` never sees the write.
        assert!(!Arc::ptr_eq(pub_rib.loc_rib.as_ref().unwrap(), &loc_before));
        assert_eq!(orig_rib.loc_rib_ref().unwrap().routes.len(), 1);
        assert_eq!(pub_rib.loc_rib_ref().unwrap().routes.len(), 2);

        // The untouched view is still the exact same Arc as before the write.
        assert!(Arc::ptr_eq(
            pub_rib.peers[&peer].adj_rib_in_pre.as_ref().unwrap(),
            &adj_before
        ));
    }

    #[test]
    fn adj_rib_view_mut_and_view_counts_attribute_each_view_correctly() {
        let mut table = AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default());
        let AfiSafiTable::Ipv4Unicast(rib) = &mut table else {
            unreachable!()
        };
        let peer_ribs = rib.peers.entry(peer_key(1)).or_default();
        let insert = |view: &mut Routes<Ipv4Net>, octet: u8| {
            let prefix: Ipv4Net = format!("10.0.{octet}.0/24").parse().unwrap();
            view.routes.insert(
                prefix,
                MultiRoute {
                    paths: [route(100)].into(),
                },
            );
        };
        insert(peer_ribs.adj_rib_view_mut(false, false), 1); // adj_rib_in_pre
        insert(peer_ribs.adj_rib_view_mut(true, false), 2); // adj_rib_in_post
        insert(peer_ribs.adj_rib_view_mut(false, true), 3); // adj_rib_out_pre
        insert(peer_ribs.adj_rib_view_mut(true, true), 4); // adj_rib_out_post

        assert_eq!(
            table.view_counts(),
            RibViewCounts {
                loc: 0,
                adj_in_pre: 1,
                adj_in_post: 1,
                adj_out_pre: 1,
                adj_out_post: 1,
            }
        );
        assert_eq!(table.route_count(), 4);
    }

    #[test]
    fn vpn_route_and_prefix_counts_sum_across_route_distinguishers() {
        let mut table = AfiSafiTable::L3VpnIpv4Unicast(AfiSafiRib::<VpnRoutes<Ipv4Net>>::default());
        let AfiSafiTable::L3VpnIpv4Unicast(rib) = &mut table else {
            unreachable!()
        };
        let rd_a = RouteDistinguisher::As2Administrator { asn2: 1, number: 1 };
        let rd_b = RouteDistinguisher::As2Administrator { asn2: 2, number: 2 };
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();

        let vpn = rib.loc_rib_mut();
        vpn.tables
            .entry(rd_a)
            .or_insert_with(|| Arc::new(PrefixMap::new()));
        Arc::make_mut(vpn.tables.get_mut(&rd_a).unwrap()).insert(
            prefix,
            MultiRoute {
                paths: [labeled_route()].into(),
            },
        );
        vpn.tables
            .entry(rd_b)
            .or_insert_with(|| Arc::new(PrefixMap::new()));
        Arc::make_mut(vpn.tables.get_mut(&rd_b).unwrap()).insert(
            prefix,
            MultiRoute {
                paths: SmallVec::from_vec(vec![labeled_route(), labeled_route()]),
            },
        );

        assert_eq!(table.prefix_count(), 2); // one trie node per RD
        assert_eq!(table.route_count(), 3); // 1 + 2 paths
    }

    #[test]
    fn remove_peer_and_peer_keys_reflect_current_membership() {
        let mut table = AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default());
        let AfiSafiTable::Ipv4Unicast(rib) = &mut table else {
            unreachable!()
        };
        let peer_a = peer_key(1);
        let peer_b = peer_key(2);
        rib.peers.insert(peer_a, PeerRibs::default());
        rib.peers.insert(peer_b, PeerRibs::default());
        assert_eq!(table.peer_keys().len(), 2);

        table.remove_peer(&peer_a);
        assert_eq!(table.peer_keys(), vec![peer_b]);
    }

    #[test]
    fn afi_safi_type_matches_the_table_variant() {
        let table = AfiSafiTable::L3VpnIpv6Unicast(AfiSafiRib::default());
        assert_eq!(table.afi_safi_type(), AfiSafiType::L3VpnIpv6Unicast);
    }

    #[test]
    fn rib_store_default_is_empty() {
        let store = RibStore::default();
        assert!(store.ribs.is_empty());
        assert_eq!(store.attr_store.unique_attrs(), 0);
    }
}
