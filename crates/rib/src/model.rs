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
//! (the local decision process's output: the best path, and optionally
//! backup/ECMP paths, tagged via path status) plus the four adj-ribs (`in`/
//! `out` x `pre`/`post` policy: what was received from, or is being advertised
//! to, one peer) held per peer in [`PeerRibs`].

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use netcalyx_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netcalyx_bmp_pkt::PeerKey;
use netcalyx_bmp_pkt::v4::PathMarking;

use crate::attrs::RouteAttributes;
use crate::peers::PeerIndex;
use crate::types::{AfiSafiType, LabeledRouteExtra, RibContext, RibView, TableId};

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
#[derive(Default, Clone)]
pub struct RouterRib {
    /// Resolves a neighbor address to its peer(s), scoped by RIB context (RD).
    pub peer_index: PeerIndex<(RibContext, IpAddr), PeerKey>,
    /// A single flat map of every table the router has
    pub tables: FxHashMap<TableId, Arc<AfiSafiTable>>,
}

impl RouterRib {
    /// Inserts a table, deriving its `TableId` from `table` itself so the map
    /// key can never disagree with the AFI-SAFI actually stored there.
    pub fn insert_table(&mut self, context: RibContext, table: AfiSafiTable) -> TableId {
        let table_id = TableId {
            context,
            afi_safi: table.afi_safi_type(),
        };
        self.tables.insert(table_id, Arc::new(table));
        table_id
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
    /// Read access to `loc_rib`; `None` until a route has been installed.
    pub fn loc_rib_ref(&self) -> Option<&T> {
        self.loc_rib.as_deref()
    }
}

impl<T: Default + Clone> AfiSafiRib<T> {
    /// Copy-on-write mutable access, allocating `loc_rib` on first use.
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

    /// Resolves a [`RibView`] to its field on this peer, the one accessor
    /// every view-keyed reader (lookup, introspection) should go through.
    /// `None` for `RibView::Loc` (not a `PeerRibs` field — see
    /// [`AfiSafiRib::loc_rib_ref`]) or for a view never populated here.
    pub fn view(&self, view: RibView) -> Option<&T> {
        match view {
            RibView::AdjInPre => self.adj_rib_in_pre_ref(),
            RibView::AdjInPost => self.adj_rib_in_post_ref(),
            RibView::AdjOutPre => self.adj_rib_out_pre_ref(),
            RibView::AdjOutPost => self.adj_rib_out_post_ref(),
            RibView::Loc => None,
        }
    }

    /// [`PeerRibs::view`] for callers holding the raw BMP `(post_policy,
    /// adj_rib_out)` flags instead of a [`RibView`].
    pub fn adj_rib_view_ref(&self, post_policy: bool, adj_rib_out: bool) -> Option<&T> {
        self.view(RibView::from_peer_flags(post_policy, adj_rib_out))
    }
}

impl<T: Default + Clone> PeerRibs<T> {
    /// Copy-on-write mutable counterpart to [`PeerRibs::view`], allocating
    /// the selected view on first use. `None` for `RibView::Loc`.
    pub fn view_mut(&mut self, view: RibView) -> Option<&mut T> {
        let slot = match view {
            RibView::AdjInPre => &mut self.adj_rib_in_pre,
            RibView::AdjInPost => &mut self.adj_rib_in_post,
            RibView::AdjOutPre => &mut self.adj_rib_out_pre,
            RibView::AdjOutPost => &mut self.adj_rib_out_post,
            RibView::Loc => return None,
        };
        Some(Arc::make_mut(
            slot.get_or_insert_with(|| Arc::new(T::default())),
        ))
    }

    /// [`PeerRibs::view_mut`] for callers holding the raw BMP `(post_policy,
    /// adj_rib_out)` flags instead of a [`RibView`]. Infallible: the flag
    /// conversion never yields `RibView::Loc`.
    pub fn adj_rib_view_mut(&mut self, post_policy: bool, adj_rib_out: bool) -> &mut T {
        self.view_mut(RibView::from_peer_flags(post_policy, adj_rib_out))
            .expect("from_peer_flags never returns RibView::Loc")
    }
}

/// All known paths for one prefix within an AFI-SAFI table.
#[derive(Debug, Clone)]
pub struct MultiRoute<E = ()> {
    // N=1 fits measured prod data where multipath is rare; if multipath grows, we could increase,
    // or if the growth is constrained only on some views make N a const generic here and split
    // loc_rib/peers in `AfiSafiRib` to size per-view.
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
pub struct Routes<P: Prefix> {
    pub routes: PrefixMap<P, MultiRoute>,
}

impl<P: Prefix> Default for Routes<P> {
    fn default() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LabeledRoutes<P: Prefix> {
    pub routes: PrefixMap<P, MultiRoute<LabeledRouteExtra>>,
}

impl<P: Prefix> Default for LabeledRoutes<P> {
    fn default() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }
}

/// One trie per route distinguisher, each behind its own `Arc` so a write to
/// one VRF does not clone the rest.
#[derive(Debug, Clone)]
pub struct VpnRoutes<P: Prefix> {
    pub tables: FxHashMap<RouteDistinguisher, Arc<PrefixMap<P, MultiRoute<LabeledRouteExtra>>>>,
}

impl<P: Prefix> Default for VpnRoutes<P> {
    fn default() -> Self {
        Self {
            tables: FxHashMap::default(),
        }
    }
}

impl<P: Prefix> VpnRoutes<P> {
    /// Read access to one RD's trie; `None` if never populated.
    pub fn table_ref(
        &self,
        rd: RouteDistinguisher,
    ) -> Option<&PrefixMap<P, MultiRoute<LabeledRouteExtra>>> {
        self.tables.get(&rd).map(Arc::as_ref)
    }
}

impl<P: Prefix + Clone> VpnRoutes<P> {
    /// Copy-on-write mutable access to one RD's trie, allocating it on
    /// first use.
    pub fn table_mut(
        &mut self,
        rd: RouteDistinguisher,
    ) -> &mut PrefixMap<P, MultiRoute<LabeledRouteExtra>> {
        Arc::make_mut(
            self.tables
                .entry(rd)
                .or_insert_with(|| Arc::new(PrefixMap::new())),
        )
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

fn count_paths<P: Prefix>(t: &Routes<P>) -> usize {
    t.routes.iter().map(|(_, m)| m.paths.len()).sum()
}

fn count_labeled_paths<P: Prefix>(t: &LabeledRoutes<P>) -> usize {
    t.routes.iter().map(|(_, m)| m.paths.len()).sum()
}

fn count_vpn_paths<P: Prefix>(t: &VpnRoutes<P>) -> usize {
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
mod tests;
