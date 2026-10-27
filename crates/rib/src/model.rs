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
//! to, one peer).
//!
//! Each `(router, table, view)` owns ONE trie shared by every peer; a route
//! records the router-local [`PeerId`] it was learned from (`None` for
//! loc-rib paths).

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};
use rustc_hash::FxHashMap;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::Arc;

use netcalyx_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netcalyx_bmp_pkt::PeerKey;
use netcalyx_bmp_pkt::v4::{PathMarking, PathStatus};

use crate::attrs::RouteAttributes;
use crate::peers::PeerIndex;
use crate::types::{AfiSafiType, LabeledRouteExtra, RibContext, RibView, TableId};

/// Order in which views are stored; also the index of each [`RibView`].
pub const RIB_VIEWS: [RibView; 5] = [
    RibView::Loc,
    RibView::AdjOutPre,
    RibView::AdjOutPost,
    RibView::AdjInPost,
    RibView::AdjInPre,
];

#[inline]
fn view_index(view: RibView) -> usize {
    view as usize
}

/// Router-local peer handle; `Option<PeerId>` is 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(NonZeroU32);

impl PeerId {
    fn from_index(i: usize) -> Self {
        PeerId(NonZeroU32::new(i as u32 + 1).expect("peer id overflow"))
    }

    fn index(self) -> usize {
        self.0.get() as usize - 1
    }
}

/// Interns `PeerKey`s into dense, recyclable [`PeerId`]s.
#[derive(Default, Clone)]
pub struct PeerTable {
    keys: Vec<Option<PeerKey>>,
    ids: FxHashMap<PeerKey, PeerId>,
    free: Vec<PeerId>,
}

impl PeerTable {
    pub fn intern(&mut self, key: PeerKey) -> PeerId {
        if let Some(id) = self.ids.get(&key) {
            return *id;
        }
        let id = match self.free.pop() {
            Some(id) => {
                self.keys[id.index()] = Some(key);
                id
            }
            None => {
                self.keys.push(Some(key));
                PeerId::from_index(self.keys.len() - 1)
            }
        };
        self.ids.insert(key, id);
        id
    }

    pub fn id(&self, key: &PeerKey) -> Option<PeerId> {
        self.ids.get(key).copied()
    }

    pub fn key(&self, id: PeerId) -> Option<&PeerKey> {
        self.keys.get(id.index())?.as_ref()
    }

    pub fn release(&mut self, key: &PeerKey) -> Option<PeerId> {
        let id = self.ids.remove(key)?;
        self.keys[id.index()] = None;
        self.free.push(id);
        Some(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (PeerId, &PeerKey)> {
        self.keys
            .iter()
            .enumerate()
            .filter_map(|(i, k)| Some((PeerId::from_index(i), k.as_ref()?)))
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

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
    pub peer_index: PeerIndex<(RibContext, IpAddr), PeerId>,
    /// A single flat map of every table the router has
    pub tables: FxHashMap<TableId, Arc<AfiSafiTable>>,
    /// Peers known to this router, interned to router-local ids.
    pub peers: PeerTable,
}

impl RouterRib {
    /// Interns `key` and indexes its address for neighbor resolution.
    pub fn add_peer(&mut self, key: PeerKey) -> PeerId {
        let id = self.peers.intern(key);
        if let Some(addr) = key.peer_address() {
            self.peer_index
                .insert((RibContext::from(key.rd()), addr), id);
        }
        id
    }

    /// Peers `addr` resolves to within `context`.
    pub fn resolve_peer(&self, context: RibContext, addr: IpAddr) -> &[PeerId] {
        self.peer_index.get(&(context, addr))
    }

    /// Purges `key`'s paths from every table/view holding any, then forgets
    /// it. Returns the number of paths removed.
    pub fn remove_peer(&mut self, key: &PeerKey) -> usize {
        let Some(id) = self.peers.id(key) else {
            return 0;
        };
        let mut removed = 0;
        // Views are checked before they are made unique, so only tries that
        // hold the peer are deep-copied; the table shell itself is shallow.
        for table in self.tables.values_mut() {
            removed += Arc::make_mut(table).remove_peer(id);
        }
        if let Some(addr) = key.peer_address() {
            self.peer_index
                .remove(&(RibContext::from(key.rd()), addr), id);
        }
        self.peers.release(key);
        removed
    }

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

/// Behaviour every per-view container (`Routes`, `VpnRoutes`) provides so
/// [`AfiSafiRib`] can manage peers and counts generically.
pub trait RibTable: Default + Clone {
    fn path_count(&self) -> usize;
    fn prefix_count(&self) -> usize;
    fn has_peer(&self, peer: PeerId) -> bool;
    /// Removes every path learned from `peer`; returns how many.
    fn remove_peer(&mut self, peer: PeerId) -> usize;
    /// Adds the peer of every path to `out`.
    fn collect_peers(&self, out: &mut BTreeSet<PeerId>);
}

/// Per-router, per-AFI-SAFI RIB state: one trie per view, shared by all peers.
/// Each view is behind its own `Arc` so copy-on-write is per trie.
#[derive(Clone)]
pub struct AfiSafiRib<T: Clone> {
    views: [Option<Arc<T>>; 5],
}

impl<T: Clone> Default for AfiSafiRib<T> {
    fn default() -> Self {
        Self {
            views: Default::default(),
        }
    }
}

impl<T: Clone> AfiSafiRib<T> {
    /// Read access to a view; `None` until a route has been installed.
    pub fn view(&self, view: RibView) -> Option<&T> {
        self.views[view_index(view)].as_deref()
    }

    /// Read access to `loc_rib`.
    pub fn loc_rib_ref(&self) -> Option<&T> {
        self.view(RibView::Loc)
    }

    /// [`AfiSafiRib::view`] for callers holding the raw BMP `(post_policy,
    /// adj_rib_out)` flags.
    pub fn adj_rib_view_ref(&self, post_policy: bool, adj_rib_out: bool) -> Option<&T> {
        self.view(RibView::from_peer_flags(post_policy, adj_rib_out))
    }

    pub fn clear_view(&mut self, view: RibView) {
        self.views[view_index(view)] = None;
    }
}

impl<T: RibTable> AfiSafiRib<T> {
    /// Copy-on-write mutable access, allocating the view on first use.
    pub fn view_mut(&mut self, view: RibView) -> &mut T {
        Arc::make_mut(self.views[view_index(view)].get_or_insert_with(|| Arc::new(T::default())))
    }

    pub fn loc_rib_mut(&mut self) -> &mut T {
        self.view_mut(RibView::Loc)
    }

    /// [`AfiSafiRib::view_mut`] for callers holding the raw BMP `(post_policy,
    /// adj_rib_out)` flags.
    pub fn adj_rib_view_mut(&mut self, post_policy: bool, adj_rib_out: bool) -> &mut T {
        self.view_mut(RibView::from_peer_flags(post_policy, adj_rib_out))
    }

    /// Populated views, in [`RIB_VIEWS`] order.
    pub fn views_iter(&self) -> impl Iterator<Item = (RibView, &T)> {
        RIB_VIEWS
            .into_iter()
            .filter_map(|v| self.view(v).map(|t| (v, t)))
    }

    pub fn has_peer(&self, peer: PeerId) -> bool {
        self.views_iter().any(|(_, t)| t.has_peer(peer))
    }

    /// Purges `peer` from every view, dropping views left empty.
    pub fn remove_peer(&mut self, peer: PeerId) -> usize {
        let mut removed = 0;
        for view in &mut self.views {
            let Some(arc) = view else { continue };
            if !arc.has_peer(peer) {
                continue;
            }
            let table = Arc::make_mut(arc);
            removed += table.remove_peer(peer);
            if table.prefix_count() == 0 {
                *view = None;
            }
        }
        removed
    }

    /// Total path count across all views.
    pub fn route_count(&self) -> usize {
        self.views_iter().map(|(_, t)| t.path_count()).sum()
    }

    /// Total prefix (trie node) count across all views.
    pub fn prefix_count(&self) -> usize {
        self.views_iter().map(|(_, t)| t.prefix_count()).sum()
    }

    pub fn view_counts(&self) -> RibViewCounts {
        let mut out = RibViewCounts::default();
        for (view, t) in self.views_iter() {
            out.0[view_index(view)] = t.path_count();
        }
        out
    }

    /// Distinct peers holding a path in any view, in id order.
    pub fn peer_ids(&self) -> BTreeSet<PeerId> {
        let mut ids = BTreeSet::new();
        for (_, t) in self.views_iter() {
            t.collect_peers(&mut ids);
        }
        ids
    }
}

/// Path counts per RIB view, indexable via [`RibViewCounts::get`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RibViewCounts(pub [usize; 5]);

impl RibViewCounts {
    pub fn get(&self, view: RibView) -> usize {
        self.0[view_index(view)]
    }
}

/// All known paths for one prefix within an AFI-SAFI table.
#[derive(Debug, Clone)]
pub struct MultiRoute<E = ()> {
    // A plain Vec: paths are mutated in place on every update, which an
    // `Arc<[_]>` would turn into a reallocation per write.
    pub paths: Vec<Route<E>>,
}

impl<E> Default for MultiRoute<E> {
    fn default() -> Self {
        Self { paths: Vec::new() }
    }
}

impl<E> MultiRoute<E> {
    /// Inserts `route`, replacing the path with the same `(peer, path_id)`
    /// and returning it.
    pub fn upsert(&mut self, route: Route<E>) -> Option<Route<E>> {
        match self
            .paths
            .iter_mut()
            .find(|r| r.peer == route.peer && r.path_id == route.path_id)
        {
            Some(existing) => Some(std::mem::replace(existing, route)),
            None => {
                self.paths.push(route);
                None
            }
        }
    }

    pub fn remove(&mut self, peer: Option<PeerId>, path_id: u32) -> Option<Route<E>> {
        let pos = self
            .paths
            .iter()
            .position(|r| r.peer == peer && r.path_id == path_id)?;
        Some(self.paths.remove(pos))
    }

    /// Removes every path tagged `peer` (`None` = loc-rib paths).
    pub fn remove_all(&mut self, peer: Option<PeerId>) -> usize {
        let before = self.paths.len();
        self.paths.retain(|r| r.peer != peer);
        before - self.paths.len()
    }

    pub fn has_peer(&self, peer: PeerId) -> bool {
        self.paths.iter().any(|r| r.peer == Some(peer))
    }

    pub fn has(&self, peer: Option<PeerId>) -> bool {
        self.paths.iter().any(|r| r.peer == peer)
    }

    /// BEST > PRIMARY > lowest path-id, among paths tagged `peer`.
    pub fn active_path_of(&self, peer: Option<PeerId>) -> Option<&Route<E>> {
        let mine = || self.paths.iter().filter(move |r| r.peer == peer);
        mine()
            .find(|r| r.path_marking.path_status().contains(PathStatus::BEST))
            .or_else(|| mine().find(|r| r.path_marking.path_status().contains(PathStatus::PRIMARY)))
            .or_else(|| mine().min_by_key(|r| r.path_id))
    }
}

impl<E: Clone> MultiRoute<E> {
    /// Returns the "active" path for correlation, across all peers.
    /// Priority:
    /// 1. Path marked as BEST
    /// 2. Any path marked as PRIMARY (useful for ECMP)
    /// 3. Fallback to lowest Path-ID
    pub fn active_path(&self) -> Option<&Route<E>> {
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
    /// Peer the path was learned from; `None` for loc-rib paths.
    pub peer: Option<PeerId>,
    pub path_id: u32,
    /// BMP Path Marking Information
    pub path_marking: PathMarking,
    /// Extra attributes, only relevant for certain route types (e.g. labels)
    pub extra: E,
}

/// Routing table: one trie shared by every peer of a view.
#[derive(Debug, Clone)]
pub struct Routes<P: Prefix, E = ()> {
    pub routes: PrefixMap<P, MultiRoute<E>>,
}

pub type LabeledRoutes<P> = Routes<P, LabeledRouteExtra>;

impl<P: Prefix, E> Default for Routes<P, E> {
    fn default() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }
}

pub type VpnTrie<P> = PrefixMap<P, MultiRoute<LabeledRouteExtra>>;

/// One trie per route distinguisher, each behind its own `Arc` so a write to
/// one VRF does not clone the rest.
#[derive(Debug, Clone)]
pub struct VpnRoutes<P: Prefix> {
    pub tables: FxHashMap<RouteDistinguisher, Arc<VpnTrie<P>>>,
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
    pub fn table_ref(&self, rd: RouteDistinguisher) -> Option<&VpnTrie<P>> {
        self.tables.get(&rd).map(Arc::as_ref)
    }
}

impl<P: Prefix + Clone> VpnRoutes<P> {
    /// Copy-on-write mutable access to one RD's trie, allocating it on
    /// first use.
    pub fn table_mut(&mut self, rd: RouteDistinguisher) -> &mut VpnTrie<P> {
        Arc::make_mut(
            self.tables
                .entry(rd)
                .or_insert_with(|| Arc::new(PrefixMap::new())),
        )
    }
}

fn trie_has_peer<P: Prefix, E>(t: &PrefixMap<P, MultiRoute<E>>, peer: PeerId) -> bool {
    t.iter().any(|(_, m)| m.has_peer(peer))
}

fn trie_remove_peer<P: Prefix, E>(t: &mut PrefixMap<P, MultiRoute<E>>, peer: PeerId) -> usize {
    let mut removed = 0;
    for (_, m) in t.iter_mut() {
        removed += m.remove_all(Some(peer));
    }
    t.retain(|_, m| !m.paths.is_empty());
    removed
}

fn trie_collect_peers<P: Prefix, E>(t: &PrefixMap<P, MultiRoute<E>>, out: &mut BTreeSet<PeerId>) {
    for (_, m) in t {
        out.extend(m.paths.iter().filter_map(|r| r.peer));
    }
}

impl<P: Prefix + Clone, E: Clone> RibTable for Routes<P, E> {
    fn path_count(&self) -> usize {
        self.routes.iter().map(|(_, m)| m.paths.len()).sum()
    }
    fn prefix_count(&self) -> usize {
        self.routes.len()
    }
    fn has_peer(&self, peer: PeerId) -> bool {
        trie_has_peer(&self.routes, peer)
    }
    fn remove_peer(&mut self, peer: PeerId) -> usize {
        trie_remove_peer(&mut self.routes, peer)
    }
    fn collect_peers(&self, out: &mut BTreeSet<PeerId>) {
        trie_collect_peers(&self.routes, out)
    }
}

impl<P: Prefix + Clone> RibTable for VpnRoutes<P> {
    fn path_count(&self) -> usize {
        self.tables
            .values()
            .map(|t| t.iter().map(|(_, m)| m.paths.len()).sum::<usize>())
            .sum()
    }
    fn prefix_count(&self) -> usize {
        self.tables.values().map(|t| t.len()).sum()
    }
    fn has_peer(&self, peer: PeerId) -> bool {
        self.tables.values().any(|t| trie_has_peer(t, peer))
    }
    fn remove_peer(&mut self, peer: PeerId) -> usize {
        let mut removed = 0;
        self.tables.retain(|_, t| {
            if trie_has_peer(t, peer) {
                let t = Arc::make_mut(t);
                removed += trie_remove_peer(t, peer);
                !t.is_empty()
            } else {
                true
            }
        });
        removed
    }
    fn collect_peers(&self, out: &mut BTreeSet<PeerId>) {
        for t in self.tables.values() {
            trie_collect_peers(t, out);
        }
    }
}

// AfiSafiTable helpers

macro_rules! with_rib {
    ($self:expr, $f:ident => $body:expr) => {
        match $self {
            AfiSafiTable::Ipv4Unicast($f) => $body,
            AfiSafiTable::Ipv6Unicast($f) => $body,
            AfiSafiTable::Ipv4LabeledUnicast($f) => $body,
            AfiSafiTable::Ipv6LabeledUnicast($f) => $body,
            AfiSafiTable::L3VpnIpv4Unicast($f) => $body,
            AfiSafiTable::L3VpnIpv6Unicast($f) => $body,
        }
    };
}

impl AfiSafiTable {
    pub fn clear_loc_rib(&mut self) {
        with_rib!(self, f => f.clear_view(RibView::Loc))
    }

    pub fn has_peer(&self, peer: PeerId) -> bool {
        with_rib!(self, f => f.has_peer(peer))
    }

    /// Purges `peer` from every view; returns the number of paths removed.
    pub fn remove_peer(&mut self, peer: PeerId) -> usize {
        with_rib!(self, f => f.remove_peer(peer))
    }

    /// Total path count across all views.
    pub fn route_count(&self) -> usize {
        with_rib!(self, f => f.route_count())
    }

    /// Total prefix (trie node) count across all views.
    pub fn prefix_count(&self) -> usize {
        with_rib!(self, f => f.prefix_count())
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

    /// Path counts per RIB view.
    pub fn view_counts(&self) -> RibViewCounts {
        with_rib!(self, f => f.view_counts())
    }

    /// Distinct peers holding a path in this table.
    pub fn peer_ids(&self) -> BTreeSet<PeerId> {
        with_rib!(self, f => f.peer_ids())
    }
}

#[cfg(test)]
mod tests;
