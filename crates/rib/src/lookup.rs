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

//! LPM lookup: resolving one address against `(context, afi-safi)` into the
//! best-matching route.
//!
//! A lookup tries [`RibView`]s in precedence order (`loc-rib` first, then the
//! adj-ribs) and, within an adj-rib view, resolves the flow's neighbor address
//! to a peer through [`PeerAddrIndex`](crate::PeerAddrIndex) rather than
//! scanning every peer. When an address is ambiguous (ties to several
//! candidates) or no neighbor was given at all, the result is the lowest
//! `(peer_address, bgp_id)` among the peers that have a match — arbitrary, but
//! deterministic across calls.
//!
//! A lookup returns one [`Match`]: the active path (best, else primary, else
//! lowest path-id) of the first view with a hit, plus the peer that answered
//! (`Match::peer`, `None` for loc-rib).

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use netcalyx_bgp_pkt::nlri::RouteDistinguisher;
use netcalyx_bmp_pkt::PeerKey;

use crate::attrs::RouteAttributes;
use crate::model::{
    AfiSafiRib, AfiSafiTable, LabeledRoutes, MultiRoute, PeerRibs, Route, RouterRib, Routes,
    VpnRoutes,
};
use crate::types::{AfiSafiType, LabeledRouteExtra, RibContext, RibView, TableId};

// RIB views and their precedence

/// Order in which views are consulted for a lookup: loc-rib is authoritative,
/// otherwise fall back to the nearest available view.
pub const DEFAULT_VIEW_ORDER: [RibView; 5] = [
    RibView::Loc,
    RibView::AdjOutPre,
    RibView::AdjOutPost,
    RibView::AdjInPost,
    RibView::AdjInPre,
];

// Lookup addressing

/// Complete address of one trie. The caller derives this from flow fields
/// (in-RD / out-RD / direction); the RIB never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LookupTarget {
    pub context: RibContext,
    pub afi_safi: AfiSafiType,
    /// NLRI route distinguisher, for the per-RD tries of the L3VPN families.
    pub rd: Option<RouteDistinguisher>,
}

impl LookupTarget {
    pub fn new(context: RibContext, afi_safi: AfiSafiType) -> Self {
        Self {
            context,
            afi_safi,
            rd: None,
        }
    }

    pub fn with_rd(mut self, rd: RouteDistinguisher) -> Self {
        self.rd = Some(rd);
        self
    }

    pub fn table_id(&self) -> TableId {
        TableId {
            context: self.context,
            afi_safi: self.afi_safi,
        }
    }
}

/// A single address lookup against one router's RIB.
pub struct LookupRequest<'a> {
    /// The address being resolved: a flow's source or destination, whichever
    /// this request is for.
    pub addr: IpAddr,
    /// Resolves which peer's adj-rib to read; unused when the match comes from
    /// loc-rib.
    pub neighbor: Option<IpAddr>,
    /// Tried in order; first hit wins. Array because one address can be
    /// valid in more than one context — e.g. look up in a VRF first, then
    /// fall back to the global table for L3vpn routes.
    pub targets: &'a [LookupTarget],
    pub view_order: &'a [RibView],
}

impl<'a> LookupRequest<'a> {
    pub fn new(addr: IpAddr, targets: &'a [LookupTarget]) -> Self {
        Self {
            addr,
            neighbor: None,
            targets,
            view_order: &DEFAULT_VIEW_ORDER,
        }
    }

    pub fn neighbor(mut self, neighbor: Option<IpAddr>) -> Self {
        self.neighbor = neighbor;
        self
    }

    pub fn view_order(mut self, order: &'a [RibView]) -> Self {
        self.view_order = order;
        self
    }
}

/// What a lookup returns: the active path (see [`MultiRoute::active_path`])
/// of the first [`RibView`] with a hit.
pub struct Match {
    /// The trie node that matched, i.e. the LPM result.
    pub prefix: IpNet,
    /// Path attributes of the active path.
    pub attrs: Arc<RouteAttributes>,
    /// Forwarding information (MPLS label stack / SRv6 SID); `None` for
    /// unlabeled families.
    pub extra: Option<LabeledRouteExtra>,
    /// BGP Path-ID of the active path.
    pub path_id: u32,
    /// Which of the five views answered.
    pub view: RibView,
    /// The `(context, afi-safi[, rd])` the match came from, echoed back for
    /// callers juggling more than one target per lookup.
    pub target: LookupTarget,
    /// The peer whose adj-rib answered; `None` when `view` is `RibView::Loc`.
    /// Lets callers locate the exact PeerRib that matched.
    pub peer: Option<PeerKey>,
}

/// Lets a generic route payload expose its labeled forwarding info, if any.
pub trait RouteExtra {
    fn as_labeled(&self) -> Option<&LabeledRouteExtra>;
}

impl RouteExtra for () {
    fn as_labeled(&self) -> Option<&LabeledRouteExtra> {
        None
    }
}

impl RouteExtra for LabeledRouteExtra {
    fn as_labeled(&self) -> Option<&LabeledRouteExtra> {
        Some(self)
    }
}

// Lookup

/// Try every target in order against one router's RIB; the first hit wins.
pub fn lookup(rib: &RouterRib, req: &LookupRequest<'_>) -> Option<Match> {
    req.targets
        .iter()
        .find_map(|target| lookup_target(rib, target, req.addr, req.neighbor, req.view_order))
}

fn lookup_target<'a>(
    rib: &'a RouterRib,
    target: &LookupTarget,
    addr: IpAddr,
    neighbor: Option<IpAddr>,
    view_order: &[RibView],
) -> Option<Match> {
    let table = rib.tables.get(&target.table_id())?.as_ref();
    let neighbor_peers = neighbor.map(|a| rib.peers_by_addr.get(&(target.context, a)));

    match (table, addr) {
        (AfiSafiTable::Ipv4Unicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let hit = lookup_views(r, neighbor_peers, view_order, |t: &'a Routes<Ipv4Net>| {
                t.routes.get_lpm(&net)
            })?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv6Unicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let hit = lookup_views(r, neighbor_peers, view_order, |t: &'a Routes<Ipv6Net>| {
                t.routes.get_lpm(&net)
            })?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv4LabeledUnicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let hit = lookup_views(
                r,
                neighbor_peers,
                view_order,
                |t: &'a LabeledRoutes<Ipv4Net>| t.routes.get_lpm(&net),
            )?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv6LabeledUnicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let hit = lookup_views(
                r,
                neighbor_peers,
                view_order,
                |t: &'a LabeledRoutes<Ipv6Net>| t.routes.get_lpm(&net),
            )?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::L3VpnIpv4Unicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let rd = target.rd?;
            let hit = lookup_views(
                r,
                neighbor_peers,
                view_order,
                |t: &'a VpnRoutes<Ipv4Net>| t.tables.get(&rd)?.get_lpm(&net),
            )?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::L3VpnIpv6Unicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let rd = target.rd?;
            let hit = lookup_views(
                r,
                neighbor_peers,
                view_order,
                |t: &'a VpnRoutes<Ipv6Net>| t.tables.get(&rd)?.get_lpm(&net),
            )?;
            Some(to_match(hit, target))
        }
        _ => None,
    }
}

type ViewHit<'a, P, E> = (Option<PeerKey>, P, &'a Route<E>, RibView);

/// Walk the views in precedence order, returning the first active path found.
/// Each view is tried in full (LPM, then active-path selection) before
/// moving to the next; a view only counts as a hit once both succeed, so a
/// prefix match with no active path falls through to the next view.
fn lookup_views<'a, T, P, E>(
    rib: &'a AfiSafiRib<T>,
    neighbor_peers: Option<&[PeerKey]>,
    view_order: &[RibView],
    lpm: impl Fn(&'a T) -> Option<(P, &'a MultiRoute<E>)>,
) -> Option<ViewHit<'a, P, E>>
where
    T: Clone,
    E: Clone,
{
    for &view in view_order {
        let hit = match view {
            RibView::Loc => rib
                .loc_rib
                .as_deref()
                .and_then(&lpm)
                .map(|(prefix, multi)| (None, prefix, multi)),
            _ => adj_hit(rib, neighbor_peers, view, &lpm)
                .map(|(pk, prefix, multi)| (Some(pk), prefix, multi)),
        };
        if let Some((peer, prefix, multi)) = hit
            && let Some(route) = multi.active_path()
        {
            return Some((peer, prefix, route, view));
        }
    }
    None
}

/// `neighbor_peers` is the peers carrying the flow's neighbor address, or
/// `None` when the flow named no neighbor and any peer may answer.
fn adj_hit<'a, T, P, E>(
    rib: &'a AfiSafiRib<T>,
    neighbor_peers: Option<&[PeerKey]>,
    view: RibView,
    lpm: impl Fn(&'a T) -> Option<(P, &'a MultiRoute<E>)>,
) -> Option<(PeerKey, P, &'a MultiRoute<E>)>
where
    T: Clone,
    E: Clone,
{
    match neighbor_peers {
        Some([pk]) => {
            let (prefix, multi) = rib.peers.get(pk)?.view(view).and_then(&lpm)?;
            Some((*pk, prefix, multi))
        }
        Some(candidates) => lowest_hit(
            candidates
                .iter()
                .filter_map(|pk| Some((*pk, rib.peers.get(pk)?))),
            view,
            lpm,
        ),
        None => lowest_hit(rib.peers.iter().map(|(pk, pr)| (*pk, pr)), view, lpm),
    }
}

/// Several peers may answer; take the lowest `(peer_address, bgp_id)` among
/// those with an active path, so the result is stable across calls and never
/// picks a hit that `lookup_views` would then reject. Arbitrary, but
/// deterministic.
fn lowest_hit<'a, T, P, E>(
    peers: impl Iterator<Item = (PeerKey, &'a PeerRibs<T>)>,
    view: RibView,
    lpm: impl Fn(&'a T) -> Option<(P, &'a MultiRoute<E>)>,
) -> Option<(PeerKey, P, &'a MultiRoute<E>)>
where
    T: Clone + 'a,
    E: Clone,
{
    peers
        .filter_map(|(pk, pr)| {
            let (prefix, multi) = pr.view(view).and_then(&lpm)?;
            multi.active_path()?;
            Some((pk.peer_address(), pk.bgp_id(), pk, prefix, multi))
        })
        .min_by_key(|(addr, bgp_id, ..)| (*addr, *bgp_id))
        .map(|(_, _, pk, prefix, multi)| (pk, prefix, multi))
}

fn to_match<P, E>(hit: ViewHit<'_, P, E>, target: &LookupTarget) -> Match
where
    P: Copy + Into<IpNet>,
    E: RouteExtra,
{
    let (peer, prefix, route, view) = hit;
    Match {
        prefix: prefix.into(),
        attrs: Arc::clone(&route.attrs),
        extra: route.extra.as_labeled().cloned(),
        path_id: route.path_id,
        view,
        target: *target,
        peer,
    }
}

#[cfg(test)]
mod tests;
