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
//! adj-ribs) and, within an adj-rib view, resolves the caller's neighbor
//! address to a peer through [`PeerIndex`](crate::peers::PeerIndex) rather
//! than scanning every peer. When an address is ambiguous (ties to several
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
use prefix_trie::{Prefix, PrefixMap};
use smallvec::SmallVec;

use netcalyx_bgp_pkt::nlri::RouteDistinguisher;
use netcalyx_bmp_pkt::PeerKey;

use crate::attrs::RouteAttributes;
use crate::model::{AfiSafiRib, AfiSafiTable, MultiRoute, PeerId, Route, RouterRib};
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

/// Complete address of one trie: `context` + `afi_safi` pick the table (see
/// [`TableId`]), and `rd` picks the per-RD trie within it for the L3VPN
/// families. Together with an [`IpAddr`], this is everything a lookup needs
/// to run an LPM. The caller derives it from whatever context it has at
/// hand; we never guess.
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
    /// The address being resolved.
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

/// What a lookup returns: the active path (see [`MultiRoute::active_path_of`])
/// of the first [`RibView`] with a hit.
#[derive(Debug, Clone)]
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
    /// Normalized like [`peer_identity`](crate::types::peer_identity).
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

fn lookup_target(
    rib: &RouterRib,
    target: &LookupTarget,
    addr: IpAddr,
    neighbor: Option<IpAddr>,
    view_order: &[RibView],
) -> Option<Match> {
    let table = rib.tables.get(&target.table_id())?.as_ref();
    let neighbor_peers = neighbor.map(|a| rib.resolve_peer(target.context, a));

    match (table, addr) {
        (AfiSafiTable::Ipv4Unicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| Some(&t.routes))?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv6Unicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| Some(&t.routes))?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv4LabeledUnicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| Some(&t.routes))?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::Ipv6LabeledUnicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| Some(&t.routes))?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::L3VpnIpv4Unicast(r), IpAddr::V4(a)) => {
            let net = Ipv4Net::new(a, 32).ok()?;
            let rd = target.rd?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| t.table_ref(rd))?;
            Some(to_match(hit, target))
        }
        (AfiSafiTable::L3VpnIpv6Unicast(r), IpAddr::V6(a)) => {
            let net = Ipv6Net::new(a, 128).ok()?;
            let rd = target.rd?;
            let hit = lookup_views(rib, r, neighbor_peers, view_order, net, |t| t.table_ref(rd))?;
            Some(to_match(hit, target))
        }
        _ => None,
    }
}

type ViewHit<'a, P, E> = (Option<PeerKey>, P, &'a Route<E>, RibView);

/// Walk the views in precedence order, returning the first active path found.
/// All peers share one trie per view, so the LPM is taken per peer: the
/// deepest node holding a path from that peer, not just the trie's deepest.
fn lookup_views<'a, T, P, E>(
    rib: &'a RouterRib,
    table: &'a AfiSafiRib<T>,
    neighbor_peers: Option<&[PeerId]>,
    view_order: &[RibView],
    net: P,
    trie: impl Fn(&'a T) -> Option<&'a PrefixMap<P, MultiRoute<E>>>,
) -> Option<ViewHit<'a, P, E>>
where
    T: Clone,
    P: Prefix + Copy + 'a,
    E: Clone,
{
    for &view in view_order {
        let Some(t) = table.view(view).and_then(&trie) else {
            continue;
        };
        let hit = match view {
            RibView::Loc => deepest_for(t, &net, None)
                .and_then(|(prefix, m)| Some((None, prefix, m.active_path_of(None)?))),
            _ => adj_hit(rib, neighbor_peers, t, &net).and_then(|(id, pk, prefix, m)| {
                Some((Some(pk), prefix, m.active_path_of(Some(id))?))
            }),
        };
        if let Some((peer, prefix, route)) = hit {
            return Some((peer, prefix, route, view));
        }
    }
    None
}

/// Deepest node covering `net` with a path tagged `peer`. Tries the trie's own
/// LPM first and only walks the covering chain when that node lacks `peer`.
fn deepest_for<'a, P, E>(
    trie: &'a PrefixMap<P, MultiRoute<E>>,
    net: &P,
    peer: Option<PeerId>,
) -> Option<(P, &'a MultiRoute<E>)>
where
    P: Prefix + Copy + 'a,
{
    match trie.get_lpm(net) {
        Some(hit) if hit.1.has(peer) => Some(hit),
        Some(_) => trie.cover(net).filter(|(_, m)| m.has(peer)).last(),
        None => None,
    }
}

/// `neighbor_peers` is the peers carrying the caller's neighbor address, or
/// `None` when the caller named no neighbor and any peer may answer. With
/// several candidates, the lowest `(peer_address, bgp_id)` among those with a
/// path wins: arbitrary, but deterministic across calls.
fn adj_hit<'a, P, E>(
    rib: &'a RouterRib,
    neighbor_peers: Option<&[PeerId]>,
    trie: &'a PrefixMap<P, MultiRoute<E>>,
    net: &P,
) -> Option<(PeerId, PeerKey, P, &'a MultiRoute<E>)>
where
    P: Prefix + Copy + 'a,
{
    if let Some(&[id]) = neighbor_peers {
        let (prefix, multi) = deepest_for(trie, net, Some(id))?;
        return Some((id, *rib.peers.key(id)?, prefix, multi));
    }
    // The lowest-keyed peer may only hold a shorter prefix, so walk the chain.
    // Deepest covering node per peer; later (longer) nodes overwrite earlier.
    let mut hits: SmallVec<[(PeerId, P, &'a MultiRoute<E>); 4]> = SmallVec::new();
    for (prefix, multi) in trie.cover(net) {
        for id in multi.paths.iter().filter_map(|r| r.peer) {
            if neighbor_peers.is_some_and(|c| !c.contains(&id)) {
                continue;
            }
            match hits.iter_mut().find(|(h, ..)| *h == id) {
                Some(h) => *h = (id, prefix, multi),
                None => hits.push((id, prefix, multi)),
            }
        }
    }
    hits.into_iter()
        .filter_map(|(id, prefix, multi)| Some((id, *rib.peers.key(id)?, prefix, multi)))
        .min_by_key(|(_, pk, ..)| (pk.peer_address(), pk.bgp_id()))
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
