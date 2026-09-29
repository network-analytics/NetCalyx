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
mod tests {
    use std::net::Ipv4Addr;

    use netcalyx_bgp_pkt::nlri::MplsLabel;
    use netcalyx_bmp_pkt::BmpPeerType;
    use netcalyx_bmp_pkt::v4::PathMarking;

    use super::*;
    use crate::model::{AfiSafiTable, MultiRoute, RouterRib};

    fn peer_key(asn: u32, addr: Ipv4Addr) -> PeerKey {
        PeerKey::new(
            Some(IpAddr::V4(addr)),
            BmpPeerType::GlobalInstancePeer {
                ipv6: false,
                post_policy: false,
                asn2: false,
                adj_rib_out: false,
            },
            None,
            asn,
            addr,
        )
    }

    fn route(path_id: u32) -> Route {
        Route {
            attrs: Arc::new(RouteAttributes::default()),
            path_id,
            path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
            extra: (),
        }
    }

    fn router_with_table(target: LookupTarget, table: AfiSafiTable) -> RouterRib {
        let mut rib = RouterRib::default();
        rib.tables.insert(target.table_id(), Arc::new(table));
        rib
    }

    #[test]
    fn matches_via_loc_rib_and_picks_the_longest_prefix() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        rib.loc_rib_mut().routes.insert(
            "10.0.0.0/16".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        rib.loc_rib_mut().routes.insert(
            "10.0.1.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(2)].into(),
            },
        );
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)), &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.view, RibView::Loc);
        assert_eq!(m.path_id, 2);
        assert_eq!(m.prefix, "10.0.1.0/24".parse::<IpNet>().unwrap());
        assert_eq!(m.peer, None);
    }

    #[test]
    fn falls_back_to_adj_rib_when_loc_rib_has_no_match() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        rib.peers
            .entry(peer)
            .or_default()
            .adj_rib_view_mut(false, false)
            .routes
            .insert(
                "10.0.0.0/24".parse().unwrap(),
                MultiRoute {
                    paths: [route(9)].into(),
                },
            );
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.view, RibView::AdjInPre);
        assert_eq!(m.path_id, 9);
        assert_eq!(m.peer, Some(peer));
    }

    #[test]
    fn view_precedence_prefers_adj_out_pre_over_adj_in_pre_when_both_match() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        let peer_ribs = rib.peers.entry(peer).or_default();
        for ((post_policy, adj_rib_out), path_id) in [((false, false), 1), ((false, true), 2)] {
            peer_ribs
                .adj_rib_view_mut(post_policy, adj_rib_out)
                .routes
                .insert(
                    "10.0.0.0/24".parse().unwrap(),
                    MultiRoute {
                        paths: [route(path_id)].into(),
                    },
                );
        }
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        // adj_rib_out_pre (path 2) precedes adj_rib_in_pre (path 1) in
        // DEFAULT_VIEW_ORDER.
        assert_eq!(m.view, RibView::AdjOutPre);
        assert_eq!(m.path_id, 2);
    }

    #[test]
    fn neighbor_selects_the_exact_peer() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        let peer_a = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        let peer_b = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
        for (peer, path_id) in [(peer_a, 10), (peer_b, 20)] {
            rib.peers
                .entry(peer)
                .or_default()
                .adj_rib_view_mut(false, false)
                .routes
                .insert(
                    "10.0.0.0/24".parse().unwrap(),
                    MultiRoute {
                        paths: [route(path_id)].into(),
                    },
                );
        }
        let mut router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));
        router.peers_by_addr.insert(
            (
                RibContext::Global,
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            ),
            peer_a,
        );
        router.peers_by_addr.insert(
            (
                RibContext::Global,
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)),
            ),
            peer_b,
        );

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
            .neighbor(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))));
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.path_id, 20);
        assert_eq!(m.peer, Some(peer_b));
    }

    #[test]
    fn ambiguous_neighbor_picks_the_lowest_matching_candidate() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        // Same peer address resolves to three candidates (e.g. a flapping
        // session): one with no route for the looked-up prefix, and two
        // with a route, to prove the tie-break considers only the peers
        // that actually match.
        let no_hit = peer_key(1, Ipv4Addr::new(192, 168, 0, 9));
        let lowest_hit = peer_key(2, Ipv4Addr::new(192, 168, 0, 3));
        let higher_hit = peer_key(3, Ipv4Addr::new(192, 168, 0, 7));
        for (peer, path_id) in [(lowest_hit, 30), (higher_hit, 70)] {
            rib.peers
                .entry(peer)
                .or_default()
                .adj_rib_view_mut(false, false)
                .routes
                .insert(
                    "10.0.0.0/24".parse().unwrap(),
                    MultiRoute {
                        paths: [route(path_id)].into(),
                    },
                );
        }
        rib.peers.entry(no_hit).or_default();
        let mut router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));
        let neighbor = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));
        for peer in [no_hit, lowest_hit, higher_hit] {
            router
                .peers_by_addr
                .insert((RibContext::Global, neighbor), peer);
        }

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
            .neighbor(Some(neighbor));
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.path_id, 30);
        assert_eq!(m.peer, Some(lowest_hit));
    }

    #[test]
    fn ambiguous_neighbor_skips_a_lower_address_candidate_with_no_active_path() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        // The lowest-address candidate has an LPM hit but an empty path
        // list (no active path); the tie-break must not pick it just
        // because its address is lowest, or the whole view would wrongly
        // be treated as a miss.
        let no_active_path = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        let has_active_path = peer_key(2, Ipv4Addr::new(192, 168, 0, 9));
        rib.peers
            .entry(no_active_path)
            .or_default()
            .adj_rib_view_mut(false, false)
            .routes
            .insert("10.0.0.0/24".parse().unwrap(), MultiRoute::default());
        rib.peers
            .entry(has_active_path)
            .or_default()
            .adj_rib_view_mut(false, false)
            .routes
            .insert(
                "10.0.0.0/24".parse().unwrap(),
                MultiRoute {
                    paths: [route(50)].into(),
                },
            );
        let mut router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));
        let neighbor = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));
        for peer in [no_active_path, has_active_path] {
            router
                .peers_by_addr
                .insert((RibContext::Global, neighbor), peer);
        }

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
            .neighbor(Some(neighbor));
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.path_id, 50);
        assert_eq!(m.peer, Some(has_active_path));
    }

    #[test]
    fn unknown_neighbor_yields_no_match_even_if_other_peers_have_one() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        rib.peers
            .entry(peer)
            .or_default()
            .adj_rib_view_mut(false, false)
            .routes
            .insert(
                "10.0.0.0/24".parse().unwrap(),
                MultiRoute {
                    paths: [route(1)].into(),
                },
            );
        let mut router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));
        router.peers_by_addr.insert(
            (
                RibContext::Global,
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            ),
            peer,
        );

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
            .neighbor(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 99))));
        assert!(lookup(&router, &req).is_none());
    }

    #[test]
    fn no_neighbor_picks_the_lowest_peer_address_deterministically() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        let peer_a = peer_key(1, Ipv4Addr::new(192, 168, 0, 5));
        let peer_b = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
        for (peer, path_id) in [(peer_a, 10), (peer_b, 20)] {
            rib.peers
                .entry(peer)
                .or_default()
                .adj_rib_view_mut(false, false)
                .routes
                .insert(
                    "10.0.0.0/24".parse().unwrap(),
                    MultiRoute {
                        paths: [route(path_id)].into(),
                    },
                );
        }
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        // 192.168.0.2 < 192.168.0.5
        assert_eq!(m.path_id, 20);
        assert_eq!(m.peer, Some(peer_b));
    }

    #[test]
    fn vpn_target_without_rd_never_matches() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::L3VpnIpv4Unicast);
        let mut rib = AfiSafiRib::<VpnRoutes<Ipv4Net>>::default();
        let rd = RouteDistinguisher::As2Administrator { asn2: 1, number: 1 };
        rib.loc_rib_mut()
            .tables
            .entry(rd)
            .or_insert_with(|| Arc::new(prefix_trie::PrefixMap::new()));
        Arc::make_mut(rib.loc_rib_mut().tables.get_mut(&rd).unwrap()).insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [Route {
                    attrs: Arc::new(RouteAttributes::default()),
                    path_id: 1,
                    path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
                    extra: LabeledRouteExtra::default(),
                }]
                .into(),
            },
        );
        let router = router_with_table(target, AfiSafiTable::L3VpnIpv4Unicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        assert!(lookup(&router, &req).is_none());

        let targets_with_rd = [target.with_rd(rd)];
        let req_with_rd =
            LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets_with_rd);
        let m = lookup(&router, &req_with_rd).unwrap();
        assert_eq!(m.path_id, 1);
        assert_eq!(m.view, RibView::Loc);
        assert_eq!(m.peer, None);
        assert_eq!(m.extra, Some(LabeledRouteExtra::default()));
    }

    #[test]
    fn adj_rib_lookup_threads_peer_and_extra_for_labeled_families() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4LabeledUnicast);
        let mut rib = AfiSafiRib::<LabeledRoutes<Ipv4Net>>::default();
        let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
        let extra = LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, 1])]));
        rib.peers
            .entry(peer)
            .or_default()
            .adj_rib_view_mut(false, false)
            .routes
            .insert(
                "10.0.0.0/24".parse().unwrap(),
                MultiRoute {
                    paths: [Route {
                        attrs: Arc::new(RouteAttributes::default()),
                        path_id: 1,
                        path_marking: PathMarking::new(
                            netcalyx_bmp_pkt::v4::PathStatus::BEST,
                            None,
                        ),
                        extra: extra.clone(),
                    }]
                    .into(),
                },
            );
        let router = router_with_table(target, AfiSafiTable::Ipv4LabeledUnicast(rib));

        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.view, RibView::AdjInPre);
        assert_eq!(m.peer, Some(peer));
        assert_eq!(m.extra, Some(extra));
    }

    #[test]
    fn view_order_can_be_overridden() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        rib.loc_rib_mut().routes.insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        // Excluding `Loc` from the order means the same lookup now misses.
        let no_loc = [
            RibView::AdjOutPre,
            RibView::AdjOutPost,
            RibView::AdjInPost,
            RibView::AdjInPre,
        ];
        let targets = [target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
            .view_order(&no_loc);
        assert!(lookup(&router, &req).is_none());
    }

    #[test]
    fn multi_target_lookup_falls_back_to_a_later_target_when_the_first_misses() {
        let vrf_target = LookupTarget::new(
            RibContext::Vrf(RouteDistinguisher::As2Administrator { asn2: 1, number: 1 }),
            AfiSafiType::Ipv4Unicast,
        );
        let global_target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);

        let mut router = RouterRib::default();
        router.tables.insert(
            vrf_target.table_id(),
            Arc::new(AfiSafiTable::Ipv4Unicast(
                AfiSafiRib::<Routes<Ipv4Net>>::default(),
            )),
        );
        let mut global_rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        global_rib.loc_rib_mut().routes.insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        router.tables.insert(
            global_target.table_id(),
            Arc::new(AfiSafiTable::Ipv4Unicast(global_rib)),
        );

        let targets = [vrf_target, global_target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.target, global_target);
        assert_eq!(m.path_id, 1);
    }

    #[test]
    fn multi_target_lookup_prefers_the_first_target_when_both_hit() {
        let vrf_target = LookupTarget::new(
            RibContext::Vrf(RouteDistinguisher::As2Administrator { asn2: 1, number: 1 }),
            AfiSafiType::Ipv4Unicast,
        );
        let global_target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);

        let mut router = RouterRib::default();
        let mut vrf_rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        vrf_rib.loc_rib_mut().routes.insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        router.tables.insert(
            vrf_target.table_id(),
            Arc::new(AfiSafiTable::Ipv4Unicast(vrf_rib)),
        );
        let mut global_rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        global_rib.loc_rib_mut().routes.insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(2)].into(),
            },
        );
        router.tables.insert(
            global_target.table_id(),
            Arc::new(AfiSafiTable::Ipv4Unicast(global_rib)),
        );

        let targets = [vrf_target, global_target];
        let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.target, vrf_target);
        assert_eq!(m.path_id, 1);
    }

    #[test]
    fn ipv6_unicast_lookup_matches_via_loc_rib() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv6Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv6Net>>::default();
        rib.loc_rib_mut().routes.insert(
            "2001:db8::/32".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        let router = router_with_table(target, AfiSafiTable::Ipv6Unicast(rib));

        let targets = [target];
        let addr = IpAddr::V6("2001:db8::1".parse().unwrap());
        let req = LookupRequest::new(addr, &targets);
        let m = lookup(&router, &req).unwrap();
        assert_eq!(m.view, RibView::Loc);
        assert_eq!(m.path_id, 1);
    }

    #[test]
    fn address_family_mismatched_with_the_table_yields_no_match() {
        let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
        let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
        rib.loc_rib_mut().routes.insert(
            "10.0.0.0/24".parse().unwrap(),
            MultiRoute {
                paths: [route(1)].into(),
            },
        );
        let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

        let targets = [target];
        // Same table_id family (Ipv4Unicast), but an IPv6 address: the
        // (table, addr) match in `lookup_target` falls through to `_ => None`.
        let req = LookupRequest::new(IpAddr::V6("::1".parse().unwrap()), &targets);
        assert!(lookup(&router, &req).is_none());
    }
}
