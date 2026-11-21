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

use std::net::Ipv4Addr;

use netcalyx_bgp_pkt::nlri::MplsLabel;
use netcalyx_bmp_pkt::BmpPeerType;
use netcalyx_bmp_pkt::v4::PathMarking;

use crate::lookup::*;
use crate::model::{AfiSafiTable, LabeledRoutes, MultiRoute, RouterRib, Routes, VpnRoutes};

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
    route_from(None, path_id)
}

fn route_from(peer: Option<PeerId>, path_id: u32) -> Route {
    Route {
        attrs: Arc::new(RouteAttributes {
            local_pref: Some(path_id),
            ..Default::default()
        }),
        peer,
        path_id,
        path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
        extra: (),
    }
}

fn router_with_table(target: LookupTarget, table: AfiSafiTable) -> RouterRib {
    let mut rib = RouterRib::default();
    rib.insert_table(target.context, table);
    rib
}

#[test]
fn vrf_neighbor_resolves_only_within_its_rd_context() {
    let rd = RouteDistinguisher::As2Administrator { asn2: 1, number: 1 };
    let target = LookupTarget::new(RibContext::Vrf(rd), AfiSafiType::Ipv4Unicast);
    let addr = Ipv4Addr::new(192, 168, 0, 1);
    let mut router = RouterRib::default();
    // Same neighbor address in the global table and in the VRF; the global
    // peer has the lower bgp_id, so it would win if context were ignored.
    let global = peer_key(1, addr);
    let vrf = PeerKey::new(
        Some(IpAddr::V4(addr)),
        BmpPeerType::RdInstancePeer {
            ipv6: false,
            post_policy: false,
            asn2: false,
            adj_rib_out: false,
        },
        Some(rd),
        2,
        Ipv4Addr::new(192, 168, 0, 9),
    );
    let id_global = router.add_peer(global);
    let id_vrf = router.add_peer(vrf);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_global), 1), route_from(Some(id_vrf), 2)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
        .neighbor(Some(IpAddr::V4(addr)));
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.path_id, 2);
    assert_eq!(m.peer, Some(vrf));
}

#[test]
fn l3vpn_adj_rib_lookup_with_neighbor_reads_the_rd_trie() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::L3VpnIpv4Unicast);
    let rd = RouteDistinguisher::As2Administrator { asn2: 1, number: 1 };
    let other_rd = RouteDistinguisher::As2Administrator { asn2: 1, number: 2 };
    let mut router = RouterRib::default();
    let pe_a = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let pe_b = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
    let id_a = router.add_peer(pe_a);
    let id_b = router.add_peer(pe_b);
    let labeled = |peer, path_id, label| Route {
        attrs: Arc::new(RouteAttributes::default()),
        peer: Some(peer),
        path_id,
        path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
        extra: LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, label])])),
    };
    let mut rib = AfiSafiRib::<VpnRoutes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).table_mut(rd).insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [labeled(id_a, 1, 1), labeled(id_b, 2, 2)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::L3VpnIpv4Unicast(rib));

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let neighbor = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
    let targets = [target.with_rd(rd)];
    let m = lookup(
        &router,
        &LookupRequest::new(addr, &targets).neighbor(neighbor),
    )
    .unwrap();
    assert_eq!(m.view, RibView::AdjInPre);
    assert_eq!(m.peer, Some(pe_b));
    assert_eq!(m.path_id, 2);
    assert_eq!(
        m.extra,
        Some(LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([
            0, 0, 2
        ])])))
    );

    let other = [target.with_rd(other_rd)];
    assert!(
        lookup(
            &router,
            &LookupRequest::new(addr, &other).neighbor(neighbor)
        )
        .is_none()
    );
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
    assert_eq!(m.extra, None);
    // Proves `to_match` carried over the winning route's own attrs, not just
    // its path_id: route(1)'s local_pref is 1, route(2)'s is 2.
    assert_eq!(m.attrs.local_pref, Some(2));
}

#[test]
fn falls_back_to_adj_rib_when_loc_rib_has_no_match() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let id = router.add_peer(peer);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id), 9)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

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
    let mut router = RouterRib::default();
    let id = router.add_peer(peer_key(1, Ipv4Addr::new(192, 168, 0, 1)));
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    for ((post_policy, adj_rib_out), path_id) in [((false, false), 1), ((false, true), 2)] {
        rib.adj_rib_view_mut(post_policy, adj_rib_out)
            .routes
            .insert(
                "10.0.0.0/24".parse().unwrap(),
                MultiRoute {
                    paths: [route_from(Some(id), path_id)].into(),
                },
            );
    }
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

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
    let mut router = RouterRib::default();
    let peer_a = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let peer_b = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
    // `add_peer` also indexes each peer under its own address.
    let id_a = router.add_peer(peer_a);
    let id_b = router.add_peer(peer_b);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_a), 10), route_from(Some(id_b), 20)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

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
    let mut router = RouterRib::default();
    // Same peer address resolves to three candidates (e.g. a flapping
    // session): one with no route for the looked-up prefix, and two
    // with a route, to prove the tie-break considers only the peers
    // that actually match.
    let no_hit = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let lowest_hit = peer_key(2, Ipv4Addr::new(192, 168, 0, 3));
    let higher_hit = peer_key(3, Ipv4Addr::new(192, 168, 0, 7));
    let ids = [no_hit, lowest_hit, higher_hit].map(|pk| router.add_peer(pk));
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(ids[2]), 70), route_from(Some(ids[1]), 30)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));
    let neighbor = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100));
    for id in ids {
        router.peer_index.insert((RibContext::Global, neighbor), id);
    }

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
        .neighbor(Some(neighbor));
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.path_id, 30);
    assert_eq!(m.peer, Some(lowest_hit));
}

#[test]
fn neighbor_lpm_falls_back_to_a_shorter_prefix_held_by_that_peer() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    // The trie is shared: the deepest node (/24) belongs to another peer, so
    // the neighbor's own LPM is its /16, not a miss.
    let mine = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let other = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
    let id_mine = router.add_peer(mine);
    let id_other = router.add_peer(other);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    let view = rib.adj_rib_view_mut(false, false);
    view.routes.insert(
        "10.0.0.0/16".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_mine), 16)].into(),
        },
    );
    view.routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_other), 24)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
        .neighbor(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.path_id, 16);
    assert_eq!(m.prefix, "10.0.0.0/16".parse::<IpNet>().unwrap());
    assert_eq!(m.peer, Some(mine));
}

#[test]
fn unknown_neighbor_yields_no_match_even_if_other_peers_have_one() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let id = router.add_peer(peer_key(1, Ipv4Addr::new(192, 168, 0, 1)));
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id), 1)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets)
        .neighbor(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 99))));
    assert!(lookup(&router, &req).is_none());
}

#[test]
fn no_neighbor_picks_the_lowest_peer_address_deterministically() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let peer_a = peer_key(1, Ipv4Addr::new(192, 168, 0, 5));
    let peer_b = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
    let id_a = router.add_peer(peer_a);
    let id_b = router.add_peer(peer_b);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_a), 10), route_from(Some(id_b), 20)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

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
    rib.loc_rib_mut().table_mut(rd).insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [Route {
                attrs: Arc::new(RouteAttributes::default()),
                peer: None,
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
    let req_with_rd = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets_with_rd);
    let m = lookup(&router, &req_with_rd).unwrap();
    assert_eq!(m.path_id, 1);
    assert_eq!(m.view, RibView::Loc);
    assert_eq!(m.peer, None);
    assert_eq!(m.extra, Some(LabeledRouteExtra::default()));
}

#[test]
fn adj_rib_lookup_threads_peer_and_extra_for_labeled_families() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4LabeledUnicast);
    let mut router = RouterRib::default();
    let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let id = router.add_peer(peer);
    let mut rib = AfiSafiRib::<LabeledRoutes<Ipv4Net>>::default();
    let extra = LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, 1])]));
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [Route {
                attrs: Arc::new(RouteAttributes::default()),
                peer: Some(id),
                path_id: 1,
                path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
                extra: extra.clone(),
            }]
            .into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4LabeledUnicast(rib));

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
    let req =
        LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets).view_order(&no_loc);
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
    router.insert_table(
        vrf_target.context,
        AfiSafiTable::Ipv4Unicast(AfiSafiRib::<Routes<Ipv4Net>>::default()),
    );
    let mut global_rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    global_rib.loc_rib_mut().routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route(1)].into(),
        },
    );
    router.insert_table(global_target.context, AfiSafiTable::Ipv4Unicast(global_rib));

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
    router.insert_table(vrf_target.context, AfiSafiTable::Ipv4Unicast(vrf_rib));
    let mut global_rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    global_rib.loc_rib_mut().routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route(2)].into(),
        },
    );
    router.insert_table(global_target.context, AfiSafiTable::Ipv4Unicast(global_rib));

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

#[test]
fn ipv6_labeled_unicast_lookup_matches_via_adj_rib() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv6LabeledUnicast);
    let mut router = RouterRib::default();
    let peer = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let id = router.add_peer(peer);
    let mut rib = AfiSafiRib::<LabeledRoutes<Ipv6Net>>::default();
    let extra = LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, 3])]));
    rib.adj_rib_view_mut(false, false).routes.insert(
        "2001:db8::/32".parse().unwrap(),
        MultiRoute {
            paths: [Route {
                attrs: Arc::new(RouteAttributes::default()),
                peer: Some(id),
                path_id: 1,
                path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
                extra: extra.clone(),
            }]
            .into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv6LabeledUnicast(rib));

    let targets = [target];
    let addr = IpAddr::V6("2001:db8::1".parse().unwrap());
    let req = LookupRequest::new(addr, &targets);
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.view, RibView::AdjInPre);
    assert_eq!(m.peer, Some(peer));
    assert_eq!(m.extra, Some(extra));
}

#[test]
fn l3vpn_ipv6_unicast_lookup_requires_matching_rd() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::L3VpnIpv6Unicast);
    let mut rib = AfiSafiRib::<VpnRoutes<Ipv6Net>>::default();
    let rd = RouteDistinguisher::As2Administrator { asn2: 1, number: 1 };
    rib.loc_rib_mut().table_mut(rd).insert(
        "2001:db8::/32".parse().unwrap(),
        MultiRoute {
            paths: [Route {
                attrs: Arc::new(RouteAttributes::default()),
                peer: None,
                path_id: 1,
                path_marking: PathMarking::new(netcalyx_bmp_pkt::v4::PathStatus::BEST, None),
                extra: LabeledRouteExtra::default(),
            }]
            .into(),
        },
    );
    let router = router_with_table(target, AfiSafiTable::L3VpnIpv6Unicast(rib));
    let addr = IpAddr::V6("2001:db8::1".parse().unwrap());

    let targets_without_rd = [target];
    let req_without_rd = LookupRequest::new(addr, &targets_without_rd);
    assert!(lookup(&router, &req_without_rd).is_none());

    let targets_with_rd = [target.with_rd(rd)];
    let req_with_rd = LookupRequest::new(addr, &targets_with_rd);
    let m = lookup(&router, &req_with_rd).unwrap();
    assert_eq!(m.path_id, 1);
    assert_eq!(m.view, RibView::Loc);
}

#[test]
fn loc_rib_hit_with_no_active_path_falls_through_to_adj_rib() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let id = router.add_peer(peer_key(1, Ipv4Addr::new(192, 168, 0, 1)));
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    // loc-rib has an LPM hit, but its `MultiRoute` has no paths at all, so
    // `lookup_views` must not stop at `Loc` here -- it has to try the
    // adj-ribs next.
    rib.loc_rib_mut()
        .routes
        .insert("10.0.0.0/24".parse().unwrap(), MultiRoute::default());
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id), 1)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.view, RibView::AdjInPre);
    assert_eq!(m.path_id, 1);
}

#[test]
fn loc_rib_empty_deepest_node_falls_back_to_a_shorter_loc_rib_prefix() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.loc_rib_mut().routes.insert(
        "10.0.0.0/16".parse().unwrap(),
        MultiRoute {
            paths: [route(16)].into(),
        },
    );
    rib.loc_rib_mut()
        .routes
        .insert("10.0.0.0/24".parse().unwrap(), MultiRoute::default());
    let router = router_with_table(target, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.view, RibView::Loc);
    assert_eq!(m.prefix, "10.0.0.0/16".parse::<IpNet>().unwrap());
}

#[test]
fn no_neighbor_prefers_the_lowest_peer_even_if_it_only_holds_a_shorter_prefix() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let low = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let high = peer_key(2, Ipv4Addr::new(192, 168, 0, 9));
    let id_low = router.add_peer(low);
    let id_high = router.add_peer(high);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    let view = rib.adj_rib_view_mut(false, false);
    view.routes.insert(
        "10.0.0.0/16".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_low), 16)].into(),
        },
    );
    view.routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_high), 24)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));

    let targets = [target];
    let req = LookupRequest::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &targets);
    let m = lookup(&router, &req).unwrap();
    assert_eq!(m.path_id, 16);
    assert_eq!(m.peer, Some(low));
}

#[test]
fn removed_peer_no_longer_answers() {
    let target = LookupTarget::new(RibContext::Global, AfiSafiType::Ipv4Unicast);
    let mut router = RouterRib::default();
    let gone = peer_key(1, Ipv4Addr::new(192, 168, 0, 1));
    let kept = peer_key(2, Ipv4Addr::new(192, 168, 0, 2));
    let id_gone = router.add_peer(gone);
    let id_kept = router.add_peer(kept);
    let mut rib = AfiSafiRib::<Routes<Ipv4Net>>::default();
    rib.adj_rib_view_mut(false, false).routes.insert(
        "10.0.0.0/24".parse().unwrap(),
        MultiRoute {
            paths: [route_from(Some(id_gone), 1), route_from(Some(id_kept), 2)].into(),
        },
    );
    router.insert_table(target.context, AfiSafiTable::Ipv4Unicast(rib));
    router.remove_peer(&gone);

    let targets = [target];
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let by_neighbor = LookupRequest::new(addr, &targets)
        .neighbor(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    assert!(lookup(&router, &by_neighbor).is_none());

    let m = lookup(&router, &LookupRequest::new(addr, &targets)).unwrap();
    assert_eq!(m.peer, Some(kept));
}
