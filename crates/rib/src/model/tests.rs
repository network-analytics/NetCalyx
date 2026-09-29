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

use netcalyx_bmp_pkt::BmpPeerType;
use netcalyx_bmp_pkt::v4::PathStatus;

use crate::model::*;
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
fn peer_ribs_view_accessors_return_none_for_loc() {
    let mut peer_ribs = PeerRibs::<Routes<Ipv4Net>>::default();
    assert!(peer_ribs.view(RibView::Loc).is_none());
    assert!(peer_ribs.view_mut(RibView::Loc).is_none());
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
