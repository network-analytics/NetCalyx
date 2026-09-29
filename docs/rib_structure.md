# RIB structure

Sketch of the `netcalyx-rib` (`crates/rib`) in-memory hierarchy: per-router
snapshots with per-trie copy-on-write.

## Hierarchy

```text
RibStore
├─ attr_store: AttrStore
└─ ribs: FxHashMap<IpAddr, Arc<RouterRib>>                     [Arc 1]  one entry per router
    └─ RouterRib
        ├─ peers_by_addr: PeerIndex<(RibContext, IpAddr), PeerKey>
        └─ tables: FxHashMap<TableId, Arc<AfiSafiTable>>       [Arc 2]  one per (context, afi-safi)
            └─ AfiSafiTable::Ipv4Unicast(AfiSafiRib<Routes<Ipv4Net>>)
                ├─ loc_rib: Option<Arc<Routes<Ipv4Net>>>       [Arc 3]
                │   └─ routes: PrefixMap<Ipv4Net, MultiRoute>  [TRIE]
                └─ peers: FxHashMap<PeerKey, PeerRibs<Routes<Ipv4Net>>>
                    └─ PeerRibs                                four independent views
                        ├─ adj_rib_in_pre:   Option<Arc<Routes<Ipv4Net>>>  [Arc 3, own TRIE]
                        ├─ adj_rib_in_post:  Option<Arc<Routes<Ipv4Net>>>  [Arc 3, own TRIE]
                        ├─ adj_rib_out_pre:  Option<Arc<Routes<Ipv4Net>>>  [Arc 3, own TRIE]
                        └─ adj_rib_out_post: Option<Arc<Routes<Ipv4Net>>>  [Arc 3, own TRIE]
```

`Ipv6Unicast`, `Ipv4LabeledUnicast` and `Ipv6LabeledUnicast` repeat the same
shape with `Ipv6Net` and/or `LabeledRoutes` in place of `Routes`.

The two L3VPN variants (`L3VpnIpv4Unicast`, `L3VpnIpv6Unicast`) replace every
leaf above — `loc_rib` and each `adj_rib_*` — with one extra layer, keyed by
route distinguisher:

```text
AfiSafiTable::L3VpnIpv4Unicast(AfiSafiRib<VpnRoutes<Ipv4Net>>)
    └─ (loc_rib, or each adj_rib_* in PeerRibs): Option<Arc<VpnRoutes<Ipv4Net>>>  [Arc 3]
        └─ VpnRoutes::tables: FxHashMap<RouteDistinguisher, Arc<PrefixMap<..>>>   [Arc 4]
            └─ [TRIE]  one per VRF
```

`Arc` legend:

| | wraps | shared until |
|---|---|---|
| Arc 1 | `RouterRib` | next publish of that router |
| Arc 2 | `AfiSafiTable` | next write to that table |
| Arc 3 | one view's trie (`Routes`/`LabeledRoutes`/`VpnRoutes`) | next write to that view |
| Arc 4 | one VRF's `PrefixMap` (VPN only) | next write to that VRF |

Trie count for one router with K peers, P AFI-SAFIs, V VRFs:

```text
tries = P × (1_loc + K × 4_adj)     # the VPN families additionally multiply by V (one trie per RD)
```

## Copy-on-write

`Arc` sits at four levels, not just on `RouterRib`. A write after a publish
walks down that chain calling `Arc::make_mut` at each level: every level above
the touched trie is a shallow clone of a map of `Arc`s, and only the single
trie being written is deep-copied. Superseded versions are reclaimed by plain
refcounting when the next publish drops the old snapshot — the cascade stops
wherever the new snapshot still shares the value. Full lifecycle walkthrough:
module doc on [`crates/rib/src/model.rs`](../crates/rib/src/model.rs).

## RIB views

Five perspectives on one table's routes: `loc-rib` (the local decision
process's output: the best path, and optionally additional backup or ECMP
paths) plus four adj-ribs (what was received from, or is being advertised
to, one peer), keyed by policy stage and direction:

| | pre-policy | post-policy |
|---|---|---|
| adj-rib-in  | `adj_rib_in_pre`  | `adj_rib_in_post`  |
| adj-rib-out | `adj_rib_out_pre` | `adj_rib_out_post` |

The whole `RouterRib` is published as one unit — `loc-rib` and every peer's
four adj-rib views together.
