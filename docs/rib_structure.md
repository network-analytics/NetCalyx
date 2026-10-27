# RIB structure

Sketch of the `netcalyx-rib` (`crates/rib`) in-memory hierarchy: per-router
snapshots with per-trie copy-on-write.

## Hierarchy

```text
RibStore
├─ attr_store: AttrStore
└─ ribs: FxHashMap<IpAddr, Arc<RouterRib>>                     [Arc 1]  one entry per router
    └─ RouterRib
        ├─ peers: PeerTable                                    PeerKey <-> router-local PeerId
        ├─ peer_index: PeerIndex<(RibContext, IpAddr), PeerId>
        └─ tables: FxHashMap<TableId, Arc<AfiSafiTable>>       [Arc 2]  one per (context, afi-safi)
            └─ AfiSafiTable::Ipv4Unicast(AfiSafiRib<Routes<Ipv4Net>>)
                └─ views: [Option<Arc<Routes<Ipv4Net>>>; 5]    [Arc 3]  one trie per view, shared by all peers
                    │      loc, adj_out_pre, adj_out_post, adj_in_post, adj_in_pre
                    └─ routes: PrefixMap<Ipv4Net, MultiRoute>  [TRIE]
                        └─ MultiRoute::paths: Route { peer: Option<PeerId>, path_id, .. }
```

`Ipv6Unicast`, `Ipv4LabeledUnicast` and `Ipv6LabeledUnicast` repeat the same
shape with `Ipv6Net` and/or `LabeledRoutes` in place of `Routes`.

The two L3VPN variants (`L3VpnIpv4Unicast`, `L3VpnIpv6Unicast`) replace every
view leaf above with one extra layer, keyed by route distinguisher:

```text
AfiSafiTable::L3VpnIpv4Unicast(AfiSafiRib<VpnRoutes<Ipv4Net>>)
    └─ each view: Option<Arc<VpnRoutes<Ipv4Net>>>                                 [Arc 3]
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

Trie count for one router with P AFI-SAFIs and V VRFs, independent of the
number of peers K:

```text
tries = P × 5_views     # the VPN families additionally multiply by V (one trie per RD)
```

Each route carries the `PeerId` it was learned from (`None` for loc-rib
paths); peers are interned per router in `PeerTable`, and ids are recycled
when a peer is removed.

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

The whole `RouterRib` is published as one unit — every view of every table
together.
