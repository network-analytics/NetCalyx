# RIB

In-memory BGP RIB storage for a BMP collector: attribute interning and
per-router, per-AFI-SAFI containers (`loc-rib` plus the four adj-ribs) with
Arc-per-trie copy-on-write, so a write after a snapshot publish only clones
the one trie it touches.

Supported so far:

- The data model (`types`, `attrs`, `model`, `peers`): table/view/peer
  addressing, the Arc-per-trie containers themselves, and interned path
  attributes.
- LPM lookup (`lookup`): resolve an address against a `&RouterRib` you build
  directly into a `Match` — the active path's attributes and forwarding
  info (MPLS label / SRv6 SID), which RIB view answered, and the peer whose
  adj-rib answered (`None` for loc-rib).

- [`docs/rib_structure.md`](../../docs/rib_structure.md) — hierarchy sketch
  and copy-on-write walkthrough.
