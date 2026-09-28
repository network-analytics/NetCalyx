# RIB

In-memory BGP RIB storage for a BMP collector: attribute interning and
per-router, per-AFI-SAFI containers (`loc-rib` plus the four adj-ribs) with
Arc-per-trie copy-on-write, so a write after a snapshot publish only clones
the one trie it touches.

Supported so far: the data model (`types`, `attrs`, `model`, `peers`). LPM
lookup and BMP ingestion will be separate, later additions on top of this.

- [`docs/rib_structure.md`](../../docs/rib_structure.md) — hierarchy sketch
  and copy-on-write walkthrough.
