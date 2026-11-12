# RIB

In-memory BGP RIB storage for a BMP collector: attribute interning and
per-router, per-AFI-SAFI containers (`loc-rib` plus the four adj-ribs) with
Arc-per-trie copy-on-write, so a write after a snapshot publish only clones
the one trie it touches.

Supported so far: the data model (`types`, `attrs`, `model`, `peers`). LPM
lookup and BMP ingestion will be separate, later additions on top of this.

- [`docs/rib_structure.md`](../../docs/rib_structure.md) — hierarchy sketch
  and copy-on-write walkthrough.

## Attribute interning

`RibStore<I = AttrStore>` accepts any `AttrInterner`. The default preserves
the existing strong-reference pools and explicit `gc()` behavior. Select the
weak-reference implementation explicitly:

```rust
use netcalyx_rib::{AttrInterner, RibStore, RouteAttributes, WeakAttrStore};

let mut rib = RibStore::<WeakAttrStore>::default();
let attrs = rib.attr_store.intern(RouteAttributes::default());
```

Both implementations deduplicate sub-components before whole attribute sets,
and share one interner across the store's routers and views. Generic callers
can use `I::NEEDS_GC` to decide whether to schedule explicit sweeps.

`WeakAttrStore` does not own attribute values. They are dropped when the last
route or retained snapshot releases its `Arc`. On an insertion miss into a
full pool, that pool scans out dead weak entries; if it remains more than 75%
full, it reserves additional capacity. This is occasional synchronous cleanup,
not background or pause-free GC. `gc()` is a no-op for this implementation.

Dead weak entries retain backing allocations, including inline slice storage,
until removed. After large withdrawals with no subsequent insertions, those
allocations can remain indefinitely, and cleanup does not shrink table capacity.
Dropping values also does not guarantee immediate return of memory to the OS.

When using the default interner without an otherwise constraining type context,
write `let rib: RibStore = RibStore::default()` to select the default type.
