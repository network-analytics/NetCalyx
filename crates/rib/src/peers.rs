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

//! Peer-address resolution.
//!
//! A caller typically holds a neighbor or next-hop *address*, but BMP
//! identifies a peer by the tuple `(address, type, RD, ASN, BGP-ID)`.
//! Resolving address -> peer by scanning a router's peer map costs O(peers)
//! on the hot path. `PeerIndex` is a context-scoped `address -> peer(s)` map
//! built once as peers come and go, so resolution during a lookup is O(1) in
//! the expected case.
//!
//! An address normally resolves to exactly one peer once the RIB context (the
//! RD) is fixed. It can still map to several peers within one context while a
//! session flaps: the new peer-up carries a different BGP-ID or ASN and lands
//! before the old peer-down. The index keeps every candidate rather than
//! collapsing them, so a lookup narrows to those few peers instead of falling
//! back to scanning the whole peer map, and it returns to a single candidate
//! as soon as the stale peer goes down.

use std::hash::Hash;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

pub struct PeerIndex<K, P> {
    map: FxHashMap<K, SmallVec<[P; 1]>>,
}

impl<K, P> Default for PeerIndex<K, P> {
    fn default() -> Self {
        Self {
            map: FxHashMap::default(),
        }
    }
}

impl<K, P> Clone for PeerIndex<K, P>
where
    K: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<K, P> PeerIndex<K, P>
where
    K: Eq + Hash,
    P: Copy + PartialEq,
{
    pub fn insert(&mut self, key: K, peer: P) {
        let candidates = self.map.entry(key).or_default();
        if !candidates.contains(&peer) {
            candidates.push(peer);
        }
    }

    /// Drop `peer` from `key`. If it was the last candidate, the key is
    /// removed; if others remain (the ambiguous case), they stay resolvable.
    pub fn remove(&mut self, key: &K, peer: P) {
        if let Some(candidates) = self.map.get_mut(key) {
            candidates.retain(|p| *p != peer);
            if candidates.is_empty() {
                self.map.remove(key);
            }
        }
    }

    /// Every peer that `key` currently resolves to. Empty means no match; more
    /// than one means the address is genuinely shared within this context
    /// and the caller must disambiguate among the candidates itself.
    pub fn get(&self, key: &K) -> &[P] {
        self.map.get(key).map(SmallVec::as_slice).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Keys currently resolving to more than one peer. O(n); only exists to
    /// assert the unambiguity in tests. Un-gate if needed by a consumer.
    #[cfg(test)]
    fn ambiguous_keys(&self) -> usize {
        self.map.values().filter(|c| c.len() > 1).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_resolves_single_peer() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.insert("10.0.0.1", 1);
        assert_eq!(index.get(&"10.0.0.1"), &[1]);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn insert_same_key_different_peer_keeps_both_candidates() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.insert("10.0.0.1", 1);
        index.insert("10.0.0.1", 2);
        assert_eq!(index.get(&"10.0.0.1"), &[1, 2]);
        assert_eq!(index.ambiguous_keys(), 1);
    }

    #[test]
    fn insert_same_peer_twice_does_not_duplicate() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.insert("10.0.0.1", 1);
        index.insert("10.0.0.1", 1);
        assert_eq!(index.get(&"10.0.0.1"), &[1]);
    }

    #[test]
    fn remove_clears_the_only_candidate() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.insert("10.0.0.1", 1);
        index.remove(&"10.0.0.1", 1);
        assert_eq!(index.get(&"10.0.0.1"), &[] as &[u32]);
        assert!(index.is_empty());
    }

    #[test]
    fn remove_from_multi_candidate_key_resolves_it_back_to_one() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.insert("10.0.0.1", 1);
        index.insert("10.0.0.1", 2);
        index.remove(&"10.0.0.1", 1);
        assert_eq!(index.get(&"10.0.0.1"), &[2]);
        assert_eq!(index.ambiguous_keys(), 0);
    }

    #[test]
    fn remove_on_absent_key_is_a_no_op() {
        let mut index = PeerIndex::<&str, u32>::default();
        index.remove(&"10.0.0.1", 1);
        assert!(index.is_empty());
    }

    #[test]
    fn clone_produces_an_independent_copy() {
        let mut original = PeerIndex::<&str, u32>::default();
        original.insert("10.0.0.1", 1);

        let mut cloned = original.clone();
        cloned.insert("10.0.0.1", 2);

        assert_eq!(original.get(&"10.0.0.1"), &[1]);
        assert_eq!(cloned.get(&"10.0.0.1"), &[1, 2]);
    }
}
