// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2025-present The NetGauze Authors.
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

//! Two-level (peer/subscription) state held by the validator.
//!
//! [`PeerCache`] owns every [`CachedSubscription`] and its hold buffer, and
//! is the only place that maintains the per-peer buffered-packet counter and
//! enforces the buffer limits. It does no logging or metrics: callers decide
//! how to report the outcome of each operation.

use crate::ContentId;
use crate::cache::storage::SubscriptionInfo;
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_udp_notif_service::UdpNotifRequest;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Per-subscription state held by the [`PeerCache`].
///
/// The combination of `schema_fetch_pending`, `yang_ctx`, and
/// `cached_content_id` encodes the current schema-loading state:
///
/// | `schema_fetch_pending` | `yang_ctx` | `cached_content_id` | Meaning |
/// |------------------------|------------|---------------------|---------|
/// | `true`  | `None`     | `None`     | Fetch in-flight — waiting for cache actor response |
/// | `false` | `Some(..)` | `Some(..)` | Schema loaded, validation active |
/// | `false` | `None`     | `Some(..)` | YANG library on disk but context creation failed, validation disabled ¹ |
/// | `false` | `None`     | `None`     | No YANG library available, validation disabled ² |
///
/// ¹ The cache actor returned a `YangLibraryReference` (files already
/// on disk from a prior cache hit or NETCONF device fetch), but
/// `Context::new_from_yang_library_file` failed — e.g. corrupt or missing
/// schema files. Packets are forwarded unvalidated.
///
/// ² The cache actor returned no `YangLibraryReference` — the NETCONF device
/// fetch failed or timed out. Packets are forwarded unvalidated.
///
/// `schema_fetch_pending` is set to `true` when a `LookupBySubscriptionInfo`
/// or `LookupBySubscriptionId` request is issued and cleared to `false` when
/// the cache actor responds, regardless of whether a schema was found. While
/// it is `true`, duplicate packets for the same subscription are buffered
/// rather than forwarded unvalidated.
///
/// At most one fetch is ever in-flight per subscription id: a
/// `SubscriptionStarted`/`SubscriptionModified` for the same id is also
/// buffered while pending, so a stale response can never clobber a newer
/// subscription generation.
#[derive(Debug)]
pub(super) struct CachedSubscription {
    cached_content_id: Option<ContentId>,
    subscription_info: SubscriptionInfo,
    yang_ctx: Option<yang5::context::Context>,
    buffered_packets: Vec<Arc<UdpNotifRequest>>,
    schema_fetch_pending: bool,
}

impl CachedSubscription {
    fn new(subscription_info: SubscriptionInfo) -> Self {
        Self {
            cached_content_id: None,
            subscription_info,
            yang_ctx: None,
            buffered_packets: Vec::new(),
            schema_fetch_pending: false,
        }
    }

    pub const fn cached_content_id(&self) -> Option<&ContentId> {
        self.cached_content_id.as_ref()
    }

    pub const fn subscription_info(&self) -> &SubscriptionInfo {
        &self.subscription_info
    }

    pub const fn yang_ctx(&self) -> Option<&yang5::context::Context> {
        self.yang_ctx.as_ref()
    }

    pub const fn is_fetch_pending(&self) -> bool {
        self.schema_fetch_pending
    }

    fn schema_state(&self) -> SchemaState {
        if self.cached_content_id.is_none() && self.schema_fetch_pending {
            SchemaState::FetchPending
        } else {
            SchemaState::Resolved
        }
    }
}

// TODO: entries here are never evicted by TTL/idleness (only replaced when a
// subscription's SubscriptionStarted info changes via
// `PeerCache::evict_if_changed`). A peer churning through many subscription
// IDs can grow this map unboundedly; consider a purge mechanism similar to
// `UdpNotifSupervisorHandle::purge_unused_peers`.
#[derive(Debug, Default)]
struct CachedPeerSubscriptions {
    subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
    /// Sum of `buffered_packets.len()` over all `subscriptions`.
    total_buffered: usize,
}

/// Schema-loading state of the cache entry matching a given
/// `SubscriptionInfo` (see the table on [`CachedSubscription`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SchemaState {
    /// No entry for this exact subscription: a cache lookup is needed.
    Untracked,
    /// A cache lookup is in-flight and no schema is known yet.
    FetchPending,
    /// The cache responded (with or without a usable schema).
    Resolved,
}

/// Which hold-buffer limit rejected a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BufferFull {
    Subscription,
    Peer,
}

/// Result of [`PeerCache::resolve`].
#[derive(Debug)]
pub(super) struct Resolved {
    /// Packets drained from the subscription's hold buffer, in arrival order.
    pub drained: Vec<Arc<UdpNotifRequest>>,
    /// Packets still buffered for the peer (other subscriptions).
    pub peer_buffered: usize,
    /// Number of subscriptions tracked for the peer.
    pub peer_subscriptions: usize,
}

/// Whether the peer and subscription ID in a schema-cache response
/// are tracked in the validator's peer cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tracking {
    UnknownPeer,
    UnknownSubscription,
    Tracked,
}

/// Per-peer, per-subscription validation state with bounded hold buffers.
#[derive(Debug)]
pub(super) struct PeerCache {
    max_buffered_packets_per_peer: usize,
    max_buffered_packets_per_subscription: usize,
    peers: FxHashMap<IpAddr, CachedPeerSubscriptions>,
}

impl PeerCache {
    pub fn new(
        max_buffered_packets_per_peer: usize,
        max_buffered_packets_per_subscription: usize,
    ) -> Self {
        Self {
            max_buffered_packets_per_peer,
            max_buffered_packets_per_subscription,
            peers: FxHashMap::default(),
        }
    }

    /// Number of peers currently tracked.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Packets currently buffered across all subscriptions of a peer.
    pub fn peer_buffered(&self, peer_ip: IpAddr) -> usize {
        self.peers.get(&peer_ip).map_or(0, |p| p.total_buffered)
    }

    /// Number of subscriptions currently tracked for a peer.
    pub fn peer_subscriptions(&self, peer_ip: IpAddr) -> usize {
        self.peers
            .get(&peer_ip)
            .map_or(0, |p| p.subscriptions.len())
    }

    /// Return the cached subscription for a peer IP and subscription ID.
    pub fn get(
        &self,
        peer_ip: IpAddr,
        subscription_id: SubscriptionId,
    ) -> Option<&CachedSubscription> {
        self.peers
            .get(&peer_ip)
            .and_then(|p| p.subscriptions.get(&subscription_id))
    }

    /// Check whether the peer and subscription ID are tracked.
    pub fn tracking(&self, peer_ip: IpAddr, subscription_id: SubscriptionId) -> Tracking {
        match self.peers.get(&peer_ip) {
            None => Tracking::UnknownPeer,
            Some(p) if !p.subscriptions.contains_key(&subscription_id) => {
                Tracking::UnknownSubscription
            }
            Some(_) => Tracking::Tracked,
        }
    }

    /// Return the schema-loading state for matching subscription metadata.
    /// Return [`SchemaState::Untracked`] if the peer or subscription ID is
    /// unknown, or if the stored metadata differs from the supplied info.
    pub fn schema_state(&self, subscription_info: &SubscriptionInfo) -> SchemaState {
        self.get(subscription_info.peer_ip(), subscription_info.id())
            .filter(|s| s.subscription_info == *subscription_info)
            .map_or(SchemaState::Untracked, CachedSubscription::schema_state)
    }

    /// Mark a cache lookup as in-flight for the subscription, creating its
    /// entry if needed.
    pub fn mark_fetch_pending(&mut self, subscription_info: &SubscriptionInfo) {
        self.entry(subscription_info.clone()).schema_fetch_pending = true;
    }

    /// If the peer is tracked and the entry for this subscription id is
    /// missing or holds different subscription info, remove it so a new
    /// cache lookup is issued. Drops the peer once it has no subscriptions.
    /// Returns `true` if the subscription was considered changed.
    /// Callers must not call this while a fetch is pending for the id (see
    /// the deferral in `Validator::resolve_subscription_info`), so the
    /// removed entry's hold buffer is always empty.
    pub fn evict_if_changed(&mut self, subscription_info: &SubscriptionInfo) -> bool {
        let peer_ip = subscription_info.peer_ip();
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return false;
        };
        let is_different = peer
            .subscriptions
            .get(&subscription_info.id())
            .is_none_or(|x| x.subscription_info != *subscription_info);
        if is_different && let Some(removed) = peer.subscriptions.remove(&subscription_info.id()) {
            peer.total_buffered -= removed.buffered_packets.len();
        }
        if peer.subscriptions.is_empty() {
            self.peers.remove(&peer_ip);
        }
        is_different
    }

    /// Add `message` to the subscription's hold buffer, enforcing the
    /// per-subscription limit first, then the per-peer limit. Returns
    /// the peer's total buffered packets on success.
    pub fn buffer(
        &mut self,
        subscription_info: SubscriptionInfo,
        message: Arc<UdpNotifRequest>,
    ) -> Result<usize, BufferFull> {
        let max_per_subscription = self.max_buffered_packets_per_subscription;
        let max_per_peer = self.max_buffered_packets_per_peer;
        let peer = self.peers.entry(subscription_info.peer_ip()).or_default();
        let sub_buffered = peer
            .subscriptions
            .get(&subscription_info.id())
            .map_or(0, |s| s.buffered_packets.len());
        if sub_buffered >= max_per_subscription {
            return Err(BufferFull::Subscription);
        }
        if peer.total_buffered >= max_per_peer {
            return Err(BufferFull::Peer);
        }
        peer.subscriptions
            .entry(subscription_info.id())
            .or_insert_with(|| CachedSubscription::new(subscription_info))
            .buffered_packets
            .push(message);
        peer.total_buffered += 1;
        Ok(peer.total_buffered)
    }

    /// Record the outcome of a schema fetch (see the state table on
    /// [`CachedSubscription`]), clear `schema_fetch_pending`, and drain the
    /// hold buffer. Returns `None` if the subscription is not tracked.
    pub fn resolve(
        &mut self,
        subscription_info: SubscriptionInfo,
        cached_content_id: Option<ContentId>,
        yang_ctx: Option<yang5::context::Context>,
    ) -> Option<Resolved> {
        let peer = self.peers.get_mut(&subscription_info.peer_ip())?;
        let subscription = peer.subscriptions.get_mut(&subscription_info.id())?;
        subscription.cached_content_id = cached_content_id;
        subscription.yang_ctx = yang_ctx;
        subscription.subscription_info = subscription_info;
        subscription.schema_fetch_pending = false;
        let drained = std::mem::take(&mut subscription.buffered_packets);
        peer.total_buffered -= drained.len();
        Some(Resolved {
            drained,
            peer_buffered: peer.total_buffered,
            peer_subscriptions: peer.subscriptions.len(),
        })
    }

    /// Get or create the subscription entry and its containing peer.
    fn entry(&mut self, subscription_info: SubscriptionInfo) -> &mut CachedSubscription {
        self.peers
            .entry(subscription_info.peer_ip())
            .or_default()
            .subscriptions
            .entry(subscription_info.id())
            .or_insert_with(|| CachedSubscription::new(subscription_info))
    }
}

#[cfg(test)]
mod tests;
