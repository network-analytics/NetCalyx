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

use super::{BufferError, ClearCacheReport, PeerCache, PeerCacheError, SchemaState, Tracking};
use crate::ContentId;
use crate::cache::storage::SubscriptionInfo;
use bytes::Bytes;
use netcalyx_udp_notif_pkt::notification::Target;
use netcalyx_udp_notif_pkt::raw::{MediaType, UdpNotifPacket};
use netcalyx_udp_notif_service::{SessionInfo, UdpNotifRequest};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn message(peer_ip: IpAddr, message_id: u32) -> Arc<UdpNotifRequest> {
    Arc::new(UdpNotifRequest::new(
        SessionInfo::new(
            SocketAddr::from(([127, 0, 0, 1], 10000)),
            None,
            SocketAddr::new(peer_ip, 5000),
        ),
        UdpNotifPacket::new(
            MediaType::YangDataJson,
            10,
            message_id,
            HashMap::new(),
            Bytes::new(),
        ),
    ))
}

fn info(peer_ip: IpAddr, id: u32, content_id: &str) -> SubscriptionInfo {
    SubscriptionInfo::new(
        peer_ip,
        id,
        Target::new_datastore(
            "ietf-datastores:operational".to_string(),
            either::Right("/ietf-interfaces:interfaces".to_string()),
        ),
        None,
        None,
        None,
        None,
        None,
        Box::new([]),
        ContentId::from(content_id.to_string()),
    )
}

fn message_ids(messages: &[Arc<UdpNotifRequest>]) -> Vec<u32> {
    messages.iter().map(|m| m.packet().message_id()).collect()
}

#[test]
fn test_schema_state_transitions() {
    let mut cache = PeerCache::new(10, 10);
    let sub = info(PEER_IP, 1, "c1");
    assert_eq!(cache.schema_state(&sub), SchemaState::Untracked);

    cache.mark_fetch_pending(&sub);
    assert_eq!(cache.schema_state(&sub), SchemaState::FetchPending);
    assert!(cache.get(PEER_IP, 1).unwrap().is_fetch_pending());

    // Same id with different info is not the tracked subscription.
    assert_eq!(
        cache.schema_state(&info(PEER_IP, 1, "c2")),
        SchemaState::Untracked
    );

    cache.resolve(sub.clone(), None, None).unwrap();
    assert_eq!(cache.schema_state(&sub), SchemaState::Resolved);
    assert!(!cache.get(PEER_IP, 1).unwrap().is_fetch_pending());
}

#[test]
fn test_tracking() {
    let mut cache = PeerCache::new(10, 10);
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownPeer);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::Tracked);
    assert_eq!(cache.tracking(PEER_IP, 2), Tracking::UnknownSubscription);
}

/// The per-subscription limit is checked before the per-peer limit, and the
/// per-peer limit is shared across subscriptions.
#[test]
fn test_buffer_limits() {
    let mut cache = PeerCache::new(3, 2);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    cache.mark_fetch_pending(&info(PEER_IP, 2, "c2"));
    assert_eq!(cache.buffer(PEER_IP, 1, message(PEER_IP, 1)), Ok(1));
    assert_eq!(cache.buffer(PEER_IP, 1, message(PEER_IP, 2)), Ok(2));
    assert_eq!(
        cache.buffer(PEER_IP, 1, message(PEER_IP, 3)),
        Err(BufferError::SubscriptionFull)
    );
    assert_eq!(cache.buffer(PEER_IP, 2, message(PEER_IP, 4)), Ok(3));
    assert_eq!(
        cache.buffer(PEER_IP, 2, message(PEER_IP, 5)),
        Err(BufferError::PeerFull)
    );
    assert_eq!(cache.peer_buffered(PEER_IP), 3);

    // Limits are per peer.
    cache.mark_fetch_pending(&info(OTHER_PEER_IP, 1, "c1"));
    assert_eq!(
        cache.buffer(OTHER_PEER_IP, 1, message(OTHER_PEER_IP, 6)),
        Ok(1)
    );
}

#[test]
fn test_buffer_does_not_create_cache_entries() {
    let mut cache = PeerCache::new(10, 10);
    assert_eq!(
        cache.buffer(PEER_IP, 1, message(PEER_IP, 1)),
        Err(BufferError::UntrackedSubscription)
    );
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownPeer);

    cache.mark_fetch_pending(&info(PEER_IP, 2, "c2"));
    assert_eq!(
        cache.buffer(PEER_IP, 1, message(PEER_IP, 2)),
        Err(BufferError::UntrackedSubscription)
    );
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownSubscription);
    assert_eq!(cache.peer_buffered(PEER_IP), 0);
}

/// Resolving drains only that subscription's buffer, in arrival order, and
/// keeps the peer counter consistent.
#[test]
fn test_resolve_drains_buffer() {
    let mut cache = PeerCache::new(10, 10);
    let sub1 = info(PEER_IP, 1, "c1");
    cache.mark_fetch_pending(&sub1);
    cache.mark_fetch_pending(&info(PEER_IP, 2, "c2"));
    cache.buffer(PEER_IP, 1, message(PEER_IP, 1)).unwrap();
    cache.buffer(PEER_IP, 2, message(PEER_IP, 2)).unwrap();
    cache.buffer(PEER_IP, 1, message(PEER_IP, 3)).unwrap();

    let resolved = cache
        .resolve(sub1, Some(ContentId::from("x".to_string())), None)
        .unwrap();
    assert_eq!(message_ids(&resolved.drained), vec![1, 3]);
    assert_eq!(resolved.peer_buffered, 1);
    assert_eq!(resolved.peer_subscriptions, 2);
    assert_eq!(cache.peer_buffered(PEER_IP), 1);
    let cached = cache.get(PEER_IP, 1).unwrap();
    assert_eq!(cached.cached_content_id().map(|c| c.as_str()), Some("x"));
    assert!(cached.yang_ctx().is_none());
}

/// The cache response's subscription info replaces the stored one (e.g. an
/// empty placeholder created by a lookup by id).
#[test]
fn test_resolve_replaces_subscription_info() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&SubscriptionInfo::new_empty(PEER_IP, 1));
    let full = info(PEER_IP, 1, "c1");
    cache.resolve(full.clone(), None, None).unwrap();
    assert_eq!(cache.get(PEER_IP, 1).unwrap().subscription_info(), &full);
}

#[test]
fn test_resolve_untracked_is_none() {
    let mut cache = PeerCache::new(10, 10);
    assert!(cache.resolve(info(PEER_IP, 1, "c1"), None, None).is_none());
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    assert!(cache.resolve(info(PEER_IP, 2, "c2"), None, None).is_none());
}

#[test]
fn test_evict_if_changed() {
    let mut cache = PeerCache::new(10, 10);
    let sub1 = info(PEER_IP, 1, "c1");
    // Untracked peer: nothing to compare against.
    assert!(!cache.evict_if_changed(&sub1));

    cache.mark_fetch_pending(&sub1);
    cache.resolve(sub1.clone(), None, None).unwrap();
    assert!(!cache.evict_if_changed(&sub1));
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::Tracked);

    // Changed info for the only subscription evicts it and the peer.
    assert!(cache.evict_if_changed(&info(PEER_IP, 1, "c2")));
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownPeer);
    assert_eq!(cache.peer_count(), 0);
}

/// A new id for a tracked peer counts as changed but keeps the other
/// subscriptions.
#[test]
fn test_evict_if_changed_new_id_keeps_peer() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    assert!(cache.evict_if_changed(&info(PEER_IP, 2, "c2")));
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::Tracked);
    assert_eq!(cache.peer_count(), 1);
}

#[test]
fn test_snapshot_all() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    cache.mark_fetch_pending(&info(OTHER_PEER_IP, 1, "c2"));

    let snapshot = cache.snapshot_all();
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot[&PEER_IP].contains_key(&1));
    assert!(snapshot[&OTHER_PEER_IP].contains_key(&1));
}

/// Only the requested peer is part of the snapshot.
#[test]
fn test_snapshot_peer() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    cache.mark_fetch_pending(&info(OTHER_PEER_IP, 1, "c2"));

    let snapshot = cache.snapshot_peer(OTHER_PEER_IP).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[&OTHER_PEER_IP].contains_key(&1));
}

#[test]
fn test_snapshot_buffered_and_pending() {
    let mut cache = PeerCache::new(10, 10);
    let sub = info(PEER_IP, 1, "c1");
    cache.mark_fetch_pending(&sub);
    cache.buffer(PEER_IP, 1, message(PEER_IP, 1)).unwrap();

    let snapshot = cache.snapshot_peer(PEER_IP).unwrap();
    assert_eq!(snapshot[&PEER_IP][&1].buffered_packet_count, 1);
    assert!(snapshot[&PEER_IP][&1].schema_fetch_pending);

    cache.resolve(sub, None, None).unwrap();
    let snapshot = cache.snapshot_peer(PEER_IP).unwrap();
    assert_eq!(snapshot[&PEER_IP][&1].buffered_packet_count, 0);
    assert!(!snapshot[&PEER_IP][&1].schema_fetch_pending);
}

#[test]
fn test_snapshot_peer_untracked_is_error() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    assert_eq!(
        cache.snapshot_peer(OTHER_PEER_IP),
        Err(PeerCacheError::PeerNotFound(OTHER_PEER_IP))
    );
}

/// Clearing a peer drops only that peer.
#[test]
fn test_clear_peer() {
    let mut cache = PeerCache::new(10, 10);
    let sub = info(PEER_IP, 1, "c1");
    cache.mark_fetch_pending(&sub);
    cache.resolve(sub, None, None).unwrap();
    cache.mark_fetch_pending(&info(OTHER_PEER_IP, 1, "c2"));

    assert_eq!(
        cache.clear_peer(PEER_IP),
        Ok(ClearCacheReport {
            cleared_peers: vec![PEER_IP],
            skipped_peers: vec![],
        })
    );
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownPeer);
    assert_eq!(cache.tracking(OTHER_PEER_IP, 1), Tracking::Tracked);
    assert_eq!(cache.peer_count(), 1);
}

#[test]
fn test_clear_peer_untracked_is_error() {
    let mut cache = PeerCache::new(10, 10);
    assert_eq!(
        cache.clear_peer(PEER_IP),
        Err(PeerCacheError::PeerNotFound(PEER_IP))
    );
}

/// A peer with a fetch in flight is kept, since removing it would drop its
/// hold buffers.
#[test]
fn test_clear_peer_pending_is_error() {
    let mut cache = PeerCache::new(10, 10);
    cache.mark_fetch_pending(&info(PEER_IP, 1, "c1"));
    cache.buffer(PEER_IP, 1, message(PEER_IP, 1)).unwrap();
    assert_eq!(
        cache.clear_peer(PEER_IP),
        Err(PeerCacheError::SchemaFetchPending(PEER_IP))
    );
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::Tracked);
    assert_eq!(cache.peer_buffered(PEER_IP), 1);
}

/// Peers are skipped as a whole: one pending subscription keeps the peer.
#[test]
fn test_clear_all_skips_pending_peers() {
    let mut cache = PeerCache::new(10, 10);
    let idle = info(PEER_IP, 1, "c1");
    cache.mark_fetch_pending(&idle);
    cache.resolve(idle, None, None).unwrap();

    let resolved = info(OTHER_PEER_IP, 1, "c2");
    cache.mark_fetch_pending(&resolved);
    cache.resolve(resolved, None, None).unwrap();
    cache.mark_fetch_pending(&info(OTHER_PEER_IP, 2, "c3"));

    assert_eq!(
        cache.clear_all(),
        ClearCacheReport {
            cleared_peers: vec![PEER_IP],
            skipped_peers: vec![OTHER_PEER_IP],
        }
    );
    assert_eq!(cache.tracking(PEER_IP, 1), Tracking::UnknownPeer);
    assert_eq!(cache.peer_subscriptions(OTHER_PEER_IP), 2);
}
