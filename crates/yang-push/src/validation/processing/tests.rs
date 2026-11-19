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

use super::{CacheLookup, PacketOutcome, Validator};
use crate::ContentId;
use crate::cache::storage::SubscriptionInfo;
use crate::validation::stats::ValidationStats;
use crate::validation::subscription::tests::load_test_yang_ctx;
use bytes::Bytes;
use netcalyx_udp_notif_pkt::raw::{MediaType, UdpNotifPacket};
use netcalyx_udp_notif_service::{SessionInfo, UdpNotifRequest};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5000);
const TEST_CONTENT_ID: &str = "test-cached-content-id";

/// Create a new validator with the given hold-buffer limits.
fn new_validator(max_per_peer: usize, max_per_subscription: usize) -> Validator {
    Validator::new(
        max_per_peer,
        max_per_subscription,
        true,
        ValidationStats::new(opentelemetry::global::meter("test_meter")),
    )
}

/// Wrap a JSON payload in a UDP-Notif request from the test peer.
fn request(message_id: u32, payload: &serde_json::Value) -> Arc<UdpNotifRequest> {
    Arc::new(UdpNotifRequest::new(
        SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, PEER),
        UdpNotifPacket::new(
            MediaType::YangDataJson,
            10,
            message_id,
            HashMap::new(),
            Bytes::from(serde_json::to_vec(payload).unwrap()),
        ),
    ))
}

/// Build a SubscriptionStarted payload with interface schema metadata.
fn subscription_started(subscription_id: u32, content_id: &str) -> serde_json::Value {
    serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "hostname": "test-router-01",
        "sequence-number": 0,
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": subscription_id,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "ietf-distributed-notif:message-publisher-id": [16843789],
            "ietf-yang-push-revision:module-version": [
              {"name": "ietf-interfaces", "revision": "2018-02-20"}
            ],
            "ietf-yang-push-revision:yang-library-content-id": content_id,
            "ietf-yang-push:periodic": {"period": 6000}
          }
        }
      }
    })
}

/// Build an interface push-update with a configurable enabled leaf name.
fn push_update(subscription_id: u32, enabled_key: &str) -> serde_json::Value {
    serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2026-04-21T13:33:31.007Z",
        "hostname": "test-router-01",
        "sequence-number": 1,
        "contents": {
          "ietf-yang-push:push-update": {
            "id": subscription_id,
            "datastore-contents": {
              "ietf-interfaces:interfaces": {
                "interface": [{
                  "name": "GigabitEthernet0/0/0",
                  "type": "iana-if-type:ethernetCsmacd",
                  enabled_key: true,
                  "admin-status": "up",
                  "oper-status": "up",
                  "if-index": 1,
                  "speed": "1000000000"
                }]
              }
            },
            "ietf-distributed-notif:message-publisher-id": 16974839
          }
        }
      }
    })
}

/// Require a lookup by subscription info and extract its subscription info.
fn expect_lookup_by_info(outcome: PacketOutcome) -> SubscriptionInfo {
    match outcome {
        PacketOutcome::CacheLookup(CacheLookup::BySubscriptionInfo {
            subscription_info, ..
        }) => *subscription_info,
        other => panic!("expected lookup by subscription info, got {other:?}"),
    }
}

/// Extract the notification, panicking unless the outcome forwards it.
fn expect_forward(outcome: PacketOutcome) -> super::ValidatedNotification {
    match outcome {
        PacketOutcome::Forward { notification, .. } => notification,
        other => panic!("expected forward, got {other:?}"),
    }
}

/// Return the number of packets buffered for the test peer.
fn total_buffered(validator: &Validator) -> usize {
    validator.peer_cache.peer_buffered(PEER.ip())
}

/// Drain all pending packets, returning their outcomes.
fn drain_pending(validator: &mut Validator) -> Vec<PacketOutcome> {
    let mut outcomes = Vec::new();
    while let Some(message) = validator.pop_pending() {
        outcomes.push(validator.process_packet(message, true));
    }
    outcomes
}

/// Load a schema for subscription 1 through a SubscriptionStarted, as the
/// actor would once the cache responds.
fn load_schema(validator: &mut Validator) -> SubscriptionInfo {
    let subscription_info = expect_lookup_by_info(
        validator.process_packet(request(1, &subscription_started(1, "c1")), false),
    );
    validator.apply_schema(
        subscription_info.clone(),
        Some(ContentId::from(TEST_CONTENT_ID.to_string())),
        Some(load_test_yang_ctx()),
    );
    let outcomes = drain_pending(validator);
    assert_eq!(outcomes.len(), 1);
    subscription_info
}

/// A SubscriptionStarted triggers a lookup and is buffered; once the schema
/// is applied it is drained, validated, and forwarded with the content id.
#[test]
fn test_validator_subscription_started_buffered_until_schema_loaded() {
    let mut validator = new_validator(100, 100);
    let subscription_info = expect_lookup_by_info(
        validator.process_packet(request(1, &subscription_started(1, "c1")), false),
    );
    assert_eq!(subscription_info.id(), 1);
    assert_eq!(total_buffered(&validator), 1);
    assert!(!validator.has_pending());

    validator.apply_schema(
        subscription_info,
        Some(ContentId::from(TEST_CONTENT_ID.to_string())),
        Some(load_test_yang_ctx()),
    );
    assert_eq!(total_buffered(&validator), 0);
    assert!(validator.has_pending());

    let mut outcomes = drain_pending(&mut validator);
    assert_eq!(outcomes.len(), 1);
    let notification = expect_forward(outcomes.remove(0));
    assert_eq!(
        notification.cached_content_id.as_deref(),
        Some(TEST_CONTENT_ID)
    );
    assert_eq!(notification.packet.message_id(), 1);
}

/// With a loaded schema, a valid push-update is forwarded right away and an
/// invalid one (unknown leaf) is dropped.
#[test]
fn test_validator_validates_against_loaded_schema() {
    let mut validator = new_validator(100, 100);
    load_schema(&mut validator);

    let valid =
        expect_forward(validator.process_packet(request(2, &push_update(1, "enabled")), false));
    assert_eq!(valid.cached_content_id.as_deref(), Some(TEST_CONTENT_ID));

    let invalid = validator.process_packet(request(3, &push_update(1, "enabelled")), false);
    assert!(
        matches!(invalid, PacketOutcome::Consumed),
        "got {invalid:?}"
    );
}

/// Packets for an unknown subscription trigger a single lookup by id; later
/// packets for the same id are buffered while the fetch is in-flight. If the
/// cache has no schema, all of them are forwarded unvalidated.
#[test]
fn test_validator_unknown_subscription_single_lookup_then_unvalidated() {
    let mut validator = new_validator(100, 100);
    match validator.process_packet(request(1, &push_update(7, "enabled")), false) {
        PacketOutcome::CacheLookup(CacheLookup::BySubscriptionId {
            subscription_id, ..
        }) => assert_eq!(subscription_id, 7),
        other => panic!("expected lookup by subscription id, got {other:?}"),
    }
    let second = validator.process_packet(request(2, &push_update(7, "enabled")), false);
    assert!(matches!(second, PacketOutcome::Consumed), "got {second:?}");
    assert_eq!(total_buffered(&validator), 2);

    validator.apply_schema(SubscriptionInfo::new_empty(PEER.ip(), 7), None, None);
    let outcomes = drain_pending(&mut validator);
    let message_ids: Vec<_> = outcomes
        .into_iter()
        .map(|o| {
            let n = expect_forward(o);
            assert!(n.cached_content_id.is_none());
            n.packet.message_id()
        })
        .collect();
    assert_eq!(message_ids, vec![1, 2]);
}

/// A SubscriptionStarted for an id whose fetch is still in-flight is
/// deferred (buffered) rather than issuing a second lookup.
#[test]
fn test_validator_defers_subscription_started_while_fetch_pending() {
    let mut validator = new_validator(100, 100);
    expect_lookup_by_info(
        validator.process_packet(request(1, &subscription_started(1, "c1")), false),
    );
    let changed = validator.process_packet(request(2, &subscription_started(1, "c2")), false);
    assert!(
        matches!(changed, PacketOutcome::Consumed),
        "got {changed:?}"
    );
    assert_eq!(total_buffered(&validator), 2);
}

/// The per-subscription hold buffer limit drops excess packets.
#[test]
fn test_validator_subscription_buffer_limit() {
    let mut validator = new_validator(100, 1);
    let first = validator.process_packet(request(1, &push_update(1, "enabled")), false);
    assert!(
        matches!(first, PacketOutcome::CacheLookup(_)),
        "got {first:?}"
    );
    let second = validator.process_packet(request(2, &push_update(1, "enabled")), false);
    assert!(matches!(second, PacketOutcome::Consumed), "got {second:?}");
    assert_eq!(total_buffered(&validator), 1);
}

/// The per-peer limit applies across all subscriptions of the same peer.
#[test]
fn test_validator_peer_buffer_limit() {
    let mut validator = new_validator(2, 100);
    for subscription_id in 1..=3 {
        let outcome = validator.process_packet(
            request(subscription_id, &push_update(subscription_id, "enabled")),
            false,
        );
        assert!(
            matches!(outcome, PacketOutcome::CacheLookup(_)),
            "got {outcome:?}"
        );
    }
    assert_eq!(total_buffered(&validator), 2);
}

/// A SubscriptionStarted without module-version cannot yield subscription
/// info and is dropped without a lookup.
#[test]
fn test_validator_incomplete_subscription_started_dropped() {
    let mut payload = subscription_started(1, "c1");
    payload["ietf-yp-notification:envelope"]["contents"]
        ["ietf-subscribed-notifications:subscription-started"]
        .as_object_mut()
        .unwrap()
        .remove("ietf-yang-push-revision:module-version");
    let outcome = validator_outcome(&payload);
    assert!(
        matches!(outcome, PacketOutcome::Consumed),
        "got {outcome:?}"
    );
}

/// Process a payload with a fresh validator and require an empty hold buffer.
fn validator_outcome(payload: &serde_json::Value) -> PacketOutcome {
    let mut validator = new_validator(100, 100);
    let outcome = validator.process_packet(request(1, payload), false);
    assert_eq!(total_buffered(&validator), 0);
    outcome
}

/// Undecodable payloads are dropped.
#[test]
fn test_validator_undecodable_packet_dropped() {
    let mut validator = new_validator(100, 100);
    let message = Arc::new(UdpNotifRequest::new(
        SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, PEER),
        UdpNotifPacket::new(
            MediaType::YangDataJson,
            10,
            1,
            HashMap::new(),
            Bytes::from_static(b"not json"),
        ),
    ));
    let outcome = validator.process_packet(message, false);
    assert!(
        matches!(outcome, PacketOutcome::Consumed),
        "got {outcome:?}"
    );
    assert_eq!(validator.peer_cache.peer_count(), 0);
}

/// Applying a schema for an untracked subscription is a no-op.
#[test]
fn test_validator_apply_schema_untracked_is_noop() {
    let mut validator = new_validator(100, 100);
    validator.apply_schema(SubscriptionInfo::new_empty(PEER.ip(), 1), None, None);
    assert_eq!(validator.peer_cache.peer_count(), 0);
    assert!(!validator.has_pending());
}
