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

use crate::cache::actor::tests::setup_actor_with_empty_cache;
use crate::cache::storage::SubscriptionInfo;
use crate::validation::{ValidatedNotification, ValidationActorHandle, ValidationStats};
use bytes::Bytes;
use netcalyx_udp_notif_pkt::raw::{MediaType, UdpNotifPacket};
use netcalyx_udp_notif_service::{SessionInfo, UdpNotifRequest};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Spawns a full validation actor stack with default buffer sizes
/// (peer=1000, subscription=100) and 100-slot channels. Returns
/// everything a test needs. Use for tests that don't require
/// non-standard buffer or channel sizes.
#[allow(clippy::type_complexity)]
fn setup_validation_actor() -> (
    tokio::task::JoinHandle<Result<String, crate::cache::actor::CacheActorCacheError>>,
    crate::cache::actor::CacheActorHandle,
    SubscriptionInfo,
    Arc<std::sync::Mutex<HashMap<SubscriptionInfo, usize>>>,
    async_channel::Sender<Arc<UdpNotifRequest>>,
    async_channel::Receiver<ValidatedNotification>,
    ValidationActorHandle,
) {
    let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
        setup_actor_with_empty_cache();
    let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
    let (validated_tx, validated_rx) = async_channel::bounded(100);
    let (_join_handle, handle) = ValidationActorHandle::new(
        100,
        1000,
        100,
        true,
        udp_notif_rx,
        validated_tx,
        caching_handle.request_tx(),
        either::Right(ValidationStats::new(opentelemetry::global::meter(
            "test_meter",
        ))),
    )
    .expect("Failed to spawn validation actor");
    (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    )
}

/// Sends a SubscriptionStarted to load YANG schemas, drains the forwarded
/// result, then returns so that the caller can send data packets that will
/// be validated against the loaded context.
async fn setup_and_load_schema(
    udp_notif_tx: &async_channel::Sender<Arc<UdpNotifRequest>>,
    validated_rx: &async_channel::Receiver<ValidatedNotification>,
    peer: SocketAddr,
) {
    let payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "hostname": "test-router-01",
        "sequence-number": 0,
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [
              16843789
            ],
            "ietf-yang-push-revision:module-version": [
              {
                "name": "ietf-interfaces",
                "revision": "2018-02-20"
              }
            ],
            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
            "ietf-yang-push:periodic": {
              "period": 6000
            }
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                1,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();
    // Draining the validated SubscriptionStarted also serves as the
    // synchronisation point: by the time it is forwarded the YANG context
    // is fully loaded and ready for subsequent push-update packets.
    let ValidatedNotification {
        cached_content_id: content_id,
        ..
    } = tokio::time::timeout(Duration::from_secs(2), validated_rx.recv())
        .await
        .expect("timeout waiting for SubscriptionStarted to be validated")
        .unwrap();
    assert!(
        content_id.is_some(),
        "SubscriptionStarted must pass YANG validation"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_schema_fetched() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    assert_eq!(fetcher_count.lock().unwrap().len(), 0);

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    let payload = serde_json::json!(
        {
            "ietf-yp-notification:envelope": {
                "event-time": "2025-09-23T14:12:16.024Z",
                "hostname": "ipf-zbl1327-r-daisy-48",
                "sequence-number": 0,
                "contents": {
                    "ietf-subscribed-notifications:subscription-started": {
                        "id": 1,
                        "ietf-yang-push:datastore": "ietf-datastores:operational",
                        "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
                        "transport": "ietf-udp-notif-transport:udp-notif",
                        "encoding": "encode-json",
                        "purpose": "test subscription",
                        "ietf-distributed-notif:message-publisher-id": [
                            16843789
                        ],
                        "ietf-yang-push-revision:module-version": [
                            {
                                "name": "ietf-interfaces",
                                "revision": "2018-02-20"
                            }
                        ],
                        "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
                        "ietf-yang-push:periodic": {
                            "period": 6000
                        }
                    }
                }
            }
        }
    );
    let bytes = serde_json::to_vec(&payload).unwrap();
    let subscription_started_packet = UdpNotifPacket::new(
        MediaType::YangDataJson,
        10,
        1,
        HashMap::new(),
        Bytes::from(bytes),
    );

    // Send SubscriptionStarted packet
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            subscription_started_packet,
        )))
        .await
        .unwrap();

    // Allow actor to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify packet is validated
    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout waiting for response")
        .unwrap();
    assert!(content_id.is_some());
    assert!(!sub_info.is_empty());

    // check fetcher was called
    {
        let hits_counts = fetcher_count
            .lock()
            .expect("Failed to lock fetcher counts")
            .clone();
        assert_eq!(hits_counts.len(), 1);
    }

    // Shutdown actor
    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_schema_not_found() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    assert_eq!(fetcher_count.lock().unwrap().len(), 0);

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    let payload = serde_json::json!(
        {
          "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:31:27.134Z",
            "hostname": "ipf-zbl1312-r-ap-01",
            "sequence-number": 0,
            "contents": {
              "ietf-subscribed-notifications:subscription-started": {
                "id": 9,
                "ietf-yang-push:datastore": "ietf-datastores:operational",
                "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces/interface",
                "transport": "ietf-udp-notif-transport:udp-notif",
                "encoding": "encode-json",
                "ietf-distributed-notif:message-publisher-id": [
                  16974839
                ],
                "ietf-yang-push-revision:module-version": [
                  {
                    "name": "ietf-interfaces",
                    "revision": "2018-02-20"
                  }
                ],
                "ietf-yang-push-revision:yang-library-content-id": "1903509911",
                "ietf-yang-push:periodic": {
                  "period": 6000,
                  "anchor-time": "2025-01-01T00:00:30Z"
                }
              }
            }
          }
        }
    );
    let bytes = serde_json::to_vec(&payload).unwrap();
    let subscription_started_packet = UdpNotifPacket::new(
        MediaType::YangDataJson,
        10,
        1,
        HashMap::new(),
        Bytes::from(bytes),
    );

    // Send SubscriptionStarted packet
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            subscription_started_packet,
        )))
        .await
        .unwrap();

    // Allow actor to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify packet is not validated
    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout waiting for response")
        .unwrap();
    assert!(content_id.is_none());
    assert!(!sub_info.is_empty());

    // check fetcher was called
    {
        let hits_counts = fetcher_count
            .lock()
            .expect("Failed to lock fetcher counts")
            .clone();
        assert_eq!(hits_counts.len(), 1);
    }

    // Shutdown actor
    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// Regression test for the cache-drain deadlock: when schemas arrive
/// and a large buffer of packets is drained while the downstream is
/// backpressured, the actor must keep draining cache_rx/rx (process
/// packets one-at-a-time) instead of blocking inside
/// process_cache_response. A slow consumer with a tiny buffer would
/// previously freeze the actor; here all packets flow.
#[tokio::test]
async fn test_validation_actor_drains_under_backpressure() {
    let (caching_join_handle, caching_handle, subscription_info, _fetcher_count) =
        setup_actor_with_empty_cache();

    let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(50);
    // Tiny downstream buffer forces backpressure during the drain.
    let (validated_tx, validated_rx) = async_channel::bounded(1);

    let (_join_handle, handle) = ValidationActorHandle::new(
        100,
        10000,
        1000,
        true,
        udp_notif_rx,
        validated_tx,
        caching_handle.request_tx(),
        either::Right(ValidationStats::new(opentelemetry::global::meter(
            "test_meter",
        ))),
    )
    .expect("Failed to spawn validation actor");

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    let payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "type": "iana-if-type:ethernetCsmacd",
                                    "enabled": true,
                                    "admin-status": "up",
                                    "oper-status": "up",
                                    "if-index": 1,
                                    "speed": "1000000000"
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&payload).unwrap();

    const N: usize = 200;
    // Produce concurrently with consumption so the tiny downstream buffer
    // never deadlocks the producer; the point is that the actor keeps
    // draining its input/cache channels under backpressure.
    let producer = tokio::spawn(async move {
        for i in 0..N {
            udp_notif_tx
                .send(Arc::new(UdpNotifRequest::new(
                    SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
                    UdpNotifPacket::new(
                        MediaType::YangDataJson,
                        10,
                        i as u32,
                        HashMap::new(),
                        Bytes::from(bytes.clone()),
                    ),
                )))
                .await
                .unwrap();
        }
        udp_notif_tx
    });

    // Slow consumer: every packet must still be forwarded without the actor
    // freezing on input or cache channels.
    for _ in 0..N {
        tokio::time::timeout(Duration::from_secs(5), validated_rx.recv())
            .await
            .expect("actor stalled: deadlock under backpressure")
            .unwrap();
    }

    let udp_notif_tx = producer.await.unwrap();
    // Input channel fully drained → actor never stopped consuming.
    assert!(udp_notif_tx.is_empty());

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// Regression test for the cache-drain livelock: a SubscriptionStarted that
/// is missing its module version can never build SubscriptionInfo. Such a
/// packet must be dropped, not buffered and re-fetched forever. We send
/// only the malformed packet; if it were re-buffered the actor would
/// spin and nothing would shut down cleanly.
#[tokio::test]
async fn test_validation_actor_malformed_subscription_started_dropped() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    // SubscriptionStarted WITHOUT module-version → build_subscription_info
    // returns None → must be dropped permanently.
    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    let payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": 103,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-hardware:hardware",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "ietf-yang-push:periodic": {
              "period": 6000
            }
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                1,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    // Nothing should be forwarded; packet is dropped, no fetch is triggered.
    let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
    assert!(res.is_err(), "malformed packet must not be forwarded");
    assert!(
        fetcher_count.lock().unwrap().is_empty(),
        "malformed packet must not trigger a schema fetch / re-buffer loop"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A well-formed push-update must be forwarded after strict YANG validation
/// succeeds.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_valid_push_update_passes() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        _,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

    // Send a push-update with ietf-interfaces data.
    let push_update_payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2026-04-21T13:33:31.007Z",
        "hostname": "ipf-zbl1312-r-ap-01",
        "sequence-number": 2,
        "contents": {
          "ietf-yang-push:push-update": {
            "id": 1,
            "datastore-contents": {
              "ietf-interfaces:interfaces": {
                "interface": [
                  {
                    "name": "Virtual-Template0",
                    "type": "iana-if-type:ppp",
                    "enabled": true,
                    "link-up-down-trap-enable": "enabled",
                    "admin-status": "up",
                    "oper-status": "up",
                    "if-index": 1,
                    "speed": "64000"
                  },
                  {
                    "name": "GigabitEthernet0/0/0",
                    "type": "iana-if-type:ethernetCsmacd",
                    "enabled": true,
                    "link-up-down-trap-enable": "enabled",
                    "admin-status": "up",
                    "oper-status": "up",
                    "if-index": 4,
                    "phys-address": "8C:E5:EF:B7:18:4E",
                    "speed": "1000000000",
                  }
                ]
              }
            },
            "ietf-yp-observation:timestamp": "2026-04-21T13:33:30.665Z",
            "ietf-yp-observation:point-in-time": "current-accounting",
            "ietf-distributed-notif:message-publisher-id": 16974839
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&push_update_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout: valid push-update was not forwarded")
        .unwrap();
    assert!(
        content_id.is_some(),
        "valid push-update must pass strict YANG validation"
    );
    assert!(!sub_info.is_empty());

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A packet with an unsupported media type (XML) cannot be decoded and must
/// be dropped immediately with a `decode_error` warning.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_unsupported_media_type_dropped() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        _,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    // YangDataXml is not handled by UdpNotifPacketDecoded::try_from →
    // UnsupportedMediaType.
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                SocketAddr::new(subscription_info.peer_ip(), 0),
            ),
            UdpNotifPacket::new(
                MediaType::YangDataXml,
                10,
                1,
                HashMap::new(),
                Bytes::from_static(b"<irrelevant/>"),
            ),
        )))
        .await
        .unwrap();

    let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
    assert!(
        res.is_err(),
        "packet with unsupported media type must be dropped"
    );
    assert!(logs_contain("Failed to decode UDP-Notif payload"));

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A packet whose payload is not valid JSON cannot be decoded and must be
/// dropped with a `decode_error` warning.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_malformed_json_payload_dropped() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        _,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    // YangDataJson with bytes that are not valid JSON → serde_json parse
    // error.
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                SocketAddr::new(subscription_info.peer_ip(), 0),
            ),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                1,
                HashMap::new(),
                Bytes::from_static(b"this is not json {{{"),
            ),
        )))
        .await
        .unwrap();

    let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
    assert!(
        res.is_err(),
        "packet with malformed JSON payload must be dropped"
    );
    assert!(logs_contain("Failed to decode UDP-Notif payload"));

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A push-update containing a typo in a field name (i.e. an unknown YANG
/// node) must be dropped by strict YANG validation and never forwarded.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_invalid_push_update_dropped() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        _,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

    // Push-update with "enabelled" (typo for "enabled"):
    // an unknown YANG node that strict validation must reject.
    let invalid_push_update_payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "type": "iana-if-type:ethernetCsmacd",
                                    "enabelled": true,
                                    "admin-status": "up",
                                    "oper-status": "up",
                                    "if-index": 1,
                                    "speed": "1000000000"
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&invalid_push_update_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
    assert!(
        res.is_err(),
        "push-update with a typo in a field name must be dropped by strict YANG validation"
    );
    assert!(logs_contain("Failed to validate UDP-Notif payload"));

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// Same push-update as `test_validation_actor_invalid_push_update_dropped`,
/// but with `anydata_strict` disabled: content of anydata nodes is not
/// being validated so the message must pass through.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_invalid_push_update_passes_when_anydata_not_strict() {
    let (caching_join_handle, caching_handle, subscription_info, _fetcher_count) =
        setup_actor_with_empty_cache();

    let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
    let (validated_tx, validated_rx) = async_channel::bounded(100);
    let (_join_handle, handle) = ValidationActorHandle::new(
        100,
        1000,
        100,
        false, // anydata_strict disabled
        udp_notif_rx,
        validated_tx,
        caching_handle.request_tx(),
        either::Right(ValidationStats::new(opentelemetry::global::meter(
            "test_meter",
        ))),
    )
    .expect("Failed to spawn validation actor");

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

    // Push-update with "enabelled" (typo for "enabled"): an unknown YANG
    // node that only strict anydata validation would reject.
    let invalid_push_update_payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "type": "iana-if-type:ethernetCsmacd",
                                    "enabelled": true,
                                    "admin-status": "up",
                                    "oper-status": "up",
                                    "if-index": 1,
                                    "speed": "1000000000"
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&invalid_push_update_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout: push-update was not forwarded")
        .unwrap();
    assert!(
        content_id.is_some(),
        "with anydata_strict disabled, an unknown node inside the anydata payload must \
        not cause validation to fail"
    );
    assert!(!sub_info.is_empty());

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

// TODO(libyang): mandatory-node enforcement inside `anydata` is not yet
// implemented upstream; once fixed, flip assertions to
// `res.is_err()` + `logs_contain`.
/// A push-update whose interface entry omits the mandatory `type` leaf must
/// be dropped by strict YANG validation and never forwarded.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_missing_mandatory_node_dropped() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        _,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

    // Push-update with the mandatory `type` leaf absent from the interface
    // entry: ietf-interfaces@2018-02-20 declares it `mandatory true`.
    let missing_type_payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "enabled": true,
                                    "admin-status": "up",
                                    "oper-status": "up",
                                    "if-index": 1,
                                    "speed": "1000000000"
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&missing_type_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    // TODO(libyang): should be `res.is_err()` once libyang enforces
    // mandatory nodes inside anydata.
    let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
    assert!(
        res.is_ok(),
        "libyang limitation apparently addressed: mandatory nodes inside anydata are now \
         enforced; flip this test to assert `res.is_err()` + `logs_contain(\"Failed to validate\")`"
    );
    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = res.unwrap().unwrap();
    assert!(content_id.is_some());
    assert!(!sub_info.is_empty());

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A SubscriptionStarted duplicate or SubscriptionModified with equal
/// subscription information that arrives while the first schema fetch is
/// still in-flight must be buffered (not forwarded unvalidated). Both
/// packets must emerge from validated_rx with a valid content_id once
/// the schema arrives, and only one cache fetch may be triggered.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_duplicate_subscription_started_in_flight() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);

    let payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "hostname": "test-router-01",
        "sequence-number": 0,
        "contents": {
          "ietf-subscribed-notifications:subscription-modified": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [
              16843789
            ],
            "ietf-yang-push-revision:module-version": [
              {
                "name": "ietf-interfaces",
                "revision": "2018-02-20"
              }
            ],
            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
            "ietf-yang-push:periodic": {
              "period": 6000
            }
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&payload).unwrap();

    let make_packet = |msg_id: u32| {
        Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                msg_id,
                HashMap::new(),
                Bytes::from(bytes.clone()),
            ),
        ))
    };

    // Send first SubscriptionStarted. This triggers the schema fetch and
    // sets schema_fetch_pending = true.
    udp_notif_tx.send(make_packet(1)).await.unwrap();
    // Yield so the actor processes the first packet before the duplicate is
    // queued.
    tokio::task::yield_now().await;

    // Send the duplicate while the fetch is in-flight. With
    // schema_fetch_pending = true the actor must buffer it
    // rather than forwarding it unvalidated.
    udp_notif_tx.send(make_packet(2)).await.unwrap();

    // Both packets must eventually be forwarded with a valid content_id.
    // Regardless of whether the duplicate arrived before or after the cache
    // responded, content_id must be Some (never forwarded unvalidated).
    for i in 1..=2u32 {
        let ValidatedNotification {
            cached_content_id: content_id,
            subscription_info: sub_info,
            ..
        } = tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for packet {i}"))
            .unwrap();
        assert!(
            content_id.is_some(),
            "packet {i}: duplicate SubscriptionStarted must be validated, not forwarded unvalidated"
        );
        assert!(!sub_info.is_empty());
    }

    // Exactly one cache fetch must have been triggered for both identical
    // packets.
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "only one cache fetch must be triggered for duplicate identical SubscriptionStarted"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A SubscriptionStarted duplicate that arrives after the schema is already
/// loaded must be validated immediately using the cached context, without
/// triggering a second cache fetch.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_duplicate_subscription_started_after_schema_loaded() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);

    // Load the schema via the first SubscriptionStarted and drain the
    // result.
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "first fetch must have been triggered"
    );

    // Send an identical SubscriptionStarted now that the schema is cached.
    let payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "hostname": "test-router-01",
        "sequence-number": 0,
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [
              16843789
            ],
            "ietf-yang-push-revision:module-version": [
              {
                "name": "ietf-interfaces",
                "revision": "2018-02-20"
              }
            ],
            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
            "ietf-yang-push:periodic": {
              "period": 6000
            }
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    // Must be validated immediately using the cached schema.
    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout: duplicate SubscriptionStarted was not forwarded")
        .unwrap();
    assert!(
        content_id.is_some(),
        "duplicate SubscriptionStarted after schema loaded must be validated"
    );
    assert!(!sub_info.is_empty());

    // No additional fetch must have been triggered.
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "no additional cache fetch must be triggered when schema is already cached"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// YANG-Push subscription state must be keyed by IP alone.
/// A device reconnecting from a new ephemeral UDP source port
/// (same IP, same subscription id) must reuse the already-cached schema.
/// `SessionInfo` forwarded downstream still reflects the new port.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_reconnect_new_source_port_reuses_schema() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();

    let peer_ip = subscription_info.peer_ip();
    let peer_port_a = SocketAddr::new(peer_ip, 12345);
    let peer_port_b = SocketAddr::new(peer_ip, 12346);

    // Load the schema using the first source port.
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer_port_a).await;
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "initial fetch must have fired once"
    );

    // Send a push-update for the same subscription id from a different
    // source port, simulating the device reconnecting with a new
    // ephemeral UDP port.
    let push_update_payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "type": "iana-if-type:ethernetCsmacd",
                                    "enabled": true,
                                    "admin-status": "up",
                                    "oper-status": "up",
                                    "if-index": 1,
                                    "speed": "1000000000"
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&push_update_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer_port_b),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    let notification = tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
        .await
        .expect("timeout: push-update from new source port was not forwarded")
        .unwrap();
    assert!(
        notification.cached_content_id.is_some(),
        "packet from a new source port for an already-known peer/subscription must reuse \
        the cached schema, not be treated as an unknown subscription"
    );
    assert!(!notification.subscription_info.is_empty());
    assert_eq!(
        notification.session.peer(),
        peer_port_b,
        "forwarded SessionInfo must retain the new source port, not the original one"
    );

    // No additional cache fetch must have been triggered:
    // the peer/subscription must be recognized from the IP alone,
    // regardless of source port.
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "reconnecting from a new source port must not trigger a second cache fetch"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A push-update for an unknown subscription is resolved by subscription
/// id (NETCONF path). A later SubscriptionStarted for the same, unchanged
/// subscription must build an identical `SubscriptionInfo`, so it is
/// served from the cache instead of being treated as a changed
/// subscription and fetched from the device a second time.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_subscription_started_after_lookup_by_id_reuses_schema() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    let peer = SocketAddr::new(subscription_info.peer_ip(), 12345);

    let push_update_payload = serde_json::json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "test-router-01",
            "sequence-number": 1,
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [
                                {
                                    "name": "GigabitEthernet0/0/0",
                                    "type": "iana-if-type:ethernetCsmacd",
                                    "enabled": true
                                }
                            ]
                        }
                    },
                    "ietf-distributed-notif:message-publisher-id": 16974839
                }
            }
        }
    });
    let bytes = serde_json::to_vec(&push_update_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                1,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(2), validated_rx.recv())
        .await
        .expect("timeout: push-update resolved by subscription id was not forwarded")
        .unwrap();
    assert!(notification.cached_content_id.is_some());
    assert_eq!(notification.subscription_info, subscription_info);

    // Same subscription announced via SubscriptionStarted.
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

    let total_fetches: usize = fetcher_count.lock().unwrap().values().sum();
    assert_eq!(
        total_fetches, 1,
        "SubscriptionStarted for an unchanged subscription must not refetch the schema \
        already resolved by subscription id"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// When a SubscriptionStarted with changed params (same id, updated
/// yang-library-content-id) arrives after the schema is already loaded:
/// 1. The validation actor clears its local cache entry, buffers the packet,
///    and sends a new `LookupBySubscriptionInfo` to the cache actor.
/// 2. The cache actor detects the content-id changed and issues a fresh fetch
///    from the device by calling the fetcher.
/// 3. The test fetcher only knows about "test-content-id-1"; for any other
///    content-id it returns an error (simulating a device that does not yet
///    have the schema, or a NETCONF fetch failure). The cache actor therefore
///    sends back `yang_lib_ref = None`.
/// 4. The validation actor drains the buffer: since no schema is available, the
///    packet is forwarded unvalidated (`content_id = None`).
/// 5. Two distinct device fetch calls must have been made (one per content-id).
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_changed_subscription_started_triggers_refetch() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);

    // Load the schema for the initial subscription (content-id =
    // "test-content-id-1").
    setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        1,
        "initial fetch must have fired once"
    );

    // Send a SubscriptionStarted for the same subscription id but with a
    // different yang-library-content-id, simulating a schema change after a
    // device software upgrade.
    let changed_payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-24T08:00:00.000Z",
        "hostname": "test-router-01",
        "sequence-number": 1,
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [16843789],
            "ietf-yang-push-revision:module-version": [
              {"name": "ietf-interfaces", "revision": "2018-02-20"}
            ],
            "ietf-yang-push-revision:yang-library-content-id": "updated-content-id-2",
            "ietf-yang-push:periodic": {"period": 6000}
          }
        }
      }
    });
    let bytes = serde_json::to_vec(&changed_payload).unwrap();
    udp_notif_tx
        .send(Arc::new(UdpNotifRequest::new(
            SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                2,
                HashMap::new(),
                Bytes::from(bytes),
            ),
        )))
        .await
        .unwrap();

    // The test fetcher only knows "test-content-id-1" and returns an error
    // for "updated-content-id-2" (simulating a failed device fetch). The
    // packet was buffered during the fetch attempt; after the fetch fails
    // it is forwarded unvalidated. In production the fetch would succeed
    // and content_id would be Some.
    let ValidatedNotification {
        cached_content_id: content_id,
        subscription_info: sub_info,
        ..
    } = tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
        .await
        .expect("timeout: changed SubscriptionStarted was not forwarded")
        .unwrap();
    assert!(
        content_id.is_none(),
        "device fetch failed for new content-id → packet must be forwarded unvalidated"
    );
    assert!(!sub_info.is_empty());

    // A second device fetch must have been triggered for the new
    // content-id; the cache must not silently reuse the old schema
    // when content-id changes.
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        2,
        "a new device fetch must be triggered when yang-library-content-id changes"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}

/// A SubscriptionModified (different content-id) arriving while
/// the original SubscriptionStarted's fetch is still in-flight must be
/// deferred, not clobber it. Messages 1-2 (started, push-update)
/// validate against the first schema; only then does the deferred
/// SubscriptionModified trigger fetch #2, and messages 3-4 follow once
/// it resolves.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_validation_actor_subscription_modified_while_fetch_in_flight() {
    let (
        caching_join_handle,
        caching_handle,
        subscription_info,
        fetcher_count,
        udp_notif_tx,
        validated_rx,
        handle,
    ) = setup_validation_actor();
    let peer = SocketAddr::new(subscription_info.peer_ip(), 0);
    let session = SessionInfo::new(SocketAddr::from(([127, 0, 0, 1], 10000)), None, peer);

    let push_update_payload = |sequence_number: u32| {
        serde_json::json!({
          "ietf-yp-notification:envelope": {
            "event-time": "2026-04-21T13:33:31.007Z",
            "hostname": "ipf-zbl1312-r-ap-01",
            "sequence-number": sequence_number,
            "contents": {
              "ietf-yang-push:push-update": {
                "id": 1,
                "datastore-contents": {
                  "ietf-interfaces:interfaces": {
                    "interface": [
                      {
                        "name": "GigabitEthernet0/0/0",
                        "type": "iana-if-type:ethernetCsmacd",
                        "enabled": true,
                        "link-up-down-trap-enable": "enabled",
                        "admin-status": "up",
                        "oper-status": "up",
                        "if-index": 4,
                        "phys-address": "8C:E5:EF:B7:18:4E",
                        "speed": "1000000000",
                      }
                    ]
                  }
                },
                "ietf-yp-observation:timestamp": "2026-04-21T13:33:30.665Z",
                "ietf-yp-observation:point-in-time": "current-accounting",
                "ietf-distributed-notif:message-publisher-id": 16974839
              }
            }
          }
        })
    };
    let make_packet = |msg_id: u32, payload: &serde_json::Value| {
        Arc::new(UdpNotifRequest::new(
            session.clone(),
            UdpNotifPacket::new(
                MediaType::YangDataJson,
                10,
                msg_id,
                HashMap::new(),
                Bytes::from(serde_json::to_vec(payload).unwrap()),
            ),
        ))
    };

    let started_payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-23T14:12:16.024Z",
        "hostname": "test-router-01",
        "sequence-number": 0,
        "contents": {
          "ietf-subscribed-notifications:subscription-started": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [16843789],
            "ietf-yang-push-revision:module-version": [
              {"name": "ietf-interfaces", "revision": "2018-02-20"}
            ],
            "ietf-yang-push-revision:yang-library-content-id": "test-content-id-1",
            "ietf-yang-push:periodic": {"period": 6000}
          }
        }
      }
    });
    let modified_payload = serde_json::json!({
      "ietf-yp-notification:envelope": {
        "event-time": "2025-09-24T08:00:00.000Z",
        "hostname": "test-router-01",
        "sequence-number": 1,
        "contents": {
          "ietf-subscribed-notifications:subscription-modified": {
            "id": 1,
            "ietf-yang-push:datastore": "ietf-datastores:operational",
            "ietf-yang-push:datastore-xpath-filter": "/ietf-interfaces:interfaces",
            "transport": "ietf-udp-notif-transport:udp-notif",
            "encoding": "encode-json",
            "purpose": "test subscription",
            "ietf-distributed-notif:message-publisher-id": [16843789],
            "ietf-yang-push-revision:module-version": [
              {"name": "ietf-interfaces", "revision": "2018-02-20"}
            ],
            "ietf-yang-push-revision:yang-library-content-id": "updated-content-id-2",
            "ietf-yang-push:periodic": {"period": 6000}
          }
        }
      }
    });

    // Enqueue all four messages before the actor has any chance to run, so
    // fetch #1 (triggered by message 1) is guaranteed to still be pending
    // when messages 2-4 are handled.
    udp_notif_tx
        .send(make_packet(1, &started_payload))
        .await
        .unwrap();
    udp_notif_tx
        .send(make_packet(2, &push_update_payload(2)))
        .await
        .unwrap();
    udp_notif_tx
        .send(make_packet(3, &modified_payload))
        .await
        .unwrap();
    udp_notif_tx
        .send(make_packet(4, &push_update_payload(4)))
        .await
        .unwrap();

    // Messages 1 and 2 must be validated with the first (content-id-1) schema.
    for expected_msg_id in [1u32, 2u32] {
        let notification = tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for message {expected_msg_id}"))
            .unwrap();
        assert_eq!(notification.packet.message_id(), expected_msg_id);
        assert!(
            notification.cached_content_id.is_some(),
            "message {expected_msg_id}: must be validated against the first fetch's schema, \
            not lost or left pending forever"
        );
    }

    // Messages 3 (deferred SubscriptionModified) and 4 must come after, once
    // the second fetch (for content-id-2, unknown to the test fetcher) fails.
    for expected_msg_id in [3u32, 4u32] {
        let notification = tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for message {expected_msg_id}"))
            .unwrap();
        assert_eq!(notification.packet.message_id(), expected_msg_id);
        assert!(
            notification.cached_content_id.is_none(),
            "message {expected_msg_id}: second fetch fails for content-id-2 in this test, \
            so must be forwarded unvalidated (not clobbered by the stale first response)"
        );
    }

    // Exactly two device fetches: one per distinct content-id. A stale
    // response clobbering the second generation would not add a third
    // fetch, so this alone doesn't prove the fix, but combined with the
    // ordering/content_id assertions above it confirms no data was lost
    // and no premature schema_fetch_pending clear occurred.
    assert_eq!(
        fetcher_count.lock().unwrap().len(),
        2,
        "exactly one device fetch per distinct yang-library-content-id"
    );

    handle.shutdown().await.unwrap();
    caching_handle.shutdown().await.unwrap();
    caching_join_handle.await.unwrap().unwrap();
}
