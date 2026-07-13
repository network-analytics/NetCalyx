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

//! YANG-Push Notification Validation Actor
//!
//! This module provides an actor-based validation system for UDP-Notif
//! packets carrying YANG-modeled data. The actor validates notification
//! payloads against YANG schemas when available, gracefully handling
//! cases where schemas haven't been loaded yet.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use netcalyx_yang_push::validation::ValidationActorHandle;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let (rx, tx, cache_cmd_tx) = /* channel setup */;
//! let (join_handle, handle) = ValidationActorHandle::new(
//!     100,          // cache response channel buffer size
//!     1000,         // max packets buffered per peer
//!     100,          // max packets buffered per subscription
//!     rx,           // incoming UDP-Notif packets
//!     tx,           // validated packets output
//!     cache_cmd_tx, // cache lookup commands
//!     either::Either::Left(meter), // metrics
//! )?;
//!
//! // Actor runs in background...
//! handle.shutdown().await?;
//! join_handle.await??;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ### Packet Processing Pipeline
//!
//! 1. **Receive**: UDP-Notif packets arrive from the network layer
//! 2. **Decode**: Extract subscription ID and notification type
//! 3. **Bootstrap**: `SubscriptionStarted` notifications trigger YANG library
//!    lookups via the cache actor
//! 4. **Buffer or Validate**:
//!    - If YANG schema available: Validate and forward
//!    - If schema pending: Buffer packet until schema arrives
//!    - If schema unavailable: Forward unvalidated with empty subscription info
//! 5. **Forward**: Send validated/unvalidated packets downstream
//!
//! ### Two-Level Caching
//!
//! The actor maintains caches at two levels to handle the asynchronous nature
//! of YANG schema retrieval:
//!
//! - **Peer Level**: Groups all subscriptions from the same source IP
//!   - Enforces `max_buffered_packets_per_peer` limit across all subscriptions
//!   - Prevents a single peer from consuming excessive memory
//!
//! - **Subscription Level**: Per-subscription state including:
//!   - `SubscriptionInfo`: Metadata from `SubscriptionStarted`
//!   - `yang5::Context`: Loaded YANG schemas for validation
//!   - Buffered packets waiting for schema retrieval
//!   - Enforces `max_buffered_packets_per_subscription` limit
//!
//! Packets arriving before schemas are loaded are buffered and reprocessed
//! when the cache actor responds with YANG library references.
//!
//! ### Buffer Limits
//!
//! Two configurable limits prevent memory exhaustion:
//! - **Per-subscription limit**: protects against slow schema retrieval
//! - **Per-peer limit**: protects against malicious peers creating many
//!   subscriptions
//!
//! When limits are exceeded, new packets are dropped with a warning logged.
//!
//! ## Validation Behavior
//!
//! The actor validates packets when YANG schemas are available:
//!
//! - **Schema available**: Validates using `yang5` library
//!   - Valid packets → forwarded with full `SubscriptionInfo`
//!   - Invalid packets → dropped with error logged
//!
//! - **Schema unavailable**: Forwards unvalidated
//!   - `content_id` is `None`; downstream can detect and handle unvalidated
//!     packets
//!
//! - **Schema loading failed**: Disables validation for subscription
//!   - All future packets forwarded unvalidated
//!   - Warning logged once when schema load fails
//!
//! ## Error Handling
//!
//! - **Non-fatal errors** (per-packet):
//!   - Decode failures: Packet dropped, warning logged
//!   - Validation failures: Packet dropped, warning logged
//!   - Cache full: New packet dropped, warning logged
//!
//! - **Fatal errors** (shutdown triggers):
//!   - Input channel closed: Actor terminates gracefully
//!   - Output channel closed: Actor terminates (backpressure failure)
//!   - Cache channel closed: Actor terminates (dependency failure)
//!   - Shutdown command received: Graceful termination

// TODO: extract the validation logic into a separate module
// (for consistency with other actors in the codebase and to allow unit testing
// without the actor runtime)

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::SubscriptionInfo;
use crate::{
    ContentId, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use netcalyx_netconf_proto::yang_push::subscription::YangPushModuleVersion;
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};
use netcalyx_udp_notif_pkt::notification::{NotificationVariant, SubscriptionStartedModified};
use netcalyx_udp_notif_pkt::raw::UdpNotifPacket;
use netcalyx_udp_notif_service::{OTL_UDP_NOTIF_PUBLISHER_ID_KEY, UdpNotifRequest};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};
use yang5::data::{DataFormat, DataOperation, DataParserFlags, DataValidationFlags};

// Attribute values for the `reason` key on the `dropped` counter.
const DROP_REASON_KEY: &str = "reason";
const DROP_REASON_DECODE_ERROR: &str = "decode_error";
const DROP_REASON_BUFFER_FULL_SUBSCRIPTION: &str = "buffer_full_subscription";
const DROP_REASON_BUFFER_FULL_PEER: &str = "buffer_full_peer";
const DROP_REASON_VALIDATION_FAILED: &str = "validation_failed";
const DROP_REASON_INCOMPLETE_SUBSCRIPTION_STARTED: &str = "incomplete_subscription_started";
const DROP_REASON_NO_SUBSCRIPTION_ID: &str = "no_subscription_id";
const DROP_REASON_SEND_ERROR: &str = "send_error";

// Attribute values for the `reason` key on the `skipped` counter.
const SKIP_REASON_KEY: &str = "reason";
const SKIP_REASON_NO_LIBRARY: &str = "no_library";
const SKIP_REASON_CONTEXT_FAILED: &str = "context_failed";
const SKIP_REASON_NO_SUBSCRIPTION_INFO: &str = "no_subscription_info";

// Attribute values for the `by` key on the `cache_lookups` counter.
const CACHE_LOOKUP_BY_KEY: &str = "by";
const CACHE_LOOKUP_BY_SUBSCRIPTION_INFO: &str = "subscription_info";
const CACHE_LOOKUP_BY_SUBSCRIPTION_ID: &str = "subscription_id";

/// Per-subscription state held by the validation actor.
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
/// request is sent and cleared to `false` when the cache actor responds,
/// regardless of whether a schema was found. While it is `true`, duplicate
/// SubscriptionStarted packets are buffered rather than forwarded unvalidated.
#[derive(Debug)]
struct CachedSubscription {
    cached_content_id: Option<ContentId>,
    subscription_info: SubscriptionInfo,
    yang_ctx: Option<yang5::context::Context>,
    buffered_packets: Vec<Arc<UdpNotifRequest>>,
    schema_fetch_pending: bool,
}

#[derive(Debug, Default)]
struct CachedPeerSubscriptions {
    subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
    total_buffered: usize,
}

#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub received: opentelemetry::metrics::Counter<u64>,
    pub decoded: opentelemetry::metrics::Counter<u64>,
    pub dropped: opentelemetry::metrics::Counter<u64>,
    pub cache_lookups: opentelemetry::metrics::Counter<u64>,
    pub buffered: opentelemetry::metrics::Gauge<u64>,
    pub buffer_drained: opentelemetry::metrics::Counter<u64>,
    pub yang_context_loaded: opentelemetry::metrics::Counter<u64>,
    pub yang_context_failed: opentelemetry::metrics::Counter<u64>,
    pub yang_context_empty: opentelemetry::metrics::Counter<u64>,
    pub validated: opentelemetry::metrics::Counter<u64>,
    pub skipped: opentelemetry::metrics::Counter<u64>,
    pub sent: opentelemetry::metrics::Counter<u64>,
    pub pending: opentelemetry::metrics::Gauge<u64>,
    pub cached_peers: opentelemetry::metrics::Gauge<u64>,
    pub cached_subscriptions: opentelemetry::metrics::Gauge<u64>,
}

impl ValidationStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netcalyx.yang_push.validation.received")
            .with_description(
                "Number of YANG-Push messages received for validation (before decoding)",
            )
            .build();
        let decoded = meter
            .u64_counter("netcalyx.yang_push.validation.decoded")
            .with_description("Number of YANG-Push messages decoded successfully")
            .build();
        let dropped = meter
            .u64_counter("netcalyx.yang_push.validation.dropped")
            .with_description(
                "Number of YANG-Push messages dropped for any reason, \
                tagged with reason (decode_error | buffer_full_subscription | \
                buffer_full_peer | validation_failed | \
                incomplete_subscription_started | no_subscription_id | send_error)",
            )
            .build();
        let cache_lookups = meter
            .u64_counter("netcalyx.yang_push.validation.cache.lookups")
            .with_description(
                "Number of YANG schema cache lookups issued, \
                tagged with by (subscription_info | subscription_id)",
            )
            .build();
        let buffered = meter
            .u64_gauge("netcalyx.yang_push.validation.buffered")
            .with_description("Number of YANG-Push messages currently buffered waiting for schemas")
            .build();
        let buffer_drained = meter
            .u64_counter("netcalyx.yang_push.validation.buffer.drained")
            .with_description(
                "Number of YANG-Push messages popped out of the buffer and sent to the validation step",
            )
            .build();
        let yang_context_loaded = meter
            .u64_counter("netcalyx.yang_push.validation.yang.context.loaded")
            .with_description("Number of libyang validation contexts successfully created")
            .build();
        let yang_context_failed = meter
            .u64_counter("netcalyx.yang_push.validation.yang.context.failed")
            .with_description(
                "Number of libyang validation contexts that failed to be created (e.g., missing schema)",
            )
            .build();
        let yang_context_empty = meter
            .u64_counter("netcalyx.yang_push.validation.yang.context.empty")
            .with_description(
                "Number of cache responses with no YANG library (schema loading from the router failed)",
            )
            .build();
        let validated = meter
            .u64_counter("netcalyx.yang_push.validation.validated")
            .with_description("Number of YANG-Push messages that passed YANG schema validation")
            .build();
        let skipped = meter
            .u64_counter("netcalyx.yang_push.validation.skipped")
            .with_description(
                "Number of YANG-Push messages forwarded without validation, \
                tagged with reason (no_library | context_failed | no_subscription_info)",
            )
            .build();
        let sent = meter
            .u64_counter("netcalyx.yang_push.validation.sent")
            .with_description(
                "Number of YANG-Push messages successfully forwarded to the next actor",
            )
            .build();
        let pending = meter
            .u64_gauge("netcalyx.yang_push.validation.pending")
            .with_description(
                "Current number of packets in the pending deque, drained from subscription \
                hold-buffers and awaiting reprocessing. Together with 'buffered' it accounts \
                for all packets held in memory by the validation actor.",
            )
            .build();
        let cached_peers = meter
            .u64_gauge("netcalyx.yang_push.validation.cached_peers")
            .with_description("Current number of distinct peer IPs tracked in the peer cache")
            .build();
        let cached_subscriptions = meter
            .u64_gauge("netcalyx.yang_push.validation.cached_subscriptions")
            .with_description(
                "Current number of subscriptions tracked per peer in the peer cache, \
                tagged with network.peer.address. Sum gives the global total.",
            )
            .build();
        Self {
            received,
            decoded,
            dropped,
            cache_lookups,
            buffered,
            buffer_drained,
            yang_context_loaded,
            yang_context_failed,
            yang_context_empty,
            validated,
            skipped,
            sent,
            pending,
            cached_peers,
            cached_subscriptions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum ValidationActorError {
    #[strum(serialize = "Failed to send cache lookup command")]
    CacheLookupSendError,
    #[strum(serialize = "Failed to receive cache response")]
    CacheResponseReceiveError,
    #[strum(serialize = "Failed to send the decoded UDP-Notif packet")]
    SendError,
}

impl std::error::Error for ValidationActorError {}

#[derive(Debug, Clone, Copy)]
enum ValidationActorCommand {
    Shutdown,
}

struct ValidationActor {
    max_buffered_packets_per_peer: usize,
    max_buffered_packets_per_subscription: usize,
    peer_cache: FxHashMap<IpAddr, CachedPeerSubscriptions>,
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
    tx: async_channel::Sender<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
    cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
    cache_tx: async_channel::Sender<CacheResponse>,
    cache_rx: async_channel::Receiver<CacheResponse>,
    /// Packets buffered while their subscription waits for schemas to arrive,
    /// then drained in pending_packets once the cache responds. They are
    /// processed one at a time
    pending_packets: VecDeque<Arc<UdpNotifRequest>>,
    stats: ValidationStats,
}

impl ValidationActor {
    /// Check if the subscription is different from the existing one in the
    /// cache.
    ///
    /// If it is different, remove the existing one from the cache to allow a
    /// new request to the caching actor.
    fn check_subscription_new(&mut self, peer: SocketAddr, subscription_info: &SubscriptionInfo) {
        if let Some(cached_peer_subscriptions) = self.peer_cache.get_mut(&peer.ip()) {
            let is_different = cached_peer_subscriptions
                .subscriptions
                .get(&subscription_info.id())
                .map(|x| x.subscription_info != *subscription_info)
                .unwrap_or(true);
            if is_different {
                trace!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    "Subscription changed, removing from cache to allow a new fetch schemas request"
                );
                if let Some(removed) = cached_peer_subscriptions
                    .subscriptions
                    .remove(&subscription_info.id())
                {
                    cached_peer_subscriptions.total_buffered -= removed.buffered_packets.len();
                }
            }
            // clear peer if there are no subscriptions left
            if cached_peer_subscriptions.subscriptions.is_empty() {
                self.peer_cache.remove(&peer.ip());
            }
        }
    }

    /// Get the subscription info from the cache or from the SubscriptionStarted
    /// notification, and the cached content id if it's found in the cache.
    ///
    /// If the notification is a SubscriptionStarted, create a new
    /// SubscriptionInfo and return it. If the notification is not a
    /// SubscriptionStarted, look up the subscription info in the cache.
    fn get_subscription_info(
        &mut self,
        peer: SocketAddr,
        collector: SocketAddr,
        interface: Option<String>,
        decoded: &UdpNotifPacketDecoded,
    ) -> Option<(SubscriptionInfo, Option<Option<String>>)> {
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notif_contents = if let Some(notif) = decoded.payload().notification_contents() {
            notif
        } else {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                "Received UDP-Notif payload without a notifications content, dropping packet"
            );
            return None;
        };

        let subscription_info = if let NotificationVariant::SubscriptionStarted(
            subscription_started,
        )
        | NotificationVariant::SubscriptionModified(
            subscription_started,
        ) = notif_contents
        {
            let subscription_info = if let Some(subscription_info) = self.build_subscription_info(
                peer,
                collector,
                interface,
                message_id,
                publisher_id,
                subscription_started,
            ) {
                subscription_info
            } else {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    notifification_type=%notif_contents.notification_type(),
                    "Received UDP-Notif of subscription started/modified payload without subscription info, dropping packet"
                );
                return None;
            };
            self.check_subscription_new(peer, &subscription_info);
            Some(subscription_info)
        } else {
            self.peer_cache.get(&peer.ip()).and_then(
                |cached_peer_subscriptions: &CachedPeerSubscriptions| {
                    cached_peer_subscriptions
                        .subscriptions
                        .get(&notif_contents.subscription_id())
                        .map(|x| x.subscription_info.clone())
                },
            )
        };
        if let Some(subscription_info) = subscription_info {
            let cached_content_id = self
                .peer_cache
                .get(&peer.ip())
                .and_then(|cached_peer_subscriptions: &CachedPeerSubscriptions| {
                    cached_peer_subscriptions
                        .subscriptions
                        .get(&notif_contents.subscription_id())
                })
                .filter(|x| x.subscription_info == subscription_info)
                .map(|x| x.cached_content_id.clone());

            Some((subscription_info, cached_content_id))
        } else {
            None
        }
    }

    /// Attempt to add `message` to the per-subscription hold buffer, enforcing
    /// both the per-subscription and per-peer packet limits.
    /// Returns `true` if the packet was buffered, `false` if it was dropped.
    fn buffer_packet(
        &mut self,
        subscription_info: SubscriptionInfo,
        message: Arc<UdpNotifRequest>,
    ) -> bool {
        let peer = message.peer_address();
        let packet = message.packet();
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let subscription_id = subscription_info.id();
        let peer_cache = self.peer_cache.entry(peer.ip()).or_default();

        let sub_buffered_packets = peer_cache
            .subscriptions
            .get(&subscription_id)
            .map(|s| s.buffered_packets.len())
            .unwrap_or(0);
        if sub_buffered_packets >= self.max_buffered_packets_per_subscription {
            // drop the new packet, since the buffer is full
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                subscription_target=%subscription_info.target(),
                router_content_id=subscription_info.content_id(),
                "Buffer full for subscription, dropping new packet"
            );
            peer_tags.push(opentelemetry::KeyValue::new(
                DROP_REASON_KEY,
                DROP_REASON_BUFFER_FULL_SUBSCRIPTION,
            ));
            self.stats.dropped.add(1, &peer_tags);
            return false;
        }
        if peer_cache.total_buffered >= self.max_buffered_packets_per_peer {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                subscription_target=%subscription_info.target(),
                router_content_id=subscription_info.content_id(),
                "Buffer full for peer, dropping new packet");
            peer_tags.push(opentelemetry::KeyValue::new(
                DROP_REASON_KEY,
                DROP_REASON_BUFFER_FULL_PEER,
            ));
            self.stats.dropped.add(1, &peer_tags);
            return false;
        }
        let subscription_cache =
            peer_cache
                .subscriptions
                .entry(subscription_id)
                .or_insert(CachedSubscription {
                    cached_content_id: None,
                    subscription_info: subscription_info.clone(),
                    yang_ctx: None,
                    buffered_packets: Vec::new(),
                    schema_fetch_pending: false,
                });
        trace!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id,
            subscription_target=%subscription_info.target(),
            router_content_id=subscription_info.content_id(),
            "Buffered UDP-Notif packet"
        );
        subscription_cache.buffered_packets.push(message);
        peer_cache.total_buffered += 1;
        self.stats
            .buffered
            .record(peer_cache.total_buffered as u64, &peer_tags);
        true
    }

    /// Build the base OpenTelemetry tag set (peer address, port, publisher id)
    /// for a given UDPNotif packet.
    fn peer_tags_from_packet(
        peer: SocketAddr,
        packet: &UdpNotifPacket,
    ) -> Vec<opentelemetry::KeyValue> {
        let publisher_id = packet.publisher_id();
        Vec::from([
            opentelemetry::KeyValue::new("network.peer.address", format!("{}", peer.ip())),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(peer.port().into()),
            ),
            opentelemetry::KeyValue::new(
                OTL_UDP_NOTIF_PUBLISHER_ID_KEY,
                opentelemetry::Value::I64(publisher_id.into()),
            ),
        ])
    }

    /// Append subscription-specific OpenTelemetry tags (id, target,
    /// router content-id) to an existing tag vector.
    fn extend_peer_tags_with_subscription_info(
        subscription_info: &SubscriptionInfo,
        peer_tags: &mut Vec<opentelemetry::KeyValue>,
    ) {
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
            opentelemetry::Value::I64(subscription_info.id().into()),
        ));
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
            format!("{}", subscription_info.target()),
        ));
        peer_tags.push(opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
            subscription_info.content_id().to_string(),
        ));
    }

    /// Decode a raw `UdpNotifPacket` into a `UdpNotifPacketDecoded`.
    /// Returns `Err(())` and drops the packet on unsupported media type or
    /// parse failure.
    ///
    /// Set `count_decoded` to `false` when reprocessing a buffered message to
    /// avoid double-counting the `decoded` metric.
    fn decode_message(
        &mut self,
        peer: SocketAddr,
        packet: &UdpNotifPacket,
        count_decoded: bool,
    ) -> Result<UdpNotifPacketDecoded, ()> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);

        // Decode the UDP-Notif packet to get subscription ID and payload information
        match UdpNotifPacketDecoded::try_from(packet) {
            Ok(decoded) => {
                let notif_contents = decoded.payload().notification_contents();
                if let Some(notif_contents) = notif_contents {
                    peer_tags.push(opentelemetry::KeyValue::new(
                        OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                        opentelemetry::Value::I64(notif_contents.subscription_id().into()),
                    ));
                }
                if tracing::enabled!(tracing::Level::TRACE) {
                    let notification_type = decoded
                        .notification_type()
                        .map(|x| x.to_string())
                        .unwrap_or("UNKNOWN".to_string());
                    trace!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        notification_type,
                        "Decoded UDP-Notif payload, starting the validation step"
                    );
                }
                if count_decoded {
                    self.stats.decoded.add(1, &peer_tags);
                }
                Ok(decoded)
            }
            Err(err) => {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    error=%err,
                    "Failed to decode UDP-Notif payload, dropping packet"
                );
                peer_tags.push(opentelemetry::KeyValue::new(
                    DROP_REASON_KEY,
                    DROP_REASON_DECODE_ERROR,
                ));
                self.stats.dropped.add(1, &peer_tags);
                Err(())
            }
        }
    }

    /// Core per-packet handler, called for every incoming UDP-Notif message and
    /// for every packet drained from the per-subscription buffer once schemas
    /// arrive.
    async fn process_udp_notif_msg(
        &mut self,
        message: Arc<UdpNotifRequest>,
        is_reprocessed: bool,
    ) -> Result<(), ValidationActorError> {
        let peer = message.peer_address();
        let packet = message.packet();

        // Step 1: decode the raw UDP-Notif payload.
        let decoded = match self.decode_message(peer, packet, !is_reprocessed) {
            Ok(decoded) => decoded,
            // Decoding errors are logged in the [Self::decode_message], and packets are dropped
            // here
            Err(_) => return Ok(()),
        };
        let notification_type = decoded
            .notification_type()
            .map(|x| x.to_string())
            .unwrap_or("UNKNOWN".to_string());
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let is_legacy = matches!(decoded.payload(), UdpNotifPayload::NotificationLegacy(_));

        // Step 2: resolve subscription info.
        // Returns None if the packet was buffered (schemas not ready yet);
        // in that case we stop here and wait for the cache to respond.
        let extract_sub_info = self
            .extract_subscription_info(Arc::clone(&message), peer, &decoded)
            .await?;
        let subscription_info = if let Some(subscription_info) = extract_sub_info {
            subscription_info
        } else {
            return Ok(());
        };
        Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);

        // Step 3: validate against YANG schemas if available, skip otherwise.
        let peer_cache = self.peer_cache.entry(peer.ip()).or_default();
        let subscription_cache = peer_cache
            .subscriptions
            .entry(subscription_info.id())
            .or_insert(CachedSubscription {
                cached_content_id: None,
                subscription_info: subscription_info.clone(),
                yang_ctx: None,
                buffered_packets: Vec::new(),
                schema_fetch_pending: false,
            });
        let cached_content_id = if let Some(cached_content_id) =
            subscription_cache.cached_content_id.clone()
            && let Some(yang_ctx) = subscription_cache.yang_ctx.as_ref()
            && !subscription_info.is_empty()
        {
            let validation_result = Self::validate_message(
                packet,
                peer,
                &subscription_info,
                cached_content_id.clone(),
                &notification_type,
                yang_ctx,
                is_legacy,
                &self.stats,
                &peer_tags,
            );
            if validation_result.is_err() {
                return Ok(());
            }
            Some(cached_content_id)
        } else {
            let skip_reason = if subscription_info.is_empty() {
                SKIP_REASON_NO_SUBSCRIPTION_INFO
            } else if subscription_cache.cached_content_id.is_some() {
                // Library reference exists but context creation failed
                SKIP_REASON_CONTEXT_FAILED
            } else {
                // No library available — device fetch failed
                SKIP_REASON_NO_LIBRARY
            };
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                skip_reason,
                "No YANG schemas found, skipping validation step",
            );
            let mut skip_tags = peer_tags.clone();
            skip_tags.push(opentelemetry::KeyValue::new(SKIP_REASON_KEY, skip_reason));
            self.stats.skipped.add(1, &skip_tags);
            None
        };

        // Step 4: forward to the enrichment actor.
        self.tx
            .send((
                cached_content_id.clone(),
                subscription_info.clone(),
                decoded,
            ))
            .await
            .map_err(|_| {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id=cached_content_id.clone().unwrap_or_default(),
                    notification_type,
                    "Failed to send UDP-Notif message for the next actor to process"
                );
                let mut drop_tags = peer_tags.clone();
                drop_tags.push(opentelemetry::KeyValue::new(
                    DROP_REASON_KEY,
                    DROP_REASON_SEND_ERROR,
                ));
                self.stats.dropped.add(1, &drop_tags);
                ValidationActorError::SendError
            })?;
        self.stats.sent.add(1, &peer_tags);
        trace!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id=subscription_info.id(),
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            cached_content_id=cached_content_id.unwrap_or_default(),
            notification_type,
            "Successfully send UDP-Notif message for the next actor to process"
        );
        Ok(())
    }

    /// Validate the raw packet payload against the loaded YANG context.
    /// Returns `Err` and drops the packet on validation failure.
    #[allow(clippy::too_many_arguments)]
    fn validate_message(
        packet: &UdpNotifPacket,
        peer: SocketAddr,
        subscription_info: &SubscriptionInfo,
        cached_content_id: ContentId,
        notification_type: &String,
        yang_ctx: &yang5::context::Context,
        is_legacy: bool,
        stats: &ValidationStats,
        peer_tags: &[opentelemetry::KeyValue],
    ) -> Result<(), yang5::Error> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();

        if !is_legacy {
            let validation_result = yang5::data::DataTree::parse_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                DataParserFlags::STRICT | DataParserFlags::ANYDATA_STRICT,
                DataValidationFlags::PRESENT,
            );
            if let Err(err) = validation_result {
                let v = packet.payload().clone();
                let packet_payload =
                    str::from_utf8(v.as_ref()).unwrap_or("unserializable packet payload");
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    notification_type,
                    error=%err,
                    packet=packet_payload,
                    "Failed to validate UDP-Notif payload, dropping packet"
                );

                let mut drop_tags = peer_tags.to_vec();
                drop_tags.push(opentelemetry::KeyValue::new(
                    DROP_REASON_KEY,
                    DROP_REASON_VALIDATION_FAILED,
                ));
                stats.dropped.add(1, &drop_tags);
                return Err(err);
            }
            stats.validated.add(1, peer_tags);
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                cached_content_id,
                "Successfully validated YANG-Push message",
            );
            Ok(())
        } else {
            let validation_result = yang5::data::DataTree::parse_op_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                DataParserFlags::STRICT,
                DataOperation::NotificationYang,
            );
            if let Err(err) = validation_result {
                warn!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    notification_type,
                    error=%err, "Failed to validate legacy UDP-Notif payload, dropping packet");
                let mut drop_tags = peer_tags.to_vec();
                drop_tags.push(opentelemetry::KeyValue::new(
                    DROP_REASON_KEY,
                    DROP_REASON_VALIDATION_FAILED,
                ));
                stats.dropped.add(1, &drop_tags);
                return Err(err);
            }
            stats.validated.add(1, peer_tags);
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                cached_content_id,
                "Successfully validated YANG-Push message using legacy UDP-Notif payload",
            );
            Ok(())
        }
    }

    /// Get the subscription info from the message, if not present cache and
    /// send a cache request and return none for the subscription info
    async fn extract_subscription_info(
        &mut self,
        message: Arc<UdpNotifRequest>,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Result<Option<SubscriptionInfo>, ValidationActorError> {
        let collector = message.collector_address();
        let interface = message.collector_interface();
        let packet = message.packet();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notification_type = decoded
            .notification_type()
            .map(|x| x.to_string())
            .unwrap_or("UNKNOWN".to_string());

        match self.get_subscription_info(peer, collector, interface.map(String::from), decoded) {
            Some((subscription_info, cached_content_id)) => {
                Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);

                match cached_content_id {
                    Some(Some(_)) => {
                        // Schema is loaded → validate and forward immediately.
                        return Ok(Some(subscription_info));
                    }
                    Some(None) => {
                        // Cache entry exists but schema not yet available. We distinguish:
                        // - fetch in-flight (schema_fetch_pending = true): buffer the packet so it
                        //   is validated once the response arrives, instead of slipping through
                        //   unvalidated.
                        // - fetch already completed with no schema (schema_fetch_pending = false):
                        //   forward unvalidated as usual; no point buffering.
                        let fetch_pending = self
                            .peer_cache
                            .get(&peer.ip())
                            .and_then(|c| c.subscriptions.get(&subscription_info.id()))
                            .map(|s| s.schema_fetch_pending)
                            .unwrap_or(false);
                        if fetch_pending {
                            trace!(
                                peer=%peer,
                                message_id,
                                publisher_id,
                                subscription_id=subscription_info.id(),
                                router_content_id=subscription_info.content_id(),
                                subscription_target=%subscription_info.target(),
                                notification_type,
                                "Schema fetch in-flight, buffering packet until response arrives",
                            );
                            self.buffer_packet(subscription_info.clone(), message);
                            return Ok(None);
                        }
                        // Fetch already completed → fast path.
                        return Ok(Some(subscription_info));
                    }
                    None => {} // no entry → fall through to send lookup + buffer
                }
                debug!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    subscription_target=%subscription_info.target(),
                    notification_type,
                    "Received new subscription sending lookup by subscription info request to the cache"
                );
                peer_tags.push(opentelemetry::KeyValue::new(
                    CACHE_LOOKUP_BY_KEY,
                    CACHE_LOOKUP_BY_SUBSCRIPTION_INFO,
                ));
                self.stats.cache_lookups.add(1, &peer_tags);
                self.cache_cmd_tx
                    .send(CacheLookupCommand::LookupBySubscriptionInfo(
                        subscription_info.clone(),
                        self.cache_tx.clone(),
                    ))
                    .await
                    .map_err(|error| {
                        warn!(
                            message_id,
                            publisher_id,
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            subscription_target=%subscription_info.target(),
                            notification_type,
                            error=%error,
                            "Error sending lookup by subscription info request to the cache"
                        );
                        ValidationActorError::CacheLookupSendError
                    })?;
                self.buffer_packet(subscription_info.clone(), message);

                // Mark the fetch as in-flight so any duplicate that arrives before the
                // cache responds is buffered rather than forwarded unvalidated.
                if let Some(peer_subs) = self.peer_cache.get_mut(&peer.ip())
                    && let Some(sub_cache) =
                        peer_subs.subscriptions.get_mut(&subscription_info.id())
                {
                    sub_cache.schema_fetch_pending = true;
                }
                Ok(None)
            }
            None => {
                let notif_contents = decoded.payload().notification_contents();
                if matches!(
                    notif_contents,
                    Some(NotificationVariant::SubscriptionStarted(_))
                        | Some(NotificationVariant::SubscriptionModified(_))
                ) {
                    // A subscription-started/modified that reached here failed to
                    // build SubscriptionInfo (e.g. missing module version). It will
                    // fail identically every time, so buffering it and re-fetching
                    // would loop forever. Drop it permanently.
                    warn!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        notification_type,
                        "Incomplete subscription started/modified (no usable subscription info), dropping packet"
                    );
                    peer_tags.push(opentelemetry::KeyValue::new(
                        DROP_REASON_KEY,
                        DROP_REASON_INCOMPLETE_SUBSCRIPTION_STARTED,
                    ));
                    self.stats.dropped.add(1, &peer_tags);
                    return Ok(None);
                }
                let subscription_id = notif_contents.map(|x| x.subscription_id());
                if let Some(subscription_id) = subscription_id {
                    debug!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        subscription_id,
                        notification_type,
                        "Received UDP-Notif packet without subscription info, \
                        caching the packet and looking up subscription info in cache");
                    peer_tags.push(opentelemetry::KeyValue::new(
                        CACHE_LOOKUP_BY_KEY,
                        CACHE_LOOKUP_BY_SUBSCRIPTION_ID,
                    ));
                    self.stats.cache_lookups.add(1, &peer_tags);
                    let subscription_info = SubscriptionInfo::new_empty(
                        collector,
                        interface.map(String::from),
                        peer,
                        subscription_id,
                    );
                    self.cache_cmd_tx
                        .send(CacheLookupCommand::LookupBySubscriptionId {
                            collector,
                            interface: interface.map(String::from),
                            peer,
                            subscription_id,
                            tx: self.cache_tx.clone(),
                        })
                        .await
                        .map_err(|_| ValidationActorError::CacheLookupSendError)?;
                    self.buffer_packet(subscription_info.clone(), message);
                    return Ok(None);
                }
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    notification_type,
                    "Received UDP-Notif packet without subscription info nor subscription ID, dropping packet"
                );
                peer_tags.push(opentelemetry::KeyValue::new(
                    DROP_REASON_KEY,
                    DROP_REASON_NO_SUBSCRIPTION_ID,
                ));
                self.stats.dropped.add(1, &peer_tags);
                Ok(None)
            }
        }
    }

    /// Handle a cache lookup response: load (or clear) the YANG context for the
    /// subscription, clear `schema_fetch_pending`, and drain the hold buffer
    /// into `pending_packets` for validation.
    fn process_cache_response(
        &mut self,
        response: CacheResponse,
    ) -> Result<(), ValidationActorError> {
        let (cached_content_id, subscription_info, yang_lib_ref) = response.into();
        let mut otl_tags = Vec::from([
            opentelemetry::KeyValue::new(
                "network.peer.address",
                format!("{}", subscription_info.peer().ip()),
            ),
            opentelemetry::KeyValue::new(
                "network.peer.port",
                opentelemetry::Value::I64(subscription_info.peer().port().into()),
            ),
        ]);
        Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut otl_tags);
        let peer_cache = if let Some(peer_cache) =
            self.peer_cache.get_mut(&subscription_info.peer().ip())
        {
            peer_cache
        } else {
            warn!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Received cache response for subscription from peer that is not in the cache, ignoring the response"
            );
            return Ok(());
        };

        let subscription_cache = if let Some(subscription_cache) =
            peer_cache.subscriptions.get_mut(&subscription_info.id())
        {
            subscription_cache
        } else {
            warn!(
                peer=%subscription_info.peer(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Received cache response for subscription that is not in the cache, ignoring the response");
            return Ok(());
        };

        // Update subscription info in the cache
        subscription_cache.subscription_info = subscription_info.clone();
        if let Some(yang_lib_ref) = yang_lib_ref {
            let search_dir = yang_lib_ref.search_dir();
            let yang_ctx_result = yang5::context::Context::new_from_yang_library_file(
                &yang_lib_ref.yang_library_path(),
                DataFormat::XML,
                &search_dir.as_path(),
                yang5::context::ContextFlags::empty(),
            );
            let yang_ctx = match yang_ctx_result {
                Ok(yang_ctx) => {
                    self.stats.yang_context_loaded.add(1, &otl_tags);
                    Some(yang_ctx)
                }
                Err(err) => {
                    self.stats.yang_context_failed.add(1, &otl_tags);
                    warn!(
                        peer=%subscription_info.peer(),
                        subscription_id=subscription_info.id(),
                        router_content_id=subscription_info.content_id(),
                        cached_content_id=yang_lib_ref.content_id(),
                        yang_library_path=%yang_lib_ref.yang_library_path().display(),
                        search_dir=%search_dir.display(),
                        error=%err,
                        "Failed to create YANG context, disabling YANG validation for this subscription");
                    None
                }
            };
            subscription_cache.cached_content_id = cached_content_id.clone();
            subscription_cache.yang_ctx = yang_ctx;
        } else {
            self.stats.yang_context_empty.add(1, &otl_tags);
            subscription_cache.cached_content_id = None;
            subscription_cache.yang_ctx = None;
        }
        subscription_cache.schema_fetch_pending = false;
        let buffered_packets = std::mem::take(&mut subscription_cache.buffered_packets);
        let drained = buffered_packets.len();
        // Update the per-peer counter while we still hold the peer_cache borrow.
        peer_cache.total_buffered -= drained;
        let remaining = peer_cache.total_buffered;
        for message in buffered_packets {
            let peer = message.peer_address();
            let packet = message.packet();
            let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
            Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);
            self.stats.buffer_drained.add(1, &peer_tags);
            trace!(
                peer=%peer,
                message_id=packet.message_id(),
                publisher_id=packet.publisher_id(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                subscription_target=%subscription_info.target(),
                cached_content_id,
                "Packet popped out of the buffer and queued for the validation step"
            );
            self.pending_packets.push_back(message);
        }
        self.stats.buffered.record(remaining as u64, &otl_tags);
        self.stats
            .pending
            .record(self.pending_packets.len() as u64, &[]);
        self.stats
            .cached_peers
            .record(self.peer_cache.len() as u64, &[]);
        let peer_ip = subscription_info.peer().ip();
        let peer_sub_count = self
            .peer_cache
            .get(&peer_ip)
            .map(|p| p.subscriptions.len())
            .unwrap_or(0);
        self.stats.cached_subscriptions.record(
            peer_sub_count as u64,
            &[opentelemetry::KeyValue::new(
                "network.peer.address",
                format!("{peer_ip}"),
            )],
        );
        Ok(())
    }

    /// Construct a `SubscriptionInfo` from a `SubscriptionStarted/Modified`
    /// notification. Returns `None` if module-version is absent.
    fn build_subscription_info(
        &self,
        peer: SocketAddr,
        collector: SocketAddr,
        interface: Option<String>,
        message_id: u32,
        publisher_id: u32,
        sub_started: &SubscriptionStartedModified,
    ) -> Option<SubscriptionInfo> {
        let modules = match sub_started.module_version() {
            Some(modules) => {
                let mut modules = modules.clone();
                modules.push(YangPushModuleVersion::new(
                    "ietf-subscribed-notifications".into(),
                    None,
                    None,
                ));
                modules.into_boxed_slice()
            }
            None => {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=sub_started.id(),
                    subscription_target=%sub_started.target(),
                    "SubscriptionStarted missing module version"
                );
                return None;
            }
        };

        Some(SubscriptionInfo::new(
            collector,
            interface,
            peer,
            sub_started.id(),
            sub_started.target().clone(),
            sub_started.stop_time().cloned(),
            sub_started.transport().cloned(),
            sub_started.encoding().cloned(),
            sub_started.purpose().map(|x| x.into()),
            sub_started.update_trigger().cloned(),
            modules,
            sub_started
                .yang_library_content_id()
                .map(|x| x.to_string())
                .unwrap_or_default(),
        ))
    }

    /// Actor event loop. Runs until a shutdown command is received or a
    /// fatal channel error occurs.
    async fn run(mut self) -> Result<String, ValidationActorError> {
        info!("Starting YANG-Push validation actor");
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(ValidationActorCommand::Shutdown) => {
                            info!("Shutting down YANG-Push validation actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            let msg = "YANG-Push validation actor terminated due to command channel closing";
                            warn!(msg);
                            Ok(msg.to_string())
                        }
                    }
                }
                msg = self.cache_rx.recv() => {
                    match msg {
                        Ok(response) => {
                            if let Err(err) = self.process_cache_response(response) {
                                let err_msg = "YANG-Push validation actor cache response processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "YANG-Push validation actor cache receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
                Some(message) = async { self.pending_packets.pop_front() }, if !self.pending_packets.is_empty() => {
                    self.stats
                        .pending
                        .record(self.pending_packets.len() as u64, &[]);
                    if let Err(err) = self.process_udp_notif_msg(message, true).await {
                        let err_msg = "YANG-Push validation actor buffered packet processing unrecoverable error, shutting down";
                        warn!(error=%err, err_msg);
                        return Ok(err_msg.to_string());
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            self.stats.received.add(
                                1,
                                &Self::peer_tags_from_packet(
                                    msg.peer_address(),
                                    msg.packet(),
                                ),
                            );
                            if let Err(err) = self.process_udp_notif_msg(msg, false).await {
                                let err_msg = "YANG-Push validation actor UDP-Notif processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "YANG-Push validation actor UDP Notif receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum ValidationActorHandleError {
    #[strum(serialize = "Failed to send command to actor")]
    SendErr,
}

impl std::error::Error for ValidationActorHandleError {}

#[derive(Debug, Clone)]
pub struct ValidationActorHandle {
    cmd_tx: mpsc::Sender<ValidationActorCommand>,
}

impl ValidationActorHandle {
    pub fn new(
        buffer_size: usize,
        max_buffered_packets_per_peer: usize,
        max_buffered_packets_per_subscription: usize,
        rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
        tx: async_channel::Sender<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
        cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
        stats: either::Either<opentelemetry::metrics::Meter, ValidationStats>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<String, ValidationActorError>>,
            Self,
        ),
        ValidationActorHandleError,
    > {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (cache_tx, cache_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor {
            max_buffered_packets_per_peer,
            max_buffered_packets_per_subscription,
            peer_cache: FxHashMap::default(),
            cmd_rx,
            rx,
            tx,
            cache_cmd_tx,
            cache_tx,
            cache_rx,
            pending_packets: VecDeque::new(),
            stats,
        };
        let handle = ValidationActorHandle { cmd_tx };
        let join_handle = tokio::spawn(async move { actor.run().await });
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), ValidationActorHandleError> {
        self.cmd_tx
            .send(ValidationActorCommand::Shutdown)
            .await
            .map_err(|_| ValidationActorHandleError::SendErr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::actor::tests::setup_actor_with_empty_cache;
    use bytes::Bytes;
    use netcalyx_udp_notif_pkt::raw::MediaType;
    use std::collections::HashMap;
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
        async_channel::Receiver<(Option<ContentId>, SubscriptionInfo, UdpNotifPacketDecoded)>,
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
        validated_rx: &async_channel::Receiver<(
            Option<ContentId>,
            SubscriptionInfo,
            UdpNotifPacketDecoded,
        )>,
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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
        let (content_id, _, _) = tokio::time::timeout(Duration::from_secs(2), validated_rx.recv())
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

        let peer = subscription_info.peer();
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
                subscription_started_packet,
            )))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is validated
        let (content_id, sub_info, _validated) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
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

        let peer = subscription_info.peer();
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
                subscription_started_packet,
            )))
            .await
            .unwrap();

        // Allow actor to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify packet is not validated
        let (content_id, sub_info, _validated) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
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

    /// Regression test for the cache-drain deadlock: when schemas arrive and a
    /// large buffer of packets is drained while the downstream is
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
            udp_notif_rx,
            validated_tx,
            caching_handle.request_tx(),
            either::Right(ValidationStats::new(opentelemetry::global::meter(
                "test_meter",
            ))),
        )
        .expect("Failed to spawn validation actor");

        let peer = subscription_info.peer();
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
                        SocketAddr::from(([127, 0, 0, 1], 10000)),
                        None,
                        peer,
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
        let peer = subscription_info.peer();
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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

        let peer = subscription_info.peer();
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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

        let (content_id, sub_info, _decoded) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                subscription_info.peer(),
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

        // YangDataJson with bytes that are not valid JSON → serde_json parse error.
        udp_notif_tx
            .send(Arc::new(UdpNotifRequest::new(
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                subscription_info.peer(),
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

        let peer = subscription_info.peer();
        setup_and_load_schema(&udp_notif_tx, &validated_rx, peer).await;

        // Push-update with "enabelled" (typo for "enabled"): an unknown YANG node
        // that strict validation must reject.
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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

        let peer = subscription_info.peer();
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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

        // TODO(libyang): should be `res.is_err()` once libyang enforces mandatory nodes
        // inside anydata.
        let res = tokio::time::timeout(Duration::from_millis(300), validated_rx.recv()).await;
        assert!(
            res.is_ok(),
            "libyang limitation apparently addressed: mandatory nodes inside anydata are now \
             enforced; flip this test to assert `res.is_err()` + `logs_contain(\"Failed to validate\")`"
        );
        let (content_id, sub_info, _decoded) = res.unwrap().unwrap();
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
        let peer = subscription_info.peer();

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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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
        // Yield so the actor processes the first packet before the duplicate is queued.
        tokio::task::yield_now().await;

        // Send the duplicate while the fetch is in-flight. With schema_fetch_pending =
        // true the actor must buffer it rather than forwarding it unvalidated.
        udp_notif_tx.send(make_packet(2)).await.unwrap();

        // Both packets must eventually be forwarded with a valid content_id.
        // Regardless of whether the duplicate arrived before or after the cache
        // responded, content_id must be Some (never forwarded unvalidated).
        for i in 1..=2u32 {
            let (content_id, sub_info, _) =
                tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
                    .await
                    .unwrap_or_else(|_| panic!("timeout waiting for packet {i}"))
                    .unwrap();
            assert!(
                content_id.is_some(),
                "packet {i}: duplicate SubscriptionStarted must be validated, not forwarded unvalidated"
            );
            assert!(!sub_info.is_empty());
        }

        // Exactly one cache fetch must have been triggered for both identical packets.
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
        let peer = subscription_info.peer();

        // Load the schema via the first SubscriptionStarted and drain the result.
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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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
        let (content_id, sub_info, _) =
            tokio::time::timeout(Duration::from_secs(1), validated_rx.recv())
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

    /// When a SubscriptionStarted with changed params (same id, updated
    /// yang-library-content-id) arrives after the schema is already loaded:
    /// 1. The validation actor clears its local cache entry, buffers the
    ///    packet, and sends a new `LookupBySubscriptionInfo` to the cache
    ///    actor.
    /// 2. The cache actor detects the content-id changed and issues a fresh
    ///    fetch from the device by calling the fetcher.
    /// 3. The test fetcher only knows about "test-content-id-1"; for any other
    ///    content-id it returns an error (simulating a device that does not yet
    ///    have the schema, or a NETCONF fetch failure). The cache actor
    ///    therefore sends back `yang_lib_ref = None`.
    /// 4. The validation actor drains the buffer: since no schema is available,
    ///    the packet is forwarded unvalidated (`content_id = None`).
    /// 5. Two distinct device fetch calls must have been made (one per
    ///    content-id).
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
        let peer = subscription_info.peer();

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
                SocketAddr::from(([127, 0, 0, 1], 10000)),
                None,
                peer,
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

        // The test fetcher only knows "test-content-id-1" and returns an error for
        // "updated-content-id-2" (simulating a failed device fetch). The packet was
        // buffered during the fetch attempt; after the fetch fails it is forwarded
        // unvalidated. In production the fetch would succeed and content_id would be
        // Some.
        let (content_id, sub_info, _) =
            tokio::time::timeout(Duration::from_secs(3), validated_rx.recv())
                .await
                .expect("timeout: changed SubscriptionStarted was not forwarded")
                .unwrap();
        assert!(
            content_id.is_none(),
            "device fetch failed for new content-id → packet must be forwarded unvalidated"
        );
        assert!(!sub_info.is_empty());

        // A second device fetch must have been triggered for the new content-id;
        // the cache must not silently reuse the old schema when content-id changes.
        assert_eq!(
            fetcher_count.lock().unwrap().len(),
            2,
            "a new device fetch must be triggered when yang-library-content-id changes"
        );

        handle.shutdown().await.unwrap();
        caching_handle.shutdown().await.unwrap();
        caching_join_handle.await.unwrap().unwrap();
    }
}
