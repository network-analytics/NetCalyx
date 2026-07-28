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

//! YANG Push Notification Validation Actor
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
//!     1000,  // max packets buffered per peer
//!     100,   // max packets buffered per subscription
//!     rx,    // incoming UDP-Notif packets
//!     tx,    // validated packets output
//!     cache_cmd_tx,  // cache lookup commands
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
//!   - `yang4::Context`: Loaded YANG schemas for validation
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
//! - **Schema available**: Validates using `yang4` library
//!   - Valid packets → forwarded with full `SubscriptionInfo`
//!   - Invalid packets → dropped with error logged
//!
//! - **Schema unavailable**: Forwards unvalidated
//!   - Marked with empty `SubscriptionInfo` (content_id = "EMPTY")
//!   - Downstream can detect and handle unvalidated packets
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

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::SubscriptionInfo;
use crate::{
    ContentId, OTL_CACHE_DROP_REASON_KEY, OTL_CACHE_DROP_REASON_PEER_CACHE_FULL,
    OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL, OTL_YANG_PUSH_DECODE_ERROR_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
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
use yang4::data::{DataFormat, DataOperation, DataParserFlags, DataValidationFlags};

#[derive(Debug)]
struct CachedSubscription {
    cached_content_id: Option<ContentId>,
    subscription_info: SubscriptionInfo,
    yang_ctx: Option<yang4::context::Context>,
    buffered_packets: Vec<Arc<UdpNotifRequest>>,
}

#[derive(Debug, Default)]
struct CachedPeerSubscriptions {
    subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
    total_buffered: usize,
}

#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub messages_received: opentelemetry::metrics::Counter<u64>,
    pub messages_decoding_success: opentelemetry::metrics::Counter<u64>,
    pub messages_decoding_fail: opentelemetry::metrics::Counter<u64>,
    pub cache_request_by_subscription_info: opentelemetry::metrics::Counter<u64>,
    pub cache_request_by_subscription_id: opentelemetry::metrics::Counter<u64>,
    pub buffered_packets: opentelemetry::metrics::Gauge<u64>,
    pub buffer_drop: opentelemetry::metrics::Counter<u64>,
    pub buffer_drain: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_created: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_invalid: opentelemetry::metrics::Counter<u64>,
    pub cache_yang_ctx_empty: opentelemetry::metrics::Counter<u64>,
    pub validation_success: opentelemetry::metrics::Counter<u64>,
    pub validation_invalid: opentelemetry::metrics::Counter<u64>,
    pub validation_malformed: opentelemetry::metrics::Counter<u64>,
    pub validation_skip: opentelemetry::metrics::Counter<u64>,
    pub messages_sent: opentelemetry::metrics::Counter<u64>,
}

impl ValidationStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let messages_received = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.received")
            .with_description(
                "Number of Yang Push messages received for validation (before decoding)",
            )
            .build();
        let messages_decoding_success = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.decode.success")
            .with_description("Number of Yang Push messages decoded successfully (UDP-Notif payload read successfully)")
            .build();
        let messages_decoding_fail = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.decode.fail")
            .with_description("Number of Yang Push messages dropped because of decoding errors (Couldn't read UDP-Notif payload)")
            .build();
        let cache_request_by_subscription_info = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.cache.requests.by.subscription_info")
            .with_description("Number of cache requests by subscription info (from subscription-start or subscription-modified messages) to retrieve the schemas for YANG-Push subscriptions")
            .build();
        let cache_request_by_subscription_id = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.cache.requests.by.subscription_id")
            .with_description("Number of cache requests by Subscription ID to retrieve the schemas for YANG-Push subscriptions")
            .build();
        let buffered_packets = meter
            .u64_gauge("netcalyx.collector.yang_push.validation.buffer.packets")
            .with_description("Number of Yang Push messages currently buffered waiting for schemas")
            .build();
        let buffer_drop = meter
            .u64_counter("netcalyx.collector.yang_push.validation.buffer.drop")
            .with_description("Number of Yang Push messages dropped because the buffer is full")
            .build();
        let buffer_drain = meter
            .u64_counter("netcalyx.collector.yang_push.validation.buffer.drain")
            .with_description("Number of Yang Push messages popped out of the buffer and sent to the validation step")
            .build();
        let cache_yang_ctx_created = meter
            .u64_counter("netcalyx.collector.yang_push.validation.cache.yang.ctx.created")
            .with_description("Number of libyang validation context that are successfully created")
            .build();
        let cache_yang_ctx_invalid = meter
            .u64_counter("netcalyx.collector.yang_push.validation.cache.yang.ctx.invalid")
            .with_description(
                "Number of libyang validation context that are invalid (e.g., missing schema)",
            )
            .build();
        let cache_yang_ctx_empty = meter
            .u64_counter("netcalyx.collector.yang_push.validation.cache.yang.ctx.empty")
            .with_description("Number of libyang validation context that are empty (e.g., schema loading from the router failed)")
            .build();
        let validation_malformed = meter
            .u64_counter("netcalyx.collector.yang_push.validation.malformed")
            .with_description(
                "Number of Yang Push messages dropped because they are malformed; e.g., missing subscription info",
            )
            .build();
        let validation_success = meter
            .u64_counter("netcalyx.collector.yang_push.validation.success")
            .with_description("Number of Yang Push messages successfully validated")
            .build();
        let validation_invalid = meter
            .u64_counter("netcalyx.collector.yang_push.validation.invalid")
            .with_description("Number of Yang Push messages dropped because of validation errors")
            .build();
        let validation_skip = meter
            .u64_counter("netcalyx.collector.yang_push.validation.skipped")
            .with_description("Number of Yang Push skipped the validation step because the subscription is not found in the cache")
            .build();
        let messages_sent = meter
            .u64_counter("netcalyx.collector.yang_push.validation.messages.sent")
            .with_description("Number of Telemetry Messages successfully sent upstream")
            .build();
        Self {
            messages_received,
            messages_decoding_success,
            messages_decoding_fail,
            cache_request_by_subscription_info,
            cache_request_by_subscription_id,
            buffered_packets,
            buffer_drop,
            buffer_drain,
            cache_yang_ctx_created,
            cache_yang_ctx_invalid,
            cache_yang_ctx_empty,
            validation_success,
            validation_invalid,
            validation_malformed,
            validation_skip,
            messages_sent,
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
        if sub_buffered_packets > self.max_buffered_packets_per_subscription {
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
                OTL_CACHE_DROP_REASON_KEY,
                OTL_CACHE_DROP_REASON_SUBSCRIPTION_CACHE_FULL,
            ));
            self.stats.buffer_drop.add(1, &peer_tags);
            return false;
        }
        if peer_cache.total_buffered > self.max_buffered_packets_per_peer {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                subscription_target=%subscription_info.target(),
                router_content_id=subscription_info.content_id(),
                "Buffer full for peer, dropping new packet");
            peer_tags.push(opentelemetry::KeyValue::new(
                OTL_CACHE_DROP_REASON_KEY,
                OTL_CACHE_DROP_REASON_PEER_CACHE_FULL,
            ));
            self.stats.buffer_drop.add(1, &peer_tags);
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
            .buffered_packets
            .record(peer_cache.total_buffered as u64, &peer_tags);
        true
    }

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

    fn extend_peer_targs_with_subscription_info(
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

    fn decode_message(
        &mut self,
        peer: SocketAddr,
        packet: &UdpNotifPacket,
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
                self.stats.messages_decoding_success.add(1, &peer_tags);
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
                    OTL_YANG_PUSH_DECODE_ERROR_ID_KEY,
                    format!("{err}"),
                ));
                self.stats.messages_decoding_fail.add(1, &peer_tags);
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
    ) -> Result<(), ValidationActorError> {
        let peer = message.peer_address();
        let packet = message.packet();

        // Step 1: decode the raw UDP-Notif payload.
        let decoded = match self.decode_message(peer, packet) {
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
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);

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
            );
            // logging of error is handled in the [Self::validate_message]
            if validation_result.is_err() {
                self.stats.validation_invalid.add(1, &peer_tags);
                return Ok(());
            }
            self.stats.validation_success.add(1, &peer_tags);
            Some(cached_content_id)
        } else {
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                "No YANG schemas found, skipping validation step",
            );
            self.stats.validation_skip.add(1, &peer_tags);
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
                ValidationActorError::SendError
            })?;
        self.stats.messages_sent.add(1, &peer_tags);
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

    fn validate_message(
        packet: &UdpNotifPacket,
        peer: SocketAddr,
        subscription_info: &SubscriptionInfo,
        cached_content_id: ContentId,
        notification_type: &String,
        yang_ctx: &yang4::context::Context,
        is_legacy: bool,
    ) -> Result<(), yang4::Error> {
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        Self::extend_peer_targs_with_subscription_info(subscription_info, &mut peer_tags);
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();

        let mut envelope_ext = None;
        if let Some(ietf_yo_notif) = yang_ctx.get_module_implemented("ietf-yp-notification")
            && let Some(ext) = ietf_yo_notif.extensions().next()
        {
            envelope_ext = Some(ext);
        }
        if let Some(envelope_ext) = envelope_ext
            && !is_legacy
        {
            let validation_result = yang4::data::DataTree::parse_ext_string(
                &envelope_ext,
                packet.payload(),
                DataFormat::JSON,
                DataParserFlags::STRICT,
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
                    "Failed to validate UDP-Notif payload using draft-ietf-netconf-notif-envelope, dropping packet"
                );
                return Err(err);
            }
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                cached_content_id,
                "Successfully validated YANG-Push message using draft-ietf-netconf-notif-envelope",
            );
            Ok(())
        } else {
            let validation_result = yang4::data::DataTree::parse_op_string(
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
                return Err(err);
            }
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
                Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
                if cached_content_id.is_some() {
                    return Ok(Some(subscription_info));
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
                self.stats
                    .cache_request_by_subscription_info
                    .add(1, &peer_tags);
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
                Ok(None)
            }
            None => {
                let notif_contents = decoded.payload().notification_contents();
                // A subscription-started/modified that reached here failed to
                // build SubscriptionInfo (e.g. missing module version). It will
                // fail identically every time, so buffering it and re-fetching
                // would loop forever. Drop it permanently.
                if matches!(
                    notif_contents,
                    Some(NotificationVariant::SubscriptionStarted(_))
                        | Some(NotificationVariant::SubscriptionModified(_))
                ) {
                    warn!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        notification_type,
                        "Malformed subscription started/modified (no usable subscription info), dropping packet"
                    );
                    self.stats.validation_malformed.add(1, &peer_tags);
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
                    self.stats
                        .cache_request_by_subscription_id
                        .add(1, &peer_tags);
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
                self.stats.validation_invalid.add(1, &peer_tags);
                Ok(None)
            }
        }
    }

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
        Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut otl_tags);
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
            let yang_ctx_result = yang4::context::Context::new_from_yang_library_file(
                &yang_lib_ref.yang_library_path(),
                DataFormat::XML,
                &search_dir.as_path(),
                yang4::context::ContextFlags::empty(),
            );
            let yang_ctx = match yang_ctx_result {
                Ok(yang_ctx) => {
                    self.stats.cache_yang_ctx_created.add(1, &otl_tags);
                    Some(yang_ctx)
                }
                Err(err) => {
                    self.stats.cache_yang_ctx_invalid.add(1, &otl_tags);
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
            self.stats.cache_yang_ctx_empty.add(1, &otl_tags);
            subscription_cache.cached_content_id = None;
            subscription_cache.yang_ctx = None;
        }
        let buffered_packets = std::mem::take(&mut subscription_cache.buffered_packets);
        let drained = buffered_packets.len();
        // Update the per-peer counter while we still hold the peer_cache borrow.
        peer_cache.total_buffered -= drained;
        let remaining = peer_cache.total_buffered;
        for message in buffered_packets {
            let peer = message.peer_address();
            let packet = message.packet();
            let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
            Self::extend_peer_targs_with_subscription_info(&subscription_info, &mut peer_tags);
            self.stats.buffer_drain.add(1, &peer_tags);
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
        self.stats
            .buffered_packets
            .record(remaining as u64, &otl_tags);
        Ok(())
    }

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

    async fn run(mut self) -> Result<String, ValidationActorError> {
        info!("Starting Yang-Push validation actor");
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(ValidationActorCommand::Shutdown) => {
                            info!("Shutting down Yang Push validation actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            let msg = "Yang Push validation actor terminated due to command channel closing";
                            warn!(msg);
                            Ok(msg.to_string())
                        }
                    }
                }
                msg = self.cache_rx.recv() => {
                    match msg {
                        Ok(response) => {
                            if let Err(err) = self.process_cache_response(response) {
                                let err_msg = "Yang Push validation actor cache response processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "Yang Push validation actor cache receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
                Some(message) = async { self.pending_packets.pop_front() }, if !self.pending_packets.is_empty() => {
                    if let Err(err) = self.process_udp_notif_msg(message).await {
                        let err_msg = "Yang Push validation actor cached packet processing unrecoverable error, shutting down";
                        warn!(error=%err, err_msg);
                        return Ok(err_msg.to_string());
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            self.stats.messages_received.add(
                                1,
                                &Self::peer_tags_from_packet(
                                    msg.peer_address(),
                                    msg.packet(),
                                ),
                            );
                            if let Err(err) = self.process_udp_notif_msg(msg).await {
                                let err_msg = "Yang Push validation actor UDP-Notif processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "Yang Push validation actor UDP Notif receiver channel closed unexpectedly, shutting down";
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

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_validation_actor_schema_fetched() {
        // Setup caching actor
        let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }

        // Setup channels
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);

        // Spawn validation actor
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

        // Create a test peer address
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
        // Setup caching actor
        let (caching_join_handle, caching_handle, subscription_info, fetcher_count) =
            setup_actor_with_empty_cache();
        {
            let hits_counts = fetcher_count
                .lock()
                .expect("Failed to lock fetcher counts")
                .clone();
            assert_eq!(hits_counts.len(), 0);
        }

        // Setup channels
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(100);
        let (validated_tx, validated_rx) = async_channel::bounded(100);

        // Spawn validation actor
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

        // Create a test peer address
        let peer = subscription_info.peer();
        let payload = serde_json::json!(
            {
                "ietf-yp-notification:envelope": {
                    "event-time": "2025-09-23T14:12:16.024Z",
                    "hostname": "ipf-zbl1327-r-daisy-48",
                    "sequence-number": 0,
                    "contents": {
                        "ietf-subscribed-notifications:subscription-started": {
                            "id": 2,
                            "ietf-yang-push:datastore": "ietf-datastores:operational",
                            "ietf-yang-push:datastore-xpath-filter": "/ietf-hardware:hardware",
                            "transport": "ietf-udp-notif-transport:udp-notif",
                            "encoding": "encode-json",
                            "ietf-distributed-notif:message-publisher-id": [
                                16843789
                            ],
                            "ietf-yang-push-revision:module-version": [
                                {
                                    "name": "ietf-hardware",
                                    "revision": ""
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
                "event-time": "2025-09-23T14:12:16.024Z",
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
                        "ietf-yang-push:periodic": {"period": 6000}
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
}
