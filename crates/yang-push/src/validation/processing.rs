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

//! Packet decoding, buffering and validation logic of the validation actor.

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::SubscriptionInfo;
use crate::validation::actor::{ValidationActor, ValidationActorError};
use crate::validation::state::{CachedPeerSubscriptions, CachedSubscription};
use crate::validation::stats::{
    CACHE_LOOKUP_BY_KEY, CacheLookupBy, DropReason, REASON_KEY, SkipReason, ValidationStats,
};
use crate::{
    ContentId, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use netcalyx_udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};
use netcalyx_udp_notif_pkt::notification::NotificationVariant;
use netcalyx_udp_notif_pkt::raw::UdpNotifPacket;
use netcalyx_udp_notif_service::{OTL_UDP_NOTIF_PUBLISHER_ID_KEY, SessionInfo, UdpNotifRequest};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, trace, warn};
use yang5::data::{DataFormat, DataOperation, DataParserFlags, DataValidationFlags};

/// The output of the validation stage: a decoded UDP-Notif packet together
/// with the subscription identity, transport session, and the locally-computed
/// schema fingerprint used for validation.
///
/// - `cached_content_id`: the SHA-256 fingerprint of the YANG library that was
///   used to validate the packet, or `None` when the packet was forwarded
///   without validation (schema unavailable or fetch failed).
/// - `subscription_info`: subscription identity — what this data stream is
///   about.
/// - `session`: transport session context — collector Socket Address,
///   interface/VRF and peer Socket Address
/// - `packet`: the decoded UDP-Notif payload ready for enrichment and
///   publishing.
#[derive(Debug)]
pub struct ValidatedNotification {
    pub cached_content_id: Option<ContentId>,
    pub subscription_info: SubscriptionInfo,
    pub session: SessionInfo,
    pub packet: UdpNotifPacketDecoded,
}

impl ValidationActor {
    /// Check if the subscription is different from the existing one in the
    /// cache.
    ///
    /// If it is different, remove the existing one from the cache to allow a
    /// new request to the caching actor.
    ///
    /// Only called when `schema_fetch_pending` is `false` for this id (see the
    /// gate in `extract_subscription_info`), so `buffered_packets` is always
    /// empty whenever an entry is removed below.
    fn check_subscription_new(&mut self, peer: SocketAddr, subscription_info: &SubscriptionInfo) {
        let Some(cached_peer_subscriptions) = self.peer_cache.get_mut(&peer.ip()) else {
            return;
        };
        let is_different = cached_peer_subscriptions
            .subscriptions
            .get(&subscription_info.id())
            .map(|x| x.subscription_info != *subscription_info)
            .unwrap_or(true);
        if !is_different {
            return;
        }
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
        // clear peer if there are no subscriptions left
        if cached_peer_subscriptions.subscriptions.is_empty() {
            self.peer_cache.remove(&peer.ip());
        }
        // Resync the per-peer gauges after the removal (0/0 when the peer is
        // gone, resetting its series).
        let (total_buffered, sub_count) = self
            .peer_cache
            .get(&peer.ip())
            .map(|p| (p.total_buffered, p.subscriptions.len()))
            .unwrap_or((0, 0));
        self.record_otel_gauges(peer.ip(), total_buffered, sub_count);
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
            let subscription_info = if let Some(subscription_info) =
                self.build_subscription_info(peer, message_id, publisher_id, subscription_started)
            {
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
        Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);
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
                REASON_KEY,
                <&str>::from(DropReason::BufferFullSubscription),
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
                REASON_KEY,
                <&str>::from(DropReason::BufferFullPeer),
            ));
            self.stats.dropped.add(1, &peer_tags);
            return false;
        }
        let subscription_cache = peer_cache
            .subscriptions
            .entry(subscription_id)
            .or_insert_with(|| CachedSubscription::new(subscription_info.clone()));
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
        let total_buffered = peer_cache.total_buffered;
        let sub_count = peer_cache.subscriptions.len();
        self.record_otel_gauges(peer.ip(), total_buffered, sub_count);
        true
    }

    /// Build the base OpenTelemetry tag set (peer address, port, publisher id)
    /// for a given UDPNotif packet.
    pub(super) fn peer_tags_from_packet(
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

    /// Record the peer-scoped cache gauges together so they never drift. Call
    /// after any change to `peer_cache` for `peer_ip`; pass `0`/`0` once the
    /// peer is gone so its per-peer series reset to zero.
    fn record_otel_gauges(&self, peer_ip: IpAddr, total_buffered: usize, sub_count: usize) {
        let peer_tag = [opentelemetry::KeyValue::new(
            "network.peer.address",
            format!("{peer_ip}"),
        )];
        self.stats.buffered.record(total_buffered as u64, &peer_tag);
        self.stats
            .cached_subscriptions
            .record(sub_count as u64, &peer_tag);
        self.stats
            .cached_peers
            .record(self.peer_cache.len() as u64, &[]);
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

        // Decode the UDP-Notif packet to get subscription ID and payload
        // information
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
                    REASON_KEY,
                    <&str>::from(DropReason::DecodeError),
                ));
                self.stats.dropped.add(1, &peer_tags);
                Err(())
            }
        }
    }

    /// Core per-packet handler, called for every incoming UDP-Notif message and
    /// for every packet drained from the per-subscription buffer once schemas
    /// arrive.
    pub(super) async fn process_udp_notif_msg(
        &mut self,
        message: Arc<UdpNotifRequest>,
        is_reprocessed: bool,
    ) -> Result<(), ValidationActorError> {
        let peer = message.peer_address();
        let packet = message.packet();
        let session = message.session().clone();

        // Step 1: decode the raw UDP-Notif payload.
        let decoded = match self.decode_message(peer, packet, !is_reprocessed) {
            Ok(decoded) => decoded,
            // Decoding errors are logged in the [Self::decode_message], and
            // packets are dropped here.
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
            .or_insert_with(|| CachedSubscription::new(subscription_info.clone()));
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
                self.anydata_strict,
                &self.stats,
                &peer_tags,
            );
            if validation_result.is_err() {
                return Ok(());
            }
            Some(cached_content_id)
        } else {
            let skip_reason = if subscription_info.is_empty() {
                SkipReason::NoSubscriptionInfo
            } else if subscription_cache.cached_content_id.is_some() {
                // Library reference exists but context creation failed
                SkipReason::ContextFailed
            } else {
                // No library available — device fetch failed
                SkipReason::NoLibrary
            };
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                skip_reason = <&str>::from(skip_reason),
                "No YANG schemas found, skipping validation step",
            );
            let mut skip_tags = peer_tags.clone();
            skip_tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(skip_reason),
            ));
            self.stats.skipped.add(1, &skip_tags);
            None
        };

        // Step 4: forward to the enrichment actor.
        self.tx
            .send(ValidatedNotification {
                cached_content_id: cached_content_id.clone(),
                subscription_info: subscription_info.clone(),
                session,
                packet: decoded,
            })
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
                    REASON_KEY,
                    <&str>::from(DropReason::SendError),
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
        anydata_strict: bool,
        stats: &ValidationStats,
        peer_tags: &[opentelemetry::KeyValue],
    ) -> Result<(), yang5::Error> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();

        if !is_legacy {
            let mut parser_flags = DataParserFlags::STRICT;
            if anydata_strict {
                parser_flags |= DataParserFlags::ANYDATA_STRICT;
            }
            let validation_result = yang5::data::DataTree::parse_string(
                yang_ctx,
                packet.payload(),
                DataFormat::JSON,
                parser_flags,
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
                    REASON_KEY,
                    <&str>::from(DropReason::ValidationFailed),
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
                    REASON_KEY,
                    <&str>::from(DropReason::ValidationFailed),
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
    /// send a cache request and return none for the subscription info.
    async fn extract_subscription_info(
        &mut self,
        message: Arc<UdpNotifRequest>,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Result<Option<SubscriptionInfo>, ValidationActorError> {
        let packet = message.packet();
        let mut peer_tags = Self::peer_tags_from_packet(peer, packet);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notification_type = decoded
            .notification_type()
            .map(|x| x.to_string())
            .unwrap_or("UNKNOWN".to_string());

        // Defer started/modified notifications while a fetch is already
        // in-flight for this id, so a stale response can never clobber
        // a newer generation.
        if let Some(notif_contents) = decoded.payload().notification_contents()
            && matches!(
                notif_contents,
                NotificationVariant::SubscriptionStarted(_)
                    | NotificationVariant::SubscriptionModified(_)
            )
        {
            let subscription_id = notif_contents.subscription_id();
            let pending_entry_info = self
                .peer_cache
                .get(&peer.ip())
                .and_then(|c| c.subscriptions.get(&subscription_id))
                .filter(|s| s.schema_fetch_pending)
                .map(|s| s.subscription_info.clone());
            if let Some(existing_info) = pending_entry_info {
                peer_tags.push(opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                    opentelemetry::Value::I64(subscription_id.into()),
                ));

                if self.buffer_packet(existing_info, message) {
                    debug!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        subscription_id,
                        notification_type,
                        "Schema fetch already in-flight for this subscription, deferring \
                        subscription started/modified notification until it resolves"
                    );
                    self.stats.subscription_update_deferred.add(1, &peer_tags);
                }
                return Ok(None);
            }
        }

        match self.get_subscription_info(peer, decoded) {
            Some((subscription_info, cached_content_id)) => {
                Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);

                match cached_content_id {
                    Some(Some(_)) => {
                        // Schema is loaded → validate and forward immediately.
                        return Ok(Some(subscription_info));
                    }
                    Some(None) => {
                        // Cache entry exists but schema not yet available.
                        // We distinguish:
                        // - fetch in-flight (schema_fetch_pending = true):
                        //   buffer the packet so it is validated once the
                        //   response arrives, instead of slipping through
                        //   unvalidated.
                        // - fetch already completed with no schema
                        //   (schema_fetch_pending = false): forward unvalidated
                        //   as usual; no point buffering.
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
                    <&str>::from(CacheLookupBy::SubscriptionInfo),
                ));
                self.stats.cache_lookups.add(1, &peer_tags);

                // Mark the fetch as in-flight
                self.peer_cache
                    .entry(peer.ip())
                    .or_default()
                    .subscriptions
                    .entry(subscription_info.id())
                    .or_insert_with(|| CachedSubscription::new(subscription_info.clone()))
                    .schema_fetch_pending = true;
                self.cache_cmd_tx
                    .send(CacheLookupCommand::LookupBySubscriptionInfo {
                        subscription_info: subscription_info.clone(),
                        session: message.session().clone(),
                        tx: self.cache_tx.clone(),
                    })
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
                if matches!(
                    notif_contents,
                    Some(NotificationVariant::SubscriptionStarted(_))
                        | Some(NotificationVariant::SubscriptionModified(_))
                ) {
                    // A subscription-started/modified that reached here failed
                    // to build SubscriptionInfo (e.g. missing module version).
                    // It will fail identically every time, so buffering it and
                    // re-fetching would loop forever. Drop it permanently.
                    warn!(
                        peer=%peer,
                        message_id,
                        publisher_id,
                        notification_type,
                        "Incomplete subscription started/modified (no usable subscription info), dropping packet"
                    );
                    peer_tags.push(opentelemetry::KeyValue::new(
                        REASON_KEY,
                        <&str>::from(DropReason::IncompleteSubscriptionStarted),
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
                        <&str>::from(CacheLookupBy::SubscriptionId),
                    ));
                    self.stats.cache_lookups.add(1, &peer_tags);
                    let subscription_info = SubscriptionInfo::new_empty(peer.ip(), subscription_id);

                    // Mark the fetch as in-flight
                    self.peer_cache
                        .entry(peer.ip())
                        .or_default()
                        .subscriptions
                        .entry(subscription_info.id())
                        .or_insert_with(|| CachedSubscription::new(subscription_info.clone()))
                        .schema_fetch_pending = true;
                    self.cache_cmd_tx
                        .send(CacheLookupCommand::LookupBySubscriptionId {
                            session: message.session().clone(),
                            subscription_id,
                            tx: self.cache_tx.clone(),
                        })
                        .await
                        .map_err(|error| {
                            warn!(
                                peer=%peer,
                                message_id,
                                publisher_id,
                                subscription_id,
                                notification_type,
                                error=%error,
                                "Error sending lookup by subscription id request to the cache"
                            );
                            ValidationActorError::CacheLookupSendError
                        })?;
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
                    REASON_KEY,
                    <&str>::from(DropReason::NoSubscriptionId),
                ));
                self.stats.dropped.add(1, &peer_tags);
                Ok(None)
            }
        }
    }

    /// Handle a cache lookup response: load (or clear) the YANG context for the
    /// subscription, clear `schema_fetch_pending`, and drain the hold buffer
    /// into `pending_packets` for validation.
    pub(super) fn process_cache_response(
        &mut self,
        response: CacheResponse,
    ) -> Result<(), ValidationActorError> {
        let (cached_content_id, subscription_info, yang_lib_ref) = response.into();
        let mut otl_tags = Vec::from([opentelemetry::KeyValue::new(
            "network.peer.address",
            format!("{}", subscription_info.peer_ip()),
        )]);
        Self::extend_peer_tags_with_subscription_info(&subscription_info, &mut otl_tags);
        let peer_cache = if let Some(peer_cache) =
            self.peer_cache.get_mut(&subscription_info.peer_ip())
        {
            peer_cache
        } else {
            warn!(
                peer_ip=%subscription_info.peer_ip(),
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
                peer_ip=%subscription_info.peer_ip(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                cached_content_id,
                "Received cache response for subscription that is not in the cache, ignoring the response");
            return Ok(());
        };

        // Update subscription info in the cache
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
                        peer_ip=%subscription_info.peer_ip(),
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
            // Sanity-check the subscription target resolves against the schema
            // and warn if it is missing or not in canonical form. Diagnostic
            // only: the target is never modified here.
            if let Some(ctx) = yang_ctx.as_ref() {
                Self::check_xpath_target_resolves(&subscription_info, ctx);
            }
            subscription_cache.cached_content_id = cached_content_id.clone();
            subscription_cache.yang_ctx = yang_ctx;
        } else {
            self.stats.yang_context_empty.add(1, &otl_tags);
            subscription_cache.cached_content_id = None;
            subscription_cache.yang_ctx = None;
        }

        // Store the subscription info in the cache.
        subscription_cache.subscription_info = subscription_info.clone();
        subscription_cache.schema_fetch_pending = false;
        let buffered_packets = std::mem::take(&mut subscription_cache.buffered_packets);
        let drained = buffered_packets.len();
        // Update the per-peer counter while we still hold the peer_cache
        // borrow.
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
        self.stats
            .pending
            .record(self.pending_packets.len() as u64, &[]);
        let peer_ip = subscription_info.peer_ip();
        let peer_sub_count = self
            .peer_cache
            .get(&peer_ip)
            .map(|p| p.subscriptions.len())
            .unwrap_or(0);
        self.record_otel_gauges(peer_ip, remaining, peer_sub_count);
        Ok(())
    }
}
