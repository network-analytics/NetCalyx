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

//! Validation logic, independent of the actor runtime.
//!
//! [`Validator`] makes every decision about incoming packets (decode,
//! resolve subscription, buffer, validate) and cache responses (load the
//! YANG context, drain the hold buffer).
//! [`PeerCache`] holds the underlying per-peer/per-subscription state.
//!
//! It performs no channel I/O: the actor executes the returned
//! [`PacketOutcome`] (forward downstream or send a cache lookup).

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::cache::storage::{SubscriptionInfo, YangLibraryReference};
use crate::validation::state::{
    BufferError, ClearCacheReport, PeerCache, PeerCacheError, Resolved, SchemaState, Tracking,
    YangPushCacheSnapshot,
};
use crate::validation::stats::{
    CACHE_LOOKUP_BY_KEY, CacheLookupBy, DropReason, SkipReason, ValidationStats,
    extend_peer_tags_with_subscription_info, peer_tags_from_packet, with_reason,
};
use crate::validation::subscription::{build_subscription_info, check_xpath_target_resolves};
use crate::{ContentId, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY};
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_udp_notif_pkt::decoded::{UdpNotifPacketDecoded, UdpNotifPayload};
use netcalyx_udp_notif_pkt::notification::NotificationVariant;
use netcalyx_udp_notif_pkt::raw::UdpNotifPacket;
use netcalyx_udp_notif_service::{SessionInfo, UdpNotifRequest};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;
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

/// A cache lookup that the actor must send on behalf of the [`Validator`].
///
/// By the time it is returned, the subscription is already marked as
/// `schema_fetch_pending` and the triggering packet is buffered (or dropped
/// if the hold buffers were full).
#[derive(Debug)]
pub(super) enum CacheLookup {
    BySubscriptionInfo {
        subscription_info: Box<SubscriptionInfo>,
        session: SessionInfo,
    },
    BySubscriptionId {
        subscription_id: SubscriptionId,
        session: SessionInfo,
    },
}

impl CacheLookup {
    /// Build the cache actor command, with `tx` as the response channel.
    pub fn into_command(self, tx: async_channel::Sender<CacheResponse>) -> CacheLookupCommand {
        match self {
            Self::BySubscriptionInfo {
                subscription_info,
                session,
            } => CacheLookupCommand::LookupBySubscriptionInfo {
                subscription_info: *subscription_info,
                session,
                tx,
            },
            Self::BySubscriptionId {
                subscription_id,
                session,
            } => CacheLookupCommand::LookupBySubscriptionId {
                subscription_id,
                session,
                tx,
            },
        }
    }
}

/// The action the actor must take after [`Validator::process_packet`].
// Keep `Forward` inline instead of boxing it to avoid an additional heap
// allocation per packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(super) enum PacketOutcome {
    /// Forward the notification downstream. `peer_tags` are the metric
    /// attributes to record the `sent` (or `dropped`) counter with.
    Forward {
        notification: ValidatedNotification,
        peer_tags: Vec<opentelemetry::KeyValue>,
    },
    /// Send a cache lookup; the packet waits in the hold buffer
    /// until the response arrives.
    CacheLookup(CacheLookup),
    /// Nothing left to do: the packet was dropped or buffered.
    Consumed,
}

/// Validation state machine, independent of the actor runtime.
///
/// Owns the two-level (peer/subscription) cache, the hold buffers, and the
/// queue of packets drained from the hold buffers once schemas arrive. It
/// performs no channel I/O: every decision is returned to the caller as a
/// [`PacketOutcome`], so the logic can be unit tested synchronously.
#[derive(Debug)]
pub(super) struct Validator {
    /// Whether `anydata` nodes are validated strictly against their
    /// schema (see `yang5::data::DataParserFlags::ANYDATA_STRICT`).
    anydata_strict: bool,
    peer_cache: PeerCache,
    /// Packets drained from the per-subscription hold buffers once the cache
    /// responds, waiting to be reprocessed one at a time.
    pending_packets: VecDeque<Arc<UdpNotifRequest>>,
    stats: ValidationStats,
}

impl Validator {
    pub fn new(
        max_buffered_packets_per_peer: usize,
        max_buffered_packets_per_subscription: usize,
        anydata_strict: bool,
        stats: ValidationStats,
    ) -> Self {
        Self {
            anydata_strict,
            peer_cache: PeerCache::new(
                max_buffered_packets_per_peer,
                max_buffered_packets_per_subscription,
            ),
            pending_packets: VecDeque::new(),
            stats,
        }
    }

    pub const fn stats(&self) -> &ValidationStats {
        &self.stats
    }

    pub fn has_pending(&self) -> bool {
        !self.pending_packets.is_empty()
    }

    /// Pop the next packet drained from a hold buffer, to be passed back to
    /// [`Self::process_packet`] with `is_reprocessed = true`.
    pub fn pop_pending(&mut self) -> Option<Arc<UdpNotifRequest>> {
        let message = self.pending_packets.pop_front()?;
        self.stats
            .pending
            .record(self.pending_packets.len() as u64, &[]);
        Some(message)
    }

    /// Core per-packet handler, called for every incoming UDP-Notif message
    /// and for every packet drained from the hold buffers once schemas arrive
    /// (`is_reprocessed = true`, which avoids double-counting the `received`
    /// and `decoded` metrics).
    pub fn process_packet(
        &mut self,
        message: Arc<UdpNotifRequest>,
        is_reprocessed: bool,
    ) -> PacketOutcome {
        let peer = message.peer_address();
        let packet = message.packet();
        let mut peer_tags = peer_tags_from_packet(peer, packet);
        if !is_reprocessed {
            self.stats.received.add(1, &peer_tags);
        }

        // Step 1: decode the raw UDP-Notif payload. Errors are logged and
        // counted in `decode_message`.
        let Some(decoded) = self.decode_message(peer, packet, &peer_tags, !is_reprocessed) else {
            return PacketOutcome::Consumed;
        };
        let notification_type = notification_type(&decoded);
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let is_legacy = matches!(decoded.payload(), UdpNotifPayload::NotificationLegacy(_));

        // Step 2: resolve subscription info. Breaks if the packet was
        // buffered, dropped, or needs a cache lookup first.
        let subscription_info = match self.resolve_subscription_info(
            Arc::clone(&message),
            peer,
            &peer_tags,
            &decoded,
        ) {
            ControlFlow::Continue(subscription_info) => subscription_info,
            ControlFlow::Break(outcome) => return outcome,
        };
        extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);

        // Step 3: validate against YANG schemas if available, skip otherwise.
        let cached = self.peer_cache.get(peer.ip(), subscription_info.id());
        let cached_content_id = if let Some(cached) = cached
            && let Some(cached_content_id) = cached.cached_content_id().cloned()
            && let Some(yang_ctx) = cached.yang_ctx()
            && !subscription_info.is_empty()
        {
            let payload = packet.payload();
            if let Err(err) = validate_payload(yang_ctx, &payload, is_legacy, self.anydata_strict) {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id,
                    notification_type,
                    is_legacy,
                    error=%err,
                    packet=str::from_utf8(&payload).unwrap_or("unserializable packet payload"),
                    "Failed to validate UDP-Notif payload, dropping packet"
                );
                self.stats
                    .dropped
                    .add(1, &with_reason(&peer_tags, DropReason::ValidationFailed));
                return PacketOutcome::Consumed;
            }
            self.stats.validated.add(1, &peer_tags);
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                notification_type,
                cached_content_id,
                is_legacy,
                "Successfully validated YANG-Push message",
            );
            Some(cached_content_id)
        } else {
            let skip_reason = if subscription_info.is_empty() {
                SkipReason::NoSubscriptionInfo
            } else if cached.is_some_and(|c| c.cached_content_id().is_some()) {
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
            self.stats
                .skipped
                .add(1, &with_reason(&peer_tags, skip_reason));
            None
        };

        // Step 4: hand over to the actor for forwarding.
        PacketOutcome::Forward {
            notification: ValidatedNotification {
                cached_content_id,
                subscription_info,
                session: message.session().clone(),
                packet: decoded,
            },
            peer_tags,
        }
    }

    /// Handle a cache lookup response: load (or clear) the YANG context for
    /// the subscription, clear `schema_fetch_pending`, and drain the hold
    /// buffer into the pending queue for reprocessing.
    pub fn process_cache_response(&mut self, response: CacheResponse) {
        let (cached_content_id, subscription_info, yang_lib_ref) = response.into();
        if !self.is_tracked(&subscription_info, cached_content_id.as_ref()) {
            return;
        }
        let otl_tags = cache_response_tags(&subscription_info);
        let (cached_content_id, yang_ctx) = if let Some(yang_lib_ref) = yang_lib_ref {
            let yang_ctx = self.load_yang_context(&subscription_info, &yang_lib_ref, &otl_tags);
            (cached_content_id, yang_ctx)
        } else {
            self.stats.yang_context_empty.add(1, &otl_tags);
            (None, None)
        };
        self.apply_schema(subscription_info, cached_content_id, yang_ctx);
    }

    pub fn cache_snapshot(
        &self,
        peer: Option<IpAddr>,
    ) -> Result<YangPushCacheSnapshot, PeerCacheError> {
        match peer {
            Some(ip) => self.peer_cache.snapshot_peer(ip),
            None => Ok(self.peer_cache.snapshot_all()),
        }
    }

    pub fn clear_cache(
        &mut self,
        peer: Option<IpAddr>,
    ) -> Result<ClearCacheReport, PeerCacheError> {
        let report = match peer {
            Some(ip) => self.peer_cache.clear_peer(ip)?,
            None => self.peer_cache.clear_all(),
        };
        for ip in &report.cleared_peers {
            self.record_otel_gauges(*ip, 0, 0);
        }
        Ok(report)
    }

    /// Whether a cache entry exists for the subscription a cache response
    /// refers to; logs and returns `false` otherwise.
    fn is_tracked(
        &self,
        subscription_info: &SubscriptionInfo,
        cached_content_id: Option<&ContentId>,
    ) -> bool {
        let msg = match self
            .peer_cache
            .tracking(subscription_info.peer_ip(), subscription_info.id())
        {
            Tracking::Tracked => return true,
            Tracking::UnknownPeer => {
                "Received cache response for subscription from peer that is not in the cache, ignoring the response"
            }
            Tracking::UnknownSubscription => {
                "Received cache response for subscription that is not in the cache, ignoring the response"
            }
        };
        warn!(
            peer_ip=%subscription_info.peer_ip(),
            subscription_id=subscription_info.id(),
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            cached_content_id,
            "{msg}"
        );
        false
    }

    /// Create the libyang context for a YANG library reference returned by
    /// the cache. Returns `None` (validation disabled) if creation fails.
    fn load_yang_context(
        &self,
        subscription_info: &SubscriptionInfo,
        yang_lib_ref: &YangLibraryReference,
        otl_tags: &[opentelemetry::KeyValue],
    ) -> Option<yang5::context::Context> {
        let search_dir = yang_lib_ref.search_dir();
        match yang5::context::Context::new_from_yang_library_file(
            &yang_lib_ref.yang_library_path(),
            DataFormat::XML,
            &search_dir.as_path(),
            yang5::context::ContextFlags::empty(),
        ) {
            Ok(yang_ctx) => {
                self.stats.yang_context_loaded.add(1, otl_tags);
                // Sanity-check the subscription target resolves against the
                // schema and warn if it is missing or not in canonical form.
                // Diagnostic only: the target is never modified here.
                check_xpath_target_resolves(subscription_info, &yang_ctx);
                Some(yang_ctx)
            }
            Err(err) => {
                self.stats.yang_context_failed.add(1, otl_tags);
                warn!(
                    peer_ip=%subscription_info.peer_ip(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    cached_content_id=yang_lib_ref.content_id(),
                    yang_library_path=%yang_lib_ref.yang_library_path().display(),
                    search_dir=%search_dir.display(),
                    error=%err,
                    "Failed to create YANG context, disabling YANG validation for this subscription"
                );
                None
            }
        }
    }

    /// Store the outcome of a schema fetch in the subscription's cache entry
    /// and move its buffered packets to the pending queue.
    ///
    /// `cached_content_id`/`yang_ctx` follow the state table on
    /// `CachedSubscription`. No-op if the subscription is not tracked.
    fn apply_schema(
        &mut self,
        subscription_info: SubscriptionInfo,
        cached_content_id: Option<ContentId>,
        yang_ctx: Option<yang5::context::Context>,
    ) {
        let Some(Resolved {
            drained,
            peer_buffered,
            peer_subscriptions,
        }) = self.peer_cache.resolve(
            subscription_info.clone(),
            cached_content_id.clone(),
            yang_ctx,
        )
        else {
            return;
        };
        let peer_ip = subscription_info.peer_ip();

        for message in drained {
            let peer = message.peer_address();
            let packet = message.packet();
            let mut peer_tags = peer_tags_from_packet(peer, packet);
            extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);
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
        self.record_otel_gauges(peer_ip, peer_buffered, peer_subscriptions);
    }

    /// Record the peer-scoped cache gauges together so they never drift. Call
    /// after any change to the peer cache for `peer_ip`; pass `0`/`0` once the
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
            .record(self.peer_cache.peer_count() as u64, &[]);
    }

    /// Resolve the subscription info for a decoded packet.
    ///
    /// Continues with the subscription info when the packet can be validated
    /// (or forwarded unvalidated) right away. Breaks with the outcome when the
    /// packet was buffered, dropped, or requires a cache lookup first.
    fn resolve_subscription_info(
        &mut self,
        message: Arc<UdpNotifRequest>,
        peer: SocketAddr,
        base_peer_tags: &[opentelemetry::KeyValue],
        decoded: &UdpNotifPacketDecoded,
    ) -> ControlFlow<PacketOutcome, SubscriptionInfo> {
        let mut peer_tags = base_peer_tags.to_vec();
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let notification_type = notification_type(decoded);
        let notif_contents = decoded.payload().notification_contents();
        let is_started_or_modified = matches!(
            notif_contents,
            Some(
                NotificationVariant::SubscriptionStarted(_)
                    | NotificationVariant::SubscriptionModified(_)
            )
        );

        // Defer started/modified notifications while a fetch is already
        // in-flight for this id, so a stale response can never clobber
        // a newer generation.
        if is_started_or_modified && let Some(notif_contents) = notif_contents {
            let subscription_id = notif_contents.subscription_id();
            let pending_entry_info = self
                .peer_cache
                .get(peer.ip(), subscription_id)
                .filter(|s| s.is_fetch_pending())
                .map(|s| s.subscription_info().clone());
            if let Some(existing_info) = pending_entry_info {
                peer_tags.push(opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                    opentelemetry::Value::I64(subscription_id.into()),
                ));
                if self.buffer_packet(&existing_info, message) {
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
                return ControlFlow::Break(PacketOutcome::Consumed);
            }
        }

        if let Some(subscription_info) = self.subscription_info(peer, decoded) {
            extend_peer_tags_with_subscription_info(&subscription_info, &mut peer_tags);
            match self.peer_cache.schema_state(&subscription_info) {
                SchemaState::Resolved => return ControlFlow::Continue(subscription_info),
                SchemaState::FetchPending => {
                    // Buffer the packet so it is validated once the response
                    // arrives, instead of slipping through unvalidated.
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
                    self.buffer_packet(&subscription_info, message);
                    return ControlFlow::Break(PacketOutcome::Consumed);
                }
                SchemaState::Untracked => {}
            }
            debug!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                subscription_target=%subscription_info.target(),
                notification_type,
                "Subscription is not tracked, requesting schemas from the cache using subscription metadata"
            );
            peer_tags.push(opentelemetry::KeyValue::new(
                CACHE_LOOKUP_BY_KEY,
                <&str>::from(CacheLookupBy::SubscriptionInfo),
            ));
            self.stats.cache_lookups.add(1, &peer_tags);
            self.peer_cache.mark_fetch_pending(&subscription_info);
            let lookup = CacheLookup::BySubscriptionInfo {
                subscription_info: Box::new(subscription_info.clone()),
                session: message.session().clone(),
            };
            self.buffer_packet(&subscription_info, message);
            return ControlFlow::Break(PacketOutcome::CacheLookup(lookup));
        }

        if is_started_or_modified {
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
            self.stats.dropped.add(
                1,
                &with_reason(&peer_tags, DropReason::IncompleteSubscriptionStarted),
            );
            return ControlFlow::Break(PacketOutcome::Consumed);
        }

        let Some(subscription_id) = notif_contents.map(|x| x.subscription_id()) else {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                notification_type,
                "Received UDP-Notif packet has no usable subscription metadata or subscription ID, dropping packet"
            );
            self.stats
                .dropped
                .add(1, &with_reason(&peer_tags, DropReason::NoSubscriptionId));
            return ControlFlow::Break(PacketOutcome::Consumed);
        };
        debug!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id,
            notification_type,
            "Received UDP-Notif packet without subscription info, \
            caching the packet and looking up subscription info in cache"
        );
        peer_tags.push(opentelemetry::KeyValue::new(
            CACHE_LOOKUP_BY_KEY,
            <&str>::from(CacheLookupBy::SubscriptionId),
        ));
        self.stats.cache_lookups.add(1, &peer_tags);
        let subscription_info = SubscriptionInfo::new_empty(peer.ip(), subscription_id);
        self.peer_cache.mark_fetch_pending(&subscription_info);
        let lookup = CacheLookup::BySubscriptionId {
            subscription_id,
            session: message.session().clone(),
        };
        self.buffer_packet(&subscription_info, message);
        ControlFlow::Break(PacketOutcome::CacheLookup(lookup))
    }

    /// Get the subscription info from the `SubscriptionStarted/Modified`
    /// notification itself, or from the cache for any other notification.
    fn subscription_info(
        &mut self,
        peer: SocketAddr,
        decoded: &UdpNotifPacketDecoded,
    ) -> Option<SubscriptionInfo> {
        let message_id = decoded.message_id();
        let publisher_id = decoded.publisher_id();
        let Some(notif_contents) = decoded.payload().notification_contents() else {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                "UDP-Notif payload contains no supported notification content, dropping packet"
            );
            return None;
        };

        if let NotificationVariant::SubscriptionStarted(subscription_started)
        | NotificationVariant::SubscriptionModified(subscription_started) = notif_contents
        {
            let Some(subscription_info) =
                build_subscription_info(peer, message_id, publisher_id, subscription_started)
            else {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    notifification_type=%notif_contents.notification_type(),
                    "SubscriptionStarted/SubscriptionModified notification is missing module-version metadata, dropping packet"
                );
                return None;
            };
            if self.peer_cache.evict_if_changed(&subscription_info) {
                trace!(
                    peer=%peer,
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    "Subscription changed, removing from cache to allow a new fetch schemas request"
                );
                // Resync the per-peer gauges after the removal (0/0 when the
                // peer is gone, resetting its series).
                self.record_otel_gauges(
                    peer.ip(),
                    self.peer_cache.peer_buffered(peer.ip()),
                    self.peer_cache.peer_subscriptions(peer.ip()),
                );
            }
            Some(subscription_info)
        } else {
            self.peer_cache
                .get(peer.ip(), notif_contents.subscription_id())
                .map(|x| x.subscription_info().clone())
        }
    }

    /// Attempt to add `message` to the per-subscription hold buffer, enforcing
    /// both the per-subscription and per-peer packet limits.
    /// Returns `true` if the packet was buffered, `false` if it was dropped.
    fn buffer_packet(
        &mut self,
        subscription_info: &SubscriptionInfo,
        message: Arc<UdpNotifRequest>,
    ) -> bool {
        let peer = message.peer_address();
        let packet = message.packet();
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();
        let mut peer_tags = peer_tags_from_packet(peer, packet);
        extend_peer_tags_with_subscription_info(subscription_info, &mut peer_tags);
        let subscription_id = subscription_info.id();
        let subscription_target = subscription_info.target().to_string();
        let router_content_id = subscription_info.content_id().to_string();

        match self
            .peer_cache
            .buffer(subscription_info.peer_ip(), subscription_id, message)
        {
            Ok(peer_buffered) => {
                trace!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id,
                    subscription_target=%subscription_target,
                    router_content_id,
                    "Buffered UDP-Notif packet"
                );
                let sub_count = self.peer_cache.peer_subscriptions(peer.ip());
                self.record_otel_gauges(peer.ip(), peer_buffered, sub_count);
                true
            }
            Err(error) => {
                let (reason, msg) = match error {
                    BufferError::UntrackedSubscription => (
                        DropReason::UntrackedSubscription,
                        "Subscription not tracked, dropping packet instead of buffering it",
                    ),
                    BufferError::SubscriptionFull => (
                        DropReason::BufferFullSubscription,
                        "Buffer full for subscription, dropping new packet",
                    ),
                    BufferError::PeerFull => (
                        DropReason::BufferFullPeer,
                        "Buffer full for peer, dropping new packet",
                    ),
                };
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    subscription_id,
                    subscription_target=%subscription_target,
                    router_content_id,
                    "{msg}"
                );
                self.stats.dropped.add(1, &with_reason(&peer_tags, reason));
                false
            }
        }
    }

    /// Decode a raw `UdpNotifPacket` into a `UdpNotifPacketDecoded`.
    /// Returns `None` and drops the packet on unsupported media type or
    /// parse failure.
    ///
    /// Set `count_decoded` to `false` when reprocessing a buffered message to
    /// avoid double-counting the `decoded` metric.
    fn decode_message(
        &self,
        peer: SocketAddr,
        packet: &UdpNotifPacket,
        peer_tags: &[opentelemetry::KeyValue],
        count_decoded: bool,
    ) -> Option<UdpNotifPacketDecoded> {
        let message_id = packet.message_id();
        let publisher_id = packet.publisher_id();

        let decoded = match UdpNotifPacketDecoded::try_from(packet) {
            Ok(decoded) => decoded,
            Err(err) => {
                warn!(
                    peer=%peer,
                    message_id,
                    publisher_id,
                    error=%err,
                    "Failed to decode UDP-Notif payload, dropping packet"
                );
                self.stats
                    .dropped
                    .add(1, &with_reason(peer_tags, DropReason::DecodeError));
                return None;
            }
        };
        if tracing::enabled!(tracing::Level::TRACE) {
            trace!(
                peer=%peer,
                message_id,
                publisher_id,
                notification_type=notification_type(&decoded),
                "Decoded UDP-Notif payload, starting the validation step"
            );
        }
        if count_decoded {
            let mut decoded_tags = peer_tags.to_vec();
            if let Some(notif_contents) = decoded.payload().notification_contents() {
                decoded_tags.push(opentelemetry::KeyValue::new(
                    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
                    opentelemetry::Value::I64(notif_contents.subscription_id().into()),
                ));
            }
            self.stats.decoded.add(1, &decoded_tags);
        }
        Some(decoded)
    }
}

/// Human-readable notification type used in logs.
pub(super) fn notification_type(decoded: &UdpNotifPacketDecoded) -> String {
    decoded
        .notification_type()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

/// Metric attributes attached to cache-response driven metrics.
fn cache_response_tags(subscription_info: &SubscriptionInfo) -> Vec<opentelemetry::KeyValue> {
    let mut tags = Vec::from([opentelemetry::KeyValue::new(
        "network.peer.address",
        format!("{}", subscription_info.peer_ip()),
    )]);
    extend_peer_tags_with_subscription_info(subscription_info, &mut tags);
    tags
}

/// Validate a raw JSON UDP-Notif payload against a loaded YANG context.
///
/// Legacy (non-envelope) payloads are parsed as a YANG notification
/// operation; `anydata_strict` only applies to envelope payloads.
fn validate_payload(
    yang_ctx: &yang5::context::Context,
    payload: &[u8],
    is_legacy: bool,
    anydata_strict: bool,
) -> Result<(), yang5::Error> {
    if is_legacy {
        yang5::data::DataTree::parse_op_string(
            yang_ctx,
            payload,
            DataFormat::JSON,
            DataParserFlags::STRICT,
            DataOperation::NotificationYang,
        )?;
    } else {
        let mut parser_flags = DataParserFlags::STRICT;
        if anydata_strict {
            parser_flags |= DataParserFlags::ANYDATA_STRICT;
        }
        yang5::data::DataTree::parse_string(
            yang_ctx,
            payload,
            DataFormat::JSON,
            parser_flags,
            DataValidationFlags::PRESENT,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
