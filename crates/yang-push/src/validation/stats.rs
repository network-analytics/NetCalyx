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

//! OpenTelemetry metrics recorded by the validation actor.

use crate::cache::storage::SubscriptionInfo;
use crate::{
    OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use netcalyx_udp_notif_pkt::raw::UdpNotifPacket;
use netcalyx_udp_notif_service::OTL_UDP_NOTIF_PUBLISHER_ID_KEY;
use std::net::SocketAddr;
use strum::VariantNames;

// Attribute key shared by the `dropped` and `skipped` counters.
pub(super) const REASON_KEY: &str = "reason";

/// Attribute values for the `reason` key on the `dropped` counter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub(super) enum DropReason {
    DecodeError,
    BufferFullSubscription,
    BufferFullPeer,
    UntrackedSubscription,
    ValidationFailed,
    IncompleteSubscriptionStarted,
    NoSubscriptionId,
    SendError,
}

/// Attribute values for the `reason` key on the `skipped` counter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub(super) enum SkipReason {
    NoLibrary,
    ContextFailed,
    NoSubscriptionInfo,
}

// Attribute key for the `cache_lookups` counter.
pub(super) const CACHE_LOOKUP_BY_KEY: &str = "by";

/// Attribute values for the `by` key on the `cache_lookups` counter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub(super) enum CacheLookupBy {
    SubscriptionInfo,
    SubscriptionId,
}

/// OpenTelemetry metrics for YANG-Push validation.
#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub received: opentelemetry::metrics::Counter<u64>,
    pub decoded: opentelemetry::metrics::Counter<u64>,
    pub dropped: opentelemetry::metrics::Counter<u64>,
    pub cache_lookups: opentelemetry::metrics::Counter<u64>,
    pub subscription_update_deferred: opentelemetry::metrics::Counter<u64>,
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
            .with_description(format!(
                "Number of YANG-Push messages dropped for any reason, \
                tagged with reason ({})",
                DropReason::VARIANTS.join(" | ")
            ))
            .build();
        let cache_lookups = meter
            .u64_counter("netcalyx.yang_push.validation.cache.lookups")
            .with_description(format!(
                "Number of YANG schema cache lookups issued, tagged with by ({})",
                CacheLookupBy::VARIANTS.join(" | ")
            ))
            .build();
        let subscription_update_deferred = meter
            .u64_counter("netcalyx.yang_push.validation.subscription_update.deferred")
            .with_description(
                "Number of SubscriptionStarted/SubscriptionModified notifications buffered \
                because a schema fetch was already in-flight for that subscription id, \
                deferring the change until the outstanding fetch resolves",
            )
            .build();
        let buffered = meter
            .u64_gauge("netcalyx.yang_push.validation.buffered")
            .with_description(
                "Number of YANG-Push messages currently buffered waiting for schemas, \
                per peer, tagged with network.peer.address. Sum gives the global total.",
            )
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
            .with_description(format!(
                "Number of YANG-Push messages forwarded without validation, \
                tagged with reason ({})",
                SkipReason::VARIANTS.join(" | ")
            ))
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
            subscription_update_deferred,
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
/// Build the base OpenTelemetry tag set (peer address, port, publisher id)
/// for a given UDP-Notif packet.
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
pub(super) fn extend_peer_tags_with_subscription_info(
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

/// Append the `reason` attribute to a copy of `tags`.
pub(super) fn with_reason(
    tags: &[opentelemetry::KeyValue],
    reason: impl Into<&'static str>,
) -> Vec<opentelemetry::KeyValue> {
    let mut tags = tags.to_vec();
    tags.push(opentelemetry::KeyValue::new(REASON_KEY, reason.into()));
    tags
}
