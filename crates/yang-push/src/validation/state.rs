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

//! Per-peer / per-subscription state held by the validation actor.

use crate::ContentId;
use crate::cache::storage::SubscriptionInfo;
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_udp_notif_service::UdpNotifRequest;
use rustc_hash::FxHashMap;
use std::sync::Arc;

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
/// or `LookupBySubscriptionId` request is sent and cleared to `false` when
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
    pub(super) cached_content_id: Option<ContentId>,
    pub(super) subscription_info: SubscriptionInfo,
    pub(super) yang_ctx: Option<yang5::context::Context>,
    pub(super) buffered_packets: Vec<Arc<UdpNotifRequest>>,
    pub(super) schema_fetch_pending: bool,
}

impl CachedSubscription {
    pub(super) fn new(subscription_info: SubscriptionInfo) -> Self {
        Self {
            cached_content_id: None,
            subscription_info,
            yang_ctx: None,
            buffered_packets: Vec::new(),
            schema_fetch_pending: false,
        }
    }
}

// TODO: entries here are never evicted by TTL/idleness (only replaced when a
// subscription's SubscriptionStarted info changes via
// `check_subscription_new`). A peer churning through many subscription IDs can
// grow this map unboundedly; consider a purge mechanism similar to
// `UdpNotifSupervisorHandle::purge_unused_peers`.
#[derive(Debug, Default)]
pub(super) struct CachedPeerSubscriptions {
    pub(super) subscriptions: FxHashMap<SubscriptionId, CachedSubscription>,
    pub(super) total_buffered: usize,
}
