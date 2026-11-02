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
//!     true,         // enforce strict validation of anydata nodes
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

mod actor;
mod processing;
mod state;
mod stats;
mod subscription;

pub use actor::{ValidationActorError, ValidationActorHandle, ValidationActorHandleError};
pub use processing::ValidatedNotification;
pub use stats::ValidationStats;
