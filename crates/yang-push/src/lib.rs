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

//! # Overview
//!
//! This module defines the constants and types relevant to the NetCalyx UDP
//! notification handling system using YANG-Push subscriptions.
//! # Exports and Definitions
//!
//! ## Submodules
//! - [cache]: Expected to define and handle caching mechanisms for the system.
//! - [model]: Contains the data models or structures used IETF Telemetry
//!   Message.
//! - [validation]: Implements validation mechanisms for YANG-Push messages.
//!
//! ## Type Definitions
//! - `ContentId`: A `String` type alias representing the identifier for content
//!   within the notification system.

pub mod cache;
pub mod model;
pub mod validation;

/// A String type alias representing the Content ID in YANG Library
/// [RFC8525](https://datatracker.ietf.org/doc/html/rfc8525).
pub type ContentId = String;

pub const OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY: &str = "netcalyx.udp.notif.yang.push.subscription.id";
pub const OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY: &str =
    "netcalyx.udp.notif.yang.push.subscription.target";
pub const OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY: &str =
    "netcalyx.udp.notif.yang.push.subscription.router_content_id";
pub const OTL_YANG_PUSH_CACHED_CONTENT_ID_KEY: &str =
    "netcalyx.udp.notif.yang.push.subscription.cached_content_id";
