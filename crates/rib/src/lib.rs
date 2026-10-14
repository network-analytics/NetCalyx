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

//! In-memory BGP RIB storage for a BMP collector.
//!
//! This crate holds the core data model, attribute interning, per-router
//! per-AFI-SAFI RIB containers with Arc-per-trie copy-on-write, peer address
//! resolution, and LPM lookup.

pub mod attrs;
pub mod lookup;
pub mod model;
pub mod peers;
pub mod types;

pub use attrs::{AttrStore, RouteAttributes};
pub use lookup::{DEFAULT_VIEW_ORDER, LookupRequest, LookupTarget, Match, lookup};
pub use model::{AfiSafiTable, RibStore, RouterRib};
pub use types::{
    AfiSafiType, LabeledRouteExtra, RibContext, RibView, Srv6RouteExtra, TableId, peer_identity,
};
