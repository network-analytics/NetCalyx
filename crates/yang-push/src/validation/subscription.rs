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

//! Building `SubscriptionInfo` from
//! `SubscriptionStarted`/`SubscriptionModified` notifications and
//! normalizing/checking their xpath targets.

use crate::cache::storage::SubscriptionInfo;
use crate::validation::actor::ValidationActor;
use netcalyx_netconf_proto::xpath::{strip_xpath_predicates, xpath_diff};
use netcalyx_netconf_proto::yang_push::filters::DatastoreXPathFilter;
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_udp_notif_pkt::notification::{SubscriptionStartedModified, Target};
use std::net::SocketAddr;
use tracing::{debug, trace, warn};
use yang5::schema::SchemaPathFormat;

impl ValidationActor {
    /// Resolve the inline `datastore-xpath-filter` target against the loaded
    /// schema and warn if it does not resolve or is not in libyang's canonical
    /// form (`LYSC_PATH_DATA`). Purely diagnostic: the target is never
    /// modified. A well-behaved publisher should always send a resolvable,
    /// canonical path, so a mismatch flags a bad xpath from the router (or
    /// a gap in the fetcher-side normalization). Skipped for targets without a
    /// datastore xpath filter.
    ///
    /// Predicates (`[...]`) are stripped before the equality check: libyang's
    /// schema path never carries them, so we compare the structural
    /// location path and still detect real prefix/structure differences
    /// without a spurious mismatch from the predicate itself.
    pub(super) fn check_xpath_target_resolves(
        subscription_info: &SubscriptionInfo,
        yang_ctx: &yang5::context::Context,
    ) {
        let subscription_id = subscription_info.id();
        let peer = subscription_info.peer_ip();

        let Some(original) = subscription_info.target.datastore_xpath_filter.as_deref() else {
            return;
        };

        // find_xpath is evaluated against the original query (predicates
        // included) so a malformed predicate/typo'd leaf name still surfaces
        // as a real evaluation error.
        let nodes = match yang_ctx.find_xpath(original) {
            Ok(set) => set.collect::<Vec<_>>(),
            Err(err) => {
                warn!(
                    %peer,
                    subscription_id,
                    path = %original,
                    error = %err,
                    "target xpath failed to evaluate against the schema (bad xpath from the publisher?)",
                );
                return;
            }
        };

        match nodes.as_slice() {
            [node] => {
                let canonical = node.path(SchemaPathFormat::DATA);
                // Schema paths are absolute and never carry predicates; strip
                // predicates from the provided path and tolerate a
                // device-omitted leading slash before comparing, so only
                // genuine structural/prefix differences are reported.
                let stripped = strip_xpath_predicates(original);
                let comparison = if stripped.starts_with('/') {
                    stripped
                } else {
                    format!("/{stripped}")
                };
                if canonical != comparison {
                    let (diverges_at, provided_unique, canonical_unique) =
                        xpath_diff(&comparison, &canonical);
                    warn!(
                        %peer,
                        subscription_id,
                        provided = %original,
                        canonical = %canonical,
                        diverges_at,
                        provided_unique,
                        canonical_unique,
                        "target xpath differs from the schema canonical form",
                    );
                } else {
                    trace!(
                        %peer,
                        subscription_id,
                        path = %original,
                        "target xpath resolves to a schema node and is canonical",
                    );
                }
            }
            [] => warn!(
                %peer,
                subscription_id,
                path = %original,
                "target xpath does not resolve to any schema node (bad xpath from the publisher?)",
            ),
            many => trace!(
                %peer,
                subscription_id,
                path = %original,
                node_count = many.len(),
                "target xpath resolves to multiple schema nodes",
            ),
        }
    }

    /// Normalize the inline `datastore-xpath-filter` carried by a JSON
    /// `SubscriptionStarted`/`SubscriptionModified` notification to the same
    /// module-name-qualified, prefix-on-change canonical form the fetcher
    /// applies to NETCONF/XML-sourced targets (see
    /// `DatastoreXPathFilter::normalize_path`).
    ///
    /// Unlike the XML case, JSON xpath strings never carry `xmlns` prefix
    /// declarations — per RFC 7951/8641 a prefix in the path text is already
    /// the module name itself. So this is a pure string transform: wrapping
    /// the path in a `DatastoreXPathFilter` with an empty namespace table
    /// makes every prefix fall into `normalize_path`'s "undeclared prefix is
    /// the module name" branch, meaning `resolve_module` is never invoked and
    /// no schema/YANG-library access is needed here.
    ///
    /// No-op if the target has no datastore xpath filter. Leaves the path
    /// untouched (but logs a warning) if it can't be confidently normalized
    /// (e.g. functions, unions, or other unsupported XPath 1.0 constructs).
    fn normalize_json_target_xpath(
        peer: SocketAddr,
        subscription_id: SubscriptionId,
        target: &mut Target,
    ) {
        let Some(original) = target.datastore_xpath_filter.as_deref() else {
            return;
        };
        let filter = DatastoreXPathFilter {
            namespaces: Box::new([]),
            path: original.into(),
        };
        match filter.normalize_path(|_uri| None) {
            Some(normalized) => {
                if normalized != original {
                    debug!(
                        %peer,
                        subscription_id,
                        from = %original,
                        to = %normalized,
                        "normalized target xpath filter",
                    );
                }
                target.datastore_xpath_filter = Some(normalized);
            }
            None => warn!(
                %peer,
                subscription_id,
                path = %original,
                "could not normalize target xpath filter, keeping original",
            ),
        }
    }

    /// Construct a `SubscriptionInfo` from a `SubscriptionStarted/Modified`
    /// notification. Returns `None` if module-version is absent.
    pub(super) fn build_subscription_info(
        &self,
        peer: SocketAddr,
        message_id: u32,
        publisher_id: u32,
        sub_started: &SubscriptionStartedModified,
    ) -> Option<SubscriptionInfo> {
        // Keep the models exactly as reported by the device: the fetcher adds
        // `ietf-subscribed-notifications` at load time, so this info matches
        // the one built by a fetch by subscription id.
        let modules = match sub_started.module_version() {
            Some(modules) => modules.clone().into_boxed_slice(),
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

        let mut target = sub_started.target().clone();
        Self::normalize_json_target_xpath(peer, sub_started.id(), &mut target);

        Some(SubscriptionInfo::new(
            peer.ip(),
            sub_started.id(),
            target,
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
}

#[cfg(test)]
mod tests;
