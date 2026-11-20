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

use super::{build_subscription_info, check_xpath_target_resolves, normalize_json_target_xpath};
use crate::ContentId;
use crate::cache::storage::SubscriptionInfo;
use netcalyx_netconf_proto::yang_push::identities::{Encoding, Transport};
use netcalyx_netconf_proto::yang_push::subscription::YangPushModuleVersion;
use netcalyx_udp_notif_pkt::notification::{SubscriptionStartedModified, Target};
use std::net::{IpAddr, SocketAddr};
use yang5::data::DataFormat;

/// A JSON `datastore-xpath-filter` with a redundant module prefix on
/// every step must be collapsed to the prefix-on-change canonical form,
/// same as the fetcher-side XML normalization.
#[test]
fn test_normalize_json_target_xpath_collapses_redundant_prefixes() {
    let mut target = Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right(
            "/ietf-interfaces:interfaces/ietf-interfaces:interface[ietf-interfaces:name='eth0']/ietf-interfaces:oper-status"
                .to_string(),
        ),
    );
    normalize_json_target_xpath(SocketAddr::from(([127, 0, 0, 1], 0)), 1, &mut target);
    assert_eq!(
        target.datastore_xpath_filter.as_deref(),
        Some("/ietf-interfaces:interfaces/interface[name='eth0']/oper-status")
    );
}

/// An already-canonical JSON xpath must be left unchanged
/// (idempotent transform).
#[test]
fn test_normalize_json_target_xpath_idempotent_on_canonical_path() {
    let mut target = Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right("/ietf-interfaces:interfaces/interface".to_string()),
    );
    normalize_json_target_xpath(SocketAddr::from(([127, 0, 0, 1], 0)), 1, &mut target);
    assert_eq!(
        target.datastore_xpath_filter.as_deref(),
        Some("/ietf-interfaces:interfaces/interface")
    );
}

/// A target without a datastore xpath filter (e.g. a stream target) must
/// be left untouched.
#[test]
fn test_normalize_json_target_xpath_noop_without_xpath_filter() {
    let mut target = Target::new_stream(
        "NETCONF".to_string(),
        None,
        either::Left(serde_json::Value::Null),
    );
    let before = target.clone();
    normalize_json_target_xpath(SocketAddr::from(([127, 0, 0, 1], 0)), 1, &mut target);
    assert_eq!(target, before);
}

/// Loads a `yang5::context::Context` from the bundled `ietf-interfaces`
/// test schema (the same assets used by the cache actor tests), for
/// tests that need a real schema to resolve xpaths against.
pub(crate) fn load_test_yang_ctx() -> yang5::context::Context {
    yang5::context::Context::new_from_yang_library_file(
        std::path::Path::new("../../assets/yang/ietf-interfaces/yang-lib.xml"),
        DataFormat::XML,
        std::path::Path::new("../../assets/yang/ietf-interfaces/modules"),
        yang5::context::ContextFlags::empty(),
    )
    .expect("Failed to load test YANG context")
}

fn test_subscription_info_with_target(target: Target) -> SubscriptionInfo {
    SubscriptionInfo::new(
        IpAddr::from([127, 0, 0, 1]),
        1,
        target,
        None,
        Some(Transport::UDPNotif),
        Some(Encoding::Json),
        None,
        None,
        Box::new([]),
        ContentId::from("test-content-id".to_string()),
    )
}

/// A target xpath that resolves to exactly one schema node and is
/// already in canonical form must not produce any warning.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_canonical_path_is_silent() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right("/ietf-interfaces:interfaces/interface/oper-status".to_string()),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(!logs_contain(
        "target xpath differs from the schema canonical form"
    ));
    assert!(!logs_contain("target xpath does not resolve"));
    assert!(!logs_contain("target xpath failed to evaluate"));
}

/// A target xpath that resolves but is not in libyang's canonical
/// (prefix-on-change) form must warn with the divergence details.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_non_canonical_path_warns() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right(
            "/ietf-interfaces:interfaces/ietf-interfaces:interface/ietf-interfaces:oper-status"
                .to_string(),
        ),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(logs_contain(
        "target xpath differs from the schema canonical form"
    ));
}

/// Predicates must be stripped before the canonical-form comparison, so
/// an instantiated key predicate alone does not trigger a false warning.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_ignores_predicates_when_comparing() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right("/ietf-interfaces:interfaces/interface[name='eth0']/oper-status".to_string()),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(!logs_contain(
        "target xpath differs from the schema canonical form"
    ));
}

/// An xpath referring to a node that doesn't exist in the schema must
/// warn that it does not resolve to any schema node.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_missing_node_warns() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right("/ietf-interfaces:interfaces/interface/no-such-leaf".to_string()),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(logs_contain(
        "target xpath does not resolve to any schema node"
    ));
}

/// A syntactically invalid xpath must warn that it failed to evaluate,
/// rather than panicking or silently passing.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_invalid_xpath_warns() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_datastore(
        "ietf-datastores:operational".to_string(),
        either::Right("/ietf-interfaces:interfaces[".to_string()),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(logs_contain(
        "target xpath failed to evaluate against the schema"
    ));
}

/// A target without a datastore xpath filter (e.g. a stream target)
/// must be a no-op: no warnings, no panics.
#[test]
#[tracing_test::traced_test]
fn test_check_xpath_target_resolves_noop_without_xpath_filter() {
    let yang_ctx = load_test_yang_ctx();
    let subscription_info = test_subscription_info_with_target(Target::new_stream(
        "NETCONF".to_string(),
        None,
        either::Left(serde_json::Value::Null),
    ));
    check_xpath_target_resolves(&subscription_info, &yang_ctx);
    assert!(!logs_contain("target xpath"));
}

fn subscription_started(
    module_version: Option<Vec<YangPushModuleVersion>>,
) -> SubscriptionStartedModified {
    SubscriptionStartedModified::new(
        7,
        Target::new_datastore(
            "ietf-datastores:operational".to_string(),
            either::Right("/ietf-interfaces:interfaces/ietf-interfaces:interface".to_string()),
        ),
        None,
        None,
        None,
        None,
        Some(Transport::UDPNotif),
        Some(Encoding::Json),
        None,
        None,
        None,
        module_version,
        Some("router-content-id".to_string()),
        serde_json::Value::Null,
    )
}

/// A SubscriptionStarted with module-version yields a `SubscriptionInfo`
/// keyed by the peer IP, with the modules kept as reported by the device
/// and the target xpath normalized.
#[test]
fn test_build_subscription_info_from_subscription_started() {
    let peer = SocketAddr::from(([192, 0, 2, 1], 4000));
    let started = subscription_started(Some(vec![YangPushModuleVersion::new(
        "ietf-interfaces".into(),
        None,
        None,
    )]));
    let info = build_subscription_info(peer, 1, 2, &started).expect("subscription info");
    assert_eq!(info.peer_ip(), peer.ip());
    assert_eq!(info.id(), 7);
    assert_eq!(info.content_id(), "router-content-id");
    let modules: Vec<_> = info.models().iter().map(|m| m.name()).collect();
    assert_eq!(modules, vec!["ietf-interfaces"]);
    assert_eq!(
        info.target().datastore_xpath_filter.as_deref(),
        Some("/ietf-interfaces:interfaces/interface")
    );
}

/// Without module-version no `SubscriptionInfo` can be built.
#[test]
fn test_build_subscription_info_requires_module_version() {
    let peer = SocketAddr::from(([192, 0, 2, 1], 4000));
    assert!(build_subscription_info(peer, 1, 2, &subscription_started(None)).is_none());
}
