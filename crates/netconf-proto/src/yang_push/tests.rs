// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2026-present The NetGauze Authors.
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

//! Unit tests for the `yang_push` module.
//!
//! Covers XML round-trip serialization, serde JSON serialization, and
//! element-reordering robustness for filters, identities, targets, and
//! the top-level [`Subscription`].

use super::*;
use crate::tests::test_xml_value;
use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use crate::yang_push::filters::*;
use crate::yang_push::identities::*;
use crate::yang_push::subscription::*;
use crate::yang_push::types::*;
use crate::yanglib::DatastoreName;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use quick_xml::events::Event;

#[test]
fn test_transport_serialization() {
    assert_eq!(
        serde_json::to_string(&Transport::UDPNotif).unwrap(),
        r#""ietf-udp-notif-transport:udp-notif""#
    );
    assert_eq!(
        serde_json::to_string(&Transport::HTTPSNotif).unwrap(),
        r#""ietf-https-notif:https""#
    );
    assert_eq!(
        serde_json::to_string(&Transport::Unknown).unwrap(),
        r#""unknown""#
    );
}

#[test]
fn test_transport_deserialization() {
    assert_eq!(
        serde_json::from_str::<Transport>(r#""ietf-udp-notif-transport:udp-notif""#).unwrap(),
        Transport::UDPNotif
    );
    assert_eq!(
        serde_json::from_str::<Transport>(r#""ietf-https-notif:https""#).unwrap(),
        Transport::HTTPSNotif
    );
    assert_eq!(
        serde_json::from_str::<Transport>(r#""unknown""#).unwrap(),
        Transport::Unknown
    );

    // Test deserialization of unknown/empty values
    assert_eq!(
        serde_json::from_str::<Transport>(r#""unsupported-value""#).unwrap(),
        Transport::Unknown
    );
    assert_eq!(
        serde_json::from_str::<Transport>(r#""""#).unwrap(),
        Transport::Unknown
    );
}

#[test]
fn test_encoding_serialization() {
    assert_eq!(
        serde_json::to_string(&Encoding::Xml).unwrap(),
        r#""ietf-subscribed-notifications:encode-xml""#
    );

    assert_eq!(
        serde_json::to_string(&Encoding::Json).unwrap(),
        r#""ietf-subscribed-notifications:encode-json""#
    );

    assert_eq!(
        serde_json::to_string(&Encoding::Cbor).unwrap(),
        r#""ietf-udp-notif-transport:encode-cbor""#
    );
    assert_eq!(
        serde_json::to_string(&Encoding::Unknown).unwrap(),
        r#""unknown""#
    );
}

#[test]
fn test_encoding_deserialization() {
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""ietf-subscribed-notifications:encode-xml""#).unwrap(),
        Encoding::Xml
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""encode-xml""#).unwrap(),
        Encoding::Xml
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""ietf-subscribed-notifications:encode-json""#).unwrap(),
        Encoding::Json
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""encode-json""#).unwrap(),
        Encoding::Json
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""ietf-udp-notif-transport:encode-cbor""#).unwrap(),
        Encoding::Cbor
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""encode-cbor""#).unwrap(),
        Encoding::Cbor
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""unknown""#).unwrap(),
        Encoding::Unknown
    );

    // Test deserialization of unknown/empty values
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""unsupported-value""#).unwrap(),
        Encoding::Unknown
    );
    assert_eq!(
        serde_json::from_str::<Encoding>(r#""""#).unwrap(),
        Encoding::Unknown
    );
}

#[test]
fn test_datastore_filter_spec() {
    let namespaces = Box::new([("example".into(), "urn:vendor:example".into())]);
    let input_xpath = r#"<datastore-xpath-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push" xmlns:example="urn:vendor:example">/example:example/debug:board-resouce-states</datastore-xpath-filter>"#;
    let input_subtree = r#"<datastore-subtree-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"  xmlns:example="urn:vendor:example">
        <example:debug/>
        </datastore-subtree-filter>"#;

    let expected_xpath = DatastoreFilterSpec::Xpath(DatastoreXPathFilter {
        namespaces: namespaces.clone(),
        path: "/example:example/debug:board-resouce-states".into(),
    });
    let expected_subtree = DatastoreFilterSpec::Subtree(DatastoreSubtreeFilter {
        namespaces: namespaces.clone(),
        subtree: "<example:debug/>".into(),
    });
    test_xml_value(input_xpath, expected_xpath).expect("XPath filter serde failed");
    test_xml_value(input_subtree, expected_subtree).expect("Subtree filter serde failed");
}

#[test]
fn test_selection_filter() {
    let input_xpath = r#"<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <filter-id>STATSBOARDRESOURCE</filter-id>
        <datastore-xpath-filter  xmlns:debug="urn:example:yang:debug">/debug:debug/debug:board-resouce-states/debug:board-resouce-state</datastore-xpath-filter>
        </selection-filter>"#;
    let input_xpath_reordered = r#"<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <datastore-xpath-filter  xmlns:debug="urn:example:yang:debug">/debug:debug/debug:board-resouce-states/debug:board-resouce-state</datastore-xpath-filter>
        <filter-id>STATSBOARDRESOURCE</filter-id>
        </selection-filter>"#;

    let input_subtree = r#"<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <filter-id>STATSCPU</filter-id>
        <datastore-subtree-filter  xmlns:debug="urn:example:yang:debug">
        <debug:cpu-utilization xmlns:debug="urn:example:yang:debug"/>
        </datastore-subtree-filter>
        </selection-filter>"#;
    let input_subtree_reordered = r#"<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <datastore-subtree-filter  xmlns:debug="urn:example:yang:debug">
            <debug:cpu-utilization xmlns:debug="urn:example:yang:debug"/>
        </datastore-subtree-filter>
        <filter-id>STATSCPU</filter-id>
        </selection-filter>"#;

    let expected_xpath = SelectionFilter {
        filter_id: "STATSBOARDRESOURCE".into(),
        filter_spec: DatastoreFilterSpec::Xpath(DatastoreXPathFilter {
            namespaces: Box::new([("debug".into(), "urn:example:yang:debug".into())]),
            path: "/debug:debug/debug:board-resouce-states/debug:board-resouce-state".into(),
        }),
    };

    let expected_subtree = SelectionFilter {
        filter_id: "STATSCPU".into(),
        filter_spec: DatastoreFilterSpec::Subtree(DatastoreSubtreeFilter {
            namespaces: Box::new([("debug".into(), "urn:example:yang:debug".into())]),
            subtree: "<debug:cpu-utilization xmlns:debug=\"urn:example:yang:debug\"/>".into(),
        }),
    };

    test_xml_value(input_xpath, expected_xpath.clone())
        .expect("XPath selection filter serde failed");
    test_xml_value(input_xpath_reordered, expected_xpath)
        .expect("Reordered XPath selection filter serde failed");
    test_xml_value(input_subtree, expected_subtree.clone())
        .expect("Subtree selection filter serde failed");
    test_xml_value(input_subtree_reordered, expected_subtree)
        .expect("Reordered Subtree selection filter serde failed");
}

#[test]
fn test_stream_filter_spec() {
    let input_xpath = r#"<stream-xpath-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications" xmlns:debug="urn:example:yang:debug">/debug:debug/debug:board-resouce-states/debug:board-resouce-state</stream-xpath-filter>"#;
    let input_subtree = r#"<stream-subtree-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"  xmlns:debug="urn:example:yang:debug">
        <debug:board-resouce-state xmlns:debug="urn:example:yang:debug"/>
        </stream-subtree-filter>"#;
    let expected_xpath = StreamFilterSpec::Xpath(StreamXPathFilter {
        namespaces: Box::new([("debug".into(), "urn:example:yang:debug".into())]),
        path: "/debug:debug/debug:board-resouce-states/debug:board-resouce-state".into(),
    });
    let expected_subtree = StreamFilterSpec::Subtree(StreamSubtreeFilter {
        namespaces: Box::new([("debug".into(), "urn:example:yang:debug".into())]),
        subtree: "<debug:board-resouce-state xmlns:debug=\"urn:example:yang:debug\"/>".into(),
    });
    test_xml_value(input_xpath, expected_xpath).expect("XPath filter serde failed");
    test_xml_value(input_subtree, expected_subtree).expect("Subtree filter serde failed");
}

#[test]
fn test_filters() {
    let input = r#"<filters xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
      <selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <filter-id>STATSBOARDRESOURCE</filter-id>
        <datastore-xpath-filter xmlns:debug="urn:example:yang:debug">/debug:debug/debug:board-resouce-states/debug:board-resouce-state</datastore-xpath-filter>
      </selection-filter>
      <stream-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
        <name>high-priority-syslog</name>
        <stream-xpath-filter xmlns:sl="urn:example:syslog">
          /sl:syslog-message[sl:severity='critical' or sl:severity='error']
        </stream-xpath-filter>
      </stream-filter>
    </filters>"#;

    let selection_filters = vec![SelectionFilter {
        filter_id: "STATSBOARDRESOURCE".into(),
        filter_spec: DatastoreFilterSpec::Xpath(DatastoreXPathFilter {
            namespaces: Box::new([("debug".into(), "urn:example:yang:debug".into())]),
            path: "/debug:debug/debug:board-resouce-states/debug:board-resouce-state".into(),
        }),
    }];

    let stream_filters = vec![StreamFilter {
        name: "high-priority-syslog".into(),
        filter_spec: StreamFilterSpec::Xpath(StreamXPathFilter {
            namespaces: Box::new([("sl".into(), "urn:example:syslog".into())]),
            path: "/sl:syslog-message[sl:severity='critical' or sl:severity='error']".into(),
        }),
    }];
    let filters = Filters::new(stream_filters, selection_filters);
    test_xml_value(input, filters).expect("filters serde failed");
}

// ── StreamTarget / DatastoreTarget ──────────────────────────────────
//
// These types serialize as flat sibling elements (no wrapping element
// of their own), so we test them inside a dummy <subscription> wrapper
// that mirrors the real YANG structure.

/// Helper: parse a `T` that lives inside an already-opened container.
fn parse_within_wrapper<'a, T: XmlDeserialize<'a, T> + std::fmt::Debug>(
    xml: &str,
    wrapper_ns: Namespace<'a>,
    wrapper_tag: &str,
) -> Result<T, ParsingError> {
    let mut reader = quick_xml::NsReader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut parser = XmlParser::new(reader)?;
    parser.open(Some(wrapper_ns), wrapper_tag)?;
    parser.skip_text()?;
    let value = T::xml_deserialize(&mut parser)?;
    parser.skip_text()?;
    parser.close()?; // close wrapper
    Ok(value)
}

/// Helper: serialize `T` inside a dummy wrapper, then strip the wrapper
/// and return just the inner XML.
fn serialize_within_wrapper<T: XmlSerialize>(
    value: &T,
    wrapper_ns: Namespace<'_>,
    wrapper_tag: &str,
) -> String {
    let writer = quick_xml::writer::Writer::new(std::io::Cursor::new(Vec::new()));
    let mut xml_writer = XmlWriter::new(writer);
    xml_writer
        .push_namespace_binding(IndexMap::from([(wrapper_ns, "".to_string())]))
        .unwrap();
    let start = xml_writer
        .create_ns_element(wrapper_ns, wrapper_tag)
        .unwrap();
    xml_writer.write_event(Event::Start(start.clone())).unwrap();
    value.xml_serialize(&mut xml_writer).unwrap();
    xml_writer.write_event(Event::End(start.to_end())).unwrap();
    xml_writer.pop_namespace_binding();
    String::from_utf8(xml_writer.into_inner().into_inner()).unwrap()
}

/// Round-trip helper for types that must live inside a wrapping element.
fn roundtrip_within_wrapper<
    'a,
    T: XmlDeserialize<'a, T> + XmlSerialize + PartialEq + std::fmt::Debug + Clone,
>(
    input_xml: &str,
    expected: T,
    wrapper_ns: Namespace<'a>,
    wrapper_tag: &str,
) {
    // 1. Parse from the test XML
    let parsed: T =
        parse_within_wrapper(input_xml, wrapper_ns, wrapper_tag).expect("deserialization failed");
    assert_eq!(
        parsed, expected,
        "Deserialized value differs:\n  expected: {expected:#?}\n  parsed:   {parsed:#?}"
    );

    // 2. Serialize the expected value back out, then re-parse to confirm round-trip
    let serialized = serialize_within_wrapper(&expected, wrapper_ns, wrapper_tag);
    let reparsed: T = parse_within_wrapper(&serialized, wrapper_ns, wrapper_tag)
        .expect("re-deserialization from serialized output failed");
    assert_eq!(
        reparsed, expected,
        "Round-trip mismatch:\n  expected:   {expected:#?}\n  reparsed:   {reparsed:#?}\n  serialized: {serialized}"
    );
}

// ── DatastoreTarget tests ───────────────────────────────────────────

#[test]
fn test_datastore_target_with_xpath_filter() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
                       xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:operational</datastore>
            <datastore-xpath-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
                                   xmlns:if="urn:example:interfaces">/if:interfaces/if:interface</datastore-xpath-filter>
        </subscription>"#;

    let expected = DatastoreTarget {
        datastore: DatastoreName::Operational,
        selection: DatastoreSelectionFilterObjects::WithInSubscription(DatastoreFilterSpec::Xpath(
            DatastoreXPathFilter {
                namespaces: Box::new([("if".into(), "urn:example:interfaces".into())]),
                path: "/if:interfaces/if:interface".into(),
            },
        )),
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_datastore_target_with_subtree_filter() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
                       xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:running</datastore>
            <datastore-subtree-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
                                     xmlns:if="urn:example:interfaces">
                <if:interfaces/>
            </datastore-subtree-filter>
        </subscription>"#;

    let expected = DatastoreTarget {
        datastore: DatastoreName::Running,
        selection: DatastoreSelectionFilterObjects::WithInSubscription(
            DatastoreFilterSpec::Subtree(DatastoreSubtreeFilter {
                namespaces: Box::new([("if".into(), "urn:example:interfaces".into())]),
                subtree: "<if:interfaces/>".into(),
            }),
        ),
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_datastore_target_with_filter_ref() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
                       xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:operational</datastore>
            <selection-filter-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">my-cpu-filter</selection-filter-ref>
        </subscription>"#;

    let expected = DatastoreTarget {
        datastore: DatastoreName::Operational,
        selection: DatastoreSelectionFilterObjects::ByReference("my-cpu-filter".into()),
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

// ── StreamTarget tests ──────────────────────────────────────────────

#[test]
fn test_stream_target_with_xpath_filter() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <stream>NETCONF</stream>
            <stream-xpath-filter xmlns:if="urn:example:interfaces">/if:interfaces/if:interface</stream-xpath-filter>
        </subscription>"#;

    let expected = StreamTarget {
        stream: "NETCONF".into(),
        filter: StreamSelectionFilterObjects::WithInSubscription(StreamFilterSpec::Xpath(
            StreamXPathFilter {
                namespaces: Box::new([("if".into(), "urn:example:interfaces".into())]),
                path: "/if:interfaces/if:interface".into(),
            },
        )),
        replay_start_time: None,
        configured_reply: false,
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_stream_target_with_filter_ref() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <stream>NETCONF</stream>
            <stream-filter-name>high-priority-syslog</stream-filter-name>
        </subscription>"#;

    let expected = StreamTarget {
        stream: "NETCONF".into(),
        filter: StreamSelectionFilterObjects::ByReference("high-priority-syslog".into()),
        replay_start_time: None,
        configured_reply: false,
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_stream_target_with_replay_and_configured_replay() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <stream>NETCONF</stream>
            <stream-filter-name>my-filter</stream-filter-name>
            <replay-start-time>2025-06-01T00:00:00Z</replay-start-time>
            <configured-replay/>
        </subscription>"#;

    let expected = StreamTarget {
        stream: "NETCONF".into(),
        filter: StreamSelectionFilterObjects::ByReference("my-filter".into()),
        replay_start_time: Some(
            DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
        configured_reply: true,
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_stream_target_elements_reordered() {
    // YANG/XML allows children in any order. Here <stream> comes after
    // the filter, which must still parse correctly.
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <stream-filter-name>my-filter</stream-filter-name>
            <replay-start-time>2025-06-01T00:00:00Z</replay-start-time>
            <stream>NETCONF</stream>
        </subscription>"#;

    let expected = StreamTarget {
        stream: "NETCONF".into(),
        filter: StreamSelectionFilterObjects::ByReference("my-filter".into()),
        replay_start_time: Some(
            DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
        configured_reply: false,
    };

    // Only test deserialization (serialization order is deterministic
    // and may differ from input order).
    let parsed: StreamTarget =
        parse_within_wrapper(xml, SUBSCRIBED_NOTIFICATIONS_NS, "subscription")
            .expect("reordered stream target deserialization failed");
    assert_eq!(parsed, expected);
}

#[test]
fn test_stream_target_with_subtree_filter() {
    let xml = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
            <stream>NETCONF</stream>
            <stream-subtree-filter xmlns:if="urn:example:interfaces">
                <if:interfaces/>
            </stream-subtree-filter>
        </subscription>"#;

    let expected = StreamTarget {
        stream: "NETCONF".into(),
        filter: StreamSelectionFilterObjects::WithInSubscription(StreamFilterSpec::Subtree(
            StreamSubtreeFilter {
                namespaces: Box::new([("if".into(), "urn:example:interfaces".into())]),
                subtree: "<if:interfaces/>".into(),
            },
        )),
        replay_start_time: None,
        configured_reply: false,
    };

    roundtrip_within_wrapper(xml, expected, SUBSCRIBED_NOTIFICATIONS_NS, "subscription");
}

#[test]
fn test_subscription() {
    // Subscription with inline xpath filter, elements in non-canonical
    // order, plus vendor/unknown children (<receivers>, <source-interface>)
    // that must be skipped gracefully.
    let input_by_value = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
        <id>3</id>
        <datastore-xpath-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
            openconfig-platform:components/component/state
        </datastore-xpath-filter>
        <datastore xmlns:idx="urn:ietf:params:xml:ns:yang:ietf-datastores"
                   xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">idx:operational
        </datastore>
        <periodic xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
            <anchor-time>2025-01-01T00:00:30+00:00</anchor-time>
            <period>360000</period>
        </periodic>
        <receivers>
            <receiver>
                <name>DAISY</name>
                <receiver-instance-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers">DAISY
                </receiver-instance-ref>
            </receiver>
        </receivers>
        <source-interface>MgmtEth0/RP0/CPU0/0</source-interface>
        <encoding xmlns:sn="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">sn:encode-json</encoding>
        <dscp>0</dscp>
    </subscription>"#;

    let expected_by_value = Subscription {
        id: 3,
        target: Target::Datastore(DatastoreTarget {
            datastore: DatastoreName::Operational,
            selection: DatastoreSelectionFilterObjects::WithInSubscription(
                DatastoreFilterSpec::Xpath(DatastoreXPathFilter {
                    namespaces: Box::new([]), /* no namespace prefixes declared for
                                               * "openconfig-platform" */
                    path: "openconfig-platform:components/component/state".into(),
                }),
            ),
        }),
        stop_time: None,
        dscp: Some(0),
        weighting: None,
        dependency: None,
        transport: None,
        encoding: Some(Encoding::Json),
        purpose: None,
        configured_subscription_state: None,
        message_publisher_id: None,
        update_trigger: Some(UpdateTrigger::Periodic {
            period: Some(CentiSeconds::new(360000)),
            anchor_time: Some(
                DateTime::parse_from_rfc3339("2025-01-01T00:00:30+00:00")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        }),
        module_version: None,
        yang_library_content_id: None,
    };

    // Subscription with filter-by-reference, transport, encoding,
    // configured-subscription-state, message-publisher-id, and
    // unknown children (<source-interface>, <receivers>) to skip.
    let input_by_reference = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
    <id>1</id>
    <datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"
               xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:operational
    </datastore>
    <selection-filter-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">STATSBOARDRESOURCE</selection-filter-ref>
    <dscp>0</dscp>
    <transport xmlns:unt="urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport">unt:udp-notif</transport>
    <encoding xmlns:sn="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">sn:encode-json</encoding>
    <source-interface>GigabitEthernet0/0/0</source-interface>
    <configured-subscription-state>valid</configured-subscription-state>
    <receivers>
        <receiver>
            <name>DAISY</name>
            <receiver-instance-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers">DAISY
            </receiver-instance-ref>
        </receiver>
    </receivers>
    <message-publisher-id xmlns="urn:ietf:params:xml:ns:yang:ietf-distributed-notif">16843789</message-publisher-id>
    <periodic xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
        <period>6000</period>
        <anchor-time>2025-01-01T00:00:30Z</anchor-time>
    </periodic>
</subscription>"#;

    let expected_by_reference = Subscription {
        id: 1,
        target: Target::Datastore(DatastoreTarget {
            datastore: DatastoreName::Operational,
            selection: DatastoreSelectionFilterObjects::ByReference("STATSBOARDRESOURCE".into()),
        }),
        stop_time: None,
        dscp: Some(0),
        weighting: None,
        dependency: None,
        transport: Some(Transport::UDPNotif),
        encoding: Some(Encoding::Json),
        purpose: None,
        configured_subscription_state: Some(ConfiguredSubscriptionState::Valid),
        message_publisher_id: Some(Box::new([16843789])),
        update_trigger: Some(UpdateTrigger::Periodic {
            period: Some(CentiSeconds::new(6000)),
            anchor_time: Some(
                DateTime::parse_from_rfc3339("2025-01-01T00:00:30Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        }),
        module_version: None,
        yang_library_content_id: None,
    };

    // Parse-only test for input_by_value (contains unknown elements that
    // prevent clean round-trip, but deserialization must succeed).
    let parsed_by_value: Subscription = {
        let mut reader = quick_xml::NsReader::from_str(input_by_value);
        reader.config_mut().trim_text(false);
        let mut parser = XmlParser::new(reader).unwrap();
        Subscription::xml_deserialize(&mut parser).expect("input_by_value parse failed")
    };
    assert_eq!(parsed_by_value, expected_by_value);

    // Parse-only test for input_by_reference (also has unknown elements).
    let parsed_by_ref: Subscription = {
        let mut reader = quick_xml::NsReader::from_str(input_by_reference);
        reader.config_mut().trim_text(false);
        let mut parser = XmlParser::new(reader).unwrap();
        Subscription::xml_deserialize(&mut parser).expect("input_by_reference parse failed")
    };
    assert_eq!(parsed_by_ref, expected_by_reference);

    // Round-trip the by_reference expected value (no unknown elements to
    // lose, so full serialize → deserialize → compare works).
    test_xml_value(input_by_reference, expected_by_reference)
        .expect("subscription by-reference round-trip failed");
}

#[test]
fn test_subscription_yang_push_augments() {
    let input_by_value = r#"<subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
        <id>3</id>
        <datastore-xpath-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
            openconfig-platform:components/component/state
        </datastore-xpath-filter>
        <datastore xmlns:idx="urn:ietf:params:xml:ns:yang:ietf-datastores"
                   xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">idx:operational
        </datastore>
        <periodic xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push">
            <anchor-time>2025-01-01T00:00:30+00:00</anchor-time>
            <period>360000</period>
        </periodic>
        <receivers>
            <receiver>
                <name>DAISY</name>
                <receiver-instance-ref xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers">DAISY
                </receiver-instance-ref>
            </receiver>
        </receivers>
        <source-interface>MgmtEth0/RP0/CPU0/0</source-interface>
        <encoding xmlns:sn="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">sn:encode-json</encoding>
        <dscp>0</dscp>
        <module-version xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push-revision">
          <name>ietf-interfaces</name>
        </module-version>
        <module-version xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push-revision">
          <name>example-module1</name>
          <revision>2024-01-01</revision>
        </module-version>
        <module-version xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push-revision">
          <name>example-module2</name>
          <version>2.0.0</version>
        </module-version>
        <module-version xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push-revision">
          <name>example-module3</name>
          <revision>2024-02-02</revision>
          <version>3.0.0</version>
        </module-version>
        <yang-library-content-id xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push-revision">
          123
        </yang-library-content-id>
    </subscription>"#;

    let expected_by_value = Subscription {
        id: 3,
        target: Target::Datastore(DatastoreTarget {
            datastore: DatastoreName::Operational,
            selection: DatastoreSelectionFilterObjects::WithInSubscription(
                DatastoreFilterSpec::Xpath(DatastoreXPathFilter {
                    namespaces: Box::new([]), /* no namespace prefixes declared for
                                               * "openconfig-platform" */
                    path: "openconfig-platform:components/component/state".into(),
                }),
            ),
        }),
        stop_time: None,
        dscp: Some(0),
        weighting: None,
        dependency: None,
        transport: None,
        encoding: Some(Encoding::Json),
        purpose: None,
        configured_subscription_state: None,
        message_publisher_id: None,
        update_trigger: Some(UpdateTrigger::Periodic {
            period: Some(CentiSeconds::new(360000)),
            anchor_time: Some(
                DateTime::parse_from_rfc3339("2025-01-01T00:00:30+00:00")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        }),
        module_version: Some(
            vec![
                YangPushModuleVersion::new("ietf-interfaces".into(), None, None),
                YangPushModuleVersion::new(
                    "example-module1".into(),
                    Some("2024-01-01".into()),
                    None,
                ),
                YangPushModuleVersion::new("example-module2".into(), None, Some("2.0.0".into())),
                YangPushModuleVersion::new(
                    "example-module3".into(),
                    Some("2024-02-02".into()),
                    Some("3.0.0".into()),
                ),
            ]
            .into_boxed_slice(),
        ),
        yang_library_content_id: Some("123".into()),
    };

    test_xml_value(input_by_value, expected_by_value)
        .expect("subscription by-reference round-trip failed");
}

#[test]
fn test_yang_push_module_version_json_serde() {
    let json_legacy = serde_json::json!({
        "module-name": "ietf-interfaces",
        "revision": "2014-05-08",
        "revision-label": "2.0.0",
    });

    let json_value = serde_json::json!({
        "name": "ietf-interfaces",
        "revision": "2014-05-08",
        "version": "2.0.0",
    });

    let modeled = YangPushModuleVersion {
        name: "ietf-interfaces".into(),
        revision: Some("2014-05-08".into()),
        version: Some("2.0.0".into()),
    };

    let serialized = serde_json::to_value(&modeled).unwrap();
    assert_eq!(serialized, json_value);

    let deserialized: YangPushModuleVersion = serde_json::from_value(json_legacy).unwrap();
    assert_eq!(deserialized, modeled);

    let deserialized: YangPushModuleVersion = serde_json::from_value(json_value).unwrap();
    assert_eq!(deserialized, modeled);
}

/// A prefix with no `xmlns` binding declared equals the module name.
#[test]
fn test_datastore_xpath_filter_path_prefixes_module_name_prefix() {
    let filter = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: "example-procmem-oper:processes-memory/nodes/node/process-ids/process-id".into(),
    };
    assert_eq!(filter.path_prefixes(), vec!["example-procmem-oper"]);
}

/// Distinct prefixes across a multi-module path are returned sorted.
#[test]
fn test_datastore_xpath_filter_path_prefixes_multi_module_are_sorted() {
    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            ("a".into(), "urn:example:yang:example-a".into()),
            ("b".into(), "urn:example:yang:example-b".into()),
        ]),
        path: "/b:root/b:child/b:leaf/a:sibling".into(),
    };
    assert_eq!(filter.path_prefixes(), vec!["a", "b"]);
}

/// Unprefixed (default-namespace) steps contribute no prefixes.
#[test]
fn test_datastore_xpath_filter_path_prefixes_unprefixed_steps_are_empty() {
    let filter = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: "/interfaces/interface/state/counters".into(),
    };
    assert!(filter.path_prefixes().is_empty());
}

/// A declared `xmlns` binding and an undeclared, module-name-as-prefix
/// encoding of the same target must converge onto the same canonical form.
#[test]
fn test_datastore_xpath_filter_normalize_path_converges_declared_and_undeclared_prefixes() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:example:yang:example-debug" => Some("example-debug".into()),
            _ => None,
        }
    };

    let declared = DatastoreXPathFilter {
        namespaces: Box::new([("debug".into(), "urn:example:yang:example-debug".into())]),
        path: "/debug:debug/debug:board-state".into(),
    };
    let undeclared = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: "/example-debug:debug/board-state".into(),
    };
    let canonical = "/example-debug:debug/board-state";
    assert_eq!(declared.normalize_path(resolve).as_deref(), Some(canonical));
    assert_eq!(
        undeclared.normalize_path(resolve).as_deref(),
        Some(canonical),
    );
}

/// Normalizing an already-canonical form yields itself.
#[test]
fn test_datastore_xpath_filter_normalize_path_is_idempotent() {
    let resolve = |_: &str| -> Option<Box<str>> { None };
    let canonical = "/example-debug:debug/board-state";
    let already = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: canonical.into(),
    };
    assert_eq!(already.normalize_path(resolve).as_deref(), Some(canonical));
}

/// A module-qualifying prefix is only emitted when the module changes.
#[test]
fn test_datastore_xpath_filter_normalize_path_multi_module_emits_prefix_only_on_change() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:example:yang:example-a" => Some("example-a".into()),
            "urn:example:yang:example-b" => Some("example-b".into()),
            _ => None,
        }
    };

    let multi = DatastoreXPathFilter {
        namespaces: Box::new([
            ("a".into(), "urn:example:yang:example-a".into()),
            ("b".into(), "urn:example:yang:example-b".into()),
        ]),
        path: "/a:root/a:child/a:leaf/b:sibling".into(),
    };
    assert_eq!(
        multi.normalize_path(resolve).as_deref(),
        Some("/example-a:root/child/leaf/example-b:sibling"),
    );
}

/// With no `xmlns` binding declared, an undeclared prefix is itself the
/// module name (the base XPath context), and a relative path is made
/// absolute.
#[test]
fn test_datastore_xpath_filter_normalize_path_module_name_prefix_is_made_absolute() {
    let resolve = |_: &str| -> Option<Box<str>> { None };

    let relative = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: "example-oper:processes/process/pids/pid".into(),
    };
    let canonical = "/example-oper:processes/process/pids/pid";
    assert_eq!(relative.normalize_path(resolve).as_deref(), Some(canonical));

    // An already-absolute equivalent normalizes identically.
    let absolute = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: canonical.into(),
    };
    assert_eq!(absolute.normalize_path(resolve).as_deref(), Some(canonical));
}

/// A predicate's own prefix is resolved the same as a step's: dropped
/// entirely when it matches the enclosing step's module (redundant, per RFC
/// 7950 §6.4.1 unprefixed-name-inherits-context-node rule), and a '/' inside
/// the predicate's value must not be mistaken for a path separator.
#[test]
fn test_datastore_xpath_filter_normalize_path_drops_redundant_predicate_prefix() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:example:yang:example-debug" => Some("example-debug".into()),
            _ => None,
        }
    };

    let with_pred = DatastoreXPathFilter {
        namespaces: Box::new([("debug".into(), "urn:example:yang:example-debug".into())]),
        path: "/debug:debug/debug:board-state[debug:id='1/2']".into(),
    };
    assert_eq!(
        with_pred.normalize_path(resolve).as_deref(),
        Some("/example-debug:debug/board-state[id='1/2']"),
    );
}

/// A predicate prefix that resolves to a *different* module than the
/// enclosing step is canonicalized to the resolved module name, not dropped.
#[test]
fn test_datastore_xpath_filter_normalize_path_predicate_prefix_different_module_is_canonicalized() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            "urn:example:oper-ext" => Some("example-oper-ext".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            (
                "if".into(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            ),
            ("ext".into(), "urn:example:oper-ext".into()),
        ]),
        path: "/if:interfaces/if:interface[ext:tag='x']".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/ietf-interfaces:interfaces/interface[example-oper-ext:tag='x']"),
    );
}

/// A predicate prefix with a declared `xmlns` binding whose namespace cannot
/// be resolved to a module bails (`None`), same as an unresolvable step
/// prefix.
#[test]
fn test_datastore_xpath_filter_normalize_path_unresolvable_predicate_prefix_bails() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            (
                "if".into(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            ),
            ("unknown".into(), "urn:unresolvable".into()),
        ]),
        path: "/if:interfaces/if:interface[unknown:name='eth0']".into(),
    };
    assert_eq!(filter.normalize_path(resolve), None);
}

/// A fully-prefix-qualified, multi-step path where the predicate's prefix
/// is the same module as the enclosing step and must be dropped, same as
/// the outer steps' redundant prefixes are dropped.
#[test]
fn test_datastore_xpath_filter_normalize_path_sub_303_redundant_predicate_prefix() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:6wind:vrouter" => Some("vrouter".into()),
            "urn:6wind:vrouter/interface" => Some("vrouter-interface".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            ("vrouter".into(), "urn:6wind:vrouter".into()),
            ("vrouter-interface".into(), "urn:6wind:vrouter/interface".into()),
        ]),
        path: "/vrouter:state/vrouter:vrf/vrouter-interface:interface/vrouter-interface:physical[vrouter-interface:name='ens192']/vrouter-interface:oper-status".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/vrouter:state/vrf/vrouter-interface:interface/physical[name='ens192']/oper-status"),
    );
}

/// A declared prefix whose namespace cannot be resolved bails (`None`).
#[test]
fn test_datastore_xpath_filter_normalize_path_unresolvable_prefix_bails() {
    let resolve = |_: &str| -> Option<Box<str>> { None };

    let unresolvable = DatastoreXPathFilter {
        namespaces: Box::new([("x".into(), "urn:unknown".into())]),
        path: "/x:foo/x:bar".into(),
    };
    assert_eq!(unresolvable.normalize_path(resolve), None);
}

/// Unsupported XPath constructs bail (`None`); the caller keeps the original.
#[test]
fn test_datastore_xpath_filter_normalize_path_unsupported_constructs_bail() {
    let resolve = |_: &str| -> Option<Box<str>> { None };

    // some unsupported xpath examples
    for path in [
        "count(/if:interfaces) > 0",
        "/a:x | /b:y",
        "descendant::if:name",
    ] {
        let f = DatastoreXPathFilter {
            namespaces: Box::new([]),
            path: path.into(),
        };
        assert_eq!(f.normalize_path(resolve), None, "should bail for `{path}`");
    }
}

/// Instantiated (real key value) predicate containing '/' must not be
/// mistaken for a path separator.
#[test]
fn test_datastore_xpath_filter_normalize_path_instantiated_predicate_with_slash() {
    let resolve = |_: &str| -> Option<Box<str>> { None };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path: "openconfig-interfaces:interfaces/interface[name='TenGigE0/0/0/14']".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/openconfig-interfaces:interfaces/interface[name='TenGigE0/0/0/14']"),
    );
}

/// A nested (multi-step) predicate path with a module-qualified identityref
/// value; both are preserved verbatim.
#[test]
fn test_datastore_xpath_filter_normalize_path_instantiated_predicate_with_nested_path() {
    let resolve = |_: &str| -> Option<Box<str>> { None };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([]),
        path:
            "openconfig-interfaces:interfaces/interface[state/type='iana-if-type:ethernetCsmacd']"
                .into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some(
            "/openconfig-interfaces:interfaces/interface[state/type='iana-if-type:ethernetCsmacd']"
        ),
    );
}

/// A declared `xmlns` binding combined with an instantiated predicate value:
/// the predicate's own `if:` prefix resolves to the same module
/// (`ietf-interfaces`) as the enclosing `interface` step, so it's dropped.
#[test]
fn test_datastore_xpath_filter_normalize_path_declared_namespace_with_instantiated_predicate() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([(
            "if".into(),
            "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
        )]),
        path: "/if:interfaces/if:interface[if:name='GigabitEthernet0/0/0']".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/ietf-interfaces:interfaces/interface[name='GigabitEthernet0/0/0']"),
    );
}

/// A binding declared only for a predicate literal's whole-QName value
/// doesn't affect the location path's module tracking, but the literal is
/// still resolved/rewritten independently. The predicate's own, non-literal
/// `if:type` prefix is resolved/dropped as usual.
#[test]
fn test_datastore_xpath_filter_normalize_path_declared_namespace_binding_in_predicate_literal() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            "urn:ietf:params:xml:ns:yang:iana-if-type" => Some("iana-if-type".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            (
                "if".into(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            ),
            (
                "iana-if-type".into(),
                "urn:ietf:params:xml:ns:yang:iana-if-type".into(),
            ),
        ]),
        path: "/if:interfaces/if:interface[if:type='iana-if-type:ethernetCsmacd']".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/ietf-interfaces:interfaces/interface[type='iana-if-type:ethernetCsmacd']"),
    );
}

/// A whole-QName predicate literal whose prefix differs from the resolved
/// module name (`hw-hwt` → `huawei-hardware-types`) is rewritten to the full
/// module name, not left as the original prefix.
#[test]
fn test_datastore_xpath_filter_normalize_path_predicate_literal_prefix_differs_from_module() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-hardware" => Some("ietf-hardware".into()),
            "urn:huawei:yang:huawei-hardware" => Some("huawei-hardware".into()),
            "urn:huawei:yang:huawei-hardware-types" => Some("huawei-hardware-types".into()),
            "urn:bbf:yang:bbf-hardware-transceivers" => Some("bbf-hardware-transceivers".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            ("hw".into(), "urn:ietf:params:xml:ns:yang:ietf-hardware".into()),
            ("hw-hw".into(), "urn:huawei:yang:huawei-hardware".into()),
            ("hw-hwt".into(), "urn:huawei:yang:huawei-hardware-types".into()),
            (
                "bbf-hw-xcvr".into(),
                "urn:bbf:yang:bbf-hardware-transceivers".into(),
            ),
        ]),
        path: "/hw:hardware/hw:component[hw-hw:sub-class='hw-hwt:ethernetCsmacd-xcvr-link']/bbf-hw-xcvr:transceiver-link".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some(
            "/ietf-hardware:hardware/component[huawei-hardware:sub-class='huawei-hardware-types:ethernetCsmacd-xcvr-link']/bbf-hardware-transceivers:transceiver-link"
        ),
    );
}

/// A whole-QName predicate literal at the very end of the path (no
/// trailing step after `]`) is still resolved.
#[test]
fn test_datastore_xpath_filter_normalize_path_predicate_literal_at_end_of_path() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            "urn:ietf:params:xml:ns:yang:iana-if-type" => Some("iana-if-type".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            (
                "if".into(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            ),
            (
                "ianaift".into(),
                "urn:ietf:params:xml:ns:yang:iana-if-type".into(),
            ),
        ]),
        path: "/if:interfaces/if:interface[if:type='ianaift:gpon']".into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some("/ietf-interfaces:interfaces/interface[type='iana-if-type:gpon']"),
    );
}

/// Two predicates in the same path. The first has a whole-QName literal
/// that gets rewritten (`ianahw:sensor` → `iana-hardware:sensor`); the
/// second is a plain literal with no ':' (`'rpm'`) and stays untouched.
/// Both predicates' node-name prefixes resolve to their enclosing step's
/// module and are dropped.
#[test]
fn test_datastore_xpath_filter_normalize_path_multiple_predicates_mixed_literal_and_plain() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-hardware" => Some("ietf-hardware".into()),
            "urn:ietf:params:xml:ns:yang:iana-hardware" => Some("iana-hardware".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            ("hw".into(), "urn:ietf:params:xml:ns:yang:ietf-hardware".into()),
            (
                "ianahw".into(),
                "urn:ietf:params:xml:ns:yang:iana-hardware".into(),
            ),
        ]),
        path: "/hw:hardware/hw:component[hw:class='ianahw:sensor']/hw:sensor-data[hw:value-type='rpm']"
            .into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some(
            "/ietf-hardware:hardware/component[class='iana-hardware:sensor']/sensor-data[value-type='rpm']"
        ),
    );
}

/// A multi-module path (a step from an augmenting module mid-path) combined
/// with an instantiated predicate value containing both '/' and ':'; the
/// predicate's `if:` prefix resolves to the same module as the enclosing
/// `interface` step and is dropped, while the following `ext:` step (a
/// different module) keeps its prefix as usual.
#[test]
fn test_datastore_xpath_filter_normalize_path_multi_module_with_instantiated_predicate() {
    let resolve = |uri: &str| -> Option<Box<str>> {
        match uri {
            "urn:ietf:params:xml:ns:yang:ietf-interfaces" => Some("ietf-interfaces".into()),
            "urn:example:oper-ext" => Some("example-oper-ext".into()),
            _ => None,
        }
    };

    let filter = DatastoreXPathFilter {
        namespaces: Box::new([
            (
                "if".into(),
                "urn:ietf:params:xml:ns:yang:ietf-interfaces".into(),
            ),
            ("ext".into(), "urn:example:oper-ext".into()),
        ]),
        path: "/if:interfaces/if:interface[if:name='TenGigE0/0/0/14']/ext:oper-status-detail"
            .into(),
    };
    assert_eq!(
        filter.normalize_path(resolve).as_deref(),
        Some(
            "/ietf-interfaces:interfaces/interface[name='TenGigE0/0/0/14']/example-oper-ext:oper-status-detail"
        ),
    );
}
