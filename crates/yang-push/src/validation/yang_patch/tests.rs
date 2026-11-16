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

use super::*;
use serde_json::{Value, json};

const INTERFACE_TARGET: &str = "/ietf-interfaces:interfaces/interface[name='eth0']";

fn load_test_yang_ctx() -> Context {
    Context::new_from_yang_library_file(
        std::path::Path::new("../../assets/yang/ietf-telemetry-message/yang-lib-full.xml"),
        DataFormat::XML,
        std::path::Path::new("../../assets/yang/ietf-telemetry-message/modules"),
        yang6::context::ContextFlags::DISABLE_SEARCHDIR_CWD,
    )
    .expect("Failed to load test YANG context")
}

fn strict_flags() -> DataParserFlags {
    DataParserFlags::STRICT | DataParserFlags::ANYDATA_STRICT
}

fn interface_value(extra: Value) -> Value {
    let mut interface = json!({
        "name": "eth0",
        "type": "iana-if-type:ethernetCsmacd",
        "enabled": true,
    });
    if let (Some(interface), Some(extra)) = (interface.as_object_mut(), extra.as_object()) {
        interface.extend(extra.clone());
    }
    json!({ "ietf-interfaces:interface": [interface] })
}

fn change_update_envelope(target: &str, value: Value) -> Value {
    json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-01-01T00:00:00Z",
            "contents": {
                "ietf-yang-push:push-change-update": {
                    "id": 1,
                    "datastore-changes": {
                        "yang-patch": {
                            "patch-id": "patch-1",
                            "edit": [{
                                "edit-id": "edit-1",
                                "operation": "replace",
                                "target": target,
                                "value": value,
                            }]
                        }
                    }
                }
            }
        }
    })
}

fn telemetry_message(payload: Value) -> Value {
    json!({
        "ietf-telemetry-message:message": {
            "telemetry-message-metadata": {
                "collection-timestamp": "2026-01-01T00:00:01Z",
                "notification-event": "log",
                "session-protocol": "yang-push",
                "export-address": "192.0.2.1",
            },
            "payload": payload,
        }
    })
}

fn validate(message: &Value, envelope_root: &str) -> Result<(), YangPatchValidationError> {
    let ctx = load_test_yang_ctx();
    let payload = serde_json::to_vec(message).expect("serializable test payload");
    validate_change_update(&ctx, &payload, strict_flags(), envelope_root)
}

#[test]
fn test_envelope_valid_edit_passes() {
    let message = change_update_envelope(INTERFACE_TARGET, interface_value(json!({})));
    validate(&message, ENVELOPE_ROOT).expect("valid edit must pass");
}

#[test]
fn test_telemetry_message_valid_edit_passes() {
    let message = telemetry_message(change_update_envelope(
        INTERFACE_TARGET,
        interface_value(json!({})),
    ));
    validate(&message, TELEMETRY_MESSAGE_ROOT).expect("valid edit must pass");
}

#[test]
fn test_telemetry_message_invalid_edit_value_reports_edit() {
    let message = telemetry_message(change_update_envelope(
        INTERFACE_TARGET,
        interface_value(json!({ "unknown-leaf": 1 })),
    ));
    let err = validate(&message, TELEMETRY_MESSAGE_ROOT).expect_err("unknown leaf must fail");
    let failed_edit = err.failed_edit.expect("failure must point to the edit");
    assert_eq!(failed_edit.edit_id(), "edit-1");
    assert_eq!(failed_edit.target(), INTERFACE_TARGET);
    assert_eq!(
        failed_edit.anchor(),
        Some("/ietf-interfaces:interfaces/interface")
    );
}

#[test]
fn test_telemetry_message_unresolvable_target_reports_edit_without_anchor() {
    let target = "/ietf-interfaces:interfaces/unknown";
    let message = telemetry_message(change_update_envelope(target, interface_value(json!({}))));
    let err = validate(&message, TELEMETRY_MESSAGE_ROOT).expect_err("bad target must fail");
    let failed_edit = err.failed_edit.expect("failure must point to the edit");
    assert_eq!(failed_edit.target(), target);
    assert_eq!(failed_edit.anchor(), None);
}

/// With the wrong root the edits are not found, so the whole message is
/// parsed at once and the edit value cannot be resolved as top-level data.
#[test]
fn test_telemetry_message_with_envelope_root_fails() {
    let message = telemetry_message(change_update_envelope(
        INTERFACE_TARGET,
        interface_value(json!({})),
    ));
    let err = validate(&message, ENVELOPE_ROOT).expect_err("unanchored edit value must fail");
    assert!(err.failed_edit.is_none());
}

#[test]
fn test_telemetry_message_without_edits_validated_as_whole() {
    let message = telemetry_message(json!({
        "ietf-yp-notification:envelope": {
            "event-time": "2026-01-01T00:00:00Z",
            "contents": {
                "ietf-yang-push:push-update": {
                    "id": 1,
                    "datastore-contents": {
                        "ietf-interfaces:interfaces": {
                            "interface": [{
                                "name": "eth0",
                                "type": "iana-if-type:ethernetCsmacd",
                            }]
                        }
                    }
                }
            }
        }
    }));
    validate(&message, TELEMETRY_MESSAGE_ROOT).expect("push-update must pass");
}
