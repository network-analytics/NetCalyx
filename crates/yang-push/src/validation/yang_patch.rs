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

//! Validation of YANG-Push `push-change-update` notifications whose
//! yang-patch edit values are checked against their edit target.

use tracing::trace;
use yang6::context::Context;
use yang6::data::{DataFormat, DataParserFlags, DataTree, DataValidationFlags};
use yang6::schema::SchemaPathFormat;

/// Root of the `ietf-yp-notification:envelope` in a bare UDP-Notif payload.
pub const ENVELOPE_ROOT: &str = "";

/// Root of the `ietf-yp-notification:envelope` in an
/// `ietf-telemetry-message:message`.
pub const TELEMETRY_MESSAGE_ROOT: &str = "/ietf-telemetry-message:message/payload";

const EVENT_TIME_POINTER: &str = "/ietf-yp-notification:envelope/event-time";
const EDITS_POINTER: &str = "/ietf-yp-notification:envelope/contents/ietf-yang-push:push-change-update/datastore-changes/yang-patch/edit";

/// The yang-patch edit whose `value` failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedEdit {
    edit_id: String,
    target: String,
    anchor: Option<String>,
}

impl FailedEdit {
    pub fn edit_id(&self) -> &str {
        &self.edit_id
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn anchor(&self) -> Option<&str> {
        self.anchor.as_deref()
    }
}

/// Validation error, with the failing edit when an edit value was rejected.
#[derive(Debug)]
pub struct YangPatchValidationError {
    pub error: yang6::Error,
    pub failed_edit: Option<Box<FailedEdit>>,
}

impl From<yang6::Error> for YangPatchValidationError {
    fn from(error: yang6::Error) -> Self {
        Self {
            error,
            failed_edit: None,
        }
    }
}

fn validation_error(msg: String) -> yang6::Error {
    yang6::Error {
        msg: Some(msg),
        ..Default::default()
    }
}

/// Validate a payload carrying a push-change-update in two steps, since a
/// schema anchor only applies to one anydata per parse: first the payload
/// with all edit values stripped, then each value in a minimal envelope whose
/// `contents` is anchored at the edit target.
///
/// `envelope_root` is the JSON pointer to the object holding the
/// `ietf-yp-notification:envelope` (e.g. [`ENVELOPE_ROOT`] or
/// [`TELEMETRY_MESSAGE_ROOT`]). Payloads without yang-patch edits at that
/// location are validated as a whole in a single parse.
pub fn validate_change_update(
    yang_ctx: &Context,
    payload: &[u8],
    parser_flags: DataParserFlags,
    envelope_root: &str,
) -> Result<(), YangPatchValidationError> {
    let parse = |data: &[u8], anchor: Option<&str>| {
        match anchor {
            Some(anchor) => DataTree::parse_string_with_anchor(
                yang_ctx,
                data,
                DataFormat::JSON,
                DataParserFlags::from_bits_truncate(parser_flags.bits()),
                DataValidationFlags::PRESENT,
                anchor,
            ),
            None => DataTree::parse_string(
                yang_ctx,
                data,
                DataFormat::JSON,
                DataParserFlags::from_bits_truncate(parser_flags.bits()),
                DataValidationFlags::PRESENT,
            ),
        }
        .map(|_| ())
    };

    let Ok(mut message) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Ok(parse(payload, None)?);
    };
    let event_time = message
        .pointer(&format!("{envelope_root}{EVENT_TIME_POINTER}"))
        .cloned();
    let edits = message
        .pointer_mut(&format!("{envelope_root}{EDITS_POINTER}"))
        .and_then(serde_json::Value::as_array_mut);
    let (Some(event_time), Some(edits)) = (event_time, edits) else {
        return Ok(parse(payload, None)?);
    };
    let values: Vec<(String, String, serde_json::Value)> = edits
        .iter_mut()
        .filter_map(|edit| {
            let edit = edit.as_object_mut()?;
            let value = edit.remove("value")?;
            let field = |name: &str| {
                edit.get(name)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            Some((field("edit-id"), field("target"), value))
        })
        .collect();

    let skeleton = serde_json::to_vec(&message).map_err(|err| validation_error(err.to_string()))?;
    parse(&skeleton, None)?;

    for (edit_id, target, value) in values {
        let failed = |error: yang6::Error, anchor: Option<String>| YangPatchValidationError {
            error,
            failed_edit: Some(Box::new(FailedEdit {
                edit_id: edit_id.clone(),
                target: target.clone(),
                anchor,
            })),
        };
        let anchor = resolve_edit_anchor(yang_ctx, &target).map_err(|err| failed(err, None))?;
        trace!(
            edit_id,
            edit_target = target,
            edit_anchor = anchor.as_deref(),
            "Validating yang-patch edit value against its target anchor"
        );
        let carrier = serde_json::json!({
            "ietf-yp-notification:envelope": {
                "event-time": event_time.clone(),
                "contents": value,
            }
        });
        let carrier = serde_json::to_vec(&carrier)
            .map_err(|err| failed(validation_error(err.to_string()), anchor.clone()))?;
        parse(&carrier, anchor.as_deref()).map_err(|err| failed(err, anchor))?;
    }
    Ok(())
}

/// Schema path of a yang-patch edit target, `None` for the datastore root.
fn resolve_edit_anchor(yang_ctx: &Context, target: &str) -> Result<Option<String>, yang6::Error> {
    if target == "/" {
        return Ok(None);
    }
    // yang6 panics on interior NUL bytes when building the C string.
    if target.contains('\0') {
        return Err(validation_error(
            "yang-patch edit target contains a NUL byte".to_string(),
        ));
    }
    let nodes = yang_ctx.find_xpath(target)?.collect::<Vec<_>>();
    match nodes.as_slice() {
        [node] => Ok(Some(node.path(SchemaPathFormat::DATA))),
        _ => Err(validation_error(format!(
            "yang-patch edit target \"{target}\" does not resolve to a single schema node"
        ))),
    }
}

#[cfg(test)]
mod tests;
