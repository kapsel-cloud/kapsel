//! ID-only MCP stdio bridge to the authenticated local resident service.

use std::{
    collections::BTreeSet,
    fmt,
    io::{BufRead as _, Read as _, Write as _},
    process::ExitCode,
};

use kapsel::{ExecutionCondition, ExecutionDisposition};
use kapsel_daemon::client_transport;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

const PROTOCOL: &str = "2025-11-25";
const INPUT_MAX: u64 = 16 * 1024;
const OUTPUT_MAX: usize = 96 * 1024;

#[cfg(test)]
#[path = "../../tests/fixtures/service_wire.rs"]
mod wire_vectors;

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Unique(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Unique(json!(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Unique(json!(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(|number| Unique(Value::Number(number)))
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Unique(json!(value)))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Unique(json!(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<Unique>()? {
            values.push(value.0);
        }
        Ok(Unique(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        let mut fields = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            fields.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(fields)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    arguments: Value,
    #[serde(rename = "_meta")]
    metadata: Option<Map<String, Value>>,
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the response constructor accepts the completed request's owned JSON-RPC ID"
)]
fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the response constructor accepts owned envelope values from completed dispatch"
)]
fn result(id: Value, value: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":value})
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the tool response consumes the completed service exchange's owned JSON value"
)]
fn tool_result(id: Value, operation_id: &Value, service: Value, failed: bool) -> Value {
    let text = json!({"operation_id":operation_id,"service":service}).to_string();
    result(
        id,
        json!({"content":[{"type":"text","text":text}],"isError":failed}),
    )
}

fn valid_id(id: &Value) -> bool {
    id.is_number() || id.as_str().is_some_and(|s| s.len() <= 128)
}

fn metadata_only(params: Option<&Value>) -> bool {
    params.is_none_or(|p| {
        p.as_object().is_some_and(|o| {
            o.is_empty() || (o.len() == 1 && o.get("_meta").is_some_and(Value::is_object))
        })
    })
}

fn identity(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|s| kapsel_authority::identity_is_valid(s))
}

fn tools() -> Value {
    let cursor_schema = json!({"type":"object","properties":{"after":{"type":["string","null"],
        "maxLength":128}},"required":["after"],"additionalProperties":false});
    let operation_id_schema = json!({"type":"object","properties":{"operation_id":{"type":"string",
        "minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},
        "required":["operation_id"],"additionalProperties":false});
    json!({"tools":[
        {"name":"kapsel.list_approved_actions",
         "description":"Read operator-approved handles.","inputSchema":cursor_schema},
        {"name":"kapsel.list_operation_history",
         "description":"Read retained operation history.","inputSchema":cursor_schema},
        {"name":"kapsel.get_status",
         "description":"Read stored status without advancing.","inputSchema":operation_id_schema},
        {"name":"kapsel.get_receipt",
         "description":"Read original signed receipt bytes and digest.",
         "inputSchema":operation_id_schema},
        {"name":"kapsel.submit",
         "description":"Explicitly submit or resume the same operation ID.",
         "inputSchema":operation_id_schema}
    ]})
}

fn receipt_valid(value: &Value) -> bool {
    let (Some(hex), Some(digest)) = (
        value.get("receipt_hex").and_then(Value::as_str),
        value.get("receipt_sha256").and_then(Value::as_str),
    ) else {
        return false;
    };
    if hex.len() > 64 * 1024
        || hex.len() % 2 != 0
        || digest.len() != 64
        || !hex
            .bytes()
            .chain(digest.bytes())
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return false;
    }

    let decode = |text: &str| {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap_or(0);
                let low = (pair[1] as char).to_digit(16).unwrap_or(0);
                u8::try_from(high * 16 + low).unwrap_or(0)
            })
            .collect::<Vec<_>>()
    };
    let bytes = decode(hex);
    let expected_digest = decode(digest);
    Sha256::digest(bytes).as_slice() == expected_digest
}

fn exact(fields: &Map<String, Value>, keys: &[&str]) -> bool {
    fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key))
}

fn string_field(fields: &Map<String, Value>, key: &str) -> bool {
    fields.get(key).is_some_and(Value::is_string)
}

fn nullable_target(value: Option<&Value>, partial_observation: bool) -> bool {
    value.is_some_and(|value| {
        value.is_null()
            || value.as_object().is_some_and(|target| {
                exact(target, &["uid", "resource_version"])
                    && ["uid", "resource_version"].iter().all(|field| {
                        target.get(*field).is_some_and(|value| {
                            value.is_string() || (partial_observation && value.is_null())
                        })
                    })
            })
    })
}

fn execution_disposition(fields: &Map<String, Value>) -> Option<ExecutionDisposition> {
    let condition = fields.get("condition")?;
    match fields.get("disposition")?.as_str()? {
        "active" if condition.is_null() => Some(ExecutionDisposition::Active),
        "waiting_for_worker" if condition.is_null() => Some(ExecutionDisposition::WaitingForWorker),
        "resume_required" => match condition.as_str() {
            None if condition.is_null() => Some(ExecutionDisposition::ResumeRequired(None)),
            Some("preflight_unavailable") => Some(ExecutionDisposition::ResumeRequired(Some(
                ExecutionCondition::PreflightUnavailable,
            ))),
            Some("worker_contention") => Some(ExecutionDisposition::ResumeRequired(Some(
                ExecutionCondition::WorkerContention,
            ))),
            _ => None,
        },
        "operator_required" => match condition.as_str()? {
            "receiver_unavailable" => Some(ExecutionDisposition::OperatorRequired(
                ExecutionCondition::ReceiverUnavailable,
            )),
            "signing_unavailable" => Some(ExecutionDisposition::OperatorRequired(
                ExecutionCondition::SigningUnavailable,
            )),
            "completion_blocked" => Some(ExecutionDisposition::OperatorRequired(
                ExecutionCondition::CompletionBlocked,
            )),
            "operation_blocked" => Some(ExecutionDisposition::OperatorRequired(
                ExecutionCondition::OperationBlocked,
            )),
            _ => None,
        },
        "complete" if condition.is_null() => Some(ExecutionDisposition::Complete),
        "admission_unconfirmed" if condition.is_null() => {
            Some(ExecutionDisposition::AdmissionUnconfirmed)
        },
        _ => None,
    }
}

fn execution_shape(value: &Value, status: &str) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let Some(disposition) = execution_disposition(fields) else {
        return false;
    };
    exact(
        fields,
        &["disposition", "condition", "next_action", "action_owner"],
    ) && fields.get("disposition").and_then(Value::as_str) == Some(disposition.as_str())
        && fields.get("next_action").and_then(Value::as_str) == Some(disposition.next_action())
        && fields.get("action_owner").and_then(Value::as_str) == Some(disposition.action_owner())
        && match status {
            "NOT_FOUND" => disposition == ExecutionDisposition::AdmissionUnconfirmed,
            "IN_PROGRESS" => !matches!(
                disposition,
                ExecutionDisposition::Complete | ExecutionDisposition::AdmissionUnconfirmed
            ),
            "NOT_ATTEMPTED" | "SUCCEEDED" | "FAILED" | "UNKNOWN" => {
                disposition == ExecutionDisposition::Complete
            },
            _ => false,
        }
}

fn target_rejection(effect: &str, value: Option<&Value>) -> bool {
    matches!(
        (effect, value.and_then(Value::as_str)),
        (
            "kubernetes.set_deployment_image",
            Some(
                "DEPLOYMENT_NOT_FOUND"
                    | "CONTAINER_NOT_FOUND"
                    | "INVALID_TARGET"
                    | "STALE_APPROVAL"
            ),
        ) | (
            "git.transition_ref",
            Some("GIT_STALE_REF" | "GIT_INVALID_OBJECTS")
        )
    )
}

fn git_targets(value: Option<&Value>) -> bool {
    let Some(fields) = value.and_then(Value::as_object) else {
        return false;
    };
    let acknowledgement = fields.get("acknowledgement").is_some_and(|value| {
        value.is_null()
            || matches!(
                value.as_str(),
                Some("updated" | "rejected_before_send" | "receiver_rejected" | "unknown")
            )
    });
    let observed_ref = fields.get("observed_ref").is_some_and(|value| {
        value.is_null()
            || value.as_object().is_some_and(|fields| {
                exact(fields, &["kind", "commit"])
                    && match fields.get("kind").and_then(Value::as_str) {
                        Some("commit") => fields.get("commit").is_some_and(Value::is_string),
                        Some("missing" | "unknown") => {
                            fields.get("commit").is_some_and(Value::is_null)
                        },
                        _ => false,
                    }
            })
    });
    exact(
        fields,
        &[
            "repository_id",
            "reference",
            "old_commit",
            "new_commit",
            "attempted",
            "acknowledgement",
            "observed_ref",
        ],
    ) && string_field(fields, "repository_id")
        && string_field(fields, "reference")
        && string_field(fields, "old_commit")
        && string_field(fields, "new_commit")
        && fields.get("attempted").is_some_and(Value::is_boolean)
        && acknowledgement
        && observed_ref
}

fn status_shape(value: &Value, with_version: bool, with_operation_id: bool) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    if with_version && fields.get("version") != Some(&json!(1)) {
        return false;
    }
    if with_operation_id && fields.get("operation_id").and_then(identity).is_none() {
        return false;
    }
    let Some(status) = fields.get("status").and_then(Value::as_str) else {
        return false;
    };
    if status == "ERROR" {
        let mut keys = vec!["status", "error_class"];
        if with_version {
            keys.push("version");
        }
        if with_operation_id {
            keys.push("operation_id");
        }
        return exact(fields, &keys)
            && matches!(
                fields.get("error_class").and_then(Value::as_str),
                Some("invalid_request" | "authority_unavailable" | "operation_failure")
            );
    }
    if !execution_shape(fields.get("execution").unwrap_or(&Value::Null), status) {
        return false;
    }
    let mut base = vec!["status", "execution"];
    if with_version {
        base.push("version");
    }
    if with_operation_id {
        base.push("operation_id");
    }
    match status {
        "NOT_FOUND" => exact(fields, &base),
        "IN_PROGRESS" | "NOT_ATTEMPTED" | "SUCCEEDED" | "FAILED" | "UNKNOWN" => {
            let has_rejection = status == "NOT_ATTEMPTED";
            if has_rejection {
                base.push("target_rejection");
            }
            let Some(effect) = fields.get("effect").and_then(Value::as_str) else {
                return false;
            };
            if has_rejection && !target_rejection(effect, fields.get("target_rejection")) {
                return false;
            }
            match effect {
                "kubernetes.set_deployment_image" => {
                    base.extend([
                        "effect",
                        "approved_target",
                        "attempt_target",
                        "observed_target",
                    ]);
                    exact(fields, &base)
                        && nullable_target(fields.get("approved_target"), false)
                        && nullable_target(fields.get("attempt_target"), false)
                        && nullable_target(fields.get("observed_target"), true)
                },
                "git.transition_ref" => {
                    base.extend(["effect", "git"]);
                    exact(fields, &base) && git_targets(fields.get("git"))
                },
                _ => false,
            }
        },
        _ => false,
    }
}

fn response_shape(name: &str, value: &Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    if fields.get("version") != Some(&json!(1)) {
        return false;
    }
    let Some(status) = fields.get("status").and_then(Value::as_str) else {
        return false;
    };
    if status == "ERROR" {
        return exact(fields, &["version", "status", "error_class"])
            && matches!(
                fields.get("error_class").and_then(Value::as_str),
                Some("invalid_request" | "authority_unavailable" | "operation_failure")
            );
    }
    match name {
        "kapsel.submit" => match status {
            "ADMITTED" => {
                exact(fields, &["version", "status", "phase"])
                    && matches!(
                        fields.get("phase").and_then(Value::as_str),
                        Some(
                            "requested"
                                | "authorized"
                                | "not_attempted"
                                | "apply_started"
                                | "receiver_observed"
                                | "finalized"
                        )
                    )
            },
            "NOT_ADMITTED" => {
                exact(fields, &["version", "status", "reason"])
                    && matches!(
                        fields.get("reason").and_then(Value::as_str),
                        Some("BUSY" | "CAPACITY")
                    )
            },
            "INDETERMINATE" => exact(fields, &["version", "status"]),
            _ => false,
        },
        "kapsel.get_receipt" => match status {
            "READY" => {
                exact(
                    fields,
                    &["version", "status", "receipt_hex", "receipt_sha256"],
                ) && receipt_valid(value)
            },
            "NOT_FOUND" | "NOT_READY" => exact(fields, &["version", "status"]),
            _ => false,
        },
        "kapsel.list_approved_actions" => {
            status == "READY"
                && exact(fields, &["version", "status", "entries", "next_cursor"])
                && fields
                    .get("entries")
                    .and_then(Value::as_array)
                    .is_some_and(|entries| {
                        entries.len() <= 8
                            && entries
                                .iter()
                                .all(|entry| entry.get("operation_id").and_then(identity).is_some())
                    })
                && fields
                    .get("next_cursor")
                    .is_some_and(|cursor| cursor.is_null() || identity(cursor).is_some())
        },
        "kapsel.list_operation_history" => {
            status == "READY"
                && exact(fields, &["version", "status", "entries", "next_cursor"])
                && fields
                    .get("entries")
                    .and_then(Value::as_array)
                    .is_some_and(|entries| {
                        entries.len() <= 8
                            && entries.iter().all(|entry| status_shape(entry, false, true))
                    })
                && fields
                    .get("next_cursor")
                    .is_some_and(|cursor| cursor.is_null() || identity(cursor).is_some())
        },
        "kapsel.get_status" => status_shape(value, true, false),
        _ => false,
    }
}

fn decode_call(params: Option<Value>) -> Option<(String, Value)> {
    let call = serde_json::from_value::<Call>(params?).ok()?;
    let _ = call.metadata;
    let arguments = call.arguments.as_object()?;
    let request = match call.name.as_str() {
        "kapsel.list_approved_actions" | "kapsel.list_operation_history"
            if arguments.len() == 1 =>
        {
            let after = match arguments.get("after") {
                Some(Value::Null) => Value::Null,
                Some(cursor) if identity(cursor).is_some() => cursor.clone(),
                _ => return None,
            };
            let request_name = if call.name == "kapsel.list_approved_actions" {
                "list_approved_actions"
            } else {
                "list_operation_history"
            };
            json!({"version":1,"request":request_name,"after":after})
        },
        "kapsel.get_status" | "kapsel.get_receipt" | "kapsel.submit" if arguments.len() == 1 => {
            let operation_id = arguments.get("operation_id").and_then(identity)?;
            let request_name = match call.name.as_str() {
                "kapsel.get_status" => "get_set_deployment_image_status",
                "kapsel.get_receipt" => "get_set_deployment_image_receipt",
                _ => "submit_set_deployment_image",
            };
            json!({"version":1,"request":request_name,"operation_id":operation_id})
        },
        _ => return None,
    };
    Some((call.name, request))
}

fn call(id: Value, params: Option<Value>) -> Value {
    let Some((name, request)) = decode_call(params) else {
        return error(id, -32602, "Invalid params");
    };

    #[cfg(feature = "test-harness")]
    let test_socket = std::env::var("KAPSELD_TEST_CLIENT_SOCKET").ok();
    #[cfg(feature = "test-harness")]
    let socket = test_socket.as_deref().unwrap_or(client_transport::SOCKET);
    #[cfg(not(feature = "test-harness"))]
    let socket = client_transport::SOCKET;
    let operation_id = request.get("operation_id").cloned().unwrap_or(Value::Null);
    let request_bytes = serde_json::to_vec(&request).unwrap_or_default();
    let response_bytes = match client_transport::exchange(socket, &request_bytes) {
        Ok((bytes, _status)) => bytes,
        Err(error) => {
            let class = if matches!(error, client_transport::Error::Response) {
                "response_invalid"
            } else {
                "service_exchange_uncertain"
            };
            return tool_result(
                id,
                &operation_id,
                json!({"status":"ERROR","error_class":class}),
                true,
            );
        },
    };

    let Ok(Unique(value)) = serde_json::from_slice::<Unique>(&response_bytes) else {
        return tool_result(
            id,
            &operation_id,
            json!({"status":"ERROR","error_class":"response_invalid"}),
            true,
        );
    };
    let failed = value.get("status").and_then(Value::as_str) == Some("ERROR");
    if !response_shape(&name, &value) {
        return tool_result(
            id,
            &operation_id,
            json!({"status":"ERROR","error_class":"response_invalid"}),
            true,
        );
    }

    // Bind the caller-selected identity to the unchanged service facts. The JSON-RPC ID
    // identifies only the transport request, not the durable operation.
    tool_result(id, &operation_id, value, failed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakePhase {
    AwaitingInitialize,
    AwaitingInitialized,
    Ready,
}

fn dispatch(
    message: Message,
    has_request_id: bool,
    handshake_phase: &mut HandshakePhase,
) -> Option<Value> {
    let id = message.id.unwrap_or(Value::Null);
    if (has_request_id && !valid_id(&id)) || message.jsonrpc != "2.0" {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    if !has_request_id
        && !matches!(
            message.method.as_str(),
            "notifications/initialized" | "notifications/cancelled"
        )
    {
        return None;
    }
    match message.method.as_str() {
        "initialize" if has_request_id => {
            let parameters = message.params.as_ref().and_then(Value::as_object);
            if *handshake_phase != HandshakePhase::AwaitingInitialize
                || !parameters.is_some_and(|fields| {
                    fields.keys().all(|key| {
                        matches!(
                            key.as_str(),
                            "protocolVersion" | "capabilities" | "clientInfo" | "_meta"
                        )
                    }) && fields.get("protocolVersion").is_some_and(Value::is_string)
                        && fields.get("capabilities").is_some_and(Value::is_object)
                        && fields.get("clientInfo").is_some_and(|client_info| {
                            client_info.get("name").is_some_and(Value::is_string)
                                && client_info.get("version").is_some_and(Value::is_string)
                        })
                        && fields.get("_meta").is_none_or(Value::is_object)
                })
            {
                return Some(error(id, -32600, "Invalid Request"));
            }
            *handshake_phase = HandshakePhase::AwaitingInitialized;
            Some(result(
                id,
                json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                "serverInfo":{"name":"kapsel-service","version":env!("CARGO_PKG_VERSION")}}),
            ))
        },
        "notifications/initialized" if !has_request_id => {
            if *handshake_phase == HandshakePhase::AwaitingInitialized
                && metadata_only(message.params.as_ref())
            {
                *handshake_phase = HandshakePhase::Ready;
            }
            None
        },
        "notifications/initialized" | "notifications/cancelled" => {
            Some(error(id, -32600, "Invalid Request"))
        },
        "tools/list" | "tools/call" if has_request_id => {
            if *handshake_phase != HandshakePhase::Ready {
                return Some(error(id, -32600, "Invalid Request"));
            }
            if message.method == "tools/list" {
                if !metadata_only(message.params.as_ref()) {
                    return Some(error(id, -32602, "Invalid params"));
                }
                Some(result(id, tools()))
            } else {
                Some(call(id, message.params))
            }
        },
        _ if !has_request_id => None,
        _ => Some(error(id, -32601, "Method not found")),
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if let Some(arg) = args.next() {
        if args.len() == 0 && arg == "--help" {
            let _ =
                writeln!(std::io::stdout(),
                "kapsel-service-mcp: ID-only resident service bridge\nUsage: kapsel-service-mcp");
            return ExitCode::SUCCESS;
        }
        if args.len() == 0 && arg == "--version" {
            let _ = writeln!(
                std::io::stdout(),
                "kapsel-service-mcp {}",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        let _ = writeln!(std::io::stderr(), "kapsel-service-mcp: invalid_usage");
        return ExitCode::from(2);
    }

    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut output = std::io::stdout().lock();
    let mut handshake_phase = HandshakePhase::AwaitingInitialize;
    loop {
        let mut bytes = Vec::new();
        let Ok(bytes_read) = input
            .by_ref()
            .take(INPUT_MAX + 1)
            .read_until(b'\n', &mut bytes)
        else {
            return ExitCode::from(4);
        };
        if bytes_read == 0 {
            return ExitCode::SUCCESS;
        }
        if bytes.len() as u64 > INPUT_MAX || bytes.last() != Some(&b'\n') {
            return ExitCode::from(2);
        }

        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }

        let response = match serde_json::from_slice::<Unique>(&bytes) {
            Ok(Unique(value)) => {
                let has_request_id = value.as_object().is_some_and(|o| o.contains_key("id"));
                let envelope_id = value
                    .get("id")
                    .filter(|id| valid_id(id))
                    .cloned()
                    .unwrap_or(Value::Null);
                #[allow(
                    clippy::option_if_let_else,
                    reason = "explicit branches separate dispatch from invalid envelopes"
                )]
                match serde_json::from_value::<Message>(value) {
                    Ok(message) => dispatch(message, has_request_id, &mut handshake_phase),
                    Err(_) => Some(error(envelope_id, -32600, "Invalid Request")),
                }
            },
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };

        if let Some(response) = response {
            let Ok(mut line) = serde_json::to_vec(&response) else {
                return ExitCode::from(4);
            };
            line.push(b'\n');
            if line.len() > OUTPUT_MAX
                || output.write_all(&line).is_err()
                || output.flush().is_err()
            {
                return ExitCode::from(4);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "independent frozen grammar fixtures")]
    use super::*;

    #[test]
    fn discovery_advertises_only_the_pinned_id_or_cursor_schemas() {
        let value = tools();
        assert_eq!(value.as_object().unwrap().len(), 1);
        let advertised = value["tools"].as_array().unwrap();
        assert_eq!(advertised.len(), wire_vectors::COMMANDS.len());
        for (name, _, field) in wire_vectors::COMMANDS {
            let tool = advertised.iter().find(|tool| tool["name"] == name).unwrap();
            let schema = if field == "after" {
                json!({"type":"object","properties":{"after":{"type":["string","null"],
                    "maxLength":128}},"required":["after"],"additionalProperties":false})
            } else {
                json!({"type":"object","properties":{"operation_id":{"type":"string",
                    "minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},
                    "required":["operation_id"],"additionalProperties":false})
            };
            assert_eq!(tool["inputSchema"], schema, "{name}");
        }
    }

    #[test]
    fn call_partitions_bind_the_five_tools_without_transport() {
        assert!(decode_call(None).is_none());
        for (tool, command, field) in wire_vectors::COMMANDS {
            for value in [json!("op-1"), json!("x".repeat(128)), Value::Null] {
                let params = json!({"name":tool,"arguments":{field:value},"_meta":{}});
                if field == "operation_id" && value.is_null() {
                    assert!(decode_call(Some(params)).is_none());
                } else {
                    assert_eq!(
                        decode_call(Some(params)),
                        Some((
                            tool.into(),
                            json!({"version":1,"request":command,field:value})
                        ))
                    );
                }
            }
            let valid = json!({"name":tool,"arguments":{field:"op-1"}});
            assert!(decode_call(Some(valid.clone())).is_some());
            for bad in [json!(true), json!("../outside"), json!("x".repeat(129))] {
                let mut changed = valid.clone();
                changed["arguments"][field] = bad;
                assert!(decode_call(Some(changed)).is_none());
            }
            for pointer in ["", "/arguments"] {
                let fields = valid.pointer(pointer).unwrap().as_object().unwrap();
                for field in fields.keys() {
                    let mut changed = valid.clone();
                    changed
                        .pointer_mut(pointer)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(field);
                    assert!(decode_call(Some(changed)).is_none());
                }
                let mut changed = valid.clone();
                changed.pointer_mut(pointer).unwrap()["grant"] = json!("caller-appointed");
                assert!(decode_call(Some(changed)).is_none());
            }
            let mut changed = valid;
            changed["name"] = json!("kapsel.execute");
            assert!(decode_call(Some(changed)).is_none());
        }
    }

    #[test]
    fn unique_json_rejects_duplicates_at_each_depth_including_escaped_aliases() {
        for bytes in [
            br#"{"id":1,"id":2}"#.as_slice(),
            br#"{"params":{"name":"a","\u006eame":"b"}}"#,
            br#"{"params":{"arguments":{"operation_id":"a","operation_id":"b"}}}"#,
            br#"{"entries":[{"uid":"a","uid":"b"}]}"#,
        ] {
            assert!(serde_json::from_slice::<Unique>(bytes).is_err());
        }
        assert!(serde_json::from_slice::<Unique>(
            br#"{"id":1,"params":{"arguments":{"\u006fperation_id":"op-1"}}}"#
        )
        .is_ok());
    }

    #[test]
    fn execution_grammar_accepts_only_the_pinned_wire_partitions() {
        let dispositions: BTreeSet<_> = wire_vectors::GUIDANCE
            .iter()
            .map(|v| v.0)
            .chain(["surprise"])
            .collect();
        let conditions: BTreeSet<_> = wire_vectors::GUIDANCE
            .iter()
            .map(|v| v.1)
            .chain([Some("surprise")])
            .collect();
        let actions: BTreeSet<_> = wire_vectors::GUIDANCE
            .iter()
            .map(|v| v.2)
            .chain(["surprise"])
            .collect();
        for status in [
            "NOT_FOUND",
            "IN_PROGRESS",
            "NOT_ATTEMPTED",
            "SUCCEEDED",
            "FAILED",
            "UNKNOWN",
        ] {
            for &disposition in &dispositions {
                for &condition in &conditions {
                    for &action in &actions {
                        for owner in ["caller", "operator", "surprise"] {
                            let tuple = (disposition, condition, action, owner);
                            let allowed = match status {
                                "NOT_FOUND" => tuple == wire_vectors::GUIDANCE[10],
                                "IN_PROGRESS" => wire_vectors::GUIDANCE[..9].contains(&tuple),
                                _ => tuple == wire_vectors::GUIDANCE[9],
                            };
                            let value = json!({"disposition":disposition,"condition":condition,
                                "next_action":action,"action_owner":owner});
                            assert_eq!(
                                execution_shape(&value, status),
                                allowed,
                                "{status} {value}"
                            );
                        }
                    }
                }
            }
        }
        for value in [
            Value::Null,
            json!([]),
            json!({"disposition":"active","condition":null,
            "next_action":"wait","action_owner":"caller","extra":true}),
        ] {
            assert!(!execution_shape(&value, "IN_PROGRESS"));
        }
    }

    fn status(effect: &str) -> Value {
        let history: Value = serde_json::from_str(wire_vectors::HISTORY).unwrap();
        let mut value = history["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["effect"] == effect)
            .unwrap()
            .clone();
        value.as_object_mut().unwrap().remove("operation_id");
        value["version"] = json!(1);
        value
    }

    fn reject_missing_and_extra_members(value: &Value, prefix: &str) {
        let fields = value.pointer(prefix).unwrap().as_object().unwrap();
        for field in fields.keys() {
            let mut changed = value.clone();
            changed
                .pointer_mut(prefix)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                !response_shape("kapsel.get_status", &changed),
                "missing {prefix}/{field}"
            );
        }
        let mut changed = value.clone();
        changed.pointer_mut(prefix).unwrap()["extra"] = json!(true);
        assert!(
            !response_shape("kapsel.get_status", &changed),
            "extra at {prefix}"
        );
    }

    #[test]
    fn effect_and_history_shapes_bind_every_member_at_the_decoder() {
        for effect in ["kubernetes.set_deployment_image", "git.transition_ref"] {
            let original = status(effect);
            assert!(response_shape("kapsel.get_status", &original));
            reject_missing_and_extra_members(&original, "");
            reject_missing_and_extra_members(&original, "/execution");
            if effect == "git.transition_ref" {
                reject_missing_and_extra_members(&original, "/git");
                reject_missing_and_extra_members(&original, "/git/observed_ref");
            } else {
                reject_missing_and_extra_members(&original, "/approved_target");
            }
            let history: Value = serde_json::from_str(wire_vectors::HISTORY).unwrap();
            assert!(response_shape("kapsel.list_operation_history", &history));
            for rejection in [
                "STALE_APPROVAL",
                "GIT_STALE_REF",
                "GIT_INVALID_OBJECTS",
                "stale_approval",
            ] {
                let mut rejected = original.clone();
                rejected["status"] = json!("NOT_ATTEMPTED");
                rejected["target_rejection"] = json!(rejection);
                rejected["execution"] = json!({"disposition":"complete","condition":null,
                    "next_action":"inspect_result","action_owner":"caller"});
                let expected = if effect == "git.transition_ref" {
                    matches!(rejection, "GIT_STALE_REF" | "GIT_INVALID_OBJECTS")
                } else {
                    rejection == "STALE_APPROVAL"
                };
                assert_eq!(response_shape("kapsel.get_status", &rejected), expected);
            }
        }
        for (pointer, bad) in [
            ("/git/acknowledgement", json!("surprise")),
            ("/git/observed_ref/kind", json!("tag")),
            ("/git/attempted", json!(1)),
        ] {
            let mut changed = status("git.transition_ref");
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(!response_shape("kapsel.get_status", &changed));
        }
        for field in ["approved_target", "attempt_target", "observed_target"] {
            for uid in [Value::Null, json!("uid-1"), json!(true), json!(7)] {
                for version in [Value::Null, json!("11"), json!([])] {
                    let mut changed = status("kubernetes.set_deployment_image");
                    changed[field] = json!({"uid":uid,"resource_version":version});
                    let allowed = (uid.is_string()
                        || (field == "observed_target" && uid.is_null()))
                        && (version.is_string()
                            || (field == "observed_target" && version.is_null()));
                    assert_eq!(
                        response_shape("kapsel.get_status", &changed),
                        allowed,
                        "{changed}"
                    );
                }
            }
            let mut changed = status("kubernetes.set_deployment_image");
            changed[field] = json!({"uid":"uid-1"});
            assert!(!response_shape("kapsel.get_status", &changed));
            changed[field] = Value::Null;
            assert!(response_shape("kapsel.get_status", &changed));
        }
    }

    #[test]
    fn admission_requires_an_exact_versioned_decision() {
        for (value, expected) in [
            (
                json!({"version":1,"status":"ADMITTED","phase":"authorized"}),
                true,
            ),
            (
                json!({"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}),
                true,
            ),
            (json!({"version":1,"status":"ADMITTED"}), false),
            (
                json!({"version":1,"status":"ADMITTED","phase":"surprise"}),
                false,
            ),
            (json!({"version":1,"status":"NOT_ADMITTED"}), false),
            (json!({"status":"ADMITTED","phase":"authorized"}), false),
            (
                json!({"version":2,"status":"ADMITTED","phase":"authorized"}),
                false,
            ),
            (
                json!({"version":1.0,"status":"ADMITTED","phase":"authorized"}),
                false,
            ),
            (
                json!({"version":1,"status":"ACCEPTED","phase":"authorized"}),
                false,
            ),
        ] {
            assert_eq!(response_shape("kapsel.submit", &value), expected, "{value}");
        }
    }

    #[test]
    fn receipt_reply_preserves_exact_hex_and_independently_pinned_digest() {
        let original: Value = serde_json::from_str(wire_vectors::RECEIPT).unwrap();
        assert!(response_shape("kapsel.get_receipt", &original));
        for (field, bad) in [
            ("receipt_hex", json!("616264")),
            ("receipt_hex", json!("61626")),
            ("receipt_hex", json!("AB")),
            ("receipt_hex", json!(false)),
            ("receipt_sha256", json!("0".repeat(64))),
            ("receipt_sha256", json!("0".repeat(63))),
            ("extra", json!(true)),
        ] {
            let mut changed = original.clone();
            changed[field] = bad;
            assert!(!response_shape("kapsel.get_receipt", &changed), "{field}");
        }
    }
}
