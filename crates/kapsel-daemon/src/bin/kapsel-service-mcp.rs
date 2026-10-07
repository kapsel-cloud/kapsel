//! ID-only MCP stdio bridge to the authenticated local resident service.
#![allow(
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    reason = "fixed JSON-RPC envelopes transfer owned values"
)]

use std::{
    collections::BTreeSet,
    fmt,
    io::{BufRead as _, Read as _, Write as _},
};

use kapsel_daemon::client_transport;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

const PROTOCOL: &str = "2025-11-25";
const INPUT_MAX: u64 = 16 * 1024;
const OUTPUT_MAX: usize = 96 * 1024;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate keys")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Unique(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Unique>()? {
            out.push(v.0);
        }
        Ok(Unique(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        let mut out = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if !keys.insert(k.clone()) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            out.insert(k, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(out)))
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
    metadata: Option<serde_json::Map<String, Value>>,
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn result(id: Value, value: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":value})
}
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
    let cursor = json!({"type":"object","properties":{"after":{"type":["string","null"],
        "maxLength":128}},"required":["after"],"additionalProperties":false});
    let id = json!({"type":"object","properties":{"operation_id":{"type":"string",
        "minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},
        "required":["operation_id"],"additionalProperties":false});
    json!({"tools":[
        {"name":"kapsel.list_approved_actions",
         "description":"Read operator-approved handles.","inputSchema":cursor},
        {"name":"kapsel.list_operation_history",
         "description":"Read retained operation history.","inputSchema":cursor},
        {"name":"kapsel.get_status",
         "description":"Read stored status without advancing.","inputSchema":id},
        {"name":"kapsel.get_receipt",
         "description":"Read original signed receipt bytes and digest.","inputSchema":id},
        {"name":"kapsel.submit",
         "description":"Explicitly submit or resume the same operation ID.","inputSchema":id}
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
    let expected = decode(digest);
    Sha256::digest(bytes).as_slice() == expected
}
fn response_shape(name: &str, value: &Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let Some(status) = fields.get("status").and_then(Value::as_str) else {
        return false;
    };
    let exact = |keys: &[&str]| {
        fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key))
    };
    if status == "ERROR" {
        return exact(&["version", "status", "error_class"])
            && matches!(
                fields.get("error_class").and_then(Value::as_str),
                Some("invalid_request" | "authority_unavailable" | "operation_failure")
            );
    }
    match name {
        "kapsel.submit" => match status {
            "ADMITTED" => {
                exact(&["version", "status", "phase"])
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
                exact(&["version", "status", "reason"])
                    && matches!(
                        fields.get("reason").and_then(Value::as_str),
                        Some("BUSY" | "CAPACITY")
                    )
            },
            "INDETERMINATE" => exact(&["version", "status"]),
            _ => false,
        },
        "kapsel.get_receipt" => match status {
            "READY" => {
                exact(&["version", "status", "receipt_hex", "receipt_sha256"])
                    && receipt_valid(value)
            },
            "NOT_FOUND" | "NOT_READY" => exact(&["version", "status"]),
            _ => false,
        },
        "kapsel.list_approved_actions" | "kapsel.list_operation_history" => {
            status == "READY"
                && exact(&["version", "status", "entries", "next_cursor"])
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
        "kapsel.get_status" => {
            matches!(
                status,
                "NOT_FOUND" | "IN_PROGRESS" | "NOT_ATTEMPTED" | "SUCCEEDED" | "FAILED" | "UNKNOWN"
            ) && fields
                .get("execution")
                .and_then(Value::as_object)
                .is_some_and(|execution| {
                    execution.get("disposition").is_some_and(Value::is_string)
                        && execution.get("next_action").is_some_and(Value::is_string)
                        && execution.get("action_owner").is_some_and(Value::is_string)
                        && execution.contains_key("condition")
                })
                && (status != "NOT_ATTEMPTED"
                    || fields.get("target_rejection").is_some_and(Value::is_string))
        },
        _ => false,
    }
}

fn call(id: Value, params: Option<Value>) -> Value {
    let Some(params) = params else {
        return error(id, -32602, "Invalid params");
    };
    let Ok(call) = serde_json::from_value::<Call>(params) else {
        return error(id, -32602, "Invalid params");
    };
    let _ = call.metadata;
    let Some(args) = call.arguments.as_object() else {
        return error(id, -32602, "Invalid params");
    };
    let request = match call.name.as_str() {
        "kapsel.list_approved_actions" | "kapsel.list_operation_history" if args.len() == 1 => {
            let after = match args.get("after") {
                Some(Value::Null) => Value::Null,
                Some(v) if identity(v).is_some() => v.clone(),
                _ => return error(id, -32602, "Invalid params"),
            };
            let kind = if call.name == "kapsel.list_approved_actions" {
                "list_approved_actions"
            } else {
                "list_operation_history"
            };
            json!({"version":1,"request":kind,"after":after})
        },
        "kapsel.get_status" | "kapsel.get_receipt" | "kapsel.submit" if args.len() == 1 => {
            let Some(op) = args.get("operation_id").and_then(identity) else {
                return error(id, -32602, "Invalid params");
            };
            let kind = match call.name.as_str() {
                "kapsel.get_status" => "get_set_deployment_image_status",
                "kapsel.get_receipt" => "get_set_deployment_image_receipt",
                _ => "submit_set_deployment_image",
            };
            json!({"version":1,"request":kind,"operation_id":op})
        },
        _ => return error(id, -32602, "Invalid params"),
    };
    #[cfg(feature = "test-harness")]
    let test_socket = std::env::var("KAPSELD_TEST_CLIENT_SOCKET").ok();
    #[cfg(feature = "test-harness")]
    let socket = test_socket.as_deref().unwrap_or(client_transport::SOCKET);
    #[cfg(not(feature = "test-harness"))]
    let socket = client_transport::SOCKET;
    let operation_id = request.get("operation_id").cloned().unwrap_or(Value::Null);
    let bytes = serde_json::to_vec(&request).unwrap_or_default();
    let bytes = match client_transport::exchange(socket, &bytes) {
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
    let Ok(Unique(value)) = serde_json::from_slice::<Unique>(&bytes) else {
        return tool_result(
            id,
            &operation_id,
            json!({"status":"ERROR","error_class":"response_invalid"}),
            true,
        );
    };
    let failed = value.get("status").and_then(Value::as_str) == Some("ERROR");
    if !response_shape(&call.name, &value) {
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
fn dispatch(message: Message, present: bool, phase: &mut u8) -> Option<Value> {
    let id = message.id.unwrap_or(Value::Null);
    if (present && !valid_id(&id)) || message.jsonrpc != "2.0" {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    if !present
        && !matches!(
            message.method.as_str(),
            "notifications/initialized" | "notifications/cancelled"
        )
    {
        return None;
    }
    match message.method.as_str() {
        "initialize" if present => {
            let p = message.params.as_ref().and_then(Value::as_object);
            if *phase != 0
                || !p.is_some_and(|p| {
                    p.keys().all(|k| {
                        matches!(
                            k.as_str(),
                            "protocolVersion" | "capabilities" | "clientInfo" | "_meta"
                        )
                    }) && p.get("protocolVersion").is_some_and(Value::is_string)
                        && p.get("capabilities").is_some_and(Value::is_object)
                        && p.get("clientInfo").is_some_and(|v| {
                            v.get("name").is_some_and(Value::is_string)
                                && v.get("version").is_some_and(Value::is_string)
                        })
                        && p.get("_meta").is_none_or(Value::is_object)
                })
            {
                return Some(error(id, -32600, "Invalid Request"));
            }
            *phase = 1;
            Some(result(
                id,
                json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                "serverInfo":{"name":"kapsel-service","version":env!("CARGO_PKG_VERSION")}}),
            ))
        },
        "notifications/initialized" if !present => {
            if *phase == 1 && metadata_only(message.params.as_ref()) {
                *phase = 2;
            }
            None
        },
        "notifications/initialized" | "notifications/cancelled" => {
            Some(error(id, -32600, "Invalid Request"))
        },
        "tools/list" | "tools/call" if present => {
            if *phase != 2 {
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
        _ if !present => None,
        _ => Some(error(id, -32601, "Method not found")),
    }
}
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    if let Some(arg) = args.next() {
        if args.len() == 0 && arg == "--help" {
            let _ =
                writeln!(std::io::stdout(),
                "kapsel-service-mcp: ID-only resident service bridge\nUsage: kapsel-service-mcp");
            return std::process::ExitCode::SUCCESS;
        }
        if args.len() == 0 && arg == "--version" {
            let _ = writeln!(
                std::io::stdout(),
                "kapsel-service-mcp {}",
                env!("CARGO_PKG_VERSION")
            );
            return std::process::ExitCode::SUCCESS;
        }
        let _ = writeln!(std::io::stderr(), "kapsel-service-mcp: invalid_usage");
        return std::process::ExitCode::from(2);
    }
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut output = std::io::stdout().lock();
    let mut phase = 0;
    loop {
        let mut bytes = Vec::new();
        let Ok(n) = input
            .by_ref()
            .take(INPUT_MAX + 1)
            .read_until(b'\n', &mut bytes)
        else {
            return std::process::ExitCode::from(4);
        };
        if n == 0 {
            return std::process::ExitCode::SUCCESS;
        }
        if bytes.len() as u64 > INPUT_MAX || bytes.last() != Some(&b'\n') {
            return std::process::ExitCode::from(2);
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let response = match serde_json::from_slice::<Unique>(&bytes) {
            Ok(Unique(value)) => {
                let present = value.as_object().is_some_and(|o| o.contains_key("id"));
                let envelope_id = value
                    .get("id")
                    .filter(|id| valid_id(id))
                    .cloned()
                    .unwrap_or(Value::Null);
                match serde_json::from_value::<Message>(value) {
                    Ok(message) => dispatch(message, present, &mut phase),
                    Err(_) => Some(error(envelope_id, -32600, "Invalid Request")),
                }
            },
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            let Ok(mut line) = serde_json::to_vec(&response) else {
                return std::process::ExitCode::from(4);
            };
            line.push(b'\n');
            if line.len() > OUTPUT_MAX
                || output.write_all(&line).is_err()
                || output.flush().is_err()
            {
                return std::process::ExitCode::from(4);
            }
        }
    }
}
