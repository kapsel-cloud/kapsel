//! Fixed MCP stdio transport for the one KAP-0038 application request.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt,
    io::{BufRead as _, Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use kapsel::{
    AgentRequest, Application, ApplicationError, GatewayError, OperationReport, OperationResult,
    OperationState, TargetRejection,
};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};

use crate::command;

const PROTOCOL_VERSION: &str = "2025-11-25";
const MESSAGE_BYTES_MAX: u64 = 16 * 1024;
const RESPONSE_BYTES_MAX: usize = 8 * 1024;
const REQUEST_ID_BYTES_MAX: usize = 128;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Uninitialized,
    Initializing,
    Ready,
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
struct CallParams {
    name: String,
    arguments: Value,
    #[serde(rename = "_meta")]
    _metadata: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolArguments {
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(String::from(value))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            values.insert(key, map.next_value::<UniqueValue>()?.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

pub(crate) fn run(mut arguments: impl Iterator<Item = OsString>) -> ExitCode {
    let Some(flag) = arguments.next() else {
        return startup_failure("command_input", 2);
    };
    let Some(operator_path) = arguments.next() else {
        return startup_failure("command_input", 2);
    };
    if flag != "--operator-config" || arguments.next().is_some() {
        return startup_failure("command_input", 2);
    }
    let runtime = match command::runtime("mcp") {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "{}", error.diagnostic());
            return ExitCode::from(error.exit_code());
        },
    };
    let application = match runtime.block_on(command::open_application(
        &PathBuf::from(operator_path),
        "mcp",
    )) {
        Ok(application) => application,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "{}", error.diagnostic());
            return ExitCode::from(error.exit_code());
        },
    };
    serve(&runtime, application)
}

fn startup_failure(class: &str, exit: u8) -> ExitCode {
    let _ = writeln!(std::io::stderr().lock(), "Kapsel MCP failure: {class}");
    ExitCode::from(exit)
}

fn serve(runtime: &tokio::runtime::Runtime, mut application: Application) -> ExitCode {
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut output = std::io::stdout().lock();
    let mut phase = Phase::Uninitialized;
    loop {
        let mut bytes = Vec::new();
        let Ok(read) = input
            .by_ref()
            .take(MESSAGE_BYTES_MAX + 1)
            .read_until(b'\n', &mut bytes)
        else {
            return startup_failure("transport", 4);
        };
        if read == 0 {
            return ExitCode::SUCCESS;
        }
        if u64::try_from(bytes.len()).map_or(true, |length| length > MESSAGE_BYTES_MAX) {
            return startup_failure("message_too_large", 2);
        }
        if bytes.last() != Some(&b'\n') {
            return startup_failure("incomplete_message", 2);
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let Ok(value) = serde_json::from_slice::<UniqueValue>(&bytes) else {
            if write_response(
                &mut output,
                error_response(Value::Null, -32700, "Parse error"),
            )
            .is_err()
            {
                return ExitCode::from(4);
            }
            continue;
        };
        let value = value.0;
        let id_present = value
            .as_object()
            .is_some_and(|object| object.contains_key("id"));
        let envelope_id = valid_request_id(
            value
                .as_object()
                .and_then(|object| object.get("id"))
                .cloned(),
        )
        .unwrap_or(Value::Null);
        let Ok(message) = serde_json::from_value::<Message>(value) else {
            if write_response(
                &mut output,
                error_response(envelope_id, -32600, "Invalid Request"),
            )
            .is_err()
            {
                return ExitCode::from(4);
            }
            continue;
        };
        let response = dispatch(message, id_present, &mut phase, runtime, &mut application);
        if let Some(response) = response {
            if write_response(&mut output, response).is_err() {
                return ExitCode::from(4);
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed protocol lifecycle and sole dispatch surface stay visible together"
)]
fn dispatch(
    message: Message,
    id_present: bool,
    phase: &mut Phase,
    runtime: &tokio::runtime::Runtime,
    application: &mut Application,
) -> Option<Value> {
    let request_id = message.id.clone();
    if id_present && valid_request_id(request_id.clone()).is_none() {
        return Some(error_response(Value::Null, -32600, "Invalid Request"));
    }
    if message.jsonrpc != "2.0" {
        return Some(error_response(
            request_id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        ));
    }
    if !id_present
        && !matches!(
            message.method.as_str(),
            "notifications/initialized" | "notifications/cancelled"
        )
    {
        return None;
    }
    match message.method.as_str() {
        "initialize" => {
            let Some(id) = valid_request_id(request_id) else {
                return Some(error_response(Value::Null, -32600, "Invalid Request"));
            };
            if *phase != Phase::Uninitialized || !valid_initialize_params(message.params.as_ref()) {
                return Some(error_response(id, -32600, "Invalid Request"));
            }
            *phase = Phase::Initializing;
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "kapsel",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }))
        },
        "notifications/initialized" => {
            if id_present {
                Some(error_response(
                    request_id.unwrap_or(Value::Null),
                    -32600,
                    "Invalid Request",
                ))
            } else if *phase != Phase::Initializing
                || !metadata_only_params(message.params.as_ref())
            {
                None
            } else {
                *phase = Phase::Ready;
                None
            }
        },
        "notifications/cancelled" if !id_present => None,
        "notifications/cancelled" => Some(error_response(
            request_id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        )),
        "tools/list" => {
            let Some(id) = valid_request_id(request_id) else {
                return Some(error_response(Value::Null, -32600, "Invalid Request"));
            };
            if *phase != Phase::Ready {
                return Some(error_response(id, -32600, "Invalid Request"));
            }
            if !metadata_only_params(message.params.as_ref()) {
                return Some(error_response(id, -32602, "Invalid params"));
            }
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": [tool_definition()]}
            }))
        },
        "tools/call" => {
            let Some(id) = valid_request_id(request_id) else {
                return Some(error_response(Value::Null, -32600, "Invalid Request"));
            };
            if *phase != Phase::Ready {
                return Some(error_response(id, -32600, "Invalid Request"));
            }
            let Some(params) = message.params else {
                return Some(error_response(id, -32602, "Invalid params"));
            };
            let Ok(call) = serde_json::from_value::<CallParams>(params) else {
                return Some(error_response(id, -32602, "Invalid params"));
            };
            if call.name != "kubernetes.set_deployment_image" {
                return Some(error_response(id, -32602, "Invalid params"));
            }
            let Ok(arguments) = serde_json::from_value::<ToolArguments>(call.arguments) else {
                return Some(error_response(id, -32602, "Invalid params"));
            };
            let request = AgentRequest {
                operation_id: arguments.operation_id,
                namespace: arguments.namespace,
                deployment: arguments.deployment,
                container: arguments.container,
                immutable_image_digest: arguments.immutable_image_digest,
            };
            Some(match runtime.block_on(application.execute(&request)) {
                Ok(report) => call_result(id, render_report(&report), false),
                Err(error) if request_rejected(&error) => call_result(
                    id,
                    String::from(r#"{"status":"ERROR","error_class":"request_rejected"}"#),
                    true,
                ),
                Err(_) => call_result(
                    id,
                    String::from(r#"{"status":"ERROR","error_class":"operation_failure"}"#),
                    true,
                ),
            })
        },
        _ if !id_present => None,
        _ => Some(error_response(
            request_id.unwrap_or(Value::Null),
            -32601,
            "Method not found",
        )),
    }
}

fn valid_request_id(id: Option<Value>) -> Option<Value> {
    id.filter(|value| {
        value
            .as_str()
            .is_some_and(|text| text.len() <= REQUEST_ID_BYTES_MAX)
            || value.is_number()
    })
}

fn valid_initialize_params(params: Option<&Value>) -> bool {
    let Some(object) = params.and_then(Value::as_object) else {
        return false;
    };
    let keys_are_known = object.keys().all(|key| {
        matches!(
            key.as_str(),
            "protocolVersion" | "capabilities" | "clientInfo" | "_meta"
        )
    });
    keys_are_known
        && object.get("protocolVersion").is_some_and(Value::is_string)
        && object.get("capabilities").is_some_and(Value::is_object)
        && object.get("clientInfo").is_some_and(|value| {
            value.as_object().is_some_and(|implementation| {
                implementation.get("name").is_some_and(Value::is_string)
                    && implementation.get("version").is_some_and(Value::is_string)
            })
        })
        && object.get("_meta").is_none_or(Value::is_object)
}

fn metadata_only_params(params: Option<&Value>) -> bool {
    params.is_none_or(|params| {
        params.as_object().is_some_and(|object| {
            object.is_empty()
                || (object.len() == 1 && object.get("_meta").is_some_and(Value::is_object))
        })
    })
}

fn tool_definition() -> Value {
    json!({
        "name": "kubernetes.set_deployment_image",
        "description": "Request one authorized immutable Kubernetes Deployment image change.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "operation_id": {
                    "type": "string", "minLength": 1, "maxLength": 128,
                    "pattern": "^[A-Za-z0-9._:-]+$"
                },
                "namespace": {
                    "type": "string", "minLength": 1, "maxLength": 63,
                    "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                },
                "deployment": {"type": "string", "minLength": 1, "maxLength": 253},
                "container": {
                    "type": "string", "minLength": 1, "maxLength": 63,
                    "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                },
                "immutable_image_digest": {
                    "type": "string", "minLength": 1, "maxLength": 512
                }
            },
            "required": [
                "operation_id", "namespace", "deployment", "container",
                "immutable_image_digest"
            ],
            "additionalProperties": false
        }
    })
}

fn request_rejected(error: &ApplicationError) -> bool {
    matches!(
        error,
        ApplicationError::Gateway(
            GatewayError::InvalidInput(_) | GatewayError::AuthorizationMismatch
        )
    )
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the protocol result takes ownership of its request ID and bounded text"
)]
fn call_result(id: Value, text: String, is_error: bool) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error
        }
    })
}

fn render_report(report: &OperationReport) -> String {
    let operation_id = json_text(&report.operation_id);
    let result = report.result.map_or_else(
        || String::from("null"),
        |value| json_text(operation_result(value)),
    );
    let rejection = report.target_rejection.map_or_else(
        || String::from("null"),
        |value| json_text(target_rejection(value)),
    );
    let (receipt_file, receipt_digest) = report.receipt.as_ref().map_or_else(
        || (String::from("null"), String::from("null")),
        |receipt| {
            let file = receipt
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .map_or_else(|| String::from("null"), json_text);
            (file, json_text(&receipt.digest))
        },
    );
    format!(
        concat!(
            "{{\"operation_id\":{operation_id},\"state\":\"{state}\",",
            "\"result\":{result},\"target_rejection\":{rejection},",
            "\"receipt_file\":{receipt_file},\"receipt_sha256\":{receipt_digest}}}"
        ),
        operation_id = operation_id,
        state = operation_state(report.state),
        result = result,
        rejection = rejection,
        receipt_file = receipt_file,
        receipt_digest = receipt_digest
    )
}

fn json_text(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("null"))
}

const fn operation_state(state: OperationState) -> &'static str {
    match state {
        OperationState::Requested => "REQUESTED",
        OperationState::Authorized => "AUTHORIZED",
        OperationState::NotAttempted => "NOT_ATTEMPTED",
        OperationState::ApplyStarted => "APPLY_STARTED",
        OperationState::ReceiverObserved => "RECEIVER_OBSERVED",
        OperationState::ReceiptPrepared => "RECEIPT_PREPARED",
        OperationState::ReceiptWritten => "RECEIPT_WRITTEN",
        OperationState::Finalized => "FINALIZED",
    }
}

const fn operation_result(result: OperationResult) -> &'static str {
    match result {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn target_rejection(rejection: TargetRejection) -> &'static str {
    match rejection {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the protocol response takes ownership of the echoed request ID"
)]
fn error_response(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "a response is serialized once and discarded after the bounded write"
)]
fn write_response(output: &mut impl std::io::Write, response: Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(&response)?;
    if bytes
        .len()
        .checked_add(1)
        .is_none_or(|length| length > RESPONSE_BYTES_MAX)
    {
        return Err(std::io::Error::other("bounded MCP response exceeded"));
    }
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.flush()
}
