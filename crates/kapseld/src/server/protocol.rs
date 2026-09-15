//! Pure fixed service grammar, validation projection, response bytes and frame limits.

use kapsel::{
    ServiceAdmission, ServiceError, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    TargetRejection,
};
use kapsel_authority::identity_is_valid;
use serde::Deserialize;

pub(super) const REQUEST_BYTES_MAX: usize = 16 * 1024;
const ORDINARY_RESPONSE_BYTES_MAX: usize = 16 * 1024;
const RECEIPT_RESPONSE_BYTES_MAX: usize = 40 * 1024;

#[derive(Clone, Copy)]
pub(super) enum SubmissionAdmission {
    Decided(ServiceAdmission),
    Indeterminate,
    Error(ServiceError),
}

#[derive(Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
enum Request {
    #[serde(rename = "list_approved_actions")]
    List {
        version: u8,
        after: serde_json::Value,
    },
    #[serde(rename = "list_operation_history")]
    History {
        version: u8,
        after: serde_json::Value,
    },
    #[serde(rename = "get_set_deployment_image_status")]
    Status { version: u8, operation_id: String },
    #[serde(rename = "get_set_deployment_image_receipt")]
    Receipt { version: u8, operation_id: String },
    #[serde(rename = "submit_set_deployment_image")]
    Submit { version: u8, operation_id: String },
}

#[derive(Clone, Copy)]
pub(super) enum ResponseClass {
    Ordinary,
    Receipt,
}

pub(super) enum Command {
    Read(ReadRequest),
    Submit(String),
}

pub(super) enum ReadRequest {
    List(Option<String>),
    History(Option<String>),
    Status(String),
    Receipt(String),
}

pub(super) fn request_length(prefix: [u8; 4]) -> Option<usize> {
    let length = usize::try_from(u32::from_be_bytes(prefix)).ok()?;
    (length > 0 && length <= REQUEST_BYTES_MAX).then_some(length)
}

pub(super) fn decode(bytes: &[u8]) -> Option<Command> {
    if bytes.is_empty()
        || bytes.len() > REQUEST_BYTES_MAX
        || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return None;
    }
    let cursor = |after: serde_json::Value| match after {
        serde_json::Value::Null => Some(None),
        serde_json::Value::String(id) if identity_is_valid(&id) => Some(Some(id)),
        _ => None,
    };
    match serde_json::from_slice::<Request>(bytes).ok()? {
        Request::List { version: 1, after } => {
            Some(Command::Read(ReadRequest::List(cursor(after)?)))
        },
        Request::History { version: 1, after } => {
            Some(Command::Read(ReadRequest::History(cursor(after)?)))
        },
        Request::Status {
            version: 1,
            operation_id,
        } if identity_is_valid(&operation_id) => {
            Some(Command::Read(ReadRequest::Status(operation_id)))
        },
        Request::Receipt {
            version: 1,
            operation_id,
        } if identity_is_valid(&operation_id) => {
            Some(Command::Read(ReadRequest::Receipt(operation_id)))
        },
        Request::Submit {
            version: 1,
            operation_id,
        } if identity_is_valid(&operation_id) => Some(Command::Submit(operation_id)),
        _ => None,
    }
}

pub(super) fn response_length_allowed(length: usize, class: ResponseClass) -> bool {
    let maximum = match class {
        ResponseClass::Ordinary => ORDINARY_RESPONSE_BYTES_MAX,
        ResponseClass::Receipt => RECEIPT_RESPONSE_BYTES_MAX,
    };
    length > 0 && length <= maximum && u32::try_from(length).is_ok()
}

pub(super) fn render_submission(admission: SubmissionAdmission) -> Vec<u8> {
    match admission {
        SubmissionAdmission::Decided(ServiceAdmission::Admitted(phase)) => format!(
            "{{\"version\":1,\"status\":\"ADMITTED\",\"phase\":\"{}\"}}",
            phase_name(phase)
        )
        .into_bytes(),
        SubmissionAdmission::Decided(ServiceAdmission::Busy) => {
            br#"{"version":1,"status":"NOT_ADMITTED","reason":"BUSY"}"#.to_vec()
        },
        SubmissionAdmission::Decided(ServiceAdmission::Full) => {
            br#"{"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}"#.to_vec()
        },
        SubmissionAdmission::Indeterminate => br#"{"version":1,"status":"INDETERMINATE"}"#.to_vec(),
        SubmissionAdmission::Error(error) => service_error(error),
    }
}

pub(super) fn invalid_request() -> Vec<u8> {
    service_error(ServiceError::InvalidRequest)
}

pub(super) fn operation_failure() -> Vec<u8> {
    service_error(ServiceError::OperationFailure)
}

pub(super) fn service_error(error: ServiceError) -> Vec<u8> {
    let class = match error {
        ServiceError::InvalidRequest => "invalid_request",
        ServiceError::AuthorityUnavailable => "authority_unavailable",
        ServiceError::Configuration | ServiceError::OperationFailure => "operation_failure",
    };
    format!("{{\"version\":1,\"status\":\"ERROR\",\"error_class\":\"{class}\"}}").into_bytes()
}

const fn phase_name(phase: kapsel::OperationState) -> &'static str {
    use kapsel::OperationState;
    match phase {
        OperationState::Requested => "requested",
        OperationState::Authorized => "authorized",
        OperationState::NotAttempted => "not_attempted",
        OperationState::ApplyStarted => "apply_started",
        OperationState::ReceiverObserved => "receiver_observed",
        OperationState::Finalized => "finalized",
    }
}

fn render_status(result: Result<SetDeploymentImageStatus, ServiceError>) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageStatus::NotFound) => br#"{"version":1,"status":"NOT_FOUND"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::InProgress) => {
            br#"{"version":1,"status":"IN_PROGRESS"}"#.to_vec()
        },
        Ok(SetDeploymentImageStatus::Succeeded) => {
            br#"{"version":1,"status":"SUCCEEDED"}"#.to_vec()
        },
        Ok(SetDeploymentImageStatus::Failed) => br#"{"version":1,"status":"FAILED"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Unknown) => br#"{"version":1,"status":"UNKNOWN"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::NotAttempted(rejection)) => format!(
            "{{\"version\":1,\"status\":\"NOT_ATTEMPTED\",\"target_rejection\":\"{}\"}}",
            target_rejection(rejection)
        )
        .into_bytes(),
        Err(error) => service_error(error),
    }
}

pub(super) fn render_status_with_targets(
    result: Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ServiceError>,
) -> Vec<u8> {
    let (status, targets) = match result {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let mut output = render_status(Ok(status));
    if status == SetDeploymentImageStatus::NotFound
        || targets == kapsel::OperationTargets::default()
    {
        return output;
    }
    let exact = |target: Option<kapsel::ApprovedTarget>| {
        target.map(|target| {
        serde_json::json!({ "uid": target.uid, "resource_version": target.resource_version })
    })
    };
    let fields = serde_json::json!({
        "approved_target": exact(targets.approved_target),
        "attempt_target": exact(targets.attempt_target),
        "observed_target": targets.observed_target.map(|target| serde_json::json!({
            "uid": target.uid, "resource_version": target.resource_version,
        })),
    })
    .to_string();
    // Both objects are locally rendered JSON. Join fields without parsing or changing values.
    output.pop();
    output.push(b',');
    output.extend_from_slice(&fields.as_bytes()[1..]);
    output
}

pub(super) fn render_receipt(result: Result<SetDeploymentImageReceipt, ServiceError>) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageReceipt::NotFound) => {
            br#"{"version":1,"status":"NOT_FOUND"}"#.to_vec()
        },
        Ok(SetDeploymentImageReceipt::NotReady) => {
            br#"{"version":1,"status":"NOT_READY"}"#.to_vec()
        },
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 }) => {
            // The fixed wrapper includes the 64-byte digest, but not the doubled receipt bytes.
            const WRAPPER_BYTES: usize =
                br#"{"version":1,"status":"READY","receipt_hex":"","receipt_sha256":""}"#.len()
                    + 64;
            if !valid_sha256(&sha256) {
                return operation_failure();
            }
            let Some(length) = bytes
                .len()
                .checked_mul(2)
                .and_then(|length| length.checked_add(WRAPPER_BYTES))
            else {
                return Vec::new();
            };
            if !response_length_allowed(length, ResponseClass::Receipt) {
                return Vec::new();
            }
            let receipt_hex = lowercase_hex(&bytes);
            format!(
                concat!(
                    "{{\"version\":1,\"status\":\"READY\",\"receipt_hex\":\"{}\",",
                    "\"receipt_sha256\":\"{}\"}}"
                ),
                receipt_hex, sha256
            )
            .into_bytes()
        },
        Err(error) => service_error(error),
    }
}

pub(super) fn render_catalog(
    entries: Vec<kapsel::ApprovedAction>,
    next_cursor: Option<&str>,
) -> Vec<u8> {
    let entries: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "operation_id": entry.request.operation_id,
                "namespace": entry.request.namespace,
                "deployment": entry.request.deployment,
                "container": entry.request.container,
                "immutable_image_digest": entry.request.immutable_image_digest,
                "approved_target": {
                    "uid": entry.approved_target.uid,
                    "resource_version": entry.approved_target.resource_version,
                },
                "label": entry.label,
            })
        })
        .collect();
    serde_json::json!({"version":1,"status":"READY","entries":entries,"next_cursor":next_cursor})
        .to_string()
        .into_bytes()
}

pub(super) fn render_history(page: kapsel::HistoryPage) -> Vec<u8> {
    let mut entries = Vec::with_capacity(page.entries.len());
    for entry in page.entries {
        let bytes = render_status_with_targets(entry.status);
        let Ok(serde_json::Value::Object(mut fields)) = serde_json::from_slice(&bytes) else {
            return operation_failure();
        };
        fields.remove("version");
        fields.insert("operation_id".into(), entry.operation_id.into());
        entries.push(fields);
    }
    serde_json::json!({
        "version":1,"status":"READY","entries":entries,"next_cursor":page.next_cursor,
    })
    .to_string()
    .into_bytes()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn target_rejection(rejection: TargetRejection) -> &'static str {
    match rejection {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
        TargetRejection::StaleApproval => "STALE_APPROVAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_request_grammars_parse_and_hostile_shapes_fail() {
        for valid in [
            r#"{"version":1,"request":"get_set_deployment_image_status","operation_id":"op-1"}"#,
            r#"{"version":1,"request":"get_set_deployment_image_receipt","operation_id":"op-1"}"#,
            r#"{"version":1,"request":"submit_set_deployment_image","operation_id":"op-1"}"#,
            r#"{"version":1,"request":"list_approved_actions","after":null}"#,
            r#"{"version":1,"request":"list_operation_history","after":"op-1"}"#,
        ] {
            assert!(decode(valid.as_bytes()).is_some());
        }
        for invalid in [
            r#"{"request":"get_set_deployment_image_status","operation_id":"a","unknown":1}"#,
            r#"{"request":"get_set_deployment_image_status","operation_id":null}"#,
            r#"{"request":"get_set_deployment_image_status","operation_id":1}"#,
            r#"{"request":"get_set_deployment_image_status","namespace":"demo"}"#,
            r#"{"request":"get_set_deployment_image_status"}"#,
            r#"{"request":"unknown","operation_id":"a"}"#,
            r#"{"request":"get_set_deployment_image_status"}{}"#,
            r"[]",
        ] {
            assert!(decode(invalid.as_bytes()).is_none());
        }
        assert!(decode(&[0xff]).is_none());
    }

    #[test]
    fn duplicate_members_and_escaped_aliases_fail_for_every_request_variant() {
        for request in [
            "get_set_deployment_image_status",
            "get_set_deployment_image_receipt",
            "submit_set_deployment_image",
        ] {
            let members = vec![
                ("request", r"\u0072equest", request),
                ("operation_id", r"\u006fperation_id", "op-1"),
            ];
            let body = format!(
                "\"version\":1,{}",
                members
                    .iter()
                    .map(|(name, _, value)| format!(r#""{name}":"{value}""#))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            assert!(
                decode(format!("{{{body}}}").as_bytes()).is_some(),
                "{request}"
            );
            for (name, escaped, value) in &members {
                let member = format!(r#""{name}":"{value}""#);
                let alias = format!(r#""{escaped}":"{value}""#);
                let unique_alias = body.replace(&member, &alias);
                assert!(
                    decode(format!("{{{unique_alias}}}").as_bytes()).is_some(),
                    "unique alias: {request} {escaped}"
                );
                let other_value = match *name {
                    "request" if request == "get_set_deployment_image_status" => {
                        "get_set_deployment_image_receipt"
                    },
                    "request" => "get_set_deployment_image_status",
                    _ => "other",
                };
                for duplicate_value in [*value, other_value] {
                    for duplicate_name in [*name, *escaped] {
                        let duplicate = format!(r#""{duplicate_name}":"{duplicate_value}""#);
                        // Keep raw members: a JSON object map would erase the duplicates.
                        for invalid in [
                            format!("{{{body},{duplicate}}}"),
                            format!("{{{duplicate},{body}}}"),
                        ] {
                            assert!(decode(invalid.as_bytes()).is_none(), "{invalid}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_status_and_receipt_projection_uses_only_the_fixed_vocabulary() {
        for (status, expected) in [
            (
                SetDeploymentImageStatus::NotFound,
                r#"{"status":"NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::InProgress,
                r#"{"status":"IN_PROGRESS"}"#,
            ),
            (
                SetDeploymentImageStatus::Succeeded,
                r#"{"status":"SUCCEEDED"}"#,
            ),
            (SetDeploymentImageStatus::Failed, r#"{"status":"FAILED"}"#),
            (SetDeploymentImageStatus::Unknown, r#"{"status":"UNKNOWN"}"#),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::DeploymentNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::ContainerNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"CONTAINER_NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::InvalidTarget),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"INVALID_TARGET"}"#,
            ),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::StaleApproval),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"STALE_APPROVAL"}"#,
            ),
        ] {
            assert_eq!(
                render_status(Ok(status)),
                expected.replacen('{', "{\"version\":1,", 1).as_bytes()
            );
        }
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotFound)),
            br#"{"version":1,"status":"NOT_FOUND"}"#
        );
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotReady)),
            br#"{"version":1,"status":"NOT_READY"}"#
        );
        let ready = render_receipt(Ok(SetDeploymentImageReceipt::Ready {
            bytes: vec![0x00, 0xab, 0xff],
            sha256: concat!(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef"
            )
            .into(),
        }));
        assert_eq!(
            ready,
            concat!(
                "{\"version\":1,\"status\":\"READY\",\"receipt_hex\":\"00abff\",",
                "\"receipt_sha256\":\"",
                r#"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
            )
            .as_bytes()
        );
        assert_eq!(lowercase_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(
            render_submission(SubmissionAdmission::Decided(ServiceAdmission::Busy)),
            br#"{"version":1,"status":"NOT_ADMITTED","reason":"BUSY"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::Decided(ServiceAdmission::Full)),
            br#"{"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::Error(ServiceError::OperationFailure)),
            br#"{"version":1,"status":"ERROR","error_class":"operation_failure"}"#
        );
    }

    #[test]
    fn version_and_named_fields_are_mandatory_on_all_five_commands() {
        for (name, fields) in [
            ("list_approved_actions", r#""after":null"#),
            ("list_operation_history", r#""after":"op-1""#),
            (
                "get_set_deployment_image_status",
                r#""operation_id":"op-1""#,
            ),
            (
                "get_set_deployment_image_receipt",
                r#""operation_id":"op-1""#,
            ),
            ("submit_set_deployment_image", r#""operation_id":"op-1""#),
        ] {
            let body = format!(r#"{{"version":1,"request":"{name}",{fields}}}"#);
            assert!(decode(body.as_bytes()).is_some());
            for version in ["0", "2", "1.0", "\"1\"", "null", "true", "-1"] {
                assert!(decode(
                    body.replace("\"version\":1", &format!("\"version\":{version}"))
                        .as_bytes()
                )
                .is_none());
            }
            for invalid in [
                body.replace("\"version\":1,", ""),
                body.replace("\"version\":1", "\"version\":1,\"version\":1"),
                body.replace("\"version\":1", "\"version\":1,\"\\u0076ersion\":1"),
                body.replace("\"version\":1", "\"version\":1,\"unknown\":null"),
                format!("{body}{{}}"),
                format!("[{body}]"),
                format!("{{\"version\":1,\"request\":\"{name}\"}}"),
                format!("{{\"version\":1,\"request\":\"{name}\",{fields},{fields}}}"),
            ] {
                assert!(decode(invalid.as_bytes()).is_none(), "{invalid}");
            }
        }
        for value in ["[]", "{}", "true", "1", "\"\""] {
            let body = format!(
                "{{\"version\":1,\"request\":\"list_approved_actions\",\"after\":{value}}}"
            );
            assert!(decode(body.as_bytes()).is_none());
        }
        assert!(decode(
            concat!(
                r#"{"version":1,"request":"submit_set_deployment_image","operation_id":"op-1","#,
                r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                r#""immutable_image_digest":"image"}"#,
            )
            .as_bytes()
        )
        .is_none());
    }

    #[test]
    fn history_projection_keeps_authority_errors_per_id_and_without_action_facts() {
        let bytes = render_history(kapsel::HistoryPage {
            entries: vec![
                kapsel::HistoryEntry {
                    operation_id: "inaccessible".into(),
                    status: Err(ServiceError::AuthorityUnavailable),
                },
                kapsel::HistoryEntry {
                    operation_id: "readable".into(),
                    status: Ok((
                        SetDeploymentImageStatus::InProgress,
                        kapsel::OperationTargets {
                            approved_target: Some(kapsel::ApprovedTarget {
                                uid: "original-uid".into(),
                                resource_version: "7".into(),
                            }),
                            ..kapsel::OperationTargets::default()
                        },
                    )),
                },
            ],
            next_cursor: Some("readable".into()),
        });
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["status"], "READY");
        assert_eq!(value["next_cursor"], "readable");
        assert_eq!(
            value["entries"][0],
            serde_json::json!({
                "operation_id":"inaccessible", "status":"ERROR",
                "error_class":"authority_unavailable",
            })
        );
        assert_eq!(value["entries"][1]["operation_id"], "readable");
        assert_eq!(
            value["entries"][1]["approved_target"]["uid"],
            "original-uid"
        );
        assert!(value["entries"][1]["attempt_target"].is_null());
    }

    #[test]
    fn request_limits_apply_before_decoding_and_frame_allocation() {
        for length in [0, u32::try_from(REQUEST_BYTES_MAX + 1).unwrap(), u32::MAX] {
            assert_eq!(request_length(length.to_be_bytes()), None);
        }
        assert_eq!(request_length(1_u32.to_be_bytes()), Some(1));
        let mut body =
            br#"{"version":1,"request":"get_set_deployment_image_status","operation_id":"op-1"}"#
                .to_vec();
        body.resize(REQUEST_BYTES_MAX, b' ');
        assert_eq!(
            request_length(u32::try_from(body.len()).unwrap().to_be_bytes()),
            Some(body.len())
        );
        assert!(decode(&body).is_some());
        body.push(b' ');
        assert!(decode(&body).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn receipt_limit_is_checked_before_hex_expansion() {
        let empty = render_receipt(Ok(SetDeploymentImageReceipt::Ready {
            bytes: vec![],
            sha256: "0".repeat(64),
        }));
        let maximum = (RECEIPT_RESPONSE_BYTES_MAX - empty.len()) / 2;
        let at_limit = render_receipt(Ok(SetDeploymentImageReceipt::Ready {
            bytes: vec![0xab; maximum],
            sha256: "0".repeat(64),
        }));
        assert!(response_length_allowed(
            at_limit.len(),
            ResponseClass::Receipt
        ));
        assert_eq!(at_limit.len(), empty.len() + maximum * 2);
        let over_limit = render_receipt(Ok(SetDeploymentImageReceipt::Ready {
            bytes: vec![0xab; maximum + 1],
            sha256: "0".repeat(64),
        }));
        assert!(over_limit.is_empty());
        assert!(!response_length_allowed(
            over_limit.len(),
            ResponseClass::Receipt
        ));
    }

    #[test]
    fn response_class_bounds_accept_exact_and_reject_one_above() {
        assert!(response_length_allowed(
            ORDINARY_RESPONSE_BYTES_MAX,
            ResponseClass::Ordinary
        ));
        assert!(!response_length_allowed(
            ORDINARY_RESPONSE_BYTES_MAX + 1,
            ResponseClass::Ordinary
        ));
        assert!(response_length_allowed(
            RECEIPT_RESPONSE_BYTES_MAX,
            ResponseClass::Receipt
        ));
        assert!(!response_length_allowed(
            RECEIPT_RESPONSE_BYTES_MAX + 1,
            ResponseClass::Receipt
        ));
    }
}
