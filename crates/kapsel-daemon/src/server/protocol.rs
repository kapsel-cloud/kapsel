//! Pure fixed service grammar, validation projection, response bytes and frame limits.

#[cfg(test)]
#[path = "../../tests/fixtures/service_wire.rs"]
mod wire_vectors;

#[cfg(test)]
use kapsel::HistoryEntry;
use kapsel::{
    ApprovedAction, ApprovedTarget, ExecutionCondition, ExecutionDisposition, ExecutionObservation,
    GitAcknowledgement, GitObservedRef, GitOperationTargets, HistoryPage, OperationReceipt,
    OperationState, OperationStatus, OperationTargets, ServiceAdmission, ServiceError,
    TargetRejection,
};
use kapsel_authority::identity_is_valid;
use serde::Deserialize;
use serde_json::Value;

pub(super) const REQUEST_BYTES_MAX: usize = 16 * 1024;
const ORDINARY_RESPONSE_BYTES_MAX: usize = 16 * 1024;
const RECEIPT_RESPONSE_BYTES_MAX: usize = 40 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SubmissionAdmission {
    Decided(ServiceAdmission),
    Indeterminate,
    Error(ServiceError),
}

#[derive(Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
enum Request {
    #[serde(rename = "list_approved_actions")]
    List { version: u8, after: Value },
    #[serde(rename = "list_operation_history")]
    History { version: u8, after: Value },
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

    let cursor = |after: Value| match after {
        Value::Null => Some(None),
        Value::String(id) if identity_is_valid(&id) => Some(Some(id)),
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
        ServiceError::Configuration
        | ServiceError::OperationFailure
        | ServiceError::StorageMissing
        | ServiceError::StorageInvalid
        | ServiceError::StorageUnavailable => "operation_failure",
    };
    format!("{{\"version\":1,\"status\":\"ERROR\",\"error_class\":\"{class}\"}}").into_bytes()
}

const fn phase_name(phase: OperationState) -> &'static str {
    match phase {
        OperationState::Requested => "requested",
        OperationState::Authorized => "authorized",
        OperationState::NotAttempted => "not_attempted",
        OperationState::ApplyStarted => "apply_started",
        OperationState::ReceiverObserved => "receiver_observed",
        OperationState::Finalized => "finalized",
    }
}

fn render_status(result: Result<OperationStatus, ServiceError>) -> Vec<u8> {
    match result {
        Ok(OperationStatus::NotFound) => br#"{"version":1,"status":"NOT_FOUND"}"#.to_vec(),
        Ok(OperationStatus::InProgress) => br#"{"version":1,"status":"IN_PROGRESS"}"#.to_vec(),
        Ok(OperationStatus::Succeeded) => br#"{"version":1,"status":"SUCCEEDED"}"#.to_vec(),
        Ok(OperationStatus::Failed) => br#"{"version":1,"status":"FAILED"}"#.to_vec(),
        Ok(OperationStatus::Unknown) => br#"{"version":1,"status":"UNKNOWN"}"#.to_vec(),
        Ok(OperationStatus::NotAttempted(rejection)) => format!(
            "{{\"version\":1,\"status\":\"NOT_ATTEMPTED\",\"target_rejection\":\"{}\"}}",
            target_rejection(rejection)
        )
        .into_bytes(),
        Err(error) => service_error(error),
    }
}

pub(super) fn render_status_with_targets(
    result: Result<(OperationStatus, OperationTargets), ServiceError>,
) -> Vec<u8> {
    let (status, targets) = match result {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };

    let mut output = render_status(Ok(status));
    if status == OperationStatus::NotFound {
        return output;
    }

    let target_fields = |target: Option<ApprovedTarget>| {
        target.map(|target| {
            serde_json::json!({ "uid": target.uid, "resource_version": target.resource_version })
        })
    };
    let fields = if let Some(git) = targets.git {
        serde_json::json!({"effect":"git.transition_ref", "git": git_targets(git)})
    } else {
        serde_json::json!({
            "effect": "kubernetes.set_deployment_image",
            "approved_target": target_fields(targets.approved_target),
            "attempt_target": target_fields(targets.attempt_target),
            "observed_target": targets.observed_target.map(|target| serde_json::json!({
                "uid": target.uid, "resource_version": target.resource_version,
            })),
        })
    }
    .to_string();
    append_object_fields(&mut output, &fields);
    output
}

pub(super) fn render_execution_status(
    result: Result<(OperationStatus, OperationTargets, ExecutionDisposition), ServiceError>,
) -> Vec<u8> {
    let (status, targets, execution) = match result {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let mut output = render_status_with_targets(Ok((status, targets)));
    let fields = serde_json::json!({
        "execution": {
            "disposition": execution.as_str(),
            "condition": execution.condition().map(ExecutionCondition::as_str),
            "next_action": execution.next_action(),
            "action_owner": execution.action_owner(),
        },
    })
    .to_string();
    append_object_fields(&mut output, &fields);
    output
}

// Both objects are locally rendered JSON. Join fields without parsing or changing values.
fn append_object_fields(output: &mut Vec<u8>, fields: &str) {
    output.pop();
    output.push(b',');
    output.extend_from_slice(&fields.as_bytes()[1..]);
}

pub(super) fn render_receipt(result: Result<OperationReceipt, ServiceError>) -> Vec<u8> {
    match result {
        Ok(OperationReceipt::NotFound) => br#"{"version":1,"status":"NOT_FOUND"}"#.to_vec(),
        Ok(OperationReceipt::NotReady) => br#"{"version":1,"status":"NOT_READY"}"#.to_vec(),
        Ok(OperationReceipt::Ready { bytes, sha256 }) => {
            // The fixed wrapper includes the 64-byte digest, but not the doubled receipt bytes.
            const WRAPPER_BYTES: usize =
                br#"{"version":1,"status":"READY","receipt_hex":"","receipt_sha256":""}"#.len()
                    + 64;
            if !valid_sha256(&sha256) {
                return operation_failure();
            }

            let Some(response_length) = bytes
                .len()
                .checked_mul(2)
                .and_then(|length| length.checked_add(WRAPPER_BYTES))
            else {
                return Vec::new();
            };
            if !response_length_allowed(response_length, ResponseClass::Receipt) {
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

pub(super) fn render_catalog(entries: Vec<ApprovedAction>, next_cursor: Option<&str>) -> Vec<u8> {
    let entries: Vec<_> = entries
        .into_iter()
        .map(|entry| match entry {
            ApprovedAction::Kubernetes {
                request,
                approved_target,
                label,
            } => {
                serde_json::json!({
                    "effect": "kubernetes.set_deployment_image",
                    "operation_id": request.operation_id,
                    "namespace": request.namespace,
                    "deployment": request.deployment,
                    "container": request.container,
                    "immutable_image_digest": request.immutable_image_digest,
                    "approved_target": {
                        "uid": approved_target.uid,
                        "resource_version": approved_target.resource_version,
                    },
                    "label": label,
                })
            },
            ApprovedAction::Git {
                authorization,
                label,
            } => serde_json::json!({
                "effect":"git.transition_ref", "operation_id": authorization.operation_id,
                "repository_id": authorization.repository_id, "reference": authorization.reference,
                "old_commit": authorization.old_commit, "new_commit": authorization.new_commit,
                "label": label,
            }),
        })
        .collect();
    serde_json::json!({"version":1,"status":"READY","entries":entries,"next_cursor":next_cursor})
        .to_string()
        .into_bytes()
}

fn git_targets(targets: GitOperationTargets) -> Value {
    let observed_ref = targets.observed_ref.map(|observed| match observed {
        GitObservedRef::Commit(oid) => serde_json::json!({"kind":"commit", "commit":oid}),
        GitObservedRef::Missing => serde_json::json!({"kind":"missing", "commit":null}),
        GitObservedRef::Unknown => serde_json::json!({"kind":"unknown", "commit":null}),
    });
    serde_json::json!({
        "repository_id": targets.approval.repository_id, "reference": targets.approval.reference,
        "old_commit": targets.approval.old_commit, "new_commit": targets.approval.new_commit,
        "attempted": targets.attempted,
        "acknowledgement": targets.acknowledgement.map(GitAcknowledgement::as_str),
        "observed_ref": observed_ref,
    })
}

#[cfg(test)]
fn render_history(page: HistoryPage) -> Vec<u8> {
    render_execution_history(page, &|_| ExecutionObservation::Unknown)
}

pub(super) fn render_execution_history(
    page: HistoryPage,
    observation: &dyn Fn(&str) -> ExecutionObservation,
) -> Vec<u8> {
    let mut entries = Vec::with_capacity(page.entries.len());
    for entry in page.entries {
        let operation_id = entry.operation_id.clone();
        let execution_observation = observation(&operation_id);
        let bytes = render_execution_status(entry.execution_status(execution_observation));
        let Ok(Value::Object(mut fields)) = serde_json::from_slice(&bytes) else {
            return operation_failure();
        };
        fields.remove("version");
        fields.insert("operation_id".into(), operation_id.into());
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
        TargetRejection::GitStaleRef => "GIT_STALE_REF",
        TargetRejection::GitInvalidObjects => "GIT_INVALID_OBJECTS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_preserves_bounded_identity_and_cursor_values() {
        for (_, name, field) in wire_vectors::COMMANDS {
            for id in ["op-1".to_owned(), "A._:-z0".into(), "x".repeat(128)] {
                let body = serde_json::json!({"version":1,"request":name,field:id});
                let decoded = decode(body.to_string().as_bytes()).unwrap();
                let actual = match decoded {
                    Command::Read(ReadRequest::List(id)) => ("list_approved_actions", id),
                    Command::Read(ReadRequest::History(id)) => ("list_operation_history", id),
                    Command::Read(ReadRequest::Status(id)) => {
                        ("get_set_deployment_image_status", Some(id))
                    },
                    Command::Read(ReadRequest::Receipt(id)) => {
                        ("get_set_deployment_image_receipt", Some(id))
                    },
                    Command::Submit(id) => ("submit_set_deployment_image", Some(id)),
                };
                assert_eq!(actual, (name, Some(id)), "{body}");
            }
            for invalid in [
                Value::Null,
                serde_json::json!(1),
                serde_json::json!(true),
                serde_json::json!([]),
                serde_json::json!({}),
                serde_json::json!(""),
                serde_json::json!("../outside"),
                serde_json::json!("é"),
                serde_json::json!("a\0b"),
                serde_json::json!("x".repeat(129)),
            ] {
                let body = serde_json::json!({"version":1,"request":name,field:invalid});
                let decoded = decode(body.to_string().as_bytes());
                if field == "after" && invalid.is_null() {
                    assert!(matches!(
                        decoded,
                        Some(Command::Read(
                            ReadRequest::List(None) | ReadRequest::History(None)
                        ))
                    ));
                } else {
                    assert!(decoded.is_none(), "{body}");
                }
            }
        }
    }

    #[test]
    fn missing_unknown_and_duplicate_members_fail_from_valid_requests() {
        for (_, name, field) in wire_vectors::COMMANDS {
            let body = serde_json::json!({"version":1,"request":name,field:"op-1"});
            let raw = body.to_string();
            assert!(decode(raw.as_bytes()).is_some());
            for (member, alias) in [
                ("version", r"\u0076ersion"),
                ("request", r"\u0072equest"),
                (
                    field,
                    if field == "after" {
                        r"\u0061fter"
                    } else {
                        r"\u006fperation_id"
                    },
                ),
            ] {
                let mut missing = body.clone();
                missing.as_object_mut().unwrap().remove(member);
                assert!(decode(missing.to_string().as_bytes()).is_none());
                let unique_alias = raw.replace(&format!("\"{member}\":"), &format!("\"{alias}\":"));
                assert!(decode(unique_alias.as_bytes()).is_some());
                for key in [member, alias] {
                    let duplicate = format!("\"{key}\":{}", body[member]);
                    // Raw JSON retains duplicate keys, including aliases and either member order.
                    for invalid in [
                        format!("{{{},{} }}", &raw[1..raw.len() - 1], duplicate),
                        format!("{{{},{} }}", duplicate, &raw[1..raw.len() - 1]),
                    ] {
                        assert!(decode(invalid.as_bytes()).is_none(), "{invalid}");
                    }
                }
            }
            for (key, value) in [
                ("version", serde_json::json!(2)),
                ("version", serde_json::json!(1.0)),
                ("version", serde_json::json!("1")),
                ("version", Value::Null),
                ("version", serde_json::json!(true)),
                ("version", serde_json::json!(-1)),
                ("request", serde_json::json!("unknown")),
                ("unknown", Value::Null),
                ("grant", serde_json::json!("caller-appointed")),
            ] {
                let mut invalid = body.clone();
                invalid[key] = value;
                assert!(
                    decode(invalid.to_string().as_bytes()).is_none(),
                    "{invalid}"
                );
            }
            for invalid in [
                format!("[{raw}]"),
                format!("{raw}{{}}"),
                raw[..raw.len() - 1].into(),
            ] {
                assert!(decode(invalid.as_bytes()).is_none(), "{invalid}");
            }
        }
        assert!(decode(&[0xff]).is_none());
    }

    #[test]
    fn every_status_and_receipt_projection_uses_only_the_fixed_vocabulary() {
        for (status, expected) in [
            (OperationStatus::NotFound, r#"{"status":"NOT_FOUND"}"#),
            (OperationStatus::InProgress, r#"{"status":"IN_PROGRESS"}"#),
            (OperationStatus::Succeeded, r#"{"status":"SUCCEEDED"}"#),
            (OperationStatus::Failed, r#"{"status":"FAILED"}"#),
            (OperationStatus::Unknown, r#"{"status":"UNKNOWN"}"#),
            (
                OperationStatus::NotAttempted(TargetRejection::DeploymentNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
            ),
            (
                OperationStatus::NotAttempted(TargetRejection::ContainerNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"CONTAINER_NOT_FOUND"}"#,
            ),
            (
                OperationStatus::NotAttempted(TargetRejection::InvalidTarget),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"INVALID_TARGET"}"#,
            ),
            (
                OperationStatus::NotAttempted(TargetRejection::StaleApproval),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"STALE_APPROVAL"}"#,
            ),
        ] {
            assert_eq!(
                render_status(Ok(status)),
                expected.replacen('{', "{\"version\":1,", 1).as_bytes()
            );
        }
        assert_eq!(
            render_receipt(Ok(OperationReceipt::NotFound)),
            br#"{"version":1,"status":"NOT_FOUND"}"#
        );
        assert_eq!(
            render_receipt(Ok(OperationReceipt::NotReady)),
            br#"{"version":1,"status":"NOT_READY"}"#
        );
        let receipt: Value = serde_json::from_str(wire_vectors::RECEIPT).unwrap();
        let ready = render_receipt(Ok(OperationReceipt::Ready {
            bytes: b"abc".to_vec(),
            sha256: receipt["receipt_sha256"].as_str().unwrap().into(),
        }));
        assert_eq!(ready, wire_vectors::RECEIPT.as_bytes());
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
    fn history_wire_vector_preserves_both_effects_partial_observations_and_access_errors() {
        let git = kapsel::GitOperationTargets {
            approval: kapsel_authority::GitRefAuthorization {
                authorization_id: "approval".into(),
                operation_id: "git-op".into(),
                repository_id: "repo-1".into(),
                reference: "refs/heads/approved".into(),
                old_commit: "a".repeat(40),
                new_commit: "b".repeat(40),
            },
            attempted: true,
            acknowledgement: Some(GitAcknowledgement::Unknown),
            observed_ref: Some(GitObservedRef::Commit("b".repeat(40))),
        };
        let targets = OperationTargets {
            git: Some(git),
            ..OperationTargets::default()
        };
        let bytes = render_history(HistoryPage {
            entries: vec![
                HistoryEntry {
                    operation_id: "git-op".into(),
                    status: Ok((OperationStatus::Unknown, targets.clone())),
                },
                HistoryEntry {
                    operation_id: "inaccessible".into(),
                    status: Err(ServiceError::AuthorityUnavailable),
                },
                HistoryEntry {
                    operation_id: "kube-op".into(),
                    status: Ok((
                        OperationStatus::InProgress,
                        OperationTargets {
                            approved_target: Some(ApprovedTarget {
                                uid: "approved-uid".into(),
                                resource_version: "7".into(),
                            }),
                            attempt_target: Some(ApprovedTarget {
                                uid: "approved-uid".into(),
                                resource_version: "9".into(),
                            }),
                            observed_target: Some(kapsel::ObservedTarget {
                                uid: None,
                                resource_version: Some("11".into()),
                            }),
                            git: None,
                        },
                    )),
                },
            ],
            next_cursor: Some("kube-op".into()),
        });
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            serde_json::from_str::<Value>(wire_vectors::HISTORY).unwrap()
        );
        let absent = render_status_with_targets(Ok((OperationStatus::NotFound, targets)));
        assert_eq!(absent, br#"{"version":1,"status":"NOT_FOUND"}"#);
    }

    #[test]
    fn execution_renderer_binds_the_guidance_owner_without_repeating_its_partitions() {
        let bytes = render_execution_status(Ok((
            OperationStatus::InProgress,
            OperationTargets::default(),
            ExecutionDisposition::ResumeRequired(Some(ExecutionCondition::PreflightUnavailable)),
        )));
        assert!(response_length_allowed(
            bytes.len(),
            ResponseClass::Ordinary
        ));
        let (token, condition, action, owner) = wire_vectors::GUIDANCE[3];
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            serde_json::json!({
                "version":1, "status":"IN_PROGRESS", "effect":"kubernetes.set_deployment_image",
                "approved_target":null, "attempt_target":null, "observed_target":null,
                "execution":{"disposition":token,"condition":condition,
                    "next_action":action,"action_owner":owner},
            })
        );
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
        let empty = render_receipt(Ok(OperationReceipt::Ready {
            bytes: vec![],
            sha256: "0".repeat(64),
        }));
        let maximum = (RECEIPT_RESPONSE_BYTES_MAX - empty.len()) / 2;
        let at_limit = render_receipt(Ok(OperationReceipt::Ready {
            bytes: vec![0xab; maximum],
            sha256: "0".repeat(64),
        }));
        assert!(response_length_allowed(
            at_limit.len(),
            ResponseClass::Receipt
        ));
        assert_eq!(at_limit.len(), empty.len() + maximum * 2);
        let over_limit = render_receipt(Ok(OperationReceipt::Ready {
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
