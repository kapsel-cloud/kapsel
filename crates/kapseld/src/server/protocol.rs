//! Pure fixed service grammar, validation projection, response bytes and frame limits.

use kapsel::{
    AgentRequest, ApplicationError, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    TargetRejection,
};
use kapsel_authority::{
    dns_label_is_valid, dns_subdomain_is_valid, identity_is_valid, immutable_image_is_valid,
};
use serde::Deserialize;

pub(super) const REQUEST_BYTES_MAX: usize = 16 * 1024;
const ORDINARY_RESPONSE_BYTES_MAX: usize = 16 * 1024;
const RECEIPT_RESPONSE_BYTES_MAX: usize = 40 * 1024;

#[derive(Clone, Copy)]
pub(super) enum SubmissionAdmission {
    Accepted,
    Busy,
    OperationFailure,
}

#[derive(Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
enum Request {
    #[serde(rename = "get_set_deployment_image_status")]
    Status { operation_id: String },
    #[serde(rename = "get_set_deployment_image_receipt")]
    Receipt { operation_id: String },
    #[serde(rename = "submit_set_deployment_image")]
    Submit {
        operation_id: String,
        namespace: String,
        deployment: String,
        container: String,
        immutable_image_digest: String,
    },
}

#[derive(Clone, Copy)]
pub(super) enum ResponseClass {
    Ordinary,
    Receipt,
}

pub(super) enum Command {
    Read(ReadRequest),
    Submit(AgentRequest),
}

pub(super) enum ReadRequest {
    Status(String),
    Receipt(String),
}

pub(super) fn request_length(prefix: [u8; 4]) -> Option<usize> {
    let length = usize::try_from(u32::from_be_bytes(prefix)).ok()?;
    (length > 0 && length <= REQUEST_BYTES_MAX).then_some(length)
}

pub(super) fn decode(bytes: &[u8]) -> Option<Command> {
    if bytes.is_empty() || bytes.len() > REQUEST_BYTES_MAX {
        return None;
    }
    match serde_json::from_slice::<Request>(bytes).ok()? {
        Request::Status { operation_id } if identity_is_valid(&operation_id) => {
            Some(Command::Read(ReadRequest::Status(operation_id)))
        },
        Request::Receipt { operation_id } if identity_is_valid(&operation_id) => {
            Some(Command::Read(ReadRequest::Receipt(operation_id)))
        },
        Request::Submit {
            operation_id,
            namespace,
            deployment,
            container,
            immutable_image_digest,
        } if identity_is_valid(&operation_id)
            && dns_label_is_valid(&namespace)
            && dns_subdomain_is_valid(&deployment)
            && dns_label_is_valid(&container)
            && immutable_image_is_valid(&immutable_image_digest) =>
        {
            Some(Command::Submit(AgentRequest {
                operation_id,
                namespace,
                deployment,
                container,
                immutable_image_digest,
            }))
        },
        Request::Status { .. } | Request::Receipt { .. } | Request::Submit { .. } => None,
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
        SubmissionAdmission::Accepted => br#"{"status":"ACCEPTED"}"#.to_vec(),
        SubmissionAdmission::Busy => br#"{"status":"BUSY"}"#.to_vec(),
        SubmissionAdmission::OperationFailure => operation_failure(),
    }
}

pub(super) fn invalid_request() -> Vec<u8> {
    br#"{"status":"ERROR","error_class":"invalid_request"}"#.to_vec()
}

pub(super) fn operation_failure() -> Vec<u8> {
    br#"{"status":"ERROR","error_class":"operation_failure"}"#.to_vec()
}

fn render_status(result: &Result<SetDeploymentImageStatus, ApplicationError>) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageStatus::NotFound) => br#"{"status":"NOT_FOUND"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::InProgress) => br#"{"status":"IN_PROGRESS"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Succeeded) => br#"{"status":"SUCCEEDED"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Failed) => br#"{"status":"FAILED"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Unknown) => br#"{"status":"UNKNOWN"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::NotAttempted(rejection)) => format!(
            "{{\"status\":\"NOT_ATTEMPTED\",\"target_rejection\":\"{}\"}}",
            target_rejection(*rejection)
        )
        .into_bytes(),
        Err(_) => operation_failure(),
    }
}

pub(super) fn render_status_with_targets(
    result: Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError>,
) -> Vec<u8> {
    let Ok((status, targets)) = result else {
        return operation_failure();
    };
    let mut output = render_status(&Ok(status));
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

pub(super) fn render_receipt(
    result: Result<SetDeploymentImageReceipt, ApplicationError>,
) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageReceipt::NotFound) => br#"{"status":"NOT_FOUND"}"#.to_vec(),
        Ok(SetDeploymentImageReceipt::NotReady) => br#"{"status":"NOT_READY"}"#.to_vec(),
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 }) => {
            // The fixed wrapper includes the 64-byte digest, but not the doubled receipt bytes.
            const WRAPPER_BYTES: usize =
                br#"{"status":"READY","receipt_hex":"","receipt_sha256":""}"#.len() + 64;
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
                    "{{\"status\":\"READY\",\"receipt_hex\":\"{}\",",
                    "\"receipt_sha256\":\"{}\"}}"
                ),
                receipt_hex, sha256
            )
            .into_bytes()
        },
        Err(_) => operation_failure(),
    }
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
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        for valid in [
            String::from(r#"{"request":"get_set_deployment_image_status","operation_id":"op-1"}"#),
            String::from(r#"{"request":"get_set_deployment_image_receipt","operation_id":"op-1"}"#),
            format!(
                concat!(
                    "{{\"request\":\"submit_set_deployment_image\",",
                    "\"operation_id\":\"op-1\",\"namespace\":\"demo\",",
                    "\"deployment\":\"agent-api\",\"container\":\"api\",",
                    "\"immutable_image_digest\":\"{image}\"}}"
                ),
                image = image
            ),
        ] {
            assert!(decode(valid.as_bytes()).is_some());
        }
        for invalid in [
            concat!(
                r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                r#""operation_id":"b"}"#
            ),
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
            assert_eq!(render_status(&Ok(status)), expected.as_bytes());
        }
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotFound)),
            br#"{"status":"NOT_FOUND"}"#
        );
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotReady)),
            br#"{"status":"NOT_READY"}"#
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
                "{\"status\":\"READY\",\"receipt_hex\":\"00abff\",\"receipt_sha256\":\"",
                r#"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
            )
            .as_bytes()
        );
        assert_eq!(lowercase_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(
            render_submission(SubmissionAdmission::Accepted),
            br#"{"status":"ACCEPTED"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::Busy),
            br#"{"status":"BUSY"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::OperationFailure),
            br#"{"status":"ERROR","error_class":"operation_failure"}"#
        );
    }

    #[test]
    fn request_limits_apply_before_decoding_and_frame_allocation() {
        for length in [0, u32::try_from(REQUEST_BYTES_MAX + 1).unwrap(), u32::MAX] {
            assert_eq!(request_length(length.to_be_bytes()), None);
        }
        assert_eq!(request_length(1_u32.to_be_bytes()), Some(1));
        let mut body =
            br#"{"request":"get_set_deployment_image_status","operation_id":"op-1"}"#.to_vec();
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
