//! Fixed private scheduler-to-system state payload adapter.
//!
//! This module owns bounded wire DTOs and exact conversion to existing [`crate::Service`]
//! transitions. It owns no listener, authentication, retry, Kubernetes, or storage abstraction.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{
    bounded_hex_128, bounded_identity, object_identity_parts, DispatchLease,
    PolicyObjectRequirement, ProvisionedObject, ProvisionedTarget, ProvisioningSpecification,
    Service, ServiceError,
};

const PROTOCOL: &str = "scheduler-state-v1";
pub(crate) const PAYLOAD_BYTES_MAX: usize = 64 * 1024;
const ACTIVE_INVENTORY_MAX: usize = 8;
const POLICY_INVENTORY_MAX: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol: String,
    request: RequestDto,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RequestDto {
    ListRecoverable {},
    ReserveNext {},
    RecoverLease {
        run_id: String,
        previous: Option<LeaseDto>,
    },
    ReadProvisioning {
        lease: LeaseDto,
    },
    CommitPolicy {
        lease: LeaseDto,
        target: ProvisionedTargetDto,
    },
    DeriveAssignment {
        lease: LeaseDto,
    },
    RecordSetupFailure {
        lease: LeaseDto,
        cleanup_identity: String,
        resource_state: SetupResourceStateDto,
    },
    AppendDeadline {
        lease: LeaseDto,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseDto {
    run_id: String,
    lease_id: String,
    epoch: i64,
    expires_at_unix_s: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupResourceStateDto {
    Recorded,
    None,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedTargetDto {
    namespace_uid: String,
    policy_revision: String,
    policy_inventory_digest: String,
    cleanup_identity: String,
    objects: Vec<ProvisionedObjectDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedObjectDto {
    identity: String,
    uid: String,
    owner_label: String,
    content_digest: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    protocol: &'static str,
    response: ResponseDto,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResponseDto {
    Recoverable { runs: Vec<RecoverableDto> },
    Lease { lease: LeaseDto },
    Provisioning { specification: ProvisioningDto },
    Committed,
    Assignment { assignment: AssignmentDto },
    Rejected { error: ErrorDto },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoverableDto {
    run_id: String,
    policy_status: PolicyStatusDto,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyStatusDto {
    NotEligible,
    Pending,
    Verified,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningDto {
    run_id: String,
    namespace: String,
    policy_revision: String,
    cleanup_identity: String,
    deadline_seconds: i64,
    deadline_at_unix_s: i64,
    policy_inventory_digest: String,
    required_objects: Vec<PolicyObjectRequirementDto>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyObjectRequirementDto {
    identity: String,
    content_digest: String,
}

struct AssignmentDto {
    run_id: String,
    operation_id: String,
    lease_id: String,
    credential: [u8; 32],
    endpoint: String,
}

impl Serialize for AssignmentDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<'a> {
            run_id: &'a str,
            operation_id: &'a str,
            lease_id: &'a str,
            credential_hex: String,
            endpoint: &'a str,
        }
        Wire {
            run_id: &self.run_id,
            operation_id: &self.operation_id,
            lease_id: &self.lease_id,
            credential_hex: hex(&self.credential),
            endpoint: &self.endpoint,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorDto {
    InvalidRequest,
    NotFound,
    Busy,
    Saturated,
    Deadline,
    Denied,
    Unavailable,
}

/// Parses, validates, and dispatches one complete scheduler-state payload.
///
/// Time and the private handoff endpoint are operator composition, never caller payload fields.
/// Every failure uses the fixed private error vocabulary.
pub(crate) fn handle(
    service: &Service,
    frame: &[u8],
    handoff_endpoint: SocketAddr,
    now_unix_s: i64,
) -> Vec<u8> {
    let response = decode_request(frame)
        .and_then(|request| dispatch(service, request, handoff_endpoint, now_unix_s))
        .unwrap_or_else(ResponseDto::rejected);
    encode_response(response)
}

fn decode_request(frame: &[u8]) -> Result<RequestDto, ErrorDto> {
    if frame.len() < 4 {
        return Err(ErrorDto::InvalidRequest);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| ErrorDto::InvalidRequest)?,
    ) as usize;
    if length == 0 || length > PAYLOAD_BYTES_MAX || frame.len() != length.saturating_add(4) {
        return Err(ErrorDto::InvalidRequest);
    }
    let envelope: RequestEnvelope =
        serde_json::from_slice(&frame[4..]).map_err(|_| ErrorDto::InvalidRequest)?;
    if envelope.protocol != PROTOCOL {
        return Err(ErrorDto::InvalidRequest);
    }
    validate_request(&envelope.request)?;
    Ok(envelope.request)
}

fn validate_request(request: &RequestDto) -> Result<(), ErrorDto> {
    match request {
        RequestDto::ListRecoverable {} | RequestDto::ReserveNext {} => Ok(()),
        RequestDto::RecoverLease { run_id, previous } => {
            valid_run(run_id)?;
            if let Some(previous) = previous {
                validate_lease(previous)?;
                if previous.run_id != *run_id {
                    return Err(ErrorDto::InvalidRequest);
                }
            }
            Ok(())
        },
        RequestDto::ReadProvisioning { lease } | RequestDto::DeriveAssignment { lease } => {
            validate_lease(lease)
        },
        RequestDto::CommitPolicy { lease, target } => {
            validate_lease(lease)?;
            valid_identity(&target.namespace_uid)?;
            valid_identity(&target.policy_revision)?;
            valid_digest(&target.policy_inventory_digest)?;
            valid_identity(&target.cleanup_identity)?;
            if target.objects.is_empty() || target.objects.len() > POLICY_INVENTORY_MAX {
                return Err(ErrorDto::InvalidRequest);
            }
            for object in &target.objects {
                valid_object_identity(&object.identity)?;
                valid_identity(&object.uid)?;
                valid_identity(&object.owner_label)?;
                valid_digest(&object.content_digest)?;
            }
            Ok(())
        },
        RequestDto::RecordSetupFailure {
            lease,
            cleanup_identity,
            resource_state: _,
        } => {
            validate_lease(lease)?;
            valid_identity(cleanup_identity)
        },
        RequestDto::AppendDeadline { lease } => validate_lease(lease),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive match keeps the fixed operation vocabulary and dispatch visible"
)]
fn dispatch(
    service: &Service,
    request: RequestDto,
    endpoint: SocketAddr,
    now: i64,
) -> Result<ResponseDto, ErrorDto> {
    match request {
        RequestDto::ListRecoverable {} => {
            let run_ids = service.recoverable_runs().map_err(map_service_error)?;
            if run_ids.len() > ACTIVE_INVENTORY_MAX {
                return Err(ErrorDto::Unavailable);
            }
            let runs = run_ids
                .into_iter()
                .map(|run_id| {
                    let policy_status = match service
                        .scheduler_policy_status(&run_id)
                        .map_err(map_service_error)?
                    {
                        None => PolicyStatusDto::NotEligible,
                        Some(false) => PolicyStatusDto::Pending,
                        Some(true) => PolicyStatusDto::Verified,
                    };
                    Ok(RecoverableDto {
                        run_id,
                        policy_status,
                    })
                })
                .collect::<Result<Vec<_>, ErrorDto>>()?;
            Ok(ResponseDto::Recoverable { runs })
        },
        RequestDto::ReserveNext {} => service
            .dispatch_next(now)
            .map(|lease| ResponseDto::Lease {
                lease: LeaseDto::from_domain(&lease),
            })
            .map_err(map_service_error),
        RequestDto::RecoverLease { run_id, previous } => {
            let previous = previous.map(LeaseDto::into_domain).transpose()?;
            service
                .recover_run(&run_id, previous.as_ref(), now)
                .map(|lease| ResponseDto::Lease {
                    lease: LeaseDto::from_domain(&lease),
                })
                .map_err(map_service_error)
        },
        RequestDto::ReadProvisioning { lease } => {
            let lease = lease.into_domain()?;
            let specification = service
                .provisioning_specification(&lease, now)
                .map_err(map_service_error)?;
            Ok(ResponseDto::Provisioning {
                specification: ProvisioningDto::from_domain(specification)?,
            })
        },
        RequestDto::CommitPolicy { lease, target } => {
            let lease = lease.into_domain()?;
            service
                .verify_provisioned_target(&lease, &target.into_domain(), now)
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
        RequestDto::DeriveAssignment { lease } => {
            let lease = lease.into_domain()?;
            if service
                .scheduler_policy_status(&lease.run_id)
                .map_err(map_service_error)?
                != Some(true)
            {
                return Err(ErrorDto::Denied);
            }
            let assignment = service
                .appoint_handoff_assignment(&lease, endpoint, now)
                .map_err(map_service_error)?;
            Ok(ResponseDto::Assignment {
                assignment: AssignmentDto {
                    run_id: assignment.run_id,
                    operation_id: assignment.operation_id,
                    lease_id: assignment.lease_id,
                    credential: assignment.credential,
                    endpoint: assignment.endpoint.to_string(),
                },
            })
        },
        RequestDto::RecordSetupFailure {
            lease,
            cleanup_identity,
            resource_state,
        } => {
            let lease = lease.into_domain()?;
            match resource_state {
                SetupResourceStateDto::Recorded => {
                    service.record_setup_failure(&lease, &cleanup_identity, now)
                },
                SetupResourceStateDto::None => {
                    service.record_setup_failure_without_resources(&lease, &cleanup_identity, now)
                },
            }
            .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
        RequestDto::AppendDeadline { lease } => {
            let lease = lease.into_domain()?;
            service
                .validate_lease(&lease, now)
                .map_err(map_service_error)?;
            service
                .record_deadline(&lease.run_id, now)
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
    }
}

impl LeaseDto {
    fn from_domain(lease: &DispatchLease) -> Self {
        Self {
            run_id: lease.run_id.clone(),
            lease_id: lease.lease_id.clone(),
            epoch: lease.epoch,
            expires_at_unix_s: lease.expires_at_unix_s,
        }
    }

    fn into_domain(self) -> Result<DispatchLease, ErrorDto> {
        validate_lease(&self)?;
        Ok(DispatchLease {
            run_id: self.run_id,
            lease_id: self.lease_id,
            epoch: self.epoch,
            expires_at_unix_s: self.expires_at_unix_s,
            handoff_credential: [0; 32],
        })
    }
}

impl ProvisionedTargetDto {
    fn into_domain(self) -> ProvisionedTarget {
        ProvisionedTarget {
            namespace_uid: self.namespace_uid,
            policy_revision: self.policy_revision,
            policy_inventory_digest: self.policy_inventory_digest,
            cleanup_identity: self.cleanup_identity,
            objects: self
                .objects
                .into_iter()
                .map(|object| ProvisionedObject {
                    identity: object.identity,
                    uid: object.uid,
                    owner_label: object.owner_label,
                    content_digest: object.content_digest,
                })
                .collect(),
        }
    }
}

impl ProvisioningDto {
    fn from_domain(specification: ProvisioningSpecification) -> Result<Self, ErrorDto> {
        if specification.required_objects.is_empty()
            || specification.required_objects.len() > POLICY_INVENTORY_MAX
        {
            return Err(ErrorDto::Unavailable);
        }
        Ok(Self {
            run_id: specification.run_id,
            namespace: specification.namespace,
            policy_revision: specification.policy_revision,
            cleanup_identity: specification.cleanup_identity,
            deadline_seconds: specification.deadline_seconds,
            deadline_at_unix_s: specification.deadline_at_unix_s,
            policy_inventory_digest: specification.policy_inventory_digest,
            required_objects: specification
                .required_objects
                .into_iter()
                .map(PolicyObjectRequirementDto::from_domain)
                .collect(),
        })
    }
}

impl PolicyObjectRequirementDto {
    fn from_domain(requirement: PolicyObjectRequirement) -> Self {
        Self {
            identity: requirement.identity,
            content_digest: requirement.content_digest,
        }
    }
}

impl ResponseDto {
    fn rejected(error: ErrorDto) -> Self {
        Self::Rejected { error }
    }
}

fn encode_response(response: ResponseDto) -> Vec<u8> {
    let envelope = ResponseEnvelope {
        protocol: PROTOCOL,
        response,
    };
    let body = serde_json::to_vec(&envelope).unwrap_or_else(|_| {
        br#"{"protocol":"scheduler-state-v1","response":{"kind":"rejected","error":"unavailable"}}"#
            .to_vec()
    });
    if body.is_empty() || body.len() > PAYLOAD_BYTES_MAX {
        return encode_response(ResponseDto::rejected(ErrorDto::Unavailable));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn validate_lease(lease: &LeaseDto) -> Result<(), ErrorDto> {
    valid_run(&lease.run_id)?;
    valid_run(&lease.lease_id)?;
    if lease.epoch < 1 || lease.expires_at_unix_s < 0 {
        return Err(ErrorDto::InvalidRequest);
    }
    Ok(())
}

fn valid_run(value: &str) -> Result<(), ErrorDto> {
    bounded_hex_128(value).map_err(|_| ErrorDto::InvalidRequest)
}

fn valid_identity(value: &str) -> Result<(), ErrorDto> {
    bounded_identity(value).map_err(|_| ErrorDto::InvalidRequest)
}

fn valid_object_identity(value: &str) -> Result<(), ErrorDto> {
    if value.len() > 253 || !value.is_ascii() {
        return Err(ErrorDto::InvalidRequest);
    }
    object_identity_parts(value)
        .map(|_| ())
        .map_err(|_| ErrorDto::InvalidRequest)
}

fn valid_digest(value: &str) -> Result<(), ErrorDto> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ErrorDto::InvalidRequest)
    }
}

fn map_service_error(error: ServiceError) -> ErrorDto {
    match error {
        ServiceError::InvalidRequest | ServiceError::UnsupportedVersion => ErrorDto::InvalidRequest,
        ServiceError::RunNotFound | ServiceError::RunExpired => ErrorDto::NotFound,
        ServiceError::LeaseBusy => ErrorDto::Busy,
        ServiceError::ActiveSaturated | ServiceError::CapacitySaturated => ErrorDto::Saturated,
        ServiceError::DeadlineExceeded => ErrorDto::Deadline,
        ServiceError::InvalidTransition
        | ServiceError::OwnershipMismatch
        | ServiceError::PolicyMismatch
        | ServiceError::IdempotencyConflict
        | ServiceError::RateLimited
        | ServiceError::ReceiptNotAvailable => ErrorDto::Denied,
        ServiceError::Unavailable => ErrorDto::Unavailable,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{json, Value};

    use super::*;
    use crate::{kubernetes_policy, HandoffIdentity, Scenario};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: i64 = 1_774_051_200;
    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const ENDPOINT: &str = "127.0.0.1:8081";

    fn fixture() -> (std::path::PathBuf, Service) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-scheduler-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("receipts")).unwrap();
        fs::set_permissions(root.join("receipts"), fs::Permissions::from_mode(0o700)).unwrap();
        let service = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW,
        )
        .unwrap();
        service
            .admit_with_run_id(&"1".repeat(32), Scenario::Healthy, NOW, RUN)
            .unwrap();
        (root, service)
    }

    fn request(value: &Value) -> Vec<u8> {
        let body = serde_json::to_vec(&json!({"protocol": PROTOCOL, "request": value})).unwrap();
        let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend(body);
        frame
    }

    fn response(frame: &[u8]) -> Value {
        let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), length + 4);
        serde_json::from_slice(&frame[4..]).unwrap()
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "test calls construct one-shot JSON vectors inline"
    )]
    fn call(service: &Service, value: Value, now: i64) -> Value {
        response(&handle(
            service,
            &request(&value),
            ENDPOINT.parse().unwrap(),
            now,
        ))
    }

    fn lease_from(value: &Value) -> Value {
        value["response"]["lease"].clone()
    }

    fn credential(value: &str) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end vector keeps every fixed operation in protocol order"
    )]
    fn exact_vectors_cover_every_operation_and_success_response() {
        let (root, service) = fixture();
        assert_eq!(
            call(&service, json!({"operation":"list_recoverable"}), NOW),
            json!({"protocol":PROTOCOL,"response":{"kind":"recoverable","runs":[]}})
        );
        let reserved = call(&service, json!({"operation":"reserve_next"}), NOW + 1);
        assert_eq!(reserved["protocol"], PROTOCOL);
        assert_eq!(reserved["response"]["kind"], "lease");
        let lease = lease_from(&reserved);

        let recoverable = call(&service, json!({"operation":"list_recoverable"}), NOW + 1);
        assert_eq!(recoverable["response"]["runs"][0]["run_id"], RUN);
        assert_eq!(
            recoverable["response"]["runs"][0]["policy_status"],
            "pending"
        );

        let provisioning = call(
            &service,
            json!({"operation":"read_provisioning","lease":lease}),
            NOW + 1,
        );
        assert_eq!(provisioning["response"]["kind"], "provisioning");
        assert_eq!(provisioning["response"]["specification"]["run_id"], RUN);
        let specification = &provisioning["response"]["specification"];
        let rendered = kubernetes_policy::render(RUN);
        let objects = rendered
            .iter()
            .enumerate()
            .map(|(index, object)| {
                json!({
                    "identity": object.identity,
                    "uid": format!("uid-{index}"),
                    "owner_label": specification["cleanup_identity"],
                    "content_digest": kubernetes_policy::content_digest(&object.body)
                })
            })
            .collect::<Vec<_>>();
        let denied_assignment = call(
            &service,
            json!({"operation":"derive_assignment","lease":lease_from(&reserved)}),
            NOW + 1,
        );
        assert_eq!(denied_assignment["response"]["error"], "denied");
        let target = json!({
            "namespace_uid":"uid-0",
            "policy_revision":specification["policy_revision"],
            "policy_inventory_digest":specification["policy_inventory_digest"],
            "cleanup_identity":specification["cleanup_identity"],
            "objects":objects
        });
        let committed = call(
            &service,
            json!({
                "operation":"commit_policy",
                "lease":lease_from(&reserved),
                "target":target
            }),
            NOW + 1,
        );
        assert_eq!(
            committed,
            json!({"protocol":PROTOCOL,"response":{"kind":"committed"}})
        );
        let assignment = call(
            &service,
            json!({"operation":"derive_assignment","lease":lease_from(&reserved)}),
            NOW + 1,
        );
        assert_eq!(assignment["response"]["kind"], "assignment");
        assert_eq!(assignment["response"]["assignment"]["run_id"], RUN);
        assert_eq!(
            assignment["response"]["assignment"]["credential_hex"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(assignment["response"]["assignment"]["endpoint"], ENDPOINT);
        let mut changed_target = target;
        changed_target["objects"][1]["content_digest"] = Value::String("0".repeat(64));
        let changed = call(
            &service,
            json!({
                "operation":"commit_policy",
                "lease":lease_from(&reserved),
                "target":changed_target
            }),
            NOW + 1,
        );
        assert_eq!(changed["response"]["error"], "denied");
        assert_eq!(
            call(&service, json!({"operation":"list_recoverable"}), NOW + 1)["response"]["runs"][0]
                ["policy_status"],
            "verified"
        );
        let assignment_body = &assignment["response"]["assignment"];
        service
            .commit_application_invoked(
                &HandoffIdentity {
                    run_id: RUN.into(),
                    operation_id: assignment_body["operation_id"].as_str().unwrap().into(),
                    lease_id: assignment_body["lease_id"].as_str().unwrap().into(),
                    credential: credential(assignment_body["credential_hex"].as_str().unwrap()),
                },
                NOW + 1,
            )
            .unwrap();
        assert_eq!(
            call(
                &service,
                json!({"operation":"derive_assignment","lease":lease_from(&reserved)}),
                NOW + 1,
            )["response"]["error"],
            "denied"
        );

        let renewed = call(
            &service,
            json!({"operation":"recover_lease","run_id":RUN,"previous":lease_from(&reserved)}),
            NOW + 2,
        );
        assert_eq!(renewed["response"]["kind"], "lease");
        let deadline_lease = call(
            &service,
            json!({"operation":"recover_lease","run_id":RUN,"previous":lease_from(&renewed)}),
            NOW + 181,
        );
        let deadline = call(
            &service,
            json!({"operation":"append_deadline","lease":lease_from(&deadline_lease)}),
            NOW + 181,
        );
        assert_eq!(deadline["response"]["kind"], "committed");
        let snapshot = service.snapshot(RUN, NOW + 181).unwrap();
        assert!(snapshot.receiver_result.is_none());
        assert!(snapshot.target_rejection.is_none());
        assert_eq!(
            service
                .events(RUN, 0, 64, NOW + 181)
                .unwrap()
                .events
                .last()
                .unwrap()
                .kind,
            "execution.deadline_reached"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn setup_failure_variants_cross_handler_and_preserve_receiver_vocabulary() {
        for no_resources in [true, false] {
            let (root, service) = fixture();
            let reserved = call(&service, json!({"operation":"reserve_next"}), NOW + 1);
            let provisioning = call(
                &service,
                json!({"operation":"read_provisioning","lease":lease_from(&reserved)}),
                NOW + 1,
            );
            let cleanup_identity = provisioning["response"]["specification"]["cleanup_identity"]
                .as_str()
                .unwrap();
            if !no_resources {
                let specification = &provisioning["response"]["specification"];
                let objects = kubernetes_policy::render(RUN)
                    .iter()
                    .enumerate()
                    .map(|(index, object)| {
                        json!({
                            "identity": object.identity,
                            "uid": format!("uid-{index}"),
                            "owner_label": cleanup_identity,
                            "content_digest": kubernetes_policy::content_digest(&object.body)
                        })
                    })
                    .collect::<Vec<_>>();
                let _ = call(
                    &service,
                    json!({
                        "operation":"commit_policy","lease":lease_from(&reserved),"target":{
                            "namespace_uid":"uid-0",
                            "policy_revision":specification["policy_revision"],
                            "policy_inventory_digest":specification["policy_inventory_digest"],
                            "cleanup_identity":cleanup_identity,"objects":objects
                        }
                    }),
                    NOW + 1,
                );
            }
            let result = call(
                &service,
                json!({
                    "operation":"record_setup_failure",
                    "lease":lease_from(&reserved),
                    "cleanup_identity":cleanup_identity,
                    "resource_state":if no_resources {"none"} else {"recorded"}
                }),
                NOW + 2,
            );
            assert_eq!(result["response"]["kind"], "committed");
            let snapshot = service.snapshot(RUN, NOW + 2).unwrap();
            assert!(snapshot.receiver_result.is_none());
            assert!(snapshot.target_rejection.is_none());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn hostile_frames_and_fields_reject_before_public_mutation() {
        let (root, service) = fixture();
        let baseline = service.events(RUN, 0, 64, NOW).unwrap();
        let cases = [
            Vec::new(),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 1, 0xff],
            {
                let mut bytes = request(&json!({"operation":"reserve_next"}));
                bytes.push(0);
                bytes
            },
            request(&json!({"operation":"unknown"})),
            request(&json!({"operation":"append_deadline","run_id":"HOSTILE"})),
            request(&json!({"operation":"reserve_next","extra":true})),
        ];
        for frame in cases {
            let actual = response(&handle(&service, &frame, ENDPOINT.parse().unwrap(), NOW));
            assert_eq!(actual["response"]["error"], "invalid_request");
        }
        let duplicate = concat!(
            r#"{"protocol":"scheduler-state-v1","request":{"operation":"reserve_next","#,
            r#""operation":"reserve_next"}}"#
        )
        .as_bytes();
        let mut frame = u32::try_from(duplicate.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        frame.extend(duplicate);
        assert_eq!(
            response(&handle(&service, &frame, ENDPOINT.parse().unwrap(), NOW))["response"]
                ["error"],
            "invalid_request"
        );
        let mut oversized = u32::try_from(PAYLOAD_BYTES_MAX + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        oversized.extend(vec![b'x'; PAYLOAD_BYTES_MAX + 1]);
        assert_eq!(
            response(&handle(
                &service,
                &oversized,
                ENDPOINT.parse().unwrap(),
                NOW
            ))["response"]["error"],
            "invalid_request"
        );
        let oversized_inventory = (0..=POLICY_INVENTORY_MAX)
            .map(|index| {
                json!({
                    "identity":format!("Pod/sandbox-{RUN}/pod-{index}"),
                    "uid":format!("uid-{index}"),
                    "owner_label":format!("cleanup-{RUN}"),
                    "content_digest":"0".repeat(64)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            call(
                &service,
                json!({
                    "operation":"commit_policy",
                    "lease":{
                        "run_id":RUN,
                        "lease_id":"f".repeat(32),
                        "epoch":1,
                        "expires_at_unix_s":NOW + 1
                    },
                    "target":{
                        "namespace_uid":"uid-0","policy_revision":"sandbox-policy-v2",
                        "policy_inventory_digest":"0".repeat(64),
                        "cleanup_identity":format!("cleanup-{RUN}"),"objects":oversized_inventory
                    }
                }),
                NOW
            )["response"]["error"],
            "invalid_request"
        );
        assert_eq!(service.events(RUN, 0, 64, NOW).unwrap(), baseline);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fifo_reservation_and_active_capacity_cross_the_handler() {
        let (root, service) = fixture();
        let mut expected = vec![RUN.to_owned()];
        for index in 1..9 {
            let run_id = format!("{index:032x}");
            service
                .admit_with_run_id(
                    &format!("{:032x}", index + 10),
                    Scenario::Healthy,
                    NOW,
                    &run_id,
                )
                .unwrap();
            expected.push(run_id);
        }
        for run_id in expected.iter().take(ACTIVE_INVENTORY_MAX) {
            let reserved = call(&service, json!({"operation":"reserve_next"}), NOW + 1);
            assert_eq!(reserved["response"]["lease"]["run_id"], *run_id);
        }
        assert_eq!(
            call(&service, json!({"operation":"reserve_next"}), NOW + 1)["response"]["error"],
            "saturated"
        );
        assert_eq!(
            call(&service, json!({"operation":"list_recoverable"}), NOW + 1)["response"]["runs"]
                .as_array()
                .unwrap()
                .len(),
            ACTIVE_INVENTORY_MAX
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_foreign_changed_replay_restart_and_capacity_semantics_are_preserved() {
        let (root, service) = fixture();
        let first = call(&service, json!({"operation":"reserve_next"}), NOW + 1);
        let mut foreign = lease_from(&first);
        foreign["lease_id"] = Value::String("f".repeat(32));
        assert_eq!(
            call(
                &service,
                json!({"operation":"recover_lease","run_id":RUN,"previous":foreign}),
                NOW + 2
            )["response"]["error"],
            "busy"
        );
        let reopened = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW + 2,
        )
        .unwrap();
        let renewed = call(
            &reopened,
            json!({"operation":"recover_lease","run_id":RUN,"previous":lease_from(&first)}),
            NOW + 2,
        );
        assert_eq!(renewed["response"]["kind"], "lease");
        assert_eq!(
            call(
                &reopened,
                json!({"operation":"recover_lease","run_id":RUN,"previous":lease_from(&first)}),
                NOW + 3
            )["response"]["error"],
            "busy"
        );
        assert_eq!(
            call(&reopened, json!({"operation":"reserve_next"}), NOW + 3)["response"]["error"],
            "not_found"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_is_confined_to_assignment_and_never_debugged() {
        let (root, service) = fixture();
        let reserved = call(&service, json!({"operation":"reserve_next"}), NOW + 1);
        assert!(!format!("{reserved:?}").contains("credential_hex"));
        let lease = service.recover_run(RUN, None, NOW + 32).unwrap();
        assert!(format!("{lease:?}").contains("[REDACTED]"));
        assert!(!format!("{lease:?}").contains(&hex(&lease.handoff_credential)));
        fs::remove_dir_all(root).unwrap();
    }
}
