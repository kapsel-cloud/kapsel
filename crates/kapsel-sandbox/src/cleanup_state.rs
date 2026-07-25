//! Fixed private cleanup-to-system state payload adapter.
//!
//! This role-specific module owns bounded wire DTOs and exact conversion to existing cleanup
//! transitions. It owns no listener, authentication, retry, Kubernetes, or storage abstraction.

use serde::{Deserialize, Serialize};

use crate::{
    bounded_hex_128, bounded_identity,
    kubernetes_cleanup::{CleanupCandidate, RecordedObject},
    object_identity_parts, CleanupAbsenceEvidence, CleanupObjectAbsence, Service, ServiceError,
};

const PROTOCOL: &str = "cleanup-state-v1";
pub(crate) const PAYLOAD_BYTES_MAX: usize = 64 * 1024;
const CANDIDATES_MAX: usize = 8;
const OWNED_OBJECTS_MAX: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol: String,
    request: RequestDto,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RequestDto {
    ListCandidates {},
    StartCleanup {
        candidate: CandidateIdentityDto,
    },
    RecordFailure {
        candidate: CandidateIdentityDto,
    },
    EscalateCleanup {
        candidate: CandidateIdentityDto,
    },
    CompleteCleanup {
        candidate: CandidateIdentityDto,
        evidence: AbsenceEvidenceDto,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateIdentityDto {
    run_id: String,
    cleanup_identity: String,
    namespace_uid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbsenceEvidenceDto {
    namespace_uid: String,
    objects: Vec<AbsenceObjectDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbsenceObjectDto {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    owner_label: String,
    present: bool,
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
    Candidates { candidates: Vec<CandidateDto> },
    Committed,
    Rejected { error: ErrorDto },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateDto {
    run_id: String,
    cleanup_identity: String,
    namespace_uid: String,
    state: CandidateStateDto,
    started_at_unix_s: Option<i64>,
    escalated: bool,
    objects: Vec<OwnedObjectDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CandidateStateDto {
    Pending,
    Running,
    Failed,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedObjectDto {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    owner_label: String,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorDto {
    InvalidPayload,
    CleanupMissing,
    CleanupForbidden,
    CleanupConflict,
    StateUnavailable,
}

/// Parses, validates, and dispatches one complete cleanup-state payload.
///
/// Operation time is supplied by system composition and never accepted from payload bytes. Every
/// failure uses the fixed cleanup-private error vocabulary.
pub(crate) fn handle(service: &Service, frame: &[u8], now_unix_s: i64) -> Vec<u8> {
    let response = decode_request(frame)
        .and_then(|request| dispatch(service, request, now_unix_s))
        .unwrap_or_else(ResponseDto::rejected);
    encode_response(response)
}

fn decode_request(frame: &[u8]) -> Result<RequestDto, ErrorDto> {
    if frame.len() < 4 {
        return Err(ErrorDto::InvalidPayload);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| ErrorDto::InvalidPayload)?,
    ) as usize;
    if length == 0 || length > PAYLOAD_BYTES_MAX || frame.len() != length.saturating_add(4) {
        return Err(ErrorDto::InvalidPayload);
    }
    let envelope: RequestEnvelope =
        serde_json::from_slice(&frame[4..]).map_err(|_| ErrorDto::InvalidPayload)?;
    if envelope.protocol != PROTOCOL {
        return Err(ErrorDto::InvalidPayload);
    }
    validate_request(&envelope.request)?;
    Ok(envelope.request)
}

fn validate_request(request: &RequestDto) -> Result<(), ErrorDto> {
    match request {
        RequestDto::ListCandidates {} => Ok(()),
        RequestDto::StartCleanup { candidate }
        | RequestDto::RecordFailure { candidate }
        | RequestDto::EscalateCleanup { candidate } => validate_candidate_identity(candidate),
        RequestDto::CompleteCleanup {
            candidate,
            evidence,
        } => {
            validate_candidate_identity(candidate)?;
            valid_identity(&evidence.namespace_uid)?;
            if evidence.namespace_uid != candidate.namespace_uid
                || evidence.objects.is_empty()
                || evidence.objects.len() > OWNED_OBJECTS_MAX
            {
                return Err(ErrorDto::InvalidPayload);
            }
            for object in &evidence.objects {
                validate_object(
                    &object.kind,
                    object.namespace.as_deref(),
                    &object.name,
                    &object.uid,
                    &object.owner_label,
                )?;
            }
            Ok(())
        },
    }
}

fn dispatch(service: &Service, request: RequestDto, now: i64) -> Result<ResponseDto, ErrorDto> {
    match request {
        RequestDto::ListCandidates {} => {
            let candidates = service.cleanup_candidates().map_err(map_service_error)?;
            if candidates.len() > CANDIDATES_MAX {
                return Err(ErrorDto::StateUnavailable);
            }
            Ok(ResponseDto::Candidates {
                candidates: candidates
                    .into_iter()
                    .map(CandidateDto::from_domain)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        },
        RequestDto::StartCleanup { candidate } => {
            service
                .start_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
        RequestDto::RecordFailure { candidate } => {
            service
                .fail_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
        RequestDto::EscalateCleanup { candidate } => {
            service
                .escalate_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
        RequestDto::CompleteCleanup {
            candidate,
            evidence,
        } => {
            service
                .complete_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &evidence.into_domain(),
                    now,
                )
                .map_err(map_service_error)?;
            Ok(ResponseDto::Committed)
        },
    }
}

impl CandidateDto {
    fn from_domain(candidate: CleanupCandidate) -> Result<Self, ErrorDto> {
        validate_domain_candidate(&candidate)?;
        let state = match candidate.state.as_str() {
            "pending" => CandidateStateDto::Pending,
            "running" => CandidateStateDto::Running,
            "failed" => CandidateStateDto::Failed,
            _ => return Err(ErrorDto::StateUnavailable),
        };
        Ok(Self {
            run_id: candidate.run_id,
            cleanup_identity: candidate.cleanup_identity,
            namespace_uid: candidate.namespace_uid,
            state,
            started_at_unix_s: candidate.started_at,
            escalated: candidate.escalated,
            objects: candidate
                .objects
                .into_iter()
                .map(OwnedObjectDto::from_domain)
                .collect(),
        })
    }
}

impl OwnedObjectDto {
    fn from_domain(object: RecordedObject) -> Self {
        Self {
            kind: object.kind,
            namespace: object.namespace,
            name: object.name,
            uid: object.uid,
            owner_label: object.owner_label,
        }
    }
}

impl AbsenceEvidenceDto {
    fn into_domain(self) -> CleanupAbsenceEvidence {
        CleanupAbsenceEvidence {
            namespace_uid: self.namespace_uid,
            objects: self
                .objects
                .into_iter()
                .map(|object| CleanupObjectAbsence {
                    kind: object.kind,
                    namespace: object.namespace,
                    name: object.name,
                    uid: object.uid,
                    owner_label: object.owner_label,
                    present: object.present,
                })
                .collect(),
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
    let body = serde_json::to_vec(&envelope).unwrap_or_else(|_| fallback_body());
    if body.is_empty() || body.len() > PAYLOAD_BYTES_MAX {
        return frame_body(&fallback_body());
    }
    frame_body(&body)
}

fn frame_body(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn fallback_body() -> Vec<u8> {
    br#"{"protocol":"cleanup-state-v1","response":{"kind":"rejected","error":"state_unavailable"}}"#
        .to_vec()
}

fn validate_candidate_identity(candidate: &CandidateIdentityDto) -> Result<(), ErrorDto> {
    valid_run(&candidate.run_id)?;
    valid_identity(&candidate.cleanup_identity)?;
    valid_identity(&candidate.namespace_uid)
}

fn validate_domain_candidate(candidate: &CleanupCandidate) -> Result<(), ErrorDto> {
    valid_run(&candidate.run_id).map_err(|_| ErrorDto::StateUnavailable)?;
    valid_identity(&candidate.cleanup_identity).map_err(|_| ErrorDto::StateUnavailable)?;
    valid_identity(&candidate.namespace_uid).map_err(|_| ErrorDto::StateUnavailable)?;
    if candidate.objects.is_empty() || candidate.objects.len() > OWNED_OBJECTS_MAX {
        return Err(ErrorDto::StateUnavailable);
    }
    if candidate.started_at.is_some_and(|time| time < 0)
        || !matches!(
            (
                candidate.state.as_str(),
                candidate.started_at.is_some(),
                candidate.escalated
            ),
            ("pending", false, false) | ("running", true, false) | ("failed", true, _)
        )
    {
        return Err(ErrorDto::StateUnavailable);
    }
    for object in &candidate.objects {
        validate_object(
            &object.kind,
            object.namespace.as_deref(),
            &object.name,
            &object.uid,
            &object.owner_label,
        )
        .map_err(|_| ErrorDto::StateUnavailable)?;
    }
    Ok(())
}

fn validate_object(
    kind: &str,
    namespace: Option<&str>,
    name: &str,
    uid: &str,
    owner_label: &str,
) -> Result<(), ErrorDto> {
    valid_identity(kind)?;
    valid_object_component(name)?;
    if let Some(namespace) = namespace {
        valid_object_component(namespace)?;
    }
    valid_identity(uid)?;
    valid_identity(owner_label)?;
    let identity = namespace.map_or_else(
        || format!("{kind}/{name}"),
        |namespace| format!("{kind}/{namespace}/{name}"),
    );
    if identity.len() > 253 {
        return Err(ErrorDto::InvalidPayload);
    }
    let parsed = object_identity_parts(&identity).map_err(|_| ErrorDto::InvalidPayload)?;
    if parsed.0 != kind || parsed.1.as_deref() != namespace || parsed.2 != name {
        return Err(ErrorDto::InvalidPayload);
    }
    if (kind == "Namespace") != namespace.is_none() {
        return Err(ErrorDto::InvalidPayload);
    }
    Ok(())
}

fn valid_run(value: &str) -> Result<(), ErrorDto> {
    bounded_hex_128(value).map_err(|_| ErrorDto::InvalidPayload)
}

fn valid_identity(value: &str) -> Result<(), ErrorDto> {
    bounded_identity(value).map_err(|_| ErrorDto::InvalidPayload)
}

fn valid_object_component(value: &str) -> Result<(), ErrorDto> {
    if (1..=253).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(ErrorDto::InvalidPayload)
    }
}

fn map_service_error(error: ServiceError) -> ErrorDto {
    match error {
        ServiceError::InvalidRequest | ServiceError::UnsupportedVersion => ErrorDto::InvalidPayload,
        ServiceError::RunNotFound | ServiceError::RunExpired => ErrorDto::CleanupMissing,
        ServiceError::OwnershipMismatch | ServiceError::PolicyMismatch => {
            ErrorDto::CleanupForbidden
        },
        ServiceError::InvalidTransition
        | ServiceError::IdempotencyConflict
        | ServiceError::RateLimited
        | ServiceError::CapacitySaturated
        | ServiceError::ActiveSaturated
        | ServiceError::LeaseBusy
        | ServiceError::DeadlineExceeded
        | ServiceError::ReceiptNotAvailable => ErrorDto::CleanupConflict,
        ServiceError::Unavailable => ErrorDto::StateUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{kubernetes_policy, ProvisionedObject, ProvisionedTarget, Scenario};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: i64 = 1_774_051_200;
    const RUN: &str = "0123456789abcdef0123456789abcdef";

    fn fixture(eligible: bool) -> (std::path::PathBuf, Service) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-cleanup-state-{}-{}",
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
        provision_run(&service, &root, RUN, &"1".repeat(32), eligible);
        (root, service)
    }

    fn provision_run(
        service: &Service,
        root: &std::path::Path,
        run_id: &str,
        key: &str,
        eligible: bool,
    ) {
        service
            .admit_with_run_id(key, Scenario::Healthy, NOW, run_id)
            .unwrap();
        let lease = service.dispatch_next(NOW + 1).unwrap();
        assert_eq!(lease.run_id, run_id);
        let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
        let uid_prefix = if run_id == RUN {
            String::new()
        } else {
            format!("{run_id}-")
        };
        let objects = kubernetes_policy::render(run_id)
            .iter()
            .enumerate()
            .map(|(index, object)| ProvisionedObject {
                identity: object.identity.clone(),
                uid: format!("{uid_prefix}uid-{index:02}"),
                owner_label: specification.cleanup_identity.clone(),
                content_digest: kubernetes_policy::content_digest(&object.body),
            })
            .collect();
        let namespace_uid = format!("{uid_prefix}uid-00");
        service
            .verify_provisioned_target(
                &lease,
                &ProvisionedTarget {
                    namespace_uid,
                    policy_revision: specification.policy_revision,
                    policy_inventory_digest: specification.policy_inventory_digest,
                    cleanup_identity: specification.cleanup_identity,
                    objects,
                },
                NOW + 1,
            )
            .unwrap();
        if eligible {
            rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                .unwrap()
                .execute(
                    "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                    [run_id],
                )
                .unwrap();
        }
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
        response(&handle(service, &request(&value), now))
    }

    fn listed_candidate(service: &Service, now: i64) -> Value {
        call(service, json!({"operation":"list_candidates"}), now)["response"]["candidates"][0]
            .clone()
    }

    fn identity(candidate: &Value) -> Value {
        json!({
            "run_id": candidate["run_id"],
            "cleanup_identity": candidate["cleanup_identity"],
            "namespace_uid": candidate["namespace_uid"]
        })
    }

    fn absence(candidate: &Value, present: bool) -> Value {
        json!({
            "namespace_uid":candidate["namespace_uid"],
            "objects":candidate["objects"].as_array().unwrap().iter().map(|object| json!({
                "kind":object["kind"],"namespace":object["namespace"],"name":object["name"],
                "uid":object["uid"],"owner_label":object["owner_label"],"present":present
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered vector proves every fixed cleanup operation and response"
    )]
    fn exact_vectors_cross_every_operation_and_restart_safe_escalation() {
        let (root, service) = fixture(true);
        let listed = call(&service, json!({"operation":"list_candidates"}), NOW + 2);
        assert_eq!(listed["protocol"], PROTOCOL);
        assert_eq!(listed["response"]["kind"], "candidates");
        let candidate = listed["response"]["candidates"][0].clone();
        let expected_objects = kubernetes_policy::render(RUN)
            .iter()
            .enumerate()
            .map(|(index, object)| {
                let (kind, namespace, name) = object_identity_parts(&object.identity).unwrap();
                json!({
                    "kind":kind,"namespace":namespace,"name":name,
                    "uid":format!("uid-{index:02}"),"owner_label":format!("cleanup-{RUN}")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            candidate,
            json!({
                "run_id":RUN,"cleanup_identity":format!("cleanup-{RUN}"),
                "namespace_uid":"uid-00","state":"pending","started_at_unix_s":null,
                "escalated":false,"objects":expected_objects
            })
        );

        let committed = json!({"protocol":PROTOCOL,"response":{"kind":"committed"}});
        assert_eq!(
            call(
                &service,
                json!({"operation":"start_cleanup","candidate":identity(&candidate)}),
                NOW + 2
            ),
            committed
        );
        assert_eq!(
            call(
                &service,
                json!({"operation":"record_failure","candidate":identity(&candidate)}),
                NOW + 3
            ),
            committed
        );
        assert_eq!(
            call(
                &service,
                json!({"operation":"record_failure","candidate":identity(&candidate)}),
                NOW + 4
            )["response"]["error"],
            "cleanup_conflict"
        );
        assert_eq!(
            call(
                &service,
                json!({"operation":"escalate_cleanup","candidate":identity(&candidate)}),
                NOW + 901
            )["response"]["error"],
            "cleanup_conflict"
        );

        let reopened = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW + 902,
        )
        .unwrap();
        assert_eq!(
            call(
                &reopened,
                json!({"operation":"escalate_cleanup","candidate":identity(&candidate)}),
                NOW + 902
            ),
            committed
        );
        assert_eq!(
            call(
                &reopened,
                json!({"operation":"escalate_cleanup","candidate":identity(&candidate)}),
                NOW + 903
            ),
            committed
        );
        let escalated = listed_candidate(&reopened, NOW + 903);
        assert_eq!(escalated["state"], "failed");
        assert_eq!(escalated["started_at_unix_s"], NOW + 2);
        assert_eq!(escalated["escalated"], true);
        assert_eq!(
            call(
                &reopened,
                json!({
                    "operation":"complete_cleanup","candidate":identity(&candidate),
                    "evidence":absence(&candidate, false)
                }),
                NOW + 904
            ),
            committed
        );
        assert_eq!(
            call(&reopened, json!({"operation":"list_candidates"}), NOW + 904),
            json!({"protocol":PROTOCOL,"response":{"kind":"candidates","candidates":[]}})
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidates_remain_in_durable_admission_order() {
        let (root, service) = fixture(true);
        let second = "fedcba9876543210fedcba9876543210";
        provision_run(&service, &root, second, &"2".repeat(32), true);
        let listed = call(&service, json!({"operation":"list_candidates"}), NOW + 2);
        let run_ids = listed["response"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["run_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(run_ids, vec![RUN, second]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_framing_fields_and_inventory_reject_without_mutation_or_reflection() {
        let (root, service) = fixture(true);
        let baseline = service.events(RUN, 0, 64, NOW + 1).unwrap();
        let cases = [
            Vec::new(),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 1, 0xff],
            vec![0, 0, 0, 1, b'{'],
            {
                let mut bytes = request(&json!({"operation":"list_candidates"}));
                bytes.pop();
                bytes
            },
            {
                let mut bytes = request(&json!({"operation":"list_candidates"}));
                bytes.push(0);
                bytes
            },
            request(&json!({"operation":"unknown"})),
            request(&json!({"operation":"list_candidates","secret":"must-not-reflect"})),
            request(&json!({
                "operation":"start_cleanup","candidate":{
                    "run_id":"HOSTILE","cleanup_identity":"cleanup-owner","namespace_uid":"uid"
                }
            })),
        ];
        for frame in cases {
            let actual = response(&handle(&service, &frame, NOW + 2));
            assert_eq!(actual["response"]["error"], "invalid_payload");
            assert!(!actual.to_string().contains("must-not-reflect"));
        }
        let duplicate = concat!(
            r#"{"protocol":"cleanup-state-v1","request":{"operation":"list_candidates","#,
            r#""operation":"list_candidates"}}"#
        )
        .as_bytes();
        let mut duplicate_frame = u32::try_from(duplicate.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        duplicate_frame.extend(duplicate);
        assert_eq!(
            response(&handle(&service, &duplicate_frame, NOW + 2))["response"]["error"],
            "invalid_payload"
        );
        let mut oversized = u32::try_from(PAYLOAD_BYTES_MAX + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        oversized.extend(vec![b'x'; PAYLOAD_BYTES_MAX + 1]);
        assert_eq!(
            response(&handle(&service, &oversized, NOW + 2))["response"]["error"],
            "invalid_payload"
        );
        let candidate = listed_candidate(&service, NOW + 2);
        let mut too_many = absence(&candidate, false);
        while too_many["objects"].as_array().unwrap().len() <= OWNED_OBJECTS_MAX {
            too_many["objects"]
                .as_array_mut()
                .unwrap()
                .push(candidate["objects"][0].clone());
        }
        assert_eq!(
            call(
                &service,
                json!({
                    "operation":"complete_cleanup","candidate":identity(&candidate),
                    "evidence":too_many
                }),
                NOW + 2
            )["response"]["error"],
            "invalid_payload"
        );
        assert_eq!(service.events(RUN, 0, 64, NOW + 2).unwrap(), baseline);
        assert_eq!(listed_candidate(&service, NOW + 2)["state"], "pending");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_candidate_and_object_identities_are_denied() {
        let (root, service) = fixture(true);
        let candidate = listed_candidate(&service, NOW + 2);
        let mut wrong_run = identity(&candidate);
        wrong_run["run_id"] = Value::String("f".repeat(32));
        assert_eq!(
            call(
                &service,
                json!({"operation":"start_cleanup","candidate":wrong_run}),
                NOW + 2
            )["response"]["error"],
            "cleanup_missing"
        );
        for field in ["cleanup_identity", "namespace_uid"] {
            let mut wrong = identity(&candidate);
            wrong[field] = Value::String("wrong".into());
            assert_eq!(
                call(
                    &service,
                    json!({"operation":"start_cleanup","candidate":wrong}),
                    NOW + 2
                )["response"]["error"],
                "cleanup_forbidden"
            );
        }
        assert_eq!(
            call(
                &service,
                json!({"operation":"start_cleanup","candidate":identity(&candidate)}),
                NOW + 2
            )["response"]["kind"],
            "committed"
        );
        for field in ["kind", "name", "uid", "owner_label"] {
            let mut evidence = absence(&candidate, false);
            evidence["objects"][1][field] = Value::String("wrong".into());
            assert_eq!(
                call(
                    &service,
                    json!({
                        "operation":"complete_cleanup","candidate":identity(&candidate),
                        "evidence":evidence
                    }),
                    NOW + 3
                )["response"]["error"],
                "cleanup_forbidden"
            );
        }
        let mut evidence = absence(&candidate, false);
        evidence["objects"][1]["namespace"] = Value::String("wrong".into());
        assert_eq!(
            call(
                &service,
                json!({
                    "operation":"complete_cleanup","candidate":identity(&candidate),
                    "evidence":evidence
                }),
                NOW + 3
            )["response"]["error"],
            "cleanup_forbidden"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_duplicate_extra_and_present_evidence_never_release_capacity() {
        let (root, service) = fixture(true);
        let candidate = listed_candidate(&service, NOW + 2);
        let _ = call(
            &service,
            json!({"operation":"start_cleanup","candidate":identity(&candidate)}),
            NOW + 2,
        );
        let exact = absence(&candidate, false);
        let mut variants = Vec::new();
        let mut incomplete = exact.clone();
        incomplete["objects"].as_array_mut().unwrap().pop();
        variants.push((incomplete, "cleanup_forbidden"));
        let mut duplicate = exact.clone();
        duplicate["objects"].as_array_mut().unwrap()[1] = duplicate["objects"][0].clone();
        variants.push((duplicate, "cleanup_forbidden"));
        let mut extra = exact.clone();
        extra["objects"].as_array_mut().unwrap().push(json!({
            "kind":"Pod","namespace":"kapsel-sandbox-runners","name":"extra",
            "uid":"extra-uid","owner_label":format!("cleanup-{RUN}"),"present":false
        }));
        variants.push((extra, "cleanup_forbidden"));
        let mut present = exact;
        present["objects"][0]["present"] = Value::Bool(true);
        variants.push((present, "cleanup_conflict"));
        for (evidence, error) in variants {
            assert_eq!(
                call(
                    &service,
                    json!({
                        "operation":"complete_cleanup","candidate":identity(&candidate),
                        "evidence":evidence
                    }),
                    NOW + 3
                )["response"]["error"],
                error
            );
            assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ineligible_or_non_owned_cleanup_is_not_disclosed_or_started() {
        let (root, service) = fixture(false);
        assert_eq!(
            call(&service, json!({"operation":"list_candidates"}), NOW + 2)["response"]
                ["candidates"],
            json!([])
        );
        let exact = json!({
            "run_id":RUN,"cleanup_identity":format!("cleanup-{RUN}"),"namespace_uid":"uid-00"
        });
        assert_eq!(
            call(
                &service,
                json!({"operation":"start_cleanup","candidate":exact}),
                NOW + 2
            )["response"]["error"],
            "cleanup_conflict"
        );
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .execute(
                concat!(
                    "UPDATE cleanup_records SET eligible = 1, ",
                    "resource_state = 'unverified' WHERE run_id = ?1"
                ),
                [RUN],
            )
            .unwrap();
        assert_eq!(
            call(&service, json!({"operation":"list_candidates"}), NOW + 2)["response"]
                ["candidates"],
            json!([])
        );
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .execute_batch(&format!(
                "UPDATE cleanup_records SET resource_state = 'owned' WHERE run_id = '{RUN}'; \
                 UPDATE provisioned_object_owners SET owner_label = 'foreign-owner' \
                 WHERE run_id = '{RUN}' AND uid = 'uid-01';"
            ))
            .unwrap();
        assert_eq!(
            call(&service, json!({"operation":"list_candidates"}), NOW + 2)["response"]["error"],
            "cleanup_forbidden"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capacity_is_held_until_exact_handler_completion() {
        let (root, service) = fixture(true);
        for index in 1..8 {
            let run_id = format!("{index:032x}");
            service
                .admit_with_run_id(
                    &format!("{:032x}", index + 10),
                    Scenario::Healthy,
                    NOW,
                    &run_id,
                )
                .unwrap();
            service.dispatch_next(NOW + 1).unwrap();
        }
        let waiting = "ffffffffffffffffffffffffffffffff";
        service
            .admit_with_run_id(&"e".repeat(32), Scenario::Healthy, NOW, waiting)
            .unwrap();
        let candidate = listed_candidate(&service, NOW + 2);
        let _ = call(
            &service,
            json!({"operation":"start_cleanup","candidate":identity(&candidate)}),
            NOW + 2,
        );
        let mut accepted_delete = absence(&candidate, false);
        accepted_delete["objects"][0]["present"] = Value::Bool(true);
        assert_eq!(
            call(
                &service,
                json!({
                    "operation":"complete_cleanup","candidate":identity(&candidate),
                    "evidence":accepted_delete
                }),
                NOW + 3
            )["response"]["error"],
            "cleanup_conflict"
        );
        assert_eq!(
            service.dispatch_next(NOW + 3),
            Err(ServiceError::ActiveSaturated)
        );
        assert_eq!(
            call(
                &service,
                json!({
                    "operation":"complete_cleanup","candidate":identity(&candidate),
                    "evidence":absence(&candidate, false)
                }),
                NOW + 4
            )["response"]["kind"],
            "committed"
        );
        assert_eq!(service.dispatch_next(NOW + 4).unwrap().run_id, waiting);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test joins cleanup failure, frozen receipt, and public expiry"
    )]
    fn public_expiry_preserves_private_cleanup_and_receiver_receipt_facts() {
        let (root, service) = fixture(true);
        let database = root.join("sandbox.sqlite3");
        let receipt_bytes = b"frozen-cleanup-receipt";
        let digest = hex(&Sha256::digest(receipt_bytes));
        let object_name = format!("sandbox-{RUN}-{digest}.receipt");
        fs::write(root.join("receipts").join(&object_name), receipt_bytes).unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute(
                concat!(
                    "UPDATE runs SET execution_state = 'terminal', receiver_result = 'UNKNOWN', ",
                    "receipt_available = 1 WHERE run_id = ?1"
                ),
                [RUN],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO receipts VALUES (?1, ?2, ?3)",
                rusqlite::params![RUN, digest, object_name],
            )
            .unwrap();
        drop(connection);
        let candidate = listed_candidate(&service, NOW + 2);
        let receiver_before: (Option<String>, Option<String>) =
            rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT receiver_result, target_rejection FROM runs WHERE run_id = ?1",
                    [RUN],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
        let receipt_before: (String, String) = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT digest, object_name FROM receipts WHERE run_id = ?1",
                [RUN],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let _ = call(
            &service,
            json!({"operation":"start_cleanup","candidate":identity(&candidate)}),
            NOW + 2,
        );
        let _ = call(
            &service,
            json!({"operation":"record_failure","candidate":identity(&candidate)}),
            NOW + 3,
        );
        let receiver_after_failure: (Option<String>, Option<String>) =
            rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT receiver_result, target_rejection FROM runs WHERE run_id = ?1",
                    [RUN],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
        let receipt_after_failure: (String, String) = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT digest, object_name FROM receipts WHERE run_id = ?1",
                [RUN],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(receiver_after_failure, receiver_before);
        assert_eq!(receipt_after_failure, receipt_before);
        assert_eq!(
            fs::read(root.join("receipts").join(&receipt_before.1)).unwrap(),
            receipt_bytes
        );
        service.sweep_retention(NOW + 86_401).unwrap();
        assert_eq!(
            service.snapshot(RUN, NOW + 86_401),
            Err(ServiceError::RunExpired)
        );
        assert_eq!(listed_candidate(&service, NOW + 86_401)["run_id"], RUN);
        let receiver_after: (Option<String>, Option<String>) =
            rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT receiver_result, target_rejection FROM runs WHERE run_id = ?1",
                    [RUN],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
        assert_eq!(receiver_after, receiver_before);
        let receipt_rows: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipt_rows, 0);
        assert!(!root.join("receipts").join(receipt_before.1).exists());
        assert_eq!(receipt_before.0, digest);
        fs::remove_dir_all(root).unwrap();
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
}
