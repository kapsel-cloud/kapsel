//! Fixed private cleanup-to-system state transport adapter.
//!
//! This role-specific module owns bounded wire DTOs, the concrete authenticated remote client,
//! the system-side listener, and exact conversion to existing cleanup transitions. It owns no
//! retry policy, Kubernetes cleanup authority, or storage abstraction.

use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use kube::Client as KubernetesClient;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::{
    bounded_hex_128, bounded_identity,
    controller_state_transport::{self, ClientInputs, Role},
    kubernetes_cleanup::{CleanupCandidate, RecordedObject},
    object_identity_parts, CleanupAbsenceEvidence, CleanupObjectAbsence, Service, ServiceError,
};

const PROTOCOL: &str = "cleanup-state-v1";
pub(crate) const PAYLOAD_BYTES_MAX: usize = 64 * 1024;
const CANDIDATES_MAX: usize = 8;
const OWNED_OBJECTS_MAX: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol: String,
    request: RequestDto,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateIdentityDto {
    run_id: String,
    cleanup_identity: String,
    namespace_uid: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AbsenceEvidenceDto {
    namespace_uid: String,
    objects: Vec<AbsenceObjectDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AbsenceObjectDto {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    owner_label: String,
    present: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    protocol: String,
    response: ResponseDto,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseDto {
    Candidates { candidates: Vec<CandidateDto> },
    Committed {},
    Rejected { error: ErrorDto },
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CandidateStateDto {
    Pending,
    Running,
    Failed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedObjectDto {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    owner_label: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorDto {
    InvalidPayload,
    CleanupMissing,
    CleanupForbidden,
    CleanupConflict,
    StateUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupStateError {
    InvalidPayload,
    CleanupMissing,
    CleanupForbidden,
    CleanupConflict,
    StateUnavailable,
    Authentication,
    Transport,
}

#[derive(Clone)]
pub(crate) struct CleanupStateClient {
    backend: CleanupStateBackend,
}

#[derive(Clone)]
enum CleanupStateBackend {
    Remote {
        endpoint: SocketAddr,
        inputs: ClientInputs,
    },
    #[cfg(test)]
    Local {
        service: Service,
        now: std::sync::Arc<std::sync::atomic::AtomicI64>,
    },
}

impl CleanupStateClient {
    pub(crate) fn new(
        endpoint: SocketAddr,
        ca_bundle_path: PathBuf,
        ca_bundle_sha256: [u8; 32],
        ca_root_count: u8,
        token_path: PathBuf,
    ) -> Result<Self, CleanupStateError> {
        let inputs = controller_state_transport::client_inputs(
            ca_bundle_path,
            ca_bundle_sha256,
            ca_root_count,
            token_path,
        )
        .map_err(|_| CleanupStateError::Transport)?;
        Ok(Self {
            backend: CleanupStateBackend::Remote { endpoint, inputs },
        })
    }

    #[cfg(test)]
    pub(crate) fn local(service: Service) -> Self {
        Self {
            backend: CleanupStateBackend::Local {
                service,
                now: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_now(&self, value: i64) {
        if let CleanupStateBackend::Local { now, .. } = &self.backend {
            now.store(value, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(crate) async fn list_candidates(&self) -> Result<Vec<CleanupCandidate>, CleanupStateError> {
        candidates_from_response(self.call(RequestDto::ListCandidates {}).await?)
    }

    pub(crate) async fn start_cleanup(
        &self,
        candidate: &CleanupCandidate,
    ) -> Result<(), CleanupStateError> {
        self.committed_call(RequestDto::StartCleanup {
            candidate: CandidateIdentityDto::from_domain(candidate),
        })
        .await
    }

    pub(crate) async fn record_failure(
        &self,
        candidate: &CleanupCandidate,
    ) -> Result<(), CleanupStateError> {
        self.committed_call(RequestDto::RecordFailure {
            candidate: CandidateIdentityDto::from_domain(candidate),
        })
        .await
    }

    pub(crate) async fn escalate_cleanup(
        &self,
        candidate: &CleanupCandidate,
    ) -> Result<(), CleanupStateError> {
        self.committed_call(RequestDto::EscalateCleanup {
            candidate: CandidateIdentityDto::from_domain(candidate),
        })
        .await
    }

    pub(crate) async fn complete_cleanup(
        &self,
        candidate: &CleanupCandidate,
        evidence: &CleanupAbsenceEvidence,
    ) -> Result<(), CleanupStateError> {
        self.committed_call(RequestDto::CompleteCleanup {
            candidate: CandidateIdentityDto::from_domain(candidate),
            evidence: AbsenceEvidenceDto::from_domain(evidence),
        })
        .await
    }

    async fn committed_call(&self, request: RequestDto) -> Result<(), CleanupStateError> {
        match self.call(request).await? {
            ResponseDto::Committed {} => Ok(()),
            _ => Err(CleanupStateError::Transport),
        }
    }

    async fn call(&self, request: RequestDto) -> Result<ResponseDto, CleanupStateError> {
        let frame = encode_request(request)?;
        let response = match &self.backend {
            CleanupStateBackend::Remote { endpoint, inputs } => {
                controller_state_transport::request(*endpoint, Role::Cleanup, inputs, &frame)
                    .await
                    .map_err(|error| match error {
                        controller_state_transport::ClientError::AuthenticationRejected => {
                            CleanupStateError::Authentication
                        },
                        controller_state_transport::ClientError::TransportRejected => {
                            CleanupStateError::Transport
                        },
                    })?
            },
            #[cfg(test)]
            CleanupStateBackend::Local { service, now } => handle(
                service,
                &frame,
                now.load(std::sync::atomic::Ordering::Relaxed),
            ),
        };
        decode_response(&response)
    }
}

pub(crate) async fn serve(
    service: Service,
    listen: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    cleanup_service_account_uid: String,
    kubernetes: KubernetesClient,
) -> Result<(), &'static str> {
    if listen.port() != 8083 {
        return Err("cleanup state listener address is invalid");
    }
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| "cleanup state listener is unavailable")?;
    let inputs = controller_state_transport::server_inputs(certificate_path, private_key_path);
    let binding =
        controller_state_transport::role_binding(Role::Cleanup, cleanup_service_account_uid)
            .map_err(|_| "cleanup state role binding is invalid")?;
    loop {
        let (connection, _) = listener
            .accept()
            .await
            .map_err(|_| "cleanup state listener failed")?;
        let inputs = inputs.clone();
        let binding = binding.clone();
        let kubernetes = kubernetes.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _ = controller_state_transport::handle_connection(
                connection,
                &inputs,
                &binding,
                kubernetes,
                move |payload| async move {
                    match unix_time() {
                        Ok(now) => handle(&service, &payload, now),
                        Err(()) => {
                            encode_response(ResponseDto::rejected(ErrorDto::StateUnavailable))
                        },
                    }
                },
            )
            .await;
        });
    }
}

fn encode_request(request: RequestDto) -> Result<Vec<u8>, CleanupStateError> {
    let body = serde_json::to_vec(&RequestEnvelope {
        protocol: PROTOCOL.to_owned(),
        request,
    })
    .map_err(|_| CleanupStateError::StateUnavailable)?;
    if body.is_empty() || body.len() > PAYLOAD_BYTES_MAX {
        return Err(CleanupStateError::InvalidPayload);
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| CleanupStateError::InvalidPayload)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn decode_response(frame: &[u8]) -> Result<ResponseDto, CleanupStateError> {
    if frame.len() < 4 {
        return Err(CleanupStateError::Transport);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| CleanupStateError::Transport)?,
    ) as usize;
    if length == 0 || length > PAYLOAD_BYTES_MAX || frame.len() != length.saturating_add(4) {
        return Err(CleanupStateError::Transport);
    }
    let envelope: ResponseEnvelope =
        serde_json::from_slice(&frame[4..]).map_err(|_| CleanupStateError::Transport)?;
    if envelope.protocol != PROTOCOL {
        return Err(CleanupStateError::Transport);
    }
    match envelope.response {
        ResponseDto::Rejected { error } => Err(error.into()),
        response => Ok(response),
    }
}

fn candidates_from_response(
    response: ResponseDto,
) -> Result<Vec<CleanupCandidate>, CleanupStateError> {
    match response {
        ResponseDto::Candidates { candidates } if candidates.len() <= CANDIDATES_MAX => candidates
            .into_iter()
            .map(CandidateDto::into_domain)
            .collect(),
        _ => Err(CleanupStateError::Transport),
    }
}

impl From<ErrorDto> for CleanupStateError {
    fn from(error: ErrorDto) -> Self {
        match error {
            ErrorDto::InvalidPayload => Self::InvalidPayload,
            ErrorDto::CleanupMissing => Self::CleanupMissing,
            ErrorDto::CleanupForbidden => Self::CleanupForbidden,
            ErrorDto::CleanupConflict => Self::CleanupConflict,
            ErrorDto::StateUnavailable => Self::StateUnavailable,
        }
    }
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
            Ok(ResponseDto::Committed {})
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
            Ok(ResponseDto::Committed {})
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
            Ok(ResponseDto::Committed {})
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
            Ok(ResponseDto::Committed {})
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

    fn into_domain(self) -> Result<CleanupCandidate, CleanupStateError> {
        let candidate = CleanupCandidate {
            run_id: self.run_id,
            cleanup_identity: self.cleanup_identity,
            namespace_uid: self.namespace_uid,
            state: match self.state {
                CandidateStateDto::Pending => "pending",
                CandidateStateDto::Running => "running",
                CandidateStateDto::Failed => "failed",
            }
            .to_owned(),
            started_at: self.started_at_unix_s,
            escalated: self.escalated,
            objects: self
                .objects
                .into_iter()
                .map(OwnedObjectDto::into_domain)
                .collect(),
        };
        validate_domain_candidate(&candidate).map_err(|_| CleanupStateError::Transport)?;
        Ok(candidate)
    }
}

impl CandidateIdentityDto {
    fn from_domain(candidate: &CleanupCandidate) -> Self {
        Self {
            run_id: candidate.run_id.clone(),
            cleanup_identity: candidate.cleanup_identity.clone(),
            namespace_uid: candidate.namespace_uid.clone(),
        }
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

    fn into_domain(self) -> RecordedObject {
        RecordedObject {
            kind: self.kind,
            namespace: self.namespace,
            name: self.name,
            uid: self.uid,
            owner_label: self.owner_label,
        }
    }
}

impl AbsenceEvidenceDto {
    fn from_domain(evidence: &CleanupAbsenceEvidence) -> Self {
        Self {
            namespace_uid: evidence.namespace_uid.clone(),
            objects: evidence
                .objects
                .iter()
                .map(|object| AbsenceObjectDto {
                    kind: object.kind.clone(),
                    namespace: object.namespace.clone(),
                    name: object.name.clone(),
                    uid: object.uid.clone(),
                    owner_label: object.owner_label.clone(),
                    present: object.present,
                })
                .collect(),
        }
    }

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
        protocol: PROTOCOL.to_owned(),
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
    let expected_namespace = format!("sandbox-{}", candidate.run_id);
    let mut namespace_count = 0;
    let mut identities = HashSet::with_capacity(candidate.objects.len());
    let mut uids = HashSet::with_capacity(candidate.objects.len());
    for object in &candidate.objects {
        validate_object(
            &object.kind,
            object.namespace.as_deref(),
            &object.name,
            &object.uid,
            &object.owner_label,
        )
        .map_err(|_| ErrorDto::StateUnavailable)?;
        if object.owner_label != candidate.cleanup_identity
            || !identities.insert((
                object.kind.as_str(),
                object.namespace.as_deref(),
                object.name.as_str(),
            ))
            || !uids.insert(object.uid.as_str())
        {
            return Err(ErrorDto::StateUnavailable);
        }
        if object.kind == "Namespace" {
            namespace_count += 1;
            if object.name != expected_namespace || object.uid != candidate.namespace_uid {
                return Err(ErrorDto::StateUnavailable);
            }
        }
    }
    if namespace_count != 1 {
        return Err(ErrorDto::StateUnavailable);
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

fn unix_time() -> Result<i64, ()> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ())
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

    use http::{Response, StatusCode};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tower_test::mock;

    use super::*;
    use crate::{kubernetes_policy, ProvisionedObject, ProvisionedTarget, Scenario};

    #[test]
    fn client_rejects_malformed_wrong_protocol_trailing_and_oversize_responses() {
        let valid = encode_response(ResponseDto::Committed {});
        assert!(matches!(
            decode_response(&valid),
            Ok(ResponseDto::Committed {})
        ));

        for rejected in [
            Vec::new(),
            frame_body(br#"{"protocol":"wrong","response":{"kind":"committed"}}"#),
            frame_body(
                br#"{"protocol":"cleanup-state-v1","response":{"kind":"committed","extra":true}}"#,
            ),
        ] {
            assert!(matches!(
                decode_response(&rejected),
                Err(CleanupStateError::Transport)
            ));
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(matches!(
            decode_response(&trailing),
            Err(CleanupStateError::Transport)
        ));
        let mut oversize = Vec::from(u32::try_from(PAYLOAD_BYTES_MAX + 1).unwrap().to_be_bytes());
        oversize.resize(PAYLOAD_BYTES_MAX + 5, b'x');
        assert!(matches!(
            decode_response(&oversize),
            Err(CleanupStateError::Transport)
        ));
    }

    #[test]
    fn client_rejects_hostile_candidate_deletion_authority_responses() {
        let (root, service) = fixture(true);
        let candidate =
            CandidateDto::from_domain(service.cleanup_candidates().unwrap().remove(0)).unwrap();
        let baseline = serde_json::to_value(ResponseEnvelope {
            protocol: PROTOCOL.to_owned(),
            response: ResponseDto::Candidates {
                candidates: vec![candidate],
            },
        })
        .unwrap();
        assert!(candidates_from_response(
            decode_response(&frame_body(&serde_json::to_vec(&baseline).unwrap())).unwrap()
        )
        .is_ok());

        let objects = baseline["response"]["candidates"][0]["objects"]
            .as_array()
            .unwrap();
        let namespace_index = objects
            .iter()
            .position(|object| object["kind"] == "Namespace")
            .unwrap();
        let ordinary = objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object["kind"] != "Namespace")
            .map(|(index, _)| index)
            .take(2)
            .collect::<Vec<_>>();
        let mut hostile = Vec::new();

        let mut wrong_owner = baseline.clone();
        wrong_owner["response"]["candidates"][0]["objects"][ordinary[0]]["owner_label"] =
            Value::String("foreign-cleanup-owner".into());
        hostile.push(wrong_owner);

        let mut wrong_namespace_name = baseline.clone();
        wrong_namespace_name["response"]["candidates"][0]["objects"][namespace_index]["name"] =
            Value::String("sandbox-foreign".into());
        hostile.push(wrong_namespace_name);

        let mut wrong_namespace_uid = baseline.clone();
        wrong_namespace_uid["response"]["candidates"][0]["objects"][namespace_index]["uid"] =
            Value::String("foreign-namespace-uid".into());
        hostile.push(wrong_namespace_uid);

        let mut missing_namespace = baseline.clone();
        missing_namespace["response"]["candidates"][0]["objects"]
            .as_array_mut()
            .unwrap()
            .remove(namespace_index);
        hostile.push(missing_namespace);

        let mut duplicate_namespace = baseline.clone();
        let mut namespace =
            duplicate_namespace["response"]["candidates"][0]["objects"][namespace_index].clone();
        namespace["uid"] = Value::String("duplicate-namespace-uid".into());
        duplicate_namespace["response"]["candidates"][0]["objects"]
            .as_array_mut()
            .unwrap()
            .push(namespace);
        hostile.push(duplicate_namespace);

        let mut duplicate_identity = baseline.clone();
        for field in ["kind", "namespace", "name"] {
            duplicate_identity["response"]["candidates"][0]["objects"][ordinary[1]][field] =
                duplicate_identity["response"]["candidates"][0]["objects"][ordinary[0]][field]
                    .clone();
        }
        hostile.push(duplicate_identity);

        let mut duplicate_uid = baseline;
        duplicate_uid["response"]["candidates"][0]["objects"][ordinary[1]]["uid"] =
            duplicate_uid["response"]["candidates"][0]["objects"][ordinary[0]]["uid"].clone();
        hostile.push(duplicate_uid);

        for response in hostile {
            let decoded = decode_response(&frame_body(&serde_json::to_vec(&response).unwrap()))
                .expect("hostile candidate still has a well-formed response envelope");
            assert!(matches!(
                candidates_from_response(decoded),
                Err(CleanupStateError::Transport)
            ));
        }
        fs::remove_dir_all(root).unwrap();
    }

    async fn start_authenticated_test_server(
        service: Service,
        certificate: PathBuf,
        private_key: PathBuf,
        now: i64,
        request_count: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        crate::controller_state_transport::allow_test_bound_port(endpoint.port());
        let inputs = crate::controller_state_transport::server_inputs(certificate, private_key);
        let binding = crate::controller_state_transport::role_binding(
            Role::Cleanup,
            "cleanup-uid".to_owned(),
        )
        .unwrap();
        let (transport, mut token_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let token_reviews = tokio::spawn(async move {
            for _ in 0..request_count {
                let (request, send) = token_handle.next_request().await.unwrap();
                let body: Value =
                    serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                assert_eq!(body["spec"]["token"], "cleanup-state-token");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(kube::client::Body::from(
                            serde_json::to_vec(&json!({
                                "apiVersion":"authentication.k8s.io/v1",
                                "kind":"TokenReview",
                                "metadata":{},
                                "spec":body["spec"],
                                "status":{
                                    "authenticated":true,
                                    "audiences":["https://kapsel.dev/sandbox/controller-state/v1"],
                                    "user":{
                                        "username":concat!(
                                            "system:serviceaccount:kapsel-sandbox-system:",
                                            "sandbox-cleanup"
                                        ),
                                        "uid":"cleanup-uid"
                                    }
                                }
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                );
            }
        });
        let server = tokio::spawn(async move {
            for _ in 0..request_count {
                let (connection, _) = listener.accept().await.unwrap();
                let service = service.clone();
                crate::controller_state_transport::handle_connection(
                    connection,
                    &inputs,
                    &binding,
                    KubernetesClient::new(transport.clone(), "default"),
                    move |payload| async move { handle(&service, &payload, now) },
                )
                .await
                .unwrap();
            }
            token_reviews.await.unwrap();
        });
        (endpoint, server)
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one role-authentication vector keeps the complete private transport proof visible"
    )]
    async fn concrete_remote_client_crosses_cleanup_tls_and_exact_role_authentication() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        let (root, service) = fixture(true);
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/controller-transport/current");
        let certificate = root.join("tls.crt");
        let private_key = root.join("tls.key");
        let ca_bundle = root.join("ca.crt");
        let token = root.join("state-token");
        for (source_name, destination, mode) in [
            ("cert.pem", &certificate, 0o400),
            ("key.pem", &private_key, 0o600),
            ("ca.pem", &ca_bundle, 0o400),
        ] {
            fs::copy(source.join(source_name), destination).unwrap();
            fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
        }
        fs::write(&token, b"cleanup-state-token").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        crate::controller_state_transport::allow_test_bound_port(endpoint.port());
        let server_inputs =
            crate::controller_state_transport::server_inputs(certificate, private_key);
        let binding = crate::controller_state_transport::role_binding(
            Role::Cleanup,
            "cleanup-uid".to_owned(),
        )
        .unwrap();
        let (transport, mut token_review_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let token_reviews = tokio::spawn(async move {
            for _ in 0..8 {
                let (request, send) = token_review_handle.next_request().await.unwrap();
                let body: Value =
                    serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                assert_eq!(body["spec"]["token"], "cleanup-state-token");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(kube::client::Body::from(
                            serde_json::to_vec(&json!({
                                "apiVersion":"authentication.k8s.io/v1",
                                "kind":"TokenReview",
                                "metadata":{},
                                "spec":body["spec"],
                                "status":{
                                    "authenticated":true,
                                    "audiences":["https://kapsel.dev/sandbox/controller-state/v1"],
                                    "user":{
                                        "username":concat!(
                                            "system:serviceaccount:kapsel-sandbox-system:",
                                            "sandbox-cleanup"
                                        ),
                                        "uid":"cleanup-uid"
                                    }
                                }
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                );
            }
        });
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            for request_index in 0..8 {
                let (connection, _) = listener.accept().await.unwrap();
                let service = server_service.clone();
                crate::controller_state_transport::handle_connection(
                    connection,
                    &server_inputs,
                    &binding,
                    KubernetesClient::new(transport.clone(), "default"),
                    move |payload| async move {
                        let now = if request_index >= 4 {
                            NOW + 902
                        } else {
                            NOW + 2
                        };
                        handle(&service, &payload, now)
                    },
                )
                .await
                .unwrap();
            }
        });
        let digest: [u8; 32] = Sha256::digest(fs::read(&ca_bundle).unwrap()).into();
        let client = CleanupStateClient::new(endpoint, ca_bundle, digest, 1, token).unwrap();

        let candidate = client.list_candidates().await.unwrap().remove(0);
        client.start_cleanup(&candidate).await.unwrap();
        client.record_failure(&candidate).await.unwrap();
        let failed = client.list_candidates().await.unwrap().remove(0);
        client.escalate_cleanup(&failed).await.unwrap();
        let escalated = client.list_candidates().await.unwrap().remove(0);
        assert!(escalated.escalated);
        let evidence = CleanupAbsenceEvidence {
            namespace_uid: escalated.namespace_uid.clone(),
            objects: escalated
                .objects
                .iter()
                .map(|object| CleanupObjectAbsence {
                    kind: object.kind.clone(),
                    namespace: object.namespace.clone(),
                    name: object.name.clone(),
                    uid: object.uid.clone(),
                    owner_label: object.owner_label.clone(),
                    present: false,
                })
                .collect(),
        };
        client
            .complete_cleanup(&escalated, &evidence)
            .await
            .unwrap();
        assert!(client.list_candidates().await.unwrap().is_empty());
        server.await.unwrap();
        token_reviews.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[allow(
        clippy::panic,
        clippy::too_many_lines,
        reason = "intentional handler panic drops each committed response before transport reply"
    )]
    async fn fresh_remote_client_relists_and_continues_after_each_committed_response_loss() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        for operation in ["start", "failure", "escalation", "completion"] {
            let (root, service) = fixture(true);
            let owner = format!("cleanup-{RUN}");
            if matches!(operation, "failure" | "escalation" | "completion") {
                service
                    .start_cleanup(RUN, &owner, "uid-00", NOW + 2)
                    .unwrap();
            }
            if operation == "escalation" {
                service
                    .fail_cleanup(RUN, &owner, "uid-00", NOW + 2)
                    .unwrap();
            }
            let candidate = service.cleanup_candidates().unwrap().remove(0);
            let evidence = CleanupAbsenceEvidence {
                namespace_uid: candidate.namespace_uid.clone(),
                objects: candidate
                    .objects
                    .iter()
                    .map(|object| CleanupObjectAbsence {
                        kind: object.kind.clone(),
                        namespace: object.namespace.clone(),
                        name: object.name.clone(),
                        uid: object.uid.clone(),
                        owner_label: object.owner_label.clone(),
                        present: false,
                    })
                    .collect(),
            };
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/controller-transport/current");
            let certificate = root.join("tls.crt");
            let private_key = root.join("tls.key");
            let ca_bundle = root.join("ca.crt");
            let token = root.join("state-token");
            for (source_name, destination, mode) in [
                ("cert.pem", &certificate, 0o400),
                ("key.pem", &private_key, 0o600),
                ("ca.pem", &ca_bundle, 0o400),
            ] {
                fs::copy(source.join(source_name), destination).unwrap();
                fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
            }
            fs::write(&token, b"cleanup-state-token").unwrap();
            fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            crate::controller_state_transport::allow_test_bound_port(endpoint.port());
            let inputs = crate::controller_state_transport::server_inputs(
                certificate.clone(),
                private_key.clone(),
            );
            let binding = crate::controller_state_transport::role_binding(
                Role::Cleanup,
                "cleanup-uid".to_owned(),
            )
            .unwrap();
            let (transport, mut token_handle) = mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let token_review = tokio::spawn(async move {
                let (request, send) = token_handle.next_request().await.unwrap();
                let body: Value =
                    serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                send.send_response(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(kube::client::Body::from(
                            serde_json::to_vec(&json!({
                                "apiVersion":"authentication.k8s.io/v1",
                                "kind":"TokenReview",
                                "metadata":{},
                                "spec":body["spec"],
                                "status":{
                                    "authenticated":true,
                                    "audiences":["https://kapsel.dev/sandbox/controller-state/v1"],
                                    "user":{
                                        "username":concat!(
                                            "system:serviceaccount:kapsel-sandbox-system:",
                                            "sandbox-cleanup"
                                        ),
                                        "uid":"cleanup-uid"
                                    }
                                }
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                );
            });
            let committed_service = service.clone();
            let server = tokio::spawn(async move {
                let (connection, _) = listener.accept().await.unwrap();
                crate::controller_state_transport::handle_connection(
                    connection,
                    &inputs,
                    &binding,
                    KubernetesClient::new(transport, "default"),
                    move |payload| async move {
                        let now = if operation == "escalation" {
                            NOW + 902
                        } else {
                            NOW + 3
                        };
                        let response = handle(&committed_service, &payload, now);
                        assert!(matches!(
                            decode_response(&response),
                            Ok(ResponseDto::Committed {})
                        ));
                        panic!("drop committed response")
                    },
                )
                .await
                .unwrap();
            });
            let digest: [u8; 32] = Sha256::digest(fs::read(&ca_bundle).unwrap()).into();
            let client =
                CleanupStateClient::new(endpoint, ca_bundle.clone(), digest, 1, token.clone())
                    .unwrap();
            let result = match operation {
                "start" => client.start_cleanup(&candidate).await,
                "failure" => client.record_failure(&candidate).await,
                "escalation" => client.escalate_cleanup(&candidate).await,
                "completion" => client.complete_cleanup(&candidate, &evidence).await,
                _ => unreachable!(),
            };
            assert_eq!(result, Err(CleanupStateError::Transport), "{operation}");
            assert!(server.await.is_err(), "{operation}");
            token_review.await.unwrap();

            let recovery_now = match operation {
                "failure" => NOW + 902,
                "escalation" => NOW + 903,
                _ => NOW + 4,
            };
            let recovery_requests = if operation == "completion" { 1 } else { 2 };
            let (recovery_endpoint, recovery_server) = start_authenticated_test_server(
                service.clone(),
                certificate,
                private_key,
                recovery_now,
                recovery_requests,
            )
            .await;
            let fresh_client =
                CleanupStateClient::new(recovery_endpoint, ca_bundle, digest, 1, token).unwrap();
            let relisted = fresh_client.list_candidates().await.unwrap();
            match operation {
                "start" => {
                    assert_eq!(relisted[0].state, "running");
                    fresh_client.record_failure(&relisted[0]).await.unwrap();
                },
                "failure" => {
                    assert_eq!(relisted[0].state, "failed");
                    fresh_client.escalate_cleanup(&relisted[0]).await.unwrap();
                },
                "escalation" => {
                    assert!(relisted[0].escalated);
                    fresh_client
                        .complete_cleanup(&relisted[0], &evidence)
                        .await
                        .unwrap();
                },
                "completion" => assert!(relisted.is_empty()),
                _ => unreachable!(),
            }
            recovery_server.await.unwrap();
            let continued = service.cleanup_candidates().unwrap();
            match operation {
                "start" => assert_eq!(continued[0].state, "failed"),
                "failure" => assert!(continued[0].escalated),
                "escalation" | "completion" => assert!(continued.is_empty()),
                _ => unreachable!(),
            }
            let snapshot = service.snapshot(RUN, NOW + 903).unwrap();
            assert!(snapshot.receiver_result.is_none());
            assert!(!snapshot.receipt_available);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn concrete_local_client_crosses_all_cleanup_operations() {
        let (root, service) = fixture(true);
        let client = CleanupStateClient::local(service.clone());
        client.set_test_now(NOW + 2);
        let candidate = client.list_candidates().await.unwrap().remove(0);
        assert_eq!(candidate.state, "pending");
        client.start_cleanup(&candidate).await.unwrap();
        client.record_failure(&candidate).await.unwrap();
        client.set_test_now(NOW + 902);
        let failed = client.list_candidates().await.unwrap().remove(0);
        client.escalate_cleanup(&failed).await.unwrap();
        let escalated = client.list_candidates().await.unwrap().remove(0);
        assert!(escalated.escalated);
        let evidence = CleanupAbsenceEvidence {
            namespace_uid: escalated.namespace_uid.clone(),
            objects: escalated
                .objects
                .iter()
                .map(|object| CleanupObjectAbsence {
                    kind: object.kind.clone(),
                    namespace: object.namespace.clone(),
                    name: object.name.clone(),
                    uid: object.uid.clone(),
                    owner_label: object.owner_label.clone(),
                    present: false,
                })
                .collect(),
        };
        client
            .complete_cleanup(&escalated, &evidence)
            .await
            .unwrap();
        assert!(client.list_candidates().await.unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

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
