//! Bounded effect continuation exploration over real journal transitions
//! and private receiver seams.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    gateway::{exploration_git_approval, ExplorationGitBarrier, ExplorationGitScript},
    ApplyOutcome, ApprovedTarget, AuthorizationTrust, DeploymentImageAdapter, ExactAuthorization,
    FaultPoint, Gateway, GatewayError, GitAcknowledgement, GitObservedRef, OperationResult,
    OperationState, ReceiptSettings, ReceiverObservation, SetDeploymentImageRequest,
    TargetIdentity, TargetReadError,
};

const IMAGE: &str = concat!(
    "registry.example/api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);
const DEFAULT_SEED: u64 = 0x004b_4150_3130_3801;
const TRACE_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Effect {
    Kubernetes,
    Git,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Receiver {
    Healthy,
    Failed,
    Pending,
    Replaced,
    StaleVersion,
    WrongGeneration,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stop {
    None,
    BeforeAttempt,
    UnsentAttempt,
    AttemptAcknowledgementLost,
    ResponseLost,
    ResponseRecorded,
    ObservationLost,
    ObservationRecorded,
}

impl Stop {
    fn fault(self) -> Option<FaultPoint> {
        match self {
            Self::None => None,
            Self::BeforeAttempt => Some(FaultPoint::TargetObserved),
            Self::UnsentAttempt => Some(FaultPoint::ApplyStartedCommitted),
            Self::AttemptAcknowledgementLost => Some(FaultPoint::AttemptCommitAcknowledgementLost),
            Self::ResponseLost => Some(FaultPoint::ApplyReturned),
            Self::ResponseRecorded => Some(FaultPoint::ApplyOutcomeCommitted),
            Self::ObservationLost => Some(FaultPoint::ReceiverRead),
            Self::ObservationRecorded => Some(FaultPoint::ReceiverObservedCommitted),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Barrier {
    Preflight,
    Mutation,
    Observation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompletionStop {
    None,
    BeforeCommit,
    AcknowledgementLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdmissionBoundary {
    FirstCommit,
    AuthorizationCommit,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Catalog {
    Original,
    Removed,
    Replaced,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "actor", rename_all = "snake_case")]
enum Event {
    AdmissionLoss {
        id: usize,
        boundary: AdmissionBoundary,
    },
    GatewayWrites {
        enabled: bool,
    },
    ApplicationSelect {
        id: usize,
        catalog: Catalog,
        signing_key: Option<u8>,
    },
    CallerCancelAtBarrier {
        id: usize,
        contender: usize,
        barrier: Barrier,
    },
    CallerSubmit {
        id: usize,
        competing: bool,
    },
    WorkerAdvance {
        id: usize,
        stop: Stop,
    },
    ReceiverChange {
        id: usize,
        receiver: Receiver,
    },
    OperatorReopen {
        trusted: bool,
    },
    WorkerComplete {
        id: usize,
        key: u8,
        stop: CompletionStop,
    },
}

impl Event {
    fn identity(&self) -> Option<usize> {
        match *self {
            Self::AdmissionLoss { id, .. }
            | Self::ApplicationSelect { id, .. }
            | Self::CallerCancelAtBarrier { id, .. }
            | Self::CallerSubmit { id, .. }
            | Self::WorkerAdvance { id, .. }
            | Self::ReceiverChange { id, .. }
            | Self::WorkerComplete { id, .. } => Some(id),
            Self::OperatorReopen { .. } | Self::GatewayWrites { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum InitialState {
    // No retained operations, original fixture trust appointed, healthy unchanged receivers.
    FreshTrustedHealthy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    version: u8,
    seed: u64,
    executable_sha256: String,
    source_sha256: String,
    initial_state: InitialState,
    identities: Vec<String>,
    #[serde(default)]
    effects: Vec<Effect>,
    require_progress: bool,
    events: Vec<Event>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedResult {
    Success,
    Failure,
    Unknown,
}

impl ExpectedResult {
    fn production_value(self) -> OperationResult {
        match self {
            Self::Success => OperationResult::Succeeded,
            Self::Failure => OperationResult::Failed,
            Self::Unknown => OperationResult::Unknown,
        }
    }
}

// This oracle never decodes a SQL phase, builds a receipt, or calls a production classifier.
#[derive(Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent oracle facts do not mirror journal phases"
)]
struct Expectation {
    admitted: bool,
    authorization_pending: bool,
    attempted: bool,
    rejected: bool,
    mutations: usize,
    frozen: Option<ExpectedResult>,
    receipt: Option<Vec<u8>>,
    receipt_signer: Option<(u8, &'static str)>,
    grant: Option<Vec<u8>>,
    git_acknowledgement: Option<ExpectedResult>,
    git_present_ref: Option<GitObservedRef>,
    git_observed_ref: Option<GitObservedRef>,
}

impl Expectation {
    fn git_acknowledgement(&self) -> Option<GitAcknowledgement> {
        self.git_acknowledgement.map(|result| match result {
            ExpectedResult::Success => GitAcknowledgement::Updated,
            ExpectedResult::Failure => GitAcknowledgement::ReceiverRejected,
            ExpectedResult::Unknown => GitAcknowledgement::Unknown,
        })
    }
}

struct ReceiverState {
    mutations: usize,
    reads: usize,
    receiver: Receiver,
    violation: Option<&'static str>,
}

struct Adapter<'a> {
    state: &'a mut ReceiverState,
    barrier: Option<Barrier>,
    journal: &'a Path,
    identity: &'a str,
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "matches the private async receiver seam"
)]
impl DeploymentImageAdapter for Adapter<'_> {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        self.state.reads += 1;
        if matches!(self.barrier, Some(Barrier::Preflight)) {
            std::future::pending::<()>().await;
        }
        if matches!(self.state.receiver, Receiver::Unavailable) {
            return Err(TargetReadError::Transient);
        }
        Ok(TargetIdentity {
            deployment_uid: if matches!(self.state.receiver, Receiver::Replaced) {
                "replacement-uid".into()
            } else {
                target_uid(&request.operation_id)
            },
            resource_version: if matches!(self.state.receiver, Receiver::StaleVersion) {
                "2"
            } else {
                "1"
            }
            .into(),
        })
    }

    async fn apply(
        &mut self,
        permission: crate::gateway::DispatchPermission,
    ) -> Result<ApplyOutcome, ()> {
        let (request, target) = permission.into_payload();
        if request != crate::lifecycle_exploration_tests::request(self.identity)
            || target.deployment_uid != target_uid(self.identity)
            || target.resource_version != "1"
        {
            self.state.violation = Some("permission_binding");
            return Err(());
        }
        let phase =
            Gateway::open_for_test(self.journal).and_then(|gateway| gateway.get(self.identity));
        if !matches!(phase, Ok(Some(OperationState::ApplyStarted))) {
            self.state.violation = Some("dispatch_before_commit");
            return Err(());
        }
        self.state.mutations += 1;
        if matches!(self.barrier, Some(Barrier::Mutation)) {
            std::future::pending::<()>().await;
        }
        Ok(ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some(target_uid(&request.operation_id)),
            resource_version: Some("2".into()),
        })
    }

    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        _: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        self.state.reads += 1;
        if matches!(self.barrier, Some(Barrier::Observation)) {
            std::future::pending::<()>().await;
        }
        if matches!(self.state.receiver, Receiver::Unavailable) {
            return Err(());
        }
        // An unsent permission leaves the receiver unchanged. A fabricated success observation
        // here would teach the model the very false-success behaviour it needs to detect.
        let sent = self.state.mutations > 0;
        let failed = matches!(self.state.receiver, Receiver::Failed);
        // Correlation failures must have otherwise healthy rollout facts, so removing UID or
        // generation checks cannot hide behind an unrelated unhealthy condition.
        let healthy = matches!(
            self.state.receiver,
            Receiver::Healthy | Receiver::Replaced | Receiver::WrongGeneration
        );
        Ok(ReceiverObservation {
            deployment_uid: Some(if matches!(self.state.receiver, Receiver::Replaced) {
                "replacement-uid".into()
            } else {
                target_uid(&request.operation_id)
            }),
            resource_version: Some(if sent { "2" } else { "1" }.into()),
            current_generation: Some(if sent { 2 } else { 1 }),
            observed_generation: Some(
                if matches!(self.state.receiver, Receiver::WrongGeneration) {
                    1
                } else if sent {
                    2
                } else {
                    1
                },
            ),
            image: sent.then(|| request.immutable_image_digest.clone()),
            operation_marker: sent.then(|| request.operation_id.clone()),
            desired_replicas: Some(1),
            updated_replicas: Some(i32::from(healthy)),
            available_replicas: Some(i32::from(healthy)),
            unavailable_replicas: Some(i32::from(!healthy)),
            rollout_condition_type: Some(if failed { "Progressing" } else { "Available" }.into()),
            rollout_condition_status: Some(if healthy { "True" } else { "False" }.into()),
            rollout_condition_reason: failed.then(|| "ProgressDeadlineExceeded".into()),
        })
    }
}

#[derive(Debug)]
struct Finding {
    invariant: &'static str,
    event: usize,
}

type RunResult = Result<(), Finding>;

fn check(condition: bool, invariant: &'static str, event: usize) -> RunResult {
    if condition {
        Ok(())
    } else {
        Err(Finding { invariant, event })
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kapsel-exploration-{}-{nonce}-{sequence}",
            std::process::id(),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The trace, not this disposable database, is the replay input.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn stored_fact<T>(result: Result<T, GatewayError>, event: usize) -> Result<T, Finding> {
    result.map_err(|_| Finding {
        invariant: "durable_history",
        event,
    })
}

struct Snapshot {
    grant: Vec<u8>,
    state: OperationState,
    result: Option<OperationResult>,
    rejection: Option<crate::TargetRejection>,
    original_request: bool,
    receipt: Option<Vec<u8>>,
    git_targets: Option<crate::GitOperationTargets>,
}

impl Trace {
    fn effect(&self, id: usize) -> Effect {
        self.effects.get(id).copied().unwrap_or(Effect::Kubernetes)
    }
}

fn snapshot(
    gateway: &Gateway,
    effect: Effect,
    id: &str,
    event: usize,
) -> Result<Snapshot, Finding> {
    let missing = Finding {
        invariant: "durable_history",
        event,
    };
    match effect {
        Effect::Kubernetes => {
            let retained = stored_fact(gateway.retained_operation(id), event)?.ok_or(missing)?;
            let state = stored_fact(gateway.get(id), event)?.ok_or(Finding {
                invariant: "durable_history",
                event,
            })?;
            Ok(Snapshot {
                grant: retained.signed_grant,
                state,
                result: stored_fact(gateway.result(id), event)?,
                rejection: stored_fact(gateway.target_rejection(id), event)?,
                original_request: retained.request == request(id),
                git_targets: None,
                receipt: if state == OperationState::Finalized {
                    Some(receipt_bytes(gateway, id, event)?)
                } else {
                    None
                },
            })
        },
        Effect::Git => {
            let retained = stored_fact(gateway.retained_git(id), event)?.ok_or(missing)?;
            Ok(Snapshot {
                grant: retained.signed_grant,
                state: retained.state,
                result: retained.result,
                rejection: retained.rejection,
                original_request: retained.targets.approval == exploration_git_approval(id),
                receipt: retained.receipt.map(|(bytes, _)| bytes),
                git_targets: Some(retained.targets),
            })
        },
    }
}

fn effect_receipt_bytes(
    gateway: &Gateway,
    effect: Effect,
    id: &str,
    event: usize,
) -> Result<Vec<u8>, Finding> {
    snapshot(gateway, effect, id, event)?
        .receipt
        .ok_or(Finding {
            invariant: "completion_state",
            event,
        })
}

fn receipt_bytes(gateway: &Gateway, id: &str, event: usize) -> Result<Vec<u8>, Finding> {
    let failure = || Finding {
        invariant: "completion_state",
        event,
    };
    let operation = gateway
        .loaded_for_test(id)
        .map_err(|_| failure())?
        .ok_or_else(failure)?;
    Gateway::read_loaded_receipt(operation)
        .map(|(bytes, _)| bytes)
        .map_err(|_| failure())
}

fn has_healthy_suffix(trace: &Trace) -> bool {
    let Some(offset) = trace
        .events
        .len()
        .checked_sub(2 + 7 * trace.identities.len())
    else {
        return false;
    };
    if !matches!(trace.events[offset], Event::GatewayWrites { enabled: true })
        || !matches!(
            trace.events[offset + 1],
            Event::OperatorReopen { trusted: true }
        )
    {
        return false;
    }
    for (id, events) in trace.events[offset + 2..]
        .as_chunks::<7>()
        .0
        .iter()
        .enumerate()
    {
        if !matches!(events,
            [Event::CallerSubmit { id: caller_id, competing: false },
             Event::ReceiverChange { id: receiver_id, receiver: Receiver::Healthy },
             Event::WorkerAdvance { id: first_advance, stop: Stop::None },
             Event::WorkerComplete { id: first_completion, .. },
             Event::OperatorReopen { trusted: true },
             Event::WorkerAdvance { id: second_advance, stop: Stop::None },
             Event::WorkerComplete {
                 id: second_completion, stop: CompletionStop::None, ..
             }]
            if [*caller_id, *receiver_id, *first_advance, *first_completion,
                *second_advance, *second_completion] == [id; 6]
        ) {
            return false;
        }
    }
    true
}

fn fixture_trust() -> AuthorizationTrust {
    AuthorizationTrust {
        key_id: "effect-gateway-authorization-test-key".into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    }
}

fn original_grant(effect: Effect, id: &str) -> Vec<u8> {
    match effect {
        Effect::Kubernetes => crate::gateway::sign_authorization_grant(
            &authorization(&request(id)),
            &[7; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap(),
        Effect::Git => kapsel_authority::sign_git_ref_grant(
            &exploration_git_approval(id),
            &[7; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap(),
    }
}

fn replacement_grant(effect: Effect, id: &str) -> Vec<u8> {
    match effect {
        Effect::Kubernetes => {
            let mut request = request(id);
            request.deployment = "replacement-api".into();
            crate::gateway::sign_authorization_grant(
                &authorization(&request),
                &[7; 32],
                "effect-gateway-authorization-test-key",
            )
            .unwrap()
        },
        Effect::Git => {
            let mut approval = exploration_git_approval(id);
            approval.new_commit = "c".repeat(40);
            kapsel_authority::sign_git_ref_grant(
                &approval,
                &[7; 32],
                "effect-gateway-authorization-test-key",
            )
            .unwrap()
        },
    }
}

fn target_uid(id: &str) -> String {
    format!("uid-{id}")
}

fn request(id: &str) -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: id.into(),
        namespace: "demo".into(),
        deployment: format!("api-{id}"),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    }
}

fn authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
    ExactAuthorization {
        authorization_id: format!("approval-{}", request.operation_id),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
        approved_target: Some(ApprovedTarget {
            uid: target_uid(&request.operation_id),
            resource_version: "1".into(),
        }),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep the event oracle and its production transition adjacent for review"
)]
async fn replay(trace: &Trace) -> RunResult {
    check(trace.version == 1, "trace_version", 0)?;
    check(
        (2..=4).contains(&trace.identities.len()),
        "identity_bound",
        0,
    )?;
    check(trace.events.len() <= 512, "event_bound", 0)?;
    check(
        trace.effects.is_empty() || trace.effects.len() == trace.identities.len(),
        "effect_bound",
        0,
    )?;
    if trace.require_progress {
        check(has_healthy_suffix(trace), "progress_prerequisite", 0)?;
    }
    let scratch = Scratch::new();
    let journal = scratch.0.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&journal).unwrap();
    let mut trusted = true;
    let mut writing = true;
    let scripts: Vec<_> = trace
        .identities
        .iter()
        .map(|id| ExplorationGitScript::new(id, journal.clone()))
        .collect();
    let mut expected: Vec<_> = trace
        .identities
        .iter()
        .enumerate()
        .map(|(id, identity)| Expectation {
            grant: Some(original_grant(trace.effect(id), identity)),
            git_present_ref: Some(GitObservedRef::Commit("a".repeat(40))),
            ..Expectation::default()
        })
        .collect();
    let mut receivers: Vec<_> = trace
        .identities
        .iter()
        .map(|_| ReceiverState {
            mutations: 0,
            reads: 0,
            receiver: Receiver::Healthy,
            violation: None,
        })
        .collect();

    for (index, event) in trace.events.iter().enumerate() {
        if let Some(id) = event.identity() {
            check(id < expected.len(), "event_identity", index)?;
        }
        match *event {
            Event::AdmissionLoss { id, boundary } => {
                check(
                    trusted && writing && !expected[id].admitted,
                    "prerequisite",
                    index,
                )?;
                let result = match trace.effect(id) {
                    Effect::Kubernetes => {
                        let request = request(&trace.identities[id]);
                        gateway
                            .submit_exact_with_fault_for_test(
                                &request,
                                &authorization(&request),
                                Some(match boundary {
                                    AdmissionBoundary::FirstCommit => {
                                        FaultPoint::RequestedCommitted
                                    },
                                    AdmissionBoundary::AuthorizationCommit => {
                                        FaultPoint::AuthorizedCommitted
                                    },
                                }),
                            )
                            .map(|_| ())
                    },
                    Effect::Git => {
                        ExplorationGitScript::submit(&gateway, &trace.identities[id], false)
                            .and_then(|()| Err(GatewayError::InjectedFault))
                    },
                };
                check(
                    matches!(result, Err(GatewayError::InjectedFault)),
                    "admission_ack_loss",
                    index,
                )?;
                expected[id].admitted = true;
                expected[id].authorization_pending = matches!(trace.effect(id), Effect::Kubernetes)
                    && matches!(boundary, AdmissionBoundary::FirstCommit);
            },
            Event::GatewayWrites { enabled } => {
                writing = enabled;
                stored_fact(gateway.exploration_write_failure(!writing), index)?;
            },
            Event::ApplicationSelect {
                id,
                catalog,
                signing_key,
            } => {
                check(expected[id].admitted, "prerequisite", index)?;
                let original = expected[id].grant.as_ref().unwrap().clone();
                let grant = match catalog {
                    Catalog::Original => Some(original),
                    Catalog::Removed => None,
                    Catalog::Replaced => {
                        Some(replacement_grant(trace.effect(id), &trace.identities[id]))
                    },
                };
                let app = crate::ServiceApplication::open(crate::ServiceConfiguration {
                    journal_path: journal.clone(),
                    authorization_trust: if trusted {
                        vec![fixture_trust()]
                    } else {
                        Vec::new()
                    },
                    approvals: grant
                        .into_iter()
                        .map(|signed_grant| crate::ServiceApproval {
                            signed_grant,
                            label: "exploration approval".into(),
                        })
                        .collect(),
                });
                if matches!(catalog, Catalog::Replaced)
                    || (!trusted && !matches!(catalog, Catalog::Removed))
                {
                    check(app.is_err(), "catalog_identity_conflict", index)?;
                } else {
                    let mut app = app.map_err(|_| Finding {
                        invariant: "application_open",
                        event: index,
                    })?;
                    app.exploration_write_failure(!writing)
                        .map_err(|_| Finding {
                            invariant: "storage_fault_setup",
                            event: index,
                        })?;
                    let mut acknowledged = None;
                    let result = app
                        .select(
                            &trace.identities[id],
                            crate::ServiceExecution {
                                kubernetes_client: None,
                                git_receiver: None,
                                receipt_signing: signing_key
                                    .map(|key| ([key; 32], "application-receipt".into())),
                            },
                            |admission| acknowledged = Some(admission),
                        )
                        .await;
                    if trusted {
                        check(
                            !writing || (result.is_ok() && acknowledged.is_some()),
                            "application_admission",
                            index,
                        )?;
                        if !writing && acknowledged.is_none() {
                            check(
                                matches!(result, Err(crate::ServiceError::StorageUnavailable)),
                                "storage_admission_unconfirmed",
                                index,
                            )?;
                        }
                        if writing {
                            expected[id].authorization_pending = false;
                        }
                        if let Some(key) = signing_key {
                            if writing && expected[id].frozen.is_some() {
                                let bytes = effect_receipt_bytes(
                                    &gateway,
                                    trace.effect(id),
                                    &trace.identities[id],
                                    index,
                                )?;
                                if let Some(original) = &expected[id].receipt {
                                    check(*original == bytes, "immutable_receipt", index)?;
                                } else {
                                    expected[id].receipt = Some(bytes);
                                    expected[id].receipt_signer =
                                        Some((key, "application-receipt"));
                                }
                            }
                        }
                    } else {
                        check(
                            result.is_err() && acknowledged.is_none(),
                            "external_trust",
                            index,
                        )?;
                        check(
                            app.status(&trace.identities[id]).is_err(),
                            "trust_non_disclosure",
                            index,
                        )?;
                        check(
                            app.receipt(&trace.identities[id]).is_err(),
                            "trust_non_disclosure",
                            index,
                        )?;
                    }
                }
            },
            Event::CallerCancelAtBarrier {
                id,
                contender,
                barrier,
            } => {
                check(
                    contender < expected.len() && contender != id,
                    "prerequisite",
                    index,
                )?;
                check(
                    trusted
                        && writing
                        && expected[id].admitted
                        && expected[contender].admitted
                        && !expected[id].authorization_pending
                        && !expected[id].attempted
                        && !expected[id].rejected
                        && expected[id].frozen.is_none(),
                    "prerequisite",
                    index,
                )?;
                check(
                    !matches!(
                        receivers[id].receiver,
                        Receiver::Unavailable | Receiver::Replaced | Receiver::StaleVersion
                    ),
                    "prerequisite",
                    index,
                )?;
                contend_then_cancel(
                    &mut gateway,
                    &journal,
                    trace,
                    &mut receivers,
                    &scripts,
                    (id, contender, barrier),
                    index,
                )
                .await?;
                if !matches!(barrier, Barrier::Preflight) {
                    expected[id].attempted = true;
                    expected[id].mutations = 1;
                    if matches!(receivers[id].receiver, Receiver::Healthy) {
                        expected[id].git_present_ref = Some(GitObservedRef::Commit("b".repeat(40)));
                    }
                    if matches!(trace.effect(id), Effect::Git)
                        && matches!(barrier, Barrier::Observation)
                    {
                        expected[id].git_acknowledgement = Some(match receivers[id].receiver {
                            Receiver::Healthy => ExpectedResult::Success,
                            Receiver::Failed => ExpectedResult::Failure,
                            _ => ExpectedResult::Unknown,
                        });
                    }
                }
            },
            Event::CallerSubmit { id, competing } => {
                let mut request = request(&trace.identities[id]);
                if competing {
                    request.deployment = "competing-api".into();
                }
                let result = match trace.effect(id) {
                    Effect::Kubernetes => gateway
                        .submit_exact_for_test(&request, &authorization(&request))
                        .map(|_| ()),
                    Effect::Git => {
                        ExplorationGitScript::submit(&gateway, &trace.identities[id], competing)
                    },
                };
                if !trusted {
                    check(result.is_err(), "external_trust", index)?;
                } else if !writing && (!expected[id].admitted || expected[id].authorization_pending)
                {
                    check(result.is_err(), "failed_admission", index)?;
                } else if competing && expected[id].admitted {
                    check(
                        matches!(result, Err(GatewayError::OperationIdentityConflict)),
                        "identity_conflict",
                        index,
                    )?;
                } else {
                    // A competing tuple before original admission is outside this trace's initial
                    // authority. Reject the schedule rather than silently changing the oracle.
                    check(!competing, "prerequisite", index)?;
                    check(result.is_ok(), "admission", index)?;
                    expected[id].admitted = true;
                    expected[id].authorization_pending = false;
                }
            },
            Event::ReceiverChange { id, receiver } => {
                receivers[id].receiver = receiver;
                // Model external ref changes from the trace, never from the scripted receiver.
                let commit = if expected[id].attempted
                    && (expected[id].mutations > 0 || matches!(receiver, Receiver::Pending))
                {
                    if matches!(receiver, Receiver::Replaced) {
                        "c"
                    } else {
                        "b"
                    }
                } else {
                    "a"
                };
                expected[id].git_present_ref = Some(GitObservedRef::Commit(commit.repeat(40)));
                configure_git(&scripts[id], receiver, expected[id].attempted);
            },
            Event::OperatorReopen {
                trusted: replacement,
            } => {
                drop(gateway);
                trusted = replacement;
                gateway = if trusted {
                    stored_fact(Gateway::open_for_test(&journal), index)?
                } else {
                    stored_fact(
                        Gateway::open_with_authorities(&journal, Vec::<AuthorizationTrust>::new()),
                        index,
                    )?
                };
                stored_fact(gateway.exploration_write_failure(!writing), index)?;
            },
            Event::WorkerAdvance { id, stop } => {
                check(expected[id].admitted, "prerequisite", index)?;
                let old_mutations = receivers[id].mutations;
                let old_reads = receivers[id].reads;
                let already_frozen = expected[id].frozen.is_some() || expected[id].rejected;
                scripts[id].state.lock().unwrap().fault = stop.fault();
                let result = effect_advance(
                    &mut gateway,
                    trace.effect(id),
                    &trace.identities[id],
                    &mut Adapter {
                        state: &mut receivers[id],
                        barrier: None,
                        journal: &journal,
                        identity: &trace.identities[id],
                    },
                    &scripts[id],
                    stop.fault(),
                )
                .await;
                refresh_counters(trace.effect(id), &mut receivers[id], &scripts[id]);
                if let Some(invariant) = receivers[id].violation {
                    return Err(Finding {
                        invariant,
                        event: index,
                    });
                }
                if !trusted {
                    check(result.is_err(), "external_trust", index)?;
                } else if !already_frozen {
                    let stale = matches!(
                        receivers[id].receiver,
                        Receiver::Replaced | Receiver::StaleVersion,
                    );
                    let available = !matches!(receivers[id].receiver, Receiver::Unavailable);
                    let fresh = !expected[id].attempted;
                    let rejects_during_preflight = matches!(trace.effect(id), Effect::Git) && stale;
                    if writing
                        && available
                        && fresh
                        && !stale
                        && !expected[id].authorization_pending
                        && !matches!(stop, Stop::None)
                    {
                        check(
                            matches!(result, Err(GatewayError::InjectedFault)),
                            "interruption_checkpoint",
                            index,
                        )?;
                    }
                    if writing
                        && available
                        && fresh
                        && !expected[id].authorization_pending
                        && (!matches!(stop, Stop::BeforeAttempt) || rejects_during_preflight)
                    {
                        if stale {
                            expected[id].rejected = true;
                        } else {
                            expected[id].attempted = true;
                        }
                        if !stale
                            && !matches!(
                                stop,
                                Stop::UnsentAttempt | Stop::AttemptAcknowledgementLost
                            )
                        {
                            expected[id].mutations += 1;
                            if matches!(receivers[id].receiver, Receiver::Healthy) {
                                expected[id].git_present_ref =
                                    Some(GitObservedRef::Commit("b".repeat(40)));
                            }
                        }
                    }
                    if writing
                        && fresh
                        && expected[id].mutations > 0
                        && matches!(trace.effect(id), Effect::Git)
                        && matches!(
                            stop,
                            Stop::None
                                | Stop::ResponseRecorded
                                | Stop::ObservationLost
                                | Stop::ObservationRecorded
                        )
                    {
                        expected[id].git_acknowledgement = Some(match receivers[id].receiver {
                            Receiver::Healthy => ExpectedResult::Success,
                            Receiver::Failed => ExpectedResult::Failure,
                            _ => ExpectedResult::Unknown,
                        });
                    }
                    let can_observe =
                        available || (matches!(trace.effect(id), Effect::Git) && !fresh);
                    let frozen = writing
                        && can_observe
                        && !expected[id].authorization_pending
                        && !expected[id].rejected
                        && ((!fresh && expected[id].attempted)
                            || (fresh && matches!(stop, Stop::None | Stop::ObservationRecorded)));
                    if frozen {
                        expected[id].frozen = Some(if matches!(trace.effect(id), Effect::Git) {
                            // Freezing records UNKNOWN when the attempt had no acknowledgement.
                            let acknowledgement = expected[id]
                                .git_acknowledgement
                                .unwrap_or(ExpectedResult::Unknown);
                            expected[id].git_acknowledgement = Some(acknowledgement);
                            expected[id].git_observed_ref = Some(if available {
                                expected[id].git_present_ref.as_ref().unwrap().clone()
                            } else {
                                GitObservedRef::Unknown
                            });
                            acknowledgement
                        } else if expected[id].mutations == 0 {
                            ExpectedResult::Unknown
                        } else {
                            match receivers[id].receiver {
                                Receiver::Healthy => ExpectedResult::Success,
                                Receiver::Failed => ExpectedResult::Failure,
                                Receiver::Pending
                                | Receiver::Replaced
                                | Receiver::StaleVersion
                                | Receiver::WrongGeneration
                                | Receiver::Unavailable => ExpectedResult::Unknown,
                            }
                        });
                    }
                    check(
                        result.is_ok()
                            || (!writing && matches!(result, Err(GatewayError::Database(_))))
                            || matches!(
                                result,
                                Err(GatewayError::InjectedFault
                                    | GatewayError::KubernetesTargetObservation
                                    | GatewayError::KubernetesReceiverObservation
                                    | GatewayError::GitReceiverUnavailable)
                            ),
                        "continuation_error",
                        index,
                    )?;
                }
                if !trusted || already_frozen {
                    check(
                        receivers[id].reads == old_reads,
                        "frozen_receiver_io",
                        index,
                    )?;
                    check(result.is_ok() || !trusted, "frozen_continuation", index)?;
                }
                check(
                    receivers[id].mutations >= old_mutations,
                    "mutation_counter",
                    index,
                )?;
            },
            Event::WorkerComplete { id, key, stop } => {
                check(expected[id].admitted, "prerequisite", index)?;
                // Completion's private seam bypasses authentication. Do not mistake it for a
                // service trust test: only drive it while external authority is available.
                check(trusted, "prerequisite", index)?;
                let seed = [key; 32];
                let settings = ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "exploration-receipt",
                };
                let fault = match stop {
                    CompletionStop::None => None,
                    CompletionStop::BeforeCommit => Some(FaultPoint::BeforeReceiptCommit),
                    CompletionStop::AcknowledgementLost => {
                        Some(FaultPoint::ReceiptCommitAcknowledgementLost)
                    },
                };
                scripts[id].state.lock().unwrap().fault = fault;
                let old_reads = receivers[id].reads;
                let result = match trace.effect(id) {
                    Effect::Kubernetes => gateway.finalize_operation_receipt_once_with_fault(
                        &trace.identities[id],
                        &settings,
                        fault,
                    ),
                    Effect::Git => {
                        scripts[id]
                            .advance(&mut gateway, &trace.identities[id], Some(&settings), true)
                            .await
                    },
                };
                refresh_counters(trace.effect(id), &mut receivers[id], &scripts[id]);
                check(
                    receivers[id].reads == old_reads,
                    "frozen_receiver_io",
                    index,
                )?;
                check(
                    result.is_ok()
                        || matches!(result, Err(GatewayError::InjectedFault))
                        || (!writing && matches!(result, Err(GatewayError::Database(_)))),
                    "completion_error",
                    index,
                )?;
                if expected[id].frozen.is_some()
                    && (writing || expected[id].receipt.is_some())
                    && (!matches!(stop, CompletionStop::BeforeCommit)
                        || expected[id].receipt.is_some())
                {
                    let bytes = effect_receipt_bytes(
                        &gateway,
                        trace.effect(id),
                        &trace.identities[id],
                        index,
                    )?;
                    if let Some(original) = &expected[id].receipt {
                        check(*original == bytes, "immutable_receipt", index)?;
                    } else {
                        expected[id].receipt = Some(bytes);
                        expected[id].receipt_signer = Some((key, "exploration-receipt"));
                    }
                }
            },
        }
        check_all_identities(&gateway, trace, &expected, &receivers, trusted, index)?;
    }
    if trace.require_progress {
        check(
            expected
                .iter()
                .all(|operation| operation.receipt.is_some() || operation.rejected),
            "bounded_progress",
            trace.events.len(),
        )?;
    }
    Ok(())
}

// Every event checks all identities, including those not selected by the current actor.
fn check_all_identities(
    gateway: &Gateway,
    trace: &Trace,
    expected: &[Expectation],
    receivers: &[ReceiverState],
    trusted: bool,
    event: usize,
) -> RunResult {
    for (id, expectation) in expected.iter().enumerate() {
        if let Some(invariant) = receivers[id].violation {
            return Err(Finding { invariant, event });
        }
        check(
            receivers[id].mutations == expectation.mutations,
            "fresh_permission",
            event,
        )?;
        check(receivers[id].mutations <= 1, "at_most_one_mutation", event)?;
        if !trusted {
            continue;
        }
        if !expectation.admitted {
            let absent = match trace.effect(id) {
                Effect::Kubernetes => {
                    stored_fact(gateway.retained_operation(&trace.identities[id]), event)?.is_none()
                },
                Effect::Git => {
                    stored_fact(gateway.retained_git(&trace.identities[id]), event)?.is_none()
                },
            };
            check(absent, "failed_admission", event)?;
            continue;
        }
        let retained = snapshot(gateway, trace.effect(id), &trace.identities[id], event)?;
        check(
            Some(&retained.grant) == expectation.grant.as_ref(),
            "original_authority",
            event,
        )?;
        check(retained.original_request, "original_request", event)?;
        if let Some(original) = &expectation.receipt {
            check(
                retained.receipt.as_ref() == Some(original),
                "immutable_receipt",
                event,
            )?;
        }
        if let Some(targets) = &retained.git_targets {
            check_git_facts(&retained, targets, expectation, event)?;
        }
        let wanted = if expectation.rejected {
            check(
                retained.rejection
                    == Some(match trace.effect(id) {
                        Effect::Kubernetes => crate::TargetRejection::StaleApproval,
                        Effect::Git => crate::TargetRejection::GitStaleRef,
                    }),
                "stale_approval_rejection",
                event,
            )?;
            OperationState::NotAttempted
        } else if expectation.receipt.is_some() {
            OperationState::Finalized
        } else if expectation.frozen.is_some() {
            OperationState::ReceiverObserved
        } else if expectation.attempted {
            OperationState::ApplyStarted
        } else if expectation.authorization_pending {
            OperationState::Requested
        } else {
            OperationState::Authorized
        };
        check(retained.state == wanted, "durable_history", event)?;
        check(
            retained.result == expectation.frozen.map(ExpectedResult::production_value),
            "independent_receiver_result",
            event,
        )?;
    }
    Ok(())
}

fn check_git_facts(
    retained: &Snapshot,
    targets: &crate::GitOperationTargets,
    expected: &Expectation,
    event: usize,
) -> RunResult {
    check(
        targets.attempted == expected.attempted,
        "git_attempt",
        event,
    )?;
    check(
        targets.acknowledgement == expected.git_acknowledgement(),
        "git_acknowledgement",
        event,
    )?;
    check(
        targets.observed_ref == expected.git_observed_ref,
        "git_observation",
        event,
    )?;
    if let Some(bytes) = &retained.receipt {
        // Trust comes from the original trace-selected signer, not the receipt or current key.
        // The parser supplies authenticated facts; expected receiver truth stays independent.
        let (key, key_id) = expected.receipt_signer.ok_or(Finding {
            invariant: "completion_state",
            event,
        })?;
        let trust = crate::ReceiptTrust {
            key_id: key_id.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[key; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: crate::GIT_RECEIPT_PURPOSE.into(),
            not_before_unix_s: 0,
            not_after_unix_s: 100,
        }
        .encode()
        .unwrap();
        let report =
            crate::inspect_git_receipt(bytes, &trust, 50, crate::InspectionLimits::default());
        check(
            report.status() == crate::InspectionStatus::Inspected,
            "git_receipt_signer",
            event,
        )?;
        let statement = report.statement().ok_or(Finding {
            invariant: "git_receipt_facts",
            event,
        })?;
        check(
            statement.authorization() == &targets.approval
                && Some(statement.acknowledgement()) == expected.git_acknowledgement()
                && Some(statement.observed_ref()) == expected.git_observed_ref.as_ref()
                && statement.authorization_grant_digest()
                    == hex(&Sha256::digest(expected.grant.as_ref().unwrap()))
                && statement.authorization_signer_key_id()
                    == "effect-gateway-authorization-test-key",
            "git_receipt_facts",
            event,
        )?;
    }
    Ok(())
}

async fn contend_then_cancel(
    gateway: &mut Gateway,
    journal: &Path,
    trace: &Trace,
    receivers: &mut [ReceiverState],
    scripts: &[ExplorationGitScript],
    schedule: (usize, usize, Barrier),
    event: usize,
) -> RunResult {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (id, contender, barrier) = schedule;
    let (owner_state, contender_state) = if id < contender {
        let (left, right) = receivers.split_at_mut(contender);
        (&mut left[id], &mut right[0])
    } else {
        let (left, right) = receivers.split_at_mut(id);
        (&mut right[0], &mut left[contender])
    };
    let mut owner = Adapter {
        state: owner_state,
        barrier: Some(barrier),
        journal,
        identity: &trace.identities[id],
    };
    scripts[id].state.lock().unwrap().barrier = Some(match barrier {
        Barrier::Preflight => ExplorationGitBarrier::Preflight,
        Barrier::Mutation => ExplorationGitBarrier::Mutation,
        Barrier::Observation => ExplorationGitBarrier::Observation,
    });
    let mut second_gateway = stored_fact(Gateway::open_for_test(journal), event)?;
    let before = (contender_state.reads, contender_state.mutations);
    {
        let mut active = Box::pin(effect_advance(
            gateway,
            trace.effect(id),
            &trace.identities[id],
            &mut owner,
            &scripts[id],
            None,
        ));
        let parked = matches!(
            active
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        if !parked {
            drop(active);
            refresh_counters(trace.effect(id), owner.state, &scripts[id]);
            return Err(Finding {
                invariant: owner.state.violation.unwrap_or("scheduled_barrier"),
                event,
            });
        }
        let result = effect_advance(
            &mut second_gateway,
            trace.effect(contender),
            &trace.identities[contender],
            &mut Adapter {
                state: contender_state,
                barrier: None,
                journal,
                identity: &trace.identities[contender],
            },
            &scripts[contender],
            None,
        )
        .await;
        refresh_counters(
            trace.effect(contender),
            contender_state,
            &scripts[contender],
        );
        check(matches!(result, Ok(None)), "worker_exclusion", event)?;
        check(
            before == (contender_state.reads, contender_state.mutations),
            "contender_receiver_io",
            event,
        )?;
        // Dropping the suspended future cancels this gateway worker. Runtime blocking-job
        // retirement is a different owner and remains covered by the service process tests.
    }
    scripts[id].state.lock().unwrap().barrier = None;
    refresh_counters(trace.effect(id), owner.state, &scripts[id]);
    Ok(())
}

async fn effect_advance(
    gateway: &mut Gateway,
    effect: Effect,
    id: &str,
    adapter: &mut Adapter<'_>,
    script: &ExplorationGitScript,
    fault: Option<FaultPoint>,
) -> Result<Option<OperationState>, GatewayError> {
    match effect {
        Effect::Kubernetes => {
            gateway
                .run_operation_once_with_adapter_and_fault(id, adapter, fault)
                .await
        },
        Effect::Git => script.advance(gateway, id, None, false).await,
    }
}

fn refresh_counters(effect: Effect, receiver: &mut ReceiverState, script: &ExplorationGitScript) {
    if matches!(effect, Effect::Git) {
        let state = script.state.lock().unwrap();
        receiver.reads = state.reads;
        receiver.mutations = state.sends;
        receiver.violation = state.violation;
    }
}

fn configure_git(script: &ExplorationGitScript, receiver: Receiver, attempted: bool) {
    let mut state = script.state.lock().unwrap();
    state.stale = matches!(receiver, Receiver::Replaced | Receiver::StaleVersion);
    state.unavailable = matches!(receiver, Receiver::Unavailable);
    state.acknowledgement = match receiver {
        Receiver::Healthy => GitAcknowledgement::Updated,
        Receiver::Failed => GitAcknowledgement::ReceiverRejected,
        _ => GitAcknowledgement::Unknown,
    };
    state.observed = if attempted && (state.sends > 0 || matches!(receiver, Receiver::Pending)) {
        GitObservedRef::Commit(
            if matches!(receiver, Receiver::Replaced) {
                "c"
            } else {
                "b"
            }
            .repeat(40),
        )
    } else {
        GitObservedRef::Commit("a".repeat(40))
    };
}

fn source_identity() -> String {
    use std::process::Command;
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .unwrap();
    assert!(output.status.success() && output.stdout.len() < 1024 * 1024);
    let mut files: Vec<_> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    files.sort_unstable();
    files.dedup();
    let mut hash = Sha256::new();
    let mut total = 0;
    for path in files {
        let text = std::str::from_utf8(path).unwrap();
        let bytes = fs::read(text).unwrap();
        total += bytes.len();
        assert!(total <= 64 * 1024 * 1024);
        hash.update(u64::try_from(path.len()).unwrap().to_le_bytes());
        hash.update(path);
        hash.update(u64::try_from(bytes.len()).unwrap().to_le_bytes());
        hash.update(bytes);
    }
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

struct Generator(u64);

impl Generator {
    fn index(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(bound).unwrap()).unwrap()
    }
}

fn trace(seed: u64, stop: Stop, receiver: Receiver, identities: usize) -> Trace {
    trace_with_steps(seed, stop, receiver, identities, 8)
}

fn trace_with_steps(
    seed: u64,
    stop: Stop,
    receiver: Receiver,
    identities: usize,
    steps: usize,
) -> Trace {
    let mut generator = Generator(seed);
    let mut events = Vec::new();
    for id in 0..identities {
        events.push(Event::CallerSubmit {
            id,
            competing: false,
        });
    }
    events.push(Event::CallerCancelAtBarrier {
        id: 0,
        contender: 1,
        barrier: [Barrier::Preflight, Barrier::Mutation, Barrier::Observation][generator.index(3)],
    });
    // Interleave independent identities rather than complete one prescribed case at a time.
    for _ in 0..identities * steps {
        let id = generator.index(identities);
        let stop = if steps > 8 {
            [
                Stop::BeforeAttempt,
                Stop::UnsentAttempt,
                Stop::AttemptAcknowledgementLost,
                Stop::ResponseLost,
                Stop::ResponseRecorded,
                Stop::ObservationLost,
                Stop::ObservationRecorded,
                Stop::None,
            ][generator.index(8)]
        } else {
            stop
        };
        let receiver = if steps > 8 {
            [
                Receiver::Healthy,
                Receiver::Failed,
                Receiver::Pending,
                Receiver::Replaced,
                Receiver::StaleVersion,
                Receiver::WrongGeneration,
                Receiver::Unavailable,
            ][generator.index(7)]
        } else {
            receiver
        };
        match generator.index(7) {
            0 => events.push(Event::CallerSubmit {
                id,
                competing: generator.index(2) == 0,
            }),
            1 => events.push(Event::WorkerAdvance { id, stop }),
            2 => events.push(Event::ReceiverChange { id, receiver }),
            3 => events.push(Event::OperatorReopen {
                trusted: generator.index(2) == 0,
            }),
            5 => events.push(Event::GatewayWrites {
                enabled: generator.index(2) == 0,
            }),
            4 => events.push(Event::ApplicationSelect {
                id,
                catalog: [Catalog::Original, Catalog::Removed, Catalog::Replaced]
                    [generator.index(3)],
                signing_key: (generator.index(2) == 0).then_some(31),
            }),
            _ => events.extend([
                Event::OperatorReopen { trusted: true },
                Event::WorkerComplete {
                    id,
                    key: if generator.index(2) == 0 { 13 } else { 99 },
                    stop: [
                        CompletionStop::None,
                        CompletionStop::BeforeCommit,
                        CompletionStop::AcknowledgementLost,
                    ][generator.index(3)],
                },
            ]),
        }
    }
    events.extend(healthy_suffix(identities));
    Trace {
        version: 1,
        seed,
        // Filled once for persisted evidence, not hashed again for every deterministic case.
        executable_sha256: String::new(),
        source_sha256: String::new(),
        initial_state: InitialState::FreshTrustedHealthy,
        identities: (0..identities)
            .map(|id| format!("exploration-{id}"))
            .collect(),
        effects: vec![Effect::Kubernetes; identities],
        require_progress: true,
        events,
    }
}

fn assign_effects(trace: &mut Trace, assignment: usize) {
    trace.effects = (0..trace.identities.len())
        .map(|id| {
            if assignment == 1 || (assignment == 2 && id % 2 == 1) {
                Effect::Git
            } else {
                Effect::Kubernetes
            }
        })
        .collect();
}

fn healthy_suffix(identities: usize) -> Vec<Event> {
    // Progress applies only after authority/receiver/signing return and faults stop.
    let mut events = vec![
        Event::GatewayWrites { enabled: true },
        Event::OperatorReopen { trusted: true },
    ];
    for id in 0..identities {
        events.extend([
            Event::CallerSubmit {
                id,
                competing: false,
            },
            Event::ReceiverChange {
                id,
                receiver: Receiver::Healthy,
            },
            Event::WorkerAdvance {
                id,
                stop: Stop::None,
            },
            Event::WorkerComplete {
                id,
                key: 13,
                stop: CompletionStop::AcknowledgementLost,
            },
            Event::OperatorReopen { trusted: true },
            Event::WorkerAdvance {
                id,
                stop: Stop::None,
            },
            Event::WorkerComplete {
                id,
                key: 99,
                stop: CompletionStop::None,
            },
        ]);
    }
    events
}

async fn same_finding(trace: &Trace, invariant: &'static str) -> bool {
    replay(trace)
        .await
        .is_err_and(|failure| failure.invariant == invariant)
}

fn without_identity(trace: &Trace, removed: usize) -> Trace {
    let mut candidate = trace.clone();
    if trace.require_progress && has_healthy_suffix(trace) {
        let suffix = candidate.events.len() - 7 * trace.identities.len();
        candidate
            .events
            .drain(suffix + 7 * removed..suffix + 7 * (removed + 1));
    }
    candidate.identities.remove(removed);
    if !candidate.effects.is_empty() {
        candidate.effects.remove(removed);
    }
    candidate.events.retain(|event| {
        let removed_contender = matches!(
            event,
            Event::CallerCancelAtBarrier { contender, .. } if *contender == removed
        );
        event.identity() != Some(removed) && !removed_contender
    });
    for event in &mut candidate.events {
        let id = match event {
            Event::CallerCancelAtBarrier { id, contender, .. } => {
                if *contender > removed {
                    *contender -= 1;
                }
                Some(id)
            },
            Event::AdmissionLoss { id, .. }
            | Event::ApplicationSelect { id, .. }
            | Event::CallerSubmit { id, .. }
            | Event::WorkerAdvance { id, .. }
            | Event::ReceiverChange { id, .. }
            | Event::WorkerComplete { id, .. } => Some(id),
            Event::OperatorReopen { .. } | Event::GatewayWrites { .. } => None,
        };
        if let Some(id) = id {
            if *id > removed {
                *id -= 1;
            }
        }
    }
    candidate
}

fn simplified(event: &Event) -> Option<Event> {
    match *event {
        Event::CallerSubmit {
            id,
            competing: true,
        } => Some(Event::CallerSubmit {
            id,
            competing: false,
        }),
        Event::WorkerAdvance { id, stop } if !matches!(stop, Stop::None) => {
            Some(Event::WorkerAdvance {
                id,
                stop: Stop::None,
            })
        },
        Event::ReceiverChange { id, receiver } if !matches!(receiver, Receiver::Healthy) => {
            Some(Event::ReceiverChange {
                id,
                receiver: Receiver::Healthy,
            })
        },
        Event::OperatorReopen { trusted: false } => Some(Event::OperatorReopen { trusted: true }),
        Event::WorkerComplete { id, key, stop }
            if key != 0 || !matches!(stop, CompletionStop::None) =>
        {
            Some(Event::WorkerComplete {
                id,
                key: 0,
                stop: CompletionStop::None,
            })
        },
        Event::AdmissionLoss { .. }
        | Event::GatewayWrites { .. }
        | Event::ApplicationSelect { .. }
        | Event::CallerCancelAtBarrier { .. }
        | Event::CallerSubmit { .. }
        | Event::WorkerAdvance { .. }
        | Event::ReceiverChange { .. }
        | Event::OperatorReopen { .. }
        | Event::WorkerComplete { .. } => None,
    }
}

async fn minimize(mut trace: Trace, invariant: &'static str) -> Trace {
    // A safety finding can end at the offending event, before the original healthy suffix.
    // Progress findings must retain their explicit quiescence obligation during reduction.
    if invariant != "bounded_progress" {
        trace.require_progress = false;
    }
    assert!(!matches!(
        invariant,
        "prerequisite" | "event_identity" | "trace_version" | "identity_bound" | "event_bound"
    ));
    loop {
        let previous_size = (trace.identities.len(), trace.events.len());
        let mut id = 0;
        while trace.identities.len() > 2 && id < trace.identities.len() {
            let candidate = without_identity(&trace, id);
            if same_finding(&candidate, invariant).await {
                trace = candidate;
            } else {
                id += 1;
            }
        }
        let mut index = 0;
        while index < trace.events.len() {
            let mut candidate = trace.clone();
            candidate.events.remove(index);
            if same_finding(&candidate, invariant).await {
                trace = candidate;
            } else {
                index += 1;
            }
        }
        let mut changed_value = false;
        for index in 0..trace.events.len() {
            if let Some(event) = simplified(&trace.events[index]) {
                let mut candidate = trace.clone();
                candidate.events[index] = event;
                if same_finding(&candidate, invariant).await {
                    trace = candidate;
                    changed_value = true;
                }
            }
        }
        if previous_size == (trace.identities.len(), trace.events.len()) && !changed_value {
            return trace;
        }
    }
}

fn persist(path: &Path, trace: &Trace) {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(trace).unwrap();
    assert!(bytes.len() <= TRACE_LIMIT);
    // Evidence must not silently overwrite an earlier finding.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn enumerated_two_identity_barrier_schedules() {
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for barrier in [Barrier::Preflight, Barrier::Mutation, Barrier::Observation] {
        for owner in 0..2 {
            for order in permutations {
                let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
                let concurrent = [
                    Event::CallerCancelAtBarrier {
                        id: owner,
                        contender: 1 - owner,
                        barrier,
                    },
                    Event::CallerSubmit {
                        id: owner,
                        competing: true,
                    },
                    Event::OperatorReopen { trusted: true },
                ];
                let suffix = healthy_suffix(2);
                input.events.truncate(2);
                input
                    .events
                    .extend(order.map(|index| concurrent[index].clone()));
                input.events.extend(suffix);
                for assignment in 0..3 {
                    assign_effects(&mut input, assignment);
                    replay(&input).await.unwrap();
                }
            }
        }
    }
}

#[tokio::test]
async fn bounded_lifecycle_exploration() {
    let stops = [
        Stop::None,
        Stop::BeforeAttempt,
        Stop::UnsentAttempt,
        Stop::AttemptAcknowledgementLost,
        Stop::ResponseLost,
        Stop::ResponseRecorded,
        Stop::ObservationLost,
        Stop::ObservationRecorded,
    ];
    let receivers = [
        Receiver::Healthy,
        Receiver::Failed,
        Receiver::Pending,
        Receiver::Replaced,
        Receiver::StaleVersion,
        Receiver::WrongGeneration,
        Receiver::Unavailable,
    ];
    for (stop_index, stop) in stops.into_iter().enumerate() {
        for (receiver_index, receiver) in receivers.into_iter().enumerate() {
            let seed = DEFAULT_SEED
                + u64::try_from(stop_index * receivers.len() + receiver_index).unwrap();
            let mut input = trace(seed, stop, receiver, 2);
            for assignment in 0..3 {
                assign_effects(&mut input, assignment);
                let result = replay(&input).await;
                assert!(result.is_ok(), "input={input:?} result={result:?}");
            }
        }
    }
}

#[tokio::test]
async fn enumerated_fresh_lifecycle_boundaries() {
    for stop in [
        Stop::None,
        Stop::BeforeAttempt,
        Stop::UnsentAttempt,
        Stop::AttemptAcknowledgementLost,
        Stop::ResponseLost,
        Stop::ResponseRecorded,
        Stop::ObservationLost,
        Stop::ObservationRecorded,
    ] {
        for receiver in [
            Receiver::Healthy,
            Receiver::Failed,
            Receiver::Pending,
            Receiver::Replaced,
            Receiver::StaleVersion,
            Receiver::WrongGeneration,
            Receiver::Unavailable,
        ] {
            let mut input = trace(DEFAULT_SEED, stop, receiver, 2);
            // No cancellation or earlier advancement may consume the fresh attempt.
            input.events.truncate(2);
            input.events.extend([
                Event::ReceiverChange { id: 0, receiver },
                Event::WorkerAdvance { id: 0, stop },
                Event::OperatorReopen { trusted: true },
            ]);
            input.events.extend(healthy_suffix(2));
            for assignment in 0..3 {
                assign_effects(&mut input, assignment);
                let result = replay(&input).await;
                assert!(result.is_ok(), "input={input:?} result={result:?}");
            }
        }
    }
}

#[test]
fn all_identity_oracle_checks_unselected_peers_without_trust() {
    let scratch = Scratch::new();
    let gateway = Gateway::open_for_test(scratch.0.join("journal.sqlite3")).unwrap();
    let input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
    let expected = [Expectation::default(), Expectation::default()];
    let mut receivers: Vec<_> = (0..2)
        .map(|_| ReceiverState {
            mutations: 0,
            reads: 0,
            receiver: Receiver::Healthy,
            violation: None,
        })
        .collect();
    check_all_identities(&gateway, &input, &expected, &receivers, false, 0).unwrap();
    receivers[1].mutations = 1;
    let finding =
        check_all_identities(&gateway, &input, &expected, &receivers, false, 1).unwrap_err();
    assert_eq!(finding.invariant, "fresh_permission");
    assert_eq!(finding.event, 1);
}

#[tokio::test]
async fn git_oracle_rejects_changed_observation_even_when_result_is_unchanged() {
    let scratch = Scratch::new();
    let journal = scratch.0.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&journal).unwrap();
    let script = ExplorationGitScript::new("oracle", journal);
    ExplorationGitScript::submit(&gateway, "oracle", false).unwrap();
    script
        .advance(&mut gateway, "oracle", None, false)
        .await
        .unwrap();
    let settings = ReceiptSettings {
        signing_seed: &[13; 32],
        key_id: "exploration-receipt",
    };
    script
        .advance(&mut gateway, "oracle", Some(&settings), true)
        .await
        .unwrap();
    let retained = snapshot(&gateway, Effect::Git, "oracle", 0).unwrap();
    let mut expected = Expectation {
        admitted: true,
        attempted: true,
        mutations: 1,
        grant: Some(original_grant(Effect::Git, "oracle")),
        receipt_signer: Some((13, "exploration-receipt")),
        frozen: Some(ExpectedResult::Success),
        git_acknowledgement: Some(ExpectedResult::Success),
        git_observed_ref: Some(GitObservedRef::Commit("b".repeat(40))),
        ..Expectation::default()
    };
    let mut targets = retained.git_targets.as_ref().unwrap().clone();
    check_git_facts(&retained, &targets, &expected, 0).unwrap();
    targets.observed_ref = Some(GitObservedRef::Commit("c".repeat(40)));
    assert_eq!(
        check_git_facts(&retained, &targets, &expected, 1)
            .unwrap_err()
            .invariant,
        "git_observation"
    );
    // Matching the changed retained observation still cannot excuse a receipt with other facts.
    expected.git_observed_ref.clone_from(&targets.observed_ref);
    assert_eq!(
        check_git_facts(&retained, &targets, &expected, 2)
            .unwrap_err()
            .invariant,
        "git_receipt_facts"
    );
    targets.acknowledgement = Some(GitAcknowledgement::Unknown);
    assert_eq!(
        check_git_facts(&retained, &targets, &expected, 3)
            .unwrap_err()
            .invariant,
        "git_acknowledgement"
    );
    expected.git_observed_ref = Some(GitObservedRef::Commit("b".repeat(40)));
    expected.receipt_signer = Some((99, "exploration-receipt"));
    assert_eq!(
        check_git_facts(
            &retained,
            retained.git_targets.as_ref().unwrap(),
            &expected,
            4
        )
        .unwrap_err()
        .invariant,
        "git_receipt_signer"
    );
    expected.receipt_signer = None;
    assert_eq!(
        check_git_facts(
            &retained,
            retained.git_targets.as_ref().unwrap(),
            &expected,
            5
        )
        .unwrap_err()
        .invariant,
        "completion_state"
    );
}

#[tokio::test]
async fn admission_commit_loss_retains_original_responsibility() {
    for assignment in 0..3 {
        for boundary in [
            AdmissionBoundary::FirstCommit,
            AdmissionBoundary::AuthorizationCommit,
        ] {
            let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
            assign_effects(&mut input, assignment);
            input.events = vec![
                Event::AdmissionLoss { id: 0, boundary },
                Event::CallerSubmit {
                    id: 1,
                    competing: false,
                },
                Event::OperatorReopen { trusted: true },
                Event::GatewayWrites { enabled: false },
                Event::CallerSubmit {
                    id: 0,
                    competing: false,
                },
                Event::GatewayWrites { enabled: true },
                Event::ApplicationSelect {
                    id: 0,
                    catalog: Catalog::Removed,
                    signing_key: None,
                },
            ];
            input.events.extend(healthy_suffix(2));
            replay(&input).await.unwrap();
        }
    }
}

#[tokio::test]
async fn sqlite_write_refusal_preserves_previous_facts_and_same_id_repair() {
    for assignment in 0..3 {
        let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
        assign_effects(&mut input, assignment);
        input.events = vec![
            Event::GatewayWrites { enabled: false },
            Event::CallerSubmit {
                id: 0,
                competing: false,
            },
            Event::GatewayWrites { enabled: true },
            Event::CallerSubmit {
                id: 0,
                competing: false,
            },
            Event::CallerSubmit {
                id: 1,
                competing: false,
            },
            Event::GatewayWrites { enabled: false },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::GatewayWrites { enabled: true },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::ResponseLost,
            },
            Event::GatewayWrites { enabled: false },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::OperatorReopen { trusted: true },
            Event::GatewayWrites { enabled: true },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::GatewayWrites { enabled: false },
            Event::WorkerComplete {
                id: 0,
                key: 13,
                stop: CompletionStop::None,
            },
            Event::ApplicationSelect {
                id: 0,
                catalog: Catalog::Removed,
                signing_key: Some(31),
            },
        ];
        input.events.extend(healthy_suffix(2));
        replay(&input).await.unwrap();
    }
}

#[tokio::test]
async fn git_present_b_never_reconstructs_a_missing_acknowledgement() {
    for stop in [Stop::UnsentAttempt, Stop::ResponseLost] {
        let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
        assign_effects(&mut input, 1);
        input.require_progress = false;
        input.events = vec![
            Event::CallerSubmit {
                id: 0,
                competing: false,
            },
            Event::WorkerAdvance { id: 0, stop },
            Event::ReceiverChange {
                id: 0,
                receiver: Receiver::Pending,
            },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::WorkerComplete {
                id: 0,
                key: 13,
                stop: CompletionStop::None,
            },
            Event::ReceiverChange {
                id: 0,
                receiver: Receiver::Healthy,
            },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::WorkerComplete {
                id: 0,
                key: 99,
                stop: CompletionStop::None,
            },
        ];
        replay(&input).await.unwrap();
    }
}

#[tokio::test]
async fn stale_targets_remain_not_attempted_after_receiver_repair() {
    for receiver in [Receiver::Replaced, Receiver::StaleVersion] {
        let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
        input.require_progress = false;
        input.events = vec![
            Event::CallerSubmit {
                id: 0,
                competing: false,
            },
            Event::ReceiverChange { id: 0, receiver },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::ReceiverChange {
                id: 0,
                receiver: Receiver::Healthy,
            },
            Event::WorkerAdvance {
                id: 0,
                stop: Stop::None,
            },
            Event::WorkerComplete {
                id: 0,
                key: 13,
                stop: CompletionStop::None,
            },
        ];
        replay(&input).await.unwrap();
    }
}

#[tokio::test]
async fn progress_reduction_cannot_remove_recovery_opportunities() {
    let original = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 4);
    assert!(has_healthy_suffix(&original));
    assert!(has_healthy_suffix(&without_identity(&original, 2)));
    let mut empty = original;
    empty.events.clear();
    let finding = replay(&empty).await.unwrap_err();
    assert_eq!(finding.invariant, "progress_prerequisite");
}

#[tokio::test]
async fn completion_without_terminal_bytes_is_a_minimizable_finding() {
    let scratch = Scratch::new();
    let gateway = Gateway::open_for_test(scratch.0.join("journal.sqlite3")).unwrap();
    let request = request("unfinished");
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    let finding = receipt_bytes(&gateway, &request.operation_id, 3).unwrap_err();
    assert_eq!(finding.invariant, "completion_state");
    assert_eq!(finding.event, 3);
}

#[tokio::test]
async fn minimized_unsent_permission_trace_preserves_unknown() {
    let mut input = trace(DEFAULT_SEED, Stop::None, Receiver::Healthy, 2);
    input.require_progress = false;
    input.events = vec![
        Event::CallerSubmit {
            id: 0,
            competing: false,
        },
        Event::WorkerAdvance {
            id: 0,
            stop: Stop::UnsentAttempt,
        },
        Event::WorkerAdvance {
            id: 0,
            stop: Stop::None,
        },
    ];
    replay(&input).await.unwrap();
}

#[tokio::test]
async fn lifecycle_trace_round_trip_replays_events_not_generator_state() {
    let original = trace(DEFAULT_SEED, Stop::UnsentAttempt, Receiver::Healthy, 4);
    let bytes = serde_json::to_vec(&original).unwrap();
    let decoded: Trace = serde_json::from_slice(&bytes).unwrap();
    replay(&decoded).await.unwrap();
}

#[tokio::test]
#[ignore = "explicit replay input or owned exploration evidence directory required"]
#[allow(
    clippy::panic,
    reason = "fail the test after preserving and replaying the minimized finding"
)]
async fn lifecycle_trace_exploration_or_replay() {
    if let Some(directory) = std::env::var_os("KAPSEL_LIFECYCLE_REPLAY_DIRECTORY") {
        let mut paths: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!((1..=10_000).contains(&paths.len()));
        paths.sort();
        for path in &paths {
            assert!(fs::metadata(path).unwrap().len() <= u64::try_from(TRACE_LIMIT).unwrap());
            let trace: Trace = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            replay(&trace).await.unwrap();
        }
        println!("KAPSEL_LIFECYCLE_REPLAYED cases={}", paths.len());
        return;
    }
    if let Some(path) = std::env::var_os("KAPSEL_LIFECYCLE_REPLAY") {
        let path = PathBuf::from(path);
        assert!(fs::metadata(&path).unwrap().len() <= u64::try_from(TRACE_LIMIT).unwrap());
        let trace: Trace = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        replay(&trace).await.unwrap();
        return;
    }
    let root = PathBuf::from(std::env::var_os("KAPSEL_LIFECYCLE_EVIDENCE").unwrap());
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(root.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    let executable_sha256 = hex(&Sha256::digest(executable));
    let source_sha256 = source_identity();
    let seed =
        std::env::var("KAPSEL_LIFECYCLE_SEED").map_or(DEFAULT_SEED, |value| value.parse().unwrap());
    let cases = std::env::var("KAPSEL_LIFECYCLE_CASES")
        .map_or(100, |value| value.parse::<usize>().unwrap());
    assert!(seed != 0 && (1..=10_000).contains(&cases));
    let steps =
        std::env::var("KAPSEL_LIFECYCLE_STEPS").map_or(48, |value| value.parse::<usize>().unwrap());
    assert!((8..=48).contains(&steps));
    let shards =
        std::env::var("KAPSEL_LIFECYCLE_SHARDS").map_or(1, |value| value.parse::<usize>().unwrap());
    let shard = std::env::var("KAPSEL_LIFECYCLE_SHARD_INDEX")
        .map_or(0, |value| value.parse::<usize>().unwrap());
    assert!((1..=128).contains(&shards) && shards <= cases && shard < shards);
    let mut completed = 0;
    let mut generator = Generator(seed);
    for case in 0..cases {
        let mut input = trace_with_steps(
            seed.wrapping_add(u64::try_from(case).unwrap()),
            [
                Stop::UnsentAttempt,
                Stop::ResponseLost,
                Stop::ObservationLost,
                Stop::None,
            ][generator.index(4)],
            [
                Receiver::Healthy,
                Receiver::Failed,
                Receiver::Replaced,
                Receiver::Unavailable,
            ][generator.index(4)],
            2 + generator.index(3),
            steps,
        );
        if case % shards != shard {
            continue;
        }
        assign_effects(&mut input, case % 3);
        input.executable_sha256.clone_from(&executable_sha256);
        input.source_sha256.clone_from(&source_sha256);
        persist(&root.join(format!("case-{case}.json")), &input);
        if let Err(finding) = replay(&input).await {
            let minimized = minimize(input, finding.invariant).await;
            persist(&root.join(format!("finding-{case}.json")), &minimized);
            let reproduced = replay(&minimized).await.unwrap_err();
            assert_eq!(reproduced.invariant, finding.invariant);
            panic!(
                "{} at event {}; minimized trace replayed",
                finding.invariant, finding.event
            );
        }
        completed += 1;
    }
    let summary = format!("seed={seed} shard={shard}/{shards} cases={completed} steps={steps}");
    println!("KAPSEL_LIFECYCLE_COMPLETED {summary}");
}
