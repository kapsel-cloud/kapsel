//! Invariant-first mixed effects through the real service, shared policy and atomic record I/O.
//! Receiver and commit delivery are independent facts; the checker never predicts lifecycle phases.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use rusqlite::{types::Value, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    gateway::{Defect, Delivery, DispatchPermission, StorageControl, StorageWrite},
    ApplyOutcome, ApprovedTarget, AuthorizationTrust, DeploymentImageAdapter, ExactAuthorization,
    FaultPoint, OperationReceipt, ReceiverObservation, ServiceApplication, ServiceApproval,
    ServiceConfiguration, ServiceExecution, SetDeploymentImageRequest, TargetIdentity,
    TargetReadError,
};

const ID: &str = "kernel-kubernetes";
const UID: &str = "original-uid";
const VERSION: &str = "approved-version";
const IMAGE: &str = concat!(
    "registry.example/api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum Receiver {
    Healthy,
    Failed,
    Pending,
    Replaced,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum Cut {
    None,
    BeforeAttempt,
    Unsent,
    Frozen,
}

impl Cut {
    fn fault(self) -> Option<FaultPoint> {
        match self {
            Self::None => None,
            Self::BeforeAttempt => Some(FaultPoint::TargetObserved),
            Self::Unsent => Some(FaultPoint::ApplyStartedCommitted),
            Self::Frozen => Some(FaultPoint::ReceiverObservedCommitted),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    commit: Option<(StorageWrite, Delivery)>,
    cut: Cut,
    lose_response: bool,
    sign: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
enum Action {
    Select(Selection),
    Peer(usize),
    Receiver(Receiver),
    GitRef { new: bool },
    Reopen { catalog: bool },
    Trust(bool),
    Restore,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum Effect {
    Kubernetes,
    Git,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    seed: u64,
    #[serde(default = "single_peer")]
    peers: usize,
    #[serde(default)]
    effects: Vec<Effect>,
    actions: Vec<Action>,
    defect: Option<Defect>,
    #[serde(default = "default_progress")]
    require_progress: bool,
    #[serde(default)]
    source_sha256: String,
    #[serde(default)]
    executable_sha256: String,
}

#[derive(Debug, PartialEq)]
struct Finding {
    law: &'static str,
    event: usize,
    defect_reached: Vec<Defect>,
}

type Checked = Result<(), Finding>;

fn default_progress() -> bool {
    true
}

fn single_peer() -> usize {
    1
}

pub(crate) struct Scratch(pub(crate) PathBuf);
impl Scratch {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kapsel-kernel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Clone)]
struct Store {
    control: StorageControl,
    path: PathBuf,
    virtualized: bool,
}
impl Store {
    fn raw(&self, id: &str) -> BTreeMap<String, Value> {
        self.raw_effect(id, false)
    }

    fn raw_effect(&self, id: &str, git: bool) -> BTreeMap<String, Value> {
        let fields = if git { GIT_FIELDS } else { FIELDS };
        let table = if git {
            "git_ref_operations"
        } else {
            "kubernetes_image_operations"
        };
        if self.virtualized {
            // Named fields are intentionally independent of the production decoder's projection.
            fields
                .iter()
                .filter_map(|field| {
                    self.control
                        .value(id, field)
                        .map(|value| ((*field).to_owned(), value))
                })
                .collect()
        } else {
            let connection = Connection::open(&self.path).unwrap();
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {table} WHERE operation_id = ?1"))
                .unwrap();
            let names = statement
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut rows = statement.query([id]).unwrap();
            rows.next().unwrap().map_or_else(BTreeMap::new, |row| {
                names
                    .into_iter()
                    .enumerate()
                    .map(|(index, field)| (field, row.get(index).unwrap()))
                    .collect()
            })
        }
    }
}

// Frozen evidence, original intent and authority are observed by physical names, not roundtripping
// through SnapshotRow/ReceiptRow. Legacy inert columns are retained by the SQLite boundary owner.
const FIELDS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "signed_authorization_grant",
    "state",
    "write_strategy",
    "target_rejection",
    "apply_attempted",
    "target_uid",
    "target_resource_version",
    "apply_accepted",
    "requested_generation",
    "apply_resource_version",
    "receiver_uid",
    "receiver_image",
    "receiver_operation_marker",
    "current_generation",
    "observed_generation",
    "receiver_resource_version",
    "desired_replicas",
    "updated_replicas",
    "available_replicas",
    "unavailable_replicas",
    "result",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
    "approved_uid",
    "approved_resource_version",
    "preflight_uid",
    "preflight_resource_version",
];

const GIT_FIELDS: &[&str] = &[
    "operation_id",
    "repository_id",
    "ref_name",
    "old_commit",
    "new_commit",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "signed_authorization_grant",
    "state",
    "target_rejection",
    "acknowledgement",
    "observed_ref_kind",
    "observed_commit",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
];

fn text<'a>(raw: &'a BTreeMap<String, Value>, field: &str) -> Option<&'a str> {
    match raw.get(field) {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}
fn integer(raw: &BTreeMap<String, Value>, field: &str) -> Option<i64> {
    match raw.get(field) {
        Some(Value::Integer(value)) => Some(*value),
        _ => None,
    }
}

#[derive(Default)]
struct Observations {
    sends: Vec<(SetDeploymentImageRequest, TargetIdentity)>,
    reads: usize,
    returned: Option<ReceiverObservation>,
    response: Option<ApplyOutcome>,
    violation: Option<&'static str>,
}

struct Adapter {
    intent: Intent,
    store: Store,
    io: Arc<Mutex<Observations>>,
    receiver: Receiver,
    lose_response: bool,
    fresh: bool,
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "controlled I/O uses the production async seam"
)]
impl DeploymentImageAdapter for Adapter {
    async fn identify(
        &mut self,
        selected: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        let mut io = self.io.lock().unwrap();
        io.reads += 1;
        if selected != &self.intent.request {
            io.violation = Some("original_intent");
        }
        drop(io);
        if matches!(self.receiver, Receiver::Unavailable) {
            return Err(TargetReadError::Transient);
        }
        Ok(TargetIdentity {
            deployment_uid: if matches!(self.receiver, Receiver::Replaced) {
                "replacement-uid".into()
            } else {
                self.intent.uid.clone()
            },
            resource_version: self.intent.version.clone(),
        })
    }

    async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
        let payload = permission.into_payload();
        let raw = self.store.raw(&self.intent.request.operation_id);
        let mut io = self.io.lock().unwrap();
        if !self.fresh
            || self.store.control.last_delivery(StorageWrite::Attempt) != Some(Delivery::Confirmed)
            || text(&raw, "state") != Some("apply_started")
        {
            io.violation = Some("dispatch_provenance");
        }
        if payload.0 != self.intent.request
            || payload.1.deployment_uid != self.intent.uid
            || payload.1.resource_version != self.intent.version
        {
            io.violation = Some("original_intent");
        }
        io.sends.push(payload);
        let outcome = ApplyOutcome {
            accepted: true,
            requested_generation: Some(7),
            deployment_uid: Some(self.intent.uid.clone()),
            resource_version: Some("after-patch".into()),
        };
        if self.lose_response {
            return Err(());
        }
        io.response = Some(outcome.clone());
        drop(io);
        Ok(outcome)
    }

    async fn observe(
        &mut self,
        selected: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        let mut io = self.io.lock().unwrap();
        io.reads += 1;
        if selected != &self.intent.request
            || outcome.deployment_uid.as_deref() != Some(self.intent.uid.as_str())
        {
            io.violation = Some("original_intent");
        }
        if matches!(self.receiver, Receiver::Unavailable) {
            return Err(());
        }
        let sent = !io.sends.is_empty();
        let failed = matches!(self.receiver, Receiver::Failed);
        let pending = matches!(self.receiver, Receiver::Pending);
        let observation = ReceiverObservation {
            deployment_uid: Some(if matches!(self.receiver, Receiver::Replaced) {
                "replacement-uid".into()
            } else {
                self.intent.uid.clone()
            }),
            resource_version: Some(
                if sent {
                    "observed-version"
                } else {
                    &self.intent.version
                }
                .into(),
            ),
            current_generation: Some(if sent { 7 } else { 3 }),
            observed_generation: Some(if sent && pending {
                6
            } else if sent {
                7
            } else {
                3
            }),
            image: sent.then(|| self.intent.request.immutable_image_digest.clone()),
            operation_marker: sent.then(|| self.intent.request.operation_id.clone()),
            desired_replicas: Some(if pending { 5 } else { 1 }),
            updated_replicas: Some(if pending { 4 } else { i32::from(!failed) }),
            available_replicas: Some(if pending { 2 } else { i32::from(!failed) }),
            unavailable_replicas: Some(if pending { 3 } else { i32::from(failed) }),
            rollout_condition_type: Some(if failed { "Progressing" } else { "Available" }.into()),
            rollout_condition_status: Some(if failed || pending { "False" } else { "True" }.into()),
            rollout_condition_reason: failed.then(|| "ProgressDeadlineExceeded".into()),
        };
        io.returned = Some(observation.clone());
        drop(io);
        Ok(observation)
    }
}

// Effect-specific law over original intent and actual I/O. No phase predictor or production
// classifier/receipt builder is used. Healthy eligible work must succeed, not only stay immutable.
fn result_from_io(io: &Observations, intent: &Intent) -> &'static str {
    let Some(observed) = &io.returned else {
        return "UNKNOWN";
    };
    let correlated = observed.deployment_uid.as_deref() == Some(intent.uid.as_str())
        && observed.image.as_deref() == Some(intent.request.immutable_image_digest.as_str())
        && observed.operation_marker.as_deref() == Some(intent.request.operation_id.as_str());
    let generation = io
        .response
        .as_ref()
        .and_then(|response| response.requested_generation)
        .or_else(|| correlated.then_some(observed.current_generation).flatten());
    if !correlated
        || generation.is_none()
        || generation != observed.current_generation
        || observed.observed_generation < generation
    {
        return "UNKNOWN";
    }
    if observed.rollout_condition_type.as_deref() == Some("Progressing")
        && observed.rollout_condition_status.as_deref() == Some("False")
        && observed.rollout_condition_reason.as_deref() == Some("ProgressDeadlineExceeded")
    {
        return "FAILED";
    }
    if observed.desired_replicas.is_some()
        && observed.updated_replicas == observed.desired_replicas
        && observed.available_replicas == observed.desired_replicas
        && observed.unavailable_replicas == Some(0)
        && observed.rollout_condition_type.as_deref() == Some("Available")
        && observed.rollout_condition_status.as_deref() == Some("True")
    {
        "SUCCEEDED"
    } else {
        "UNKNOWN"
    }
}

#[derive(Clone)]
struct Intent {
    request: SetDeploymentImageRequest,
    uid: String,
    version: String,
    authorization_id: String,
    authorization_key: String,
    authority_seed: [u8; 32],
    grant: Vec<u8>,
    receipt_seed: [u8; 32],
    receipt_key: String,
}

impl Intent {
    fn new(peer: usize) -> Self {
        let distinct = |original: &str| {
            if peer == 0 {
                original.to_owned()
            } else {
                format!("{original}-{peer}")
            }
        };
        let request = SetDeploymentImageRequest {
            operation_id: distinct(ID),
            namespace: distinct("demo"),
            deployment: distinct("api"),
            container: distinct("api"),
            immutable_image_digest: if peer == 0 {
                IMAGE.into()
            } else {
                format!("registry.example/api@sha256:{peer:064x}")
            },
        };
        let uid = distinct(UID);
        let version = distinct(VERSION);
        let authorization_id = distinct("original-authorization");
        let authorization_key = distinct("original-authority");
        let authority_seed = [17 + u8::try_from(peer).unwrap(); 32];
        let authorization = ExactAuthorization {
            authorization_id: authorization_id.clone(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
            approved_target: Some(ApprovedTarget {
                uid: uid.clone(),
                resource_version: version.clone(),
            }),
        };
        let grant = crate::gateway::sign_authorization_grant(
            &authorization,
            &authority_seed,
            &authorization_key,
        )
        .unwrap();
        Self {
            request,
            uid,
            version,
            authorization_id,
            authorization_key,
            authority_seed,
            grant,
            receipt_seed: [23 + u8::try_from(peer).unwrap(); 32],
            receipt_key: distinct("original-receipt"),
        }
    }

    fn git(peer: usize) -> (Self, kapsel_authority::GitRefAuthorization) {
        let mut intent = Self::new(peer);
        intent.request.operation_id = format!("kernel-git-{peer}");
        let approval = kapsel_authority::GitRefAuthorization {
            authorization_id: intent.authorization_id.clone(),
            operation_id: intent.request.operation_id.clone(),
            repository_id: format!("kernel-repository-{peer}"),
            reference: kapsel_authority::APPROVED_GIT_REF.into(),
            old_commit: format!("{:040x}", peer + 1),
            new_commit: format!("{:040x}", peer + 5),
        };
        intent.grant = kapsel_authority::sign_git_ref_grant(
            &approval,
            &intent.authority_seed,
            &intent.authorization_key,
        )
        .unwrap();
        (intent, approval)
    }

    fn trust(&self) -> AuthorizationTrust {
        AuthorizationTrust {
            key_id: self.authorization_key.clone(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&self.authority_seed)
                .verifying_key()
                .to_bytes(),
        }
    }

    fn matches_record(&self, raw: &BTreeMap<String, Value>) -> bool {
        let grant_digest = crate::lifecycle_exploration_tests::hex(&Sha256::digest(&self.grant));
        text(raw, "authorization_id") == Some(self.authorization_id.as_str())
            && text(raw, "authorization_signer_key_id") == Some(self.authorization_key.as_str())
            && text(raw, "authorization_grant_digest") == Some(grant_digest.as_str())
            && text(raw, "operation_id") == Some(self.request.operation_id.as_str())
            && text(raw, "namespace") == Some(self.request.namespace.as_str())
            && text(raw, "deployment") == Some(self.request.deployment.as_str())
            && text(raw, "container") == Some(self.request.container.as_str())
            && text(raw, "immutable_image_digest")
                == Some(self.request.immutable_image_digest.as_str())
            && raw.get("signed_authorization_grant") == Some(&Value::Blob(self.grant.clone()))
            && text(raw, "approved_uid") == Some(self.uid.as_str())
            && text(raw, "approved_resource_version") == Some(self.version.as_str())
    }

    fn approval(&self) -> ServiceApproval {
        ServiceApproval {
            signed_grant: self.grant.clone(),
            label: "exact snapshot".into(),
        }
    }
}

fn open(configuration: ServiceConfiguration, control: &StorageControl) -> ServiceApplication {
    ServiceApplication::open_simulated(configuration, control.clone()).unwrap()
}

#[derive(Default)]
struct Checker {
    frozen: Option<BTreeMap<String, Value>>,
    frozen_reads: usize,
    original_bytes: Option<Value>,
}
impl Checker {
    fn check(
        &mut self,
        store: &Store,
        io: &Observations,
        intent: &Intent,
        event: usize,
    ) -> Checked {
        let require = |condition, law| {
            if condition {
                Ok(())
            } else {
                Err(Finding {
                    law,
                    event,
                    defect_reached: store.control.defect_reached(),
                })
            }
        };
        if let Some(law) = io.violation {
            require(false, law)?;
        }
        require(io.sends.len() <= 1, "at_most_one_mutation")?;
        let mut raw = store.raw(&intent.request.operation_id);
        if raw.is_empty() {
            return Ok(());
        }
        require(intent.matches_record(&raw), "original_authority")?;
        if integer(&raw, "apply_attempted") == Some(1) {
            require(
                text(&raw, "target_uid") == Some(intent.uid.as_str())
                    && text(&raw, "target_resource_version") == Some(intent.version.as_str()),
                "attempt_binding",
            )?;
        }
        if let Some(bytes) = raw
            .get("receipt_bytes")
            .filter(|value| **value != Value::Null)
        {
            if let Some(original) = &self.original_bytes {
                require(original == bytes, "original_receipt_bytes")?;
            } else {
                self.original_bytes = Some(bytes.clone());
            }
        }
        if matches!(text(&raw, "state"), Some("receiver_observed" | "finalized")) {
            if self.frozen.is_none() {
                require(
                    text(&raw, "result") == Some(result_from_io(io, intent)),
                    "initial_result",
                )?;
                let observation = io.returned.as_ref().unwrap();
                require(
                    text(&raw, "receiver_uid") == observation.deployment_uid.as_deref()
                        && text(&raw, "receiver_resource_version")
                            == observation.resource_version.as_deref()
                        && text(&raw, "receiver_image") == observation.image.as_deref()
                        && text(&raw, "receiver_operation_marker")
                            == observation.operation_marker.as_deref()
                        && integer(&raw, "current_generation") == observation.current_generation
                        && integer(&raw, "observed_generation") == observation.observed_generation
                        && integer(&raw, "desired_replicas")
                            == observation.desired_replicas.map(i64::from)
                        && integer(&raw, "updated_replicas")
                            == observation.updated_replicas.map(i64::from)
                        && integer(&raw, "available_replicas")
                            == observation.available_replicas.map(i64::from)
                        && integer(&raw, "unavailable_replicas")
                            == observation.unavailable_replicas.map(i64::from)
                        && text(&raw, "rollout_condition_type")
                            == observation.rollout_condition_type.as_deref()
                        && text(&raw, "rollout_condition_status")
                            == observation.rollout_condition_status.as_deref()
                        && text(&raw, "rollout_condition_reason")
                            == observation.rollout_condition_reason.as_deref(),
                    "frozen_io_binding",
                )?;
            }
            for field in ["state", "receipt_bytes", "receipt_digest", "receipt_key_id"] {
                raw.remove(field);
            }
            if let Some(original) = &self.frozen {
                require(
                    original == &raw && self.frozen_reads == io.reads,
                    "frozen_no_io",
                )?;
            } else {
                self.frozen = Some(raw);
                self.frozen_reads = io.reads;
            }
        }
        Ok(())
    }
}

async fn replay(trace: &Trace, virtualized: bool) -> Checked {
    let control = if virtualized {
        StorageControl::virtualized()
    } else {
        StorageControl::default()
    };
    replay_with_control(trace, virtualized, control).await
}

#[allow(
    clippy::too_many_lines,
    reason = "keep schedule execution, all-peer laws and progress prerequisites in one owner"
)]
async fn replay_with_control(trace: &Trace, virtualized: bool, control: StorageControl) -> Checked {
    let scratch = Scratch::new();
    if let Some(defect) = trace.defect {
        control.seed(defect);
    }
    let store = Store {
        control: control.clone(),
        path: scratch.0.join("journal.sqlite3"),
        virtualized,
    };
    assert!(
        (1..=4).contains(&trace.peers),
        "bounded local replay identities"
    );
    let mut peers = (0..trace.peers)
        .map(|peer| {
            let effect = trace
                .effects
                .get(peer)
                .copied()
                .unwrap_or(Effect::Kubernetes);
            let (intent, git) = match effect {
                Effect::Kubernetes => (Intent::new(peer), None),
                Effect::Git => {
                    let (intent, authorization) = Intent::git(peer);
                    let script = crate::gateway::git::exploration::Script::kernel(
                        authorization.clone(),
                        store.path.clone(),
                        control.clone(),
                    );
                    (
                        intent,
                        Some(GitPeer {
                            authorization,
                            script,
                            durable_ack: Mutex::new(None),
                        }),
                    )
                },
            };
            Peer {
                adapter: Adapter {
                    intent,
                    store: store.clone(),
                    io: Arc::new(Mutex::new(Observations::default())),
                    receiver: Receiver::Healthy,
                    lose_response: false,
                    fresh: true,
                },
                checker: Checker::default(),
                eligible_progress: false,
                git,
            }
        })
        .collect::<Vec<_>>();
    let mut configuration = ServiceConfiguration {
        journal_path: store.path.clone(),
        authorization_trust: peers
            .iter()
            .map(|peer| peer.adapter.intent.trust())
            .collect(),
        approvals: peers
            .iter()
            .map(|peer| peer.adapter.intent.approval())
            .collect(),
    };
    let mut app = open(configuration.clone(), &control);
    let mut selected = 0;
    let mut restored = false;
    let mut trusted = true;
    for (event, action) in trace.actions.iter().enumerate() {
        match *action {
            Action::Select(selection) => {
                let before =
                    (!trusted).then(|| peers.iter().map(Peer::snapshot).collect::<Vec<_>>());
                let peer = &mut peers[selected];
                let adapter = &mut peer.adapter;
                peer.eligible_progress |= restored
                    && trusted
                    && selection.sign
                    && selection.commit.is_none()
                    && matches!(selection.cut, Cut::None)
                    && !selection.lose_response
                    && matches!(adapter.receiver, Receiver::Healthy)
                    && (!store
                        .raw_effect(&adapter.intent.request.operation_id, peer.git.is_some())
                        .is_empty()
                        || !configuration.approvals.is_empty());
                if let Some(git) = &peer.git {
                    selection.execute_git(&mut app, adapter, git, event).await?;
                } else {
                    selection
                        .execute(&mut app, adapter, &mut peer.checker, event)
                        .await?;
                }
                if before.is_some_and(|originals| {
                    originals != peers.iter().map(Peer::snapshot).collect::<Vec<_>>()
                }) {
                    return Err(Finding {
                        law: "withdrawn_trust",
                        event,
                        defect_reached: control.defect_reached(),
                    });
                }
            },
            Action::Peer(peer) => {
                assert!(peer < peers.len(), "bounded local replay peer index");
                selected = peer;
            },
            Action::Receiver(receiver) => {
                peers[selected].adapter.receiver = receiver;
                if let Some(git) = &peers[selected].git {
                    let mut state = git.script.state.lock().unwrap();
                    state.unavailable = matches!(receiver, Receiver::Unavailable);
                    state.stale = matches!(receiver, Receiver::Replaced);
                    state.acknowledgement = if matches!(receiver, Receiver::Failed) {
                        crate::gateway::git::Acknowledgement::ReceiverRejected
                    } else {
                        crate::gateway::git::Acknowledgement::Updated
                    };
                    state.observed = crate::gateway::git::ObservedRef::Commit(
                        if matches!(receiver, Receiver::Healthy) && state.sends > 0 {
                            git.authorization.new_commit.clone()
                        } else {
                            git.authorization.old_commit.clone()
                        },
                    );
                }
            },
            Action::GitRef { new } => {
                let git = peers[selected]
                    .git
                    .as_ref()
                    .expect("Git-ref events select a Git peer");
                git.script.state.lock().unwrap().observed =
                    crate::gateway::git::ObservedRef::Commit(if new {
                        git.authorization.new_commit.clone()
                    } else {
                        git.authorization.old_commit.clone()
                    });
            },
            Action::Reopen { catalog } => {
                drop(app);
                configuration.approvals = if catalog && trusted {
                    peers
                        .iter()
                        .map(|peer| peer.adapter.intent.approval())
                        .collect()
                } else {
                    vec![]
                };
                app = open(configuration.clone(), &control);
            },
            Action::Trust(available) => {
                drop(app);
                trusted = available;
                configuration.approvals.clear();
                configuration.authorization_trust = if available {
                    peers
                        .iter()
                        .map(|peer| peer.adapter.intent.trust())
                        .collect()
                } else {
                    vec![]
                };
                app = open(configuration.clone(), &control);
            },
            Action::Restore => {
                restored = true;
                trusted = true;
                drop(app);
                for peer in &mut peers {
                    peer.adapter.receiver = Receiver::Healthy;
                    peer.adapter.lose_response = false;
                    if let Some(git) = &peer.git {
                        let mut state = git.script.state.lock().unwrap();
                        state.unavailable = false;
                        state.stale = false;
                        state.acknowledgement = crate::gateway::git::Acknowledgement::Updated;
                    }
                }
                configuration.authorization_trust = peers
                    .iter()
                    .map(|peer| peer.adapter.intent.trust())
                    .collect();
                configuration.approvals = peers
                    .iter()
                    .map(|peer| peer.adapter.intent.approval())
                    .collect();
                app = open(configuration.clone(), &control);
            },
        }
        for peer in &mut peers {
            let adapter = &peer.adapter;
            if let Some(git) = &peer.git {
                peer.checker
                    .check_git(&app, &store, &adapter.intent, git, event, false)?;
                continue;
            }
            peer.checker
                .check(&store, &adapter.io.lock().unwrap(), &adapter.intent, event)?;
            check_terminal(
                &app,
                &store,
                &adapter.io.lock().unwrap(),
                &adapter.intent,
                event,
                false,
            )?;
        }
    }
    if trace.require_progress && peers.iter().any(|peer| !peer.eligible_progress) {
        return Err(Finding {
            law: "ineligible_progress",
            event: trace.actions.len(),
            defect_reached: control.defect_reached(),
        });
    }
    for peer in &mut peers {
        let adapter = &peer.adapter;
        if let Some(git) = &peer.git {
            peer.checker.check_git(
                &app,
                &store,
                &adapter.intent,
                git,
                trace.actions.len(),
                trace.require_progress,
            )?;
            continue;
        }
        check_terminal(
            &app,
            &store,
            &adapter.io.lock().unwrap(),
            &adapter.intent,
            trace.actions.len(),
            trace.require_progress,
        )?;
    }
    Ok(())
}

struct Peer {
    adapter: Adapter,
    checker: Checker,
    eligible_progress: bool,
    git: Option<GitPeer>,
}

struct GitPeer {
    authorization: kapsel_authority::GitRefAuthorization,
    script: crate::gateway::git::exploration::Script,
    durable_ack: Mutex<Option<crate::gateway::git::Acknowledgement>>,
}

impl Peer {
    fn snapshot(&self) -> (BTreeMap<String, Value>, usize, usize) {
        let (reads, sends) = self.git.as_ref().map_or_else(
            || {
                let io = self.adapter.io.lock().unwrap();
                (io.reads, io.sends.len())
            },
            |git| {
                let io = git.script.state.lock().unwrap();
                (io.reads, io.sends)
            },
        );
        (
            self.adapter.store.raw_effect(
                &self.adapter.intent.request.operation_id,
                self.git.is_some(),
            ),
            reads,
            sends,
        )
    }
}

impl Checker {
    #[allow(
        clippy::too_many_lines,
        reason = "keep Git intent, raw frozen facts and independently returned bytes together"
    )]
    fn check_git(
        &mut self,
        app: &ServiceApplication,
        store: &Store,
        intent: &Intent,
        git: &GitPeer,
        event: usize,
        require_progress: bool,
    ) -> Checked {
        use crate::gateway::git::{Acknowledgement, ObservedRef};
        let require = |condition, law| {
            if condition {
                Ok(())
            } else {
                Err(Finding {
                    law,
                    event,
                    defect_reached: store.control.defect_reached(),
                })
            }
        };
        let io = git.script.state.lock().unwrap();
        if let Some(law) = io.violation {
            require(false, law)?;
        }
        require(io.sends <= 1, "at_most_one_mutation")?;
        let mut raw = store.raw_effect(&intent.request.operation_id, true);
        if raw.is_empty() {
            return require(!require_progress, "healthy_progress");
        }
        let approval = &git.authorization;
        let digest = crate::lifecycle_exploration_tests::hex(&Sha256::digest(&intent.grant));
        for (field, expected) in [
            ("operation_id", &approval.operation_id),
            ("repository_id", &approval.repository_id),
            ("ref_name", &approval.reference),
            ("old_commit", &approval.old_commit),
            ("new_commit", &approval.new_commit),
            ("authorization_id", &intent.authorization_id),
            ("authorization_signer_key_id", &intent.authorization_key),
            ("authorization_grant_digest", &digest),
        ] {
            require(
                text(&raw, field) == Some(expected.as_str()),
                "original_authority",
            )?;
        }
        require(
            raw.get("signed_authorization_grant") == Some(&Value::Blob(intent.grant.clone())),
            "original_authority",
        )?;
        let acknowledgement = git
            .durable_ack
            .lock()
            .unwrap()
            .unwrap_or(Acknowledgement::Unknown);
        let expected_result = match acknowledgement {
            Acknowledgement::Updated => crate::OperationResult::Succeeded,
            Acknowledgement::RejectedBeforeSend | Acknowledgement::ReceiverRejected => {
                crate::OperationResult::Failed
            },
            Acknowledgement::Unknown => crate::OperationResult::Unknown,
        };
        if matches!(text(&raw, "state"), Some("receiver_observed" | "finalized")) {
            if self.frozen.is_none() {
                require(
                    text(&raw, "acknowledgement") == Some(acknowledgement.as_str()),
                    "git_acknowledgement_binding",
                )?;
                let observed = io.returned_observation.as_ref();
                let bound = match observed {
                    Some(ObservedRef::Commit(commit)) => {
                        text(&raw, "observed_ref_kind") == Some("commit")
                            && text(&raw, "observed_commit") == Some(commit.as_str())
                    },
                    Some(ObservedRef::Missing) => {
                        text(&raw, "observed_ref_kind") == Some("missing")
                            && raw.get("observed_commit") == Some(&Value::Null)
                    },
                    Some(ObservedRef::Unknown) => {
                        text(&raw, "observed_ref_kind") == Some("unknown")
                            && raw.get("observed_commit") == Some(&Value::Null)
                    },
                    None => false,
                };
                require(bound, "frozen_io_binding")?;
            }
            if let Ok(OperationReceipt::Ready { bytes, sha256 }) =
                app.receipt(&approval.operation_id)
            {
                let trust = crate::ReceiptTrust {
                    key_id: intent.receipt_key.clone(),
                    public_key: ed25519_dalek::SigningKey::from_bytes(&intent.receipt_seed)
                        .verifying_key()
                        .to_bytes(),
                    accepted_purpose: "kapsel.git-ref-transition-receipt.v1".into(),
                    not_before_unix_s: 0,
                    not_after_unix_s: 60,
                }
                .encode()
                .unwrap();
                let inspection = crate::inspect_git_receipt(
                    &bytes,
                    &trust,
                    1,
                    crate::InspectionLimits::default(),
                );
                require(
                    inspection.status() == crate::InspectionStatus::Inspected,
                    "original_signer",
                )?;
                require(
                    inspection.statement().is_some_and(|statement| {
                        statement.authorization() == approval
                            && statement.authorization_signer_key_id() == intent.authorization_key
                            && statement.authorization_grant_digest() == digest
                            && statement.acknowledgement() == acknowledgement
                            && Some(statement.observed_ref()) == io.returned_observation.as_ref()
                    }),
                    "receipt_binding",
                )?;
                require(
                    inspection
                        .statement()
                        .is_some_and(|statement| statement.result() == expected_result),
                    "git_result_classification",
                )?;
                require(
                    raw.get("receipt_bytes") == Some(&Value::Blob(bytes.clone())),
                    "original_receipt_bytes",
                )?;
                require(
                    crate::lifecycle_exploration_tests::hex(&Sha256::digest(&bytes)) == sha256,
                    "receipt_digest",
                )?;
                let bytes = Value::Blob(bytes);
                if let Some(original) = &self.original_bytes {
                    require(original == &bytes, "original_receipt_bytes")?;
                } else {
                    self.original_bytes = Some(bytes);
                }
            } else {
                require(!require_progress, "healthy_progress")?;
            }
            for field in ["state", "receipt_bytes", "receipt_digest", "receipt_key_id"] {
                raw.remove(field);
            }
            if let Some(original) = &self.frozen {
                require(
                    original == &raw && self.frozen_reads == io.reads,
                    "frozen_no_io",
                )?;
            } else {
                self.frozen = Some(raw);
                self.frozen_reads = io.reads;
            }
        } else if text(&raw, "state") == Some("not_attempted") {
            require(
                text(&raw, "target_rejection") == Some("stale_ref") && io.sends == 0,
                "rejection_binding",
            )?;
        } else {
            require(!require_progress, "healthy_progress")?;
        }
        drop(io);
        Ok(())
    }
}

impl Selection {
    async fn execute_git(
        &self,
        app: &mut ServiceApplication,
        adapter: &Adapter,
        git: &GitPeer,
        event: usize,
    ) -> Checked {
        let control = &adapter.store.control;
        let writes_before = control.reached().len();
        if let Some((write, delivery)) = self.commit {
            control.fail_next(write, delivery);
        }
        let (sends_before, expected_update) = {
            let mut io = git.script.state.lock().unwrap();
            io.fault = self.cut.fault();
            io.lose_response = self.lose_response;
            let before = adapter
                .store
                .raw_effect(&adapter.intent.request.operation_id, true);
            io.fresh_attempt = before.is_empty() || text(&before, "state") == Some("authorized");
            (
                io.sends,
                io.acknowledgement == crate::gateway::git::Acknowledgement::Updated,
            )
        };
        let mut acknowledgements = Vec::new();
        let _result = app
            .select_with_adapters::<Adapter>(
                &adapter.intent.request.operation_id,
                ServiceExecution {
                    kubernetes_client: None,
                    git_receiver: None,
                    receipt_signing: self.sign.then(|| {
                        (
                            adapter.intent.receipt_seed,
                            adapter.intent.receipt_key.clone(),
                        )
                    }),
                },
                None,
                Some(git.script.receiver()),
                |admission| acknowledgements.push(admission),
                self.cut.fault(),
            )
            .await;
        {
            let io = git.script.state.lock().unwrap();
            if self.lose_response
                && expected_update
                && io.sends > sends_before
                && io.ref_after_send
                    != Some(crate::gateway::git::ObservedRef::Commit(
                        git.authorization.new_commit.clone(),
                    ))
            {
                return Err(Finding {
                    law: "git_lost_response_preserves_update",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        }
        let reached = control.reached();
        if reached[writes_before..].contains(&StorageWrite::Response)
            && control.last_delivery(StorageWrite::Response) != Some(Delivery::NoCommit)
        {
            *git.durable_ack.lock().unwrap() =
                git.script.state.lock().unwrap().returned_acknowledgement;
        }
        if let Some((write, delivery)) = self.commit {
            if !reached[writes_before..].contains(&write)
                || control.last_delivery(write) != Some(delivery)
            {
                return Err(Finding {
                    law: "fault_not_reached",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if write == StorageWrite::Admission
                && delivery != Delivery::Confirmed
                && !acknowledgements.is_empty()
            {
                return Err(Finding {
                    law: "unconfirmed_admission",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        }
        Ok(())
    }

    async fn execute(
        &self,
        app: &mut ServiceApplication,
        adapter: &mut Adapter,
        checker: &mut Checker,
        event: usize,
    ) -> Checked {
        let control = adapter.store.control.clone();
        if let Some((write, delivery)) = self.commit {
            control.fail_next(write, delivery);
        }
        adapter.lose_response = self.lose_response;
        let before = adapter.store.raw(&adapter.intent.request.operation_id);
        adapter.fresh = !matches!(
            text(&before, "state"),
            Some("apply_started" | "receiver_observed" | "finalized")
        );
        let execution = ServiceExecution {
            kubernetes_client: None,
            git_receiver: None,
            receipt_signing: self.sign.then(|| {
                (
                    adapter.intent.receipt_seed,
                    adapter.intent.receipt_key.clone(),
                )
            }),
        };
        let mut acknowledgements = Vec::new();
        let _result = app
            .select_with_adapter(
                &adapter.intent.request.operation_id.clone(),
                execution,
                Some(&mut *adapter),
                |admission| acknowledgements.push(admission),
                self.cut.fault(),
            )
            .await;
        checker.check(
            &adapter.store,
            &adapter.io.lock().unwrap(),
            &adapter.intent,
            event,
        )?;
        if let Some((write, delivery)) = self.commit {
            if !control.reached().contains(&write) || control.last_delivery(write) != Some(delivery)
            {
                return Err(Finding {
                    law: "fault_not_reached",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if write == StorageWrite::Admission
                && delivery != Delivery::Confirmed
                && !acknowledgements.is_empty()
            {
                return Err(Finding {
                    law: "unconfirmed_admission",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        }
        Ok(())
    }
}

fn check_terminal(
    app: &ServiceApplication,
    store: &Store,
    io: &Observations,
    intent: &Intent,
    event: usize,
    require_progress: bool,
) -> Checked {
    let control = &store.control;
    let terminal = store.raw(&intent.request.operation_id);
    if text(&terminal, "state") == Some("not_attempted") {
        if text(&terminal, "target_rejection") == Some("stale_approval")
            && text(&terminal, "preflight_uid") == Some("replacement-uid")
            && io.sends.is_empty()
        {
            return Ok(());
        }
        return Err(Finding {
            law: "rejection_binding",
            event,
            defect_reached: control.defect_reached(),
        });
    }
    match app.receipt(&intent.request.operation_id) {
        Ok(OperationReceipt::Ready { bytes, sha256 }) => {
            let trust = crate::ReceiptTrust {
                key_id: intent.receipt_key.clone(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&intent.receipt_seed)
                    .verifying_key()
                    .to_bytes(),
                accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
                not_before_unix_s: 0,
                not_after_unix_s: 60,
            }
            .encode()
            .unwrap();
            let inspection =
                crate::inspect_receipt(&bytes, &trust, 1, crate::InspectionLimits::default());
            if inspection.status() != crate::InspectionStatus::Inspected {
                return Err(Finding {
                    law: "original_signer",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if !inspection
                .statement()
                .is_some_and(|statement| receipt_matches_columns(statement, &terminal, io, intent))
            {
                return Err(Finding {
                    law: "receipt_binding",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if terminal.get("receipt_bytes") != Some(&Value::Blob(bytes.clone())) {
                return Err(Finding {
                    law: "original_receipt_bytes",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            let digest = crate::lifecycle_exploration_tests::hex(&Sha256::digest(&bytes));
            if digest != sha256 {
                return Err(Finding {
                    law: "receipt_digest",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        },
        _ if !require_progress => {},
        _ => {
            return Err(Finding {
                law: "healthy_progress",
                event,
                defect_reached: control.defect_reached(),
            })
        },
    }
    Ok(())
}

// Named columns have already been bound to original intent and actual I/O by event laws.
// This projects public inspected fields, not the production statement builder or classifier.
fn receipt_matches_columns(
    statement: &crate::ReceiptStatement,
    raw: &BTreeMap<String, Value>,
    io: &Observations,
    intent: &Intent,
) -> bool {
    let texts = [
        ("operation_id", Some(statement.operation_id())),
        ("authorization_id", Some(statement.authorization_id())),
        (
            "authorization_signer_key_id",
            Some(statement.authorization_signer_key_id()),
        ),
        (
            "authorization_grant_digest",
            Some(statement.authorization_grant_digest()),
        ),
        ("namespace", Some(statement.namespace())),
        ("deployment", Some(statement.deployment())),
        ("container", Some(statement.container())),
        (
            "immutable_image_digest",
            Some(statement.immutable_image_digest()),
        ),
        ("write_strategy", Some(statement.write_strategy())),
        (
            "approved_uid",
            statement
                .approved_target()
                .map(|target| target.uid.as_str()),
        ),
        (
            "approved_resource_version",
            statement
                .approved_target()
                .map(|target| target.resource_version.as_str()),
        ),
        ("target_uid", Some(statement.target_uid())),
        (
            "target_resource_version",
            Some(statement.target_resource_version()),
        ),
        ("receiver_uid", statement.receiver_uid()),
        ("receiver_image", statement.observed_image()),
        (
            "receiver_operation_marker",
            statement.observed_operation_marker(),
        ),
        (
            "receiver_resource_version",
            statement.observed_resource_version(),
        ),
        ("rollout_condition_type", statement.rollout_condition_type()),
        (
            "rollout_condition_status",
            statement.rollout_condition_status(),
        ),
        (
            "rollout_condition_reason",
            statement.rollout_condition_reason(),
        ),
    ];
    let integers = [
        ("current_generation", statement.current_generation()),
        ("requested_generation", statement.requested_generation()),
        ("observed_generation", statement.observed_generation()),
        (
            "desired_replicas",
            statement.desired_replicas().map(i64::from),
        ),
        (
            "updated_replicas",
            statement.updated_replicas().map(i64::from),
        ),
        (
            "available_replicas",
            statement.available_replicas().map(i64::from),
        ),
        (
            "unavailable_replicas",
            statement.unavailable_replicas().map(i64::from),
        ),
    ];
    let result = match statement.result() {
        crate::OperationResult::Succeeded => "SUCCEEDED",
        crate::OperationResult::Failed => "FAILED",
        crate::OperationResult::Unknown => "UNKNOWN",
    };
    texts
        .iter()
        .all(|(column, value)| text(raw, column) == *value)
        && integers
            .iter()
            .all(|(column, value)| integer(raw, column) == *value)
        && result == result_from_io(io, intent)
}

fn select(
    commit: Option<(StorageWrite, Delivery)>,
    cut: Cut,
    lose_response: bool,
    sign: bool,
) -> Action {
    Action::Select(Selection {
        commit,
        cut,
        lose_response,
        sign,
    })
}
fn trace(seed: u64, mut prefix: Vec<Action>) -> Trace {
    prefix.extend([
        Action::Restore,
        select(None, Cut::None, false, true),
        Action::Reopen { catalog: false },
        select(None, Cut::None, false, true),
    ]);
    Trace {
        seed,
        peers: 1,
        effects: vec![],
        actions: prefix,
        defect: None,
        require_progress: true,
        source_sha256: String::new(),
        executable_sha256: String::new(),
    }
}

fn multi_trace(seed: u64, peers: usize, prefix: Vec<Action>) -> Trace {
    let mut input = trace(seed, vec![]);
    input.peers = peers;
    input.actions = prefix;
    input.actions.push(Action::Restore);
    for peer in 0..peers {
        input.actions.push(Action::Peer(peer));
        input.actions.push(select(None, Cut::None, false, true));
    }
    input.actions.push(Action::Reopen { catalog: false });
    for peer in (0..peers).rev() {
        input.actions.push(Action::Peer(peer));
        input.actions.push(select(None, Cut::None, false, true));
    }
    input
}

async fn minimize(mut input: Trace, law: &'static str) -> Trace {
    input.require_progress = law == "healthy_progress";
    let mut index = 0;
    while index < input.actions.len() {
        if input.require_progress && matches!(input.actions[index], Action::Restore) {
            index += 1;
            continue;
        }
        let mut candidate = input.clone();
        candidate.actions.remove(index);
        if replay(&candidate, true).await.err().is_some_and(|finding| {
            finding.law == law
                && candidate
                    .defect
                    .is_none_or(|defect| finding.defect_reached.contains(&defect))
        }) {
            input = candidate;
        } else {
            index += 1;
        }
    }
    input
}

pub(crate) async fn executed_write_statements() -> Vec<(StorageWrite, String)> {
    let mut statements = Vec::new();
    for receiver in [
        Receiver::Healthy,
        Receiver::Failed,
        Receiver::Pending,
        Receiver::Replaced,
    ] {
        let control = StorageControl::default();
        let input = trace(
            0,
            vec![
                Action::Receiver(receiver),
                select(None, Cut::None, false, true),
            ],
        );
        assert_eq!(
            replay_with_control(&input, false, control.clone()).await,
            Ok(())
        );
        statements.extend(control.executed_sql());
    }
    for prefix in [
        vec![select(None, Cut::None, false, true)],
        vec![
            Action::Receiver(Receiver::Failed),
            select(None, Cut::None, false, true),
        ],
        vec![
            Action::Receiver(Receiver::Replaced),
            select(None, Cut::None, false, true),
        ],
        vec![
            select(None, Cut::Unsent, false, false),
            Action::Receiver(Receiver::Unavailable),
            select(None, Cut::Frozen, false, false),
        ],
    ] {
        let control = StorageControl::default();
        let mut input = trace(0, prefix);
        input.effects = vec![Effect::Git];
        assert_eq!(
            replay_with_control(&input, false, control.clone()).await,
            Ok(())
        );
        statements.extend(control.executed_sql());
    }
    for (table, writes) in [
        (
            "kubernetes_image_operations",
            vec![
                StorageWrite::Admission,
                StorageWrite::Authorization,
                StorageWrite::Rejection,
                StorageWrite::Attempt,
                StorageWrite::Response,
                StorageWrite::Observation,
                StorageWrite::Receipt,
            ],
        ),
        (
            "git_ref_operations",
            vec![
                StorageWrite::Admission,
                StorageWrite::Rejection,
                StorageWrite::Attempt,
                StorageWrite::Response,
                StorageWrite::Observation,
                StorageWrite::Receipt,
            ],
        ),
    ] {
        for write in writes {
            assert!(
                statements
                    .iter()
                    .any(|(point, sql)| *point == write && sql.contains(table)),
                "missing {table}/{write:?} SQL"
            );
        }
    }
    statements.sort_by(|left, right| left.1.cmp(&right.1));
    statements.dedup_by(|left, right| left.1 == right.1);
    statements
}

#[tokio::test(start_paused = true)]
async fn atomic_delivery_and_receiver_faults_preserve_laws_and_progress() {
    for write in [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
            let input = trace(
                0,
                vec![select(Some((write, delivery)), Cut::None, false, true)],
            );
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{write:?}/{delivery:?}"
                );
            }
        }
    }
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let input = trace(
            1,
            vec![
                select(None, cut, false, false),
                Action::Receiver(Receiver::Failed),
                Action::Reopen { catalog: false },
                select(None, Cut::None, false, true),
            ],
        );
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
    let input = trace(
        2,
        vec![
            select(None, Cut::None, true, true),
            Action::Receiver(Receiver::Unavailable),
            select(None, Cut::None, false, true),
            Action::Reopen { catalog: false },
        ],
    );
    for virtualized in [true, false] {
        assert_eq!(replay(&input, virtualized).await, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
async fn git_atomic_delivery_and_interruption_preserve_laws_and_progress() {
    for write in [
        StorageWrite::Admission,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        for delivery in [Delivery::NoCommit, Delivery::LostAcknowledgement] {
            let mut input = trace(
                0,
                vec![select(Some((write, delivery)), Cut::None, false, true)],
            );
            input.effects = vec![Effect::Git];
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{write:?}/{delivery:?}"
                );
            }
        }
    }
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let mut input = trace(
            1,
            vec![
                select(None, cut, false, false),
                Action::Receiver(Receiver::Failed),
                Action::Reopen { catalog: false },
                select(None, Cut::None, false, true),
            ],
        );
        input.effects = vec![Effect::Git];
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn git_results_follow_acknowledgement_not_the_present_ref() {
    for prefix in [
        vec![select(None, Cut::None, false, true)],
        vec![
            Action::Receiver(Receiver::Failed),
            select(None, Cut::None, false, true),
        ],
        vec![select(None, Cut::None, true, true)],
        vec![
            select(
                Some((StorageWrite::Observation, Delivery::NoCommit)),
                Cut::None,
                true,
                true,
            ),
            Action::GitRef { new: false },
            select(None, Cut::None, false, true),
        ],
        vec![
            select(None, Cut::Unsent, false, false),
            Action::GitRef { new: true },
            select(None, Cut::None, false, true),
        ],
    ] {
        let mut input = trace(9, prefix);
        input.effects = vec![Effect::Git];
        for virtualized in [true, false] {
            assert_eq!(replay(&input, virtualized).await, Ok(()));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn all_peers_preserve_original_authority_during_material_withdrawal() {
    for cut in [Cut::BeforeAttempt, Cut::Unsent, Cut::Frozen] {
        let mut input = multi_trace(
            4,
            3,
            vec![
                Action::Peer(0),
                select(None, cut, false, false),
                Action::Peer(1),
                Action::Receiver(Receiver::Failed),
                select(None, Cut::Frozen, false, false),
                Action::Peer(2),
                select(
                    Some((StorageWrite::Attempt, Delivery::LostAcknowledgement)),
                    Cut::None,
                    false,
                    true,
                ),
                Action::Reopen { catalog: false },
                Action::Trust(false),
                Action::Peer(0),
                select(None, Cut::None, false, true),
                Action::Receiver(Receiver::Replaced),
                Action::Peer(1),
                select(None, Cut::None, false, true),
                Action::Peer(2),
                select(None, Cut::None, false, true),
                Action::Trust(true),
                Action::Peer(1),
                select(None, Cut::None, false, true),
            ],
        );
        for effects in [
            vec![Effect::Kubernetes; 3],
            vec![Effect::Git; 3],
            vec![Effect::Kubernetes, Effect::Git, Effect::Git],
        ] {
            input.effects = effects;
            for virtualized in [true, false] {
                assert_eq!(
                    replay(&input, virtualized).await,
                    Ok(()),
                    "{cut:?}/{virtualized}/{:?}",
                    input.effects
                );
            }
        }
    }
}

fn defect_cases() -> Vec<(Defect, &'static str, Vec<Action>)> {
    vec![
        (
            Defect::GitInferredAcknowledgement,
            "git_acknowledgement_binding",
            vec![
                select(None, Cut::Unsent, false, false),
                Action::GitRef { new: true },
                select(None, Cut::Frozen, false, false),
            ],
        ),
        (
            Defect::Remint,
            "dispatch_provenance",
            vec![select(None, Cut::Unsent, false, false)],
        ),
        (
            Defect::InitialUnknown,
            "initial_result",
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (Defect::NoOp, "healthy_progress", vec![]),
        (
            Defect::WrongPeerRead,
            "original_intent",
            vec![
                select(None, Cut::BeforeAttempt, false, false),
                Action::Peer(1),
                select(None, Cut::BeforeAttempt, false, false),
            ],
        ),
        (
            Defect::WrongSigner,
            "original_signer",
            vec![select(None, Cut::Frozen, false, false)],
        ),
        (
            Defect::ReceiptProjectionSwap,
            "receipt_binding",
            vec![
                Action::Receiver(Receiver::Pending),
                select(None, Cut::Frozen, false, false),
            ],
        ),
        (
            Defect::ReplicaSwap,
            "frozen_io_binding",
            vec![
                Action::Receiver(Receiver::Pending),
                select(None, Cut::Frozen, false, false),
            ],
        ),
    ]
}

#[tokio::test(start_paused = true)]
async fn seeded_defects_fail_intended_laws_and_minimized_replay_reaches_the_branch() {
    for (defect, law, prefix) in defect_cases() {
        let mut input = multi_trace(3, 2, prefix);
        if defect == Defect::GitInferredAcknowledgement {
            input.effects = vec![Effect::Git; 2];
        }
        input.defect = Some(defect);
        for virtualized in [true, false] {
            let finding = replay(&input, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
        }
        let minimized = minimize(input, law).await;
        let document = serde_json::to_vec(&minimized).unwrap();
        let replayed: Trace = serde_json::from_slice(&document).unwrap();
        for virtualized in [true, false] {
            let finding = replay(&replayed, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
        }
        let mut correct = replayed.clone();
        correct.defect = None;
        for virtualized in [true, false] {
            assert_eq!(
                replay(&correct, virtualized).await,
                Ok(()),
                "correct SUT must pass minimized witness"
            );
        }
        println!(
            "KAPSEL_KERNEL_DEFECT {defect:?} {law} actions={} input={}",
            replayed.actions.len(),
            String::from_utf8(document).unwrap()
        );
    }
}

fn defect_law(defect: Defect) -> &'static str {
    match defect {
        Defect::Remint => "dispatch_provenance",
        Defect::InitialUnknown => "initial_result",
        Defect::NoOp => "healthy_progress",
        Defect::UnconditionalWrite => "conditional_binding",
        Defect::ReplicaSwap => "frozen_io_binding",
        Defect::WrongSigner => "original_signer",
        Defect::WrongPeerRead => "original_intent",
        Defect::ReceiptProjectionSwap => "receipt_binding",
        Defect::GitInferredAcknowledgement => "git_acknowledgement_binding",
    }
}

fn check_replay_result(input: &Trace, result: Checked) {
    if let Some(defect) = input.defect {
        let finding = result.unwrap_err();
        assert_eq!(
            finding.law,
            defect_law(defect),
            "unrelated failure is not defect detection"
        );
        assert!(
            finding.defect_reached.contains(&defect),
            "defect branch was not reached"
        );
    } else {
        assert_eq!(result, Ok(()));
    }
}

#[tokio::test(start_paused = true)]
async fn unrelated_or_ineligible_progress_does_not_qualify_as_defect_detection() {
    let mut input = trace(0, vec![]);
    input.actions.clear();
    input.defect = Some(Defect::Remint);
    let finding = replay(&input, true).await.unwrap_err();
    assert_eq!(finding.law, "ineligible_progress");
    assert_ne!(finding.law, defect_law(Defect::Remint));
    assert!(finding.defect_reached.is_empty());
    input.actions = vec![Action::Restore, select(None, Cut::None, false, false)];
    input.defect = Some(Defect::NoOp);
    for virtualized in [true, false] {
        let finding = replay(&input, virtualized).await.unwrap_err();
        assert_eq!(finding.law, "ineligible_progress");
        assert_ne!(finding.law, defect_law(Defect::NoOp));
        assert!(finding.defect_reached.contains(&Defect::NoOp));
    }
}

fn generated(seed: u64, steps: usize) -> Trace {
    let writes = [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ];
    let delivery = if seed & 1 == 0 {
        Delivery::NoCommit
    } else {
        Delivery::LostAcknowledgement
    };
    let effects = match seed % 3 {
        0 => vec![Effect::Kubernetes; 3],
        1 => vec![Effect::Git; 3],
        _ => vec![Effect::Kubernetes, Effect::Git, Effect::Git],
    };
    let mut write = writes[usize::try_from((seed / 2) % 6).unwrap()];
    if matches!(effects[0], Effect::Git) && write == StorageWrite::Authorization {
        write = StorageWrite::Admission;
    }
    let mut actions = vec![select(Some((write, delivery)), Cut::None, false, true)];
    let mut random = seed.wrapping_add(1);
    for _ in 0..steps {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        actions.push(Action::Peer(usize::try_from((random / 8) % 3).unwrap()));
        actions.push(match random % 8 {
            0 => Action::Receiver(Receiver::Unavailable),
            1 => Action::Receiver(Receiver::Pending),
            2 => Action::Receiver(Receiver::Failed),
            3 => Action::Receiver(Receiver::Healthy),
            4 => Action::Reopen {
                catalog: random & 8 == 0,
            },
            5 => Action::Trust(false),
            6 => Action::Trust(true),
            _ => select(None, Cut::None, false, random & 8 == 0),
        });
    }
    let mut input = multi_trace(seed, 3, actions);
    input.effects = effects;
    input
}

#[tokio::test(start_paused = true)]
async fn generated_io_schedules_have_replayable_healthy_suffixes() {
    for steps in [12, 48] {
        for seed in 0..32 {
            let input = generated(seed, steps);
            let document = serde_json::to_vec(&input).unwrap();
            let replayed = serde_json::from_slice(&document).unwrap();
            assert_eq!(
                replay(&replayed, true).await,
                Ok(()),
                "seed={seed}/steps={steps}"
            );
            if seed < 4 {
                assert_eq!(
                    replay(&replayed, false).await,
                    Ok(()),
                    "SQLite seed={seed}/steps={steps}"
                );
            }
        }
    }
}

fn read_trace(path: &Path) -> Trace {
    use std::io::Read;
    assert!(path.is_absolute() && fs::symlink_metadata(path).unwrap().is_file());
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let input: Trace = serde_json::from_slice(&bytes).unwrap();
    assert!(input.actions.len() <= 256 && (1..=4).contains(&input.peers));
    assert!(input.effects.is_empty() || input.effects.len() == input.peers);
    input
}

#[tokio::test(start_paused = true)]
#[ignore = "explicit bounded replay input or private evidence directory required"]
#[allow(
    clippy::too_many_lines,
    reason = "retain generation, bounded replay and minimization custody in one entry point"
)]
async fn kernel_trace_exploration_or_replay() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if let Ok(directory) = std::env::var("KAPSEL_KERNEL_REPLAY_DIRECTORY") {
        let directory = PathBuf::from(directory);
        assert!(directory.is_absolute() && fs::symlink_metadata(&directory).unwrap().is_dir());
        let mut paths = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert!((1..=10_000).contains(&paths.len()));
        paths.sort();
        for path in &paths {
            let input = read_trace(path);
            assert!(input.defect.is_none() && input.require_progress);
            check_replay_result(&input, replay(&input, true).await);
        }
        println!("KAPSEL_KERNEL_REPLAYED cases={}", paths.len());
        return;
    }
    if let Ok(path) = std::env::var("KAPSEL_KERNEL_REPLAY") {
        let path = PathBuf::from(path);
        let input = read_trace(&path);
        check_replay_result(&input, replay(&input, true).await);
        return;
    }
    let requested = PathBuf::from(std::env::var("KAPSEL_KERNEL_EVIDENCE").unwrap());
    assert!(requested.is_absolute() && fs::symlink_metadata(&requested).unwrap().is_dir());
    let directory = fs::canonicalize(requested).unwrap();
    crate::gateway::validate_private_directory(&directory).unwrap();
    let source = crate::lifecycle_exploration_tests::source_identity();
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    let executable_digest = crate::lifecycle_exploration_tests::hex(&Sha256::digest(&executable));
    let number = |name: &str, default: u64| {
        std::env::var(name).map_or(default, |value| value.parse::<u64>().unwrap())
    };
    let seed = number("KAPSEL_KERNEL_SEED", 0);
    let cases = usize::try_from(number("KAPSEL_KERNEL_CASES", 32)).unwrap();
    let steps = usize::try_from(number("KAPSEL_KERNEL_STEPS", 12)).unwrap();
    let shards = usize::try_from(number("KAPSEL_KERNEL_SHARDS", 1)).unwrap();
    let shard = usize::try_from(number("KAPSEL_KERNEL_SHARD_INDEX", 0)).unwrap();
    assert!((1..=10_000).contains(&cases) && (8..=48).contains(&steps));
    assert!((1..=128).contains(&shards) && shards <= cases && shard < shards);
    let inputs = if std::env::var_os("KAPSEL_KERNEL_DEFECTS").is_some() {
        defect_cases()
            .into_iter()
            .map(|(defect, _, prefix)| {
                let mut input = multi_trace(3, 2, prefix);
                if defect == Defect::GitInferredAcknowledgement {
                    input.effects = vec![Effect::Git; 2];
                }
                input.defect = Some(defect);
                input
            })
            .collect::<Vec<_>>()
    } else {
        (0..cases)
            .map(|case| generated(seed.wrapping_add(u64::try_from(case).unwrap()), steps))
            .collect::<Vec<_>>()
    };
    let mut completed = 0;
    for (case, mut input) in inputs.into_iter().enumerate() {
        if case % shards != shard {
            continue;
        }
        input.source_sha256.clone_from(&source);
        input.executable_sha256.clone_from(&executable_digest);
        let persist = |name: &str, trace: &Trace| {
            let bytes = serde_json::to_vec(trace).unwrap();
            assert!(bytes.len() <= 64 * 1024);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(format!("{name}-{case}.json")))
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        };
        persist("case", &input);
        let result = replay(&input, true).await;
        if let Err(finding) = &result {
            let minimized = minimize(input.clone(), finding.law).await;
            persist("finding", &minimized);
            check_replay_result(&minimized, replay(&minimized, true).await);
        }
        check_replay_result(&input, result);
        completed += 1;
    }
    println!(
        "KAPSEL_KERNEL_COMPLETED seed={seed} shard={shard}/{shards} \
         cases={completed} steps={steps}"
    );
    println!("KAPSEL_KERNEL_EVIDENCE source={source} executable={executable_digest}");
}
