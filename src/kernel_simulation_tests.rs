//! Invariant-first Kubernetes slice through the real service, shared policy and atomic record I/O.
//! Receiver and commit delivery are independent facts; the checker never predicts lifecycle phases.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
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
    Receiver(Receiver),
    Reopen { catalog: bool },
    Restore,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    seed: u64,
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
    fn raw(&self) -> BTreeMap<String, Value> {
        if self.virtualized {
            // Named fields are intentionally independent of the production decoder's projection.
            FIELDS
                .iter()
                .filter_map(|field| {
                    self.control
                        .value(ID, field)
                        .map(|value| ((*field).to_owned(), value))
                })
                .collect()
        } else {
            let connection = Connection::open(&self.path).unwrap();
            let mut statement = connection
                .prepare("SELECT * FROM kubernetes_image_operations WHERE operation_id = ?1")
                .unwrap();
            let names = statement
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut rows = statement.query([ID]).unwrap();
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
        if selected != &request() {
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
                UID.into()
            },
            resource_version: VERSION.into(),
        })
    }

    async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
        let payload = permission.into_payload();
        let raw = self.store.raw();
        let mut io = self.io.lock().unwrap();
        if !self.fresh
            || self.store.control.last_delivery(StorageWrite::Attempt) != Some(Delivery::Confirmed)
            || text(&raw, "state") != Some("apply_started")
        {
            io.violation = Some("dispatch_provenance");
        }
        if payload.0 != request()
            || payload.1.deployment_uid != UID
            || payload.1.resource_version != VERSION
        {
            io.violation = Some("original_intent");
        }
        io.sends.push(payload);
        let outcome = ApplyOutcome {
            accepted: true,
            requested_generation: Some(7),
            deployment_uid: Some(UID.into()),
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
        if selected != &request() || outcome.deployment_uid.as_deref() != Some(UID) {
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
                UID.into()
            }),
            resource_version: Some(if sent { "observed-version" } else { VERSION }.into()),
            current_generation: Some(if sent { 7 } else { 3 }),
            observed_generation: Some(if sent && pending {
                6
            } else if sent {
                7
            } else {
                3
            }),
            image: sent.then(|| IMAGE.into()),
            operation_marker: sent.then(|| ID.into()),
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
fn result_from_io(io: &Observations) -> &'static str {
    let Some(observed) = &io.returned else {
        return "UNKNOWN";
    };
    let correlated = observed.deployment_uid.as_deref() == Some(UID)
        && observed.image.as_deref() == Some(IMAGE)
        && observed.operation_marker.as_deref() == Some(ID);
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

fn request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: ID.into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    }
}

fn configuration(path: PathBuf) -> ServiceConfiguration {
    let authorization = ExactAuthorization {
        authorization_id: "original-authorization".into(),
        operation_id: ID.into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
        approved_target: Some(ApprovedTarget {
            uid: UID.into(),
            resource_version: VERSION.into(),
        }),
    };
    let signed_grant =
        crate::gateway::sign_authorization_grant(&authorization, &[17; 32], "original-authority")
            .unwrap();
    ServiceConfiguration {
        journal_path: path,
        authorization_trust: vec![AuthorizationTrust {
            key_id: "original-authority".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                .verifying_key()
                .to_bytes(),
        }],
        approvals: vec![ServiceApproval {
            signed_grant,
            label: "exact snapshot".into(),
        }],
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
        original_grant: &[u8],
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
        let mut raw = store.raw();
        if raw.is_empty() {
            return Ok(());
        }
        let grant_digest = crate::lifecycle_exploration_tests::hex(&Sha256::digest(original_grant));
        require(
            text(&raw, "authorization_id") == Some("original-authorization")
                && text(&raw, "authorization_signer_key_id") == Some("original-authority")
                && text(&raw, "authorization_grant_digest") == Some(grant_digest.as_str())
                && text(&raw, "operation_id") == Some(ID)
                && text(&raw, "namespace") == Some("demo")
                && text(&raw, "deployment") == Some("api")
                && text(&raw, "container") == Some("api")
                && text(&raw, "immutable_image_digest") == Some(IMAGE)
                && raw.get("signed_authorization_grant")
                    == Some(&Value::Blob(original_grant.to_vec()))
                && text(&raw, "approved_uid") == Some(UID)
                && text(&raw, "approved_resource_version") == Some(VERSION),
            "original_authority",
        )?;
        if integer(&raw, "apply_attempted") == Some(1) {
            require(
                text(&raw, "target_uid") == Some(UID)
                    && text(&raw, "target_resource_version") == Some(VERSION),
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
                    text(&raw, "result") == Some(result_from_io(io)),
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
    let mut configuration = configuration(store.path.clone());
    let original_grant = configuration.approvals[0].signed_grant.clone();
    let mut app = open(configuration.clone(), &control);
    let io = Arc::new(Mutex::new(Observations::default()));
    let mut adapter = Adapter {
        store: store.clone(),
        io: io.clone(),
        receiver: Receiver::Healthy,
        lose_response: false,
        fresh: true,
    };
    let mut checker = Checker::default();
    let mut restored = false;
    let mut eligible_progress = false;
    for (event, action) in trace.actions.iter().enumerate() {
        match *action {
            Action::Select(selection) => {
                eligible_progress |= restored
                    && selection.sign
                    && selection.commit.is_none()
                    && matches!(selection.cut, Cut::None)
                    && !selection.lose_response
                    && matches!(adapter.receiver, Receiver::Healthy)
                    && (!store.raw().is_empty() || !configuration.approvals.is_empty());
                selection
                    .execute(&mut app, &mut adapter, &mut checker, &original_grant, event)
                    .await?;
            },
            Action::Receiver(receiver) => adapter.receiver = receiver,
            Action::Reopen { catalog } => {
                drop(app);
                configuration.approvals = if catalog {
                    vec![ServiceApproval {
                        signed_grant: original_grant.clone(),
                        label: "original".into(),
                    }]
                } else {
                    vec![]
                };
                app = open(configuration.clone(), &control);
            },
            Action::Restore => {
                restored = true;
                adapter.receiver = Receiver::Healthy;
                adapter.lose_response = false;
            },
        }
        checker.check(&store, &io.lock().unwrap(), &original_grant, event)?;
    }
    if trace.require_progress && !eligible_progress {
        return Err(Finding {
            law: "ineligible_progress",
            event: trace.actions.len(),
            defect_reached: control.defect_reached(),
        });
    }
    let result = check_terminal(
        &app,
        &store,
        &io.lock().unwrap(),
        trace.actions.len(),
        trace.require_progress,
    );
    result
}

impl Selection {
    async fn execute(
        &self,
        app: &mut ServiceApplication,
        adapter: &mut Adapter,
        checker: &mut Checker,
        original_grant: &[u8],
        event: usize,
    ) -> Checked {
        let control = adapter.store.control.clone();
        if let Some((write, delivery)) = self.commit {
            control.fail_next(write, delivery);
        }
        adapter.lose_response = self.lose_response;
        let before = adapter.store.raw();
        adapter.fresh = !matches!(
            text(&before, "state"),
            Some("apply_started" | "receiver_observed" | "finalized")
        );
        let execution = ServiceExecution {
            kubernetes_client: None,
            git_receiver: None,
            receipt_signing: self.sign.then(|| ([23; 32], "original-receipt".into())),
        };
        let mut acknowledgements = Vec::new();
        let _result = app
            .select_with_adapter(
                ID,
                execution,
                Some(&mut *adapter),
                |admission| acknowledgements.push(admission),
                self.cut.fault(),
            )
            .await;
        checker.check(
            &adapter.store,
            &adapter.io.lock().unwrap(),
            original_grant,
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
    event: usize,
    require_progress: bool,
) -> Checked {
    let control = &store.control;
    let terminal = store.raw();
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
    match app.receipt(ID) {
        Ok(OperationReceipt::Ready { bytes, sha256 }) => {
            let trust = crate::ReceiptTrust {
                key_id: "original-receipt".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[23; 32])
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
                .is_some_and(|statement| receipt_matches_columns(statement, &terminal, io))
            {
                return Err(Finding {
                    law: "receipt_binding",
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
        && result == result_from_io(io)
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
        actions: prefix,
        defect: None,
        require_progress: true,
        source_sha256: String::new(),
        executable_sha256: String::new(),
    }
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
    statements.sort_by(|left, right| left.1.cmp(&right.1));
    statements.dedup_by(|left, right| left.1 == right.1);
    for write in [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Rejection,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        assert!(
            statements.iter().any(|(point, _)| *point == write),
            "missing {write:?} SQL"
        );
    }
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

fn defect_cases() -> Vec<(Defect, &'static str, Vec<Action>)> {
    vec![
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
        let mut input = trace(3, prefix);
        input.defect = Some(defect);
        for virtualized in [true, false] {
            let finding = replay(&input, virtualized).await.unwrap_err();
            assert_eq!(finding.law, law);
            assert!(finding.defect_reached.contains(&defect));
        }
        let minimized = minimize(input, law).await;
        let document = serde_json::to_vec(&minimized).unwrap();
        let replayed: Trace = serde_json::from_slice(&document).unwrap();
        let finding = replay(&replayed, true).await.unwrap_err();
        assert_eq!(finding.law, law);
        assert!(finding.defect_reached.contains(&defect));
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
        Defect::ReceiptProjectionSwap => "receipt_binding",
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

fn generated(seed: u64) -> Trace {
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
    let mut actions = vec![select(
        Some((writes[usize::try_from((seed / 2) % 6).unwrap()], delivery)),
        Cut::None,
        false,
        true,
    )];
    let mut random = seed + 1;
    for _ in 0..12 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        actions.push(match random % 6 {
            0 => Action::Receiver(Receiver::Unavailable),
            1 => Action::Receiver(Receiver::Pending),
            2 => Action::Receiver(Receiver::Failed),
            3 => Action::Receiver(Receiver::Healthy),
            4 => Action::Reopen { catalog: true },
            _ => select(None, Cut::None, false, random & 8 == 0),
        });
    }
    trace(seed, actions)
}

#[tokio::test(start_paused = true)]
async fn generated_io_schedules_have_replayable_healthy_suffixes() {
    for seed in 0..32 {
        let input = generated(seed);
        let document = serde_json::to_vec(&input).unwrap();
        let replayed = serde_json::from_slice(&document).unwrap();
        assert_eq!(replay(&replayed, true).await, Ok(()), "seed={seed}");
    }
}

#[tokio::test(start_paused = true)]
#[ignore = "explicit bounded replay input or private evidence directory required"]
async fn kernel_trace_exploration_or_replay() {
    use std::{
        io::{Read, Write},
        os::unix::fs::OpenOptionsExt,
    };
    if let Ok(path) = std::env::var("KAPSEL_KERNEL_REPLAY") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute());
        let mut bytes = Vec::new();
        fs::File::open(path)
            .unwrap()
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 64 * 1024);
        let input: Trace = serde_json::from_slice(&bytes).unwrap();
        assert!(input.actions.len() <= 256);
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
    let inputs = if std::env::var_os("KAPSEL_KERNEL_DEFECTS").is_some() {
        defect_cases()
            .into_iter()
            .map(|(defect, _, prefix)| {
                let mut input = trace(3, prefix);
                input.defect = Some(defect);
                input
            })
            .collect::<Vec<_>>()
    } else {
        (0..32).map(generated).collect::<Vec<_>>()
    };
    for (case, mut input) in inputs.into_iter().enumerate() {
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
        persist("input", &input);
        let result = replay(&input, true).await;
        if let Err(finding) = &result {
            let minimized = minimize(input.clone(), finding.law).await;
            persist("finding", &minimized);
            check_replay_result(&minimized, replay(&minimized, true).await);
        }
        check_replay_result(&input, result);
    }
    println!("KAPSEL_KERNEL_EVIDENCE source={source} executable={executable_digest}");
}
