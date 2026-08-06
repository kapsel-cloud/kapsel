//! Deterministic orchestration for the fixed public Kapsel sandbox.
//!
//! This package owns sandbox admission, bounded scheduling, public projection, receipt retention,
//! and cleanup. It delegates effect lifecycle and receiver classification to
//! [`kapsel::Application`] and exposes no generic provider, storage, or capability interface.

use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    fs::OpenOptions,
    io::Write,
    marker::PhantomData,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use http::{
    header::{self, HeaderValue},
    Method, Request, Response, StatusCode,
};

use kapsel::{
    AgentRequest, Application, ApplicationError, OperationResult, OperatorConfiguration,
    TargetRejection,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod backup;
mod controller_role;
mod fixed_staging;
pub use fixed_staging::GenerationIdentity;
mod kubernetes_policy;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Slice 4 cleanup composition follows accepted dispatch and retention integration"
    )
)]
mod local_roles;
mod native_process;
mod runner_handoff;
mod runner_host;
mod runner_process;
mod service_schema;
mod state_root;
pub use controller_role::{
    AuthorityController, CleanupController, ControllerConfiguration, ControllerError,
    ControllerRole, ControllerRun, ControllerWait, RetentionController,
};
#[cfg(test)]
pub(crate) use local_roles::CleanupRole;
pub(crate) use local_roles::{RetentionRole, SchedulerRole, SchedulerStep};
use runner_handoff::{
    constant_time_equal, credential_verifier, handle_connection_at, report_payload_digest,
    HandoffIdentity,
};
pub use runner_handoff::{
    run_application_handoff, serve_private_handoff, HandoffAssignment, HandoffError,
    TerminalHandoffReport,
};
pub use runner_process::run as run_runner_process;

/// Runs the one fixed native sandbox process composition.
///
/// This doc-hidden unsupported package-to-binary bridge accepts only the shipped command grammar.
/// It does not expose state, storage, backup, or lifecycle sequencing.
#[doc(hidden)]
#[must_use]
pub fn run_native_process() -> std::process::ExitCode {
    native_process::main(state_root::DeploymentProfile::Production)
}

/// Runs the fixed unprivileged state-root process test harness.
///
/// This no-input bridge is compiled only for the separately named integration-test executable. The
/// ordinary `kapsel-sandbox` binary always uses fixed production identities and architecture.
#[cfg(feature = "state-root-test-harness")]
#[doc(hidden)]
#[must_use]
pub fn run_state_root_test_harness() -> std::process::ExitCode {
    native_process::main(state_root::DeploymentProfile::Test)
}

#[cfg(test)]
mod cluster_policy_tests;
#[cfg(test)]
mod service_contract_tests;
#[cfg(test)]
mod test_authority;

const QUEUED_RUNS_MAX: i64 = 32;
const ACTIVE_RUNS_MAX: i64 = 1;
const EVENT_COUNT_MAX: i64 = 64;
const PUBLIC_RETENTION_SECONDS: i64 = 86_400;
const SANDBOX_DEADLINE_SECONDS: i64 = 180;
const SCHEDULER_LEASE_SECONDS: i64 = 30;
const RECEIPT_BYTES_MAX: usize = 16 * 1024;

#[cfg(test)]
pub(crate) fn test_authority_identity() -> GenerationIdentity {
    GenerationIdentity::new(1, test_authority::manifest_digest([7; 32]))
        .expect("fixed test authority identity")
}
const PROVISIONED_OBJECT_OWNERS_MAX: i64 = 64;
pub(crate) const PROVISIONED_OBJECT_OWNERS_MAX_USIZE: usize = 64;
type StoredReportBinding = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<u8>,
);

const FORBIDDEN_HEADERS: [&str; 17] = [
    "authorization",
    "cookie",
    "transfer-encoding",
    "range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "forwarded",
    "x-forwarded-for",
    "x-client-cert",
    "x-forwarded-client-cert",
    "x-ssl-client-cert",
    "ssl-client-cert",
    "content-encoding",
    "traceparent",
    "tracestate",
];

/// One caller-selectable fixed scenario.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    /// Fixed image intended to reach the available-rollout predicate.
    Healthy,
    /// Fixed unavailable image intended to reach `ProgressDeadlineExceeded`.
    UnavailableImage,
}

impl Scenario {
    fn token(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::UnavailableImage => "unavailable-image",
        }
    }

    fn parse(value: &str) -> Result<Self, ServiceError> {
        match value {
            "healthy" => Ok(Self::Healthy),
            "unavailable-image" => Ok(Self::UnavailableImage),
            _ => Err(ServiceError::InvalidRequest),
        }
    }
}

/// Whether an admission created a run or replayed its durable identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    /// A new durable run was committed.
    Created,
    /// The same key and scenario recovered an existing durable run.
    Replayed,
}

/// Durable admission response, distinct from dispatch or receiver outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    /// Opaque 128-bit public bearer locator.
    pub run_id: String,
    /// Server-owned KAP-0038 operation identity.
    pub operation_id: String,
    /// Fixed scenario selected by the caller.
    pub scenario: Scenario,
    /// Whether this call created or replayed the admission.
    pub disposition: AdmissionDisposition,
    /// Whole-second admission time.
    pub admitted_at_unix_s: i64,
    /// Public expiry boundary.
    pub expires_at_unix_s: i64,
    /// Durable public event high-water mark.
    pub last_sequence: u8,
}

/// Durable scheduler lease appointing one recovery owner without changing public outcome.
#[derive(Clone, Eq, PartialEq)]
pub struct DispatchLease {
    /// Public run identity whose active reservation is leased.
    pub run_id: String,
    /// Opaque private lease identity generated by the service.
    lease_id: String,
    /// Monotonic lease generation for restart recovery.
    epoch: i64,
    /// Absolute whole-second lease expiry.
    expires_at_unix_s: i64,
    /// Raw private runner credential, never retained in system state.
    handoff_credential: [u8; 32],
    /// Durable authority generation pinned by the dispatch transaction.
    authority: GenerationIdentity,
}

impl DispatchLease {
    pub(crate) fn epoch(&self) -> i64 {
        self.epoch
    }
}

impl fmt::Debug for DispatchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchLease")
            .field("run_id", &self.run_id)
            .field("lease_id", &self.lease_id)
            .field("epoch", &self.epoch)
            .field("expires_at_unix_s", &self.expires_at_unix_s)
            .field("authority", &self.authority)
            .field("handoff_credential", &"[REDACTED]")
            .finish()
    }
}

/// One exact policy object frozen at admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyObjectRequirement {
    /// Canonical kind/name identity within the per-run namespace.
    pub identity: String,
    /// Exact revision-owned canonical object body.
    pub canonical_body: serde_json::Value,
    /// SHA-256 digest of the revision-owned canonical policy content.
    pub content_digest: String,
}

/// Closed baseline/canary objects and provider-neutral behavior records.
pub type ClusterBoundarySpecification = (Vec<PolicyObjectRequirement>, Vec<serde_json::Value>);

/// One observed owned policy object returned by deterministic provisioning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProvisionedObject {
    /// Canonical kind/name identity.
    pub identity: String,
    /// Exact immutable Kubernetes UID observed for the object.
    pub uid: String,
    /// Exact server-owned cleanup label observed on the object.
    pub owner_label: String,
    /// SHA-256 digest of the observed policy-relevant content.
    pub content_digest: String,
}

/// One deterministic post-deletion observation for a recorded owned object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupObjectAbsence {
    /// Exact Kubernetes kind.
    pub kind: String,
    /// Exact namespace, absent only for the owned Namespace object.
    pub namespace: Option<String>,
    /// Exact object name.
    pub name: String,
    /// Exact immutable UID recorded before deletion.
    pub uid: String,
    /// Exact server-owned cleanup label recorded before deletion.
    pub owner_label: String,
    /// Whether the exact object remains present at observation time.
    pub present: bool,
}

/// Complete deterministic absence evidence consumed by cleanup completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupAbsenceEvidence {
    /// Exact recorded namespace UID.
    pub namespace_uid: String,
    /// Durable post-provisioning cleanup epoch observed after the final delete plan.
    pub cleanup_epoch: String,
    /// Durable deletion-plan attempt observed after its requests were issued.
    pub cleanup_attempt: i64,
    /// Exact digest of the durably issued delete-request list.
    pub plan_digest: String,
    /// Unique bounded observation identity consumed at most once.
    pub observation_id: String,
    /// One observation for every append-only recorded provisioned object.
    pub objects: Vec<CleanupObjectAbsence>,
    /// Objects returned by the fixed current-owner orphan scan; success requires zero.
    pub owned_orphans: Vec<ObservedPolicyObject>,
}

/// Fixed server-owned target specification frozen at admission and completed at dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningSpecification {
    /// Public run identity.
    pub run_id: String,
    /// Fixed namespace name derived from the run identity.
    pub namespace: String,
    /// Exact admitted deployment-policy revision.
    pub policy_revision: String,
    /// Exact server-owned cleanup identity.
    pub cleanup_identity: String,
    /// Server-owned execution-window duration frozen at admission.
    pub deadline_seconds: i64,
    /// Absolute maximum execution deadline established transactionally at dispatch.
    pub deadline_at_unix_s: i64,
    /// Digest binding the admitted policy revision to its exact inventory.
    pub policy_inventory_digest: String,
    /// Exact policy object inventory required before Application invocation.
    pub required_objects: Vec<PolicyObjectRequirement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProvisionedTarget {
    namespace_uid: String,
    policy_revision: String,
    policy_inventory_digest: String,
    cleanup_identity: String,
    objects: Vec<ProvisionedObject>,
}

/// One bounded Kubernetes object response consumed by cluster-policy verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedPolicyObject {
    /// Complete bounded Kubernetes response body.
    pub body: serde_json::Value,
}

/// Provider-neutral boundary facts required before a run policy can be accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterBoundaryObservation {
    /// Complete bounded immutable baseline and canary object responses; order is not trusted.
    pub objects: Vec<ObservedPolicyObject>,
    /// Complete canonical provider-neutral admission/network behavior records.
    pub behavior_records: Vec<serde_json::Value>,
}

/// Complete bounded composition observed by the controller-owned provisioning path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedClusterComposition {
    /// Fixed cluster runtime, network, admission, and canary facts.
    pub boundary: ClusterBoundaryObservation,
    /// Exact ten explicit current-run objects; order is not trusted.
    pub run_objects: Vec<ObservedPolicyObject>,
    /// At most two generated ReplicaSets and one generated Pod observed by exact UID.
    pub generated_children: Vec<ObservedPolicyObject>,
    /// Any extra object carrying the current cleanup owner marker.
    pub owned_orphans: Vec<ObservedPolicyObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProvisioningClosureEvidence {
    boundary_uid_digest: String,
    deployment_uid: String,
    deployment_resource_version: String,
    deployment_current_image: String,
}

/// Exact old/new Deployment bodies presented to the closed conditional-operation rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalDeploymentObservation {
    /// Complete bounded old Deployment request object.
    pub old_object: serde_json::Value,
    /// Complete bounded new Deployment request object.
    pub new_object: serde_json::Value,
}

/// Disclosure-reviewed sandbox execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    /// Durably admitted and waiting for dispatch.
    Queued,
    /// Owned setup or the configured application has begun.
    Running,
    /// KAP-0038 returned a permanent pre-attempt rejection.
    NotAttempted,
    /// Setup provably failed before application invocation.
    ServiceFailed,
    /// KAP-0038 returned a receiver result.
    Terminal,
}

impl ExecutionState {
    #[cfg(test)]
    fn token(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::NotAttempted => "not_attempted",
            Self::ServiceFailed => "service_failed",
            Self::Terminal => "terminal",
        }
    }

    fn parse(value: &str) -> Result<Self, ServiceError> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "not_attempted" => Ok(Self::NotAttempted),
            "service_failed" => Ok(Self::ServiceFailed),
            "terminal" => Ok(Self::Terminal),
            _ => Err(ServiceError::Unavailable),
        }
    }
}

/// Cleanup state independent from operation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    /// Cleanup is durably owned but has not begun.
    Pending,
    /// Cleanup is being reconciled.
    Running,
    /// Every owned target is confirmed absent.
    Succeeded,
    /// Cleanup failed and remains retryable.
    Failed,
}

impl CleanupState {
    fn token(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, ServiceError> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(ServiceError::Unavailable),
        }
    }
}

/// Public snapshot containing no private gateway state or local path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Public run identity.
    pub run_id: String,
    /// Server-owned operation identity.
    pub operation_id: String,
    /// Fixed scenario.
    pub scenario: Scenario,
    /// Sandbox-owned execution projection.
    pub execution_state: ExecutionState,
    /// Receiver result only for a terminal KAP-0038 report.
    pub receiver_result: Option<String>,
    /// Pre-attempt rejection only for `not_attempted`.
    pub target_rejection: Option<String>,
    /// Whether exact frozen receipt bytes are retrievable.
    pub receipt_available: bool,
    /// Independent cleanup state.
    pub cleanup_state: CleanupState,
    /// Admission time.
    pub admitted_at_unix_s: i64,
    /// Expiry time.
    pub expires_at_unix_s: i64,
    /// Durable event high-water mark.
    pub last_sequence: u8,
}

/// One contiguous disclosure-reviewed public event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// Contiguous event sequence.
    pub sequence: u8,
    /// Contract-owned event kind.
    pub kind: String,
    /// Whole-second event time.
    pub occurred_at_unix_s: i64,
    /// Execution projection after the event.
    pub execution_state: ExecutionState,
    /// Receiver result after the event.
    pub receiver_result: Option<String>,
    /// Target rejection after the event.
    pub target_rejection: Option<String>,
    /// Receipt availability after the event.
    pub receipt_available: bool,
    /// Cleanup projection after the event.
    pub cleanup_state: CleanupState,
}

/// A bounded replay page from one durable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    /// Public run identity.
    pub run_id: String,
    /// Events after the requested cursor.
    pub events: Vec<Event>,
    /// High-water mark used for this response.
    pub last_sequence: u8,
    /// Cursor for the next request.
    pub next_after: u8,
}

/// Bounded sandbox failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// Hostile or incompatible request input.
    InvalidRequest,
    /// Route or body API version is unsupported.
    UnsupportedVersion,
    /// No retained run matched the bearer locator.
    RunNotFound,
    /// An expiry tombstone matched without disclosing former facts.
    RunExpired,
    /// The idempotency key already names another scenario.
    IdempotencyConflict,
    /// Anonymous source controls rejected the request before admission.
    RateLimited,
    /// Queue capacity was exhausted before admission.
    CapacitySaturated,
    /// Global stop or a required durable dependency failed closed.
    Unavailable,
    /// Active capacity has no free reservation.
    ActiveSaturated,
    /// No receipt is retrievable for this run.
    ReceiptNotAvailable,
    /// Cleanup observed a different target identity.
    OwnershipMismatch,
    /// Provisioning did not establish the exact admitted policy and cleanup owner.
    PolicyMismatch,
    /// Another unexpired scheduler lease owns recovery.
    LeaseBusy,
    /// The dispatch-established absolute execution deadline has elapsed.
    DeadlineExceeded,
    /// The requested transition is incompatible with durable state.
    InvalidTransition,
}

/// Non-secret fixed authority-root configuration for one service process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityConfiguration {
    root: PathBuf,
    controller_uid: u32,
    controller_gid: u32,
    staging_uid: u32,
    staging_gid: u32,
}

impl AuthorityConfiguration {
    /// Binds the one fixed authority root and its separate numeric owners.
    #[must_use]
    #[allow(
        clippy::similar_names,
        reason = "the fixed controller and staging UID/GID pairs remain deliberately explicit"
    )]
    pub fn new(
        root: PathBuf,
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
    ) -> Self {
        Self {
            root,
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
        }
    }

    /// Validates and atomically activates the fixed incoming authority generation.
    ///
    /// This operation must run under the configured staging identity. It accepts no authority
    /// payload through the process interface; the fixed owner-private inbox is its sole source.
    ///
    /// # Errors
    ///
    /// Returns unavailable unless the complete incoming inventory, role identities, ownership,
    /// modes, monotonic generation, and crash-recovery state are valid.
    pub fn activate_incoming(&self) -> Result<GenerationIdentity, ServiceError> {
        fixed_staging::FixedStagingInstaller::open(
            &self.root,
            self.controller_uid,
            self.controller_gid,
            self.staging_uid,
            self.staging_gid,
        )
        .and_then(|installer| installer.activate_incoming())
        .map_err(|_| ServiceError::Unavailable)
    }

    fn open_reader(&self) -> Result<fixed_staging::FixedStagingReader, ServiceError> {
        fixed_staging::FixedStagingReader::open(
            &self.root,
            self.controller_uid,
            self.controller_gid,
            self.staging_uid,
            self.staging_gid,
        )
        .map_err(|_| ServiceError::Unavailable)
    }
}

#[allow(
    dead_code,
    reason = "the accepted stopped backup boundary precedes its private generation coordinator"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackupPublication {
    pub(crate) generation: u64,
    pub(crate) captured_at: i64,
    pub(crate) authorities: Vec<GenerationIdentity>,
    pub(crate) predecessor: Option<(u64, String)>,
}

/// SQLite-backed fixed sandbox service.
#[derive(Clone)]
pub struct Service {
    database_path: PathBuf,
    receipt_directory: PathBuf,
    pinned_state: Option<Arc<PinnedServiceState>>,
    authority: Arc<fixed_staging::FixedStagingReader>,
    origin: String,
}

struct PinnedServiceState {
    state_directory: fs::File,
    database: fs::File,
    receipts: fs::File,
}

#[allow(
    dead_code,
    reason = "the accepted stopped backup boundary precedes its private generation coordinator"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublishedBackup {
    pub(crate) generation: u64,
    pub(crate) captured_at: i64,
    pub(crate) manifest_digest: String,
    pub(crate) authorities: Vec<GenerationIdentity>,
}

#[allow(
    dead_code,
    reason = "the accepted stopped backup boundary precedes its private generation coordinator"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackupPublicationState {
    Empty,
    Pending(BackupPublication),
    Current(PublishedBackup),
    Replacing {
        current: PublishedBackup,
        pending: BackupPublication,
    },
    Deleting {
        current: PublishedBackup,
        deleting: PublishedBackup,
    },
}

#[allow(
    dead_code,
    reason = "the accepted stopped backup boundary precedes its private generation coordinator"
)]
pub(crate) struct StoppedBackupService<'guard> {
    service: Service,
    _guard: PhantomData<&'guard ()>,
}

#[derive(Clone, Copy)]
pub(crate) enum ExpiryTransactionBarrier {
    BeforeCommit,
    AfterCommit,
}

#[allow(
    dead_code,
    reason = "the accepted stopped backup boundary precedes its private generation coordinator"
)]
impl StoppedBackupService<'_> {
    fn open_internal(
        database_path: &Path,
        receipt_directory: &Path,
        authority: &AuthorityConfiguration,
        pinned_state: Option<PinnedServiceState>,
    ) -> Result<Self, ServiceError> {
        if !database_path.is_absolute() || !receipt_directory.is_absolute() {
            return Err(ServiceError::Unavailable);
        }
        let database_name = database_path.file_name().ok_or(ServiceError::Unavailable)?;
        let database_parent =
            fs::canonicalize(database_path.parent().ok_or(ServiceError::Unavailable)?)
                .map_err(|_| ServiceError::Unavailable)?;
        let database_path = database_parent.join(database_name);
        let receipt_directory =
            fs::canonicalize(receipt_directory).map_err(|_| ServiceError::Unavailable)?;
        if let Some(pinned) = pinned_state.as_ref() {
            validate_pinned_state(&database_path, &receipt_directory, pinned)?;
        }
        let authority = Arc::new(authority.open_reader()?);
        let service = Service {
            database_path,
            receipt_directory,
            pinned_state: pinned_state.map(Arc::new),
            authority,
            origin: "https://kapsel.invalid".into(),
        };
        let connection = service.read_only_connection()?;
        validate_exact_service_schema(&connection)?;
        validate_authority_pins(&connection)?;
        preflight_backup_schema(&connection)?;
        validate_serial_capacity(&connection)?;
        let stopped: bool = connection
            .query_row(
                "SELECT stopped = 1 FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        service.validate_authority_reference_owners(&connection)?;
        service.validate_pinned_paths()?;
        Ok(Self {
            service,
            _guard: PhantomData,
        })
    }

    pub(crate) fn open_restored(
        database_path: &Path,
        receipt_directory: &Path,
        authority: &AuthorityConfiguration,
    ) -> Result<Self, ServiceError> {
        Self::open_internal(database_path, receipt_directory, authority, None)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        database_path: impl AsRef<Path>,
        receipt_directory: impl AsRef<Path>,
        digest_key: [u8; 32],
    ) -> Result<Self, ServiceError> {
        if digest_key == [0; 32] {
            return Err(ServiceError::Unavailable);
        }
        let database_path = database_path.as_ref();
        let parent = database_path.parent().ok_or(ServiceError::Unavailable)?;
        Self::open_internal(
            database_path,
            receipt_directory.as_ref(),
            &test_authority::configuration(parent, digest_key),
            None,
        )
    }

    pub(crate) fn publication_state(&self) -> Result<BackupPublicationState, ServiceError> {
        self.service.backup_publication_state()
    }

    pub(crate) fn resume_pending(&self) -> Result<BackupPublication, ServiceError> {
        self.service.resume_pending_backup_publication()
    }

    pub(crate) fn begin_publication(
        &self,
        generation: u64,
        captured_at: i64,
    ) -> Result<BackupPublication, ServiceError> {
        self.service
            .begin_backup_publication(generation, captured_at)
    }

    pub(crate) fn finish_publication(
        &self,
        generation: u64,
        manifest_digest: &str,
    ) -> Result<Option<u64>, ServiceError> {
        self.service
            .finish_backup_publication(generation, manifest_digest)
    }

    pub(crate) fn finish_deletion(&self, generation: u64) -> Result<(), ServiceError> {
        self.service.finish_backup_deletion(generation)
    }

    pub(crate) fn restore_publication(
        &self,
        selected: &BackupPublication,
        manifest_digest: &str,
    ) -> Result<(), ServiceError> {
        self.service
            .restore_backup_publication(selected, manifest_digest)
    }

    pub(crate) fn apply_restore_expiry_with_barrier<F>(
        &self,
        now_unix_s: i64,
        barrier: F,
    ) -> Result<(), ServiceError>
    where
        F: FnMut(ExpiryTransactionBarrier) -> Result<(), ServiceError>,
    {
        timestamp(now_unix_s)?;
        self.service
            .expire_transaction_with_barrier(now_unix_s, false, barrier)
    }
}

/// Commits the operator-owned admission stop using only the existing private admission database.
///
/// This path deliberately does not open receipt storage, load key material, run retention, or
/// initialize/migrate service state. It therefore remains available when those dependencies fail.
///
/// # Errors
///
/// Returns [`ServiceError::Unavailable`] unless the existing owner-private database and singleton
/// control row can be opened, updated, and read back safely.
pub fn set_global_stop(database_path: impl AsRef<Path>, stopped: bool) -> Result<(), ServiceError> {
    set_global_stop_internal(database_path.as_ref(), stopped, None)
}

fn set_global_stop_internal(
    database_path: &Path,
    stopped: bool,
    pinned: Option<(&Path, &PinnedServiceState)>,
) -> Result<(), ServiceError> {
    if !database_path.is_absolute() {
        return Err(ServiceError::Unavailable);
    }
    let database_name = database_path.file_name().ok_or(ServiceError::Unavailable)?;
    let database_parent =
        fs::canonicalize(database_path.parent().ok_or(ServiceError::Unavailable)?)
            .map_err(|_| ServiceError::Unavailable)?;
    validate_private_directory(&database_parent)?;
    let database_path = database_parent.join(database_name);
    if let Some((receipts, pinned)) = pinned {
        let receipts = fs::canonicalize(receipts).map_err(|_| ServiceError::Unavailable)?;
        validate_pinned_state(&database_path, &receipts, pinned)?;
    }
    let connection = open_database_connection(&database_path)?;
    commit_global_stop(&connection, stopped)?;
    if let Some((receipts, pinned)) = pinned {
        let receipts = fs::canonicalize(receipts).map_err(|_| ServiceError::Unavailable)?;
        validate_pinned_state(&database_path, &receipts, pinned)?;
    }
    Ok(())
}

impl Service {
    /// Opens a sandbox store separate from every KAP-0038 gateway journal.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when directories or durable state cannot be opened,
    /// configured, or migrated.
    pub fn open(
        database_path: impl AsRef<Path>,
        receipt_directory: impl AsRef<Path>,
        authority: &AuthorityConfiguration,
        now_unix_s: i64,
    ) -> Result<Self, ServiceError> {
        Self::open_internal(
            database_path.as_ref(),
            receipt_directory.as_ref(),
            authority,
            now_unix_s,
            None,
        )
    }

    fn open_internal(
        database_path: &Path,
        receipt_directory: &Path,
        authority: &AuthorityConfiguration,
        now_unix_s: i64,
        pinned_state: Option<PinnedServiceState>,
    ) -> Result<Self, ServiceError> {
        timestamp(now_unix_s)?;
        if !database_path.is_absolute() || !receipt_directory.is_absolute() {
            return Err(ServiceError::Unavailable);
        }
        let database_name = database_path.file_name().ok_or(ServiceError::Unavailable)?;
        let database_parent =
            fs::canonicalize(database_path.parent().ok_or(ServiceError::Unavailable)?)
                .map_err(|_| ServiceError::Unavailable)?;
        let database_path = database_parent.join(database_name);
        let receipt_directory =
            fs::canonicalize(receipt_directory).map_err(|_| ServiceError::Unavailable)?;
        if let Some(pinned) = pinned_state.as_ref() {
            validate_pinned_state(&database_path, &receipt_directory, pinned)?;
        }
        let authority = Arc::new(authority.open_reader()?);
        let pending_collection = pending_authority_collection(&database_path)?;
        if let Some(identity) = pending_collection.as_ref() {
            authority
                .validate_collection_recovery(identity)
                .map_err(|_| ServiceError::Unavailable)?;
        } else {
            authority
                .tombstone_keyring()
                .map_err(|_| ServiceError::Unavailable)?;
        }
        let service = Self {
            database_path,
            receipt_directory,
            pinned_state: pinned_state.map(Arc::new),
            authority,
            origin: "https://kapsel.invalid".into(),
        };
        service.initialize()?;
        service.recover_authority_collection()?;
        service
            .authority
            .tombstone_keyring()
            .map_err(|_| ServiceError::Unavailable)?;
        Ok(service)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        database_path: impl AsRef<Path>,
        receipt_directory: impl AsRef<Path>,
        digest_key: [u8; 32],
        now_unix_s: i64,
    ) -> Result<Self, ServiceError> {
        if digest_key == [0; 32] {
            return Err(ServiceError::Unavailable);
        }
        let database_path = database_path.as_ref().to_owned();
        let receipt_directory = receipt_directory.as_ref().to_owned();
        let parent = database_path.parent().ok_or(ServiceError::Unavailable)?;
        Self::open(
            &database_path,
            &receipt_directory,
            &test_authority::configuration(parent, digest_key),
            now_unix_s,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one closed read-only predecessor, authority, and owner audit precedes migration"
    )]
    fn preflight_stopped_state_root_migration(
        database_path: &Path,
        authority: &AuthorityConfiguration,
    ) -> Result<(), ServiceError> {
        let database_path =
            fs::canonicalize(database_path).map_err(|_| ServiceError::Unavailable)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        preflight_existing_authority_schema(&connection)?;
        validate_authority_pins(&connection)?;
        let backup_tables: i64 = connection
            .query_row(
                concat!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ",
                    "('backup_generations', 'backup_authority_references')"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !matches!(backup_tables, 0 | 2) {
            return Err(ServiceError::Unavailable);
        }
        validate_migration_schema(&connection, backup_tables == 2)?;
        if backup_tables == 2 {
            preflight_backup_schema(&connection)?;
            let rows: i64 = connection
                .query_row(
                    concat!(
                        "SELECT (SELECT COUNT(*) FROM backup_generations) + ",
                        "(SELECT COUNT(*) FROM backup_authority_references)"
                    ),
                    [],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if rows != 0 {
                return Err(ServiceError::Unavailable);
            }
        }
        let valid: bool = connection
            .query_row(
                concat!(
                    "SELECT stopped = 1 ",
                    "AND NOT EXISTS(SELECT 1 FROM runs WHERE active = 1) ",
                    "AND NOT EXISTS(SELECT 1 FROM receipt_publications) ",
                    "AND NOT EXISTS(SELECT 1 FROM cleanup_records WHERE active = 1) ",
                    "AND NOT EXISTS(SELECT 1 FROM authority_collection) ",
                    "FROM service_state WHERE singleton = 1"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !valid {
            return Err(ServiceError::Unavailable);
        }
        for table in [
            "receipts",
            "receipt_publications",
            "cleanup_records",
            "application_reports",
        ] {
            let orphaned: bool = connection
                .query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM {table} LEFT JOIN runs USING (run_id) \
                         WHERE runs.run_id IS NULL)"
                    ),
                    [],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if orphaned {
                return Err(ServiceError::Unavailable);
            }
        }
        let reader = authority.open_reader()?;
        let mut identities = HashSet::new();
        for table in ["runs", "tombstones"] {
            let predicate = if table == "runs" {
                " WHERE authority_generation IS NOT NULL"
            } else {
                ""
            };
            let mut statement = connection
                .prepare(&format!(
                    "SELECT authority_generation, authority_manifest_digest FROM {table}{predicate}"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage_error)?;
            for row in rows {
                let (generation, digest) = row.map_err(storage_error)?;
                let identity = stored_authority_identity(generation, digest)?;
                reader
                    .validate_identity(&identity)
                    .map_err(|_| ServiceError::Unavailable)?;
                identities.insert((identity.generation, identity.manifest_digest));
            }
        }
        if identities.len() > 2 {
            return Err(ServiceError::Unavailable);
        }
        for (run_id, published_epoch) in reader
            .dispatch_references()
            .map_err(|_| ServiceError::Unavailable)?
        {
            let owner = connection
                .query_row(
                    concat!(
                        "SELECT execution_state, authority_generation, ",
                        "authority_manifest_digest, lease_epoch FROM runs WHERE run_id = ?1"
                    ),
                    [&run_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage_error)?;
            let Some((state, generation, digest, durable_epoch)) = owner else {
                return Err(ServiceError::Unavailable);
            };
            stored_authority_identity(generation, digest)?;
            if state == "queued" || durable_epoch <= 0 || published_epoch != durable_epoch {
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(())
    }

    pub(crate) fn preflight_stopped_backup_source(
        database_path: &Path,
    ) -> Result<(), ServiceError> {
        Self::preflight_stopped_backup_source_mode(database_path, 0o600)
    }

    fn preflight_stopped_backup_source_mode(
        database_path: &Path,
        mode: u32,
    ) -> Result<(), ServiceError> {
        let database_path =
            fs::canonicalize(database_path).map_err(|_| ServiceError::Unavailable)?;
        let before = validate_database_file_mode(&database_path, mode)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        if validate_database_file_mode(&database_path, mode)? != before {
            return Err(ServiceError::Unavailable);
        }
        validate_exact_service_schema(&connection)?;
        validate_authority_pins(&connection)?;
        preflight_backup_schema(&connection)?;
        validate_serial_capacity(&connection)?;
        let stopped: bool = connection
            .query_row(
                "SELECT stopped = 1 FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped || validate_database_file_mode(&database_path, mode)? != before {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn preflight_clean_backup_source(database_path: &Path) -> Result<(), ServiceError> {
        Self::preflight_stopped_backup_source(database_path)?;
        let database_path =
            fs::canonicalize(database_path).map_err(|_| ServiceError::Unavailable)?;
        let before = validate_database_file(&database_path)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        let clean: bool = connection
            .query_row(
                concat!(
                    "SELECT stopped = 1 AND boundary_uid_digest = '' ",
                    "AND NOT EXISTS(SELECT 1 FROM runs) ",
                    "AND NOT EXISTS(SELECT 1 FROM tombstones) ",
                    "AND NOT EXISTS(SELECT 1 FROM receipts) ",
                    "AND NOT EXISTS(SELECT 1 FROM receipt_publications) ",
                    "AND NOT EXISTS(SELECT 1 FROM cleanup_records) ",
                    "AND NOT EXISTS(SELECT 1 FROM application_reports) ",
                    "AND NOT EXISTS(SELECT 1 FROM provisioned_object_owners) ",
                    "AND NOT EXISTS(SELECT 1 FROM events) ",
                    "AND NOT EXISTS(SELECT 1 FROM authority_collection) ",
                    "AND NOT EXISTS(SELECT 1 FROM backup_generations) ",
                    "AND NOT EXISTS(SELECT 1 FROM backup_authority_references) ",
                    "FROM service_state WHERE singleton = 1"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !clean || validate_database_file(&database_path)? != before {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn preflight_clean_restore_source(
        database_path: &Path,
        generation: u64,
        captured_at: i64,
    ) -> Result<(), ServiceError> {
        if Self::preflight_clean_restored_source(database_path, generation, captured_at, None)? {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn preflight_clean_restored_source(
        database_path: &Path,
        generation: u64,
        captured_at: i64,
        manifest_digest: Option<&str>,
    ) -> Result<bool, ServiceError> {
        if generation == 0
            || captured_at <= 0
            || manifest_digest.is_some_and(|digest| !valid_sha256(digest))
        {
            return Err(ServiceError::Unavailable);
        }
        let mode = if manifest_digest.is_some() {
            0o600
        } else {
            0o400
        };
        Self::preflight_stopped_backup_source_mode(database_path, mode)?;
        let database_path =
            fs::canonicalize(database_path).map_err(|_| ServiceError::Unavailable)?;
        let before = validate_database_file_mode(&database_path, mode)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        let clean: bool = connection
            .query_row(
                concat!(
                    "SELECT stopped = 1 AND boundary_uid_digest = '' ",
                    "AND NOT EXISTS(SELECT 1 FROM runs) ",
                    "AND NOT EXISTS(SELECT 1 FROM tombstones) ",
                    "AND NOT EXISTS(SELECT 1 FROM receipts) ",
                    "AND NOT EXISTS(SELECT 1 FROM receipt_publications) ",
                    "AND NOT EXISTS(SELECT 1 FROM cleanup_records) ",
                    "AND NOT EXISTS(SELECT 1 FROM application_reports) ",
                    "AND NOT EXISTS(SELECT 1 FROM provisioned_object_owners) ",
                    "AND NOT EXISTS(SELECT 1 FROM events) ",
                    "AND NOT EXISTS(SELECT 1 FROM authority_collection) ",
                    "AND (SELECT COUNT(*) FROM backup_generations) = 1 ",
                    "AND NOT EXISTS(SELECT 1 FROM backup_authority_references) ",
                    "FROM service_state WHERE singleton = 1"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        let publication = connection
            .query_row(
                concat!(
                    "SELECT slot, generation, manifest_digest, state, captured_at ",
                    "FROM backup_generations"
                ),
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map_err(storage_error)?;
        let current = match (publication.0.as_str(), publication.2.as_deref()) {
            ("pending", None) if publication.3 == "pending" => false,
            ("current", Some(digest))
                if publication.3 == "current" && manifest_digest == Some(digest) =>
            {
                true
            },
            _ => return Err(ServiceError::Unavailable),
        };
        if !clean
            || u64::try_from(publication.1).ok() != Some(generation)
            || publication.4 != captured_at
            || validate_database_file_mode(&database_path, mode)? != before
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(current)
    }

    fn migrate_stopped_state_root(database_path: &Path) -> Result<(), ServiceError> {
        let database_path =
            fs::canonicalize(database_path).map_err(|_| ServiceError::Unavailable)?;
        let before = validate_database_file(&database_path)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        if validate_database_file(&database_path)? != before {
            return Err(ServiceError::Unavailable);
        }
        let sql = format!(
            "BEGIN IMMEDIATE; {} {} COMMIT;",
            service_schema::BACKUP_GENERATIONS,
            service_schema::BACKUP_AUTHORITY_REFERENCES
        );
        connection.execute_batch(&sql).map_err(storage_error)
    }

    /// Runs the operator-owned periodic retention and tombstone deletion sweep.
    ///
    /// Call this from the bounded maintenance scheduler even when there is no visitor traffic.
    ///
    /// # Errors
    ///
    /// Returns a time, storage, or immutable-object deletion failure.
    pub(crate) fn sweep_retention(&self, now_unix_s: i64) -> Result<(), ServiceError> {
        timestamp(now_unix_s)?;
        self.expire(now_unix_s)
    }

    /// Sets the exact same-origin value accepted from a reviewed proxy.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidRequest`] unless the origin is bounded visible ASCII with an
    /// `https://` scheme and no path.
    pub fn set_origin(&mut self, origin: &str) -> Result<(), ServiceError> {
        if origin.len() > 253
            || !origin.starts_with("https://")
            || origin[8..].is_empty()
            || origin[8..].contains('/')
            || !origin.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ServiceError::InvalidRequest);
        }
        origin.clone_into(&mut self.origin);
        Ok(())
    }

    /// Atomically admits one fixed scenario before dispatch using OS-generated run entropy.
    ///
    /// # Errors
    ///
    /// Returns a bounded request, idempotency, capacity, expiry, stop, entropy, or storage error.
    pub fn admit(
        &self,
        idempotency_key: &str,
        scenario: Scenario,
        now_unix_s: i64,
    ) -> Result<Admission, ServiceError> {
        bounded_hex_128(idempotency_key)?;
        timestamp(now_unix_s)?;
        let expires_at = now_unix_s
            .checked_add(PUBLIC_RETENTION_SECONDS)
            .ok_or(ServiceError::InvalidRequest)?;
        timestamp(expires_at)?;
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| ServiceError::Unavailable)?;
        let run_id = hex(&bytes);
        self.admit_with_run_id(idempotency_key, scenario, now_unix_s, &run_id)
    }

    /// Activates or clears the durable fail-closed admission stop.
    ///
    /// Existing reads, recovery, receipt retrieval, and cleanup remain available.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when the stop state cannot be committed.
    pub fn set_global_stop(&self, stopped: bool) -> Result<(), ServiceError> {
        let connection = self.connection()?;
        commit_global_stop(&connection, stopped)
    }

    /// Returns the oldest queued run while atomically reserving active capacity and a lease.
    ///
    /// # Errors
    ///
    /// Returns a storage, entropy, [`ServiceError::ActiveSaturated`], or
    /// [`ServiceError::RunNotFound`] failure.
    pub(crate) fn dispatch_next(
        &self,
        now_unix_s: i64,
        authority: &GenerationIdentity,
    ) -> Result<DispatchLease, ServiceError> {
        validate_authority_identity(authority)?;
        let lease_id = random_identity()?;
        let handoff_credential = random_credential()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        validate_serial_capacity(&transaction)?;
        let active: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM cleanup_records WHERE active = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if active >= ACTIVE_RUNS_MAX {
            return Err(ServiceError::ActiveSaturated);
        }
        let (run_id, operation_id, deadline_seconds): (String, String, i64) = transaction
            .query_row(
                concat!(
                    "SELECT run_id, operation_id, deadline_seconds FROM runs ",
                    "WHERE execution_state = 'queued' AND public_retained = 1 ",
                    "ORDER BY admission_order LIMIT 1"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        let deadline_at = now_unix_s
            .checked_add(deadline_seconds)
            .ok_or(ServiceError::Unavailable)?;
        let lease_expires_at = lease_expiry(now_unix_s, deadline_at)?;
        let verifier = credential_verifier(&HandoffIdentity {
            run_id: run_id.clone(),
            operation_id,
            lease_id: lease_id.clone(),
            credential: handoff_credential,
        });
        let run_changed = transaction
            .execute(
                concat!(
                    "UPDATE runs SET active = 1, execution_state = 'running', ",
                    "dispatched_at = ?2, deadline_at = ?3, lease_id = ?4, lease_epoch = 1, ",
                    "lease_expires_at = ?5, handoff_credential_verifier = ?6, ",
                    "authority_generation = ?7, authority_manifest_digest = ?8 ",
                    "WHERE run_id = ?1 AND active = 0 AND execution_state = 'queued' ",
                    "AND authority_generation IS NULL AND authority_manifest_digest = ''"
                ),
                params![
                    run_id,
                    now_unix_s,
                    deadline_at,
                    lease_id,
                    lease_expires_at,
                    verifier.as_slice(),
                    i64::try_from(authority.generation).map_err(|_| ServiceError::Unavailable)?,
                    authority.manifest_digest
                ],
            )
            .map_err(storage_error)?;
        let cleanup_changed = transaction
            .execute(
                concat!(
                    "UPDATE cleanup_records SET active = 1 WHERE run_id = ?1 ",
                    "AND active = 0 AND state = 'pending'"
                ),
                [&run_id],
            )
            .map_err(storage_error)?;
        if run_changed != 1 || cleanup_changed != 1 {
            return Err(ServiceError::Unavailable);
        }
        append_event(&transaction, &run_id, "execution.started", now_unix_s)?;
        transaction.commit().map_err(storage_error)?;
        Ok(DispatchLease {
            run_id,
            lease_id,
            epoch: 1,
            expires_at_unix_s: lease_expires_at,
            handoff_credential,
            authority: authority.clone(),
        })
    }

    /// Lists active runs in durable admission order for restart recovery.
    ///
    /// The returned public run identities appoint no lifecycle action. A restarted scheduler must
    /// reopen each run's same private journal and call [`Service::reconcile_application`].
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when active ownership cannot be read.
    pub fn recoverable_runs(&self) -> Result<Vec<String>, ServiceError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT runs.run_id FROM runs JOIN cleanup_records ",
                "ON cleanup_records.run_id = runs.run_id WHERE cleanup_records.active = 1 ",
                "ORDER BY runs.admission_order"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
    }

    pub(crate) fn sole_active_run(&self) -> Result<Option<String>, ServiceError> {
        let runs = self.recoverable_runs()?;
        match runs.as_slice() {
            [] => Ok(None),
            [run_id] => Ok(Some(run_id.clone())),
            _ => Err(ServiceError::Unavailable),
        }
    }

    pub(crate) fn sole_cleanup_authority_identity(
        &self,
    ) -> Result<Option<GenerationIdentity>, ServiceError> {
        let connection = self.connection()?;
        validate_authority_pins(&connection)?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT runs.authority_generation, runs.authority_manifest_digest FROM ",
                "cleanup_records JOIN runs ON runs.run_id = cleanup_records.run_id WHERE ",
                "cleanup_records.active = 1 AND cleanup_records.eligible = 1 ORDER BY ",
                "runs.admission_order"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        match rows.as_slice() {
            [] => Ok(None),
            [(generation, digest)] => {
                stored_authority_identity(*generation, digest.clone()).map(Some)
            },
            _ => Err(ServiceError::Unavailable),
        }
    }

    pub(crate) fn sole_active_authority_identity(
        &self,
    ) -> Result<Option<GenerationIdentity>, ServiceError> {
        let Some(run_id) = self.sole_active_run()? else {
            return Ok(None);
        };
        let (generation, manifest_digest): (Option<i64>, String) = self
            .connection()?
            .query_row(
                concat!(
                    "SELECT authority_generation, authority_manifest_digest FROM runs ",
                    "WHERE run_id = ?1"
                ),
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage_error)?;
        stored_authority_identity(generation, manifest_digest).map(Some)
    }

    /// Claims or renews recovery after process loss without changing public projection.
    ///
    /// An unexpired lease can be renewed only with the exact previous lease. After expiry, a new
    /// opaque lease and incremented epoch are durably installed.
    ///
    /// # Errors
    ///
    /// Returns missing-run, inactive-run, lease-busy, entropy, or storage failures. Recovery leases
    /// remain available after the ordinary execution deadline.
    #[allow(
        clippy::too_many_lines,
        reason = "one recovery transaction validates and preserves the durable authority pin"
    )]
    pub(crate) fn recover_run(
        &self,
        run_id: &str,
        previous: Option<&DispatchLease>,
        now_unix_s: i64,
    ) -> Result<DispatchLease, ServiceError> {
        bounded_hex_128(run_id)?;
        let new_lease_id = random_identity()?;
        let handoff_credential = random_credential()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let (
            stored_id,
            epoch,
            expires_at,
            active,
            revoked,
            retiring,
            retired,
            generation,
            manifest_digest,
        ): (
            String,
            i64,
            i64,
            bool,
            bool,
            bool,
            bool,
            Option<i64>,
            String,
        ) = transaction
            .query_row(
                concat!(
                    "SELECT lease_id, lease_epoch, lease_expires_at, active, runner_revoked, ",
                    "runner_state_retiring, runner_state_retired, authority_generation, ",
                    "authority_manifest_digest FROM runs WHERE run_id = ?1"
                ),
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !active || revoked || retiring || retired {
            return Err(ServiceError::InvalidTransition);
        }
        let authority = stored_authority_identity(generation, manifest_digest)?;
        let previous_matches = previous.is_some_and(|lease| {
            lease.run_id == run_id && lease.lease_id == stored_id && lease.epoch == epoch
        });
        if now_unix_s < expires_at && !previous_matches {
            return Err(ServiceError::LeaseBusy);
        }
        let lease_id = new_lease_id;
        let next_epoch = epoch.checked_add(1).ok_or(ServiceError::Unavailable)?;
        let next_expiry = recovery_lease_expiry(now_unix_s)?;
        let operation_id: String = transaction
            .query_row(
                "SELECT operation_id FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        let verifier = credential_verifier(&HandoffIdentity {
            run_id: run_id.to_owned(),
            operation_id,
            lease_id: lease_id.clone(),
            credential: handoff_credential,
        });
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET lease_id = ?2, lease_epoch = ?3, lease_expires_at = ?4, ",
                    "handoff_credential_verifier = ?5 WHERE run_id = ?1"
                ),
                params![
                    run_id,
                    lease_id,
                    next_epoch,
                    next_expiry,
                    verifier.as_slice()
                ],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(DispatchLease {
            run_id: run_id.to_owned(),
            lease_id,
            epoch: next_epoch,
            expires_at_unix_s: next_expiry,
            handoff_credential,
            authority,
        })
    }

    /// Builds the raw owner-private assignment for the current lease without reading it back from
    /// durable system state.
    ///
    /// # Errors
    ///
    /// Returns a lease or identity failure when the supplied lease is not current.
    pub fn handoff_assignment(
        &self,
        lease: &DispatchLease,
        endpoint: std::net::SocketAddr,
        now_unix_s: i64,
    ) -> Result<HandoffAssignment, ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        self.validate_runner_authority(&lease.run_id)?;
        let operation_id = self.server_owned_request(&lease.run_id)?.operation_id;
        Ok(HandoffAssignment {
            run_id: lease.run_id.clone(),
            operation_id,
            lease_id: lease.lease_id.clone(),
            credential: lease.handoff_credential,
            endpoint,
        })
    }

    /// Returns the exact immutable provisioning specification frozen by admission.
    ///
    /// # Errors
    ///
    /// Returns a lease, deadline, missing-run, or storage failure.
    pub fn provisioning_specification(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
    ) -> Result<ProvisioningSpecification, ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        let connection = self.connection()?;
        let stored: (String, String, i64, Option<i64>, String, String) = connection
            .query_row(
                concat!(
                    "SELECT policy_revision, cleanup_identity, deadline_seconds, deadline_at, ",
                    "policy_inventory, policy_inventory_digest FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        let deadline_at_unix_s = stored.3.ok_or(ServiceError::InvalidTransition)?;
        if now_unix_s >= deadline_at_unix_s {
            return Err(ServiceError::DeadlineExceeded);
        }
        if policy_binding_digest(&stored.0, &stored.4) != stored.5 {
            return Err(ServiceError::PolicyMismatch);
        }
        let required_objects =
            serde_json::from_str(&stored.4).map_err(|_| ServiceError::Unavailable)?;
        Ok(ProvisioningSpecification {
            run_id: lease.run_id.clone(),
            namespace: format!("sandbox-{}", lease.run_id),
            policy_revision: stored.0,
            cleanup_identity: stored.1,
            deadline_seconds: stored.2,
            deadline_at_unix_s,
            policy_inventory_digest: stored.5,
            required_objects,
        })
    }

    /// Returns the compile-time closed baseline/canary and behavior-record specification.
    ///
    /// # Errors
    ///
    /// Returns a policy failure if any compile-time embedded behavior record is malformed.
    pub fn cluster_boundary_specification() -> Result<ClusterBoundarySpecification, ServiceError> {
        let objects = kubernetes_policy::boundary_objects()
            .into_iter()
            .map(|object| PolicyObjectRequirement {
                identity: object.identity,
                content_digest: kubernetes_policy::content_digest(&object.body),
                canonical_body: object.body,
            })
            .collect();
        let records =
            kubernetes_policy::behavior_records().map_err(|_| ServiceError::PolicyMismatch)?;
        Ok((objects, records))
    }

    /// Derives and verifies exact policy evidence from bounded Kubernetes object responses.
    ///
    /// This is the concrete provider-neutral Slice 3 provisioning boundary. It derives identities,
    /// immutable UIDs, owner labels, and canonical content digests rather than trusting supplied
    /// summaries.
    ///
    /// # Errors
    ///
    /// Returns a policy, ownership, lease, deadline, or storage failure before runner launch.
    #[allow(
        clippy::too_many_lines,
        reason = "one deep verification path owns boundary and complete object derivation"
    )]
    pub fn verify_observed_cluster(
        &self,
        lease: &DispatchLease,
        observation: &ObservedClusterComposition,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        if observation
            .boundary
            .objects
            .iter()
            .chain(&observation.run_objects)
            .chain(&observation.generated_children)
            .chain(&observation.owned_orphans)
            .any(|object| {
                serde_json::to_vec(&object.body).map_or(true, |bytes| bytes.len() > 2 * 1024 * 1024)
            })
        {
            return Err(ServiceError::PolicyMismatch);
        }
        if !observation.owned_orphans.is_empty() {
            return Err(ServiceError::PolicyMismatch);
        }
        let expected_boundary = kubernetes_policy::boundary_objects();
        let expected_behavior =
            kubernetes_policy::behavior_records().map_err(|_| ServiceError::PolicyMismatch)?;
        if observation.boundary.objects.len() != expected_boundary.len()
            || observation.boundary.behavior_records != expected_behavior
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let mut remaining_boundary = observation.boundary.objects.iter().collect::<Vec<_>>();
        let mut boundary_uids = Vec::with_capacity(expected_boundary.len());
        for expected in &expected_boundary {
            let Some(index) = remaining_boundary.iter().position(|observed| {
                observed_policy_identity(&observed.body).as_deref()
                    == Some(expected.identity.as_str())
            }) else {
                return Err(ServiceError::PolicyMismatch);
            };
            let observed = remaining_boundary.swap_remove(index);
            if kubernetes_policy::observed_content_digest(&expected.body, &observed.body)
                != Some(kubernetes_policy::content_digest(&expected.body))
            {
                return Err(ServiceError::PolicyMismatch);
            }
            boundary_uids.push((
                expected.identity.clone(),
                observed_policy_uid(&observed.body)?,
            ));
        }
        if !remaining_boundary.is_empty() {
            return Err(ServiceError::PolicyMismatch);
        }

        let specification = self.provisioning_specification(lease, now_unix_s)?;
        let selected_image = self
            .server_owned_request(&lease.run_id)?
            .immutable_image_digest;
        let expected = kubernetes_policy::render(&lease.run_id, &selected_image)
            .map_err(|_| ServiceError::PolicyMismatch)?;
        if expected.len() != specification.required_objects.len()
            || observation.run_objects.len() != expected.len()
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let mut remaining = observation.run_objects.iter().collect::<Vec<_>>();
        let mut objects = Vec::with_capacity(expected.len());
        let mut deployment_facts = None;
        for expected_object in expected {
            let Some(index) = remaining.iter().position(|observed| {
                observed_policy_identity(&observed.body).as_deref()
                    == Some(expected_object.identity.as_str())
            }) else {
                return Err(ServiceError::PolicyMismatch);
            };
            let observed = remaining.swap_remove(index);
            let content_digest = observed_or_raw_digest(&expected_object.body, &observed.body);
            let uid = observed_policy_uid(&observed.body)?;
            let owner_label = observed_policy_owner(&observed.body)?;
            if expected_object.body["kind"] == "Deployment" {
                let resource_version = observed
                    .body
                    .pointer("/metadata/resourceVersion")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(ServiceError::PolicyMismatch)?
                    .to_owned();
                bounded_identity(&resource_version)?;
                let current_image = selected_container_mutation(&observed.body, "target")?
                    .pointer("/image")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(ServiceError::PolicyMismatch)?
                    .to_owned();
                deployment_facts = Some((uid.clone(), resource_version, current_image));
            }
            objects.push(ProvisionedObject {
                identity: expected_object.identity,
                uid,
                owner_label,
                content_digest,
            });
        }
        if !remaining.is_empty() {
            return Err(ServiceError::PolicyMismatch);
        }
        let (deployment_uid, _, _) = deployment_facts
            .as_ref()
            .ok_or(ServiceError::PolicyMismatch)?;
        let deployment_template = specification
            .required_objects
            .iter()
            .find(|object| object.canonical_body["kind"] == "Deployment")
            .and_then(|object| object.canonical_body.pointer("/spec/template"))
            .ok_or(ServiceError::PolicyMismatch)?;
        objects.extend(derive_generated_children(
            &observation.generated_children,
            &lease.run_id,
            &specification.cleanup_identity,
            deployment_uid,
            &[deployment_template],
            &HashSet::new(),
        )?);
        let namespace_uid = objects
            .first()
            .ok_or(ServiceError::PolicyMismatch)?
            .uid
            .clone();
        boundary_uids.sort();
        let (deployment_uid, deployment_resource_version, deployment_current_image) =
            deployment_facts.ok_or(ServiceError::PolicyMismatch)?;
        let closure = ProvisioningClosureEvidence {
            boundary_uid_digest: digest_identity_uids(&boundary_uids)?,
            deployment_uid,
            deployment_resource_version,
            deployment_current_image,
        };
        self.verify_provisioned_target(
            lease,
            &ProvisionedTarget {
                namespace_uid,
                policy_revision: specification.policy_revision,
                policy_inventory_digest: specification.policy_inventory_digest,
                cleanup_identity: specification.cleanup_identity,
                objects,
            },
            now_unix_s,
            &closure,
        )
    }

    pub(crate) fn append_observed_generated_children(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        children: &[ObservedPolicyObject],
    ) -> Result<(), ServiceError> {
        if children.iter().any(|object| {
            serde_json::to_vec(&object.body).map_or(true, |bytes| bytes.len() > 2 * 1024 * 1024)
        }) {
            return Err(ServiceError::PolicyMismatch);
        }
        let request = self.server_owned_request(run_id)?;
        let rendered = kubernetes_policy::render(run_id, &request.immutable_image_digest)
            .map_err(|_| ServiceError::PolicyMismatch)?;
        let deployment_template = rendered
            .iter()
            .find(|object| object.body["kind"] == "Deployment")
            .and_then(|object| object.body.pointer("/spec/template"))
            .ok_or(ServiceError::PolicyMismatch)?;
        let mut selected_deployment =
            serde_json::json!({"spec": {"template": deployment_template.clone()}});
        selected_container_mutation_mut(&mut selected_deployment, "target")?["image"] =
            serde_json::json!(request.immutable_image_digest);
        let selected_template = selected_deployment["spec"]["template"].clone();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored: (String, String, String) = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_identity, deployment_uid, provisioned_objects FROM runs ",
                    "WHERE run_id = ?1 AND provisioning_closed = 1 AND active = 1"
                ),
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage_error)?;
        if stored.0 != cleanup_identity || stored.1.is_empty() {
            return Err(ServiceError::OwnershipMismatch);
        }
        let known_replica_set_uids = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT uid FROM provisioned_object_owners WHERE run_id = ?1 ",
                    "AND identity LIKE 'ReplicaSet/%'"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([run_id], |row| row.get::<_, String>(0))
                .map_err(storage_error)?;
            rows.collect::<Result<HashSet<_>, _>>()
                .map_err(storage_error)?
        };
        let derived = derive_generated_children(
            children,
            run_id,
            cleanup_identity,
            &stored.1,
            &[deployment_template, &selected_template],
            &known_replica_set_uids,
        )?;
        let mut inventory: Vec<ProvisionedObject> =
            serde_json::from_str(&stored.2).map_err(|_| ServiceError::Unavailable)?;
        for object in derived {
            if let Some(existing) = inventory.iter().find(|item| item.uid == object.uid) {
                if existing != &object {
                    return Err(ServiceError::OwnershipMismatch);
                }
                continue;
            }
            if inventory.len() >= PROVISIONED_OBJECT_OWNERS_MAX_USIZE {
                return Err(ServiceError::PolicyMismatch);
            }
            transaction
                .execute(
                    "INSERT INTO provisioned_object_owners VALUES (?1, ?2, ?3, ?4)",
                    params![object.uid, run_id, object.identity, object.owner_label],
                )
                .map_err(storage_error)?;
            inventory.push(object);
        }
        let serialized =
            serde_json::to_string(&inventory).map_err(|_| ServiceError::Unavailable)?;
        transaction
            .execute(
                "UPDATE runs SET provisioned_objects = ?2 WHERE run_id = ?1",
                params![run_id, serialized],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)
    }

    /// Verifies the exact conditional old/new Deployment comparison without issuing a request.
    ///
    /// All preconditions are derived from the admission-frozen run and verified composition. The
    /// caller supplies no digest, identity, result, retry, or force flag.
    ///
    /// # Errors
    ///
    /// Returns a policy, lease, transition, or bound failure. It never changes receiver facts.
    #[allow(
        clippy::too_many_lines,
        reason = "one closed comparison keeps every old/new Deployment invariant visible"
    )]
    pub fn verify_conditional_deployment(
        &self,
        lease: &DispatchLease,
        observation: &ConditionalDeploymentObservation,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.validate_application_ready(lease, now_unix_s, false)?;
        for body in [&observation.old_object, &observation.new_object] {
            if serde_json::to_vec(body).map_or(true, |bytes| bytes.len() > 2 * 1024 * 1024) {
                return Err(ServiceError::PolicyMismatch);
            }
        }
        let specification = self.provisioning_specification(lease, now_unix_s)?;
        let expected = specification
            .required_objects
            .iter()
            .find(|object| object.identity.starts_with("Deployment/"))
            .ok_or(ServiceError::PolicyMismatch)?;
        let old = &observation.old_object;
        if kubernetes_policy::observed_content_digest(&expected.canonical_body, old)
            != Some(expected.content_digest.clone())
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let old_uid = observed_policy_uid(old)?;
        let old_resource_version = old
            .pointer("/metadata/resourceVersion")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::PolicyMismatch)?;
        let retained: (String, String, String) = self
            .connection()?
            .query_row(
                concat!(
                    "SELECT deployment_uid, deployment_resource_version, ",
                    "deployment_current_image FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage_error)?;
        if retained.0 != old_uid
            || retained.1 != old_resource_version
            || old
                .pointer("/spec/template/spec/containers/0/image")
                .and_then(serde_json::Value::as_str)
                != Some(retained.2.as_str())
        {
            return Err(ServiceError::PolicyMismatch);
        }
        if observation
            .new_object
            .pointer("/metadata/uid")
            .and_then(serde_json::Value::as_str)
            != Some(old_uid.as_str())
            || observation
                .new_object
                .pointer("/metadata/resourceVersion")
                .and_then(serde_json::Value::as_str)
                != Some(old_resource_version)
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let request = self.server_owned_request(&lease.run_id)?;
        let old_annotations = old
            .pointer("/metadata/annotations")
            .and_then(serde_json::Value::as_object)
            .ok_or(ServiceError::PolicyMismatch)?;
        let expected_deployment_digest =
            kubernetes_policy::canonical_deployment_digest(&expected.canonical_body);
        if old_annotations.contains_key("kapsel.dev/kap0038-operation-id")
            || old_annotations
                .get("kapsel.dev/policy-inventory-digest")
                .and_then(serde_json::Value::as_str)
                != Some(specification.policy_inventory_digest.as_str())
            || old_annotations
                .get("kapsel.dev/canonical-deployment-digest")
                .and_then(serde_json::Value::as_str)
                != Some(expected_deployment_digest.as_str())
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let old_target = selected_container_mutation(old, "target")?;
        let new_target = selected_container_mutation(&observation.new_object, "target")?;
        if old_target
            .pointer("/image")
            .and_then(serde_json::Value::as_str)
            != Some(kubernetes_policy::BASE_IMAGE)
            || new_target
                .pointer("/image")
                .and_then(serde_json::Value::as_str)
                != Some(request.immutable_image_digest.as_str())
            || observation
                .new_object
                .pointer("/metadata/annotations/kapsel.dev~1kap0038-operation-id")
                .and_then(serde_json::Value::as_str)
                != Some(request.operation_id.as_str())
        {
            return Err(ServiceError::PolicyMismatch);
        }
        let mut normalized = observation.new_object.clone();
        selected_container_mutation_mut(&mut normalized, "target")?["image"] =
            serde_json::json!(kubernetes_policy::BASE_IMAGE);
        let annotations = normalized
            .pointer_mut("/metadata/annotations")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or(ServiceError::PolicyMismatch)?;
        annotations.remove("kapsel.dev/kap0038-operation-id");
        if normalized != *old {
            return Err(ServiceError::PolicyMismatch);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction binds exact policy and cross-run ownership evidence"
    )]
    fn verify_provisioned_target(
        &self,
        lease: &DispatchLease,
        target: &ProvisionedTarget,
        now_unix_s: i64,
        closure: &ProvisioningClosureEvidence,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        bounded_identity(&target.namespace_uid)?;
        let specification = self.provisioning_specification(lease, now_unix_s)?;
        if target.cleanup_identity != specification.cleanup_identity
            || target
                .objects
                .iter()
                .any(|object| object.owner_label != specification.cleanup_identity)
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        let (namespace_object, expected_namespace) = target
            .objects
            .first()
            .zip(specification.required_objects.first())
            .ok_or(ServiceError::OwnershipMismatch)?;
        let wrong_namespace_identity = namespace_object.identity != expected_namespace.identity;
        let wrong_namespace_uid = namespace_object.uid != target.namespace_uid;
        if wrong_namespace_identity || wrong_namespace_uid {
            return Err(ServiceError::OwnershipMismatch);
        }
        let mut object_uids = HashSet::new();
        for object in &target.objects {
            bounded_identity(&object.uid)?;
            if !object_uids.insert(object.uid.as_str()) {
                return Err(ServiceError::OwnershipMismatch);
            }
        }
        let exact_object_count = target.objects.len() >= specification.required_objects.len()
            && target.objects.len() <= specification.required_objects.len() + 3;
        let exact_object_content = target
            .objects
            .iter()
            .take(specification.required_objects.len())
            .zip(&specification.required_objects)
            .all(|(actual, expected)| {
                actual.identity == expected.identity
                    && actual.content_digest == expected.content_digest
            });
        let policy_matches = target.policy_revision == specification.policy_revision
            && target.policy_inventory_digest == specification.policy_inventory_digest
            && exact_object_count
            && exact_object_content;
        let provisioned_objects =
            serde_json::to_string(&target.objects).map_err(|_| ServiceError::Unavailable)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let current: (Option<String>, bool, String, bool, Option<String>) = transaction
            .query_row(
                concat!(
                    "SELECT namespace_uid, application_invoked, execution_state, policy_verified, ",
                    "provisioned_objects FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(storage_error)?;
        if current.1 || current.2 != "running" {
            return Err(ServiceError::InvalidTransition);
        }
        if current
            .0
            .as_deref()
            .is_some_and(|uid| uid != target.namespace_uid)
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        if current.3 {
            if !policy_matches
                || current.0.as_deref() != Some(target.namespace_uid.as_str())
                || current.4.as_deref() != Some(provisioned_objects.as_str())
            {
                return Err(ServiceError::PolicyMismatch);
            }
            close_provisioning(&transaction, &lease.run_id, closure)?;
            transaction.commit().map_err(storage_error)?;
            return Ok(());
        }
        let existing_owner_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM provisioned_object_owners WHERE run_id = ?1",
                [&lease.run_id],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        let mut new_owner_count = 0_i64;
        for object in &target.objects {
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM provisioned_object_owners WHERE uid = ?1)",
                    [&object.uid],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !exists {
                new_owner_count = new_owner_count
                    .checked_add(1)
                    .ok_or(ServiceError::Unavailable)?;
            }
        }
        if existing_owner_count
            .checked_add(new_owner_count)
            .ok_or(ServiceError::Unavailable)?
            > PROVISIONED_OBJECT_OWNERS_MAX
        {
            return Err(ServiceError::PolicyMismatch);
        }
        for object in &target.objects {
            let existing: Option<(String, String, String)> = transaction
                .query_row(
                    concat!(
                        "SELECT run_id, identity, owner_label FROM provisioned_object_owners ",
                        "WHERE uid = ?1"
                    ),
                    [&object.uid],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage_error)?;
            if existing.as_ref().is_some_and(|(run_id, identity, owner)| {
                run_id != &lease.run_id
                    || identity != &object.identity
                    || owner != &object.owner_label
            }) {
                return Err(ServiceError::OwnershipMismatch);
            }
            transaction
                .execute(
                    "INSERT OR IGNORE INTO provisioned_object_owners VALUES (?1, ?2, ?3, ?4)",
                    params![
                        object.uid,
                        lease.run_id,
                        object.identity,
                        object.owner_label
                    ],
                )
                .map_err(storage_error)?;
        }
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET namespace_uid = ?2, policy_verified = ?3, ",
                    "provisioned_objects = ?4, cleanup_resource_state = 'owned' WHERE run_id = ?1"
                ),
                params![
                    lease.run_id,
                    target.namespace_uid,
                    policy_matches,
                    provisioned_objects
                ],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                concat!(
                    "UPDATE cleanup_records SET namespace_uid = ?2, resource_state = 'owned' ",
                    "WHERE run_id = ?1"
                ),
                params![lease.run_id, target.namespace_uid],
            )
            .map_err(storage_error)?;
        close_provisioning(&transaction, &lease.run_id, closure)?;
        transaction.commit().map_err(storage_error)?;
        if policy_matches {
            Ok(())
        } else {
            Err(ServiceError::PolicyMismatch)
        }
    }

    pub(crate) fn commit_application_invoked(
        &self,
        identity: &HandoffIdentity,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        timestamp(now_unix_s)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored: (String, String, i64, bool, Vec<u8>, String, bool, bool) = transaction
            .query_row(
                concat!(
                    "SELECT operation_id, lease_id, lease_expires_at, active, ",
                    "handoff_credential_verifier, execution_state, policy_verified, ",
                    "application_invoked FROM runs WHERE run_id = ?1"
                ),
                [&identity.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::Unavailable)?;
        let verifier = credential_verifier(identity);
        if stored.0 != identity.operation_id
            || stored.1 != identity.lease_id
            || now_unix_s >= stored.2
            || !stored.3
            || !constant_time_equal(&stored.4, &verifier)
            || !stored.6
            || (!stored.7 && stored.5 != "running")
        {
            return Err(ServiceError::Unavailable);
        }
        if !stored.7 {
            let changed = transaction
                .execute(
                    concat!(
                        "UPDATE runs SET application_invoked = 1 WHERE run_id = ?1 ",
                        "AND lease_id = ?2 AND handoff_credential_verifier = ?3 ",
                        "AND active = 1 AND execution_state = 'running'"
                    ),
                    params![identity.run_id, identity.lease_id, verifier.as_slice()],
                )
                .map_err(storage_error)?;
            if changed != 1 {
                return Err(ServiceError::Unavailable);
            }
        }
        transaction.commit().map_err(storage_error)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transaction keeps authentication, report binding, and projection together"
    )]
    pub(crate) fn commit_application_report(
        &self,
        identity: &HandoffIdentity,
        report: &TerminalHandoffReport,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        timestamp(now_unix_s)?;
        let payload_digest =
            report_payload_digest(&identity.run_id, &identity.operation_id, report);
        let (kind, result, rejection, receipt_digest, receipt_bytes) = match report {
            TerminalHandoffReport::NotAttempted(rejection) => {
                let rejection = match rejection {
                    TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
                    TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
                    TargetRejection::InvalidTarget => "INVALID_TARGET",
                };
                ("not_attempted", None, Some(rejection), None, None)
            },
            TerminalHandoffReport::Finalized {
                result,
                receipt_digest,
                receipt_bytes,
            } => {
                if receipt_bytes.is_empty()
                    || receipt_bytes.len() > RECEIPT_BYTES_MAX
                    || hex(&Sha256::digest(receipt_bytes)) != *receipt_digest
                {
                    return Err(ServiceError::Unavailable);
                }
                let result = match result {
                    OperationResult::Succeeded => "SUCCEEDED",
                    OperationResult::Failed => "FAILED",
                    OperationResult::Unknown => "UNKNOWN",
                };
                (
                    "finalized",
                    Some(result),
                    None,
                    Some(receipt_digest.as_str()),
                    Some(receipt_bytes.as_slice()),
                )
            },
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored: (String, String, i64, bool, Vec<u8>, String, bool, bool) = transaction
            .query_row(
                concat!(
                    "SELECT operation_id, lease_id, lease_expires_at, active, ",
                    "handoff_credential_verifier, execution_state, application_invoked, ",
                    "public_retained FROM runs WHERE run_id = ?1"
                ),
                [&identity.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::Unavailable)?;
        let verifier = credential_verifier(identity);
        if stored.0 != identity.operation_id
            || stored.1 != identity.lease_id
            || now_unix_s >= stored.2
            || !stored.3
            || !constant_time_equal(&stored.4, &verifier)
            || !stored.6
        {
            return Err(ServiceError::Unavailable);
        }
        let existing: Option<StoredReportBinding> = transaction
            .query_row(
                concat!(
                    "SELECT kind, receiver_result, target_rejection, receipt_digest, ",
                    "payload_digest FROM application_reports WHERE run_id = ?1"
                ),
                [&identity.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        if let Some(existing) = existing {
            if existing.0 != kind
                || existing.1.as_deref() != result
                || existing.2.as_deref() != rejection
                || existing.3.as_deref() != receipt_digest
                || !constant_time_equal(&existing.4, &payload_digest)
            {
                return Err(ServiceError::Unavailable);
            }
        } else {
            if stored.5 != "running" {
                return Err(ServiceError::Unavailable);
            }
            transaction
                .execute(
                    "INSERT INTO application_reports VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        identity.run_id,
                        kind,
                        result,
                        rejection,
                        receipt_digest,
                        payload_digest.as_slice()
                    ],
                )
                .map_err(storage_error)?;
            let (state, event) = if kind == "not_attempted" {
                ("not_attempted", "execution.not_attempted")
            } else {
                ("terminal", "execution.terminal")
            };
            transaction
                .execute(
                    concat!(
                        "UPDATE runs SET execution_state = ?2, receiver_result = ?3, ",
                        "target_rejection = ?4 WHERE run_id = ?1"
                    ),
                    params![identity.run_id, state, result, rejection],
                )
                .map_err(storage_error)?;
            if stored.7 {
                append_event(&transaction, &identity.run_id, event, now_unix_s)?;
            }
            if kind == "not_attempted" {
                transaction
                    .execute(
                        "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                        [&identity.run_id],
                    )
                    .map_err(storage_error)?;
            }
        }
        if let Some(digest) = receipt_digest {
            let object_name = format!("sandbox-{}-{digest}.receipt", identity.run_id);
            let completed: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM receipts WHERE run_id = ?1)",
                    [&identity.run_id],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !completed {
                let pending: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT digest, object_name FROM receipt_publications WHERE run_id = ?1",
                        [&identity.run_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(storage_error)?;
                if let Some((pending_digest, pending_name)) = pending {
                    if pending_digest != digest || pending_name != object_name {
                        return Err(ServiceError::Unavailable);
                    }
                } else {
                    transaction
                        .execute(
                            "INSERT INTO receipt_publications VALUES (?1, ?2, ?3, ?4)",
                            params![identity.run_id, digest, object_name, now_unix_s],
                        )
                        .map_err(storage_error)?;
                }
            }
        }
        transaction.commit().map_err(storage_error)?;
        if let (Some(digest), Some(bytes)) = (receipt_digest, receipt_bytes) {
            let object_name = format!("sandbox-{}-{digest}.receipt", identity.run_id);
            self.complete_receipt_publication(
                &identity.run_id,
                bytes,
                digest,
                &object_name,
                now_unix_s,
            )?;
        }
        Ok(())
    }

    /// Process-local deterministic compatibility adapter for package contract tests.
    ///
    /// Production composition uses the separate native `runner` and `handoff-serve` modes. This
    /// hidden adapter crosses the same loopback codec and system transactions; it does not directly
    /// mark invocation, project reports, read a system path from the application, or define another
    /// deployment interface. Its final service-only retirement transition explicitly simulates the
    /// host boundary; production retirement is composed only by `ControllerRole` around
    /// `RunnerHost::retire`.
    ///
    /// # Errors
    ///
    /// Returns bounded sandbox, application-open, or private-handoff failures.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation can leave Kapsel durable state after an attempt marker. Reopen with the same
    /// configuration and call [`Service::reconcile_application`]; never dispatch a second run.
    pub async fn execute_application(
        &self,
        lease: &DispatchLease,
        configuration: OperatorConfiguration,
        now_unix_s: i64,
    ) -> Result<Snapshot, RunError> {
        self.run_application_via_handoff(lease, configuration, now_unix_s, false)
            .await?
            .ok_or(RunError::Service(ServiceError::RunNotFound))
    }

    /// Process-local deterministic recovery adapter crossing the exact private handoff.
    ///
    /// Production composition uses the separate native modes. This method remains only so the
    /// accepted package contract matrix can exercise deterministic Kubernetes transports. Its
    /// service-only retirement completion is a host simulation, not production host evidence.
    ///
    /// # Errors
    ///
    /// Returns bounded sandbox, application-open, or private-handoff failures.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation preserves both journals at their last committed states. Repeat with the same
    /// operation identity and per-run journal.
    pub async fn reconcile_application(
        &self,
        lease: &DispatchLease,
        configuration: OperatorConfiguration,
        now_unix_s: i64,
    ) -> Result<Option<Snapshot>, RunError> {
        self.run_application_via_handoff(lease, configuration, now_unix_s, true)
            .await
    }

    async fn run_application_via_handoff(
        &self,
        lease: &DispatchLease,
        configuration: OperatorConfiguration,
        now_unix_s: i64,
        recovery: bool,
    ) -> Result<Option<Snapshot>, RunError> {
        self.validate_application_ready(lease, now_unix_s, recovery)
            .map_err(RunError::Service)?;
        let request = self
            .server_owned_request(&lease.run_id)
            .map_err(RunError::Service)?;
        let application = Application::open(configuration).map_err(RunError::Application)?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|_| RunError::Handoff(HandoffError::Unavailable))?;
        let endpoint = listener
            .local_addr()
            .map_err(|_| RunError::Handoff(HandoffError::Unavailable))?;
        let assignment = self
            .handoff_assignment(lease, endpoint, now_unix_s)
            .map_err(RunError::Service)?;
        let system = self.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().map_err(|_| HandoffError::Unavailable)?;
                handle_connection_at(stream, &system, now_unix_s)?;
            }
            Ok::<(), HandoffError>(())
        });
        let result = run_application_handoff(application, &request, &assignment).await;
        if result.is_ok() {
            server
                .join()
                .map_err(|_| RunError::Handoff(HandoffError::Unavailable))?
                .map_err(RunError::Handoff)?;
        }
        result.map_err(RunError::Handoff)?;
        self.simulate_host_retirement_for_deterministic_adapter(&lease.run_id)
            .map_err(RunError::Service)?;
        match self.snapshot(&lease.run_id, now_unix_s) {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(ServiceError::RunExpired | ServiceError::RunNotFound) => Ok(None),
            Err(error) => Err(RunError::Service(error)),
        }
    }

    /// Freezes setup failure only when the application was durably never invoked.
    ///
    /// # Errors
    ///
    /// Returns a missing-run, invalid-transition, or storage error.
    pub fn record_setup_failure(
        &self,
        lease: &DispatchLease,
        cleanup_identity: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        bounded_identity(cleanup_identity)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE runs SET execution_state = 'service_failed', runner_revoked = 1, ",
                    "runner_process_absent = 1, journal_handoff = 1, ",
                    "runner_state_retiring = 1, runner_state_retired = 1, ",
                    "handoff_credential_verifier = X'' ",
                    "WHERE run_id = ?1 AND execution_state = 'running' ",
                    "AND provisioning_closed = 1 AND application_invoked = 0 ",
                    "AND namespace_uid IS NOT NULL ",
                    "AND cleanup_identity = ?2"
                ),
                params![lease.run_id, cleanup_identity],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        append_event(
            &transaction,
            &lease.run_id,
            "execution.service_failed",
            now_unix_s,
        )?;
        transaction.commit().map_err(storage_error)
    }

    /// Completes setup-failure cleanup when provisioning durably confirms no resource existed.
    ///
    /// This path is valid only before Application invocation and before any namespace UID was
    /// recorded. It appends the same bounded setup-failure and cleanup projection while releasing
    /// active capacity atomically.
    ///
    /// # Errors
    ///
    /// Returns lease, cleanup-identity, ownership, transition, deadline, or storage failures.
    pub fn record_setup_failure_without_resources(
        &self,
        lease: &DispatchLease,
        cleanup_identity: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        bounded_identity(cleanup_identity)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let state: (String, bool, Option<String>, String, String) = transaction
            .query_row(
                concat!(
                    "SELECT runs.execution_state, runs.application_invoked, runs.namespace_uid, ",
                    "runs.cleanup_identity, cleanup_records.resource_state FROM runs ",
                    "JOIN cleanup_records ON cleanup_records.run_id = runs.run_id ",
                    "WHERE runs.run_id = ?1"
                ),
                [&lease.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if state.0 != "running" || state.1 || state.2.is_some() || state.4 != "unverified" {
            return Err(ServiceError::InvalidTransition);
        }
        if state.3 != cleanup_identity {
            return Err(ServiceError::OwnershipMismatch);
        }
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET execution_state = 'service_failed', ",
                    "cleanup_resource_state = 'confirmed_absent' WHERE run_id = ?1"
                ),
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        append_event(
            &transaction,
            &lease.run_id,
            "execution.service_failed",
            now_unix_s,
        )?;
        transaction
            .execute(
                "UPDATE runs SET cleanup_state = 'running' WHERE run_id = ?1",
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        append_event(&transaction, &lease.run_id, "cleanup.started", now_unix_s)?;
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET cleanup_state = 'succeeded', active = 0, ",
                    "handoff_credential_verifier = X'' WHERE run_id = ?1"
                ),
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        append_event(&transaction, &lease.run_id, "cleanup.succeeded", now_unix_s)?;
        transaction
            .execute(
                "DELETE FROM cleanup_records WHERE run_id = ?1",
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)
    }

    fn simulate_host_retirement_for_deterministic_adapter(
        &self,
        run_id: &str,
    ) -> Result<(), ServiceError> {
        self.begin_runner_retirement(run_id)?;
        self.commit_runner_state_retired(run_id)
    }

    pub(crate) fn begin_runner_retirement(&self, run_id: &str) -> Result<(), ServiceError> {
        let changed = self
            .connection()?
            .execute(
                concat!(
                    "UPDATE runs SET runner_revoked = 1, runner_process_absent = 1, ",
                    "journal_handoff = 1, handoff_credential_verifier = X'', ",
                    "runner_state_retiring = 1 WHERE run_id = ?1 AND provisioning_closed = 1 ",
                    "AND runner_revoked = 0 AND runner_state_retiring = 0 ",
                    "AND runner_state_retired = 0 AND ((execution_state = 'terminal' AND NOT ",
                    "EXISTS (SELECT 1 FROM receipt_publications WHERE ",
                    "receipt_publications.run_id = runs.run_id)) OR execution_state IN ",
                    "('not_attempted', 'service_failed'))"
                ),
                [run_id],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn runner_retirement_state(
        &self,
        run_id: &str,
    ) -> Result<(bool, bool), ServiceError> {
        self.connection()?
            .query_row(
                "SELECT runner_state_retiring, runner_state_retired FROM runs WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)
    }

    pub(crate) fn commit_runner_state_retired(&self, run_id: &str) -> Result<(), ServiceError> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                concat!(
                    "UPDATE runs SET runner_state_retired = 1 WHERE run_id = ?1 ",
                    "AND runner_revoked = 1 AND runner_process_absent = 1 ",
                    "AND journal_handoff = 1 AND runner_state_retiring = 1 ",
                    "AND runner_state_retired = 0"
                ),
                [run_id],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            let retired = connection
                .query_row(
                    "SELECT runner_state_retired FROM runs WHERE run_id = ?1",
                    [run_id],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(storage_error)?;
            if retired != Some(true) {
                return Err(ServiceError::InvalidTransition);
            }
        }
        self.authority
            .remove_retired_dispatch(run_id)
            .map_err(|_| ServiceError::Unavailable)
    }

    pub(crate) fn converge_retired_dispatch(&self, run_id: &str) -> Result<(), ServiceError> {
        let retired = self
            .connection()?
            .query_row(
                "SELECT runner_state_retired FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(storage_error)?;
        if retired != Some(true) {
            return Err(ServiceError::InvalidTransition);
        }
        self.authority
            .remove_retired_dispatch(run_id)
            .map_err(|_| ServiceError::Unavailable)
    }

    /// Appends the independent sandbox deadline fact without classifying the receiver.
    ///
    /// # Errors
    ///
    /// Returns a missing-run, duplicate/invalid transition, or storage error.
    pub fn record_deadline(&self, run_id: &str, now_unix_s: i64) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let (deadline_at, emitted): (Option<i64>, bool) = transaction
            .query_row(
                "SELECT deadline_at, deadline_emitted FROM runs WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        let deadline_at = deadline_at.ok_or(ServiceError::InvalidTransition)?;
        if emitted || now_unix_s < deadline_at {
            return Err(ServiceError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE runs SET deadline_emitted = 1 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        append_event(
            &transaction,
            run_id,
            "execution.deadline_reached",
            now_unix_s,
        )?;
        transaction.commit().map_err(storage_error)
    }

    /// Starts UID-safe cleanup after a terminal operation or pre-application setup failure.
    ///
    /// # Errors
    ///
    /// Returns an ownership, state, missing-run, or storage error.
    pub(crate) fn start_cleanup(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        observed_namespace_uid: &str,
        authority: &GenerationIdentity,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        validate_authority_identity(authority)?;
        self.cleanup_transition(
            run_id,
            cleanup_identity,
            observed_namespace_uid,
            Some(authority),
            CleanupState::Running,
            "cleanup.started",
            now_unix_s,
        )
    }

    /// Records one coalesced cleanup failure while preserving receiver outcome.
    ///
    /// # Errors
    ///
    /// Returns an ownership, state, missing-run, or storage error.
    pub fn fail_cleanup(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        observed_namespace_uid: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.cleanup_transition(
            run_id,
            cleanup_identity,
            observed_namespace_uid,
            None,
            CleanupState::Failed,
            "cleanup.failed",
            now_unix_s,
        )
    }

    /// Confirms cleanup only after every exact recorded owned object is observed absent.
    ///
    /// # Errors
    ///
    /// Returns an ownership, presence, state, missing-run, or storage error.
    pub fn complete_cleanup(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        evidence: &CleanupAbsenceEvidence,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.complete_cleanup_with_evidence(run_id, cleanup_identity, evidence, now_unix_s)
    }

    /// Reads one retained disclosure-reviewed snapshot.
    ///
    /// # Errors
    ///
    /// Returns not-found, expiry, or storage errors without disclosing private state.
    pub fn snapshot(&self, run_id: &str, now_unix_s: i64) -> Result<Snapshot, ServiceError> {
        self.expire(now_unix_s)?;
        let connection = self.connection()?;
        if self.run_tombstoned(&connection, run_id, now_unix_s)? {
            return Err(ServiceError::RunExpired);
        }
        load_snapshot(&connection, run_id)?.ok_or(ServiceError::RunNotFound)
    }

    /// Returns a contiguous retained event page.
    ///
    /// # Errors
    ///
    /// Returns invalid cursor/limit, not-found, expiry, or storage errors.
    pub fn events(
        &self,
        run_id: &str,
        after: u8,
        limit: u8,
        now_unix_s: i64,
    ) -> Result<EventPage, ServiceError> {
        if after > 64 || !(1..=64).contains(&limit) {
            return Err(ServiceError::InvalidRequest);
        }
        self.expire(now_unix_s)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage_error)?;
        if self.run_tombstoned(&transaction, run_id, now_unix_s)? {
            return Err(ServiceError::RunExpired);
        }
        let snapshot = load_snapshot(&transaction, run_id)?.ok_or(ServiceError::RunNotFound)?;
        let events = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT sequence, kind, occurred_at, execution_state, receiver_result, ",
                    "target_rejection, receipt_available, cleanup_state FROM events ",
                    "WHERE run_id = ?1 AND sequence > ?2 ORDER BY sequence LIMIT ?3"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![run_id, after, limit], event_from_row)
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
        };
        let next_after = events.last().map_or(after, |event| event.sequence);
        transaction.commit().map_err(storage_error)?;
        Ok(EventPage {
            run_id: run_id.to_owned(),
            events,
            last_sequence: snapshot.last_sequence,
            next_after,
        })
    }

    pub(crate) fn retained_public_trust(&self, run_id: &str) -> Result<Vec<u8>, ServiceError> {
        bounded_hex_128(run_id)?;
        let pin = self
            .connection()?
            .query_row(
                concat!(
                    "SELECT runs.authority_generation, runs.authority_manifest_digest FROM runs ",
                    "JOIN receipts ON receipts.run_id = runs.run_id WHERE runs.run_id = ?1 ",
                    "AND runs.public_retained = 1 AND runs.receipt_available = 1"
                ),
                [run_id],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::ReceiptNotAvailable)?;
        let identity = stored_authority_identity(pin.0, pin.1)?;
        self.authority
            .public_trust(&identity)
            .map(|trust| trust.bytes)
            .map_err(|_| ServiceError::Unavailable)
    }

    /// Retrieves exact unchanged KAP-0038 receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns not-found, expiry, unavailable-receipt, digest, or storage errors.
    pub fn receipt(&self, run_id: &str, now_unix_s: i64) -> Result<Vec<u8>, ServiceError> {
        self.snapshot(run_id, now_unix_s)?;
        let connection = self.connection()?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT digest, object_name FROM receipts WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let (digest, object_name) = row.ok_or(ServiceError::ReceiptNotAvailable)?;
        self.read_receipt_object(run_id, &digest, &object_name)
    }

    /// Translates one already transport-bounded HTTP request through the exact `v1` service seam.
    ///
    /// The native listener must additionally enforce connection and receive deadlines. This
    /// method rejects the owned request-line, header, body, framing, method, media, origin, and
    /// query bounds before admission and never reflects hostile input.
    pub fn handle_http(&self, req: &Request<Vec<u8>>, now_unix_s: i64) -> Response<Vec<u8>> {
        match self.translate_http(req, now_unix_s) {
            Ok(response) => response,
            Err(error) => error_response(error),
        }
    }

    fn translate_http(
        &self,
        request: &Request<Vec<u8>>,
        now_unix_s: i64,
    ) -> Result<Response<Vec<u8>>, ServiceError> {
        validate_http_envelope(request, &self.origin)?;
        let path = request.uri().path();
        if path.starts_with("/sandbox/") && !path.starts_with("/sandbox/v1/") {
            return Err(ServiceError::UnsupportedVersion);
        }
        match (request.method(), path) {
            (&Method::POST, "/sandbox/v1/runs") => {
                if request.uri().query().is_some() {
                    return Err(ServiceError::InvalidRequest);
                }
                validate_post_headers(request)?;
                let body: AdmissionBody = serde_json::from_slice(request.body())
                    .map_err(|_| ServiceError::InvalidRequest)?;
                if body.api_version != "v1" {
                    return Err(ServiceError::UnsupportedVersion);
                }
                let key = request
                    .headers()
                    .get("idempotency-key")
                    .and_then(|value| value.to_str().ok())
                    .ok_or(ServiceError::InvalidRequest)?;
                let admission = self.admit(key, body.scenario, now_unix_s)?;
                let status = match admission.disposition {
                    AdmissionDisposition::Created => StatusCode::CREATED,
                    AdmissionDisposition::Replayed => StatusCode::OK,
                };
                let disposition = match admission.disposition {
                    AdmissionDisposition::Created => "created",
                    AdmissionDisposition::Replayed => "replayed",
                };
                json_response(
                    status,
                    &AdmissionJson {
                        api_version: "v1",
                        run_id: &admission.run_id,
                        operation_id: &admission.operation_id,
                        scenario: admission.scenario,
                        admission_disposition: disposition,
                        admitted_at: timestamp(admission.admitted_at_unix_s)?,
                        expires_at: timestamp(admission.expires_at_unix_s)?,
                        last_sequence: admission.last_sequence,
                    },
                )
            },
            (&Method::GET, _) => self.translate_get(request, now_unix_s),
            _ => Err(ServiceError::InvalidRequest),
        }
    }

    fn translate_get(
        &self,
        request: &Request<Vec<u8>>,
        now_unix_s: i64,
    ) -> Result<Response<Vec<u8>>, ServiceError> {
        validate_get_headers(request)?;
        let path = request.uri().path();
        let prefix = "/sandbox/v1/runs/";
        let suffix = path
            .strip_prefix(prefix)
            .ok_or(ServiceError::InvalidRequest)?;
        if let Some(run_id) = suffix.strip_suffix("/events") {
            bounded_hex_128(run_id).map_err(|_| ServiceError::RunNotFound)?;
            let (after, limit) = parse_event_query(request.uri().query())?;
            let page = self.events(run_id, after, limit, now_unix_s)?;
            let events = page.events.iter().map(event_json).collect::<Vec<_>>();
            return json_response(
                StatusCode::OK,
                &EventPageJson {
                    api_version: "v1",
                    run_id: &page.run_id,
                    events,
                    last_sequence: page.last_sequence,
                    next_after: page.next_after,
                },
            );
        }
        if let Some(run_id) = suffix.strip_suffix("/receipt") {
            bounded_hex_128(run_id).map_err(|_| ServiceError::RunNotFound)?;
            let bytes = self.receipt(run_id, now_unix_s)?;
            let digest = hex(&Sha256::digest(&bytes));
            let mut response = Response::new(bytes);
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/vnd.kapsel.kap0038.receipt"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            let length = HeaderValue::from_str(&response.body().len().to_string())
                .map_err(|_| ServiceError::Unavailable)?;
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, length);
            let etag = HeaderValue::from_str(&format!("\"{digest}\""))
                .map_err(|_| ServiceError::Unavailable)?;
            response.headers_mut().insert(header::ETAG, etag);
            return Ok(response);
        }
        if suffix.contains('/') || request.uri().query().is_some() {
            return Err(ServiceError::InvalidRequest);
        }
        bounded_hex_128(suffix).map_err(|_| ServiceError::RunNotFound)?;
        let snapshot = self.snapshot(suffix, now_unix_s)?;
        json_response(StatusCode::OK, &snapshot_json(&snapshot)?)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "schema creation and idempotent migrations stay ordered"
    )]
    fn initialize(&self) -> Result<(), ServiceError> {
        let database_parent = self
            .database_path
            .parent()
            .ok_or(ServiceError::Unavailable)?;
        validate_private_directory(database_parent)?;
        validate_private_directory(&self.receipt_directory)?;
        prepare_database_file(&self.database_path)?;
        let mut connection = self.connection()?;
        preflight_existing_authority_schema(&connection)?;
        preflight_backup_schema(&connection)?;
        connection
            .execute_batch("PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL;")
            .map_err(storage_error)?;
        for ddl in service_schema::TABLES_BY_NAME {
            connection.execute_batch(ddl).map_err(storage_error)?;
        }
        connection
            .execute(
                "INSERT OR IGNORE INTO service_state (singleton, stopped) VALUES (1, 0)",
                [],
            )
            .map_err(storage_error)?;
        let has_handoff_verifier = {
            let mut statement = connection
                .prepare("PRAGMA table_info(runs)")
                .map_err(storage_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)?
                .iter()
                .any(|name| name == "handoff_credential_verifier")
        };
        if !has_handoff_verifier {
            connection
                .execute(
                    concat!(
                        "ALTER TABLE runs ADD COLUMN handoff_credential_verifier ",
                        "BLOB NOT NULL DEFAULT X''"
                    ),
                    [],
                )
                .map_err(storage_error)?;
        }
        migrate_cleanup_columns(&connection)?;
        migrate_service_state_columns(&connection)?;
        migrate_slice3_run_columns(&connection)?;
        migrate_authority_columns(&mut connection)?;
        validate_authority_pins(&connection)?;
        preflight_backup_schema(&connection)?;
        validate_serial_capacity(&connection)?;
        self.remove_orphan_receipts(&mut connection)
    }

    fn remove_orphan_receipts(&self, connection: &mut Connection) -> Result<(), ServiceError> {
        self.validate_pinned_paths()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stale_publications = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT receipt_publications.run_id, receipt_publications.object_name FROM ",
                    "receipt_publications LEFT JOIN runs ON runs.run_id = ",
                    "receipt_publications.run_id WHERE runs.run_id IS NULL OR (",
                    "runs.public_retained = 0 AND NOT EXISTS (SELECT 1 FROM cleanup_records ",
                    "JOIN application_reports ON application_reports.run_id = ",
                    "cleanup_records.run_id ",
                    "WHERE cleanup_records.run_id = receipt_publications.run_id ",
                    "AND cleanup_records.active = 1 AND cleanup_records.eligible = 0 ",
                    "AND application_reports.kind = 'finalized'))"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
        };
        for (run_id, _) in &stale_publications {
            transaction
                .execute(
                    "DELETE FROM receipt_publications WHERE run_id = ?1",
                    [run_id],
                )
                .map_err(storage_error)?;
        }
        let mut referenced = HashSet::new();
        for table in ["receipts", "receipt_publications"] {
            let mut statement = transaction
                .prepare(&format!("SELECT object_name FROM {table}"))
                .map_err(storage_error)?;
            let names = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(storage_error)?;
            for name in names {
                referenced.insert(name.map_err(storage_error)?);
            }
        }
        let entries =
            fs::read_dir(&self.receipt_directory).map_err(|_| ServiceError::Unavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| ServiceError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ServiceError::Unavailable)?;
            let orphan_final = name.starts_with("sandbox-")
                && name.ends_with(".receipt")
                && !referenced.contains(&name);
            let stale_temporary =
                name.starts_with(".sandbox-") && name.contains(".receipt.pending-");
            if orphan_final || stale_temporary {
                fs::remove_file(entry.path()).map_err(|_| ServiceError::Unavailable)?;
            }
        }
        fs::File::open(&self.receipt_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ServiceError::Unavailable)?;
        transaction.commit().map_err(storage_error)
    }

    fn connection(&self) -> Result<Connection, ServiceError> {
        self.validate_pinned_paths()?;
        let connection = open_database_connection(&self.database_path)?;
        self.validate_pinned_paths()?;
        Ok(connection)
    }

    fn read_only_connection(&self) -> Result<Connection, ServiceError> {
        self.validate_pinned_paths()?;
        let before = validate_database_file(&self.database_path)?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage_error)?;
        if validate_database_file(&self.database_path)? != before {
            return Err(ServiceError::Unavailable);
        }
        self.validate_pinned_paths()?;
        Ok(connection)
    }

    fn validate_pinned_paths(&self) -> Result<(), ServiceError> {
        if let Some(pinned) = self.pinned_state.as_deref() {
            validate_pinned_state(&self.database_path, &self.receipt_directory, pinned)?;
        }
        Ok(())
    }

    pub(crate) fn authority_reader(&self) -> Arc<fixed_staging::FixedStagingReader> {
        Arc::clone(&self.authority)
    }

    fn recover_authority_collection(&self) -> Result<(), ServiceError> {
        let connection = self.connection()?;
        let pending = connection
            .query_row(
                "SELECT generation, manifest_digest FROM authority_collection WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let Some((generation, manifest_digest)) = pending else {
            return Ok(());
        };
        let identity = stored_authority_identity(Some(generation), manifest_digest)?;
        self.authority
            .recover_collection(&identity)
            .map_err(|_| ServiceError::Unavailable)?;
        connection
            .execute("DELETE FROM authority_collection WHERE singleton = 1", [])
            .map_err(storage_error)?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "the closed read state is consumed by the following private backup foundation"
    )]
    fn backup_publication_state(&self) -> Result<BackupPublicationState, ServiceError> {
        let connection = self.read_only_connection()?;
        validate_exact_service_schema(&connection)?;
        validate_authority_pins(&connection)?;
        preflight_backup_schema(&connection)?;
        self.validate_authority_reference_owners(&connection)?;
        let stopped: bool = connection
            .query_row(
                "SELECT stopped = 1 FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        let mut statement = connection
            .prepare(concat!(
                "SELECT slot, generation, manifest_digest, captured_at FROM backup_generations ",
                "ORDER BY slot"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        drop(statement);
        let find = |slot: &str| rows.iter().find(|(candidate, _, _, _)| candidate == slot);
        let published = |slot: &str| -> Result<Option<PublishedBackup>, ServiceError> {
            let Some((_, generation, digest, captured_at)) = find(slot) else {
                return Ok(None);
            };
            Ok(Some(PublishedBackup {
                generation: u64::try_from(*generation).map_err(|_| ServiceError::Unavailable)?,
                captured_at: *captured_at,
                manifest_digest: digest.clone().ok_or(ServiceError::Unavailable)?,
                authorities: backup_references_for_slot(&connection, slot)?,
            }))
        };
        let current = published("current")?;
        let deleting = published("deleting")?;
        let pending = find("pending")
            .map(|(_, generation, digest, captured_at)| {
                if digest.is_some() {
                    return Err(ServiceError::Unavailable);
                }
                Ok(BackupPublication {
                    generation: u64::try_from(*generation)
                        .map_err(|_| ServiceError::Unavailable)?,
                    captured_at: *captured_at,
                    authorities: backup_references_for_slot(&connection, "pending")?,
                    predecessor: current
                        .as_ref()
                        .map(|record| (record.generation, record.manifest_digest.clone())),
                })
            })
            .transpose()?;
        match (pending, current, deleting) {
            (None, None, None) => Ok(BackupPublicationState::Empty),
            (Some(pending), None, None) => Ok(BackupPublicationState::Pending(pending)),
            (None, Some(current), None) => Ok(BackupPublicationState::Current(current)),
            (Some(pending), Some(current), None) => {
                Ok(BackupPublicationState::Replacing { current, pending })
            },
            (None, Some(current), Some(deleting)) => {
                Ok(BackupPublicationState::Deleting { current, deleting })
            },
            _ => Err(ServiceError::Unavailable),
        }
    }

    #[allow(
        dead_code,
        reason = "exact pending resume is consumed by the following private backup foundation"
    )]
    fn resume_pending_backup_publication(&self) -> Result<BackupPublication, ServiceError> {
        let (BackupPublicationState::Pending(pending)
        | BackupPublicationState::Replacing { pending, .. }) = self.backup_publication_state()?
        else {
            return Err(ServiceError::Unavailable);
        };
        let connection = self.read_only_connection()?;
        let retained = backup_authority_references(&connection, &self.authority)?;
        if retained != pending.authorities {
            return Err(ServiceError::Unavailable);
        }
        Ok(pending)
    }

    fn begin_backup_publication(
        &self,
        generation: u64,
        captured_at: i64,
    ) -> Result<BackupPublication, ServiceError> {
        if generation == 0 || captured_at <= 0 {
            return Err(ServiceError::Unavailable);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        validate_authority_pins(&transaction)?;
        preflight_backup_schema(&transaction)?;
        self.validate_authority_reference_owners(&transaction)?;
        let stopped: bool = transaction
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        let existing = transaction
            .query_row(
                "SELECT generation, manifest_digest FROM backup_generations WHERE slot = 'current'",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let transitional: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM backup_generations WHERE slot != 'current')",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if transitional {
            return Err(ServiceError::Unavailable);
        }
        let predecessor = match existing {
            Some((stored_generation, digest)) => {
                let stored_generation =
                    u64::try_from(stored_generation).map_err(|_| ServiceError::Unavailable)?;
                if stored_generation.checked_add(1) != Some(generation) || !valid_sha256(&digest) {
                    return Err(ServiceError::Unavailable);
                }
                Some((stored_generation, digest))
            },
            None if generation == 1 => None,
            None => return Err(ServiceError::Unavailable),
        };
        let authorities = backup_authority_references(&transaction, &self.authority)?;
        let generation_i64 = i64::try_from(generation).map_err(|_| ServiceError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO backup_generations VALUES ('pending', ?1, NULL, 'pending', ?2)",
                params![generation_i64, captured_at],
            )
            .map_err(storage_error)?;
        for identity in &authorities {
            let authority_generation =
                i64::try_from(identity.generation).map_err(|_| ServiceError::Unavailable)?;
            transaction
                .execute(
                    "INSERT INTO backup_authority_references VALUES ('pending', ?1, ?2)",
                    params![authority_generation, identity.manifest_digest],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(BackupPublication {
            generation,
            captured_at,
            authorities,
            predecessor,
        })
    }

    fn finish_backup_publication(
        &self,
        generation: u64,
        manifest_digest: &str,
    ) -> Result<Option<u64>, ServiceError> {
        if generation == 0 || !valid_sha256(manifest_digest) {
            return Err(ServiceError::Unavailable);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        preflight_backup_schema(&transaction)?;
        self.validate_authority_reference_owners(&transaction)?;
        let stopped: bool = transaction
            .query_row(
                "SELECT stopped = 1 FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        let pending: (i64, i64) = transaction
            .query_row(
                concat!(
                    "SELECT generation, captured_at FROM backup_generations ",
                    "WHERE slot = 'pending' AND manifest_digest IS NULL"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage_error)?;
        if u64::try_from(pending.0).ok() != Some(generation) {
            return Err(ServiceError::Unavailable);
        }
        let current = transaction
            .query_row(
                "SELECT generation FROM backup_generations WHERE slot = 'current'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage_error)?;
        if current.is_some() {
            transaction
                .execute(
                    concat!(
                        "UPDATE backup_generations SET slot = 'deleting', state = 'deleting' ",
                        "WHERE slot = 'current'"
                    ),
                    [],
                )
                .map_err(storage_error)?;
            transaction
                .execute(
                    concat!(
                        "UPDATE backup_authority_references SET slot = 'deleting' ",
                        "WHERE slot = 'current'"
                    ),
                    [],
                )
                .map_err(storage_error)?;
        }
        transaction
            .execute(
                concat!(
                    "UPDATE backup_generations SET slot = 'current', state = 'current', ",
                    "manifest_digest = ?2 WHERE slot = 'pending' AND generation = ?1"
                ),
                params![pending.0, manifest_digest],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "UPDATE backup_authority_references SET slot = 'current' WHERE slot = 'pending'",
                [],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        current
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ServiceError::Unavailable)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one stopped transaction keeps restored backup references continuously owned"
    )]
    fn restore_backup_publication(
        &self,
        selected: &BackupPublication,
        manifest_digest: &str,
    ) -> Result<(), ServiceError> {
        if selected.generation == 0
            || selected.captured_at <= 0
            || selected.authorities.len() > 2
            || !valid_sha256(manifest_digest)
        {
            return Err(ServiceError::Unavailable);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        preflight_backup_schema(&transaction)?;
        self.validate_authority_reference_owners(&transaction)?;
        let stopped: bool = transaction
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        let pending = transaction
            .query_row(
                concat!(
                    "SELECT generation, captured_at FROM backup_generations ",
                    "WHERE slot = 'pending' AND manifest_digest IS NULL"
                ),
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(storage_error)?;
        if u64::try_from(pending.0).ok() != Some(selected.generation)
            || pending.1 != selected.captured_at
        {
            return Err(ServiceError::Unavailable);
        }
        let predecessor = transaction
            .query_row(
                concat!(
                    "SELECT generation, manifest_digest FROM backup_generations ",
                    "WHERE slot = 'current'"
                ),
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .map(|(generation, digest)| {
                Ok((
                    u64::try_from(generation).map_err(|_| ServiceError::Unavailable)?,
                    digest,
                ))
            })
            .transpose()?;
        if predecessor != selected.predecessor {
            return Err(ServiceError::Unavailable);
        }
        let mut statement = transaction
            .prepare(concat!(
                "SELECT authority_generation, authority_manifest_digest FROM ",
                "backup_authority_references WHERE slot = 'pending' ",
                "ORDER BY authority_generation"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?;
        let mut authorities = Vec::new();
        for row in rows {
            let (generation, digest) = row.map_err(storage_error)?;
            authorities.push(stored_authority_identity(Some(generation), digest)?);
        }
        drop(statement);
        if authorities != selected.authorities {
            return Err(ServiceError::Unavailable);
        }
        transaction
            .execute("DELETE FROM backup_authority_references", [])
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM backup_generations", [])
            .map_err(storage_error)?;
        let generation =
            i64::try_from(selected.generation).map_err(|_| ServiceError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO backup_generations VALUES ('current', ?1, ?2, 'current', ?3)",
                params![generation, manifest_digest, selected.captured_at],
            )
            .map_err(storage_error)?;
        for identity in &authorities {
            let authority_generation =
                i64::try_from(identity.generation).map_err(|_| ServiceError::Unavailable)?;
            transaction
                .execute(
                    "INSERT INTO backup_authority_references VALUES ('current', ?1, ?2)",
                    params![authority_generation, identity.manifest_digest],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
    }

    fn finish_backup_deletion(&self, generation: u64) -> Result<(), ServiceError> {
        let generation = i64::try_from(generation).map_err(|_| ServiceError::Unavailable)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        preflight_backup_schema(&transaction)?;
        self.validate_authority_reference_owners(&transaction)?;
        let stopped: bool = transaction
            .query_row(
                "SELECT stopped = 1 FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !stopped {
            return Err(ServiceError::Unavailable);
        }
        transaction
            .execute(
                "DELETE FROM backup_authority_references WHERE slot = 'deleting'",
                [],
            )
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                "DELETE FROM backup_generations WHERE slot = 'deleting' AND generation = ?1",
                [generation],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::Unavailable);
        }
        transaction.commit().map_err(storage_error)
    }

    pub(crate) fn collect_unused_authority(&self) -> Result<bool, ServiceError> {
        self.recover_authority_collection()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        validate_authority_pins(&transaction)?;
        let Some(identity) = self
            .authority
            .noncurrent_identity()
            .map_err(|_| ServiceError::Unavailable)?
        else {
            transaction.commit().map_err(storage_error)?;
            return Ok(false);
        };
        let current = self
            .authority
            .current_identity()
            .map_err(|_| ServiceError::Unavailable)?;
        let referenced =
            Self::noncurrent_authority_is_referenced(&transaction, &current, &identity)?;
        let generation =
            i64::try_from(identity.generation).map_err(|_| ServiceError::Unavailable)?;
        self.validate_authority_reference_owners(&transaction)?;
        if referenced {
            transaction.commit().map_err(storage_error)?;
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO authority_collection VALUES (1, ?1, ?2)",
                params![generation, identity.manifest_digest],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        self.authority
            .collect_noncurrent(&identity)
            .map_err(|_| ServiceError::Unavailable)?;
        self.connection()?
            .execute("DELETE FROM authority_collection WHERE singleton = 1", [])
            .map_err(storage_error)?;
        Ok(true)
    }

    fn noncurrent_authority_is_referenced(
        transaction: &rusqlite::Transaction<'_>,
        current: &GenerationIdentity,
        noncurrent: &GenerationIdentity,
    ) -> Result<bool, ServiceError> {
        let mut statement = transaction
            .prepare(concat!(
                "SELECT authority_generation, authority_manifest_digest FROM runs ",
                "WHERE authority_generation IS NOT NULL UNION ALL SELECT authority_generation, ",
                "authority_manifest_digest FROM tombstones UNION ALL SELECT authority_generation, ",
                "authority_manifest_digest FROM backup_authority_references"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?;
        let mut referenced = false;
        for row in rows {
            let (generation, digest) = row.map_err(storage_error)?;
            let identity = stored_authority_identity(generation, digest)?;
            if &identity == noncurrent {
                referenced = true;
            } else if &identity != current {
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(referenced)
    }

    fn validate_authority_reference_owners(
        &self,
        connection: &Connection,
    ) -> Result<(), ServiceError> {
        for table in [
            "receipts",
            "receipt_publications",
            "cleanup_records",
            "application_reports",
        ] {
            let sql = format!(
                "SELECT EXISTS(SELECT 1 FROM {table} LEFT JOIN runs USING (run_id) \
                 WHERE runs.run_id IS NULL)"
            );
            let orphaned: bool = connection
                .query_row(&sql, [], |row| row.get(0))
                .map_err(storage_error)?;
            if orphaned {
                return Err(ServiceError::Unavailable);
            }
        }
        let orphaned_backup_reference: bool = connection
            .query_row(
                concat!(
                    "SELECT EXISTS(SELECT 1 FROM backup_authority_references r ",
                    "LEFT JOIN backup_generations g USING (slot) WHERE g.slot IS NULL)"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if orphaned_backup_reference {
            return Err(ServiceError::Unavailable);
        }
        let current = self
            .authority
            .current_identity()
            .map_err(|_| ServiceError::Unavailable)?;
        let noncurrent = self
            .authority
            .noncurrent_identity()
            .map_err(|_| ServiceError::Unavailable)?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT authority_generation, authority_manifest_digest FROM runs ",
                "WHERE authority_generation IS NOT NULL UNION SELECT authority_generation, ",
                "authority_manifest_digest FROM tombstones UNION SELECT authority_generation, ",
                "authority_manifest_digest FROM backup_authority_references"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?;
        for row in rows {
            let (generation, digest) = row.map_err(storage_error)?;
            let identity = stored_authority_identity(generation, digest)?;
            if identity != current && noncurrent.as_ref() != Some(&identity) {
                return Err(ServiceError::Unavailable);
            }
        }
        drop(statement);
        let dispatch_references = self
            .authority
            .dispatch_references()
            .map_err(|_| ServiceError::Unavailable)?;
        for (run_id, published_epoch) in dispatch_references {
            let owner = connection
                .query_row(
                    concat!(
                        "SELECT execution_state, authority_generation, ",
                        "authority_manifest_digest, lease_epoch FROM runs WHERE run_id = ?1"
                    ),
                    [&run_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage_error)?;
            let Some((state, generation, digest, durable_epoch)) = owner else {
                return Err(ServiceError::Unavailable);
            };
            stored_authority_identity(generation, digest)?;
            if state == "queued" || durable_epoch <= 0 || published_epoch != durable_epoch {
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(())
    }

    pub(crate) fn validate_authority_state(&self) -> Result<(), ServiceError> {
        validate_authority_pins(&self.connection()?)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps all immutable admission and capacity facts auditable"
    )]
    fn admit_with_run_id(
        &self,
        idempotency_key: &str,
        scenario: Scenario,
        now_unix_s: i64,
        run_id: &str,
    ) -> Result<Admission, ServiceError> {
        bounded_hex_128(idempotency_key)?;
        bounded_hex_128(run_id)?;
        timestamp(now_unix_s)?;
        self.expire(now_unix_s)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let keyring = self
            .authority
            .tombstone_keyring()
            .map_err(|_| ServiceError::Unavailable)?;
        let first_key = keyring
            .entries
            .first()
            .ok_or(ServiceError::Unavailable)?
            .digest_key;
        let second_key = keyring
            .entries
            .get(1)
            .map_or(first_key, |entry| entry.digest_key);
        let first_digest = keyed_digest(&first_key, idempotency_key);
        let second_digest = keyed_digest(&second_key, idempotency_key);
        let tombstoned: bool = transaction
            .query_row(
                concat!(
                    "SELECT EXISTS(SELECT 1 FROM tombstones WHERE key_digest IN (?1, ?2) ",
                    "AND delete_at > ?3)"
                ),
                params![first_digest, second_digest, now_unix_s],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if tombstoned {
            return Err(ServiceError::RunExpired);
        }
        if let Some(existing) = admission_by_key(&transaction, idempotency_key)? {
            if existing.scenario != scenario {
                return Err(ServiceError::IdempotencyConflict);
            }
            return Ok(Admission {
                disposition: AdmissionDisposition::Replayed,
                ..existing
            });
        }
        let stopped: bool = transaction
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if stopped {
            return Err(ServiceError::Unavailable);
        }
        let queued: i64 = transaction
            .query_row(
                concat!(
                    "SELECT COUNT(*) FROM runs WHERE execution_state = 'queued' ",
                    "AND public_retained = 1"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if queued >= QUEUED_RUNS_MAX {
            return Err(ServiceError::CapacitySaturated);
        }
        let operation_id = format!("sandbox-{run_id}");
        let cleanup_identity = format!("cleanup-{run_id}");
        let (policy_inventory, policy_inventory_digest) =
            policy_inventory(run_id, scenario_image(scenario))?;
        let expires_at = now_unix_s
            .checked_add(PUBLIC_RETENTION_SECONDS)
            .ok_or(ServiceError::InvalidRequest)?;
        transaction
            .execute(
                concat!(
                    "INSERT INTO runs (run_id, idempotency_key, scenario, operation_id, ",
                    "admitted_at, expires_at, execution_state, receipt_available, cleanup_state, ",
                    "last_sequence, active, deadline_emitted, application_invoked, ",
                    "public_retained, policy_revision, policy_inventory, ",
                    "policy_inventory_digest, cleanup_identity, deadline_seconds, deadline_at, ",
                    "policy_verified, cleanup_resource_state, lease_id, lease_epoch, ",
                    "lease_expires_at, handoff_credential_verifier) VALUES ",
                    "(?1, ?2, ?3, ?4, ?5, ?6, 'queued', 0, 'pending', 1, 0, 0, 0, 1, ",
                    "?7, ?8, ?9, ?10, ?11, NULL, 0, 'unverified', '', 0, 0, X'')"
                ),
                params![
                    run_id,
                    idempotency_key,
                    scenario.token(),
                    operation_id,
                    now_unix_s,
                    expires_at,
                    kubernetes_policy::REVISION,
                    policy_inventory,
                    policy_inventory_digest,
                    cleanup_identity,
                    SANDBOX_DEADLINE_SECONDS
                ],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                concat!(
                    "INSERT INTO cleanup_records VALUES ",
                    "(?1, ?2, NULL, 'unverified', 'pending', 0, 0, NULL, 0)"
                ),
                params![run_id, cleanup_identity],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                concat!(
                    "INSERT INTO events VALUES ",
                    "(?1, 1, 'admission.accepted', ?2, 'queued', NULL, NULL, 0, 'pending')"
                ),
                params![run_id, now_unix_s],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(Admission {
            run_id: run_id.to_owned(),
            operation_id,
            scenario,
            disposition: AdmissionDisposition::Created,
            admitted_at_unix_s: now_unix_s,
            expires_at_unix_s: expires_at,
            last_sequence: 1,
        })
    }

    pub(crate) fn server_owned_request(&self, run_id: &str) -> Result<AgentRequest, ServiceError> {
        let connection = self.connection()?;
        let (operation_id, scenario): (String, String) = connection
            .query_row(
                "SELECT operation_id, scenario FROM runs WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        let scenario = Scenario::parse(&scenario)?;
        let digest = scenario_image(scenario);
        Ok(AgentRequest {
            operation_id,
            namespace: format!("sandbox-{run_id}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: digest.into(),
        })
    }

    fn validate_lease(&self, lease: &DispatchLease, now: i64) -> Result<(), ServiceError> {
        bounded_hex_128(&lease.run_id)?;
        let connection = self.connection()?;
        let stored: (String, i64, i64, bool, Option<i64>, String) = connection
            .query_row(
                concat!(
                    "SELECT lease_id, lease_epoch, lease_expires_at, active, ",
                    "authority_generation, authority_manifest_digest ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !stored.3
            || stored.0 != lease.lease_id
            || stored.1 != lease.epoch
            || stored.2 != lease.expires_at_unix_s
            || now >= stored.2
            || stored_authority_identity(stored.4, stored.5)? != lease.authority
        {
            return Err(ServiceError::LeaseBusy);
        }
        Ok(())
    }

    fn validate_runner_authority(&self, run_id: &str) -> Result<(), ServiceError> {
        let authority: (bool, bool, bool) = self
            .connection()?
            .query_row(
                concat!(
                    "SELECT runner_revoked, runner_state_retiring, runner_state_retired ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if authority.0 || authority.1 || authority.2 {
            return Err(ServiceError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn validate_runner_launch(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let recovery: bool = self
            .connection()?
            .query_row(
                "SELECT application_invoked FROM runs WHERE run_id = ?1",
                [&lease.run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        self.validate_application_ready(lease, now_unix_s, recovery)
    }

    fn validate_application_ready(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
        recovery: bool,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        self.validate_runner_authority(&lease.run_id)?;
        let (policy_verified, provisioning_closed, deadline_at): (bool, bool, i64) = self
            .connection()?
            .query_row(
                concat!(
                    "SELECT policy_verified, provisioning_closed, deadline_at FROM runs ",
                    "WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !policy_verified || !provisioning_closed {
            return Err(ServiceError::PolicyMismatch);
        }
        if !recovery && now_unix_s >= deadline_at {
            return Err(ServiceError::DeadlineExceeded);
        }
        Ok(())
    }

    #[cfg(test)]
    fn terminal_transition(
        &self,
        run_id: &str,
        state: ExecutionState,
        result: Option<&str>,
        rejection: Option<&str>,
        kind: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let current: (String, Option<String>, Option<String>, bool) = transaction
            .query_row(
                concat!(
                    "SELECT execution_state, receiver_result, target_rejection, ",
                    "public_retained FROM runs WHERE run_id = ?1"
                ),
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if current.0 == state.token()
            && current.1.as_deref() == result
            && current.2.as_deref() == rejection
        {
            return Ok(());
        }
        if current.0 != "running" {
            return Err(ServiceError::InvalidTransition);
        }
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET execution_state = ?2, receiver_result = ?3, ",
                    "target_rejection = ?4 WHERE run_id = ?1"
                ),
                params![run_id, state.token(), result, rejection],
            )
            .map_err(storage_error)?;
        if state == ExecutionState::NotAttempted {
            transaction
                .execute(
                    "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                    [run_id],
                )
                .map_err(storage_error)?;
        }
        if current.3 {
            append_event(&transaction, run_id, kind, now_unix_s)?;
        }
        transaction.commit().map_err(storage_error)
    }

    #[cfg(test)]
    fn install_receipt(
        &self,
        run_id: &str,
        bytes: &[u8],
        digest: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        if bytes.is_empty()
            || bytes.len() > RECEIPT_BYTES_MAX
            || hex(&Sha256::digest(bytes)) != digest
        {
            return Err(ServiceError::Unavailable);
        }
        let object_name = format!("sandbox-{run_id}-{digest}.receipt");
        if !self.claim_receipt_publication(run_id, bytes, digest, &object_name, now_unix_s)? {
            return Ok(());
        }
        self.complete_receipt_publication(run_id, bytes, digest, &object_name, now_unix_s)
    }

    #[cfg(test)]
    fn claim_receipt_publication(
        &self,
        run_id: &str,
        bytes: &[u8],
        digest: &str,
        object_name: &str,
        now_unix_s: i64,
    ) -> Result<bool, ServiceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        if let Some((existing_digest, existing_name)) = transaction
            .query_row(
                "SELECT digest, object_name FROM receipts WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?
        {
            if existing_digest != digest || existing_name != object_name {
                return Err(ServiceError::Unavailable);
            }
            if self.read_receipt_object(run_id, digest, object_name)? != bytes {
                return Err(ServiceError::Unavailable);
            }
            transaction.commit().map_err(storage_error)?;
            return Ok(false);
        }
        let publishable: bool = transaction
            .query_row(
                concat!(
                    "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = ?1 ",
                    "AND execution_state = 'terminal' AND public_retained = 1)"
                ),
                [run_id],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if !publishable {
            return Err(ServiceError::InvalidTransition);
        }
        if let Some((pending_digest, pending_name)) = transaction
            .query_row(
                "SELECT digest, object_name FROM receipt_publications WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?
        {
            if pending_digest != digest || pending_name != object_name {
                return Err(ServiceError::Unavailable);
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO receipt_publications VALUES (?1, ?2, ?3, ?4)",
                    params![run_id, digest, object_name, now_unix_s],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publication keeps public and post-expiry exact-byte completion in one protocol"
    )]
    fn complete_receipt_publication(
        &self,
        run_id: &str,
        bytes: &[u8],
        digest: &str,
        object_name: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        if bytes.is_empty()
            || bytes.len() > RECEIPT_BYTES_MAX
            || hex(&Sha256::digest(bytes)) != digest
            || object_name != format!("sandbox-{run_id}-{digest}.receipt")
        {
            return Err(ServiceError::Unavailable);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let public_retained: bool = transaction
            .query_row(
                "SELECT public_retained FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if let Some((existing_digest, existing_name)) = transaction
            .query_row(
                "SELECT digest, object_name FROM receipts WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage_error)?
        {
            if existing_digest != digest || existing_name != object_name {
                return Err(ServiceError::Unavailable);
            }
            let installed = self.read_receipt_object(run_id, digest, object_name)?;
            if installed != bytes {
                return Err(ServiceError::Unavailable);
            }
            transaction
                .execute(
                    "DELETE FROM receipt_publications WHERE run_id = ?1",
                    [run_id],
                )
                .map_err(storage_error)?;
            if !public_retained {
                transaction
                    .execute("DELETE FROM receipts WHERE run_id = ?1", [run_id])
                    .map_err(storage_error)?;
                transaction
                    .execute(
                        "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                        [run_id],
                    )
                    .map_err(storage_error)?;
            }
            transaction.commit().map_err(storage_error)?;
            if !public_retained {
                self.remove_receipt_object(run_id, digest, object_name)?;
            }
            return Ok(());
        }
        let pending: Option<(String, String)> = transaction
            .query_row(
                "SELECT digest, object_name FROM receipt_publications WHERE run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        if pending.as_ref().map(|(value, _)| value.as_str()) != Some(digest)
            || pending.as_ref().map(|(_, value)| value.as_str()) != Some(object_name)
        {
            return Err(ServiceError::InvalidTransition);
        }
        self.install_receipt_object(object_name, bytes)?;
        let installed = self.read_receipt_object(run_id, digest, object_name)?;
        if installed != bytes {
            return Err(ServiceError::Unavailable);
        }
        if public_retained {
            transaction
                .execute(
                    "INSERT INTO receipts VALUES (?1, ?2, ?3)",
                    params![run_id, digest, object_name],
                )
                .map_err(storage_error)?;
            let changed = transaction
                .execute(
                    concat!(
                        "UPDATE runs SET receipt_available = 1 WHERE run_id = ?1 ",
                        "AND execution_state = 'terminal'"
                    ),
                    [run_id],
                )
                .map_err(storage_error)?;
            if changed != 1 {
                return Err(ServiceError::InvalidTransition);
            }
            append_event(&transaction, run_id, "receipt.available", now_unix_s)?;
        }
        transaction
            .execute(
                "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM receipt_publications WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        if !public_retained {
            self.remove_receipt_object(run_id, digest, object_name)?;
        }
        Ok(())
    }

    fn install_receipt_object(&self, object_name: &str, bytes: &[u8]) -> Result<(), ServiceError> {
        self.validate_pinned_paths()?;
        let final_path = self.receipt_directory.join(object_name);
        if final_path.exists() {
            let existing = fs::read(&final_path).map_err(|_| ServiceError::Unavailable)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(ServiceError::Unavailable)
            };
        }
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).map_err(|_| ServiceError::Unavailable)?;
        let pending_path = self
            .receipt_directory
            .join(format!(".{object_name}.pending-{}", hex(&suffix)));
        let mut pending = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending_path)
            .map_err(|_| ServiceError::Unavailable)?;
        let write_result = pending
            .write_all(bytes)
            .and_then(|()| pending.sync_all())
            .map_err(|_| ServiceError::Unavailable);
        if write_result.is_err() {
            let _ = fs::remove_file(&pending_path);
            return write_result;
        }
        let directory =
            fs::File::open(&self.receipt_directory).map_err(|_| ServiceError::Unavailable)?;
        let pending_name = pending_path.file_name().ok_or(ServiceError::Unavailable)?;
        match rustix::fs::renameat_with(
            &directory,
            pending_name,
            &directory,
            object_name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {},
            Err(rustix::io::Errno::EXIST) => {
                let existing = fs::read(&final_path).map_err(|_| ServiceError::Unavailable)?;
                fs::remove_file(&pending_path).map_err(|_| ServiceError::Unavailable)?;
                if existing != bytes {
                    return Err(ServiceError::Unavailable);
                }
            },
            Err(_) => {
                let _ = fs::remove_file(&pending_path);
                return Err(ServiceError::Unavailable);
            },
        }
        self.validate_pinned_paths()?;
        directory.sync_all().map_err(|_| ServiceError::Unavailable)
    }

    fn read_receipt_object(
        &self,
        run_id: &str,
        digest: &str,
        object_name: &str,
    ) -> Result<Vec<u8>, ServiceError> {
        self.validate_pinned_paths()?;
        let expected_name = format!("sandbox-{run_id}-{digest}.receipt");
        if object_name != expected_name {
            return Err(ServiceError::Unavailable);
        }
        let path = self.receipt_directory.join(object_name);
        let metadata = fs::symlink_metadata(&path).map_err(|_| ServiceError::Unavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode().trailing_zeros() < 6
            || metadata.len() == 0
            || metadata.len() > RECEIPT_BYTES_MAX as u64
        {
            return Err(ServiceError::Unavailable);
        }
        let bytes = fs::read(path).map_err(|_| ServiceError::Unavailable)?;
        if hex(&Sha256::digest(&bytes)) != digest {
            return Err(ServiceError::Unavailable);
        }
        Ok(bytes)
    }

    pub(crate) fn begin_cleanup_attempt(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        plan_digest: &str,
    ) -> Result<i64, ServiceError> {
        bounded_identity(cleanup_identity)?;
        bounded_digest(plan_digest)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE runs SET cleanup_attempt = cleanup_attempt + 1, ",
                    "cleanup_plan_digest = ?3, cleanup_plan_issued = 0, ",
                    "cleanup_pending_observation_id = '' WHERE run_id = ?1 ",
                    "AND cleanup_attempt < 9223372036854775807 AND runner_state_retired = 1 ",
                    "AND EXISTS (SELECT 1 FROM cleanup_records WHERE cleanup_records.run_id = ?1 ",
                    "AND cleanup_records.cleanup_identity = ?2 AND cleanup_records.eligible = 1 ",
                    "AND cleanup_records.state IN ('running', 'failed'))"
                ),
                params![run_id, cleanup_identity, plan_digest],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        let attempt = transaction
            .query_row(
                "SELECT cleanup_attempt FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(attempt)
    }

    pub(crate) fn mark_cleanup_plan_issued(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        cleanup_attempt: i64,
        plan_digest: &str,
    ) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        let transaction = guarded_immediate_transaction(&mut connection)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE runs SET cleanup_plan_issued = 1 WHERE run_id = ?1 ",
                    "AND cleanup_attempt = ?3 AND cleanup_plan_digest = ?4 ",
                    "AND cleanup_plan_issued = 0 ",
                    "AND EXISTS (SELECT 1 FROM cleanup_records WHERE cleanup_records.run_id = ?1 ",
                    "AND cleanup_records.cleanup_identity = ?2 AND cleanup_records.eligible = 1 ",
                    "AND cleanup_records.state IN ('running', 'failed'))"
                ),
                params![run_id, cleanup_identity, cleanup_attempt, plan_digest],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        transaction.commit().map_err(storage_error)
    }

    pub(crate) fn begin_cleanup_observation(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        cleanup_attempt: i64,
        plan_digest: &str,
    ) -> Result<String, ServiceError> {
        bounded_digest(plan_digest)?;
        let observation_id = sha256_hex(
            format!("KAPSEL-CLEANUP-OBSERVATION-V1\0{run_id}\0{cleanup_attempt}\0{plan_digest}")
                .as_bytes(),
        );
        let mut connection = self.connection()?;
        let transaction = guarded_immediate_transaction(&mut connection)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE runs SET cleanup_pending_observation_id = ?5 WHERE run_id = ?1 ",
                    "AND cleanup_attempt = ?3 AND cleanup_plan_digest = ?4 ",
                    "AND cleanup_plan_issued = 1 AND cleanup_observation_id = '' ",
                    "AND cleanup_pending_observation_id IN ('', ?5) ",
                    "AND EXISTS (SELECT 1 FROM cleanup_records WHERE cleanup_records.run_id = ?1 ",
                    "AND cleanup_records.cleanup_identity = ?2 AND cleanup_records.eligible = 1 ",
                    "AND cleanup_records.state IN ('running', 'failed'))"
                ),
                params![
                    run_id,
                    cleanup_identity,
                    cleanup_attempt,
                    plan_digest,
                    observation_id
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        transaction.commit().map_err(storage_error)?;
        Ok(observation_id)
    }

    #[allow(
        clippy::suspicious_operation_groupings,
        clippy::too_many_lines,
        clippy::type_complexity,
        reason = "tuple fields compare independent durable prerequisites and one cleanup attempt"
    )]
    fn complete_cleanup_with_evidence(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        evidence: &CleanupAbsenceEvidence,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        bounded_identity(cleanup_identity)?;
        bounded_identity(&evidence.namespace_uid)?;
        bounded_identity(&evidence.cleanup_epoch)?;
        bounded_identity(&evidence.observation_id)?;
        bounded_digest(&evidence.plan_digest)?;
        if !evidence.owned_orphans.is_empty() {
            return Err(ServiceError::OwnershipMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored: (
            String,
            Option<String>,
            String,
            String,
            bool,
            bool,
            String,
            String,
            i64,
            String,
            bool,
            String,
            bool,
        ) = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_records.cleanup_identity, cleanup_records.namespace_uid, ",
                    "cleanup_records.resource_state, cleanup_records.state, ",
                    "cleanup_records.eligible, runs.public_retained, runs.cleanup_epoch, ",
                    "runs.cleanup_observation_id, runs.cleanup_attempt, ",
                    "runs.cleanup_plan_digest, runs.cleanup_plan_issued, ",
                    "runs.cleanup_pending_observation_id, runs.provisioning_closed = 1 ",
                    "AND runs.runner_revoked = 1 AND runs.runner_process_absent = 1 ",
                    "AND runs.journal_handoff = 1 AND runs.runner_state_retired = 1 ",
                    "FROM cleanup_records JOIN runs ",
                    "ON runs.run_id = cleanup_records.run_id WHERE cleanup_records.run_id = ?1"
                ),
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if stored.0 != cleanup_identity
            || stored.1.as_deref() != Some(&evidence.namespace_uid)
            || stored.2 != "owned"
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        if !stored.4
            || !stored.10
            || !stored.12
            || (stored.6 != evidence.cleanup_epoch)
            || !stored.7.is_empty()
            || stored.8 <= 0
            || stored.8 != evidence.cleanup_attempt
            || stored.9 != evidence.plan_digest
            || stored.11 != evidence.observation_id
            || !matches!(stored.3.as_str(), "running" | "failed")
        {
            return Err(ServiceError::InvalidTransition);
        }
        let recorded_objects = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT identity, uid, owner_label FROM provisioned_object_owners ",
                    "WHERE run_id = ?1 ORDER BY uid"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([run_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
        };
        if recorded_objects.len() != evidence.objects.len() || recorded_objects.is_empty() {
            return Err(ServiceError::OwnershipMismatch);
        }
        let mut consumed = vec![false; evidence.objects.len()];
        for (identity, uid, owner_label) in recorded_objects {
            let (kind, namespace, name) = object_identity_parts(&identity)?;
            let Some((index, observed)) =
                evidence.objects.iter().enumerate().find(|(index, item)| {
                    !consumed[*index]
                        && item.kind == kind
                        && item.namespace == namespace
                        && item.name == name
                        && item.uid == uid
                        && item.owner_label == owner_label
                })
            else {
                return Err(ServiceError::OwnershipMismatch);
            };
            if observed.present {
                return Err(ServiceError::InvalidTransition);
            }
            consumed[index] = true;
        }
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET cleanup_observation_id = ?2, ",
                    "cleanup_pending_observation_id = '' WHERE run_id = ?1"
                ),
                params![run_id, evidence.observation_id],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "UPDATE cleanup_records SET state = 'succeeded', active = 0 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        if stored.5 {
            transaction
                .execute(
                    concat!(
                        "UPDATE runs SET cleanup_state = 'succeeded', active = 0, ",
                        "handoff_credential_verifier = X'' WHERE run_id = ?1"
                    ),
                    [run_id],
                )
                .map_err(storage_error)?;
            append_event(&transaction, run_id, "cleanup.succeeded", now_unix_s)?;
        }
        transaction
            .execute("DELETE FROM cleanup_records WHERE run_id = ?1", [run_id])
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM provisioned_object_owners WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        if !stored.5 {
            transaction
                .execute("DELETE FROM runs WHERE run_id = ?1", [run_id])
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one cleanup transition validates the complete authority-bound durable identity"
    )]
    fn cleanup_transition(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        observed_uid: &str,
        expected_authority: Option<&GenerationIdentity>,
        state: CleanupState,
        kind: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        bounded_identity(cleanup_identity)?;
        bounded_identity(observed_uid)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let (
            owned_cleanup,
            owned_uid,
            resource_state,
            cleanup_state,
            eligible,
            prerequisites,
            generation,
            manifest_digest,
        ): (
            String,
            Option<String>,
            String,
            String,
            bool,
            bool,
            Option<i64>,
            String,
        ) = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_records.cleanup_identity, cleanup_records.namespace_uid, ",
                    "cleanup_records.resource_state, cleanup_records.state, ",
                    "cleanup_records.eligible, runs.provisioning_closed = 1 ",
                    "AND runs.runner_revoked = 1 AND runs.runner_process_absent = 1 ",
                    "AND runs.journal_handoff = 1 AND runs.runner_state_retired = 1, ",
                    "runs.authority_generation, runs.authority_manifest_digest ",
                    "FROM cleanup_records JOIN runs ",
                    "ON runs.run_id = cleanup_records.run_id WHERE cleanup_records.run_id = ?1"
                ),
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if owned_cleanup != cleanup_identity
            || owned_uid.as_deref() != Some(observed_uid)
            || resource_state != "owned"
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        if !eligible || !prerequisites {
            return Err(ServiceError::InvalidTransition);
        }
        let stored_authority = stored_authority_identity(generation, manifest_digest)?;
        if expected_authority.is_some_and(|expected| expected != &stored_authority) {
            return Err(ServiceError::Unavailable);
        }
        let allowed = matches!(
            (cleanup_state.as_str(), state),
            ("pending", CleanupState::Running) | ("running", CleanupState::Failed)
        );
        if !allowed {
            return Err(ServiceError::InvalidTransition);
        }
        transaction
            .execute(
                concat!(
                    "UPDATE cleanup_records SET state = ?2, started_at = CASE ",
                    "WHEN ?2 = 'running' AND started_at IS NULL THEN ?3 ELSE started_at END ",
                    "WHERE run_id = ?1"
                ),
                params![run_id, state.token(), now_unix_s],
            )
            .map_err(storage_error)?;
        let public_retained: Option<bool> = transaction
            .query_row(
                "SELECT public_retained FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        if public_retained == Some(true) {
            transaction
                .execute(
                    "UPDATE runs SET cleanup_state = ?2 WHERE run_id = ?1",
                    params![run_id, state.token()],
                )
                .map_err(storage_error)?;
            append_event(&transaction, run_id, kind, now_unix_s)?;
        }
        transaction.commit().map_err(storage_error)
    }

    fn expire(&self, now_unix_s: i64) -> Result<(), ServiceError> {
        self.expire_transaction_with_barrier(now_unix_s, true, |_| Ok(()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one retention transaction erases public, receipt, cleanup, and ownership rows"
    )]
    fn expire_transaction_with_barrier<F>(
        &self,
        now_unix_s: i64,
        remove_orphans: bool,
        mut barrier: F,
    ) -> Result<(), ServiceError>
    where
        F: FnMut(ExpiryTransactionBarrier) -> Result<(), ServiceError>,
    {
        let keyring = self
            .authority
            .tombstone_keyring()
            .map_err(|_| ServiceError::Unavailable)?;
        let mut connection = self.connection()?;
        validate_authority_pins(&connection)?;
        validate_tombstone_dependencies(&connection, &keyring)?;
        let queued_expired: bool = connection
            .query_row(
                concat!(
                    "SELECT EXISTS(SELECT 1 FROM runs WHERE expires_at <= ?1 ",
                    "AND public_retained = 1 AND execution_state = 'queued')"
                ),
                [now_unix_s],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if queued_expired {
            validate_authority_identity(&keyring.current)?;
        }
        if remove_orphans {
            self.remove_orphan_receipts(&mut connection)?;
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM tombstones WHERE delete_at <= ?1", [now_unix_s])
            .map_err(storage_error)?;
        let expired = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT runs.run_id, runs.idempotency_key, runs.expires_at, ",
                    "runs.execution_state, receipts.digest, receipts.object_name, ",
                    "receipt_publications.digest, ",
                    "receipt_publications.object_name, runs.authority_generation, ",
                    "runs.authority_manifest_digest, runs.runner_state_retired FROM runs ",
                    "LEFT JOIN receipts ",
                    "ON receipts.run_id = runs.run_id LEFT JOIN receipt_publications ON ",
                    "receipt_publications.run_id = runs.run_id WHERE runs.expires_at <= ?1 ",
                    "AND runs.public_retained = 1"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([now_unix_s], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, bool>(10)?,
                    ))
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
        };
        let dispatch_runs = self
            .authority
            .dispatch_run_ids()
            .map_err(|_| ServiceError::Unavailable)?;
        let mut expired_objects = Vec::new();
        for (
            run_id,
            key,
            expires_at,
            execution_state,
            digest,
            object_name,
            pending_digest,
            pending_name,
            authority_generation,
            authority_manifest_digest,
            runner_retired,
        ) in expired
        {
            let authority = if execution_state == "queued" {
                if authority_generation.is_some() || !authority_manifest_digest.is_empty() {
                    return Err(ServiceError::Unavailable);
                }
                keyring.current.clone()
            } else {
                stored_authority_identity(authority_generation, authority_manifest_digest)?
            };
            let digest_key = keyring
                .key_for(&authority)
                .ok_or(ServiceError::Unavailable)?;
            if let (Some(digest), Some(object_name)) = (digest, object_name) {
                expired_objects.push((run_id.clone(), digest, object_name));
            }
            let pending_object = pending_digest.zip(pending_name);
            let tombstone_delete_at = expires_at
                .checked_add(PUBLIC_RETENTION_SECONDS)
                .ok_or(ServiceError::Unavailable)?;
            if tombstone_delete_at > now_unix_s {
                transaction
                    .execute(
                        concat!(
                            "INSERT OR REPLACE INTO tombstones (run_digest, key_digest, ",
                            "delete_at, authority_generation, authority_manifest_digest) ",
                            "VALUES (?1, ?2, ?3, ?4, ?5)"
                        ),
                        params![
                            keyed_digest(&digest_key, &run_id),
                            keyed_digest(&digest_key, &key),
                            tombstone_delete_at,
                            i64::try_from(authority.generation)
                                .map_err(|_| ServiceError::Unavailable)?,
                            authority.manifest_digest
                        ],
                    )
                    .map_err(storage_error)?;
            }
            let active: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM cleanup_records WHERE run_id = ?1 AND active = 1)",
                    [&run_id],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let unresolved_finalized = active
                && pending_object.is_some()
                && transaction
                    .query_row(
                        concat!(
                            "SELECT EXISTS(SELECT 1 FROM cleanup_records JOIN application_reports ",
                            "ON application_reports.run_id = cleanup_records.run_id ",
                            "WHERE cleanup_records.run_id = ?1 AND cleanup_records.active = 1 ",
                            "AND cleanup_records.eligible = 0 ",
                            "AND application_reports.kind = 'finalized')"
                        ),
                        [&run_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(storage_error)?;
            if !unresolved_finalized {
                if let Some((digest, object_name)) = pending_object.as_ref() {
                    expired_objects.push((run_id.clone(), digest.clone(), object_name.clone()));
                }
            }
            if active {
                transaction
                    .execute(
                        concat!(
                            "UPDATE runs SET public_retained = 0, idempotency_key = ?2, ",
                            "receipt_available = 0, last_sequence = 0 WHERE run_id = ?1"
                        ),
                        params![run_id, keyed_digest(&digest_key, &key)],
                    )
                    .map_err(storage_error)?;
            } else {
                if execution_state != "queued" && !runner_retired && dispatch_runs.contains(&run_id)
                {
                    return Err(ServiceError::Unavailable);
                }
                self.authority
                    .remove_retired_dispatch(&run_id)
                    .map_err(|_| ServiceError::Unavailable)?;
                transaction
                    .execute("DELETE FROM cleanup_records WHERE run_id = ?1", [&run_id])
                    .map_err(storage_error)?;
                transaction
                    .execute(
                        "DELETE FROM provisioned_object_owners WHERE run_id = ?1",
                        [&run_id],
                    )
                    .map_err(storage_error)?;
                transaction
                    .execute("DELETE FROM runs WHERE run_id = ?1", [&run_id])
                    .map_err(storage_error)?;
            }
            transaction
                .execute("DELETE FROM events WHERE run_id = ?1", [&run_id])
                .map_err(storage_error)?;
            transaction
                .execute("DELETE FROM receipts WHERE run_id = ?1", [&run_id])
                .map_err(storage_error)?;
            if !unresolved_finalized {
                transaction
                    .execute(
                        "DELETE FROM receipt_publications WHERE run_id = ?1",
                        [&run_id],
                    )
                    .map_err(storage_error)?;
            }
        }
        barrier(ExpiryTransactionBarrier::BeforeCommit)?;
        transaction.commit().map_err(storage_error)?;
        barrier(ExpiryTransactionBarrier::AfterCommit)?;
        for (run_id, digest, object_name) in expired_objects {
            self.remove_receipt_object(&run_id, &digest, &object_name)?;
        }
        Ok(())
    }

    fn remove_receipt_object(
        &self,
        run_id: &str,
        digest: &str,
        object_name: &str,
    ) -> Result<(), ServiceError> {
        self.validate_pinned_paths()?;
        let expected = format!("sandbox-{run_id}-{digest}.receipt");
        if object_name != expected {
            return Err(ServiceError::Unavailable);
        }
        match fs::remove_file(self.receipt_directory.join(object_name)) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => return Err(ServiceError::Unavailable),
        }
        fs::File::open(&self.receipt_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ServiceError::Unavailable)
    }

    fn run_tombstoned(
        &self,
        connection: &Connection,
        run_id: &str,
        now_unix_s: i64,
    ) -> Result<bool, ServiceError> {
        let keyring = self
            .authority
            .tombstone_keyring()
            .map_err(|_| ServiceError::Unavailable)?;
        let first_key = keyring
            .entries
            .first()
            .ok_or(ServiceError::Unavailable)?
            .digest_key;
        let second_key = keyring
            .entries
            .get(1)
            .map_or(first_key, |entry| entry.digest_key);
        connection
            .query_row(
                concat!(
                    "SELECT EXISTS(SELECT 1 FROM tombstones WHERE run_digest IN (?1, ?2) ",
                    "AND delete_at > ?3)"
                ),
                params![
                    keyed_digest(&first_key, run_id),
                    keyed_digest(&second_key, run_id),
                    now_unix_s
                ],
                |row| row.get(0),
            )
            .map_err(storage_error)
    }
}

fn validate_tombstone_dependencies(
    connection: &Connection,
    keyring: &fixed_staging::TombstoneKeyring,
) -> Result<(), ServiceError> {
    let mut statement = connection
        .prepare(concat!(
            "SELECT authority_generation, authority_manifest_digest FROM tombstones UNION ",
            "SELECT authority_generation, authority_manifest_digest FROM runs ",
            "WHERE execution_state != 'queued' AND public_retained = 1"
        ))
        .map_err(storage_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?;
    for row in rows {
        let (generation, digest) = row.map_err(storage_error)?;
        let identity = stored_authority_identity(generation, digest)?;
        if keyring.key_for(&identity).is_none() {
            return Err(ServiceError::Unavailable);
        }
    }
    Ok(())
}

fn keyed_digest(key: &[u8; 32], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(key);
    digest.update(value.as_bytes());
    hex(&digest.finalize())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionBody {
    api_version: String,
    scenario: Scenario,
}

#[derive(Serialize)]
struct AdmissionJson<'a> {
    api_version: &'static str,
    run_id: &'a str,
    operation_id: &'a str,
    scenario: Scenario,
    admission_disposition: &'a str,
    admitted_at: String,
    expires_at: String,
    last_sequence: u8,
}

#[derive(Serialize)]
struct SnapshotJson<'a> {
    api_version: &'static str,
    run_id: &'a str,
    operation_id: &'a str,
    scenario: Scenario,
    execution_state: ExecutionState,
    receiver_result: &'a Option<String>,
    target_rejection: &'a Option<String>,
    receipt_available: bool,
    cleanup_state: CleanupState,
    admitted_at: String,
    expires_at: String,
    last_sequence: u8,
}

#[derive(Serialize)]
struct EventJson<'a> {
    sequence: u8,
    kind: &'a str,
    occurred_at: String,
    execution_state: ExecutionState,
    receiver_result: &'a Option<String>,
    target_rejection: &'a Option<String>,
    receipt_available: bool,
    cleanup_state: CleanupState,
}

#[derive(Serialize)]
struct EventPageJson<'a> {
    api_version: &'static str,
    run_id: &'a str,
    events: Vec<EventJson<'a>>,
    last_sequence: u8,
    next_after: u8,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    api_version: &'static str,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

fn validate_http_envelope(request: &Request<Vec<u8>>, origin: &str) -> Result<(), ServiceError> {
    let uri_length = request.uri().to_string().len();
    if uri_length > 512 || request.headers().len() > 16 || request.body().len() > 512 {
        return Err(ServiceError::InvalidRequest);
    }
    let mut names = HashSet::new();
    let mut aggregate_bytes = 0_usize;
    for (name, value) in request.headers() {
        aggregate_bytes = aggregate_bytes
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or(ServiceError::InvalidRequest)?;
        if value.as_bytes().len() > 256
            || aggregate_bytes > 8 * 1024
            || !names.insert(name.as_str())
        {
            return Err(ServiceError::InvalidRequest);
        }
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(ServiceError::InvalidRequest)?;
    let configured_host = origin
        .strip_prefix("https://")
        .ok_or(ServiceError::Unavailable)?;
    if host != configured_host || host.len() > 253 || !host.is_ascii() {
        return Err(ServiceError::InvalidRequest);
    }
    if let Some(value) = request.headers().get(header::ORIGIN) {
        if value.to_str().ok() != Some(origin) {
            return Err(ServiceError::InvalidRequest);
        }
    }
    if request
        .headers()
        .keys()
        .any(|name| untrusted_routing_header(name.as_str()))
    {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(())
}

fn untrusted_routing_header(name: &str) -> bool {
    FORBIDDEN_HEADERS.contains(&name)
        || name.contains("forwarded")
        || name.contains("client-cert")
        || name.contains("clientcert")
        || name.contains("trace")
        || name.starts_with("x-b3-")
        || name.starts_with("x-ot-")
        || name.starts_with("x-datadog-")
        || name.starts_with("x-cloud-trace-")
        || name.starts_with("x-envoy-")
        || matches!(
            name,
            "baggage"
                | "via"
                | "x-real-ip"
                | "true-client-ip"
                | "cf-connecting-ip"
                | "cf-ray"
                | "x-amzn-trace-id"
                | "uber-trace-id"
                | "grpc-trace-bin"
                | "x-request-id"
                | "x-correlation-id"
                | "request-id"
        )
}

fn validate_post_headers(request: &Request<Vec<u8>>) -> Result<(), ServiceError> {
    if request.body().is_empty()
        || request.body().len() > 512
        || request.headers().get(header::CONTENT_TYPE)
            != Some(&HeaderValue::from_static("application/json"))
    {
        return Err(ServiceError::InvalidRequest);
    }
    let length_text = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .ok_or(ServiceError::InvalidRequest)?;
    if length_text.is_empty()
        || !length_text.bytes().all(|byte| byte.is_ascii_digit())
        || (length_text.len() > 1 && length_text.starts_with('0'))
    {
        return Err(ServiceError::InvalidRequest);
    }
    let length = length_text
        .parse::<usize>()
        .map_err(|_| ServiceError::InvalidRequest)?;
    if length != request.body().len() || !request.headers().contains_key("idempotency-key") {
        return Err(ServiceError::InvalidRequest);
    }
    validate_accept(request, "application/json")
}

fn validate_get_headers(request: &Request<Vec<u8>>) -> Result<(), ServiceError> {
    if !request.body().is_empty()
        || request.headers().contains_key(header::CONTENT_TYPE)
        || request.headers().contains_key(header::CONTENT_LENGTH)
    {
        return Err(ServiceError::InvalidRequest);
    }
    let expected = if request.uri().path().ends_with("/receipt") {
        "application/vnd.kapsel.kap0038.receipt"
    } else {
        "application/json"
    };
    validate_accept(request, expected)
}

fn validate_accept(request: &Request<Vec<u8>>, expected: &str) -> Result<(), ServiceError> {
    match request.headers().get(header::ACCEPT) {
        Some(value) if value.to_str().ok() != Some(expected) => Err(ServiceError::InvalidRequest),
        _ => Ok(()),
    }
}

fn parse_event_query(query: Option<&str>) -> Result<(u8, u8), ServiceError> {
    let mut after = None;
    let mut limit = None;
    for pair in query.ok_or(ServiceError::InvalidRequest)?.split('&') {
        let (name, value) = pair.split_once('=').ok_or(ServiceError::InvalidRequest)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ServiceError::InvalidRequest);
        }
        match name {
            "after" if after.is_none() => after = value.parse::<u8>().ok(),
            "limit" if limit.is_none() => limit = value.parse::<u8>().ok(),
            _ => return Err(ServiceError::InvalidRequest),
        }
    }
    let after = after.ok_or(ServiceError::InvalidRequest)?;
    let limit = limit.ok_or(ServiceError::InvalidRequest)?;
    if after > 64 || !(1..=64).contains(&limit) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok((after, limit))
}

fn snapshot_json(snapshot: &Snapshot) -> Result<SnapshotJson<'_>, ServiceError> {
    Ok(SnapshotJson {
        api_version: "v1",
        run_id: &snapshot.run_id,
        operation_id: &snapshot.operation_id,
        scenario: snapshot.scenario,
        execution_state: snapshot.execution_state,
        receiver_result: &snapshot.receiver_result,
        target_rejection: &snapshot.target_rejection,
        receipt_available: snapshot.receipt_available,
        cleanup_state: snapshot.cleanup_state,
        admitted_at: timestamp(snapshot.admitted_at_unix_s)?,
        expires_at: timestamp(snapshot.expires_at_unix_s)?,
        last_sequence: snapshot.last_sequence,
    })
}

fn event_json(event: &Event) -> EventJson<'_> {
    EventJson {
        sequence: event.sequence,
        kind: &event.kind,
        occurred_at: timestamp(event.occurred_at_unix_s)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        execution_state: event.execution_state,
        receiver_result: &event.receiver_result,
        target_rejection: &event.target_rejection,
        receipt_available: event.receipt_available,
        cleanup_state: event.cleanup_state,
    }
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<Response<Vec<u8>>, ServiceError> {
    let bytes = serde_json::to_vec(body).map_err(|_| ServiceError::Unavailable)?;
    if bytes.len() > 64 * 1024 {
        return Err(ServiceError::Unavailable);
    }
    let mut response = Response::new(bytes);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn error_response(error: ServiceError) -> Response<Vec<u8>> {
    let (status, code, message, retryable) = match error {
        ServiceError::InvalidRequest
        | ServiceError::InvalidTransition
        | ServiceError::OwnershipMismatch
        | ServiceError::PolicyMismatch
        | ServiceError::LeaseBusy
        | ServiceError::DeadlineExceeded => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request is invalid.",
            false,
        ),
        ServiceError::UnsupportedVersion => (
            StatusCode::BAD_REQUEST,
            "unsupported_version",
            "The API version is unsupported.",
            false,
        ),
        ServiceError::RunNotFound => (
            StatusCode::NOT_FOUND,
            "run_not_found",
            "The run was not found.",
            false,
        ),
        ServiceError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "The idempotency key names another request.",
            false,
        ),
        ServiceError::ReceiptNotAvailable => (
            StatusCode::CONFLICT,
            "receipt_not_available",
            "The receipt is not available.",
            true,
        ),
        ServiceError::RunExpired => (
            StatusCode::GONE,
            "run_expired",
            "The run has expired.",
            false,
        ),
        ServiceError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "The anonymous request rate is limited.",
            true,
        ),
        ServiceError::CapacitySaturated | ServiceError::ActiveSaturated => (
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_saturated",
            "Sandbox capacity is temporarily saturated.",
            true,
        ),
        ServiceError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "The sandbox service is temporarily unavailable.",
            true,
        ),
    };
    let envelope = ErrorEnvelope {
        api_version: "v1",
        error: ErrorBody {
            code,
            message,
            retryable,
        },
    };
    let mut response =
        json_response(status, &envelope).unwrap_or_else(|_| Response::new(Vec::new()));
    if retryable {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    }
    response
}

fn timestamp(unix_s: i64) -> Result<String, ServiceError> {
    if unix_s < 0 {
        return Err(ServiceError::InvalidRequest);
    }
    let days = unix_s / 86_400;
    let seconds = unix_s % 86_400;
    let (year, month, day) = civil_date(days)?;
    if !(0..=9_999).contains(&year) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

fn civil_date(days_since_epoch: i64) -> Result<(i64, i64, i64), ServiceError> {
    let shifted = days_since_epoch
        .checked_add(719_468)
        .ok_or(ServiceError::InvalidRequest)?;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok((year, month, day))
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sandbox service failure: {self:?}")
    }
}

impl Error for ServiceError {}

/// Combined runner failure preserving the root application's typed error.
#[derive(Debug)]
pub enum RunError {
    /// Sandbox admission/projection failure.
    Service(ServiceError),
    /// KAP-0038 application-open failure without reinterpretation.
    Application(ApplicationError),
    /// Fixed private handoff or runner lifecycle failure without receiver reinterpretation.
    Handoff(HandoffError),
}

fn append_event(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    kind: &str,
    occurred_at: i64,
) -> Result<(), ServiceError> {
    let (last, state, result, rejection, receipt, cleanup): (
        i64,
        String,
        Option<String>,
        Option<String>,
        bool,
        String,
    ) = transaction
        .query_row(
            concat!(
                "SELECT last_sequence, execution_state, receiver_result, target_rejection, ",
                "receipt_available, cleanup_state FROM runs WHERE run_id = ?1"
            ),
            [run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?
        .ok_or(ServiceError::RunNotFound)?;
    if last >= EVENT_COUNT_MAX {
        return Err(ServiceError::Unavailable);
    }
    let previous_time: i64 = transaction
        .query_row(
            "SELECT occurred_at FROM events WHERE run_id = ?1 AND sequence = ?2",
            params![run_id, last],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if occurred_at < previous_time {
        return Err(ServiceError::InvalidTransition);
    }
    let sequence = last + 1;
    transaction
        .execute(
            "INSERT INTO events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                run_id,
                sequence,
                kind,
                occurred_at,
                state,
                result,
                rejection,
                receipt,
                cleanup
            ],
        )
        .map_err(storage_error)?;
    transaction
        .execute(
            "UPDATE runs SET last_sequence = ?2 WHERE run_id = ?1",
            params![run_id, sequence],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn admission_by_key(connection: &Connection, key: &str) -> Result<Option<Admission>, ServiceError> {
    connection
        .query_row(
            concat!(
                "SELECT run_id, operation_id, scenario, admitted_at, expires_at, last_sequence ",
                "FROM runs WHERE idempotency_key = ?1 AND public_retained = 1"
            ),
            [key],
            |row| {
                let scenario: String = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    scenario,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, u8>(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?
        .map(
            |(run_id, operation_id, scenario, admitted, expires, last)| {
                Ok(Admission {
                    run_id,
                    operation_id,
                    scenario: Scenario::parse(&scenario)?,
                    disposition: AdmissionDisposition::Created,
                    admitted_at_unix_s: admitted,
                    expires_at_unix_s: expires,
                    last_sequence: last,
                })
            },
        )
        .transpose()
}

fn load_snapshot(connection: &Connection, run_id: &str) -> Result<Option<Snapshot>, ServiceError> {
    connection
        .query_row(
            concat!(
                "SELECT operation_id, scenario, execution_state, receiver_result, ",
                "target_rejection, receipt_available, cleanup_state, admitted_at, expires_at, ",
                "last_sequence FROM runs WHERE run_id = ?1 AND public_retained = 1"
            ),
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, u8>(9)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?
        .map(|row| {
            Ok(Snapshot {
                run_id: run_id.to_owned(),
                operation_id: row.0,
                scenario: Scenario::parse(&row.1)?,
                execution_state: ExecutionState::parse(&row.2)?,
                receiver_result: row.3,
                target_rejection: row.4,
                receipt_available: row.5,
                cleanup_state: CleanupState::parse(&row.6)?,
                admitted_at_unix_s: row.7,
                expires_at_unix_s: row.8,
                last_sequence: row.9,
            })
        })
        .transpose()
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    let execution: String = row.get(3)?;
    let cleanup: String = row.get(7)?;
    Ok(Event {
        sequence: row.get(0)?,
        kind: row.get(1)?,
        occurred_at_unix_s: row.get(2)?,
        execution_state: ExecutionState::parse(&execution)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        receiver_result: row.get(4)?,
        target_rejection: row.get(5)?,
        receipt_available: row.get(6)?,
        cleanup_state: CleanupState::parse(&cleanup).map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn bounded_digest(value: &str) -> Result<(), ServiceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ServiceError::InvalidRequest)
    }
}

fn bounded_hex_128(value: &str) -> Result<(), ServiceError> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ServiceError::InvalidRequest)
    }
}

fn bounded_identity(value: &str) -> Result<(), ServiceError> {
    if (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(ServiceError::InvalidRequest)
    }
}

fn random_identity() -> Result<String, ServiceError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ServiceError::Unavailable)?;
    Ok(hex(&bytes))
}

fn random_credential() -> Result<[u8; 32], ServiceError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ServiceError::Unavailable)?;
    Ok(bytes)
}

fn observed_or_raw_digest(expected: &serde_json::Value, observed: &serde_json::Value) -> String {
    kubernetes_policy::observed_content_digest(expected, observed)
        .unwrap_or_else(|| kubernetes_policy::content_digest(observed))
}

fn selected_container_mutation<'a>(
    deployment: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Value, ServiceError> {
    let containers = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(serde_json::Value::as_array)
        .ok_or(ServiceError::PolicyMismatch)?;
    let mut selected = containers.iter().filter(|container| {
        container.get("name").and_then(serde_json::Value::as_str) == Some(name)
    });
    let container = selected.next().ok_or(ServiceError::PolicyMismatch)?;
    if selected.next().is_some() {
        return Err(ServiceError::PolicyMismatch);
    }
    Ok(container)
}

fn selected_container_mutation_mut<'a>(
    deployment: &'a mut serde_json::Value,
    name: &str,
) -> Result<&'a mut serde_json::Value, ServiceError> {
    let containers = deployment
        .pointer_mut("/spec/template/spec/containers")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or(ServiceError::PolicyMismatch)?;
    let index = containers
        .iter()
        .enumerate()
        .filter(|(_, container)| {
            container.get("name").and_then(serde_json::Value::as_str) == Some(name)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if index.len() != 1 {
        return Err(ServiceError::PolicyMismatch);
    }
    Ok(&mut containers[index[0]])
}

fn observed_policy_identity(body: &serde_json::Value) -> Option<String> {
    let kind = body.get("kind")?.as_str()?;
    let metadata = body.get("metadata")?.as_object()?;
    let name = metadata.get("name")?.as_str()?;
    if matches!(
        kind,
        "Namespace" | "RuntimeClass" | "ClusterRole" | "ClusterRoleBinding"
    ) {
        Some(format!("{kind}/{name}"))
    } else {
        let namespace = metadata.get("namespace")?.as_str()?;
        Some(format!("{kind}/{namespace}/{name}"))
    }
}

fn observed_policy_uid(body: &serde_json::Value) -> Result<String, ServiceError> {
    let uid = body
        .pointer("/metadata/uid")
        .and_then(serde_json::Value::as_str)
        .ok_or(ServiceError::OwnershipMismatch)?
        .to_owned();
    bounded_identity(&uid)?;
    Ok(uid)
}

fn observed_policy_owner(body: &serde_json::Value) -> Result<String, ServiceError> {
    let owner = body
        .pointer("/metadata/labels/kapsel.dev~1cleanup-owner")
        .and_then(serde_json::Value::as_str)
        .ok_or(ServiceError::OwnershipMismatch)?
        .to_owned();
    bounded_identity(&owner)?;
    Ok(owner)
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed derivation binds generated child identity, ancestry, template, and UID"
)]
fn derive_generated_children(
    children: &[ObservedPolicyObject],
    run_id: &str,
    cleanup_identity: &str,
    deployment_uid: &str,
    deployment_templates: &[&serde_json::Value],
    known_replica_set_uids: &HashSet<String>,
) -> Result<Vec<ProvisionedObject>, ServiceError> {
    if children.len() > 3 {
        return Err(ServiceError::PolicyMismatch);
    }
    let namespace = format!("sandbox-{run_id}");
    let mut replica_set_uids = known_replica_set_uids.clone();
    let mut replica_sets = 0_usize;
    let mut pods = 0_usize;
    for child in children {
        let kind = child.body.get("kind").and_then(serde_json::Value::as_str);
        if kind == Some("ReplicaSet") {
            replica_sets += 1;
            replica_set_uids.insert(observed_policy_uid(&child.body)?);
        } else if kind == Some("Pod") {
            pods += 1;
        } else {
            return Err(ServiceError::PolicyMismatch);
        }
    }
    if replica_sets > 2 || pods > 1 {
        return Err(ServiceError::PolicyMismatch);
    }
    let mut derived = Vec::with_capacity(children.len());
    let mut identities = HashSet::new();
    for child in children {
        let kind = child
            .body
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::PolicyMismatch)?;
        let api_version = child
            .body
            .get("apiVersion")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::PolicyMismatch)?;
        if (kind == "ReplicaSet" && api_version != "apps/v1")
            || (kind == "Pod" && api_version != "v1")
            || child
                .body
                .pointer("/metadata/namespace")
                .and_then(serde_json::Value::as_str)
                != Some(namespace.as_str())
            || observed_policy_owner(&child.body)? != cleanup_identity
            || child
                .body
                .pointer("/metadata/labels/kapsel.dev~1sandbox-run-id")
                .and_then(serde_json::Value::as_str)
                != Some(run_id)
            || child
                .body
                .pointer("/metadata/labels/kapsel.dev~1policy-revision")
                .and_then(serde_json::Value::as_str)
                != Some(kubernetes_policy::REVISION)
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        let owner_references = child
            .body
            .pointer("/metadata/ownerReferences")
            .and_then(serde_json::Value::as_array)
            .filter(|items| items.len() == 1)
            .ok_or(ServiceError::OwnershipMismatch)?;
        let owner = &owner_references[0];
        let owner_uid = owner
            .get("uid")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::OwnershipMismatch)?;
        let expected_owner = if kind == "ReplicaSet" {
            owner.get("kind").and_then(serde_json::Value::as_str) == Some("Deployment")
                && owner.get("name").and_then(serde_json::Value::as_str) == Some("sandbox-target")
                && owner_uid == deployment_uid
        } else {
            owner.get("kind").and_then(serde_json::Value::as_str) == Some("ReplicaSet")
                && replica_set_uids.contains(owner_uid)
        };
        if !expected_owner
            || owner.get("controller").and_then(serde_json::Value::as_bool) != Some(true)
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        let observed_template = if kind == "ReplicaSet" {
            child
                .body
                .pointer("/spec/template")
                .ok_or(ServiceError::PolicyMismatch)?
                .clone()
        } else {
            serde_json::json!({
                "metadata": {"labels": child.body.pointer("/metadata/labels")
                    .ok_or(ServiceError::PolicyMismatch)?},
                "spec": child.body.get("spec").ok_or(ServiceError::PolicyMismatch)?
            })
        };
        if !deployment_templates.iter().any(|template| {
            kubernetes_policy::observed_template_matches(template, &observed_template)
        }) {
            return Err(ServiceError::PolicyMismatch);
        }
        let identity = observed_policy_identity(&child.body).ok_or(ServiceError::PolicyMismatch)?;
        if !identities.insert(identity.clone()) {
            return Err(ServiceError::OwnershipMismatch);
        }
        let (_, _, name) = object_identity_parts(&identity)?;
        bounded_identity(&name)?;
        derived.push(ProvisionedObject {
            identity,
            uid: observed_policy_uid(&child.body)?,
            owner_label: cleanup_identity.to_owned(),
            content_digest: kubernetes_policy::content_digest(&child.body),
        });
    }
    derived.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(derived)
}

fn object_identity_parts(identity: &str) -> Result<(String, Option<String>, String), ServiceError> {
    let parts = identity.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["Namespace", name] if !name.is_empty() => {
            Ok(("Namespace".into(), None, (*name).to_owned()))
        },
        [kind, namespace, name]
            if !kind.is_empty() && !namespace.is_empty() && !name.is_empty() =>
        {
            Ok((
                (*kind).to_owned(),
                Some((*namespace).to_owned()),
                (*name).to_owned(),
            ))
        },
        _ => Err(ServiceError::Unavailable),
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn digest_identity_uids(entries: &[(String, String)]) -> Result<String, ServiceError> {
    let bytes = serde_json::to_vec(entries).map_err(|_| ServiceError::Unavailable)?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn close_provisioning(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    closure: &ProvisioningClosureEvidence,
) -> Result<(), ServiceError> {
    let retained: String = transaction
        .query_row(
            "SELECT boundary_uid_digest FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if !retained.is_empty() && retained != closure.boundary_uid_digest {
        return Err(ServiceError::PolicyMismatch);
    }
    if retained.is_empty() {
        transaction
            .execute(
                "UPDATE service_state SET boundary_uid_digest = ?1 WHERE singleton = 1",
                [&closure.boundary_uid_digest],
            )
            .map_err(storage_error)?;
    }
    let existing: (bool, String, String, String) = transaction
        .query_row(
            concat!(
                "SELECT provisioning_closed, deployment_uid, deployment_resource_version, ",
                "deployment_current_image FROM runs WHERE run_id = ?1"
            ),
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(storage_error)?;
    if existing.0 {
        if existing.1 != closure.deployment_uid
            || existing.2 != closure.deployment_resource_version
            || existing.3 != closure.deployment_current_image
        {
            return Err(ServiceError::PolicyMismatch);
        }
        return Ok(());
    }
    let changed = transaction
        .execute(
            concat!(
                "UPDATE runs SET provisioning_closed = 1, cleanup_epoch = ?2, ",
                "deployment_uid = ?3, deployment_resource_version = ?4, ",
                "deployment_current_image = ?5 WHERE run_id = ?1 AND application_invoked = 0 ",
                "AND provisioning_closed = 0"
            ),
            params![
                run_id,
                format!("cleanup-{run_id}-1"),
                closure.deployment_uid,
                closure.deployment_resource_version,
                closure.deployment_current_image
            ],
        )
        .map_err(storage_error)?;
    if changed != 1 {
        return Err(ServiceError::InvalidTransition);
    }
    Ok(())
}

fn policy_inventory(run_id: &str, selected_image: &str) -> Result<(String, String), ServiceError> {
    let inventory = kubernetes_policy::render(run_id, selected_image)
        .map_err(|_| ServiceError::PolicyMismatch)?
        .into_iter()
        .map(|object| PolicyObjectRequirement {
            identity: object.identity,
            content_digest: kubernetes_policy::content_digest(&object.body),
            canonical_body: object.body,
        })
        .collect::<Vec<_>>();
    let canonical = serde_json::to_string(&inventory).map_err(|_| ServiceError::Unavailable)?;
    let digest = policy_binding_digest(kubernetes_policy::REVISION, &canonical);
    Ok((canonical, digest))
}

fn scenario_image(scenario: Scenario) -> &'static str {
    match scenario {
        Scenario::Healthy => concat!(
            "registry.k8s.io/pause@sha256:",
            "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
        ),
        Scenario::UnavailableImage => concat!(
            "registry.k8s.io/pause@sha256:",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    }
}

fn policy_binding_digest(revision: &str, canonical_inventory: &str) -> String {
    let canonical = serde_json::from_str::<Vec<PolicyObjectRequirement>>(canonical_inventory)
        .map(|inventory| {
            inventory
                .into_iter()
                .map(|object| {
                    let mut body = object.canonical_body;
                    if body.get("kind").and_then(serde_json::Value::as_str) == Some("Deployment") {
                        if let Some(annotations) = body
                            .pointer_mut("/metadata/annotations")
                            .and_then(serde_json::Value::as_object_mut)
                        {
                            annotations.remove("kapsel.dev/policy-inventory-digest");
                            annotations.remove("kapsel.dev/canonical-deployment-digest");
                        }
                    }
                    serde_json::json!({"identity": object.identity, "canonical_body": body})
                })
                .collect::<Vec<_>>()
        })
        .and_then(|inventory| serde_json::to_string(&inventory))
        .unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(revision.as_bytes());
    digest.update([0]);
    digest.update(canonical.as_bytes());
    hex(&digest.finalize())
}

fn lease_expiry(now_unix_s: i64, deadline_at: i64) -> Result<i64, ServiceError> {
    let ordinary_expiry = now_unix_s
        .checked_add(SCHEDULER_LEASE_SECONDS)
        .ok_or(ServiceError::DeadlineExceeded)?;
    let expiry = ordinary_expiry.min(deadline_at);
    if expiry <= now_unix_s {
        Err(ServiceError::DeadlineExceeded)
    } else {
        Ok(expiry)
    }
}

fn recovery_lease_expiry(now_unix_s: i64) -> Result<i64, ServiceError> {
    now_unix_s
        .checked_add(SCHEDULER_LEASE_SECONDS)
        .ok_or(ServiceError::Unavailable)
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn prepare_database_file(path: &Path) -> Result<(), ServiceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_database_file(path)?;
            Ok(())
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| ServiceError::Unavailable)?;
            file.sync_all().map_err(|_| ServiceError::Unavailable)?;
            validate_database_file(path)?;
            Ok(())
        },
        Err(_) => Err(ServiceError::Unavailable),
    }
}

fn validate_database_file(path: &Path) -> Result<(u64, u64), ServiceError> {
    validate_database_file_mode(path, 0o600)
}

fn validate_database_file_mode(
    path: &Path,
    expected_mode: u32,
) -> Result<(u64, u64), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Unavailable)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || mode != expected_mode
    {
        return Err(ServiceError::Unavailable);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn validate_pinned_state(
    database_path: &Path,
    receipt_directory: &Path,
    pinned: &PinnedServiceState,
) -> Result<(), ServiceError> {
    let state_path = database_path.parent().ok_or(ServiceError::Unavailable)?;
    if receipt_directory.parent() != Some(state_path)
        || receipt_directory.file_name() != Some(std::ffi::OsStr::new("receipts"))
        || database_path.file_name() != Some(std::ffi::OsStr::new("sandbox.sqlite3"))
    {
        return Err(ServiceError::Unavailable);
    }
    let path_identity = |path: &Path, directory: bool| {
        let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Unavailable)?;
        if (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(ServiceError::Unavailable);
        }
        Ok((metadata.dev(), metadata.ino()))
    };
    let descriptor_identity = |file: &fs::File, directory: bool| {
        let metadata = file.metadata().map_err(|_| ServiceError::Unavailable)?;
        if (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(ServiceError::Unavailable);
        }
        Ok((metadata.dev(), metadata.ino()))
    };
    if path_identity(state_path, true)? != descriptor_identity(&pinned.state_directory, true)?
        || path_identity(database_path, false)? != descriptor_identity(&pinned.database, false)?
        || path_identity(receipt_directory, true)? != descriptor_identity(&pinned.receipts, true)?
    {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Unavailable)?;
    let owner_matches = metadata.uid() == rustix::process::geteuid().as_raw();
    let private_mode = metadata.permissions().mode().trailing_zeros() >= 6;
    if metadata.file_type().is_dir() && owner_matches && private_mode {
        Ok(())
    } else {
        Err(ServiceError::Unavailable)
    }
}

fn pending_authority_collection(
    database_path: &Path,
) -> Result<Option<GenerationIdentity>, ServiceError> {
    if !database_path.exists() {
        return Ok(None);
    }
    let connection = open_database_connection(database_path)?;
    let table_exists: bool = connection
        .query_row(
            concat!(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' ",
                "AND name = 'authority_collection')"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if !table_exists {
        return Ok(None);
    }
    let mut columns = connection
        .prepare("PRAGMA table_info(authority_collection)")
        .map_err(storage_error)?;
    let columns = columns
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let expected = vec![
        ("singleton".into(), "INTEGER".into(), 0, 1),
        ("generation".into(), "INTEGER".into(), 1, 0),
        ("manifest_digest".into(), "TEXT".into(), 1, 0),
    ];
    if columns != expected {
        return Err(ServiceError::Unavailable);
    }
    let mut rows = connection
        .prepare(concat!(
            "SELECT singleton, typeof(singleton), generation, typeof(generation), ",
            "manifest_digest, typeof(manifest_digest) FROM authority_collection"
        ))
        .map_err(storage_error)?;
    let rows = rows
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    match rows.as_slice() {
        [] => Ok(None),
        [(1, singleton_type, generation, generation_type, digest, digest_type)]
            if singleton_type == "integer"
                && generation_type == "integer"
                && digest_type == "text" =>
        {
            stored_authority_identity(Some(*generation), digest.clone()).map(Some)
        },
        _ => Err(ServiceError::Unavailable),
    }
}

fn open_database_connection(database_path: &Path) -> Result<Connection, ServiceError> {
    let before = validate_database_file(database_path)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(database_path, flags).map_err(storage_error)?;
    let after = validate_database_file(database_path)?;
    if before != after {
        return Err(ServiceError::Unavailable);
    }
    connection
        .execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")
        .map_err(storage_error)?;
    Ok(connection)
}

fn commit_global_stop(connection: &Connection, stopped: bool) -> Result<(), ServiceError> {
    let changed = connection
        .execute(
            "UPDATE service_state SET stopped = ?1 WHERE singleton = 1",
            [stopped],
        )
        .map_err(storage_error)?;
    if changed != 1 {
        return Err(ServiceError::Unavailable);
    }
    let committed: bool = connection
        .query_row(
            "SELECT stopped FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if committed != stopped {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn validate_serial_capacity(connection: &Connection) -> Result<(), ServiceError> {
    let invalid: i64 = connection
        .query_row(
            concat!(
                "SELECT (SELECT COUNT(*) FROM runs WHERE active NOT IN (0, 1)) + ",
                "(SELECT COUNT(*) FROM cleanup_records WHERE active NOT IN (0, 1)) + ",
                "(SELECT COUNT(*) FROM cleanup_records LEFT JOIN runs ",
                "ON runs.run_id = cleanup_records.run_id WHERE runs.run_id IS NULL) + ",
                "(SELECT COUNT(*) FROM runs LEFT JOIN cleanup_records ",
                "ON cleanup_records.run_id = runs.run_id WHERE cleanup_records.run_id IS NULL ",
                "AND NOT (runs.active = 0 AND runs.cleanup_state = 'succeeded' ",
                "AND runs.execution_state IN ('not_attempted', 'service_failed', 'terminal'))) + ",
                "(SELECT COUNT(*) FROM runs JOIN cleanup_records ",
                "ON cleanup_records.run_id = runs.run_id ",
                "WHERE runs.active != cleanup_records.active) + ",
                "(SELECT CASE WHEN COUNT(*) > ?1 THEN 1 ELSE 0 END FROM runs WHERE active = 1) + ",
                "(SELECT CASE WHEN COUNT(*) > ?1 THEN 1 ELSE 0 END FROM cleanup_records ",
                "WHERE active = 1)"
            ),
            [ACTIVE_RUNS_MAX],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if invalid != 0 {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn migrate_service_state_columns(connection: &Connection) -> Result<(), ServiceError> {
    let has_boundary_uid_digest = {
        let mut statement = connection
            .prepare("PRAGMA table_info(service_state)")
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
            .iter()
            .any(|name| name == "boundary_uid_digest")
    };
    if !has_boundary_uid_digest {
        connection
            .execute(
                "ALTER TABLE service_state ADD COLUMN boundary_uid_digest TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn migrate_slice3_run_columns(connection: &Connection) -> Result<(), ServiceError> {
    let columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(runs)")
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?;
        rows.collect::<Result<HashSet<_>, _>>()
            .map_err(storage_error)?
    };
    for (name, declaration) in [
        ("provisioning_closed", "INTEGER NOT NULL DEFAULT 0"),
        ("deployment_uid", "TEXT NOT NULL DEFAULT ''"),
        ("deployment_resource_version", "TEXT NOT NULL DEFAULT ''"),
        ("deployment_current_image", "TEXT NOT NULL DEFAULT ''"),
        ("cleanup_epoch", "TEXT NOT NULL DEFAULT ''"),
        ("runner_revoked", "INTEGER NOT NULL DEFAULT 0"),
        ("runner_process_absent", "INTEGER NOT NULL DEFAULT 0"),
        ("journal_handoff", "INTEGER NOT NULL DEFAULT 0"),
        ("runner_state_retiring", "INTEGER NOT NULL DEFAULT 0"),
        ("runner_state_retired", "INTEGER NOT NULL DEFAULT 0"),
        ("cleanup_attempt", "INTEGER NOT NULL DEFAULT 0"),
        ("cleanup_plan_digest", "TEXT NOT NULL DEFAULT ''"),
        ("cleanup_plan_issued", "INTEGER NOT NULL DEFAULT 0"),
        ("cleanup_pending_observation_id", "TEXT NOT NULL DEFAULT ''"),
        ("cleanup_observation_id", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !columns.contains(name) {
            connection
                .execute(
                    &format!("ALTER TABLE runs ADD COLUMN {name} {declaration}"),
                    [],
                )
                .map_err(storage_error)?;
        }
    }
    Ok(())
}

fn guarded_immediate_transaction(
    connection: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, ServiceError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    validate_authority_pins(&transaction)?;
    Ok(transaction)
}

fn validate_authority_identity(identity: &GenerationIdentity) -> Result<(), ServiceError> {
    if identity.generation == 0
        || identity.manifest_digest.len() != 64
        || !identity
            .manifest_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_exact_service_schema(connection: &Connection) -> Result<(), ServiceError> {
    fn signature(
        connection: &Connection,
    ) -> Result<Vec<(String, String, String, String)>, ServiceError> {
        connection
            .prepare(concat!(
                "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ",
                "ORDER BY type, name, tbl_name, sql"
            ))
            .map_err(storage_error)?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)
    }

    let expected = Connection::open_in_memory().map_err(storage_error)?;
    for ddl in service_schema::TABLES_BY_NAME {
        expected.execute_batch(ddl).map_err(storage_error)?;
    }
    if signature(connection)? == signature(&expected)? {
        Ok(())
    } else {
        Err(ServiceError::Unavailable)
    }
}

fn validate_migration_schema(
    connection: &Connection,
    includes_backup: bool,
) -> Result<(), ServiceError> {
    fn signature(connection: &Connection) -> Result<Vec<(String, Vec<String>)>, ServiceError> {
        let mut tables = connection
            .prepare(concat!(
                "SELECT name FROM sqlite_master WHERE type = 'table' ",
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ))
            .map_err(storage_error)?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        tables.sort();
        let mut output = Vec::with_capacity(tables.len());
        for table in tables {
            let columns = connection
                .prepare(&format!("PRAGMA table_info('{table}')"))
                .map_err(storage_error)?
                .query_map([], |row| {
                    Ok(format!(
                        "{}|{}|{}|{}|{}",
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        row.get::<_, i64>(5)?
                    ))
                })
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)?;
            output.push((table, columns));
        }
        Ok(output)
    }

    let expected = Connection::open_in_memory().map_err(storage_error)?;
    for ddl in service_schema::TABLES_BY_NAME {
        let backup = ddl == service_schema::BACKUP_GENERATIONS
            || ddl == service_schema::BACKUP_AUTHORITY_REFERENCES;
        if includes_backup || !backup {
            expected.execute_batch(ddl).map_err(storage_error)?;
        }
    }
    if signature(connection)? == signature(&expected)? {
        Ok(())
    } else {
        Err(ServiceError::Unavailable)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed two-table backup storage and transition preflight stays visibly atomic"
)]
fn preflight_backup_schema(connection: &Connection) -> Result<(), ServiceError> {
    let table_count: i64 = connection
        .query_row(
            concat!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ",
                "('backup_generations', 'backup_authority_references')"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if table_count == 0 {
        return Ok(());
    }
    if table_count != 2 {
        return Err(ServiceError::Unavailable);
    }

    let mut statement = connection
        .prepare(concat!(
            "SELECT slot, generation, manifest_digest, state, captured_at, ",
            "typeof(generation), typeof(manifest_digest), typeof(captured_at) ",
            "FROM backup_generations ORDER BY slot"
        ))
        .map_err(storage_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(storage_error)?;
    let mut generations = Vec::new();
    for row in rows {
        let (slot, generation, digest, state, captured_at, gen_type, digest_type, time_type) =
            row.map_err(storage_error)?;
        let valid_digest = match (&*slot, digest.as_deref(), digest_type.as_str()) {
            ("pending", None, "null") => true,
            ("current" | "deleting", Some(value), "text") => valid_sha256(value),
            _ => false,
        };
        if !matches!(slot.as_str(), "pending" | "current" | "deleting")
            || state != slot
            || generation <= 0
            || captured_at <= 0
            || gen_type != "integer"
            || time_type != "integer"
            || !valid_digest
        {
            return Err(ServiceError::Unavailable);
        }
        generations.push((slot, generation));
    }
    if generations.len() > 3 {
        return Err(ServiceError::Unavailable);
    }
    let generation_for = |slot: &str| {
        generations
            .iter()
            .find_map(|(candidate, generation)| (candidate == slot).then_some(*generation))
    };
    let pending = generation_for("pending");
    let current = generation_for("current");
    let deleting = generation_for("deleting");
    let valid_state = match (pending, current, deleting) {
        (None | Some(1), None, None) | (None, Some(_), None) => true,
        (Some(next), Some(previous), None) | (None, Some(next), Some(previous)) => {
            previous.checked_add(1) == Some(next)
        },
        _ => false,
    };
    if !valid_state {
        return Err(ServiceError::Unavailable);
    }

    let mut statement = connection
        .prepare(concat!(
            "SELECT slot, authority_generation, authority_manifest_digest, ",
            "typeof(authority_generation), typeof(authority_manifest_digest) ",
            "FROM backup_authority_references ORDER BY slot, authority_generation"
        ))
        .map_err(storage_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(storage_error)?;
    let mut reference_counts = [("pending", 0_u8), ("current", 0), ("deleting", 0)];
    for row in rows {
        let (slot, generation, digest, generation_type, digest_type) =
            row.map_err(storage_error)?;
        let Some((_, count)) = reference_counts
            .iter_mut()
            .find(|(candidate, _)| *candidate == slot)
        else {
            return Err(ServiceError::Unavailable);
        };
        *count = count.checked_add(1).ok_or(ServiceError::Unavailable)?;
        if *count > 2
            || generation <= 0
            || generation_type != "integer"
            || digest_type != "text"
            || !valid_sha256(&digest)
            || generation_for(&slot).is_none()
        {
            return Err(ServiceError::Unavailable);
        }
    }
    Ok(())
}

fn backup_references_for_slot(
    connection: &Connection,
    slot: &str,
) -> Result<Vec<GenerationIdentity>, ServiceError> {
    if !matches!(slot, "pending" | "current" | "deleting") {
        return Err(ServiceError::Unavailable);
    }
    let mut statement = connection
        .prepare(concat!(
            "SELECT authority_generation, authority_manifest_digest FROM ",
            "backup_authority_references WHERE slot = ?1 ORDER BY authority_generation"
        ))
        .map_err(storage_error)?;
    let rows = statement
        .query_map([slot], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?;
    let mut identities = Vec::new();
    for row in rows {
        let (generation, digest) = row.map_err(storage_error)?;
        identities.push(stored_authority_identity(Some(generation), digest)?);
    }
    if identities.len() > 2 {
        return Err(ServiceError::Unavailable);
    }
    Ok(identities)
}

fn backup_authority_references(
    transaction: &Connection,
    authority: &fixed_staging::FixedStagingReader,
) -> Result<Vec<GenerationIdentity>, ServiceError> {
    let current = authority
        .current_identity()
        .map_err(|_| ServiceError::Unavailable)?;
    let noncurrent = authority
        .noncurrent_identity()
        .map_err(|_| ServiceError::Unavailable)?;
    let mut statement = transaction
        .prepare(concat!(
            "SELECT authority_generation, authority_manifest_digest FROM runs ",
            "WHERE authority_generation IS NOT NULL UNION SELECT authority_generation, ",
            "authority_manifest_digest FROM tombstones ORDER BY authority_generation"
        ))
        .map_err(storage_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?;
    let mut identities = Vec::new();
    for row in rows {
        let (generation, digest) = row.map_err(storage_error)?;
        let identity = stored_authority_identity(generation, digest)?;
        if identity != current && noncurrent.as_ref() != Some(&identity) {
            return Err(ServiceError::Unavailable);
        }
        if identities.last() != Some(&identity) {
            identities.push(identity);
        }
    }
    if identities.len() > 2 {
        return Err(ServiceError::Unavailable);
    }
    Ok(identities)
}

fn stored_authority_identity(
    generation: Option<i64>,
    manifest_digest: String,
) -> Result<GenerationIdentity, ServiceError> {
    let generation = generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ServiceError::Unavailable)?;
    let identity = GenerationIdentity {
        generation,
        manifest_digest,
    };
    validate_authority_identity(&identity)?;
    Ok(identity)
}

fn preflight_existing_authority_schema(connection: &Connection) -> Result<(), ServiceError> {
    let core_tables: i64 = connection
        .query_row(
            concat!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' ",
                "AND name IN ('service_state', 'runs', 'tombstones')"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if core_tables == 0 {
        return Ok(());
    }
    if core_tables != 3 {
        return Err(ServiceError::Unavailable);
    }
    let table_columns = |table: &str| -> Result<HashSet<String>, ServiceError> {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?;
        rows.collect::<Result<HashSet<_>, _>>()
            .map_err(storage_error)
    };
    let run_columns = table_columns("runs")?;
    let tombstone_columns = table_columns("tombstones")?;
    let authority_column_count = [
        run_columns.contains("authority_generation"),
        run_columns.contains("authority_manifest_digest"),
        tombstone_columns.contains("authority_generation"),
        tombstone_columns.contains("authority_manifest_digest"),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if authority_column_count == 4 {
        return validate_authority_pins(connection);
    }
    if authority_column_count != 0 {
        return Err(ServiceError::Unavailable);
    }
    let stopped: bool = connection
        .query_row(
            "SELECT stopped FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    let non_drained: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM runs) + (SELECT COUNT(*) FROM tombstones)",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if stopped && non_drained == 0 {
        Ok(())
    } else {
        Err(ServiceError::Unavailable)
    }
}

fn migrate_authority_columns(connection: &mut Connection) -> Result<(), ServiceError> {
    let table_columns = |table: &str| -> Result<HashSet<String>, ServiceError> {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?;
        rows.collect::<Result<HashSet<_>, _>>()
            .map_err(storage_error)
    };
    let run_columns = table_columns("runs")?;
    let tombstone_columns = table_columns("tombstones")?;
    let authority_column_count = [
        run_columns.contains("authority_generation"),
        run_columns.contains("authority_manifest_digest"),
        tombstone_columns.contains("authority_generation"),
        tombstone_columns.contains("authority_manifest_digest"),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if authority_column_count == 4 {
        return Ok(());
    }
    if authority_column_count != 0 {
        return Err(ServiceError::Unavailable);
    }
    let stopped: bool = connection
        .query_row(
            "SELECT stopped FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    let non_drained: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM runs) + (SELECT COUNT(*) FROM tombstones)",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if !stopped || non_drained != 0 {
        return Err(ServiceError::Unavailable);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    if !run_columns.contains("authority_generation") {
        transaction
            .execute(
                "ALTER TABLE runs ADD COLUMN authority_generation INTEGER",
                [],
            )
            .map_err(storage_error)?;
    }
    if !run_columns.contains("authority_manifest_digest") {
        transaction
            .execute(
                "ALTER TABLE runs ADD COLUMN authority_manifest_digest TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(storage_error)?;
    }
    if !tombstone_columns.contains("authority_generation") {
        transaction
            .execute(
                concat!(
                    "ALTER TABLE tombstones ADD COLUMN authority_generation ",
                    "INTEGER NOT NULL DEFAULT 0"
                ),
                [],
            )
            .map_err(storage_error)?;
    }
    if !tombstone_columns.contains("authority_manifest_digest") {
        transaction
            .execute(
                concat!(
                    "ALTER TABLE tombstones ADD COLUMN authority_manifest_digest ",
                    "TEXT NOT NULL DEFAULT ''"
                ),
                [],
            )
            .map_err(storage_error)?;
    }
    transaction.commit().map_err(storage_error)
}

fn validate_authority_pins(connection: &Connection) -> Result<(), ServiceError> {
    let invalid_runs: i64 = connection
        .query_row(
            concat!(
                "SELECT COUNT(*) FROM runs WHERE ",
                "(execution_state = 'queued' AND (authority_generation IS NOT NULL OR ",
                "typeof(authority_manifest_digest) != 'text' OR authority_manifest_digest != '')) ",
                "OR (execution_state != 'queued' AND (typeof(authority_generation) != 'integer' ",
                "OR authority_generation <= 0 OR typeof(authority_manifest_digest) != 'text' OR ",
                "length(authority_manifest_digest) != 64 OR ",
                "authority_manifest_digest GLOB '*[^0-9a-f]*'))"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    let invalid_tombstones: i64 = connection
        .query_row(
            concat!(
                "SELECT COUNT(*) FROM tombstones WHERE ",
                "typeof(authority_generation) != 'integer' OR authority_generation <= 0 OR ",
                "typeof(authority_manifest_digest) != 'text' OR ",
                "length(authority_manifest_digest) != 64 OR ",
                "authority_manifest_digest GLOB '*[^0-9a-f]*'"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if invalid_runs != 0 || invalid_tombstones != 0 {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn migrate_cleanup_columns(connection: &Connection) -> Result<(), ServiceError> {
    let columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(cleanup_records)")
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?;
        rows.collect::<Result<HashSet<_>, _>>()
            .map_err(storage_error)?
    };
    if !columns.contains("started_at") {
        connection
            .execute(
                "ALTER TABLE cleanup_records ADD COLUMN started_at INTEGER",
                [],
            )
            .map_err(storage_error)?;
    }
    if !columns.contains("escalated") {
        connection
            .execute(
                "ALTER TABLE cleanup_records ADD COLUMN escalated INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(storage_error)?;
    }
    connection
        .execute(
            concat!(
                "UPDATE cleanup_records SET started_at = COALESCE((SELECT MIN(occurred_at) ",
                "FROM events WHERE events.run_id = cleanup_records.run_id ",
                "AND events.kind = 'cleanup.started'), 0) WHERE started_at IS NULL ",
                "AND state IN ('running', 'failed')"
            ),
            [],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn storage_error(_: rusqlite::Error) -> ServiceError {
    ServiceError::Unavailable
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "controlled fixture failures must stop the invariant test"
    )]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn receipt_install_is_exact_immutable_restart_safe_and_expiring() {
        let root =
            std::env::temp_dir().join(format!("kapsel-sandbox-receipt-{}", std::process::id()));
        if root.exists() {
            crate::test_authority::remove_root(&root);
        }
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("sandbox.sqlite3");
        let service = Service::open_for_test(&database, &receipts, [9; 32], 1_774_051_200).unwrap();
        let admission = service
            .admit_with_run_id(
                "00000000000000000000000000000001",
                Scenario::Healthy,
                1_774_051_200,
                "0123456789abcdef0123456789abcdef",
            )
            .unwrap();
        service
            .dispatch_next(
                1_774_051_201,
                &GenerationIdentity::new(1, test_authority::manifest_digest([9; 32])).unwrap(),
            )
            .unwrap();
        service
            .terminal_transition(
                &admission.run_id,
                ExecutionState::Terminal,
                Some("SUCCEEDED"),
                None,
                "execution.terminal",
                1_774_051_202,
            )
            .unwrap();
        let receipt_hex =
            include_str!("../../../docs/fixtures/sandbox-v1/unavailable-image.receipt.hex").trim();
        let bytes = receipt_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect::<Vec<_>>();
        let digest = hex(&Sha256::digest(&bytes));
        service
            .install_receipt(&admission.run_id, &bytes, &digest, 1_774_051_203)
            .unwrap();
        service
            .install_receipt(&admission.run_id, &bytes, &digest, 1_774_051_204)
            .unwrap();
        assert_eq!(
            service.install_receipt(
                &admission.run_id,
                b"replacement",
                &hex(&Sha256::digest(b"replacement")),
                1_774_051_204
            ),
            Err(ServiceError::Unavailable)
        );
        drop(service);

        let service = Service::open_for_test(&database, &receipts, [9; 32], 1_774_051_205).unwrap();
        assert_eq!(
            service.receipt(&admission.run_id, 1_774_051_205).unwrap(),
            bytes
        );
        assert_eq!(
            service.receipt(&admission.run_id, 1_774_137_600),
            Err(ServiceError::RunExpired)
        );
        crate::test_authority::remove_root(&root);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one invariant test holds the exact publication/collector interleaving together"
    )]
    fn concurrent_collector_preserves_pending_publication_and_collects_stale_owner() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-sandbox-receipt-publication-{}",
            std::process::id()
        ));
        if root.exists() {
            crate::test_authority::remove_root(&root);
        }
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("sandbox.sqlite3");
        let service = Service::open_for_test(&database, &receipts, [9; 32], 1_774_051_200).unwrap();
        let admission = service
            .admit_with_run_id(
                "00000000000000000000000000000002",
                Scenario::Healthy,
                1_774_051_200,
                "1123456789abcdef0123456789abcdef",
            )
            .unwrap();
        service
            .dispatch_next(
                1_774_051_201,
                &GenerationIdentity::new(1, test_authority::manifest_digest([9; 32])).unwrap(),
            )
            .unwrap();
        service
            .terminal_transition(
                &admission.run_id,
                ExecutionState::Terminal,
                Some("SUCCEEDED"),
                None,
                "execution.terminal",
                1_774_051_202,
            )
            .unwrap();
        let bytes = b"exact pending receipt bytes";
        let digest = hex(&Sha256::digest(bytes));
        let object_name = format!("sandbox-{}-{digest}.receipt", admission.run_id);
        assert!(service
            .claim_receipt_publication(
                &admission.run_id,
                bytes,
                &digest,
                &object_name,
                1_774_051_203,
            )
            .unwrap());
        Service::open_for_test(&database, &receipts, [9; 32], 1_774_051_203).unwrap();
        assert!(!receipts.join(&object_name).exists());
        let pending_before_install: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_before_install, 1);
        service.install_receipt_object(&object_name, bytes).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let collector_barrier = std::sync::Arc::clone(&barrier);
        let collector_database = database.clone();
        let collector_receipts = receipts.clone();
        let collector = std::thread::spawn(move || {
            collector_barrier.wait();
            Service::open_for_test(
                collector_database,
                collector_receipts,
                [9; 32],
                1_774_051_203,
            )
            .unwrap();
        });
        barrier.wait();
        collector.join().unwrap();
        assert_eq!(fs::read(receipts.join(&object_name)).unwrap(), bytes);
        let pending: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        service
            .complete_receipt_publication(
                &admission.run_id,
                bytes,
                &digest,
                &object_name,
                1_774_051_204,
            )
            .unwrap();
        assert_eq!(
            service.receipt(&admission.run_id, 1_774_051_204).unwrap(),
            bytes
        );
        let completed_pending: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(completed_pending, 0);

        let stale_run = "ffffffffffffffffffffffffffffffff";
        let stale_bytes = b"stale pending bytes";
        let stale_digest = hex(&Sha256::digest(stale_bytes));
        let stale_name = format!("sandbox-{stale_run}-{stale_digest}.receipt");
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute(
                "INSERT INTO receipt_publications VALUES (?1, ?2, ?3, ?4)",
                params![stale_run, stale_digest, stale_name, 1_774_051_100_i64],
            )
            .unwrap();
        service
            .install_receipt_object(&stale_name, stale_bytes)
            .unwrap();
        Service::open_for_test(&database, &receipts, [9; 32], 1_774_051_204).unwrap();
        assert!(!receipts.join(&stale_name).exists());
        let stale_pending: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [stale_run],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale_pending, 0);
        crate::test_authority::remove_root(&root);
    }
}
