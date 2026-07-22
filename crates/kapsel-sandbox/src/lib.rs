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
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use http::{
    header::{self, HeaderValue},
    Method, Request, Response, StatusCode,
};

use kapsel::{
    AgentRequest, Application, ApplicationError, OperationReport, OperationResult, OperationState,
    OperatorConfiguration, TargetRejection,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const QUEUED_RUNS_MAX: i64 = 32;
const ACTIVE_RUNS_MAX: i64 = 8;
const EVENT_COUNT_MAX: i64 = 64;
const PUBLIC_RETENTION_SECONDS: i64 = 86_400;
const SANDBOX_DEADLINE_SECONDS: i64 = 180;
const SCHEDULER_LEASE_SECONDS: i64 = 30;
const DEPLOYMENT_POLICY_REVISION: &str = "sandbox-policy-v1";
const POLICY_NAMESPACE_TOKEN: &str = "{namespace}";
const POLICY_OBJECTS_V1: [(&str, &str); 10] = [
    (
        "Namespace/{namespace}",
        "pod-security=restricted;owner-label=required",
    ),
    (
        "ServiceAccount/{namespace}/sandbox-runner",
        "automount-service-account-token=false",
    ),
    (
        "Role/{namespace}/sandbox-runner",
        "verbs=get,list,watch,patch;resources=deployments",
    ),
    (
        "RoleBinding/{namespace}/sandbox-runner",
        "subject=server-owned-service-account",
    ),
    (
        "ResourceQuota/{namespace}/sandbox-quota",
        "pods=1;services=1;cpu=500m;memory=256Mi",
    ),
    (
        "LimitRange/{namespace}/sandbox-limits",
        "cpu=500m;memory=256Mi;ephemeral-storage=256Mi",
    ),
    (
        "NetworkPolicy/{namespace}/default-deny",
        "ingress=deny-all;egress=deny-all",
    ),
    (
        "NetworkPolicy/{namespace}/fixed-egress",
        "egress=dns,kubernetes-api,fixed-registry;selectors=exact",
    ),
    (
        "Deployment/{namespace}/sandbox-target",
        "replicas=1;service-account=server-owned;scenario=fixed",
    ),
    (
        "Service/{namespace}/sandbox-target",
        "selector=server-owned-target;ports=fixed",
    ),
];
const RECEIPT_BYTES_MAX: usize = 16 * 1024;
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchLease {
    /// Public run identity whose active reservation is leased.
    pub run_id: String,
    /// Opaque private lease identity generated by the service.
    lease_id: String,
    /// Monotonic lease generation for restart recovery.
    epoch: i64,
    /// Absolute whole-second lease expiry.
    expires_at_unix_s: i64,
}

/// One exact policy object frozen at admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyObjectRequirement {
    /// Canonical kind/name identity within the per-run namespace.
    pub identity: String,
    /// SHA-256 digest of the revision-owned canonical policy content.
    pub content_digest: String,
}

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
    /// One observation for every append-only recorded provisioned object.
    pub objects: Vec<CleanupObjectAbsence>,
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

/// Observed deterministic provisioning facts supplied by the private runner adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionedTarget {
    /// Exact Kubernetes namespace UID established by provisioning.
    pub namespace_uid: String,
    /// Policy revision actually applied to the target.
    pub policy_revision: String,
    /// Digest binding the applied revision to its exact inventory.
    pub policy_inventory_digest: String,
    /// Cleanup identity actually attached to owned resources.
    pub cleanup_identity: String,
    /// Complete observed per-object identity, UID, owner, and policy-content evidence.
    pub objects: Vec<ProvisionedObject>,
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

/// SQLite-backed fixed sandbox service.
pub struct Service {
    database_path: PathBuf,
    receipt_directory: PathBuf,
    digest_key: [u8; 32],
    origin: String,
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
        digest_key: [u8; 32],
        now_unix_s: i64,
    ) -> Result<Self, ServiceError> {
        let database_path = database_path.as_ref();
        let receipt_directory = receipt_directory.as_ref();
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
        if digest_key == [0; 32] {
            return Err(ServiceError::Unavailable);
        }
        let service = Self {
            database_path,
            receipt_directory,
            digest_key,
            origin: "https://kapsel.invalid".into(),
        };
        service.initialize()?;
        service.sweep_retention(now_unix_s)?;
        Ok(service)
    }

    /// Runs the operator-owned periodic retention and tombstone deletion sweep.
    ///
    /// Call this from the bounded maintenance scheduler even when there is no visitor traffic.
    ///
    /// # Errors
    ///
    /// Returns a time, storage, or immutable-object deletion failure.
    pub fn sweep_retention(&self, now_unix_s: i64) -> Result<(), ServiceError> {
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
        connection
            .execute(
                "UPDATE service_state SET stopped = ?1 WHERE singleton = 1",
                [stopped],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Returns the oldest queued run while atomically reserving active capacity and a lease.
    ///
    /// # Errors
    ///
    /// Returns a storage, entropy, [`ServiceError::ActiveSaturated`], or
    /// [`ServiceError::RunNotFound`] failure.
    pub fn dispatch_next(&self, now_unix_s: i64) -> Result<DispatchLease, ServiceError> {
        let lease_id = random_identity()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
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
        let (run_id, deadline_seconds): (String, i64) = transaction
            .query_row(
                concat!(
                    "SELECT run_id, deadline_seconds FROM runs WHERE execution_state = 'queued' ",
                    "AND public_retained = 1 ORDER BY admission_order LIMIT 1"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        let deadline_at = now_unix_s
            .checked_add(deadline_seconds)
            .ok_or(ServiceError::Unavailable)?;
        let lease_expires_at = lease_expiry(now_unix_s, deadline_at)?;
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET active = 1, execution_state = 'running', ",
                    "dispatched_at = ?2, deadline_at = ?3, lease_id = ?4, lease_epoch = 1, ",
                    "lease_expires_at = ?5 WHERE run_id = ?1"
                ),
                params![run_id, now_unix_s, deadline_at, lease_id, lease_expires_at],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "UPDATE cleanup_records SET active = 1 WHERE run_id = ?1",
                [&run_id],
            )
            .map_err(storage_error)?;
        append_event(&transaction, &run_id, "execution.started", now_unix_s)?;
        transaction.commit().map_err(storage_error)?;
        Ok(DispatchLease {
            run_id,
            lease_id,
            epoch: 1,
            expires_at_unix_s: lease_expires_at,
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

    /// Claims or renews recovery after process loss without changing public projection.
    ///
    /// An unexpired lease can be renewed only with the exact previous lease. After expiry, a new
    /// opaque lease and incremented epoch are durably installed.
    ///
    /// # Errors
    ///
    /// Returns missing-run, inactive-run, lease-busy, entropy, or storage failures. Recovery leases
    /// remain available after the ordinary execution deadline.
    pub fn recover_run(
        &self,
        run_id: &str,
        previous: Option<&DispatchLease>,
        now_unix_s: i64,
    ) -> Result<DispatchLease, ServiceError> {
        bounded_hex_128(run_id)?;
        let new_lease_id = random_identity()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let (stored_id, epoch, expires_at, active): (String, i64, i64, bool) = transaction
            .query_row(
                concat!(
                    "SELECT lease_id, lease_epoch, lease_expires_at, active ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !active {
            return Err(ServiceError::InvalidTransition);
        }
        let previous_matches = previous.is_some_and(|lease| {
            lease.run_id == run_id && lease.lease_id == stored_id && lease.epoch == epoch
        });
        if now_unix_s < expires_at && !previous_matches {
            return Err(ServiceError::LeaseBusy);
        }
        let lease_id = if previous_matches {
            stored_id
        } else {
            new_lease_id
        };
        let next_epoch = epoch.checked_add(1).ok_or(ServiceError::Unavailable)?;
        let next_expiry = recovery_lease_expiry(now_unix_s)?;
        transaction
            .execute(
                concat!(
                    "UPDATE runs SET lease_id = ?2, lease_epoch = ?3, lease_expires_at = ?4 ",
                    "WHERE run_id = ?1"
                ),
                params![run_id, lease_id, next_epoch, next_expiry],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(DispatchLease {
            run_id: run_id.to_owned(),
            lease_id,
            epoch: next_epoch,
            expires_at_unix_s: next_expiry,
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

    /// Verifies exact policy-complete provisioning before Application invocation.
    ///
    /// # Errors
    ///
    /// Returns a lease/deadline failure, policy or ownership mismatch, invalid transition, or
    /// storage failure. A mismatch changes no invocation or receiver fact.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction binds exact policy and cross-run ownership evidence"
    )]
    pub fn verify_provisioned_target(
        &self,
        lease: &DispatchLease,
        target: &ProvisionedTarget,
        now_unix_s: i64,
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
        let exact_object_count = target.objects.len() == specification.required_objects.len();
        let exact_object_content = target
            .objects
            .iter()
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
        let current: (Option<String>, bool, String) = transaction
            .query_row(
                concat!(
                    "SELECT namespace_uid, application_invoked, execution_state ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
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
        transaction.commit().map_err(storage_error)?;
        if policy_matches {
            Ok(())
        } else {
            Err(ServiceError::PolicyMismatch)
        }
    }

    /// Runs the existing Kapsel application with one server-owned request and projects its report.
    ///
    /// # Errors
    ///
    /// Returns bounded sandbox transition/storage errors or the unchanged application failure.
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
        self.validate_application_ready(lease, now_unix_s, false)
            .map_err(RunError::Service)?;
        let request = self
            .server_owned_request(&lease.run_id)
            .map_err(RunError::Service)?;
        let mut application = Application::open(configuration).map_err(RunError::Application)?;
        self.mark_application_invoked(lease, now_unix_s)
            .map_err(RunError::Service)?;
        let report = application
            .execute(&request)
            .await
            .map_err(RunError::Application)?;
        self.record_application_report(&lease.run_id, &report, now_unix_s)
            .map_err(RunError::Service)?;
        self.snapshot(&lease.run_id, now_unix_s)
            .map_err(RunError::Service)
    }

    /// Reopens the configured application and reconciles the same operation after restart.
    ///
    /// # Errors
    ///
    /// Returns a bounded sandbox failure or unchanged application failure.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation preserves both journals at their last committed states. Repeat this method with
    /// the same operation identity and per-run journal.
    pub async fn reconcile_application(
        &self,
        lease: &DispatchLease,
        configuration: OperatorConfiguration,
        now_unix_s: i64,
    ) -> Result<Option<Snapshot>, RunError> {
        self.validate_application_ready(lease, now_unix_s, true)
            .map_err(RunError::Service)?;
        let mut application = Application::open(configuration).map_err(RunError::Application)?;
        self.mark_application_invoked(lease, now_unix_s)
            .map_err(RunError::Service)?;
        let expected = self
            .server_owned_request(&lease.run_id)
            .map_err(RunError::Service)?;
        let report = match application
            .reconcile()
            .await
            .map_err(RunError::Application)?
        {
            Some(report) => report,
            None => application
                .execute(&expected)
                .await
                .map_err(RunError::Application)?,
        };
        if report.operation_id != expected.operation_id {
            return Err(RunError::Service(ServiceError::InvalidTransition));
        }
        self.record_application_report(&lease.run_id, &report, now_unix_s)
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
                    "UPDATE runs SET execution_state = 'service_failed' ",
                    "WHERE run_id = ?1 AND execution_state = 'running' ",
                    "AND application_invoked = 0 AND namespace_uid IS NOT NULL ",
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
                "UPDATE runs SET cleanup_state = 'succeeded', active = 0 WHERE run_id = ?1",
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
    pub fn start_cleanup(
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

    fn initialize(&self) -> Result<(), ServiceError> {
        let database_parent = self
            .database_path
            .parent()
            .ok_or(ServiceError::Unavailable)?;
        validate_private_directory(database_parent)?;
        validate_private_directory(&self.receipt_directory)?;
        prepare_database_file(&self.database_path)?;
        let mut connection = self.connection()?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = DELETE;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS service_state (
                   singleton INTEGER PRIMARY KEY CHECK (singleton = 1), stopped INTEGER NOT NULL
                 );
                 INSERT OR IGNORE INTO service_state VALUES (1, 0);
                 CREATE TABLE IF NOT EXISTS runs (
                   admission_order INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE,
                   scenario TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                   admitted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                   execution_state TEXT NOT NULL, receiver_result TEXT,
                   target_rejection TEXT, receipt_available INTEGER NOT NULL,
                   cleanup_state TEXT NOT NULL, last_sequence INTEGER NOT NULL,
                   active INTEGER NOT NULL, deadline_emitted INTEGER NOT NULL,
                   application_invoked INTEGER NOT NULL, public_retained INTEGER NOT NULL,
                   policy_revision TEXT NOT NULL, policy_inventory TEXT NOT NULL,
                   policy_inventory_digest TEXT NOT NULL, cleanup_identity TEXT NOT NULL,
                   deadline_seconds INTEGER NOT NULL, deadline_at INTEGER,
                   policy_verified INTEGER NOT NULL, provisioned_objects TEXT,
                   cleanup_resource_state TEXT NOT NULL, dispatched_at INTEGER,
                   namespace_uid TEXT, lease_id TEXT NOT NULL,
                   lease_epoch INTEGER NOT NULL, lease_expires_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS cleanup_records (
                   run_id TEXT PRIMARY KEY, cleanup_identity TEXT NOT NULL,
                   namespace_uid TEXT, resource_state TEXT NOT NULL, state TEXT NOT NULL,
                   active INTEGER NOT NULL, eligible INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS provisioned_object_owners (
                   uid TEXT PRIMARY KEY, run_id TEXT NOT NULL, identity TEXT NOT NULL,
                   owner_label TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS events (
                   run_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL,
                   occurred_at INTEGER NOT NULL, execution_state TEXT NOT NULL,
                   receiver_result TEXT, target_rejection TEXT,
                   receipt_available INTEGER NOT NULL, cleanup_state TEXT NOT NULL,
                   PRIMARY KEY (run_id, sequence)
                 );
                 CREATE TABLE IF NOT EXISTS receipts (
                   run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, object_name TEXT NOT NULL UNIQUE
                 );
                 CREATE TABLE IF NOT EXISTS receipt_publications (
                   run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, object_name TEXT NOT NULL UNIQUE,
                   started_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS tombstones (
                   run_digest TEXT PRIMARY KEY, key_digest TEXT NOT NULL UNIQUE,
                   delete_at INTEGER NOT NULL
                 );",
            )
            .map_err(storage_error)?;
        self.remove_orphan_receipts(&mut connection)
    }

    fn remove_orphan_receipts(&self, connection: &mut Connection) -> Result<(), ServiceError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stale_publications = {
            let mut statement = transaction
                .prepare(concat!(
                    "SELECT receipt_publications.run_id, receipt_publications.object_name FROM ",
                    "receipt_publications LEFT JOIN runs ON runs.run_id = ",
                    "receipt_publications.run_id ",
                    "WHERE runs.run_id IS NULL OR runs.public_retained = 0"
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
        let before = validate_database_file(&self.database_path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection =
            Connection::open_with_flags(&self.database_path, flags).map_err(storage_error)?;
        let after = validate_database_file(&self.database_path)?;
        if before != after {
            return Err(ServiceError::Unavailable);
        }
        connection
            .execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")
            .map_err(storage_error)?;
        Ok(connection)
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
        let key_digest = self.keyed_digest(idempotency_key);
        let tombstoned: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE key_digest = ?1 AND delete_at > ?2)",
                params![key_digest, now_unix_s],
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
        let (policy_inventory, policy_inventory_digest) = policy_inventory_v1(run_id)?;
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
                    "lease_expires_at) VALUES ",
                    "(?1, ?2, ?3, ?4, ?5, ?6, 'queued', 0, 'pending', 1, 0, 0, 0, 1, ",
                    "?7, ?8, ?9, ?10, ?11, NULL, 0, 'unverified', '', 0, 0)"
                ),
                params![
                    run_id,
                    idempotency_key,
                    scenario.token(),
                    operation_id,
                    now_unix_s,
                    expires_at,
                    DEPLOYMENT_POLICY_REVISION,
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
                    "(?1, ?2, NULL, 'unverified', 'pending', 0, 0)"
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

    fn server_owned_request(&self, run_id: &str) -> Result<AgentRequest, ServiceError> {
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
        let digest = match scenario {
            Scenario::Healthy => concat!(
                "registry.k8s.io/pause@sha256:",
                "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
            ),
            Scenario::UnavailableImage => concat!(
                "registry.k8s.io/pause@sha256:",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ),
        };
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
        let stored: (String, i64, i64, bool) = connection
            .query_row(
                concat!(
                    "SELECT lease_id, lease_epoch, lease_expires_at, active ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !stored.3
            || stored.0 != lease.lease_id
            || stored.1 != lease.epoch
            || stored.2 != lease.expires_at_unix_s
            || now >= stored.2
        {
            return Err(ServiceError::LeaseBusy);
        }
        Ok(())
    }

    fn validate_application_ready(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
        recovery: bool,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        let (policy_verified, deadline_at): (bool, i64) = self
            .connection()?
            .query_row(
                "SELECT policy_verified, deadline_at FROM runs WHERE run_id = ?1",
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !policy_verified {
            return Err(ServiceError::PolicyMismatch);
        }
        if !recovery && now_unix_s >= deadline_at {
            return Err(ServiceError::DeadlineExceeded);
        }
        Ok(())
    }

    fn mark_application_invoked(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        self.validate_lease(lease, now_unix_s)?;
        let connection = self.connection()?;
        let (state, invoked, policy_verified): (String, bool, bool) = connection
            .query_row(
                concat!(
                    "SELECT execution_state, application_invoked, policy_verified ",
                    "FROM runs WHERE run_id = ?1"
                ),
                [&lease.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)?;
        if !policy_verified {
            return Err(ServiceError::PolicyMismatch);
        }
        if invoked {
            return Ok(());
        }
        if state != "running" {
            return Err(ServiceError::InvalidTransition);
        }
        connection
            .execute(
                "UPDATE runs SET application_invoked = 1 WHERE run_id = ?1",
                [&lease.run_id],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    fn record_application_report(
        &self,
        run_id: &str,
        report: &OperationReport,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let expected = self.server_owned_request(run_id)?;
        if report.operation_id != expected.operation_id {
            return Err(ServiceError::InvalidTransition);
        }
        match report.state {
            OperationState::NotAttempted => {
                let rejection = match report.target_rejection {
                    Some(TargetRejection::DeploymentNotFound) => "DEPLOYMENT_NOT_FOUND",
                    Some(TargetRejection::ContainerNotFound) => "CONTAINER_NOT_FOUND",
                    Some(TargetRejection::InvalidTarget) => "INVALID_TARGET",
                    None => return Err(ServiceError::InvalidTransition),
                };
                self.terminal_transition(
                    run_id,
                    ExecutionState::NotAttempted,
                    None,
                    Some(rejection),
                    "execution.not_attempted",
                    now_unix_s,
                )
            },
            OperationState::Finalized => {
                let result = match report.result {
                    Some(OperationResult::Succeeded) => "SUCCEEDED",
                    Some(OperationResult::Failed) => "FAILED",
                    Some(OperationResult::Unknown) => "UNKNOWN",
                    None => return Err(ServiceError::InvalidTransition),
                };
                let reference = report
                    .receipt
                    .as_ref()
                    .ok_or(ServiceError::InvalidTransition)?;
                let bytes = fs::read(&reference.path).map_err(|_| ServiceError::Unavailable)?;
                if bytes.is_empty()
                    || bytes.len() > RECEIPT_BYTES_MAX
                    || hex(&Sha256::digest(&bytes)) != reference.digest
                {
                    return Err(ServiceError::Unavailable);
                }
                self.terminal_transition(
                    run_id,
                    ExecutionState::Terminal,
                    Some(result),
                    None,
                    "execution.terminal",
                    now_unix_s,
                )?;
                if self.is_public_retained(run_id)? {
                    self.install_receipt(run_id, &bytes, &reference.digest, now_unix_s)
                } else {
                    self.mark_cleanup_eligible(run_id)
                }
            },
            OperationState::Requested
            | OperationState::Authorized
            | OperationState::ApplyStarted
            | OperationState::ReceiverObserved
            | OperationState::ReceiptPrepared
            | OperationState::ReceiptWritten => Ok(()),
        }
    }

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

    fn is_public_retained(&self, run_id: &str) -> Result<bool, ServiceError> {
        self.connection()?
            .query_row(
                "SELECT public_retained FROM runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?
            .ok_or(ServiceError::RunNotFound)
    }

    fn mark_cleanup_eligible(&self, run_id: &str) -> Result<(), ServiceError> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ServiceError::RunNotFound)
        }
    }

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
            transaction.commit().map_err(storage_error)?;
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
        transaction
            .execute(
                "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        append_event(&transaction, run_id, "receipt.available", now_unix_s)?;
        transaction
            .execute(
                "DELETE FROM receipt_publications WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        let installed = self.read_receipt_object(run_id, digest, object_name)?;
        if installed != bytes {
            return Err(ServiceError::Unavailable);
        }
        transaction.commit().map_err(storage_error)
    }

    fn install_receipt_object(&self, object_name: &str, bytes: &[u8]) -> Result<(), ServiceError> {
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
        match fs::hard_link(&pending_path, &final_path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&final_path).map_err(|_| ServiceError::Unavailable)?;
                if existing != bytes {
                    let _ = fs::remove_file(&pending_path);
                    return Err(ServiceError::Unavailable);
                }
            },
            Err(_) => {
                let _ = fs::remove_file(&pending_path);
                return Err(ServiceError::Unavailable);
            },
        }
        fs::remove_file(&pending_path).map_err(|_| ServiceError::Unavailable)?;
        let directory =
            fs::File::open(&self.receipt_directory).map_err(|_| ServiceError::Unavailable)?;
        directory.sync_all().map_err(|_| ServiceError::Unavailable)
    }

    fn read_receipt_object(
        &self,
        run_id: &str,
        digest: &str,
        object_name: &str,
    ) -> Result<Vec<u8>, ServiceError> {
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

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction validates all objects before releasing cleanup ownership"
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored: (String, Option<String>, String, String, bool, bool) = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_records.cleanup_identity, cleanup_records.namespace_uid, ",
                    "cleanup_records.resource_state, cleanup_records.state, ",
                    "cleanup_records.eligible, runs.public_retained FROM cleanup_records ",
                    "JOIN runs ON runs.run_id = cleanup_records.run_id ",
                    "WHERE cleanup_records.run_id = ?1"
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
        if stored.0 != cleanup_identity
            || stored.1.as_deref() != Some(&evidence.namespace_uid)
            || stored.2 != "owned"
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        if !stored.4 || !matches!(stored.3.as_str(), "running" | "failed") {
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
                "UPDATE cleanup_records SET state = 'succeeded', active = 0 WHERE run_id = ?1",
                [run_id],
            )
            .map_err(storage_error)?;
        if stored.5 {
            transaction
                .execute(
                    "UPDATE runs SET cleanup_state = 'succeeded', active = 0 WHERE run_id = ?1",
                    [run_id],
                )
                .map_err(storage_error)?;
            append_event(&transaction, run_id, "cleanup.succeeded", now_unix_s)?;
        }
        transaction
            .execute("DELETE FROM cleanup_records WHERE run_id = ?1", [run_id])
            .map_err(storage_error)?;
        if !stored.5 {
            transaction
                .execute(
                    "DELETE FROM provisioned_object_owners WHERE run_id = ?1",
                    [run_id],
                )
                .map_err(storage_error)?;
            transaction
                .execute("DELETE FROM runs WHERE run_id = ?1", [run_id])
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
    }

    fn cleanup_transition(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        observed_uid: &str,
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
        let (owned_cleanup, owned_uid, resource_state, cleanup_state, eligible): (
            String,
            Option<String>,
            String,
            String,
            bool,
        ) = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_identity, namespace_uid, resource_state, state, eligible ",
                    "FROM cleanup_records WHERE run_id = ?1"
                ),
                [run_id],
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
        if owned_cleanup != cleanup_identity
            || owned_uid.as_deref() != Some(observed_uid)
            || resource_state != "owned"
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        if !eligible {
            return Err(ServiceError::InvalidTransition);
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
                "UPDATE cleanup_records SET state = ?2 WHERE run_id = ?1",
                params![run_id, state.token()],
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

    #[allow(
        clippy::too_many_lines,
        reason = "one retention transaction erases public, receipt, cleanup, and ownership rows"
    )]
    fn expire(&self, now_unix_s: i64) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        self.remove_orphan_receipts(&mut connection)?;
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
                    "receipts.digest, receipts.object_name, receipt_publications.digest, ",
                    "receipt_publications.object_name FROM runs LEFT JOIN receipts ",
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
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                })
                .map_err(storage_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)?
        };
        let mut expired_objects = Vec::new();
        for (run_id, key, expires_at, digest, object_name, pending_digest, pending_name) in expired
        {
            if let (Some(digest), Some(object_name)) = (digest, object_name) {
                expired_objects.push((run_id.clone(), digest, object_name));
            }
            if let (Some(digest), Some(object_name)) = (pending_digest, pending_name) {
                expired_objects.push((run_id.clone(), digest, object_name));
            }
            let tombstone_delete_at = expires_at
                .checked_add(PUBLIC_RETENTION_SECONDS)
                .ok_or(ServiceError::Unavailable)?;
            if tombstone_delete_at > now_unix_s {
                transaction
                    .execute(
                        "INSERT OR REPLACE INTO tombstones VALUES (?1, ?2, ?3)",
                        params![
                            self.keyed_digest(&run_id),
                            self.keyed_digest(&key),
                            tombstone_delete_at
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
            if active {
                transaction
                    .execute(
                        concat!(
                            "UPDATE runs SET public_retained = 0, idempotency_key = ?2, ",
                            "receipt_available = 0, last_sequence = 0 WHERE run_id = ?1"
                        ),
                        params![run_id, self.keyed_digest(&key)],
                    )
                    .map_err(storage_error)?;
            } else {
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
            transaction
                .execute(
                    "DELETE FROM receipt_publications WHERE run_id = ?1",
                    [&run_id],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
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
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE run_digest = ?1 AND delete_at > ?2)",
                params![self.keyed_digest(run_id), now_unix_s],
                |row| row.get(0),
            )
            .map_err(storage_error)
    }

    fn keyed_digest(&self, value: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(self.digest_key);
        digest.update(value.as_bytes());
        hex(&digest.finalize())
    }
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
    /// KAP-0038 application failure without reinterpretation.
    Application(ApplicationError),
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

fn policy_inventory_v1(run_id: &str) -> Result<(String, String), ServiceError> {
    let namespace = format!("sandbox-{run_id}");
    let inventory = POLICY_OBJECTS_V1
        .iter()
        .map(|(identity, canonical_content)| PolicyObjectRequirement {
            identity: identity.replace(POLICY_NAMESPACE_TOKEN, &namespace),
            content_digest: hex(&Sha256::digest(canonical_content.as_bytes())),
        })
        .collect::<Vec<_>>();
    let canonical = serde_json::to_string(&inventory).map_err(|_| ServiceError::Unavailable)?;
    let digest = policy_binding_digest(DEPLOYMENT_POLICY_REVISION, &canonical);
    Ok((canonical, digest))
}

fn policy_binding_digest(revision: &str, canonical_inventory: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(revision.as_bytes());
    digest.update([0]);
    digest.update(canonical_inventory.as_bytes());
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
    let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Unavailable)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || mode != 0o600
    {
        return Err(ServiceError::Unavailable);
    }
    Ok((metadata.dev(), metadata.ino()))
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
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("sandbox.sqlite3");
        let service = Service::open(&database, &receipts, [9; 32], 1_774_051_200).unwrap();
        let admission = service
            .admit_with_run_id(
                "00000000000000000000000000000001",
                Scenario::Healthy,
                1_774_051_200,
                "0123456789abcdef0123456789abcdef",
            )
            .unwrap();
        service.dispatch_next(1_774_051_201).unwrap();
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

        let service = Service::open(&database, &receipts, [9; 32], 1_774_051_205).unwrap();
        assert_eq!(
            service.receipt(&admission.run_id, 1_774_051_205).unwrap(),
            bytes
        );
        assert_eq!(
            service.receipt(&admission.run_id, 1_774_137_600),
            Err(ServiceError::RunExpired)
        );
        fs::remove_dir_all(root).unwrap();
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
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("sandbox.sqlite3");
        let service = Service::open(&database, &receipts, [9; 32], 1_774_051_200).unwrap();
        let admission = service
            .admit_with_run_id(
                "00000000000000000000000000000002",
                Scenario::Healthy,
                1_774_051_200,
                "1123456789abcdef0123456789abcdef",
            )
            .unwrap();
        service.dispatch_next(1_774_051_201).unwrap();
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
        service.install_receipt_object(&object_name, bytes).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let collector_barrier = std::sync::Arc::clone(&barrier);
        let collector_database = database.clone();
        let collector_receipts = receipts.clone();
        let collector = std::thread::spawn(move || {
            collector_barrier.wait();
            Service::open(
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
        Service::open(&database, &receipts, [9; 32], 1_774_051_204).unwrap();
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
        fs::remove_dir_all(root).unwrap();
    }
}
