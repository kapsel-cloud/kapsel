//! Stores operation history and guards each durable transition.
//!
//! Row decoding checks that retained facts agree with their lifecycle phase. Conditional writes
//! prevent stale snapshots from advancing history. The worker lock excludes overlapping execution,
//! while capacity checks leave configured SQLite headroom for admitted operations to complete.
//! Private children own the exact schema, file custody, backups and rollback-file recovery.

pub(in crate::gateway) mod capacity;
pub(in crate::gateway) mod git;
mod opening;
mod records;
mod schema;
#[cfg(test)]
pub(in crate::gateway) mod test_history;

#[cfg(test)]
pub(crate) async fn executed_write_statements() -> Vec<(StorageWrite, String)> {
    let mut statements = Vec::new();
    for write in [
        StorageWrite::Admission,
        StorageWrite::Authorization,
        StorageWrite::Rejection,
        StorageWrite::Attempt,
        StorageWrite::Response,
        StorageWrite::Observation,
        StorageWrite::Receipt,
    ] {
        statements.extend(tests::kube_sqlite_bridge(write, Delivery::Confirmed));
    }
    statements.extend(tests::observation_mapping(
        0,
        false,
        false,
        OperationResult::Unknown,
        None,
        None,
    ));
    statements.extend(git::executed_write_statements().await);
    statements.sort_by(|left, right| left.1.cmp(&right.1));
    statements.dedup_by(|left, right| left.1 == right.1);
    statements
}

use std::{
    fs::{File, TryLockError},
    path::Path,
    sync::{Arc, Mutex},
};

#[cfg(test)]
use records::MappingDefect;
use records::Record;
pub(crate) use records::Write as StorageWrite;
#[cfg(test)]
pub(crate) use records::{Control as StorageControl, Defect, Delivery, WriteEvent};
#[cfg(test)]
use rusqlite::OptionalExtension;
use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::{
    kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity, ValidatedTargetIdentity},
    receipt::{decode_frozen_receipt, publication, ReceiptStatement, RECEIPT_BYTES_MAX},
    validate_identity, ApprovedTarget, AuthorizedRequest, FaultPoint, FrozenReceipt, GatewayError,
    InputField, ObservedTarget, OperationResult, OperationState, OperationTargets,
    ReceiptToPrepare, RetainedOperation, SetDeploymentImageRequest, TargetRejection,
    ValidatedRequest, WRITE_STRATEGY,
};

pub(crate) const OPERATION_COUNT_MAX: i64 = 10_000;

pub(crate) struct Journal {
    pub(crate) connection: Connection,
    worker_lock: Arc<Mutex<Option<File>>>,
    records: records::Io,
}

pub(crate) struct WorkerLock {
    file: Option<File>,
    slot: Arc<Mutex<Option<File>>>,
}

// Only confirmation of a fresh attempt commit creates this one-use permission.
// Loading an attempt cannot recreate it, even when the original send never reached the receiver.
pub(crate) struct DispatchPermission {
    request: ValidatedRequest,
    target: ValidatedTargetIdentity,
}

impl DispatchPermission {
    // The adapter consumes permission when building its mutation request. Consumption alone cannot
    // prevent transport retries. The I/O implementation must send at most one mutation request.
    pub(crate) fn into_payload(self) -> (SetDeploymentImageRequest, TargetIdentity) {
        (
            self.request.to_adapter_request(),
            self.target.to_adapter_target(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct RequestFacts {
    approved_target: Option<ApprovedTarget>,
    preflight_target: Option<ApprovedTarget>,
    request: ValidatedRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Sha256Digest(String);

impl TryFrom<String> for Sha256Digest {
    type Error = GatewayError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            Ok(Self(value))
        } else {
            Err(GatewayError::InvalidPersistedState)
        }
    }
}

#[allow(
    dead_code,
    reason = "validated authorization provenance is retained by every authenticated phase"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct AuthorizationFacts {
    authorization_id: String,
    signer_key_id: String,
    grant_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplyResponseFacts {
    accepted: bool,
    requested_generation: Option<i64>,
    resource_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct AttemptFacts {
    target: ValidatedTargetIdentity,
    response: Option<ApplyResponseFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct ReceiverFacts {
    statement: ReceiptStatement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestedOperation {
    request: RequestFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedOperation {
    request: RequestFacts,
    authorization: AuthorizationFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NotAttemptedOperation {
    authorized: AuthorizedOperation,
    rejection: TargetRejection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyStartedOperation {
    authorized: AuthorizedOperation,
    attempt: AttemptFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiverObservedOperation {
    apply_started: ApplyStartedOperation,
    receiver: ReceiverFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinalizedOperation {
    receiver_observed: ReceiverObservedOperation,
    receipt: FrozenReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoadedOperation {
    Requested(RequestedOperation),
    Authorized(AuthorizedOperation),
    NotAttempted(NotAttemptedOperation),
    ApplyStarted(ApplyStartedOperation),
    ReceiverObserved(ReceiverObservedOperation),
    Finalized(FinalizedOperation),
}

impl RequestedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        &self.request.request
    }
}

impl AuthorizedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        &self.request.request
    }

    pub(in crate::gateway) fn approved_target(&self) -> Option<&ApprovedTarget> {
        self.request.approved_target.as_ref()
    }
}

impl ApplyStartedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        self.authorized.request()
    }

    pub(in crate::gateway) fn classification_outcome(&self) -> ApplyOutcome {
        ApplyOutcome {
            accepted: self
                .attempt
                .response
                .as_ref()
                .is_some_and(|response| response.accepted),
            requested_generation: self
                .attempt
                .response
                .as_ref()
                .and_then(|response| response.requested_generation),
            deployment_uid: Some(self.attempt.target.deployment_uid().to_owned()),
            resource_version: Some(self.attempt.response.as_ref().map_or_else(
                || self.attempt.target.resource_version().to_owned(),
                |response| response.resource_version.clone(),
            )),
        }
    }
}

impl ReceiverObservedOperation {
    pub(in crate::gateway) fn operation_id(&self) -> &str {
        self.apply_started.request().operation_id()
    }

    pub(in crate::gateway) fn statement(&self) -> &ReceiptStatement {
        &self.receiver.statement
    }
}

impl FinalizedOperation {
    pub(in crate::gateway) fn receipt(&self) -> &FrozenReceipt {
        &self.receipt
    }
}

impl LoadedOperation {
    pub(crate) fn state(&self) -> OperationState {
        match self {
            Self::Requested(_) => OperationState::Requested,
            Self::Authorized(_) => OperationState::Authorized,
            Self::NotAttempted(_) => OperationState::NotAttempted,
            Self::ApplyStarted(_) => OperationState::ApplyStarted,
            Self::ReceiverObserved(_) => OperationState::ReceiverObserved,
            Self::Finalized(_) => OperationState::Finalized,
        }
    }

    fn request_facts(&self) -> &RequestFacts {
        match self {
            Self::Requested(operation) => &operation.request,
            Self::Authorized(operation) => &operation.request,
            Self::NotAttempted(operation) => &operation.authorized.request,
            Self::ApplyStarted(operation) => &operation.authorized.request,
            Self::ReceiverObserved(operation) => &operation.apply_started.authorized.request,
            Self::Finalized(operation) => {
                &operation.receiver_observed.apply_started.authorized.request
            },
        }
    }

    pub(crate) fn targets(&self) -> OperationTargets {
        let request = self.request_facts();
        let attempt = match self {
            Self::ApplyStarted(operation) => Some(&operation.attempt),
            Self::ReceiverObserved(operation) => Some(&operation.apply_started.attempt),
            Self::Finalized(operation) => Some(&operation.receiver_observed.apply_started.attempt),
            Self::Requested(_) | Self::Authorized(_) | Self::NotAttempted(_) => None,
        };
        let statement = match self {
            Self::ReceiverObserved(operation) => Some(operation.statement()),
            Self::Finalized(operation) => Some(operation.receiver_observed.statement()),
            _ => None,
        };

        OperationTargets {
            git: None,
            approved_target: request.approved_target.clone(),
            attempt_target: attempt.map(|attempt| ApprovedTarget {
                uid: attempt.target.deployment_uid().to_owned(),
                resource_version: attempt.target.resource_version().to_owned(),
            }),
            observed_target: statement.map_or_else(
                || {
                    request
                        .preflight_target
                        .as_ref()
                        .map(|target| ObservedTarget {
                            uid: Some(target.uid.clone()),
                            resource_version: Some(target.resource_version.clone()),
                        })
                },
                |statement| {
                    Some(ObservedTarget {
                        uid: statement.receiver_uid.clone(),
                        resource_version: statement.observed_resource_version.clone(),
                    })
                },
            ),
        }
    }

    pub(crate) fn result(&self) -> Option<OperationResult> {
        match self {
            Self::ReceiverObserved(value) => Some(value.receiver.statement.result),
            Self::Finalized(value) => Some(value.receiver_observed.receiver.statement.result),
            Self::Requested(_)
            | Self::Authorized(_)
            | Self::NotAttempted(_)
            | Self::ApplyStarted(_) => None,
        }
    }

    pub(crate) fn target_rejection(&self) -> Option<TargetRejection> {
        match self {
            Self::NotAttempted(value) => Some(value.rejection),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(in crate::gateway) fn frozen_receipt(&self) -> Option<&FrozenReceipt> {
        match self {
            Self::Finalized(value) => Some(value.receipt()),
            _ => None,
        }
    }
}

struct SnapshotRow {
    approved_uid: Option<String>,
    approved_resource_version: Option<String>,
    preflight_uid: Option<String>,
    preflight_resource_version: Option<String>,
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
    state: String,
    result: Option<String>,
    target_rejection: Option<String>,
    authorization_id: Option<String>,
    authorization_signer_key_id: Option<String>,
    authorization_grant_digest: Option<String>,
    write_strategy: Option<String>,
    apply_attempted: i64,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    apply_accepted: Option<i64>,
    requested_generation: Option<i64>,
    apply_resource_version: Option<String>,
    receiver_facts_present: bool,
    receipt_digest: Option<String>,
    receipt_bytes: Option<Vec<u8>>,
    receipt_key_id: Option<String>,
}

impl SnapshotRow {
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive hostile-row decoder keeps every phase/fact combination visible"
    )]
    fn into_operation(
        self,
        statement: Option<ReceiptStatement>,
    ) -> Result<LoadedOperation, GatewayError> {
        let state = OperationState::from_sql(&self.state)?;
        let apply_attempted = decode_sql_bool(self.apply_attempted)?;
        let apply_accepted = self.apply_accepted.map(decode_sql_bool).transpose()?;
        let approved_target = snapshot_target(self.approved_uid, self.approved_resource_version)?;
        let preflight_target =
            snapshot_target(self.preflight_uid, self.preflight_resource_version)?;
        if preflight_target.is_some()
            && matches!(
                state,
                OperationState::Requested | OperationState::Authorized
            )
        {
            return Err(GatewayError::InvalidPersistedState);
        }

        let request = RequestFacts {
            approved_target,
            preflight_target,
            request: ValidatedRequest::try_from(&SetDeploymentImageRequest {
                operation_id: self.operation_id,
                namespace: self.namespace,
                deployment: self.deployment,
                container: self.container,
                immutable_image_digest: self.immutable_image_digest,
            })
            .map_err(|_| GatewayError::InvalidPersistedState)?,
        };

        let result = self
            .result
            .map(|value| OperationResult::from_sql(&value))
            .transpose()?;
        let rejection = self
            .target_rejection
            .map(|value| TargetRejection::from_sql(&value))
            .transpose()?;
        let authorization = validate_snapshot_authorization(
            self.authorization_id,
            self.authorization_signer_key_id,
            self.authorization_grant_digest,
        )?;
        let attempt = validate_snapshot_attempt_facts(
            state,
            self.write_strategy,
            self.target_uid,
            self.target_resource_version,
            apply_accepted,
            self.requested_generation,
            self.apply_resource_version,
        )?;

        if let Some(approved) = &request.approved_target {
            if authorization.is_none()
                || attempt.as_ref().is_some_and(|attempt| {
                    attempt.target.deployment_uid() != approved.uid
                        || attempt.target.resource_version() != approved.resource_version
                })
                || (attempt.is_some() && request.preflight_target.as_ref() != Some(approved))
            {
                return Err(GatewayError::InvalidPersistedState);
            }
        }
        if rejection == Some(TargetRejection::StaleApproval)
            && (request.approved_target.is_none()
                || request.preflight_target.is_none()
                || request.approved_target == request.preflight_target)
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if state == OperationState::NotAttempted
            && rejection != Some(TargetRejection::StaleApproval)
            && request.preflight_target.is_some()
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if statement.as_ref().map(|value| value.result) != result {
            return Err(GatewayError::InvalidPersistedState);
        }

        let receipt = snapshot_frozen_receipt(
            request.request.operation_id(),
            self.receipt_digest,
            self.receipt_bytes,
            self.receipt_key_id,
            statement.as_ref(),
        )?;
        let receiver = statement.map(|statement| ReceiverFacts { statement });

        match state {
            OperationState::Requested
                if !apply_attempted
                    && rejection.is_none()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::Requested(RequestedOperation { request }))
            },
            OperationState::Authorized
                if !apply_attempted
                    && authorization.is_some()
                    && rejection.is_none()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::Authorized(AuthorizedOperation {
                    request,
                    authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::NotAttempted
                if !apply_attempted
                    && authorization.is_some()
                    && rejection.is_some()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::NotAttempted(NotAttemptedOperation {
                    authorized: AuthorizedOperation {
                        request,
                        authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    rejection: rejection.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::ApplyStarted
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::ApplyStarted(ApplyStartedOperation {
                    authorized: AuthorizedOperation {
                        request,
                        authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::ReceiverObserved
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_none() =>
            {
                Ok(LoadedOperation::ReceiverObserved(
                    ReceiverObservedOperation {
                        apply_started: ApplyStartedOperation {
                            authorized: AuthorizedOperation {
                                request,
                                authorization: authorization
                                    .ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                        receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                ))
            },
            OperationState::Finalized
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_some() =>
            {
                Ok(LoadedOperation::Finalized(FinalizedOperation {
                    receiver_observed: ReceiverObservedOperation {
                        apply_started: ApplyStartedOperation {
                            authorized: AuthorizedOperation {
                                request,
                                authorization: authorization
                                    .ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                        receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    receipt: receipt.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

fn validate_snapshot_attempt_facts(
    state: OperationState,
    write_strategy: Option<String>,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    apply_accepted: Option<bool>,
    requested_generation: Option<i64>,
    apply_resource_version: Option<String>,
) -> Result<Option<AttemptFacts>, GatewayError> {
    let target = match (write_strategy, target_uid, target_resource_version) {
        (Some(strategy), Some(deployment_uid), Some(resource_version))
            if strategy == WRITE_STRATEGY =>
        {
            Some(
                ValidatedTargetIdentity::try_from(TargetIdentity {
                    deployment_uid,
                    resource_version,
                })
                .map_err(|_| GatewayError::InvalidPersistedState)?,
            )
        },
        (None, None, None) => None,
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    let Some(target) = target else {
        if apply_accepted.is_none()
            && requested_generation.is_none()
            && apply_resource_version.is_none()
        {
            return Ok(None);
        }
        return Err(GatewayError::InvalidPersistedState);
    };
    let response = match (apply_accepted, apply_resource_version) {
        (None, None) if state != OperationState::ApplyStarted || requested_generation.is_none() => {
            None
        },
        (Some(accepted), Some(resource_version)) => {
            ApplyOutcome {
                accepted,
                requested_generation,
                deployment_uid: Some(target.deployment_uid().to_owned()),
                resource_version: Some(resource_version.clone()),
            }
            .validate()
            .map_err(|_| GatewayError::InvalidPersistedState)?;
            Some(ApplyResponseFacts {
                accepted,
                requested_generation,
                resource_version,
            })
        },
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    Ok(Some(AttemptFacts { target, response }))
}

impl Drop for WorkerLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            if file.unlock().is_err() {
                return;
            }
            if let Ok(mut slot) = self.slot.lock() {
                *slot = Some(file);
            }
        }
    }
}

impl OperationState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::NotAttempted => "not_attempted",
            Self::ApplyStarted => "apply_started",
            Self::ReceiverObserved => "receiver_observed",
            Self::Finalized => "finalized",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "requested" => Ok(Self::Requested),
            "authorized" => Ok(Self::Authorized),
            "not_attempted" => Ok(Self::NotAttempted),
            "apply_started" => Ok(Self::ApplyStarted),
            "receiver_observed" => Ok(Self::ReceiverObserved),
            "finalized" => Ok(Self::Finalized),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl TargetRejection {
    fn as_sql(self) -> &'static str {
        match self {
            Self::DeploymentNotFound => "deployment_not_found",
            Self::ContainerNotFound => "container_not_found",
            Self::InvalidTarget => "invalid_target",
            Self::StaleApproval => "stale_approval",
            Self::GitStaleRef => "git_stale_ref",
            Self::GitInvalidObjects => "git_invalid_objects",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "deployment_not_found" => Ok(Self::DeploymentNotFound),
            "container_not_found" => Ok(Self::ContainerNotFound),
            "invalid_target" => Ok(Self::InvalidTarget),
            "stale_approval" => Ok(Self::StaleApproval),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl OperationResult {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "SUCCEEDED" => Ok(Self::Succeeded),
            "FAILED" => Ok(Self::Failed),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl Journal {
    pub(in crate::gateway) fn validate_replacement(
        path: &Path,
        approvals: &[AuthorizedRequest],
    ) -> Result<(), GatewayError> {
        Self::validate_mixed_replacement(path, approvals, &[])
    }

    pub(in crate::gateway) fn validate_mixed_replacement(
        path: &Path,
        approvals: &[AuthorizedRequest],
        git_approvals: &[git::GitBinding],
    ) -> Result<(), GatewayError> {
        let Some(connection) = opening::open_validation_snapshot(path)? else {
            return Ok(());
        };
        for approval in approvals {
            authorized_operation_on(&connection, approval, || {})?;
        }
        for approval in git_approvals {
            git::load_on(&connection, approval)?;
        }
        connection
            .close()
            .map_err(|(_, error)| GatewayError::Database(error))
    }

    pub(in crate::gateway) fn open(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        let opening::OpenedJournal {
            connection,
            worker_lock,
        } = opening::open_journal(path.as_ref())?;
        Ok(Self {
            connection,
            worker_lock: Arc::new(Mutex::new(Some(worker_lock))),
            records: records::Io::default(),
        })
    }

    pub(in crate::gateway) fn try_lock_worker(&self) -> Result<Option<WorkerLock>, GatewayError> {
        let mut slot = self
            .worker_lock
            .lock()
            .map_err(|_| GatewayError::InvalidPersistedState)?;
        let Some(file) = slot.take() else {
            return Ok(None);
        };
        match file.try_lock() {
            Ok(()) => Ok(Some(WorkerLock {
                file: Some(file),
                slot: self.worker_lock.clone(),
            })),
            Err(error) => {
                *slot = Some(file);
                drop(slot);
                match error {
                    TryLockError::WouldBlock => Ok(None),
                    TryLockError::Error(error) => Err(GatewayError::WorkerLock(error)),
                }
            },
        }
    }

    pub(in crate::gateway) fn owns_worker(&self, worker: &WorkerLock) -> bool {
        Arc::ptr_eq(&self.worker_lock, &worker.slot) && worker.file.is_some()
    }

    pub(in crate::gateway) fn existing_submission(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<Option<OperationState>, GatewayError> {
        Ok(self
            .authorized_operation(authorized)?
            .map(|operation| operation.state()))
    }

    pub(in crate::gateway) fn authorized_operation(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        self.authorized_operation_with(authorized, || {})
    }

    fn authorized_operation_with(
        &self,
        authorized: &AuthorizedRequest,
        after_ownership_read: impl FnOnce(),
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        authorized_record_on(
            &transaction,
            &self.records,
            authorized,
            after_ownership_read,
        )
    }

    pub(in crate::gateway) fn history_ids(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<String>, GatewayError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT CASE WHEN length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
                         THEN operation_id END
             FROM (
                 SELECT operation_id FROM kubernetes_image_operations
                 UNION ALL SELECT operation_id FROM git_ref_operations
             )
             WHERE (?1 IS NULL OR operation_id > ?1 COLLATE BINARY)
             ORDER BY operation_id COLLATE BINARY LIMIT 9",
            )
            .map_err(GatewayError::Database)?;
        let rows = statement
            .query_map([after], |row| row.get::<_, String>(0))
            .map_err(GatewayError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn retained_operation(
        &self,
        operation_id: &str,
        authorize: impl FnOnce(&[u8]) -> Result<AuthorizedRequest, GatewayError>,
    ) -> Result<Option<RetainedOperation>, GatewayError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(GatewayError::Database)?;
        let Some(record) = self.records.read(&transaction, operation_id)? else {
            return Ok(None);
        };
        let bytes: Vec<u8> = record.get("signed_authorization_grant")?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(GatewayError::InvalidPersistedState);
        }
        let authorized = authorize(&bytes)?;
        let operation = authorized_record_on(&transaction, &self.records, &authorized, || {})?
            .ok_or(GatewayError::InvalidPersistedState)?;
        Ok(Some(RetainedOperation {
            request: authorized.request().to_adapter_request(),
            signed_grant: bytes,
            operation,
        }))
    }

    pub(in crate::gateway) fn insert_requested(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<(), GatewayError> {
        let request = authorized.request();
        let authority = authorized.authorization();
        let approved = authority.authorization.approved_target.as_ref();
        let mut record = Record::empty(request.operation_id());
        record.set("namespace", request.namespace().to_owned());
        record.set("deployment", request.deployment().to_owned());
        record.set("container", request.container().to_owned());
        record.set(
            "immutable_image_digest",
            request.immutable_image_digest().to_owned(),
        );
        record.set("state", OperationState::Requested.as_sql().to_owned());
        record.set(
            "authorization_id",
            authority.authorization.authorization_id.clone(),
        );
        record.set(
            "authorization_signer_key_id",
            authority.signer_key_id.clone(),
        );
        record.set("authorization_grant_digest", authority.grant_digest.clone());
        record.set("signed_authorization_grant", authority.signed_grant.clone());
        record.set_optional("approved_uid", approved.map(|target| target.uid.clone()));
        record.set_optional(
            "approved_resource_version",
            approved.map(|target| target.resource_version.clone()),
        );
        self.records
            .replace(&self.connection, None, &record, StorageWrite::Admission)
    }

    pub(in crate::gateway) fn mark_authorized(
        &self,
        operation: &RequestedOperation,
        authorized: &AuthorizedRequest,
    ) -> Result<(), GatewayError> {
        if operation.request() != authorized.request()
            || self.existing_submission(authorized)? != Some(OperationState::Requested)
        {
            return Err(GatewayError::InvalidTransition);
        }
        let expected = self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::Requested(operation.clone()),
        )?;
        let mut next = expected.clone();
        let authorization = authorized.authorization();
        next.set("state", OperationState::Authorized.as_sql().to_owned());
        next.set(
            "authorization_id",
            authorization.authorization.authorization_id.clone(),
        );
        next.set(
            "authorization_signer_key_id",
            authorization.signer_key_id.clone(),
        );
        next.set(
            "authorization_grant_digest",
            authorization.grant_digest.clone(),
        );
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Authorization,
        )
    }

    #[cfg(test)]
    pub(in crate::gateway) fn state(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.connection
            .query_row(
                "SELECT state FROM kubernetes_image_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .map(|state| OperationState::from_sql(&state))
            .transpose()
    }

    #[cfg(test)]
    pub(in crate::gateway) fn result(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationResult>, GatewayError> {
        self.connection
            .query_row(
                "SELECT result FROM kubernetes_image_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .flatten()
            .map(|result| OperationResult::from_sql(&result))
            .transpose()
    }

    #[cfg(test)]
    pub(in crate::gateway) fn receipt_statement(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptStatement>, GatewayError> {
        Ok(match self.operation(operation_id)? {
            Some(LoadedOperation::ReceiverObserved(operation)) => {
                Some(operation.receiver.statement)
            },
            Some(LoadedOperation::Finalized(operation)) => {
                Some(operation.receiver_observed.receiver.statement)
            },
            _ => None,
        })
    }

    // Receipt completion commits the original signed evidence in SQLite, independently of export.
    pub(in crate::gateway) fn commit_receipt(
        &self,
        operation: &ReceiverObservedOperation,
        candidate: &ReceiptToPrepare,
    ) -> Result<(), GatewayError> {
        let receipt = candidate.receipt();
        if receipt.operation_id != operation.operation_id() {
            return Err(GatewayError::InvalidTransition);
        }
        let expected = self.bound_record(
            operation.operation_id(),
            &LoadedOperation::ReceiverObserved(operation.clone()),
        )?;
        let (key_id, statement) =
            decode_frozen_receipt(&receipt.bytes).map_err(GatewayError::Receipt)?;
        if statement != *operation.statement()
            || key_id != receipt.key_id
            || publication::receipt_digest_hex(&receipt.bytes) != receipt.digest
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        let mut next = expected.clone();
        next.set("state", OperationState::Finalized.as_sql().to_owned());
        next.set("receipt_digest", receipt.digest.clone());
        next.set("receipt_bytes", receipt.bytes.clone());
        next.set("receipt_key_id", receipt.key_id.clone());
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Receipt,
        )
    }

    pub(in crate::gateway) fn operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        self.records
            .read(&transaction, operation_id)?
            .as_ref()
            .map(|record| self.records.decode(record))
            .transpose()
    }

    fn bound_record(&self, id: &str, operation: &LoadedOperation) -> Result<Record, GatewayError> {
        let record = self
            .records
            .read(&self.connection, id)?
            .ok_or(GatewayError::InvalidTransition)?;
        if self.records.decode(&record)? != *operation {
            return Err(GatewayError::InvalidTransition);
        }
        Ok(record)
    }

    #[cfg(test)]
    pub(crate) fn control_storage(&mut self, control: StorageControl) {
        self.records.control = control;
    }

    #[cfg(test)]
    pub(crate) fn record_cut(&self) {
        self.records.control.record_cut();
    }

    #[cfg(test)]
    pub(crate) fn exercise_defect(&self, defect: Defect) -> bool {
        self.records.control.exercise(defect)
    }

    #[cfg(test)]
    pub(crate) fn peer_read_for_control(&self, id: &str) -> Result<Option<String>, GatewayError> {
        Ok(self
            .records
            .other_identity(&self.connection, id)?
            .filter(|_| self.exercise_defect(Defect::WrongPeerRead)))
    }

    #[cfg(test)]
    pub(crate) fn remint_for_control(operation: &ApplyStartedOperation) -> DispatchPermission {
        DispatchPermission {
            request: operation.request().clone(),
            target: operation.attempt.target.clone(),
        }
    }

    pub(in crate::gateway) fn mark_not_attempted(
        &self,
        operation: &AuthorizedOperation,
        rejection: TargetRejection,
    ) -> Result<(), GatewayError> {
        let expected = self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::Authorized(operation.clone()),
        )?;
        let mut next = expected.clone();
        next.set("state", OperationState::NotAttempted.as_sql().to_owned());
        next.set("target_rejection", rejection.as_sql().to_owned());
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Rejection,
        )
    }

    pub(in crate::gateway) fn begin_attempt(
        &self,
        operation: &AuthorizedOperation,
        observed: ValidatedTargetIdentity,
        fault: Option<FaultPoint>,
    ) -> Result<Option<DispatchPermission>, GatewayError> {
        #[cfg(not(test))]
        let _ = fault;
        // The raw store conditionally commits against the complete original record, not merely
        // the phase or identity. Only confirmed acknowledgement reaches permission construction.
        self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::Authorized(operation.clone()),
        )?;
        let target = if let Some(approved) = operation.approved_target() {
            if observed.deployment_uid() != approved.uid
                || observed.resource_version() != approved.resource_version
            {
                self.mark_stale_approval(operation, &observed)?;
                return Ok(None);
            }
            ValidatedTargetIdentity::try_from(TargetIdentity {
                deployment_uid: approved.uid.clone(),
                resource_version: approved.resource_version.clone(),
            })
            .map_err(|_| GatewayError::InvalidPersistedState)?
        } else {
            observed
        };

        self.mark_apply_started(operation, &target)?;
        #[cfg(test)]
        if fault == Some(FaultPoint::AttemptCommitAcknowledgementLost) {
            self.record_cut();
            return Err(GatewayError::InjectedFault);
        }

        Ok(Some(DispatchPermission {
            request: operation.request().clone(),
            target,
        }))
    }

    pub(in crate::gateway) fn mark_stale_approval(
        &self,
        operation: &AuthorizedOperation,
        observed: &ValidatedTargetIdentity,
    ) -> Result<(), GatewayError> {
        let expected = self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::Authorized(operation.clone()),
        )?;
        let mut next = expected.clone();
        next.set("state", "not_attempted".to_owned());
        next.set("target_rejection", "stale_approval".to_owned());
        next.set("preflight_uid", observed.deployment_uid().to_owned());
        next.set(
            "preflight_resource_version",
            observed.resource_version().to_owned(),
        );
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Rejection,
        )
    }

    fn mark_apply_started(
        &self,
        operation: &AuthorizedOperation,
        target: &ValidatedTargetIdentity,
    ) -> Result<(), GatewayError> {
        let expected = self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::Authorized(operation.clone()),
        )?;
        let mut next = expected.clone();
        next.set("state", OperationState::ApplyStarted.as_sql().to_owned());
        next.set("write_strategy", WRITE_STRATEGY.to_owned());
        next.set("apply_attempted", 1_i64);
        for field in ["target_uid", "preflight_uid"] {
            next.set(field, target.deployment_uid().to_owned());
        }
        for field in ["target_resource_version", "preflight_resource_version"] {
            next.set(field, target.resource_version().to_owned());
        }
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Attempt,
        )
    }

    pub(in crate::gateway) fn record_apply_outcome(
        &self,
        operation: &ApplyStartedOperation,
        outcome: &ApplyOutcome,
    ) -> Result<(), GatewayError> {
        outcome.validate()?;
        let expected = self.bound_record(
            operation.request().operation_id(),
            &LoadedOperation::ApplyStarted(operation.clone()),
        )?;
        let target_uid: Option<String> = expected.get("target_uid")?;
        if target_uid.is_none()
            || outcome.deployment_uid.as_ref() != target_uid.as_ref()
            || outcome.resource_version.is_none()
        {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        let mut next = expected.clone();
        next.set("apply_accepted", i64::from(outcome.accepted));
        next.set_optional("requested_generation", outcome.requested_generation);
        next.set_optional("apply_resource_version", outcome.resource_version.clone());
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Response,
        )
    }

    pub(in crate::gateway) fn freeze_observation(
        &self,
        operation: &ApplyStartedOperation,
        observation: &ReceiverObservation,
    ) -> Result<(), GatewayError> {
        observation.validate()?;
        let request = operation.request();
        let outcome = operation.classification_outcome();
        let result = observation.classify(request, &outcome);
        #[cfg(test)]
        let result = if self.exercise_defect(Defect::InitialUnknown) {
            OperationResult::Unknown
        } else {
            result
        };
        let requested_generation = observation.requested_generation(request, &outcome);
        let expected = self.bound_record(
            request.operation_id(),
            &LoadedOperation::ApplyStarted(operation.clone()),
        )?;
        let mut next = expected.clone();
        next.set(
            "state",
            OperationState::ReceiverObserved.as_sql().to_owned(),
        );
        next.set_optional("receiver_uid", observation.deployment_uid.clone());
        next.set_optional("receiver_image", observation.image.clone());
        next.set_optional(
            "receiver_operation_marker",
            observation.operation_marker.clone(),
        );
        next.set_optional("current_generation", observation.current_generation);
        next.set_optional("observed_generation", observation.observed_generation);
        next.set_optional(
            "receiver_resource_version",
            observation.resource_version.clone(),
        );
        next.set_optional(
            "desired_replicas",
            observation.desired_replicas.map(i64::from),
        );
        next.set_optional(
            "updated_replicas",
            observation.updated_replicas.map(i64::from),
        );
        let available_replicas = observation.available_replicas;
        #[cfg(test)]
        let available_replicas = match self.records.control.mapping_defect() {
            Some(MappingDefect::WriterReplicaSwap | MappingDefect::WriterReaderReplicaSwap) => {
                observation.updated_replicas
            },
            Some(MappingDefect::NullableDrop) => None,
            _ => available_replicas,
        };
        #[cfg(test)]
        if self.records.control.mapping_defect() == Some(MappingDefect::WriterReaderReplicaSwap) {
            next.set_optional(
                "updated_replicas",
                observation.available_replicas.map(i64::from),
            );
        }
        #[cfg(test)]
        if self.records.control.mapping_defect() == Some(MappingDefect::GenerationSwap) {
            next.set_optional("current_generation", observation.observed_generation);
            next.set_optional("observed_generation", observation.current_generation);
        };
        next.set_optional("available_replicas", available_replicas.map(i64::from));
        next.set_optional(
            "unavailable_replicas",
            observation.unavailable_replicas.map(i64::from),
        );
        next.set("result", result.as_sql().to_owned());
        next.set_optional("requested_generation", requested_generation);
        next.set_optional(
            "rollout_condition_type",
            observation.rollout_condition_type.clone(),
        );
        next.set_optional(
            "rollout_condition_status",
            observation.rollout_condition_status.clone(),
        );
        next.set_optional(
            "rollout_condition_reason",
            observation.rollout_condition_reason.clone(),
        );
        self.records.replace(
            &self.connection,
            Some(&expected),
            &next,
            StorageWrite::Observation,
        )
    }
}

fn authorized_operation_on(
    connection: &Connection,
    authorized: &AuthorizedRequest,
    after_ownership_read: impl FnOnce(),
) -> Result<Option<LoadedOperation>, GatewayError> {
    authorized_record_on(
        connection,
        &records::Io::default(),
        authorized,
        after_ownership_read,
    )
}

fn authorized_record_on(
    connection: &Connection,
    io: &records::Io,
    authorized: &AuthorizedRequest,
    after_ownership_read: impl FnOnce(),
) -> Result<Option<LoadedOperation>, GatewayError> {
    let request = authorized.request();
    let authorization = authorized.authorization();
    let existing_record = io.read(connection, request.operation_id())?;
    let retained_binding = existing_record
        .as_ref()
        .map(|record| -> Result<_, GatewayError> {
            Ok((
                record.get::<String>("namespace")?,
                record.get::<String>("deployment")?,
                record.get::<String>("container")?,
                record.get::<String>("immutable_image_digest")?,
                record.get::<Option<String>>("authorization_id")?,
                record.get::<Option<String>>("authorization_signer_key_id")?,
                record.get::<Option<String>>("authorization_grant_digest")?,
                record.get::<String>("state")?,
                record.get::<Option<Vec<u8>>>("signed_authorization_grant")?,
            ))
        })
        .transpose()?;
    let Some((
        namespace,
        deployment,
        container,
        image,
        authorization_id,
        authorization_signer_key_id,
        authorization_grant_digest,
        state,
        signed_grant,
    )) = retained_binding
    else {
        let collision: bool = connection
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM git_ref_operations WHERE operation_id = ?1)",
                [request.operation_id()],
                |row| row.get(0),
            )
            .map_err(GatewayError::Database)?;
        return if collision {
            Err(GatewayError::OperationIdentityConflict)
        } else {
            Ok(None)
        };
    };
    let signed_grant = signed_grant.ok_or(GatewayError::InvalidPersistedState)?;
    let grant_changed = signed_grant != authorization.signed_grant;
    #[cfg(test)]
    let grant_changed = grant_changed && !io.control.exercise(Defect::CustodyIgnored);
    if grant_changed
        || namespace != request.namespace()
        || deployment != request.deployment()
        || container != request.container()
        || image != request.immutable_image_digest()
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let state = OperationState::from_sql(&state)?;
    if state == OperationState::Requested
        && authorization_id.is_none()
        && authorization.authorization.approved_target.is_some()
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    if (state != OperationState::Requested || authorization_id.is_some())
        && (authorization_id.as_deref()
            != Some(authorization.authorization.authorization_id.as_str())
            || authorization_signer_key_id.as_deref() != Some(authorization.signer_key_id.as_str())
            || authorization_grant_digest.as_deref() != Some(authorization.grant_digest.as_str()))
    {
        return Err(GatewayError::OperationIdentityConflict);
    }

    after_ownership_read();

    let loaded = io
        .read(connection, request.operation_id())?
        .as_ref()
        .map(|record| io.decode(record))
        .transpose()?
        .ok_or(GatewayError::InvalidPersistedState)?;
    if loaded.request_facts().approved_target != authorization.authorization.approved_target {
        return Err(GatewayError::OperationIdentityConflict);
    }
    if loaded.state() != state {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(Some(loaded))
}

fn snapshot_target(
    uid: Option<String>,
    resource_version: Option<String>,
) -> Result<Option<ApprovedTarget>, GatewayError> {
    match (uid, resource_version) {
        (None, None) => Ok(None),
        (Some(uid), Some(resource_version)) => {
            let target = ApprovedTarget {
                uid,
                resource_version,
            };
            if !target.is_valid() {
                return Err(GatewayError::InvalidPersistedState);
            }
            Ok(Some(target))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn decode_sql_bool(value: i64) -> Result<bool, GatewayError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn validate_snapshot_authorization(
    authorization_id: Option<String>,
    signer_key_id: Option<String>,
    grant_digest: Option<String>,
) -> Result<Option<AuthorizationFacts>, GatewayError> {
    match (authorization_id, signer_key_id, grant_digest) {
        (None, None, None) => Ok(None),
        (Some(authorization_id), Some(signer_key_id), Some(grant_digest)) => {
            validate_identity(InputField::AuthorizationId, &authorization_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            validate_identity(InputField::AuthorizationId, &signer_key_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            Ok(Some(AuthorizationFacts {
                authorization_id,
                signer_key_id,
                grant_digest: Sha256Digest::try_from(grant_digest)?,
            }))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn snapshot_frozen_receipt(
    operation_id: &str,
    digest: Option<String>,
    bytes: Option<Vec<u8>>,
    key_id: Option<String>,
    statement: Option<&ReceiptStatement>,
) -> Result<Option<FrozenReceipt>, GatewayError> {
    match (digest, bytes, key_id) {
        (None, None, None) => Ok(None),
        (Some(digest), Some(bytes), Some(key_id)) => {
            let receipt = validate_frozen_receipt(FrozenReceipt {
                operation_id: operation_id.to_owned(),
                digest,
                bytes,
                key_id,
            })?;
            let expected_statement = statement.ok_or(GatewayError::InvalidPersistedState)?;
            let (embedded_key_id, embedded_statement) =
                decode_frozen_receipt(&receipt.bytes).map_err(GatewayError::Receipt)?;
            if embedded_key_id != receipt.key_id || embedded_statement != *expected_statement {
                return Err(GatewayError::InvalidPersistedState);
            }
            Ok(Some(receipt))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn validate_frozen_receipt(receipt: FrozenReceipt) -> Result<FrozenReceipt, GatewayError> {
    if receipt.bytes.len() > RECEIPT_BYTES_MAX
        || publication::receipt_digest_hex(&receipt.bytes) != receipt.digest
    {
        return Err(GatewayError::ReceiptDigestMismatch);
    }
    validate_identity(InputField::AuthorizationId, &receipt.key_id)
        .map_err(|_| GatewayError::InvalidPersistedState)?;
    Ok(receipt)
}

struct ReceiptRow {
    approved_uid: Option<String>,
    approved_resource_version: Option<String>,
    operation_id: String,
    authorization_id: Option<String>,
    authorization_signer_key_id: Option<String>,
    authorization_grant_digest: Option<String>,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
    write_strategy: Option<String>,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    receiver_uid: Option<String>,
    observed_image: Option<String>,
    observed_operation_marker: Option<String>,
    current_generation: Option<i64>,
    requested_generation: Option<i64>,
    observed_generation: Option<i64>,
    observed_resource_version: Option<String>,
    desired_replicas: Option<i32>,
    updated_replicas: Option<i32>,
    available_replicas: Option<i32>,
    unavailable_replicas: Option<i32>,
    rollout_condition_type: Option<String>,
    rollout_condition_status: Option<String>,
    rollout_condition_reason: Option<String>,
    result: String,
}

impl ReceiptRow {
    fn into_statement(self) -> Result<ReceiptStatement, GatewayError> {
        let statement = ReceiptStatement {
            approved_target: snapshot_target(self.approved_uid, self.approved_resource_version)?,
            operation_id: self.operation_id,
            authorization_id: self
                .authorization_id
                .ok_or(GatewayError::InvalidPersistedState)?,
            authorization_signer_key_id: self
                .authorization_signer_key_id
                .ok_or(GatewayError::InvalidPersistedState)?,
            authorization_grant_digest: self
                .authorization_grant_digest
                .ok_or(GatewayError::InvalidPersistedState)?,
            namespace: self.namespace,
            deployment: self.deployment,
            container: self.container,
            immutable_image_digest: self.immutable_image_digest,
            write_strategy: self
                .write_strategy
                .ok_or(GatewayError::InvalidPersistedState)?,
            target_uid: self.target_uid.ok_or(GatewayError::InvalidPersistedState)?,
            target_resource_version: self
                .target_resource_version
                .ok_or(GatewayError::InvalidPersistedState)?,
            receiver_uid: self.receiver_uid,
            observed_image: self.observed_image,
            observed_operation_marker: self.observed_operation_marker,
            current_generation: self.current_generation,
            requested_generation: self.requested_generation,
            observed_generation: self.observed_generation,
            observed_resource_version: self.observed_resource_version,
            desired_replicas: self.desired_replicas,
            updated_replicas: self.updated_replicas,
            available_replicas: self.available_replicas,
            unavailable_replicas: self.unavailable_replicas,
            rollout_condition_type: self.rollout_condition_type,
            rollout_condition_status: self.rollout_condition_status,
            rollout_condition_reason: self.rollout_condition_reason,
            result: OperationResult::from_sql(&self.result)?,
        };
        statement
            .validate()
            .map_err(|_| GatewayError::InvalidPersistedState)?;
        Ok(statement)
    }
}

fn changed_one(changed: usize) -> Result<(), GatewayError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(GatewayError::InvalidTransition)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use super::{
        test_history::{open_scratch, stored_rows, History, Scratch},
        *,
    };

    fn assert_history(operation: &LoadedOperation, history: &History, phase: &str) {
        assert_eq!(
            operation.request_facts().request.to_adapter_request(),
            history.request
        );
        assert_eq!(
            operation.request_facts().approved_target,
            history.statement.approved_target
        );
        assert_eq!(
            operation.request_facts().preflight_target,
            matches!(phase, "apply_started" | "receiver_observed" | "finalized").then(|| {
                ApprovedTarget {
                    uid: "target-uid".into(),
                    resource_version: "target-rv".into(),
                }
            })
        );
        let expected_state = match phase {
            "requested" => OperationState::Requested,
            "authorized" => OperationState::Authorized,
            "not_attempted" => OperationState::NotAttempted,
            "apply_started" => OperationState::ApplyStarted,
            "receiver_observed" => OperationState::ReceiverObserved,
            "finalized" => OperationState::Finalized,
            _ => unreachable!(),
        };
        assert_eq!(operation.state(), expected_state);
        assert_eq!(
            operation.target_rejection(),
            (phase == "not_attempted").then_some(TargetRejection::DeploymentNotFound)
        );
        assert_eq!(
            operation.result(),
            matches!(phase, "receiver_observed" | "finalized").then_some(history.statement.result)
        );
        let (authorization, attempt, statement) = match operation {
            LoadedOperation::Requested(_) => (None, None, None),
            LoadedOperation::Authorized(op) => (Some(&op.authorization), None, None),
            LoadedOperation::NotAttempted(op) => (Some(&op.authorized.authorization), None, None),
            LoadedOperation::ApplyStarted(op) => {
                (Some(&op.authorized.authorization), Some(&op.attempt), None)
            },
            LoadedOperation::ReceiverObserved(op) => (
                Some(&op.apply_started.authorized.authorization),
                Some(&op.apply_started.attempt),
                Some(op.statement()),
            ),
            LoadedOperation::Finalized(op) => {
                assert_eq!(op.receipt(), &history.receipt());
                let observed = &op.receiver_observed;
                (
                    Some(&observed.apply_started.authorized.authorization),
                    Some(&observed.apply_started.attempt),
                    Some(observed.statement()),
                )
            },
        };
        if let Some(auth) = authorization {
            assert_eq!(auth.authorization_id, "snapshot-auth");
            assert_eq!(auth.signer_key_id, "snapshot-signer");
            assert_eq!(
                auth.grant_digest.0,
                history.statement.authorization_grant_digest
            );
        }
        if let Some(attempt) = attempt {
            assert_eq!(attempt.target.deployment_uid(), "target-uid");
            assert_eq!(attempt.target.resource_version(), "target-rv");
            assert_eq!(attempt.response, None);
        }
        if let Some(statement) = statement {
            assert_eq!(statement, &history.statement);
        }
    }

    #[test]
    fn independently_authored_histories_bind_every_field_across_sql_readers() {
        for approved in [
            None,
            Some(ApprovedTarget {
                uid: "target-uid".into(),
                resource_version: "target-rv".into(),
            }),
        ] {
            let scratch = Scratch::new();
            let path = scratch.0.join("journal.sqlite3");
            let journal = open_scratch(&scratch);
            for phase in [
                "requested",
                "authorized",
                "not_attempted",
                "apply_started",
                "receiver_observed",
                "finalized",
            ] {
                let mut history = History::kube(phase);
                if approved.is_some() {
                    history = History::new(history.request, approved.clone());
                }
                history.insert(&journal.connection, phase);
                let before = stored_rows(&journal.connection);
                let operation = journal.operation(phase).unwrap().unwrap();
                assert_history(&operation, &history, phase);
                assert_eq!(
                    journal.authorized_operation(&history.authorized).unwrap(),
                    Some(operation.clone())
                );
                let retained = journal
                    .retained_operation(phase, |bytes| {
                        assert_eq!(bytes, history.authorized.authorization().signed_grant);
                        history.authorize(bytes)
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.request, history.request);
                assert_eq!(retained.operation, operation);
                let snapshot = opening::open_validation_snapshot(&path).unwrap().unwrap();
                assert_eq!(
                    authorized_operation_on(&snapshot, &history.authorized, || {}).unwrap(),
                    Some(operation)
                );
                drop(snapshot);
                Journal::validate_replacement(&path, &[history.authorized]).unwrap();
                assert_eq!(stored_rows(&journal.connection), before);
            }
            drop(journal);
            let bytes = fs::read(&path).unwrap();
            drop(Journal::open(&path).unwrap());
            Journal::validate_replacement(&path, &[]).unwrap();
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "compact corruption data stays beside its three readers"
    )]
    fn field_corruptions_are_refused_by_writable_retained_and_publication_readers() {
        // Every vector starts from a validated legal row. No incidental missing facts may
        // reject the baseline and mask the field under test.
        let cases = [
            ("requested", "namespace = 'Uppercase'"),
            ("authorized", "authorization_id = NULL"),
            ("authorized", "authorization_signer_key_id = 'bad key'"),
            ("authorized", "authorization_grant_digest = '00'"),
            ("not_attempted", "target_rejection = NULL"),
            ("not_attempted", "target_rejection = 'unknown'"),
            ("apply_started", "target_uid = NULL"),
            ("apply_started", "target_uid = ''"),
            ("apply_started", "target_uid = 'other'"),
            ("apply_started", "target_uid = printf('%129s', 'x')"),
            ("apply_started", "apply_attempted = 0"),
            ("apply_started", "apply_attempted = 2"),
            ("apply_started", "apply_attempted = -1"),
            ("apply_started", "write_strategy = 'banana'"),
            ("apply_started", "requested_generation = 2"),
            ("apply_started", "apply_accepted = 0"),
            ("apply_started", "apply_accepted = 1"),
            ("apply_started", "apply_accepted = 2"),
            ("apply_started", "apply_accepted = -1"),
            ("receiver_observed", "result = NULL"),
            ("receiver_observed", "result = 'SUCCEEDED'"),
            ("receiver_observed", "result = 'FAILED'"),
            ("receiver_observed", "receipt_key_id = 'early-key'"),
            ("receiver_observed", "state = 'finalized'"),
            ("finalized", "receipt_bytes = X'00'"),
            ("finalized", "receipt_digest = NULL"),
            ("finalized", "receipt_bytes = NULL"),
            ("finalized", "receipt_key_id = NULL"),
            ("finalized", "receipt_key_id = 'bad key'"),
            ("finalized", "receipt_key_id = 'other-valid-key'"),
            ("finalized", "receipt_digest = '00'"),
            ("finalized", "receipt_bytes = zeroblob(16385)"),
            ("finalized", "available_replicas = 0"),
            ("finalized", "state = 'receipt_prepared'"),
            ("finalized", "state = 'receipt_written'"),
            ("requested", "apply_attempted = 1"),
            ("authorized", "apply_attempted = 1"),
            ("not_attempted", "apply_attempted = 1"),
            ("not_attempted", "apply_accepted = 0"),
            ("not_attempted", "receiver_uid = 'early'"),
            ("authorized", "receiver_uid = 'early'"),
            ("authorized", "result = 'FAILED'"),
            (
                "authorized",
                "write_strategy = 'conditional-strategic-merge-patch'",
            ),
            ("authorized", "preflight_uid = 'early'"),
            ("authorized", "approved_uid = NULL"),
            ("apply_started", "preflight_resource_version = 'other'"),
            ("authorized", "signed_authorization_grant = X'00'"),
        ];
        for (phase, assignment) in cases {
            let scratch = Scratch::new();
            let path = scratch.0.join("journal.sqlite3");
            let journal = open_scratch(&scratch);
            let history = History::new(
                History::kube("snapshot-op").request,
                Some(ApprovedTarget {
                    uid: "target-uid".into(),
                    resource_version: "target-rv".into(),
                }),
            );
            history.insert(&journal.connection, phase);
            assert_history(
                &journal.operation("snapshot-op").unwrap().unwrap(),
                &history,
                phase,
            );
            if matches!(assignment, "apply_accepted = 2" | "apply_accepted = -1") {
                journal
                    .connection
                    .execute(
                        "UPDATE kubernetes_image_operations SET apply_accepted = 0,
                     apply_resource_version = 'apply-rv'",
                        [],
                    )
                    .unwrap();
                assert!(journal.operation("snapshot-op").is_ok());
            }
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment}
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();
            if assignment == "receipt_bytes = X'00'" {
                journal
                    .connection
                    .execute(
                        "UPDATE kubernetes_image_operations SET receipt_digest = ?1",
                        [test_history::digest(&[0])],
                    )
                    .unwrap();
            }
            // The unauthenticated phase decoder does not own signed-grant custody.
            if !assignment.starts_with("signed_authorization_grant") {
                assert!(
                    journal.operation("snapshot-op").is_err(),
                    "{phase}: {assignment}"
                );
            }
            assert!(
                journal.authorized_operation(&history.authorized).is_err(),
                "{phase}: {assignment}"
            );
            assert!(
                journal
                    .retained_operation("snapshot-op", |bytes| history.authorize(bytes))
                    .is_err(),
                "{phase}: {assignment}"
            );
            let before = fs::read(&path).unwrap();
            assert!(
                Journal::validate_replacement(&path, &[history.authorized]).is_err(),
                "{phase}: {assignment}"
            );
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn independently_pinned_statement_detects_decoder_field_swap() {
        let scratch = Scratch::new();
        let mut journal = open_scratch(&scratch);
        let history = History::kube("projection-control");
        history.insert(&journal.connection, "receiver_observed");
        assert_eq!(
            journal.receipt_statement("projection-control").unwrap(),
            Some(history.statement.clone())
        );
        let control = StorageControl::default();
        control.seed_mapping(MappingDefect::ReaderReplicaSwap);
        journal.control_storage(control.clone());
        assert_ne!(
            journal.receipt_statement("projection-control").unwrap(),
            Some(history.statement)
        );
        assert_eq!(
            control.mapping_defect(),
            Some(MappingDefect::ReaderReplicaSwap)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one independent phase/target table binds the three public read methods"
    )]
    fn public_kubernetes_reads_preserve_literal_phase_targets_and_receipt_fields() {
        use test_history::{named_kube_row, trust};

        use crate::application::{
            ExecutionDisposition, ExecutionObservation, OperationReceipt, OperationStatus,
            ServiceApplication, ServiceConfiguration,
        };

        for approved in [false, true] {
            for (phase, result, expected_status) in [
                (
                    "requested",
                    OperationResult::Unknown,
                    OperationStatus::InProgress,
                ),
                (
                    "authorized",
                    OperationResult::Unknown,
                    OperationStatus::InProgress,
                ),
                (
                    "not_attempted",
                    OperationResult::Unknown,
                    OperationStatus::NotAttempted(TargetRejection::DeploymentNotFound),
                ),
                (
                    "apply_started",
                    OperationResult::Unknown,
                    OperationStatus::InProgress,
                ),
                (
                    "receiver_observed",
                    OperationResult::Unknown,
                    OperationStatus::InProgress,
                ),
                (
                    "finalized",
                    OperationResult::Unknown,
                    OperationStatus::Unknown,
                ),
                (
                    "finalized",
                    OperationResult::Succeeded,
                    OperationStatus::Succeeded,
                ),
                (
                    "finalized",
                    OperationResult::Failed,
                    OperationStatus::Failed,
                ),
            ] {
                let scratch = Scratch::new();
                let journal = open_scratch(&scratch);
                let target = ApprovedTarget {
                    uid: "target-uid".into(),
                    resource_version: "target-rv".into(),
                };
                let mut history = History::new(
                    History::kube("public-read").request,
                    approved.then_some(target.clone()),
                );
                if result != OperationResult::Unknown {
                    let s = &mut history.statement;
                    s.receiver_uid = Some("target-uid".into());
                    s.observed_image = Some(history.request.immutable_image_digest.clone());
                    s.observed_operation_marker = Some("public-read".into());
                    s.current_generation = Some(6);
                    s.requested_generation = Some(6);
                    s.observed_generation = Some(7);
                    s.desired_replicas = Some(3);
                    if result == OperationResult::Succeeded {
                        s.updated_replicas = Some(3);
                        s.available_replicas = Some(3);
                        s.unavailable_replicas = Some(0);
                        s.rollout_condition_type = Some("Available".into());
                        s.rollout_condition_status = Some("True".into());
                        s.rollout_condition_reason = Some("MinimumReplicasAvailable".into());
                    } else {
                        s.updated_replicas = Some(1);
                        s.available_replicas = Some(0);
                        s.unavailable_replicas = Some(3);
                    }
                    s.result = result;
                }
                history.insert(&journal.connection, phase);
                let before = named_kube_row(&journal.connection, "public-read");
                drop(journal);
                let control = StorageControl::default();
                let app = ServiceApplication::open_simulated(
                    ServiceConfiguration {
                        journal_path: scratch.0.join("journal.sqlite3"),
                        authorization_trust: vec![trust()],
                        approvals: vec![],
                    },
                    control.clone(),
                )
                .unwrap();
                let attempted =
                    matches!(phase, "apply_started" | "receiver_observed" | "finalized");
                let frozen = matches!(phase, "receiver_observed" | "finalized");
                let expected_targets = OperationTargets {
                    approved_target: approved.then_some(target.clone()),
                    attempt_target: attempted.then_some(target),
                    observed_target: if frozen {
                        Some(ObservedTarget {
                            uid: history.statement.receiver_uid.clone(),
                            resource_version: Some("receiver-rv".into()),
                        })
                    } else {
                        attempted.then_some(ObservedTarget {
                            uid: Some("target-uid".into()),
                            resource_version: Some("target-rv".into()),
                        })
                    },
                    git: None,
                };
                assert_eq!(
                    app.status("public-read").unwrap(),
                    (expected_status, expected_targets.clone())
                );
                let expected_disposition = if matches!(phase, "not_attempted" | "finalized") {
                    ExecutionDisposition::Complete
                } else {
                    ExecutionDisposition::ResumeRequired(None)
                };
                assert_eq!(
                    app.execution_status("public-read", ExecutionObservation::Unknown)
                        .unwrap(),
                    (expected_status, expected_targets, expected_disposition)
                );
                let expected_receipt = if phase == "finalized" {
                    let receipt = history.receipt();
                    OperationReceipt::Ready {
                        bytes: receipt.bytes,
                        sha256: receipt.digest,
                    }
                } else {
                    OperationReceipt::NotReady
                };
                assert_eq!(app.receipt("public-read").unwrap(), expected_receipt);
                let entries = app.history(None).unwrap();
                assert_eq!(entries.entries.len(), 1);
                assert_eq!(entries.entries[0].operation_id, "public-read");
                assert_eq!(entries.entries[0].status, app.status("public-read"));
                assert!(entries.next_cursor.is_none());
                assert!(
                    control.events().is_empty(),
                    "reads perform no durable transition"
                );
                drop(app);
                let reopened = open_scratch(&scratch);
                assert_eq!(named_kube_row(&reopened.connection, "public-read"), before);
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "candidate refusals and exact four-field finalization share one witness"
    )]
    fn receipt_commit_binds_candidate_and_expected_snapshot_without_changing_other_facts() {
        use test_history::named_kube_row;

        let scratch = Scratch::new();
        let foreign_scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let foreign_journal = open_scratch(&foreign_scratch);
        let history = History::kube("receipt-owner");
        let mut foreign = History::kube("receipt-owner");
        foreign.statement.available_replicas = Some(13);
        history.insert(&journal.connection, "receiver_observed");
        foreign.insert(&foreign_journal.connection, "receiver_observed");
        History::kube("untouched-receipt-peer").insert(&journal.connection, "finalized");
        let LoadedOperation::ReceiverObserved(operation) =
            journal.operation("receipt-owner").unwrap().unwrap()
        else {
            unreachable!()
        };
        let LoadedOperation::ReceiverObserved(foreign_operation) =
            foreign_journal.operation("receipt-owner").unwrap().unwrap()
        else {
            unreachable!()
        };
        assert_eq!(operation.statement(), &history.statement);
        assert_eq!(foreign_operation.statement(), &foreign.statement);
        let before = named_kube_row(&journal.connection, "receipt-owner");
        let peer_before = named_kube_row(&journal.connection, "untouched-receipt-peer");
        let foreign_candidate = ReceiptToPrepare {
            receipt: foreign.receipt(),
        };
        assert!(matches!(
            journal.commit_receipt(&operation, &foreign_candidate),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert!(matches!(
            journal.commit_receipt(&foreign_operation, &foreign_candidate),
            Err(GatewayError::InvalidTransition)
        ));
        for field in ["identity", "digest", "key"] {
            let mut receipt = history.receipt();
            let error = match field {
                "identity" => {
                    receipt.operation_id = "another-operation".into();
                    GatewayError::InvalidTransition
                },
                "digest" => {
                    receipt.digest = "0".repeat(64);
                    GatewayError::InvalidPersistedState
                },
                "key" => {
                    receipt.key_id = "another-key".into();
                    GatewayError::InvalidPersistedState
                },
                _ => unreachable!(),
            };
            let result = journal.commit_receipt(&operation, &ReceiptToPrepare { receipt });
            assert_eq!(
                std::mem::discriminant(&result.unwrap_err()),
                std::mem::discriminant(&error)
            );
            assert_eq!(named_kube_row(&journal.connection, "receipt-owner"), before);
            assert_eq!(
                named_kube_row(&journal.connection, "untouched-receipt-peer"),
                peer_before
            );
        }
        let receipt = history.receipt();
        journal
            .commit_receipt(
                &operation,
                &ReceiptToPrepare {
                    receipt: receipt.clone(),
                },
            )
            .unwrap();
        let mut expected = before;
        expected.insert(
            "state".into(),
            rusqlite::types::Value::Text("finalized".into()),
        );
        expected.insert("receipt_digest".into(), receipt.digest.into());
        expected.insert("receipt_bytes".into(), receipt.bytes.into());
        expected.insert("receipt_key_id".into(), receipt.key_id.into());
        assert_eq!(
            named_kube_row(&journal.connection, "receipt-owner"),
            expected
        );
        assert!(matches!(
            journal.commit_receipt(&operation, &foreign_candidate),
            Err(GatewayError::InvalidTransition)
        ));
        assert_eq!(
            named_kube_row(&journal.connection, "receipt-owner"),
            expected
        );
        assert_eq!(
            named_kube_row(&journal.connection, "untouched-receipt-peer"),
            peer_before
        );
        drop(journal);
        let reopened = open_scratch(&scratch);
        assert_eq!(
            named_kube_row(&reopened.connection, "receipt-owner"),
            expected
        );
        assert_eq!(
            reopened.receipt_statement("receipt-owner").unwrap(),
            Some(history.statement)
        );
        assert_eq!(
            named_kube_row(&reopened.connection, "untouched-receipt-peer"),
            peer_before
        );
    }

    #[test]
    fn kubernetes_sqlite_bridge_consumes_all_seven_writes_under_three_deliveries() {
        let mut consumed = 0;
        for write in [
            StorageWrite::Admission,
            StorageWrite::Authorization,
            StorageWrite::Rejection,
            StorageWrite::Attempt,
            StorageWrite::Response,
            StorageWrite::Observation,
            StorageWrite::Receipt,
        ] {
            for delivery in [
                Delivery::Confirmed,
                Delivery::NoCommit,
                Delivery::LostAcknowledgement,
            ] {
                kube_sqlite_bridge(write, delivery);
                consumed += 1;
            }
        }
        assert_eq!(consumed, 21);
        eprintln!("KAPSEL_SQLITE_DELIVERIES Kubernetes consumed={consumed}");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "seven independent rows each bind one write, without history suffixes"
    )]
    pub(super) fn kube_sqlite_bridge(
        write: StorageWrite,
        delivery: Delivery,
    ) -> Vec<(StorageWrite, String)> {
        use test_history::{git_binding, insert_git_phase, named_git_row, named_kube_row};

        use crate::gateway::{Gateway, ReceiptSettings};

        let scratch = Scratch::new();
        let expected_scratch = Scratch::new();
        let mut journal = open_scratch(&scratch);
        let expected_journal = open_scratch(&expected_scratch);
        let mut history = History::kube("sqlite-bridge");
        history.statement.requested_generation = None;
        let (prior, next) = match write {
            StorageWrite::Admission => (None, "requested"),
            StorageWrite::Authorization => (Some("requested"), "authorized"),
            StorageWrite::Rejection => (Some("authorized"), "not_attempted"),
            StorageWrite::Attempt => (Some("authorized"), "apply_started"),
            StorageWrite::Response => (Some("apply_started"), "apply_started"),
            StorageWrite::Observation => (Some("apply_started"), "receiver_observed"),
            StorageWrite::Receipt => (Some("receiver_observed"), "finalized"),
        };
        if let Some(prior) = prior {
            history.insert(&journal.connection, prior);
            history.insert(&expected_journal.connection, prior);
            assert_history(
                &journal.operation("sqlite-bridge").unwrap().unwrap(),
                &history,
                prior,
            );
        }
        let peer = History::kube("untouched-peer");
        peer.insert(&journal.connection, "finalized");
        let peer_before = named_kube_row(&journal.connection, "untouched-peer");
        let git_peer = git_binding("untouched-git-peer");
        let git_phase = insert_git_phase(&journal.connection, &git_peer, "finalized");
        assert_eq!(journal.git_operation(&git_peer).unwrap(), Some(git_phase));
        let git_peer_before = named_git_row(&journal.connection, "untouched-git-peer");
        let before = named_kube_row(&journal.connection, "sqlite-bridge");
        assert_eq!(
            before,
            named_kube_row(&expected_journal.connection, "sqlite-bridge")
        );
        expected_journal
            .connection
            .execute(
                "DELETE FROM kubernetes_image_operations WHERE operation_id = 'sqlite-bridge'",
                [],
            )
            .unwrap();
        history.insert(&expected_journal.connection, next);
        if write == StorageWrite::Response {
            expected_journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations SET apply_accepted = 1,
                 requested_generation = 17, apply_resource_version = 'apply:0023'
                 WHERE operation_id = 'sqlite-bridge'",
                    [],
                )
                .unwrap();
        }
        let next_row = named_kube_row(&expected_journal.connection, "sqlite-bridge");
        assert!(!next_row.is_empty());
        assert_ne!(before, next_row, "the targeted write changes facts");
        let operation = journal.operation("sqlite-bridge").unwrap();
        let control = StorageControl::default();
        control.fail_next(write, delivery);
        journal.control_storage(control.clone());
        let result = match (write, operation) {
            (StorageWrite::Admission, None) => journal.insert_requested(&history.authorized),
            (StorageWrite::Authorization, Some(LoadedOperation::Requested(op))) => {
                journal.mark_authorized(&op, &history.authorized)
            },
            (StorageWrite::Rejection, Some(LoadedOperation::Authorized(op))) => {
                journal.mark_not_attempted(&op, TargetRejection::DeploymentNotFound)
            },
            (StorageWrite::Attempt, Some(LoadedOperation::Authorized(op))) => journal
                .begin_attempt(
                    &op,
                    ValidatedTargetIdentity::try_from(TargetIdentity {
                        deployment_uid: "target-uid".into(),
                        resource_version: "target-rv".into(),
                    })
                    .unwrap(),
                    None,
                )
                .map(|permission| assert!(permission.is_some())),
            (StorageWrite::Response, Some(LoadedOperation::ApplyStarted(op))) => journal
                .record_apply_outcome(
                    &op,
                    &ApplyOutcome {
                        accepted: true,
                        requested_generation: Some(17),
                        deployment_uid: Some("target-uid".into()),
                        resource_version: Some("apply:0023".into()),
                    },
                ),
            (StorageWrite::Observation, Some(LoadedOperation::ApplyStarted(op))) => journal
                .freeze_observation(
                    &op,
                    &ReceiverObservation {
                        deployment_uid: Some("receiver-uid".into()),
                        image: Some(format!(
                            "registry.example/receiver@sha256:{}",
                            "1".repeat(64)
                        )),
                        operation_marker: Some("receiver-marker".into()),
                        current_generation: Some(7),
                        observed_generation: Some(5),
                        resource_version: Some("receiver-rv".into()),
                        desired_replicas: Some(5),
                        updated_replicas: Some(3),
                        available_replicas: Some(2),
                        unavailable_replicas: Some(1),
                        rollout_condition_type: Some("Progressing".into()),
                        rollout_condition_status: Some("False".into()),
                        rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
                    },
                ),
            (StorageWrite::Receipt, Some(LoadedOperation::ReceiverObserved(op))) => {
                let candidate = Gateway::build_receipt(
                    &op,
                    &ReceiptSettings {
                        signing_seed: &[9; 32],
                        key_id: "snapshot-receipt-key",
                    },
                )
                .unwrap();
                journal.commit_receipt(&op, &candidate)
            },
            _ => unreachable!("independently authored bridge phase did not reach {write:?}"),
        };
        match delivery {
            Delivery::Confirmed => assert!(result.is_ok(), "{write:?}: {result:?}"),
            Delivery::NoCommit | Delivery::LostAcknowledgement => {
                assert!(matches!(result, Err(GatewayError::InjectedFault)));
            },
        }
        let events = control.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.operation_id, "sqlite-bridge");
        assert_eq!(event.effect, "Kubernetes");
        assert_eq!(event.write, write);
        assert_eq!(event.delivery, delivery);
        assert!(event.consumed, "targeted write must consume its delivery");
        let expected = if delivery == Delivery::NoCommit {
            before
        } else {
            next_row
        };
        assert_eq!(
            named_kube_row(&journal.connection, "sqlite-bridge"),
            expected
        );
        assert_eq!(
            named_kube_row(&journal.connection, "untouched-peer"),
            peer_before
        );
        let sql = control.executed_sql();
        assert_eq!(sql.len(), 1, "one actually executed SQL statement");
        assert_eq!(sql[0].0, write);
        drop(journal);
        let reopened = open_scratch(&scratch);
        assert_eq!(
            named_kube_row(&reopened.connection, "sqlite-bridge"),
            expected
        );
        assert_eq!(
            named_kube_row(&reopened.connection, "untouched-peer"),
            peer_before
        );
        assert_eq!(
            named_git_row(&reopened.connection, "untouched-git-peer"),
            git_peer_before
        );
        sql
    }

    #[test]
    fn observation_writers_bind_named_sql_and_reopened_statements_to_independent_inputs() {
        for variant in [0, 1, 17, 127] {
            for response in [false, true] {
                observation_mapping(
                    variant,
                    false,
                    response,
                    OperationResult::Unknown,
                    None,
                    None,
                );
                for result in [
                    OperationResult::Unknown,
                    OperationResult::Succeeded,
                    OperationResult::Failed,
                ] {
                    observation_mapping(variant, true, response, result, None, None);
                }
            }
        }
        // Condition type/status form a required pair; reason alone may be absent.
        for absent in [
            "uid",
            "image",
            "marker",
            "current",
            "observed",
            "version",
            "desired",
            "updated",
            "available",
            "unavailable",
            "condition",
            "reason",
        ] {
            observation_mapping(17, true, true, OperationResult::Unknown, Some(absent), None);
        }
        for defect in [
            MappingDefect::WriterReplicaSwap,
            MappingDefect::ReaderReplicaSwap,
            MappingDefect::WriterReaderReplicaSwap,
            MappingDefect::GenerationSwap,
            MappingDefect::NullableDrop,
        ] {
            observation_mapping(17, true, true, OperationResult::Unknown, None, Some(defect));
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "independent recipes bind named SQL, complete reopened facts and public reads"
    )]
    pub(super) fn observation_mapping(
        variant: i32,
        present: bool,
        response: bool,
        result: OperationResult,
        absent: Option<&str>,
        defect: Option<MappingDefect>,
    ) -> Vec<(StorageWrite, String)> {
        use test_history::named_kube_row;

        use crate::application::{
            ExecutionDisposition, ExecutionObservation, OperationReceipt, OperationStatus,
            ServiceApplication, ServiceConfiguration,
        };

        let scratch = Scratch::new();
        let expected_scratch = Scratch::new();
        let mut journal = open_scratch(&scratch);
        let expected_journal = open_scratch(&expected_scratch);
        let target_uid = format!("attempt-uid-{variant}");
        let target_version = format!("attempt:version-{variant}");
        let approved = ApprovedTarget {
            uid: target_uid.clone(),
            resource_version: target_version.clone(),
        };
        let request = SetDeploymentImageRequest {
            operation_id: format!("mapped-operation-{variant}"),
            namespace: format!("namespace-{variant}"),
            deployment: format!("deployment-{variant}"),
            container: format!("container-{variant}"),
            immutable_image_digest: format!("registry.example/request@sha256:{variant:064x}"),
        };
        let mut history = History::with_authority(
            request,
            Some(approved.clone()),
            &format!("approval-{variant}"),
            "snapshot-signer",
        );
        let id = history.request.operation_id.clone();
        history.statement.target_uid.clone_from(&target_uid);
        history
            .statement
            .target_resource_version
            .clone_from(&target_version);
        let peer = History::kube("untouched-peer");
        peer.insert(&journal.connection, "finalized");
        let peer_before = named_kube_row(&journal.connection, "untouched-peer");
        history.insert(&journal.connection, "apply_started");
        let LoadedOperation::ApplyStarted(operation) = journal.operation(&id).unwrap().unwrap()
        else {
            unreachable!()
        };
        let requested = response.then_some(i64::from(11 + variant));
        if response {
            journal
                .record_apply_outcome(
                    &operation,
                    &ApplyOutcome {
                        accepted: true,
                        requested_generation: requested,
                        deployment_uid: Some(target_uid.clone()),
                        resource_version: Some(format!("apply-version-{variant}")),
                    },
                )
                .unwrap();
        }
        // Foreign receiver facts establish UNKNOWN independently of numeric values. The
        // conclusive recipes explicitly supply correlated identity, generation and conditions.
        let mut observation = ReceiverObservation {
            deployment_uid: present.then(|| format!("receiver-uid-{variant}")),
            image: present.then(|| format!("registry.example/receiver@sha256:{}", "1".repeat(64))),
            operation_marker: present.then(|| format!("receiver-marker-{variant}")),
            current_generation: present.then_some(i64::from(101 + variant)),
            observed_generation: present.then_some(i64::from(211 + variant)),
            resource_version: present.then(|| format!("receiver-version-{variant}")),
            desired_replicas: present.then_some(3 + variant),
            updated_replicas: present.then_some(5 + variant),
            available_replicas: present.then_some(7 + variant),
            unavailable_replicas: present.then_some(11 + variant),
            rollout_condition_type: present.then(|| "Progressing".into()),
            rollout_condition_status: present.then(|| "False".into()),
            rollout_condition_reason: present.then(|| "ProgressDeadlineExceeded".into()),
        };
        if result != OperationResult::Unknown {
            observation.deployment_uid = Some(target_uid.clone());
            observation.image = Some(history.request.immutable_image_digest.clone());
            observation.operation_marker = Some(id.clone());
            observation.current_generation = Some(i64::from(11 + variant));
            observation.observed_generation = Some(i64::from(19 + variant));
            if result == OperationResult::Succeeded {
                observation.updated_replicas = observation.desired_replicas;
                observation.available_replicas = observation.desired_replicas;
                observation.unavailable_replicas = Some(0);
                observation.rollout_condition_type = Some("Available".into());
                observation.rollout_condition_status = Some("True".into());
                observation.rollout_condition_reason = Some("MinimumReplicasAvailable".into());
            }
        }
        match absent {
            None => {},
            Some("uid") => observation.deployment_uid = None,
            Some("image") => observation.image = None,
            Some("marker") => observation.operation_marker = None,
            Some("current") => observation.current_generation = None,
            Some("observed") => observation.observed_generation = None,
            Some("version") => observation.resource_version = None,
            Some("desired") => observation.desired_replicas = None,
            Some("updated") => observation.updated_replicas = None,
            Some("available") => observation.available_replicas = None,
            Some("unavailable") => observation.unavailable_replicas = None,
            Some("condition") => {
                observation.rollout_condition_type = None;
                observation.rollout_condition_status = None;
                observation.rollout_condition_reason = None;
            },
            Some("reason") => observation.rollout_condition_reason = None,
            Some(_) => unreachable!("fixed optional-field catalogue"),
        }
        let s = &mut history.statement;
        s.receiver_uid = observation.deployment_uid.clone();
        s.observed_image = observation.image.clone();
        s.observed_operation_marker = observation.operation_marker.clone();
        s.current_generation = observation.current_generation;
        s.requested_generation = if result == OperationResult::Unknown {
            requested
        } else {
            Some(i64::from(11 + variant))
        };
        s.observed_generation = observation.observed_generation;
        s.observed_resource_version = observation.resource_version.clone();
        s.desired_replicas = observation.desired_replicas;
        s.updated_replicas = observation.updated_replicas;
        s.available_replicas = observation.available_replicas;
        s.unavailable_replicas = observation.unavailable_replicas;
        s.rollout_condition_type = observation.rollout_condition_type.clone();
        s.rollout_condition_status = observation.rollout_condition_status.clone();
        s.rollout_condition_reason = observation.rollout_condition_reason.clone();
        s.result = result;
        history.insert(&expected_journal.connection, "receiver_observed");
        if response {
            expected_journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations SET apply_accepted = 1,
                 apply_resource_version = ?1 WHERE operation_id = ?2",
                    [format!("apply-version-{variant}"), id.clone()],
                )
                .unwrap();
        }
        assert_eq!(
            expected_journal.receipt_statement(&id).unwrap(),
            Some(history.statement.clone()),
            "independently authored expected row is valid"
        );
        let LoadedOperation::ApplyStarted(operation) = journal.operation(&id).unwrap().unwrap()
        else {
            unreachable!()
        };
        let control = StorageControl::default();
        if let Some(defect) = defect {
            control.seed_mapping(defect);
        }
        journal.control_storage(control.clone());
        journal
            .freeze_observation(&operation, &observation)
            .unwrap();
        let actual = named_kube_row(&journal.connection, &id);
        let expected = named_kube_row(&expected_journal.connection, &id);
        let mapped = journal.receipt_statement(&id).unwrap();
        if let Some(defect) = defect {
            assert!(actual != expected || mapped != Some(history.statement.clone()));
            assert_eq!(control.mapping_defect(), Some(defect));
            if defect == MappingDefect::WriterReaderReplicaSwap {
                assert_eq!(
                    mapped,
                    Some(history.statement.clone()),
                    "round trip hides the swap"
                );
                assert_ne!(actual, expected, "named SQL detects coordinated swaps");
            }
        } else {
            assert_eq!(actual, expected, "complete named row");
            assert_eq!(
                mapped,
                Some(history.statement.clone()),
                "complete statement"
            );
            let loaded = journal.operation(&id).unwrap().unwrap();
            assert_eq!(loaded.state(), OperationState::ReceiverObserved);
            assert_eq!(loaded.result(), Some(result));
            assert_eq!(
                loaded.request_facts().request.to_adapter_request(),
                history.request
            );
            let expected_targets = OperationTargets {
                approved_target: Some(approved.clone()),
                observed_target: Some(ObservedTarget {
                    uid: observation.deployment_uid.clone(),
                    resource_version: observation.resource_version,
                }),
                attempt_target: Some(approved),
                git: None,
            };
            assert_eq!(loaded.targets(), expected_targets);
            drop(journal);
            let reopened = open_scratch(&scratch);
            assert_eq!(
                reopened.receipt_statement(&id).unwrap(),
                Some(history.statement),
                "reopened complete statement"
            );
            assert_eq!(
                reopened.operation(&id).unwrap().unwrap().targets(),
                expected_targets,
                "reopened target projection"
            );
            drop(reopened);
            let app = ServiceApplication::open_simulated(
                ServiceConfiguration {
                    journal_path: scratch.0.join("journal.sqlite3"),
                    authorization_trust: vec![test_history::trust()],
                    approvals: vec![],
                },
                control.clone(),
            )
            .unwrap();
            let reads_before = control.events();
            assert_eq!(
                app.status(&id).unwrap(),
                (OperationStatus::InProgress, expected_targets.clone())
            );
            assert_eq!(
                app.execution_status(&id, ExecutionObservation::Unknown)
                    .unwrap(),
                (
                    OperationStatus::InProgress,
                    expected_targets,
                    ExecutionDisposition::ResumeRequired(None),
                )
            );
            assert_eq!(
                app.admitted_state(&id).unwrap(),
                Some(OperationState::ReceiverObserved)
            );
            assert_eq!(app.receipt(&id).unwrap(), OperationReceipt::NotReady);
            assert_eq!(
                control.events(),
                reads_before,
                "public reads perform no writes"
            );
            drop(app);
            let reopened = open_scratch(&scratch);
            assert_eq!(named_kube_row(&reopened.connection, &id), expected);
            assert_eq!(
                named_kube_row(&reopened.connection, "untouched-peer"),
                peer_before
            );
        }
        control.executed_sql()
    }

    #[test]
    fn apply_response_requires_matching_complete_identity_and_preserves_previous_facts() {
        let scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let history = History::kube("snapshot-op");
        history.insert(&journal.connection, "apply_started");
        let LoadedOperation::ApplyStarted(mut operation) =
            journal.operation("snapshot-op").unwrap().unwrap()
        else {
            unreachable!()
        };
        let before = stored_rows(&journal.connection);
        for (uid, version) in [
            (None, Some("apply-rv")),
            (Some("target-uid"), None),
            (Some("other-uid"), Some("apply-rv")),
        ] {
            assert!(matches!(
                journal.record_apply_outcome(
                    &operation,
                    &ApplyOutcome {
                        accepted: true,
                        requested_generation: Some(6),
                        deployment_uid: uid.map(str::to_owned),
                        resource_version: version.map(str::to_owned),
                    }
                ),
                Err(GatewayError::InvalidKubernetesFact)
            ));
            assert_eq!(stored_rows(&journal.connection), before);
        }
        for (accepted, generation) in [(false, None), (true, Some(6))] {
            journal
                .record_apply_outcome(
                    &operation,
                    &ApplyOutcome {
                        accepted,
                        requested_generation: generation,
                        deployment_uid: Some("target-uid".into()),
                        resource_version: Some("apply-rv".into()),
                    },
                )
                .unwrap();
            let LoadedOperation::ApplyStarted(loaded) =
                journal.operation("snapshot-op").unwrap().unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                loaded.classification_outcome(),
                ApplyOutcome {
                    accepted,
                    requested_generation: generation,
                    deployment_uid: Some("target-uid".into()),
                    resource_version: Some("apply-rv".into()),
                }
            );
            operation = loaded;
        }
    }

    #[test]
    fn authorized_snapshot_holds_receipt_and_custody_in_one_sqlite_read_view() {
        for phase in ["requested", "finalized"] {
            let scratch = Scratch::new();
            let journal = open_scratch(&scratch);
            let history = History::kube("snapshot-op");
            assert_eq!(
                journal.existing_submission(&history.authorized).unwrap(),
                None
            );
            history.insert(&journal.connection, phase);
            let other = open_scratch(&scratch);
            other.connection.busy_timeout(Duration::ZERO).unwrap();
            let snapshot =
                journal
                    .authorized_operation_with(&history.authorized, || {
                        let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations SET signed_authorization_grant = X'00',
                     receipt_bytes = X'01' WHERE operation_id = ?1", ["snapshot-op"]);
                        assert_eq!(
                            result.unwrap_err().sqlite_error_code(),
                            Some(rusqlite::ErrorCode::DatabaseBusy)
                        );
                    })
                    .unwrap()
                    .unwrap();
            assert_history(&snapshot, &history, phase);
            other
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations
                SET signed_authorization_grant = X'00' WHERE operation_id = ?1",
                    ["snapshot-op"],
                )
                .unwrap();
            assert!(matches!(
                journal.existing_submission(&history.authorized),
                Err(GatewayError::OperationIdentityConflict)
            ));
        }
    }
}
