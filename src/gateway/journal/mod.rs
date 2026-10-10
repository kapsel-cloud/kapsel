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

use std::{
    fs::{File, TryLockError},
    path::Path,
    sync::{Arc, Mutex},
};

use records::Record;
pub(crate) use records::Write as StorageWrite;
#[cfg(test)]
pub(crate) use records::{Control as StorageControl, Defect, Delivery};
#[cfg(test)]
use rusqlite::{params, OptionalExtension};
use rusqlite::{Connection, Transaction, TransactionBehavior};

#[cfg(test)]
use super::ReceiptReference;
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
    #[cfg(test)]
    pub(crate) fn request_for_test(&self) -> SetDeploymentImageRequest {
        self.request.to_adapter_request()
    }

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

    #[cfg(test)]
    pub(crate) fn receipt_reference(&self) -> Option<ReceiptReference> {
        match self {
            Self::Finalized(value) => Some(ReceiptReference {
                digest: value.receipt().digest.clone(),
            }),
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

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are one persisted fact group"
)]
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
    pub(in crate::gateway) fn target_rejection(
        &self,
        operation_id: &str,
    ) -> Result<Option<TargetRejection>, GatewayError> {
        self.connection
            .query_row(
                "SELECT target_rejection
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2",
                params![operation_id, OperationState::NotAttempted.as_sql()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .map(|value| TargetRejection::from_sql(&value))
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

    #[cfg(test)]
    pub(in crate::gateway) fn receipt_reference(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptReference>, GatewayError> {
        Ok(self
            .operation(operation_id)?
            .and_then(|op| op.receipt_reference()))
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
        let available_replicas = if self.exercise_defect(Defect::ReplicaSwap) {
            observation.updated_replicas
        } else {
            available_replicas
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
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::gateway::{
        receipt::sign_statement, sign_authorization_grant, verify_authorization_grant,
        AuthorizationTrust, ExactAuthorization,
    };

    fn journal(name: &str) -> (Journal, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-journal-snapshot-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let journal = Journal::open(root.join("journal.sqlite3")).unwrap();
        (journal, root)
    }

    fn snapshot_statement() -> ReceiptStatement {
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        ReceiptStatement {
            approved_target: None,
            operation_id: "snapshot-op".into(),
            authorization_id: "snapshot-auth".into(),
            authorization_signer_key_id: "snapshot-signer".into(),
            authorization_grant_digest:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: image.into(),
            write_strategy: WRITE_STRATEGY.into(),
            target_uid: "target-uid".into(),
            target_resource_version: "target-rv".into(),
            receiver_uid: Some("target-uid".into()),
            observed_image: Some(image.into()),
            observed_operation_marker: Some("snapshot-op".into()),
            current_generation: Some(2),
            requested_generation: Some(2),
            observed_generation: Some(2),
            observed_resource_version: Some("receiver-rv".into()),
            desired_replicas: Some(1),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            unavailable_replicas: Some(0),
            rollout_condition_type: Some("Available".into()),
            rollout_condition_status: Some("True".into()),
            rollout_condition_reason: Some("MinimumReplicasAvailable".into()),
            result: OperationResult::Succeeded,
        }
    }

    fn insert_snapshot_row(
        journal: &Journal,
        state: &str,
        result: Option<&str>,
        rejection: Option<&str>,
        receipt: bool,
    ) {
        let authorized = state != "requested";
        let attempted = matches!(
            state,
            "apply_started"
                | "receiver_observed"
                | "receipt_prepared"
                | "receipt_written"
                | "finalized"
        );
        let observed = matches!(
            state,
            "receiver_observed" | "receipt_prepared" | "receipt_written" | "finalized"
        );
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let statement = snapshot_statement();
        let receipt_bytes =
            sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key").unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        journal
            .connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container,
                    immutable_image_digest, state, result, target_rejection,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, write_strategy, apply_attempted,
                    target_uid, target_resource_version, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, requested_generation,
                    observed_generation, receiver_resource_version, desired_replicas,
                    updated_replicas, available_replicas, unavailable_replicas,
                    rollout_condition_type, rollout_condition_status,
                    rollout_condition_reason, receipt_digest,
                    receipt_bytes, receipt_key_id
                 ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                           ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                           ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                           ?27, ?28, ?29)",
                params![
                    "snapshot-op",
                    image,
                    state,
                    result,
                    rejection,
                    authorized.then_some("snapshot-auth"),
                    authorized.then_some("snapshot-signer"),
                    authorized.then_some(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    ),
                    attempted.then_some(WRITE_STRATEGY),
                    attempted,
                    attempted.then_some("target-uid"),
                    attempted.then_some("target-rv"),
                    observed.then_some("target-uid"),
                    observed.then_some(image),
                    observed.then_some("snapshot-op"),
                    observed.then_some(2_i64),
                    observed.then_some(2_i64),
                    observed.then_some(2_i64),
                    observed.then_some("receiver-rv"),
                    observed.then_some(1_i32),
                    observed.then_some(1_i32),
                    observed.then_some(1_i32),
                    observed.then_some(0_i32),
                    observed.then_some("Available"),
                    observed.then_some("True"),
                    observed.then_some("MinimumReplicasAvailable"),
                    receipt.then_some(receipt_digest),
                    receipt.then_some(receipt_bytes),
                    receipt.then_some("snapshot-receipt-key"),
                ],
            )
            .unwrap();
    }

    #[test]
    fn persisted_operation_decoder_builds_exact_variant_for_every_legal_phase() {
        for (state, result, rejection, receipt) in [
            ("requested", None, None, false),
            ("authorized", None, None, false),
            ("not_attempted", None, Some("deployment_not_found"), false),
            ("apply_started", None, None, false),
            ("receiver_observed", Some("SUCCEEDED"), None, false),
            ("finalized", Some("SUCCEEDED"), None, true),
        ] {
            let (journal, root) = journal(&format!("legal-{state}"));
            insert_snapshot_row(&journal, state, result, rejection, receipt);
            let operation = journal.operation("snapshot-op").unwrap().unwrap();
            let exact_variant = matches!(
                (state, &operation),
                ("requested", LoadedOperation::Requested(_))
                    | ("authorized", LoadedOperation::Authorized(_))
                    | ("not_attempted", LoadedOperation::NotAttempted(_))
                    | ("apply_started", LoadedOperation::ApplyStarted(_))
                    | ("receiver_observed", LoadedOperation::ReceiverObserved(_))
                    | ("finalized", LoadedOperation::Finalized(_))
            );
            assert!(exact_variant, "{state}");
            assert_eq!(
                operation.request_facts().request.operation_id(),
                "snapshot-op"
            );

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_missing_required_phase_facts() {
        for (name, state, result, rejection, receipt, assignment) in [
            (
                "requested-invalid-request",
                "requested",
                None,
                None,
                false,
                "namespace = 'Uppercase'",
            ),
            (
                "authorized-missing-authorization",
                "authorized",
                None,
                None,
                false,
                "authorization_id = NULL",
            ),
            (
                "not-attempted-missing-rejection",
                "not_attempted",
                None,
                Some("deployment_not_found"),
                false,
                "target_rejection = NULL",
            ),
            (
                "apply-started-missing-attempt",
                "apply_started",
                None,
                None,
                false,
                "target_uid = NULL",
            ),
            (
                "receiver-observed-missing-result",
                "receiver_observed",
                Some("SUCCEEDED"),
                None,
                false,
                "result = NULL",
            ),
            (
                "receipt-prepared-missing-receipt",
                "receipt_prepared",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_bytes = NULL",
            ),
            (
                "receipt-written-missing-receipt",
                "receipt_written",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_digest = NULL",
            ),
            (
                "finalized-missing-receipt",
                "finalized",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_bytes = NULL",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, receipt);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{name}");

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_facts_before_their_phase() {
        for (name, state, result, rejection, assignment) in [
            (
                "attempt-before-apply",
                "authorized",
                None,
                None,
                concat!(
                    "write_strategy = 'conditional-strategic-merge-patch', ",
                    "apply_attempted = 1, target_uid = 'uid', ",
                    "target_resource_version = 'rv'"
                ),
            ),
            (
                "receiver-before-observed",
                "authorized",
                None,
                None,
                "receiver_uid = 'uid'",
            ),
            (
                "receipt-before-prepared",
                "receiver_observed",
                Some("SUCCEEDED"),
                None,
                "receipt_key_id = 'early-key'",
            ),
            (
                "rejection-and-receiver-result",
                "not_attempted",
                Some("UNKNOWN"),
                Some("deployment_not_found"),
                "receiver_uid = 'uid'",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, false);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{name}");

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_marker_only_pre_attempt_rows() {
        for (state, rejection) in [
            ("requested", None),
            ("authorized", None),
            ("not_attempted", Some("deployment_not_found")),
        ] {
            let (journal, root) = journal(&format!("marker-only-{state}"));
            insert_snapshot_row(&journal, state, None, rejection, false);
            journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations SET apply_attempted = 1
                     WHERE operation_id = ?1",
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{state}");

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_noncanonical_write_strategy() {
        let (journal, root) = journal("noncanonical-write-strategy");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET write_strategy = 'banana'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();

        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persisted_operation_decoder_rejects_nonbinary_boolean_columns() {
        for (name, assignment) in [
            ("attempt-positive", "apply_attempted = 2"),
            ("attempt-negative", "apply_attempted = -1"),
            (
                "accepted-positive",
                "apply_accepted = 2, apply_resource_version = 'apply-rv'",
            ),
            (
                "accepted-negative",
                "apply_accepted = -1, apply_resource_version = 'apply-rv'",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "apply_started", None, None, false);
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

            assert!(journal.operation("snapshot-op").is_err(), "{name}");

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_requires_complete_apply_response_facts() {
        for accepted in [false, true] {
            let (journal, root) = journal(if accepted {
                "accepted-response-no-version"
            } else {
                "rejected-response-no-version"
            });
            insert_snapshot_row(&journal, "apply_started", None, None, false);
            journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations
                     SET apply_accepted = ?1, requested_generation = 2
                     WHERE operation_id = ?2",
                    params![accepted, "snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err());

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("complete-rejected-response");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = 0, apply_resource_version = 'apply-rv'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();
        assert!(matches!(
            journal.operation("snapshot-op").unwrap(),
            Some(LoadedOperation::ApplyStarted(_))
        ));
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_apply_outcome_requires_complete_matching_response_identity() {
        let (journal, root) = journal("provider-response-identity");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        let loaded = journal.operation("snapshot-op").unwrap().unwrap();
        assert!(matches!(&loaded, LoadedOperation::ApplyStarted(_)));
        let LoadedOperation::ApplyStarted(operation) = loaded else {
            return;
        };
        for outcome in [
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: None,
                resource_version: Some("apply-rv".into()),
            },
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("target-uid".into()),
                resource_version: None,
            },
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("other-uid".into()),
                resource_version: Some("apply-rv".into()),
            },
        ] {
            assert!(matches!(
                journal.record_apply_outcome(&operation, &outcome),
                Err(GatewayError::InvalidKubernetesFact)
            ));
        }
        let retained_response: (Option<bool>, Option<i64>, Option<String>) = journal
            .connection
            .query_row(
                "SELECT apply_accepted, requested_generation, apply_resource_version
                 FROM kubernetes_image_operations WHERE operation_id = ?1",
                ["snapshot-op"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(retained_response, (None, None, None));

        journal
            .record_apply_outcome(
                &operation,
                &ApplyOutcome {
                    accepted: false,
                    requested_generation: None,
                    deployment_uid: Some("target-uid".into()),
                    resource_version: Some("apply-rv".into()),
                },
            )
            .unwrap();
        assert!(matches!(
            journal.operation("snapshot-op").unwrap(),
            Some(LoadedOperation::ApplyStarted(_))
        ));
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_rejects_incoherent_public_facts() {
        for (name, state, result, rejection, receipt) in [
            ("finalized-no-result", "finalized", None, None, true),
            (
                "not-attempted-no-rejection",
                "not_attempted",
                None,
                None,
                false,
            ),
            (
                "active-with-terminal-facts",
                "authorized",
                Some("SUCCEEDED"),
                Some("deployment_not_found"),
                false,
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, receipt);

            assert!(journal.operation("snapshot-op").is_err());

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn loaded_operation_requires_complete_valid_frozen_receipt_facts() {
        for (name, assignment) in [
            ("missing-digest", "receipt_digest = NULL"),
            ("missing-bytes", "receipt_bytes = NULL"),
            ("missing-key", "receipt_key_id = NULL"),
            (
                "missing-tuple",
                "receipt_digest = NULL, receipt_bytes = NULL, \
                 receipt_key_id = NULL",
            ),
            ("bad-key", "receipt_key_id = 'bad key'"),
            ("bad-digest", "receipt_digest = '00'"),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
            let update = format!(
                "UPDATE kubernetes_image_operations SET {assignment} \
                 WHERE operation_id = ?1"
            );
            journal
                .connection
                .execute(&update, ["snapshot-op"])
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err());

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("oversized-receipt");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET receipt_bytes = ?1 \
                 WHERE operation_id = ?2",
                params![vec![0_u8; RECEIPT_BYTES_MAX + 1], "snapshot-op"],
            )
            .unwrap();
        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_binds_receiver_facts_and_receipt_envelope() {
        for (name, assignment) in [
            ("result-tamper", "result = 'FAILED'"),
            ("classifier-tamper", "available_replicas = 0"),
            ("key-tamper", "receipt_key_id = 'other-valid-key'"),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err());

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("non-receipt-bytes");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        let bytes = b"not-a-receipt";
        let digest = publication::receipt_digest_hex(bytes);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET receipt_digest = ?1, receipt_bytes = ?2
                 WHERE operation_id = ?3",
                params![digest, bytes.as_slice(), "snapshot-op"],
            )
            .unwrap();
        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorized_snapshot_holds_one_sqlite_read_view() {
        let (journal, root) = journal("atomic-authorization");
        let request = SetDeploymentImageRequest {
            operation_id: "snapshot-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        };
        let authorization = ExactAuthorization {
            approved_target: None,
            authorization_id: "snapshot-auth".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        };
        let signed =
            sign_authorization_grant(&authorization, &[7_u8; 32], "snapshot-signer").unwrap();
        let verified = verify_authorization_grant(
            &signed,
            &AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        let authorized =
            AuthorizedRequest::bind(ValidatedRequest::try_from(&request).unwrap(), verified)
                .unwrap();
        assert_eq!(journal.authorized_operation(&authorized).unwrap(), None);
        assert_eq!(journal.existing_submission(&authorized).unwrap(), None);
        journal.insert_requested(&authorized).unwrap();
        assert_eq!(
            journal.existing_submission(&authorized).unwrap(),
            Some(OperationState::Requested)
        );
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();
        other.connection.busy_timeout(Duration::ZERO).unwrap();

        let snapshot = journal
            .authorized_operation_with(&authorized, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET signed_authorization_grant = ?1
                     WHERE operation_id = ?2",
                    params![b"changed-custody".as_slice(), "snapshot-op"],
                );
                assert_eq!(
                    result.unwrap_err().sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
            })
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.state(), OperationState::Requested);
        assert_eq!(
            journal.existing_submission(&authorized).unwrap(),
            Some(snapshot.state())
        );
        other
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET signed_authorization_grant = ?1
             WHERE operation_id = ?2",
                params![b"changed-custody".as_slice(), "snapshot-op"],
            )
            .unwrap();
        assert!(matches!(
            journal.existing_submission(&authorized),
            Err(GatewayError::OperationIdentityConflict)
        ));

        drop(other);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorized_finalized_snapshot_freezes_receipt_and_ownership_together() {
        let (journal, root) = journal("atomic-finalized-receipt");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        let request = SetDeploymentImageRequest {
            operation_id: "snapshot-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        };
        let authorization = ExactAuthorization {
            approved_target: None,
            authorization_id: "snapshot-auth".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        };
        let signed =
            sign_authorization_grant(&authorization, &[7_u8; 32], "snapshot-signer").unwrap();
        let verified = verify_authorization_grant(
            &signed,
            &AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        let mut statement = snapshot_statement();
        statement.authorization_grant_digest = verified.grant_digest.clone();
        let receipt_bytes =
            sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key").unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET authorization_grant_digest = ?1,
                     receipt_digest = ?2, receipt_bytes = ?3, signed_authorization_grant = ?5
                 WHERE operation_id = ?4",
                params![
                    verified.grant_digest,
                    receipt_digest,
                    receipt_bytes,
                    "snapshot-op",
                    signed
                ],
            )
            .unwrap();
        let authorized =
            AuthorizedRequest::bind(ValidatedRequest::try_from(&request).unwrap(), verified)
                .unwrap();
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();
        other.connection.busy_timeout(Duration::ZERO).unwrap();

        let snapshot = journal
            .authorized_operation_with(&authorized, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET authorization_id = 'other-auth', receipt_bytes = ?1
                     WHERE operation_id = ?2",
                    params![b"replacement".as_slice(), "snapshot-op"],
                );
                assert_eq!(
                    result.unwrap_err().sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
            })
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.state(), OperationState::Finalized);
        assert_eq!(
            journal.existing_submission(&authorized).unwrap(),
            Some(snapshot.state())
        );
        let receipt = snapshot.frozen_receipt().unwrap();
        assert_eq!(receipt.bytes, receipt_bytes);
        assert_eq!(receipt.digest, receipt_digest);
        assert_eq!(
            publication::receipt_digest_hex(&receipt.bytes),
            receipt.digest
        );

        drop(other);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_requires_state_local_authorization_and_attempt_facts() {
        for (name, state, assignment) in [
            (
                "authorized-no-auth",
                "authorized",
                "authorization_id = NULL",
            ),
            ("apply-no-marker", "apply_started", "apply_attempted = 0"),
            ("apply-no-target", "apply_started", "target_uid = NULL"),
            ("apply-empty-target", "apply_started", "target_uid = ''"),
            (
                "apply-partial-outcome",
                "apply_started",
                "requested_generation = 2",
            ),
            (
                "not-attempted-apply-fact",
                "not_attempted",
                "apply_accepted = 0",
            ),
            (
                "not-attempted-receiver-fact",
                "not_attempted",
                "receiver_uid = 'unexpected'",
            ),
            ("observed-no-result", "receiver_observed", "result = NULL"),
        ] {
            let (journal, root) = journal(name);
            let result = (state == "receiver_observed").then_some("SUCCEEDED");
            insert_snapshot_row(&journal, state, result, None, false);
            let update = format!(
                "UPDATE kubernetes_image_operations SET {assignment} \
                 WHERE operation_id = ?1"
            );
            journal
                .connection
                .execute(&update, ["snapshot-op"])
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{name}");

            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (oversized_journal, root) = journal("apply-oversized-target");
        insert_snapshot_row(&oversized_journal, "apply_started", None, None, false);
        oversized_journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET target_uid = ?1
                 WHERE operation_id = ?2",
                params!["x".repeat(129), "snapshot-op"],
            )
            .unwrap();
        assert!(oversized_journal.operation("snapshot-op").is_err());
        drop(oversized_journal);
        fs::remove_dir_all(root).unwrap();

        let (outcome_journal, root) = journal("apply-complete-outcome");
        insert_snapshot_row(&outcome_journal, "apply_started", None, None, false);
        outcome_journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = 1, requested_generation = 2,
                     apply_resource_version = 'apply-rv'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();
        assert_eq!(
            outcome_journal
                .operation("snapshot-op")
                .unwrap()
                .unwrap()
                .state(),
            OperationState::ApplyStarted
        );
        drop(outcome_journal);
        fs::remove_dir_all(root).unwrap();
    }
}
