//! Private durable representation for KAP-0038 operations.
//!
//! This deep module owns row decoding, capacity enforcement, worker locking, snapshots, and guarded
//! transitions. Private children concentrate exact schema/migration and owner-private opening,
//! backup, and rollback-file behavior without creating a selectable storage interface.

mod opening;
mod schema;

use std::{
    fs::{File, TryLockError},
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::{
    authorization::VerifiedAuthorization,
    kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity},
    receipt::{decode_frozen_receipt, publication, ReceiptStatement, RECEIPT_BYTES_MAX},
    validate_identity, FrozenReceipt, GatewayError, InputField, OperationResult, OperationState,
    ReceiptReference, SetDeploymentImageRequest, TargetRejection, WRITE_STRATEGY,
};

pub(crate) const OPERATION_COUNT_MAX: i64 = 10_000;

#[cfg(test)]
pub(crate) fn qualification_storage_limits() -> (usize, i32, u64) {
    (
        schema::PERSISTED_VALUE_BYTES_MAX,
        schema::PERSISTED_ROW_BYTES_MAX,
        opening::ROLLBACK_JOURNAL_BYTES_MAX,
    )
}

pub(crate) struct Journal {
    pub(crate) connection: Connection,
    worker_lock: File,
}

pub(crate) struct WorkerLock<'a> {
    file: &'a File,
}

pub(crate) struct OperationSnapshot {
    pub(crate) state: OperationState,
    pub(crate) result: Option<OperationResult>,
    pub(crate) target_rejection: Option<TargetRejection>,
    pub(crate) receipt: Option<ReceiptReference>,
    pub(crate) frozen_receipt: Option<FrozenReceipt>,
}

struct SnapshotRow {
    state: String,
    result: Option<String>,
    target_rejection: Option<String>,
    authorization_id: Option<String>,
    authorization_signer_key_id: Option<String>,
    authorization_grant_digest: Option<String>,
    write_strategy: Option<String>,
    apply_attempted: bool,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    apply_accepted: Option<bool>,
    requested_generation: Option<i64>,
    apply_resource_version: Option<String>,
    receiver_facts_present: bool,
    receipt_path: Option<String>,
    receipt_digest: Option<String>,
    receipt_bytes: Option<Vec<u8>>,
    receipt_key_id: Option<String>,
}

impl SnapshotRow {
    fn into_snapshot(
        self,
        operation_id: &str,
        statement: Option<&ReceiptStatement>,
    ) -> Result<OperationSnapshot, GatewayError> {
        let state = OperationState::from_sql(&self.state)?;
        let result = self
            .result
            .map(|value| OperationResult::from_sql(&value))
            .transpose()?;
        let target_rejection = self
            .target_rejection
            .map(|value| TargetRejection::from_sql(&value))
            .transpose()?;
        let authorization_present = validate_snapshot_authorization(
            self.authorization_id,
            self.authorization_signer_key_id,
            self.authorization_grant_digest,
        )?;
        let (target_present, apply_facts_present) = validate_snapshot_attempt_facts(
            state,
            self.write_strategy,
            self.target_uid,
            self.target_resource_version,
            self.apply_accepted,
            self.requested_generation,
            self.apply_resource_version,
        )?;
        if statement.map(|value| value.result) != result {
            return Err(GatewayError::InvalidPersistedState);
        }
        let frozen_receipt = snapshot_frozen_receipt(
            operation_id,
            self.receipt_path,
            self.receipt_digest,
            self.receipt_bytes,
            self.receipt_key_id,
            statement,
        )?;
        let facts = (u8::from(authorization_present) * SNAPSHOT_AUTHORIZATION)
            | (u8::from(self.apply_attempted) * SNAPSHOT_ATTEMPTED)
            | (u8::from(target_present) * SNAPSHOT_TARGET)
            | (u8::from(result.is_some()) * SNAPSHOT_RESULT)
            | (u8::from(target_rejection.is_some()) * SNAPSHOT_REJECTION)
            | (u8::from(frozen_receipt.is_some()) * SNAPSHOT_RECEIPT)
            | (u8::from(statement.is_some()) * SNAPSHOT_STATEMENT);
        if facts != expected_snapshot_facts(state)
            || (matches!(
                state,
                OperationState::Requested
                    | OperationState::Authorized
                    | OperationState::NotAttempted
            ) && (apply_facts_present || self.receiver_facts_present))
            || (state == OperationState::ApplyStarted && self.receiver_facts_present)
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        let receipt = if state == OperationState::Finalized {
            frozen_receipt.as_ref().map(|receipt| ReceiptReference {
                path: receipt.path.clone(),
                digest: receipt.digest.clone(),
            })
        } else {
            None
        };
        Ok(OperationSnapshot {
            state,
            result,
            target_rejection,
            receipt,
            frozen_receipt,
        })
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
) -> Result<(bool, bool), GatewayError> {
    let target = match (write_strategy, target_uid, target_resource_version) {
        (Some(strategy), Some(deployment_uid), Some(resource_version))
            if strategy == WRITE_STRATEGY =>
        {
            let target = TargetIdentity {
                deployment_uid,
                resource_version,
            };
            target
                .validate()
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            Some(target)
        },
        (None, None, None) => None,
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    let apply_facts_present = apply_accepted.is_some()
        || requested_generation.is_some()
        || apply_resource_version.is_some();
    if state == OperationState::ApplyStarted {
        match (apply_accepted, requested_generation, apply_resource_version) {
            (None, None, None) => {},
            (Some(accepted), requested_generation, apply_resource_version) => {
                let target = target.as_ref().ok_or(GatewayError::InvalidPersistedState)?;
                ApplyOutcome {
                    accepted,
                    requested_generation,
                    deployment_uid: Some(target.deployment_uid.clone()),
                    resource_version: apply_resource_version
                        .or_else(|| Some(target.resource_version.clone())),
                }
                .validate()
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            },
            _ => return Err(GatewayError::InvalidPersistedState),
        }
    }
    Ok((target.is_some(), apply_facts_present))
}

impl Drop for WorkerLock<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
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
            Self::ReceiptPrepared => "receipt_prepared",
            Self::ReceiptWritten => "receipt_written",
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
            "receipt_prepared" => Ok(Self::ReceiptPrepared),
            "receipt_written" => Ok(Self::ReceiptWritten),
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
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "deployment_not_found" => Ok(Self::DeploymentNotFound),
            "container_not_found" => Ok(Self::ContainerNotFound),
            "invalid_target" => Ok(Self::InvalidTarget),
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
    pub(in crate::gateway) fn open(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        let opening::OpenedJournal {
            connection,
            worker_lock,
        } = opening::open_journal(path.as_ref())?;
        Ok(Self {
            connection,
            worker_lock,
        })
    }

    pub(in crate::gateway) fn try_lock_worker(
        &self,
    ) -> Result<Option<WorkerLock<'_>>, GatewayError> {
        match self.worker_lock.try_lock() {
            Ok(()) => Ok(Some(WorkerLock {
                file: &self.worker_lock,
            })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(GatewayError::WorkerLock(error)),
        }
    }

    pub(in crate::gateway) fn existing_submission(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &VerifiedAuthorization,
    ) -> Result<Option<OperationState>, GatewayError> {
        existing_submission_on(&self.connection, request, authorization)
    }

    pub(in crate::gateway) fn authorized_operation_snapshot(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &VerifiedAuthorization,
    ) -> Result<Option<OperationSnapshot>, GatewayError> {
        self.authorized_operation_snapshot_with(request, authorization, || {})
    }

    fn authorized_operation_snapshot_with(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &VerifiedAuthorization,
        after_ownership_read: impl FnOnce(),
    ) -> Result<Option<OperationSnapshot>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        if existing_submission_on(&transaction, request, authorization)?.is_none() {
            return Ok(None);
        }
        after_ownership_read();
        operation_snapshot_on(&transaction, &request.operation_id)
    }

    pub(in crate::gateway) fn insert_requested(
        &self,
        request: &SetDeploymentImageRequest,
    ) -> Result<(), GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(GatewayError::Database)?;
        let operation_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM kubernetes_image_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(GatewayError::Database)?;
        if operation_count >= OPERATION_COUNT_MAX {
            return Err(GatewayError::JournalFull);
        }
        transaction
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container,
                    immutable_image_digest, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.operation_id,
                    request.namespace,
                    request.deployment,
                    request.container,
                    request.immutable_image_digest,
                    OperationState::Requested.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        transaction.commit().map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn mark_authorized(
        &self,
        operation_id: &str,
        authorization: &VerifiedAuthorization,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, authorization_id = ?2,
                     authorization_signer_key_id = ?3, authorization_grant_digest = ?4
                 WHERE operation_id = ?5 AND state = ?6",
                params![
                    OperationState::Authorized.as_sql(),
                    authorization.authorization.authorization_id,
                    authorization.signer_key_id,
                    authorization.grant_digest,
                    operation_id,
                    OperationState::Requested.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
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
    pub(in crate::gateway) fn operation_snapshot(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationSnapshot>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        operation_snapshot_on(&transaction, operation_id)
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

    pub(in crate::gateway) fn receipt_statement(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptStatement>, GatewayError> {
        receipt_statement_on(&self.connection, operation_id)
    }

    pub(in crate::gateway) fn prepare_receipt(
        &self,
        receipt: &FrozenReceipt,
    ) -> Result<(), GatewayError> {
        let path = receipt
            .path
            .to_str()
            .ok_or(GatewayError::ReceiptPublication)?;
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, receipt_path = ?2, receipt_digest = ?3,
                     receipt_bytes = ?4, receipt_key_id = ?5
                 WHERE operation_id = ?6 AND state = ?7",
                params![
                    OperationState::ReceiptPrepared.as_sql(),
                    path,
                    receipt.digest,
                    receipt.bytes,
                    receipt.key_id,
                    receipt.operation_id,
                    OperationState::ReceiverObserved.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_receipt_written(
        &self,
        operation_id: &str,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1
                 WHERE operation_id = ?2 AND state = ?3
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL
                       AND receipt_bytes IS NOT NULL AND receipt_key_id IS NOT NULL",
                params![
                    OperationState::ReceiptWritten.as_sql(),
                    operation_id,
                    OperationState::ReceiptPrepared.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn frozen_receipt_for(
        &self,
        operation_id: &str,
        state: OperationState,
    ) -> Result<Option<FrozenReceipt>, GatewayError> {
        if !matches!(
            state,
            OperationState::ReceiptPrepared
                | OperationState::ReceiptWritten
                | OperationState::Finalized
        ) {
            return Err(GatewayError::InvalidPersistedState);
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        let snapshot = snapshot_row_on(&transaction, operation_id)?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        if OperationState::from_sql(&snapshot.state)? != state {
            return Ok(None);
        }
        let statement = receipt_statement_on(&transaction, operation_id)?;
        let receipt = snapshot_frozen_receipt(
            operation_id,
            snapshot.receipt_path,
            snapshot.receipt_digest,
            snapshot.receipt_bytes,
            snapshot.receipt_key_id,
            statement.as_ref(),
        )?;
        if receipt.is_none() {
            return Err(GatewayError::InvalidPersistedState);
        }
        Ok(receipt)
    }

    pub(in crate::gateway) fn mark_finalized(
        &self,
        operation_id: &str,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1
                 WHERE operation_id = ?2 AND state = ?3
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL
                       AND receipt_bytes IS NOT NULL AND receipt_key_id IS NOT NULL",
                params![
                    OperationState::Finalized.as_sql(),
                    operation_id,
                    OperationState::ReceiptWritten.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    #[cfg(test)]
    pub(in crate::gateway) fn receipt_reference(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptReference>, GatewayError> {
        self.connection
            .query_row(
                "SELECT receipt_path, receipt_digest
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state IN (?2, ?3)
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL",
                params![
                    operation_id,
                    OperationState::ReceiptWritten.as_sql(),
                    OperationState::Finalized.as_sql(),
                ],
                |row| {
                    Ok(ReceiptReference {
                        path: PathBuf::from(row.get::<_, String>(0)?),
                        digest: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn next_request(
        &self,
        state: OperationState,
    ) -> Result<Option<SetDeploymentImageRequest>, GatewayError> {
        self.connection
            .query_row(
                "SELECT operation_id, namespace, deployment, container,
                        immutable_image_digest
                 FROM kubernetes_image_operations
                 WHERE state = ?1
                 ORDER BY CASE WHEN ?1 = 'authorized' THEN target_read_failures ELSE 0 END,
                          operation_id
                 LIMIT 1",
                [state.as_sql()],
                |row| {
                    Ok(SetDeploymentImageRequest {
                        operation_id: row.get(0)?,
                        namespace: row.get(1)?,
                        deployment: row.get(2)?,
                        container: row.get(3)?,
                        immutable_image_digest: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn request_in_state(
        &self,
        operation_id: &str,
        state: OperationState,
    ) -> Result<Option<SetDeploymentImageRequest>, GatewayError> {
        self.connection
            .query_row(
                "SELECT operation_id, namespace, deployment, container,
                        immutable_image_digest
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2",
                params![operation_id, state.as_sql()],
                |row| {
                    Ok(SetDeploymentImageRequest {
                        operation_id: row.get(0)?,
                        namespace: row.get(1)?,
                        deployment: row.get(2)?,
                        container: row.get(3)?,
                        immutable_image_digest: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn defer_target_retry(
        &self,
        operation_id: &str,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET target_read_failures = target_read_failures + 1
                 WHERE operation_id = ?1 AND state = ?2
                       AND target_read_failures < 9223372036854775807",
                params![operation_id, OperationState::Authorized.as_sql()],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_not_attempted(
        &self,
        operation_id: &str,
        rejection: TargetRejection,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, target_rejection = ?2, apply_attempted = 0
                 WHERE operation_id = ?3 AND state = ?4",
                params![
                    OperationState::NotAttempted.as_sql(),
                    rejection.as_sql(),
                    operation_id,
                    OperationState::Authorized.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_apply_started(
        &self,
        operation_id: &str,
        write_strategy: &str,
        target: &TargetIdentity,
    ) -> Result<(), GatewayError> {
        target.validate()?;
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, write_strategy = ?2, apply_attempted = 1,
                     target_uid = ?3, target_resource_version = ?4
                 WHERE operation_id = ?5 AND state = ?6",
                params![
                    OperationState::ApplyStarted.as_sql(),
                    write_strategy,
                    target.deployment_uid,
                    target.resource_version,
                    operation_id,
                    OperationState::Authorized.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn record_apply_outcome(
        &self,
        operation_id: &str,
        outcome: &ApplyOutcome,
    ) -> Result<(), GatewayError> {
        outcome.validate()?;
        let target_uid = self
            .connection
            .query_row(
                "SELECT target_uid
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2 AND apply_attempted = 1",
                params![operation_id, OperationState::ApplyStarted.as_sql()],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(GatewayError::Database)?;
        if target_uid.is_none()
            || outcome
                .deployment_uid
                .as_ref()
                .is_some_and(|uid| Some(uid) != target_uid.as_ref())
        {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = ?1, requested_generation = ?2,
                     apply_resource_version = ?3
                 WHERE operation_id = ?4 AND state = ?5 AND apply_attempted = 1",
                params![
                    outcome.accepted,
                    outcome.requested_generation,
                    outcome.resource_version,
                    operation_id,
                    OperationState::ApplyStarted.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn persisted_apply_outcome(
        &self,
        operation_id: &str,
    ) -> Result<ApplyOutcome, GatewayError> {
        self.connection
            .query_row(
                "SELECT apply_accepted, requested_generation, target_uid,
                        COALESCE(apply_resource_version, target_resource_version)
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2 AND apply_attempted = 1",
                params![operation_id, OperationState::ApplyStarted.as_sql()],
                |row| {
                    Ok(ApplyOutcome {
                        accepted: row.get::<_, Option<bool>>(0)?.unwrap_or(false),
                        requested_generation: row.get(1)?,
                        deployment_uid: row.get(2)?,
                        resource_version: row.get(3)?,
                    })
                },
            )
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn freeze_observation(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
        observation: &ReceiverObservation,
    ) -> Result<(), GatewayError> {
        observation.validate()?;
        let result = observation.classify(request, outcome);
        let requested_generation = observation.requested_generation(request, outcome);
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, receiver_uid = ?2, receiver_image = ?3,
                     receiver_operation_marker = ?4, current_generation = ?5,
                     observed_generation = ?6, receiver_resource_version = ?7,
                     desired_replicas = ?8, updated_replicas = ?9,
                     available_replicas = ?10, unavailable_replicas = ?11,
                     result = ?12, requested_generation = ?13,
                     rollout_condition_type = ?14, rollout_condition_status = ?15,
                     rollout_condition_reason = ?16
                 WHERE operation_id = ?17 AND state = ?18",
                params![
                    OperationState::ReceiverObserved.as_sql(),
                    observation.deployment_uid,
                    observation.image,
                    observation.operation_marker,
                    observation.current_generation,
                    observation.observed_generation,
                    observation.resource_version,
                    observation.desired_replicas,
                    observation.updated_replicas,
                    observation.available_replicas,
                    observation.unavailable_replicas,
                    result.as_sql(),
                    requested_generation,
                    observation.rollout_condition_type,
                    observation.rollout_condition_status,
                    observation.rollout_condition_reason,
                    request.operation_id,
                    OperationState::ApplyStarted.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }
}

const SNAPSHOT_AUTHORIZATION: u8 = 1 << 0;
const SNAPSHOT_ATTEMPTED: u8 = 1 << 1;
const SNAPSHOT_TARGET: u8 = 1 << 2;
const SNAPSHOT_RESULT: u8 = 1 << 3;
const SNAPSHOT_REJECTION: u8 = 1 << 4;
const SNAPSHOT_RECEIPT: u8 = 1 << 5;
const SNAPSHOT_STATEMENT: u8 = 1 << 6;

fn expected_snapshot_facts(state: OperationState) -> u8 {
    match state {
        OperationState::Requested => 0,
        OperationState::Authorized => SNAPSHOT_AUTHORIZATION,
        OperationState::NotAttempted => SNAPSHOT_AUTHORIZATION | SNAPSHOT_REJECTION,
        OperationState::ApplyStarted => {
            SNAPSHOT_AUTHORIZATION | SNAPSHOT_ATTEMPTED | SNAPSHOT_TARGET
        },
        OperationState::ReceiverObserved => {
            SNAPSHOT_AUTHORIZATION
                | SNAPSHOT_ATTEMPTED
                | SNAPSHOT_TARGET
                | SNAPSHOT_RESULT
                | SNAPSHOT_STATEMENT
        },
        OperationState::ReceiptPrepared
        | OperationState::ReceiptWritten
        | OperationState::Finalized => {
            SNAPSHOT_AUTHORIZATION
                | SNAPSHOT_ATTEMPTED
                | SNAPSHOT_TARGET
                | SNAPSHOT_RESULT
                | SNAPSHOT_RECEIPT
                | SNAPSHOT_STATEMENT
        },
    }
}

fn existing_submission_on(
    connection: &Connection,
    request: &SetDeploymentImageRequest,
    authorization: &VerifiedAuthorization,
) -> Result<Option<OperationState>, GatewayError> {
    let existing = connection
        .query_row(
            "SELECT namespace, deployment, container, immutable_image_digest,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, state
             FROM kubernetes_image_operations
             WHERE operation_id = ?1",
            [&request.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(GatewayError::Database)?;
    let Some((
        namespace,
        deployment,
        container,
        image,
        authorization_id,
        authorization_signer_key_id,
        authorization_grant_digest,
        state,
    )) = existing
    else {
        return Ok(None);
    };
    if namespace != request.namespace
        || deployment != request.deployment
        || container != request.container
        || image != request.immutable_image_digest
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let state = OperationState::from_sql(&state)?;
    if state != OperationState::Requested
        && (authorization_id.as_deref()
            != Some(authorization.authorization.authorization_id.as_str())
            || authorization_signer_key_id.as_deref() != Some(authorization.signer_key_id.as_str())
            || authorization_grant_digest.as_deref() != Some(authorization.grant_digest.as_str()))
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    Ok(Some(state))
}

fn snapshot_row_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<SnapshotRow>, GatewayError> {
    connection
        .query_row(
            "SELECT state, result, target_rejection,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, write_strategy, apply_attempted,
                    target_uid, target_resource_version, apply_accepted,
                    requested_generation, apply_resource_version,
                    receiver_uid IS NOT NULL OR receiver_image IS NOT NULL
                        OR receiver_operation_marker IS NOT NULL
                        OR current_generation IS NOT NULL
                        OR observed_generation IS NOT NULL
                        OR receiver_resource_version IS NOT NULL
                        OR desired_replicas IS NOT NULL
                        OR updated_replicas IS NOT NULL
                        OR available_replicas IS NOT NULL
                        OR unavailable_replicas IS NOT NULL
                        OR rollout_condition_type IS NOT NULL
                        OR rollout_condition_status IS NOT NULL
                        OR rollout_condition_reason IS NOT NULL,
                    receipt_path, receipt_digest, receipt_bytes, receipt_key_id
             FROM kubernetes_image_operations
             WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok(SnapshotRow {
                    state: row.get(0)?,
                    result: row.get(1)?,
                    target_rejection: row.get(2)?,
                    authorization_id: row.get(3)?,
                    authorization_signer_key_id: row.get(4)?,
                    authorization_grant_digest: row.get(5)?,
                    write_strategy: row.get(6)?,
                    apply_attempted: row.get(7)?,
                    target_uid: row.get(8)?,
                    target_resource_version: row.get(9)?,
                    apply_accepted: row.get(10)?,
                    requested_generation: row.get(11)?,
                    apply_resource_version: row.get(12)?,
                    receiver_facts_present: row.get(13)?,
                    receipt_path: row.get(14)?,
                    receipt_digest: row.get(15)?,
                    receipt_bytes: row.get(16)?,
                    receipt_key_id: row.get(17)?,
                })
            },
        )
        .optional()
        .map_err(GatewayError::Database)
}

fn receipt_statement_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ReceiptStatement>, GatewayError> {
    connection
        .query_row(
            "SELECT operation_id, authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, namespace, deployment, container,
                    immutable_image_digest, write_strategy, target_uid,
                    target_resource_version, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, requested_generation,
                    observed_generation, receiver_resource_version, desired_replicas,
                    updated_replicas, available_replicas, unavailable_replicas,
                    rollout_condition_type, rollout_condition_status,
                    rollout_condition_reason, result
             FROM kubernetes_image_operations
             WHERE operation_id = ?1 AND state IN (?2, ?3, ?4, ?5)",
            params![
                operation_id,
                OperationState::ReceiverObserved.as_sql(),
                OperationState::ReceiptPrepared.as_sql(),
                OperationState::ReceiptWritten.as_sql(),
                OperationState::Finalized.as_sql(),
            ],
            ReceiptRow::from_sql,
        )
        .optional()
        .map_err(GatewayError::Database)?
        .map(ReceiptRow::into_statement)
        .transpose()
}

fn operation_snapshot_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<OperationSnapshot>, GatewayError> {
    let Some(row) = snapshot_row_on(connection, operation_id)? else {
        return Ok(None);
    };
    let statement = receipt_statement_on(connection, operation_id)?;
    row.into_snapshot(operation_id, statement.as_ref())
        .map(Some)
}

fn validate_snapshot_authorization(
    authorization_id: Option<String>,
    signer_key_id: Option<String>,
    grant_digest: Option<String>,
) -> Result<bool, GatewayError> {
    match (authorization_id, signer_key_id, grant_digest) {
        (None, None, None) => Ok(false),
        (Some(authorization_id), Some(signer_key_id), Some(grant_digest)) => {
            validate_identity(InputField::AuthorizationId, &authorization_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            validate_identity(InputField::AuthorizationId, &signer_key_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            if grant_digest.len() != 64
                || !grant_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(GatewayError::InvalidPersistedState);
            }
            Ok(true)
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn snapshot_frozen_receipt(
    operation_id: &str,
    path: Option<String>,
    digest: Option<String>,
    bytes: Option<Vec<u8>>,
    key_id: Option<String>,
    statement: Option<&ReceiptStatement>,
) -> Result<Option<FrozenReceipt>, GatewayError> {
    match (path, digest, bytes, key_id) {
        (None, None, None, None) => Ok(None),
        (Some(path), Some(digest), Some(bytes), Some(key_id)) => {
            let receipt = validate_frozen_receipt(FrozenReceipt {
                operation_id: operation_id.to_owned(),
                path: PathBuf::from(path),
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
    let expected_name = publication::receipt_filename(&receipt.operation_id, &receipt.digest);
    if !receipt.path.is_absolute()
        || receipt.path.file_name() != Some(expected_name.as_ref())
        || receipt.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(receipt)
}

struct ReceiptRow {
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
    fn from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            authorization_id: row.get(1)?,
            authorization_signer_key_id: row.get(2)?,
            authorization_grant_digest: row.get(3)?,
            namespace: row.get(4)?,
            deployment: row.get(5)?,
            container: row.get(6)?,
            immutable_image_digest: row.get(7)?,
            write_strategy: row.get(8)?,
            target_uid: row.get(9)?,
            target_resource_version: row.get(10)?,
            receiver_uid: row.get(11)?,
            observed_image: row.get(12)?,
            observed_operation_marker: row.get(13)?,
            current_generation: row.get(14)?,
            requested_generation: row.get(15)?,
            observed_generation: row.get(16)?,
            observed_resource_version: row.get(17)?,
            desired_replicas: row.get(18)?,
            updated_replicas: row.get(19)?,
            available_replicas: row.get(20)?,
            unavailable_replicas: row.get(21)?,
            rollout_condition_type: row.get(22)?,
            rollout_condition_status: row.get(23)?,
            rollout_condition_reason: row.get(24)?,
            result: row.get(25)?,
        })
    }

    fn into_statement(self) -> Result<ReceiptStatement, GatewayError> {
        let statement = ReceiptStatement {
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
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::*;
    use crate::gateway::{
        sign_authorization_grant, verify_authorization_grant, ExactAuthorization,
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
            super::super::receipt::sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key")
                .unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        let receipt_path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &receipt_digest)
        );
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
                    rollout_condition_reason, receipt_path, receipt_digest,
                    receipt_bytes, receipt_key_id
                 ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                           ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                           ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                           ?27, ?28, ?29, ?30)",
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
                    receipt.then_some(receipt_path),
                    receipt.then_some(receipt_digest),
                    receipt.then_some(receipt_bytes),
                    receipt.then_some("snapshot-receipt-key"),
                ],
            )
            .unwrap();
    }

    #[test]
    fn operation_snapshot_rejects_incoherent_public_facts() {
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
            assert!(journal.operation_snapshot("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn operation_snapshot_requires_complete_valid_frozen_receipt_facts() {
        for (name, assignment) in [
            ("missing-path", "receipt_path = NULL"),
            ("missing-digest", "receipt_digest = NULL"),
            ("missing-bytes", "receipt_bytes = NULL"),
            ("missing-key", "receipt_key_id = NULL"),
            (
                "missing-tuple",
                "receipt_path = NULL, receipt_digest = NULL, receipt_bytes = NULL, \
                 receipt_key_id = NULL",
            ),
            ("bad-key", "receipt_key_id = 'bad key'"),
            ("bad-digest", "receipt_digest = '00'"),
            ("wrong-name", "receipt_path = '/private/wrong.receipt'"),
            ("relative-path", "receipt_path = 'relative.receipt'"),
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
            assert!(journal.operation_snapshot("snapshot-op").is_err());
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
        assert!(journal.operation_snapshot("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_snapshot_binds_receiver_facts_and_receipt_envelope() {
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
            assert!(journal.operation_snapshot("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("non-receipt-bytes");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        let bytes = b"not-a-receipt";
        let digest = publication::receipt_digest_hex(bytes);
        let path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &digest)
        );
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET receipt_path = ?1, receipt_digest = ?2, receipt_bytes = ?3
                 WHERE operation_id = ?4",
                params![path, digest, bytes.as_slice(), "snapshot-op"],
            )
            .unwrap();
        assert!(journal.operation_snapshot("snapshot-op").is_err());
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
            &super::super::AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        journal.insert_requested(&request).unwrap();
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();

        let snapshot = journal
            .authorized_operation_snapshot_with(&request, &verified, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET state = 'authorized', authorization_id = 'other-auth',
                         authorization_signer_key_id = 'other-signer',
                         authorization_grant_digest = ?1
                     WHERE operation_id = ?2",
                    params!["0".repeat(64), "snapshot-op"],
                );
                assert!(result.is_err());
            })
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.state, OperationState::Requested);

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
            &super::super::AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        let mut statement = snapshot_statement();
        statement.authorization_grant_digest = verified.grant_digest.clone();
        let receipt_bytes =
            super::super::receipt::sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key")
                .unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        let receipt_path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &receipt_digest)
        );
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET authorization_grant_digest = ?1, receipt_path = ?2,
                     receipt_digest = ?3, receipt_bytes = ?4
                 WHERE operation_id = ?5",
                params![
                    verified.grant_digest,
                    receipt_path,
                    receipt_digest,
                    receipt_bytes,
                    "snapshot-op"
                ],
            )
            .unwrap();
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();

        let snapshot = journal
            .authorized_operation_snapshot_with(&request, &verified, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET authorization_id = 'other-auth', receipt_bytes = ?1
                     WHERE operation_id = ?2",
                    params![b"replacement".as_slice(), "snapshot-op"],
                );
                assert!(result.is_err());
            })
            .unwrap()
            .unwrap();
        let receipt = snapshot.frozen_receipt.unwrap();
        assert_ne!(receipt.bytes, b"replacement");
        assert_eq!(
            publication::receipt_digest_hex(&receipt.bytes),
            receipt.digest
        );

        drop(other);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_snapshot_requires_state_local_authorization_and_attempt_facts() {
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
            assert!(journal.operation_snapshot("snapshot-op").is_err());
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
        assert!(oversized_journal.operation_snapshot("snapshot-op").is_err());
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
                .operation_snapshot("snapshot-op")
                .unwrap()
                .unwrap()
                .state,
            OperationState::ApplyStarted
        );
        drop(outcome_journal);
        fs::remove_dir_all(root).unwrap();
    }
}
