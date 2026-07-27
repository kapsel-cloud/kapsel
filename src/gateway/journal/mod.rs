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

use rusqlite::{params, Connection, OptionalExtension};

use super::{
    authorization::VerifiedAuthorization,
    kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity},
    receipt::{publication, ReceiptStatement, RECEIPT_BYTES_MAX},
    validate_identity, FrozenReceipt, GatewayError, InputField, OperationResult, OperationState,
    ReceiptReference, SetDeploymentImageRequest, TargetRejection,
};

pub(crate) const OPERATION_COUNT_MAX: i64 = 10_000;
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
        let existing = self
            .connection
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
                || authorization_signer_key_id.as_deref()
                    != Some(authorization.signer_key_id.as_str())
                || authorization_grant_digest.as_deref()
                    != Some(authorization.grant_digest.as_str()))
        {
            return Err(GatewayError::OperationIdentityConflict);
        }
        Ok(Some(state))
    }

    pub(in crate::gateway) fn insert_requested(
        &self,
        request: &SetDeploymentImageRequest,
    ) -> Result<(), GatewayError> {
        let operation_count = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM kubernetes_image_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(GatewayError::Database)?;
        if operation_count >= OPERATION_COUNT_MAX {
            return Err(GatewayError::JournalFull);
        }
        self.connection
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
        Ok(())
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

    pub(in crate::gateway) fn operation_snapshot(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationSnapshot>, GatewayError> {
        let row = self
            .connection
            .query_row(
                "SELECT state, result, target_rejection, receipt_path, receipt_digest
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(GatewayError::Database)?;
        let Some((state, result, rejection, receipt_path, receipt_digest)) = row else {
            return Ok(None);
        };
        let state = OperationState::from_sql(&state)?;
        let result = result
            .map(|value| OperationResult::from_sql(&value))
            .transpose()?;
        let target_rejection = rejection
            .map(|value| TargetRejection::from_sql(&value))
            .transpose()?;
        let receipt = if state == OperationState::Finalized {
            match (receipt_path, receipt_digest) {
                (Some(path), Some(digest)) => Some(ReceiptReference {
                    path: PathBuf::from(path),
                    digest,
                }),
                _ => return Err(GatewayError::InvalidPersistedState),
            }
        } else {
            None
        };
        Ok(Some(OperationSnapshot {
            state,
            result,
            target_rejection,
            receipt,
        }))
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
        self.connection
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
                 WHERE operation_id = ?1 AND state IN (?2, ?3, ?4)",
                params![
                    operation_id,
                    OperationState::ReceiverObserved.as_sql(),
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
            OperationState::ReceiptPrepared | OperationState::ReceiptWritten
        ) {
            return Err(GatewayError::InvalidPersistedState);
        }
        let receipt = self
            .connection
            .query_row(
                "SELECT operation_id, receipt_path, receipt_digest, receipt_bytes,
                        receipt_key_id
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2",
                params![operation_id, state.as_sql()],
                |row| {
                    Ok(FrozenReceipt {
                        operation_id: row.get(0)?,
                        path: PathBuf::from(row.get::<_, String>(1)?),
                        digest: row.get(2)?,
                        bytes: row.get(3)?,
                        key_id: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(GatewayError::Database)?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        if receipt.bytes.len() > RECEIPT_BYTES_MAX
            || publication::receipt_digest_hex(&receipt.bytes) != receipt.digest
        {
            return Err(GatewayError::ReceiptDigestMismatch);
        }
        validate_identity(InputField::AuthorizationId, &receipt.key_id)
            .map_err(|_| GatewayError::InvalidPersistedState)?;
        Ok(Some(receipt))
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
        Ok(ReceiptStatement {
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
        })
    }
}

fn changed_one(changed: usize) -> Result<(), GatewayError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(GatewayError::InvalidTransition)
    }
}
