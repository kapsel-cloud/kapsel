//! Private durable representation for KAP-0038 operations.
//!
//! This module owns SQLite schema, row decoding, capacity enforcement, and guarded transitions. It
//! is not a generic repository interface and is not exposed outside the effect-gateway crate.

use std::{
    fs::{self, File, TryLockError},
    io::{self, Read as _, Seek as _, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use rustix::fs::{open, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::{
    authorization::VerifiedAuthorization,
    kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity},
    receipt::{publication, ReceiptStatement, RECEIPT_BYTES_MAX},
    validate_identity, FrozenReceipt, GatewayError, InputField, OperationResult, OperationState,
    ReceiptReference, SetDeploymentImageRequest, TargetRejection,
};

pub(crate) const OPERATION_COUNT_MAX: i64 = 10_000;
const JOURNAL_FORMAT_VERSION: u32 = 2;
const SQLITE_HEADER_BYTES: usize = 100;
const SQLITE_USER_VERSION_OFFSET: usize = 60;
const BACKUP_SUFFIX: &str = ".kapsel-v011.backup";
const BACKUP_DIGEST_SUFFIX: &str = ".sha256";

const CURRENT_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "state",
    "write_strategy",
    "target_rejection",
    "target_read_failures",
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
    "available_condition",
    "progress_deadline_exceeded",
    "result",
    "receipt_path",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
];

const LEGACY_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "state",
    "write_strategy",
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
    "available_condition",
    "progress_deadline_exceeded",
    "result",
];

const MIGRATED_LEGACY_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "state",
    "write_strategy",
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
    "available_condition",
    "progress_deadline_exceeded",
    "result",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "target_rejection",
    "target_read_failures",
    "receipt_path",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
];

const CREATE_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    authorization_signer_key_id TEXT,
    authorization_grant_digest TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    target_rejection TEXT,
    target_read_failures INTEGER NOT NULL DEFAULT 0,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT,
    receipt_path TEXT,
    receipt_digest TEXT,
    receipt_bytes BLOB,
    receipt_key_id TEXT,
    rollout_condition_type TEXT,
    rollout_condition_status TEXT,
    rollout_condition_reason TEXT
) STRICT;";

const LEGACY_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT
) STRICT;";

const MIGRATED_LEGACY_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT,
    authorization_signer_key_id TEXT,
    authorization_grant_digest TEXT,
    target_rejection TEXT,
    target_read_failures INTEGER NOT NULL DEFAULT 0,
    receipt_path TEXT,
    receipt_digest TEXT,
    receipt_bytes BLOB,
    receipt_key_id TEXT,
    rollout_condition_type TEXT,
    rollout_condition_status TEXT,
    rollout_condition_reason TEXT
) STRICT;";

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
        let path = path.as_ref();
        require_private_parent(path).map_err(GatewayError::JournalFile)?;
        let mut database_file = open_private_file(path).map_err(GatewayError::JournalFile)?;
        let database_identity = database_file
            .metadata()
            .map_err(GatewayError::JournalFile)?;
        let fresh = database_identity.len() == 0;
        let initial_version = read_header_version(&mut database_file)?;
        if !fresh && initial_version != 0 && initial_version != JOURNAL_FORMAT_VERSION {
            return Err(GatewayError::UnsupportedJournalVersion);
        }
        recover_private_rollback_journal(path, &database_identity)?;
        let source_version = read_header_version(&mut database_file)?;
        if !fresh && source_version != 0 && source_version != JOURNAL_FORMAT_VERSION {
            return Err(GatewayError::UnsupportedJournalVersion);
        }
        let backup_digest = if !fresh && source_version == 0 {
            Some(verify_offline_backup(
                path,
                &mut database_file,
                &database_identity,
            )?)
        } else {
            None
        };
        #[cfg(test)]
        migration_recovery_process_loss_seam(source_version);

        let mut connection = Connection::open(path).map_err(GatewayError::Database)?;
        require_named_identity(path, &database_identity).map_err(GatewayError::JournalFile)?;
        require_private_parent(path).map_err(GatewayError::JournalFile)?;
        configure_durable_connection(&connection)?;
        let opened_version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .map_err(GatewayError::Database)?;
        if opened_version != source_version {
            return Err(GatewayError::InvalidPersistedState);
        }
        if fresh || source_version == 0 {
            initialize_journal(
                &mut connection,
                &mut database_file,
                fresh,
                backup_digest.as_deref(),
            )?;
        } else if !recognized_supported_schema(&connection)? {
            return Err(GatewayError::InvalidPersistedState);
        }

        let worker_lock_path = worker_lock_path(path);
        let worker_lock = open_private_file(&worker_lock_path).map_err(GatewayError::WorkerLock)?;
        let worker_lock_identity = worker_lock.metadata().map_err(GatewayError::WorkerLock)?;
        require_named_identity(&worker_lock_path, &worker_lock_identity)
            .map_err(GatewayError::WorkerLock)?;
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

fn configure_durable_connection(connection: &Connection) -> Result<(), GatewayError> {
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(GatewayError::Database)?;
    let journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(GatewayError::InvalidPersistedState);
    }
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(GatewayError::Database)?;
    let verified_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?;
    let synchronous = connection
        .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
        .map_err(GatewayError::Database)?;
    if !verified_mode.eq_ignore_ascii_case("delete") || synchronous != 2 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

fn initialize_journal(
    connection: &mut Connection,
    database_file: &mut File,
    fresh: bool,
    backup_digest: Option<&str>,
) -> Result<(), GatewayError> {
    #[cfg(test)]
    migration_process_loss_seam("before_exclusive_transaction");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(GatewayError::Database)?;
    if let Some(expected) = backup_digest {
        if digest_file(database_file).map_err(GatewayError::JournalBackup)? != expected {
            return Err(GatewayError::JournalBackupMismatch);
        }
        require_integrity(&transaction)?;
    }
    if fresh {
        transaction
            .execute_batch(CREATE_OPERATION_TABLE)
            .map_err(GatewayError::Database)?;
    } else if recognized_schema(&transaction, CURRENT_COLUMNS, CREATE_OPERATION_TABLE)? {
        // Exact v0.1.1 operation rows need no transformation.
    } else if recognized_schema(&transaction, LEGACY_COLUMNS, LEGACY_OPERATION_TABLE)? {
        migrate_receipt_schema(&transaction)?;
    } else {
        return Err(GatewayError::InvalidPersistedState);
    }
    transaction
        .pragma_update(None, "user_version", JOURNAL_FORMAT_VERSION)
        .map_err(GatewayError::Database)?;
    #[cfg(test)]
    force_hot_rollback_journal_for_process_loss(&transaction, database_file)?;
    #[cfg(test)]
    migration_process_loss_seam("marker_set_inside_exclusive_transaction");
    transaction.commit().map_err(GatewayError::Database)?;
    #[cfg(test)]
    migration_process_loss_seam("after_marker_commit");
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(GatewayError::Database)?;
    if version != JOURNAL_FORMAT_VERSION || !recognized_supported_schema(connection)? {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

#[cfg(test)]
fn force_hot_rollback_journal_for_process_loss(
    transaction: &Transaction<'_>,
    database_file: &mut File,
) -> Result<(), GatewayError> {
    use std::io::Write as _;
    if std::env::var("KAPSEL_KAP0060_MIGRATION_SEAM").as_deref()
        != Ok("marker_set_inside_exclusive_transaction")
    {
        return Ok(());
    }
    transaction
        .execute_batch(
            "PRAGMA cache_size = 1;
             PRAGMA cache_spill = ON;
             CREATE TABLE kap0060_hot_rollback_probe (
                 page INTEGER PRIMARY KEY,
                 payload BLOB NOT NULL
             ) STRICT;",
        )
        .map_err(GatewayError::Database)?;
    for page in 0..32 {
        transaction
            .execute(
                "INSERT INTO kap0060_hot_rollback_probe(page, payload)
                 VALUES (?1, zeroblob(8192))",
                [page],
            )
            .map_err(GatewayError::Database)?;
    }
    transaction.cache_flush().map_err(GatewayError::Database)?;
    // SQLite can keep page 1 pinned even after spilling the probe pages. This test-only write
    // materializes the transaction's already-selected marker bytes in that main-database page;
    // the hot journal still owns the original page and must restore marker 0 after process loss.
    database_file
        .seek(SeekFrom::Start(SQLITE_USER_VERSION_OFFSET as u64))
        .and_then(|_| database_file.write_all(&JOURNAL_FORMAT_VERSION.to_be_bytes()))
        .and_then(|()| database_file.sync_all())
        .and_then(|()| database_file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(GatewayError::JournalFile)
}

#[cfg(test)]
fn migration_recovery_process_loss_seam(source_version: u32) {
    if std::env::var_os("KAPSEL_KAP0060_RECOVERY_CHILD").is_none() {
        return;
    }
    assert_eq!(
        source_version, 0,
        "hot rollback must restore the old marker"
    );
    migration_ready_marker("KAPSEL_KAP0060_RECOVERY_READY", "hot_rollback_restored");
}

#[cfg(test)]
fn migration_process_loss_seam(selected: &str) {
    if std::env::var("KAPSEL_KAP0060_MIGRATION_SEAM").as_deref() != Ok(selected) {
        return;
    }
    migration_ready_marker("KAPSEL_KAP0060_MIGRATION_READY", selected);
}

#[cfg(test)]
fn migration_ready_marker(environment: &str, selected: &str) {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _, time::Duration};

    let ready = PathBuf::from(
        std::env::var_os(environment)
            .expect("the migration process-loss seam requires a ready path"),
    );
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&ready)
        .expect("the migration process-loss ready marker must be new");
    marker
        .write_all(selected.as_bytes())
        .expect("the migration process-loss marker must be writable");
    marker
        .sync_all()
        .expect("the migration process-loss marker must synchronize");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn require_integrity(transaction: &Transaction<'_>) -> Result<(), GatewayError> {
    let mut statement = transaction
        .prepare("PRAGMA integrity_check")
        .map_err(GatewayError::Database)?;
    let results = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)?;
    if results == ["ok"] {
        Ok(())
    } else {
        Err(GatewayError::InvalidPersistedState)
    }
}

fn recognized_supported_schema(connection: &Connection) -> Result<bool, GatewayError> {
    Ok(
        recognized_schema(connection, CURRENT_COLUMNS, CREATE_OPERATION_TABLE)?
            || recognized_schema(
                connection,
                MIGRATED_LEGACY_COLUMNS,
                MIGRATED_LEGACY_OPERATION_TABLE,
            )?,
    )
}

type SchemaEntry = (String, String, String, Option<String>);
type ColumnFact = (i64, String, String, i64, Option<String>, i64, i64);
type IndexFact = (i64, String, i64, String, i64);
type IndexColumnFact = (i64, i64, Option<String>, i64, String, i64);

fn schema_entries(connection: &Connection) -> Result<Vec<SchemaEntry>, GatewayError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             ORDER BY type, name",
        )
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn table_columns(connection: &Connection) -> Result<Vec<ColumnFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA table_xinfo(kubernetes_image_operations)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn table_indexes(connection: &Connection) -> Result<Vec<IndexFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA index_list(kubernetes_image_operations)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn primary_index_columns(connection: &Connection) -> Result<Vec<IndexColumnFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA index_xinfo(sqlite_autoindex_kubernetes_image_operations_1)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn recognized_schema(
    connection: &Connection,
    expected_columns: &[&str],
    expected_create_sql: &str,
) -> Result<bool, GatewayError> {
    let schema = schema_entries(connection)?;
    let expected_index = "sqlite_autoindex_kubernetes_image_operations_1";
    let expected_sql = normalize_schema_sql(expected_create_sql);
    if schema.len() != 2
        || schema[0]
            != (
                "index".into(),
                expected_index.into(),
                "kubernetes_image_operations".into(),
                None,
            )
        || schema[1].0 != "table"
        || schema[1].1 != "kubernetes_image_operations"
        || schema[1].2 != "kubernetes_image_operations"
        || schema[1].3.as_deref().map(normalize_schema_sql).as_deref()
            != Some(expected_sql.as_str())
    {
        return Ok(false);
    }
    let strict = connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name = 'kubernetes_image_operations'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(GatewayError::Database)?;
    if strict != Some(1) {
        return Ok(false);
    }
    let columns = table_columns(connection)?;
    if columns.len() != expected_columns.len()
        || !columns.iter().zip(expected_columns).enumerate().all(
            |(
                index,
                (
                    (column_id, name, declared_type, not_null, default_value, primary_key, hidden),
                    expected_name,
                ),
            )| {
                i64::try_from(index).is_ok_and(|expected_id| *column_id == expected_id)
                    && name == expected_name
                    && declared_type == expected_column_type(expected_name)
                    && *not_null == i64::from(expected_column_not_null(expected_name))
                    && default_value.as_deref() == expected_column_default(expected_name)
                    && *primary_key == i64::from(*expected_name == "operation_id")
                    && *hidden == 0
            },
        )
    {
        return Ok(false);
    }
    let indexes = table_indexes(connection)?;
    if indexes != [(0, expected_index.into(), 1, "pk".into(), 0)] {
        return Ok(false);
    }
    let index_columns = primary_index_columns(connection)?;
    Ok(index_columns
        == [
            (0, 0, Some("operation_id".into()), 0, "BINARY".into(), 1),
            (1, -1, None, 0, "BINARY".into(), 0),
        ])
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .trim_end_matches(';')
        .to_owned()
}

fn expected_column_type(name: &str) -> &'static str {
    match name {
        "receipt_bytes" => "BLOB",
        "target_read_failures"
        | "apply_attempted"
        | "apply_accepted"
        | "requested_generation"
        | "current_generation"
        | "observed_generation"
        | "desired_replicas"
        | "updated_replicas"
        | "available_replicas"
        | "unavailable_replicas"
        | "available_condition"
        | "progress_deadline_exceeded" => "INTEGER",
        _ => "TEXT",
    }
}

fn expected_column_not_null(name: &str) -> bool {
    matches!(
        name,
        "operation_id"
            | "namespace"
            | "deployment"
            | "container"
            | "immutable_image_digest"
            | "state"
            | "target_read_failures"
            | "apply_attempted"
    )
}

fn expected_column_default(name: &str) -> Option<&'static str> {
    matches!(name, "target_read_failures" | "apply_attempted").then_some("0")
}

fn migrate_receipt_schema(transaction: &Transaction<'_>) -> Result<(), GatewayError> {
    let columns = {
        let mut statement = transaction
            .prepare("PRAGMA table_info(kubernetes_image_operations)")
            .map_err(GatewayError::Database)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(GatewayError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(GatewayError::Database)?
    };
    for (name, declaration) in [
        (
            "authorization_signer_key_id",
            "authorization_signer_key_id TEXT",
        ),
        (
            "authorization_grant_digest",
            "authorization_grant_digest TEXT",
        ),
        ("target_rejection", "target_rejection TEXT"),
        (
            "target_read_failures",
            "target_read_failures INTEGER NOT NULL DEFAULT 0",
        ),
        ("receipt_path", "receipt_path TEXT"),
        ("receipt_digest", "receipt_digest TEXT"),
        ("receipt_bytes", "receipt_bytes BLOB"),
        ("receipt_key_id", "receipt_key_id TEXT"),
        ("rollout_condition_type", "rollout_condition_type TEXT"),
        ("rollout_condition_status", "rollout_condition_status TEXT"),
        ("rollout_condition_reason", "rollout_condition_reason TEXT"),
    ] {
        if !columns.iter().any(|column| column == name) {
            transaction
                .execute(
                    &format!("ALTER TABLE kubernetes_image_operations ADD COLUMN {declaration}"),
                    [],
                )
                .map_err(GatewayError::Database)?;
        }
    }
    transaction
        .execute(
            "UPDATE kubernetes_image_operations
             SET requested_generation = current_generation
             WHERE requested_generation IS NULL
                   AND result IN ('SUCCEEDED', 'FAILED')
                   AND target_uid IS NOT NULL
                   AND receiver_uid = target_uid
                   AND receiver_image = immutable_image_digest
                   AND receiver_operation_marker = operation_id
                   AND current_generation IS NOT NULL
                   AND observed_generation >= current_generation",
            [],
        )
        .map_err(GatewayError::Database)?;
    transaction
        .execute(
            "UPDATE kubernetes_image_operations
             SET rollout_condition_type = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'Progressing'
                    WHEN available_condition = 1 THEN 'Available'
                    ELSE NULL
                 END,
                 rollout_condition_status = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'False'
                    WHEN available_condition = 1 THEN 'True'
                    ELSE NULL
                 END,
                 rollout_condition_reason = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'ProgressDeadlineExceeded'
                    ELSE NULL
                 END
             WHERE rollout_condition_type IS NULL
                   AND (progress_deadline_exceeded = 1 OR available_condition = 1)",
            [],
        )
        .map_err(GatewayError::Database)?;
    Ok(())
}

fn read_header_version(file: &mut File) -> Result<u32, GatewayError> {
    let length = file.metadata().map_err(GatewayError::JournalFile)?.len();
    if length == 0 {
        return Ok(0);
    }
    if length < SQLITE_HEADER_BYTES as u64 {
        return Err(GatewayError::InvalidPersistedState);
    }
    let mut header = [0_u8; SQLITE_HEADER_BYTES];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut header))
        .map_err(GatewayError::JournalFile)?;
    if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(u32::from_be_bytes([
        header[SQLITE_USER_VERSION_OFFSET],
        header[SQLITE_USER_VERSION_OFFSET + 1],
        header[SQLITE_USER_VERSION_OFFSET + 2],
        header[SQLITE_USER_VERSION_OFFSET + 3],
    ]))
}

fn recover_private_rollback_journal(
    database_path: &Path,
    database_identity: &fs::Metadata,
) -> Result<(), GatewayError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(GatewayError::JournalBackupMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(GatewayError::JournalBackup(error)),
        }
    }
    let mut journal_name = database_path.as_os_str().to_os_string();
    journal_name.push("-journal");
    let journal_path = PathBuf::from(journal_name);
    let journal = match open_existing_private_file(&journal_path) {
        Ok(journal) => journal,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(GatewayError::JournalBackup(error)),
    };
    let journal_identity = journal.metadata().map_err(GatewayError::JournalBackup)?;
    if database_identity.len() == 0 {
        return Err(GatewayError::InvalidPersistedState);
    }
    if journal_identity.dev() == database_identity.dev()
        && journal_identity.ino() == database_identity.ino()
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    require_named_identity(&journal_path, &journal_identity)
        .map_err(GatewayError::JournalBackup)?;
    require_named_identity(database_path, database_identity).map_err(GatewayError::JournalFile)?;
    require_private_parent(database_path).map_err(GatewayError::JournalFile)?;
    drop(journal);

    let connection = Connection::open(database_path).map_err(GatewayError::Database)?;
    configure_durable_connection(&connection)?;
    connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(GatewayError::Database)?;
    drop(connection);
    match open_existing_private_file(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(GatewayError::JournalBackup(error)),
        Ok(mut residual) => {
            let residual_identity = residual.metadata().map_err(GatewayError::JournalBackup)?;
            if residual_identity.dev() != journal_identity.dev()
                || residual_identity.ino() != journal_identity.ino()
            {
                return Err(GatewayError::JournalBackupMismatch);
            }
            let mut header = [0_u8; 8];
            residual
                .read_exact(&mut header)
                .map_err(GatewayError::JournalBackup)?;
            if header != [0_u8; 8] {
                return Err(GatewayError::InvalidPersistedState);
            }
            require_named_identity(&journal_path, &residual_identity)
                .map_err(GatewayError::JournalBackup)?;
            fs::remove_file(&journal_path).map_err(GatewayError::JournalBackup)?;
            File::open(database_path.parent().ok_or_else(|| {
                GatewayError::JournalBackup(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "journal path has no parent",
                ))
            })?)
            .and_then(|parent| parent.sync_all())
            .map_err(GatewayError::JournalBackup)?;
        },
    }
    require_named_identity(database_path, database_identity).map_err(GatewayError::JournalFile)
}

fn verify_offline_backup(
    database_path: &Path,
    database_file: &mut File,
    database_identity: &fs::Metadata,
) -> Result<String, GatewayError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(GatewayError::JournalBackupMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(GatewayError::JournalBackup(error)),
        }
    }
    let backup_path = backup_path(database_path);
    let digest_path = backup_digest_path(database_path);
    let mut backup =
        open_existing_private_file(&backup_path).map_err(GatewayError::JournalBackup)?;
    let backup_identity = backup.metadata().map_err(GatewayError::JournalBackup)?;
    if backup_identity.dev() == database_identity.dev()
        && backup_identity.ino() == database_identity.ino()
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    let mut digest_file_handle =
        open_existing_private_file(&digest_path).map_err(GatewayError::JournalBackup)?;
    let digest_identity = digest_file_handle
        .metadata()
        .map_err(GatewayError::JournalBackup)?;
    let mut expected = Vec::with_capacity(65);
    digest_file_handle
        .by_ref()
        .take(66)
        .read_to_end(&mut expected)
        .map_err(GatewayError::JournalBackup)?;
    if expected.len() != 65
        || expected[64] != b'\n'
        || !expected[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    let expected =
        std::str::from_utf8(&expected[..64]).map_err(|_| GatewayError::JournalBackupMismatch)?;
    let source_digest = digest_file(database_file).map_err(GatewayError::JournalBackup)?;
    let backup_digest = digest_file(&mut backup).map_err(GatewayError::JournalBackup)?;
    if source_digest != expected || backup_digest != expected {
        return Err(GatewayError::JournalBackupMismatch);
    }
    require_named_identity(&backup_path, &backup_identity).map_err(GatewayError::JournalBackup)?;
    require_named_identity(&digest_path, &digest_identity).map_err(GatewayError::JournalBackup)?;
    Ok(source_digest)
}

fn digest_file(file: &mut File) -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(digest
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
            output
        }))
}

fn backup_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(BACKUP_SUFFIX);
    PathBuf::from(path)
}

fn backup_digest_path(database_path: &Path) -> PathBuf {
    let mut path = backup_path(database_path).into_os_string();
    path.push(BACKUP_DIGEST_SUFFIX);
    PathBuf::from(path)
}

fn open_private_file(path: &Path) -> io::Result<File> {
    let file = File::from(open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || (metadata.mode() & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal file is not owner-private",
        ));
    }
    Ok(file)
}

fn open_existing_private_file(path: &Path) -> io::Result<File> {
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || (metadata.mode() & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upgrade backup is not owner-private",
        ));
    }
    Ok(file)
}

fn require_private_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal has no private parent",
        )
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || (metadata.mode() & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal parent is not owner-private",
        ));
    }
    Ok(())
}

fn require_named_identity(path: &Path, expected: &fs::Metadata) -> io::Result<()> {
    let actual = fs::symlink_metadata(path)?;
    if !actual.is_file()
        || actual.dev() != expected.dev()
        || actual.ino() != expected.ino()
        || actual.uid() != expected.uid()
        || actual.nlink() != 1
        || (actual.mode() & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal file identity changed",
        ));
    }
    Ok(())
}

fn worker_lock_path(database_path: &Path) -> PathBuf {
    let mut lock_path = database_path.as_os_str().to_os_string();
    lock_path.push(".kap0038-worker.lock");
    PathBuf::from(lock_path)
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
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn named_identity_rejects_a_simple_path_replacement() {
        let directory =
            std::env::temp_dir().join(format!("kapsel-journal-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("journal.sqlite3");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let original = open_private_file(&path).unwrap();
        let identity = original.metadata().unwrap();
        let displaced = directory.join("displaced.sqlite3");
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(require_named_identity(&path, &identity).is_err());
        assert_eq!(fs::read(&displaced).unwrap(), b"original");
        assert_eq!(fs::read(&path).unwrap(), b"replacement");

        drop(original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_uses_full_synchronous_rollback_durability() {
        let directory =
            std::env::temp_dir().join(format!("kapsel-journal-durability-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("journal.sqlite3");

        let journal = Journal::open(&path).unwrap();
        let journal_mode = journal
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap();
        let synchronous = journal
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap();

        assert_eq!(journal_mode, "delete");
        assert_eq!(synchronous, 2);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }
}
