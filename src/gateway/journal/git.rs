//! Git rows share journal custody, the worker lease, identity namespace and capacity accounting.
//!
//! A typed table preserves Git facts without interpreting Kubernetes columns as Git evidence.

use kapsel_authority::{verify_git_ref_grant, AuthorizationTrust, GitRefAuthorization};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::{capacity, changed_one, GatewayError, Journal, WorkerLock};
use crate::gateway::{
    git::{Acknowledgement, ObservedRef, PreparedTransition},
    receipt::{git as evidence, publication::receipt_digest_hex},
    FrozenReceipt,
};

pub(in crate::gateway) struct GitBinding {
    authorization: GitRefAuthorization,
    signer: String,
    digest: String,
    grant: Vec<u8>,
}

impl GitBinding {
    pub(in crate::gateway) fn signed_grant(&self) -> &[u8] {
        &self.grant
    }

    pub(in crate::gateway) fn authorization(&self) -> &GitRefAuthorization {
        &self.authorization
    }

    pub(in crate::gateway) fn verify(
        bytes: &[u8],
        trust: &[AuthorizationTrust],
    ) -> Result<Self, GatewayError> {
        if bytes.len() > 4096 {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        for appointment in trust {
            if let Ok(grant) = verify_git_ref_grant(bytes, appointment) {
                let (authorization, signer, digest) = grant.into_parts();
                return Ok(Self {
                    authorization,
                    signer,
                    digest,
                    grant: bytes.to_vec(),
                });
            }
        }
        Err(GatewayError::UntrustedAuthorizationGrant)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::gateway) enum GitRejection {
    StaleRef,
    InvalidObjects,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) enum GitPhase {
    Authorized,
    NotAttempted(GitRejection),
    Attempted(Option<Acknowledgement>),
    Observed {
        acknowledgement: Acknowledgement,
        observed: ObservedRef,
    },
    Finalized {
        statement: Box<evidence::GitStatement>,
        receipt: FrozenReceipt,
    },
}

impl GitPhase {
    pub(in crate::gateway) fn state(&self) -> crate::gateway::OperationState {
        use crate::gateway::OperationState;
        match self {
            Self::Authorized => OperationState::Authorized,
            Self::NotAttempted(_) => OperationState::NotAttempted,
            Self::Attempted(_) => OperationState::ApplyStarted,
            Self::Observed { .. } => OperationState::ReceiverObserved,
            Self::Finalized { .. } => OperationState::Finalized,
        }
    }

    pub(in crate::gateway) fn statement(
        &self,
        binding: &GitBinding,
    ) -> Option<evidence::GitStatement> {
        match self {
            Self::Observed {
                acknowledgement,
                observed,
            } => Some(evidence::GitStatement {
                authorization: binding.authorization.clone(),
                authorization_signer: binding.signer.clone(),
                authorization_digest: binding.digest.clone(),
                acknowledgement: *acknowledgement,
                observed: observed.clone(),
            }),
            Self::Finalized { statement, .. } => Some((**statement).clone()),
            Self::Authorized | Self::Attempted(_) | Self::NotAttempted(_) => None,
        }
    }
}

pub(in crate::gateway) struct GitDispatchPermission<'receiver> {
    prepared: PreparedTransition<'receiver>,
}

impl<'receiver> GitDispatchPermission<'receiver> {
    pub(in crate::gateway) fn into_prepared(self) -> PreparedTransition<'receiver> {
        self.prepared
    }
}

impl Journal {
    pub(in crate::gateway) fn retained_git(
        &self,
        id: &str,
        trust: &[AuthorizationTrust],
    ) -> Result<Option<(GitBinding, GitPhase)>, GatewayError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(GatewayError::Database)?;
        let bytes: Option<Option<Vec<u8>>> = transaction
            .query_row(
                "SELECT CASE WHEN length(signed_authorization_grant) BETWEEN 1 AND 4096
                 THEN signed_authorization_grant END
             FROM git_ref_operations WHERE operation_id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(GatewayError::Database)?;
        let Some(bytes) = bytes else { return Ok(None) };
        let bytes = bytes.ok_or(GatewayError::InvalidPersistedState)?;
        let binding = GitBinding::verify(&bytes, trust)?;
        if binding.authorization.operation_id != id {
            return Err(GatewayError::OperationIdentityConflict);
        }
        let phase = load_on(&transaction, &binding)?.ok_or(GatewayError::InvalidPersistedState)?;
        Ok(Some((binding, phase)))
    }

    pub(in crate::gateway) fn git_operation(
        &self,
        binding: &GitBinding,
    ) -> Result<Option<GitPhase>, GatewayError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(GatewayError::Database)?;
        load_on(&transaction, binding)
    }

    pub(in crate::gateway) fn insert_git(
        &self,
        binding: &GitBinding,
        worker: &WorkerLock,
    ) -> Result<GitPhase, GatewayError> {
        if !self.owns_worker(worker) {
            return Err(GatewayError::InvalidTransition);
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(GatewayError::Database)?;
        if let Some(existing) = load_on(&transaction, binding)? {
            return Ok(existing);
        }
        let other: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM kubernetes_image_operations WHERE operation_id = ?1)",
                [&binding.authorization.operation_id],
                |row| row.get(0),
            )
            .map_err(GatewayError::Database)?;
        if other {
            return Err(GatewayError::OperationIdentityConflict);
        }
        capacity::require_admission(&transaction)?;
        let approval = &binding.authorization;
        transaction
            .execute(
                "INSERT INTO git_ref_operations (
                operation_id, repository_id, ref_name, old_commit, new_commit, authorization_id,
                authorization_signer_key_id, authorization_grant_digest, signed_authorization_grant,
                state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'authorized')",
                params![
                    approval.operation_id,
                    approval.repository_id,
                    approval.reference,
                    approval.old_commit,
                    approval.new_commit,
                    approval.authorization_id,
                    binding.signer,
                    binding.digest,
                    binding.grant
                ],
            )
            .map_err(GatewayError::Database)?;
        transaction.commit().map_err(GatewayError::Database)?;
        Ok(GitPhase::Authorized)
    }

    pub(in crate::gateway) fn begin_git_attempt<'receiver>(
        &self,
        binding: &GitBinding,
        prepared: PreparedTransition<'receiver>,
        worker: &WorkerLock,
    ) -> Result<GitDispatchPermission<'receiver>, GatewayError> {
        if !self.owns_worker(worker) || prepared.authorization() != &binding.authorization {
            return Err(GatewayError::InvalidTransition);
        }
        let transaction = self.git_write(binding, worker)?;
        if load_on(&transaction, binding)? != Some(GitPhase::Authorized) {
            return Err(GatewayError::InvalidTransition);
        }
        changed_one(
            transaction
                .execute(
                    "UPDATE git_ref_operations SET state = 'apply_started'
             WHERE operation_id = ?1 AND state = 'authorized'",
                    [&binding.authorization.operation_id],
                )
                .map_err(GatewayError::Database)?,
        )?;
        transaction.commit().map_err(GatewayError::Database)?;
        // No permission is ever reconstructed from the stored apply_started phase.
        Ok(GitDispatchPermission { prepared })
    }

    pub(in crate::gateway) fn reject_git(
        &self,
        binding: &GitBinding,
        rejection: GitRejection,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let transaction = self.git_write(binding, worker)?;
        if load_on(&transaction, binding)? != Some(GitPhase::Authorized) {
            return Err(GatewayError::InvalidTransition);
        }
        let rejection = match rejection {
            GitRejection::StaleRef => "stale_ref",
            GitRejection::InvalidObjects => "invalid_objects",
        };
        changed_one(
            transaction
                .execute(
                    "UPDATE git_ref_operations SET state = 'not_attempted', target_rejection = ?2
             WHERE operation_id = ?1 AND state = 'authorized'",
                    params![binding.authorization.operation_id, rejection],
                )
                .map_err(GatewayError::Database)?,
        )?;
        transaction.commit().map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn record_git_acknowledgement(
        &self,
        binding: &GitBinding,
        acknowledgement: Acknowledgement,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let transaction = self.git_write(binding, worker)?;
        if load_on(&transaction, binding)? != Some(GitPhase::Attempted(None)) {
            return Err(GatewayError::InvalidTransition);
        }
        changed_one(
            transaction
                .execute(
                    "UPDATE git_ref_operations SET acknowledgement = ?2
             WHERE operation_id = ?1 AND state = 'apply_started' AND acknowledgement IS NULL",
                    params![binding.authorization.operation_id, acknowledgement.as_sql()],
                )
                .map_err(GatewayError::Database)?,
        )?;
        transaction.commit().map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn freeze_git_observation(
        &self,
        binding: &GitBinding,
        observed: &ObservedRef,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let transaction = self.git_write(binding, worker)?;
        let Some(GitPhase::Attempted(ack)) = load_on(&transaction, binding)? else {
            return Err(GatewayError::InvalidTransition);
        };
        let (kind, commit) = match observed {
            ObservedRef::Commit(commit) if kapsel_authority::git_commit_id_is_valid(commit) => {
                ("commit", Some(commit.as_str()))
            },
            ObservedRef::Commit(_) => return Err(GatewayError::InvalidPersistedState),
            ObservedRef::Missing => ("missing", None),
            ObservedRef::Unknown => ("unknown", None),
        };
        changed_one(transaction.execute(
            "UPDATE git_ref_operations SET state = 'receiver_observed', acknowledgement = ?2,
                observed_ref_kind = ?3, observed_commit = ?4
             WHERE operation_id = ?1 AND state = 'apply_started'",
            params![binding.authorization.operation_id,
                ack.unwrap_or(Acknowledgement::Unknown).as_sql(), kind, commit],
        ).map_err(GatewayError::Database)?)?;
        transaction.commit().map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn commit_git_receipt(
        &self,
        binding: &GitBinding,
        bytes: &[u8],
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let transaction = self.git_write(binding, worker)?;
        let phase = load_on(&transaction, binding)?.ok_or(GatewayError::InvalidTransition)?;
        if !matches!(phase, GitPhase::Observed { .. }) {
            return Err(GatewayError::InvalidTransition);
        }
        let (key_id, statement) = evidence::decode(bytes).map_err(GatewayError::Receipt)?;
        if phase.statement(binding).as_ref() != Some(&statement) {
            return Err(GatewayError::InvalidPersistedState);
        }
        let digest = receipt_digest_hex(bytes);
        changed_one(
            transaction
                .execute(
                    "UPDATE git_ref_operations SET state = 'finalized', receipt_bytes = ?2,
                receipt_digest = ?3, receipt_key_id = ?4
             WHERE operation_id = ?1 AND state = 'receiver_observed'",
                    params![binding.authorization.operation_id, bytes, digest, key_id],
                )
                .map_err(GatewayError::Database)?,
        )?;
        transaction.commit().map_err(GatewayError::Database)
    }

    fn git_write(
        &self,
        binding: &GitBinding,
        worker: &WorkerLock,
    ) -> Result<Transaction<'_>, GatewayError> {
        if !self.owns_worker(worker) {
            return Err(GatewayError::InvalidTransition);
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(GatewayError::Database)?;
        if load_on(&transaction, binding)?.is_none() {
            return Err(GatewayError::InvalidTransition);
        }
        Ok(transaction)
    }
}

impl Acknowledgement {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::RejectedBeforeSend => "rejected_before_send",
            Self::ReceiverRejected => "receiver_rejected",
            Self::Unknown => "unknown",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "updated" => Ok(Self::Updated),
            "rejected_before_send" => Ok(Self::RejectedBeforeSend),
            "receiver_rejected" => Ok(Self::ReceiverRejected),
            "unknown" => Ok(Self::Unknown),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one snapshot authenticates binding and all frozen phase fields"
)]
pub(super) fn load_on(
    connection: &Connection,
    binding: &GitBinding,
) -> Result<Option<GitPhase>, GatewayError> {
    let raw = connection
        .query_row(
            "SELECT repository_id, ref_name, old_commit, new_commit, authorization_id,
            authorization_signer_key_id, authorization_grant_digest, signed_authorization_grant,
            state, target_rejection, acknowledgement, observed_ref_kind, observed_commit,
            receipt_digest, receipt_bytes, receipt_key_id
         FROM git_ref_operations WHERE operation_id = ?1",
            [&binding.authorization.operation_id],
            |row| {
                Ok((
                    [
                        row.get::<_, String>(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ],
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                ))
            },
        )
        .optional()
        .map_err(GatewayError::Database)?;
    let Some((
        fields,
        grant,
        state,
        rejection,
        ack,
        observed_kind,
        observed_commit,
        receipt_digest,
        receipt_bytes,
        receipt_key,
    )) = raw
    else {
        let collision: bool = connection
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM kubernetes_image_operations WHERE operation_id = ?1)",
                [&binding.authorization.operation_id],
                |row| row.get(0),
            )
            .map_err(GatewayError::Database)?;
        return if collision {
            Err(GatewayError::OperationIdentityConflict)
        } else {
            Ok(None)
        };
    };
    let approval = &binding.authorization;
    if fields.iter().map(String::as_str).ne([
        approval.repository_id.as_str(),
        &approval.reference,
        &approval.old_commit,
        &approval.new_commit,
        &approval.authorization_id,
        &binding.signer,
        &binding.digest,
    ]) || grant != binding.grant
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let receipt = match (state.as_str(), receipt_digest, receipt_bytes, receipt_key) {
        ("finalized", Some(digest), Some(bytes), Some(key_id))
            if receipt_digest_hex(&bytes) == digest =>
        {
            Some(FrozenReceipt {
                operation_id: approval.operation_id.clone(),
                bytes,
                digest,
                key_id,
            })
        },
        ("finalized", _, _, _) => return Err(GatewayError::InvalidPersistedState),
        (_, None, None, None) => None,
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    let phase = decode_phase(
        &state,
        rejection.as_deref(),
        ack.as_deref(),
        observed_kind.as_deref(),
        observed_commit,
    )?;
    if let Some(receipt) = receipt {
        let statement = phase
            .statement(binding)
            .ok_or(GatewayError::InvalidPersistedState)?;
        let (key_id, decoded) = evidence::decode(&receipt.bytes).map_err(GatewayError::Receipt)?;
        if decoded != statement || key_id != receipt.key_id {
            return Err(GatewayError::InvalidPersistedState);
        }
        Ok(Some(GitPhase::Finalized {
            statement: Box::new(statement),
            receipt,
        }))
    } else {
        Ok(Some(phase))
    }
}

fn decode_phase(
    state: &str,
    rejection: Option<&str>,
    ack: Option<&str>,
    observed_kind: Option<&str>,
    observed_commit: Option<String>,
) -> Result<GitPhase, GatewayError> {
    let acknowledgement = ack.map(Acknowledgement::from_sql).transpose()?;
    let observed = match (observed_kind, observed_commit) {
        (None, None) => None,
        (Some("unknown"), None) => Some(ObservedRef::Unknown),
        (Some("missing"), None) => Some(ObservedRef::Missing),
        (Some("commit"), Some(oid)) if kapsel_authority::git_commit_id_is_valid(&oid) => {
            Some(ObservedRef::Commit(oid))
        },
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    match (state, rejection, acknowledgement, observed) {
        ("authorized", None, None, None) => Ok(GitPhase::Authorized),
        ("not_attempted", Some("stale_ref"), None, None) => {
            Ok(GitPhase::NotAttempted(GitRejection::StaleRef))
        },
        ("not_attempted", Some("invalid_objects"), None, None) => {
            Ok(GitPhase::NotAttempted(GitRejection::InvalidObjects))
        },
        ("apply_started", None, ack, None) => Ok(GitPhase::Attempted(ack)),
        ("receiver_observed" | "finalized", None, Some(acknowledgement), Some(observed)) => {
            Ok(GitPhase::Observed {
                acknowledgement,
                observed,
            })
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "kapsel-git-journal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn open(&self) -> Journal {
            Journal::open(self.0.join("journal")).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn binding(id: &str) -> GitBinding {
        binding_with_commit(id, "b".repeat(40))
    }

    fn binding_with_commit(id: &str, new_commit: String) -> GitBinding {
        let approval = GitRefAuthorization {
            authorization_id: "approval".into(),
            operation_id: id.into(),
            repository_id: "repository".into(),
            reference: kapsel_authority::APPROVED_GIT_REF.into(),
            old_commit: "a".repeat(40),
            new_commit,
        };
        let bytes = kapsel_authority::sign_git_ref_grant(&approval, &[7; 32], "owner").unwrap();
        let trust = AuthorizationTrust {
            key_id: "owner".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        };
        GitBinding::verify(&bytes, &[trust]).unwrap()
    }

    #[test]
    fn original_git_binding_survives_restart_and_rejects_changed_payload() {
        let fixture = Fixture::new();
        let original = binding("operation");
        {
            let journal = fixture.open();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            assert_eq!(
                journal.insert_git(&original, &worker).unwrap(),
                GitPhase::Authorized
            );
        }
        let journal = fixture.open();
        let worker = journal.try_lock_worker().unwrap().unwrap();
        assert_eq!(
            journal.insert_git(&original, &worker).unwrap(),
            GitPhase::Authorized
        );
        let changed = binding_with_commit("operation", "c".repeat(40));
        assert!(matches!(
            journal.insert_git(&changed, &worker),
            Err(GatewayError::OperationIdentityConflict)
        ));
        assert_eq!(
            journal.git_operation(&original).unwrap(),
            Some(GitPhase::Authorized)
        );
    }

    #[test]
    fn lost_acknowledgement_freezes_unknown_even_when_present_ref_is_b() {
        let fixture = Fixture::new();
        let original = binding("operation");
        {
            let journal = fixture.open();
            let worker = journal.try_lock_worker().unwrap().unwrap();
            journal.insert_git(&original, &worker).unwrap();
            // Crash fixture: durable attempted history carries no fresh dispatch permission.
            journal
                .connection
                .execute("UPDATE git_ref_operations SET state = 'apply_started'", [])
                .unwrap();
        }
        let journal = fixture.open();
        let worker = journal.try_lock_worker().unwrap().unwrap();
        let observed = ObservedRef::Commit(original.authorization.new_commit.clone());
        journal
            .freeze_git_observation(&original, &observed, &worker)
            .unwrap();
        let frozen = GitPhase::Observed {
            acknowledgement: Acknowledgement::Unknown,
            observed,
        };
        assert_eq!(
            journal.git_operation(&original).unwrap(),
            Some(frozen.clone())
        );
        assert!(journal
            .record_git_acknowledgement(&original, Acknowledgement::Updated, &worker)
            .is_err());
        assert!(journal
            .freeze_git_observation(&original, &ObservedRef::Missing, &worker)
            .is_err());
        drop(worker);
        drop(journal);
        assert_eq!(
            fixture.open().git_operation(&original).unwrap(),
            Some(frozen)
        );
    }

    #[test]
    fn acknowledgement_and_not_attempted_are_phase_guarded() {
        let fixture = Fixture::new();
        let journal = fixture.open();
        let worker = journal.try_lock_worker().unwrap().unwrap();
        let original = binding("operation");
        journal.insert_git(&original, &worker).unwrap();
        assert!(journal
            .record_git_acknowledgement(&original, Acknowledgement::Updated, &worker)
            .is_err());
        journal
            .reject_git(&original, GitRejection::StaleRef, &worker)
            .unwrap();
        assert_eq!(
            journal.git_operation(&original).unwrap(),
            Some(GitPhase::NotAttempted(GitRejection::StaleRef))
        );
        journal
            .connection
            .execute(
                "UPDATE git_ref_operations SET acknowledgement = 'updated'",
                [],
            )
            .unwrap();
        assert!(journal.git_operation(&original).is_err());
    }

    #[test]
    fn both_capabilities_share_capacity_and_identity_namespace() {
        let fixture = Fixture::new();
        let journal = fixture.open();
        let worker = journal.try_lock_worker().unwrap().unwrap();
        journal
            .connection
            .execute(
                "INSERT INTO kubernetes_image_operations
             (operation_id, namespace, deployment, container, immutable_image_digest, state)
             VALUES ('shared', 'ns', 'app', 'app', 'fixture-only', 'authorized')",
                [],
            )
            .unwrap();
        assert!(matches!(
            journal.insert_git(&binding("shared"), &worker),
            Err(GatewayError::OperationIdentityConflict)
        ));
        for index in 0..31 {
            journal
                .insert_git(&binding(&format!("git-{index}")), &worker)
                .unwrap();
        }
        assert_eq!(capacity::counts(&journal.connection).unwrap(), (32, 32));
        assert!(matches!(
            journal.insert_git(&binding("full"), &worker),
            Err(GatewayError::JournalFull)
        ));
        assert_eq!(
            journal.insert_git(&binding("git-0"), &worker).unwrap(),
            GitPhase::Authorized
        );
        drop(worker);
        drop(journal);
        assert_eq!(
            capacity::counts(&fixture.open().connection).unwrap(),
            (32, 32)
        );
    }
}
