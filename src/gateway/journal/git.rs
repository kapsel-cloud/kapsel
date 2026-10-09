//! Git rows share journal custody, the worker lease, identity namespace and capacity accounting.
//!
//! A typed table preserves Git facts without interpreting Kubernetes columns as Git evidence.

use kapsel_authority::{verify_git_ref_grant, AuthorizationTrust, GitRefAuthorization};
use rusqlite::Connection;

use super::{
    records::{Record, Write},
    GatewayError, Journal, WorkerLock,
};
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
        let Some(record) = self.records.read_git(&self.connection, id)? else {
            return Ok(None);
        };
        let bytes: Vec<u8> = record.get("signed_authorization_grant")?;
        let binding = GitBinding::verify(&bytes, trust)?;
        if binding.authorization.operation_id != id {
            return Err(GatewayError::OperationIdentityConflict);
        }
        let phase = decode_record(&record, &binding)?;
        Ok(Some((binding, phase)))
    }

    pub(in crate::gateway) fn git_operation(
        &self,
        binding: &GitBinding,
    ) -> Result<Option<GitPhase>, GatewayError> {
        self.git_record(binding)?
            .map(|record| decode_record(&record, binding))
            .transpose()
    }

    pub(in crate::gateway) fn insert_git(
        &self,
        binding: &GitBinding,
        worker: &WorkerLock,
    ) -> Result<GitPhase, GatewayError> {
        if !self.owns_worker(worker) {
            return Err(GatewayError::InvalidTransition);
        }
        if let Some(existing) = self.git_operation(binding)? {
            return Ok(existing);
        }
        let approval = &binding.authorization;
        let mut record = Record::git_empty(&approval.operation_id);
        for (field, value) in [
            ("repository_id", &approval.repository_id),
            ("ref_name", &approval.reference),
            ("old_commit", &approval.old_commit),
            ("new_commit", &approval.new_commit),
            ("authorization_id", &approval.authorization_id),
            ("authorization_signer_key_id", &binding.signer),
            ("authorization_grant_digest", &binding.digest),
        ] {
            record.set(field, value.clone());
        }
        record.set("signed_authorization_grant", binding.grant.clone());
        record.set("state", "authorized".to_owned());
        self.records
            .replace(&self.connection, None, &record, Write::Admission)?;
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
        let (original, phase) = self.git_write(binding, worker)?;
        if phase != GitPhase::Authorized {
            return Err(GatewayError::InvalidTransition);
        }
        let mut next = original.clone();
        next.set("state", "apply_started".to_owned());
        self.records
            .replace(&self.connection, Some(&original), &next, Write::Attempt)?;
        #[cfg(test)]
        if prepared.exploration_attempt_acknowledgement_lost() {
            return Err(GatewayError::InjectedFault);
        }
        // No permission is ever reconstructed from the stored apply_started phase.
        Ok(GitDispatchPermission { prepared })
    }

    pub(in crate::gateway) fn reject_git(
        &self,
        binding: &GitBinding,
        rejection: GitRejection,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let (original, phase) = self.git_write(binding, worker)?;
        if phase != GitPhase::Authorized {
            return Err(GatewayError::InvalidTransition);
        }
        let rejection = match rejection {
            GitRejection::StaleRef => "stale_ref",
            GitRejection::InvalidObjects => "invalid_objects",
        };
        let mut next = original.clone();
        next.set("state", "not_attempted".to_owned());
        next.set("target_rejection", rejection.to_owned());
        self.records
            .replace(&self.connection, Some(&original), &next, Write::Rejection)
    }

    pub(in crate::gateway) fn record_git_acknowledgement(
        &self,
        binding: &GitBinding,
        acknowledgement: Acknowledgement,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let (original, phase) = self.git_write(binding, worker)?;
        if phase != GitPhase::Attempted(None) {
            return Err(GatewayError::InvalidTransition);
        }
        let mut next = original.clone();
        next.set("acknowledgement", acknowledgement.as_str().to_owned());
        self.records
            .replace(&self.connection, Some(&original), &next, Write::Response)
    }

    pub(in crate::gateway) fn freeze_git_observation(
        &self,
        binding: &GitBinding,
        observed: &ObservedRef,
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let (original, phase) = self.git_write(binding, worker)?;
        let GitPhase::Attempted(ack) = phase else {
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
        let mut next = original.clone();
        next.set("state", "receiver_observed".to_owned());
        let acknowledgement = ack.unwrap_or(Acknowledgement::Unknown);
        #[cfg(test)]
        let acknowledgement = if self
            .records
            .control
            .exercise(super::records::Defect::GitInferredAcknowledgement)
            && matches!(observed, ObservedRef::Commit(commit)
                if commit == &binding.authorization.new_commit)
        {
            Acknowledgement::Updated
        } else {
            acknowledgement
        };
        next.set("acknowledgement", acknowledgement.as_str().to_owned());
        next.set("observed_ref_kind", kind.to_owned());
        next.set_optional("observed_commit", commit.map(str::to_owned));
        self.records
            .replace(&self.connection, Some(&original), &next, Write::Observation)
    }

    pub(in crate::gateway) fn commit_git_receipt(
        &self,
        binding: &GitBinding,
        bytes: &[u8],
        worker: &WorkerLock,
    ) -> Result<(), GatewayError> {
        let (original, phase) = self.git_write(binding, worker)?;
        if !matches!(phase, GitPhase::Observed { .. }) {
            return Err(GatewayError::InvalidTransition);
        }
        let (key_id, statement) = evidence::decode(bytes).map_err(GatewayError::Receipt)?;
        if phase.statement(binding).as_ref() != Some(&statement) {
            return Err(GatewayError::InvalidPersistedState);
        }
        let digest = receipt_digest_hex(bytes);
        let mut next = original.clone();
        next.set("state", "finalized".to_owned());
        next.set("receipt_bytes", bytes.to_vec());
        next.set("receipt_digest", digest);
        next.set("receipt_key_id", key_id);
        self.records
            .replace(&self.connection, Some(&original), &next, Write::Receipt)
    }

    fn git_write(
        &self,
        binding: &GitBinding,
        worker: &WorkerLock,
    ) -> Result<(Record, GitPhase), GatewayError> {
        if !self.owns_worker(worker) {
            return Err(GatewayError::InvalidTransition);
        }
        let record = self
            .git_record(binding)?
            .ok_or(GatewayError::InvalidTransition)?;
        let phase = decode_record(&record, binding)?;
        Ok((record, phase))
    }

    fn git_record(&self, binding: &GitBinding) -> Result<Option<Record>, GatewayError> {
        let id = &binding.authorization.operation_id;
        let record = self.records.read_git(&self.connection, id)?;
        if record.is_none() && self.records.read(&self.connection, id)?.is_some() {
            return Err(GatewayError::OperationIdentityConflict);
        }
        Ok(record)
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
    let id = &binding.authorization.operation_id;
    let Some(record) = super::records::read_git(connection, id)? else {
        return if super::records::read(connection, id)?.is_some() {
            Err(GatewayError::OperationIdentityConflict)
        } else {
            Ok(None)
        };
    };
    decode_record(&record, binding).map(Some)
}

fn decode_record(record: &Record, binding: &GitBinding) -> Result<GitPhase, GatewayError> {
    let approval = &binding.authorization;
    for (field, expected) in [
        ("operation_id", &approval.operation_id),
        ("repository_id", &approval.repository_id),
        ("ref_name", &approval.reference),
        ("old_commit", &approval.old_commit),
        ("new_commit", &approval.new_commit),
        ("authorization_id", &approval.authorization_id),
        ("authorization_signer_key_id", &binding.signer),
        ("authorization_grant_digest", &binding.digest),
    ] {
        if record.get::<String>(field)? != *expected {
            return Err(GatewayError::OperationIdentityConflict);
        }
    }
    if record.get::<Vec<u8>>("signed_authorization_grant")? != binding.grant {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let state: String = record.get("state")?;
    let rejection: Option<String> = record.get("target_rejection")?;
    let ack: Option<String> = record.get("acknowledgement")?;
    let observed_kind: Option<String> = record.get("observed_ref_kind")?;
    let observed_commit: Option<String> = record.get("observed_commit")?;
    let receipt_digest: Option<String> = record.get("receipt_digest")?;
    let receipt_bytes: Option<Vec<u8>> = record.get("receipt_bytes")?;
    let receipt_key: Option<String> = record.get("receipt_key_id")?;
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
        Ok(GitPhase::Finalized {
            statement: Box::new(statement),
            receipt,
        })
    } else {
        Ok(phase)
    }
}

fn decode_phase(
    state: &str,
    rejection: Option<&str>,
    ack: Option<&str>,
    observed_kind: Option<&str>,
    observed_commit: Option<String>,
) -> Result<GitPhase, GatewayError> {
    let acknowledgement = ack
        .map(|value| Acknowledgement::parse(value).ok_or(GatewayError::InvalidPersistedState))
        .transpose()?;
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
    use crate::gateway::journal::capacity;

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
        assert!(matches!(
            journal.reject_git(&changed, GitRejection::StaleRef, &worker),
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
