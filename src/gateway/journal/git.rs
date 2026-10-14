//! Git rows share journal custody, the worker lease, identity namespace and capacity accounting.
//!
//! A typed table preserves Git facts without interpreting Kubernetes columns as Git evidence.

use kapsel_authority::{verify_git_ref_grant, AuthorizationTrust, GitRefAuthorization};
use rusqlite::Connection;

#[cfg(test)]
use super::records::Defect;
use super::{
    records::{Record, Write},
    GatewayError, Journal, WorkerLock,
};
use crate::gateway::{
    git::{Acknowledgement, ObservedRef, PreparedTransition},
    receipt::{git as evidence, publication::receipt_digest_hex},
    FrozenReceipt, OperationState,
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
    pub(in crate::gateway) fn state(&self) -> OperationState {
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
            .map(|record| self.decode_git_record(&record, binding))
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
        let GitPhase::Attempted(retained_acknowledgement) = phase else {
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
        let acknowledgement = retained_acknowledgement.unwrap_or(Acknowledgement::Unknown);
        #[cfg(test)]
        let acknowledgement = if self
            .records
            .control
            .exercise(Defect::GitInferredAcknowledgement)
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
        #[cfg(test)]
        if self
            .records
            .control
            .exercise(Defect::GitObservationSubstitution)
        {
            next.set("observed_ref_kind", "commit".to_owned());
            next.set("observed_commit", binding.authorization.old_commit.clone());
        }
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
        let phase = self.decode_git_record(&record, binding)?;
        Ok((record, phase))
    }

    #[allow(
        clippy::unused_self,
        reason = "custody control exists only in test builds"
    )]
    fn decode_git_record(
        &self,
        record: &Record,
        binding: &GitBinding,
    ) -> Result<GitPhase, GatewayError> {
        #[cfg(test)]
        if record.get::<Vec<u8>>("signed_authorization_grant")? != binding.grant
            && self.exercise_defect(Defect::CustodyIgnored)
        {
            let unchecked_binding = GitBinding {
                authorization: binding.authorization.clone(),
                signer: binding.signer.clone(),
                digest: binding.digest.clone(),
                grant: record.get("signed_authorization_grant")?,
            };
            return decode_record(record, &unchecked_binding);
        }
        decode_record(record, binding)
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
    let retained_acknowledgement: Option<String> = record.get("acknowledgement")?;
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
        retained_acknowledgement.as_deref(),
        observed_kind.as_deref(),
        observed_commit,
    )?;
    if let Some(receipt) = receipt {
        let statement = phase
            .statement(binding)
            .ok_or(GatewayError::InvalidPersistedState)?;
        let (key_id, decoded_statement) =
            evidence::decode(&receipt.bytes).map_err(GatewayError::Receipt)?;
        if decoded_statement != statement || key_id != receipt.key_id {
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
    retained_acknowledgement: Option<&str>,
    observed_kind: Option<&str>,
    observed_commit: Option<String>,
) -> Result<GitPhase, GatewayError> {
    let acknowledgement = retained_acknowledgement
        .map(|value| Acknowledgement::parse(value).ok_or(GatewayError::InvalidPersistedState))
        .transpose()?;
    let observed = match (observed_kind, observed_commit) {
        (None, None) => None,
        (Some("unknown"), None) => Some(ObservedRef::Unknown),
        (Some("missing"), None) => Some(ObservedRef::Missing),
        (Some("commit"), Some(commit_id))
            if kapsel_authority::git_commit_id_is_valid(&commit_id) =>
        {
            Some(ObservedRef::Commit(commit_id))
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
        ("apply_started", None, retained_acknowledgement, None) => {
            Ok(GitPhase::Attempted(retained_acknowledgement))
        },
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
pub(super) async fn executed_write_statements() -> Vec<(Write, String)> {
    let mut statements = Vec::new();
    for write in [
        Write::Admission,
        Write::Rejection,
        Write::Attempt,
        Write::Response,
        Write::Observation,
        Write::Receipt,
    ] {
        statements.extend(tests::sqlite_bridge(write, super::Delivery::Confirmed, false).await);
    }
    statements
        .extend(tests::sqlite_bridge(Write::Observation, super::Delivery::Confirmed, true).await);
    statements
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{
        journal::{
            capacity, records,
            test_history::{
                digest, git_binding, git_binding_with_authority,
                insert_git_phase as authored_phase, open_scratch, trust, History, Scratch,
            },
        },
        tests::storage::copy_closed_journal,
        OperationResult,
    };

    #[test]
    fn git_writers_preserve_independent_acknowledgement_and_ref_facts_through_reopen() {
        for variant in [0, 17, 127] {
            for (acknowledgement, token, result) in [
                (
                    Acknowledgement::Updated,
                    "updated",
                    OperationResult::Succeeded,
                ),
                (
                    Acknowledgement::RejectedBeforeSend,
                    "rejected_before_send",
                    OperationResult::Failed,
                ),
                (
                    Acknowledgement::ReceiverRejected,
                    "receiver_rejected",
                    OperationResult::Failed,
                ),
                (
                    Acknowledgement::Unknown,
                    "unknown",
                    OperationResult::Unknown,
                ),
            ] {
                for (observed, kind, commit) in [
                    (
                        ObservedRef::Commit(format!("{:040x}", 101 + variant)),
                        "commit",
                        Some(format!("{:040x}", 101 + variant)),
                    ),
                    (
                        ObservedRef::Commit(format!("{:040x}", 211 + variant)),
                        "commit",
                        Some(format!("{:040x}", 211 + variant)),
                    ),
                    (
                        ObservedRef::Commit(format!("{:040x}", 307 + variant)),
                        "commit",
                        Some(format!("{:040x}", 307 + variant)),
                    ),
                    (ObservedRef::Missing, "missing", None),
                    (ObservedRef::Unknown, "unknown", None),
                ] {
                    git_mapping(
                        variant,
                        acknowledgement,
                        token,
                        &observed,
                        kind,
                        commit.as_deref(),
                        result,
                    );
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one mapping binds SQL, finalization and public reads"
    )]
    fn git_mapping(
        variant: i32,
        acknowledgement: Acknowledgement,
        token: &str,
        observed: &ObservedRef,
        kind: &str,
        commit: Option<&str>,
        result: OperationResult,
    ) {
        use crate::{
            application::{
                ExecutionDisposition, ExecutionObservation, OperationReceipt, OperationStatus,
                ServiceApplication, ServiceConfiguration,
            },
            gateway::{
                journal::test_history::named_git_row, GitOperationTargets, OperationTargets,
            },
        };

        let scratch = Scratch::new();
        let expected_scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let expected_journal = open_scratch(&expected_scratch);
        let binding = git_binding_with_authority(&GitRefAuthorization {
            operation_id: "git-mapping".into(),
            authorization_id: format!("approval-{variant}"),
            repository_id: format!("repository-{variant}"),
            reference: "refs/heads/approved".into(),
            old_commit: format!("{:040x}", 101 + variant),
            new_commit: format!("{:040x}", 211 + variant),
        });
        authored_phase(&journal.connection, &binding, "apply_started");
        authored_phase(&expected_journal.connection, &binding, "apply_started");
        let peer = git_binding("untouched-git-peer");
        authored_phase(&journal.connection, &peer, "finalized");
        let peer_before = named_git_row(&journal.connection, "untouched-git-peer");
        expected_journal
            .connection
            .execute(
                "UPDATE git_ref_operations SET state = 'receiver_observed', acknowledgement = ?1,
             observed_ref_kind = ?2, observed_commit = ?3 WHERE operation_id = 'git-mapping'",
                rusqlite::params![token, kind, commit],
            )
            .unwrap();
        let expected_statement = evidence::GitStatement {
            authorization: binding.authorization().clone(),
            authorization_signer: "snapshot-signer".into(),
            authorization_digest: digest(binding.signed_grant()),
            acknowledgement,
            observed: observed.clone(),
        };
        let assert_unfinished_reads = |observed_ref| {
            let before = named_git_row(&journal.connection, "git-mapping");
            let control = records::Control::default();
            let app = ServiceApplication::open_simulated(
                ServiceConfiguration {
                    journal_path: scratch.0.join("journal.sqlite3"),
                    authorization_trust: vec![trust()],
                    approvals: vec![],
                },
                control.clone(),
            )
            .unwrap();
            let targets = OperationTargets {
                git: Some(GitOperationTargets {
                    approval: binding.authorization().clone(),
                    attempted: true,
                    acknowledgement: Some(acknowledgement),
                    observed_ref,
                }),
                ..OperationTargets::default()
            };
            let expected = (OperationStatus::InProgress, targets);
            assert_eq!(app.status("git-mapping").unwrap(), expected);
            assert_eq!(
                app.execution_status("git-mapping", ExecutionObservation::Unknown)
                    .unwrap(),
                (
                    expected.0,
                    expected.1.clone(),
                    ExecutionDisposition::ResumeRequired(None)
                )
            );
            let page = app.history(None).unwrap();
            let entry = page
                .entries
                .iter()
                .find(|entry| entry.operation_id == "git-mapping");
            assert_eq!(entry.unwrap().status, Ok(expected));
            assert_eq!(
                app.receipt("git-mapping").unwrap(),
                OperationReceipt::NotReady
            );
            assert!(
                control.events().is_empty(),
                "reads perform no durable transition"
            );
            assert_eq!(named_git_row(&journal.connection, "git-mapping"), before);
        };
        let worker = journal.try_lock_worker().unwrap().unwrap();
        journal
            .record_git_acknowledgement(&binding, acknowledgement, &worker)
            .unwrap();
        assert_unfinished_reads(None);
        journal
            .freeze_git_observation(&binding, observed, &worker)
            .unwrap();
        assert_unfinished_reads(Some(observed.clone()));
        let expected_row = named_git_row(&expected_journal.connection, "git-mapping");
        assert_eq!(
            named_git_row(&journal.connection, "git-mapping"),
            expected_row
        );
        let expected_phase = GitPhase::Observed {
            acknowledgement,
            observed: observed.clone(),
        };
        assert_eq!(
            journal.git_operation(&binding).unwrap(),
            Some(expected_phase)
        );
        let actual = journal
            .git_operation(&binding)
            .unwrap()
            .unwrap()
            .statement(&binding)
            .unwrap();
        assert_eq!(actual, expected_statement);
        assert_eq!(actual.result(), result);
        let bytes = evidence::sign(&expected_statement, &[9; 32], "mapping-receipt-key").unwrap();
        journal
            .commit_git_receipt(&binding, &bytes, &worker)
            .unwrap();
        let mut finalized_row = expected_row;
        for (field, value) in [
            ("state", "finalized".to_owned().into()),
            ("receipt_bytes", bytes.clone().into()),
            ("receipt_digest", digest(&bytes).into()),
            ("receipt_key_id", "mapping-receipt-key".to_owned().into()),
        ] {
            finalized_row.insert(field.into(), value);
        }
        assert_eq!(
            named_git_row(&journal.connection, "git-mapping"),
            finalized_row,
            "finalization changes only terminal/receipt fields"
        );
        assert_eq!(
            named_git_row(&journal.connection, "untouched-git-peer"),
            peer_before
        );
        drop(worker);
        drop(journal);
        let reopened = open_scratch(&scratch);
        assert_eq!(
            named_git_row(&reopened.connection, "git-mapping"),
            finalized_row
        );
        assert_eq!(
            reopened.git_operation(&binding).unwrap(),
            Some(GitPhase::Finalized {
                statement: Box::new(expected_statement.clone()),
                receipt: FrozenReceipt {
                    operation_id: "git-mapping".into(),
                    bytes: bytes.clone(),
                    digest: digest(&bytes),
                    key_id: "mapping-receipt-key".into(),
                },
            })
        );
        assert_eq!(
            reopened
                .git_operation(&binding)
                .unwrap()
                .unwrap()
                .statement(&binding),
            Some(expected_statement)
        );
        assert_eq!(
            named_git_row(&reopened.connection, "untouched-git-peer"),
            peer_before
        );
        drop(reopened);
        let control = records::Control::default();
        let app = ServiceApplication::open_simulated(
            ServiceConfiguration {
                journal_path: scratch.0.join("journal.sqlite3"),
                authorization_trust: vec![trust()],
                approvals: vec![],
            },
            control.clone(),
        )
        .unwrap();
        let status = match result {
            OperationResult::Succeeded => OperationStatus::Succeeded,
            OperationResult::Failed => OperationStatus::Failed,
            OperationResult::Unknown => OperationStatus::Unknown,
        };
        let targets = OperationTargets {
            git: Some(GitOperationTargets {
                approval: binding.authorization().clone(),
                attempted: true,
                acknowledgement: Some(acknowledgement),
                observed_ref: Some(observed.clone()),
            }),
            ..OperationTargets::default()
        };
        assert_eq!(
            app.status("git-mapping").unwrap(),
            (status, targets.clone())
        );
        assert_eq!(
            app.execution_status("git-mapping", ExecutionObservation::Unknown)
                .unwrap(),
            (status, targets, ExecutionDisposition::Complete)
        );
        assert_eq!(
            app.receipt("git-mapping").unwrap(),
            OperationReceipt::Ready {
                bytes: bytes.clone(),
                sha256: digest(&bytes),
            }
        );
        assert_eq!(
            app.admitted_state("git-mapping").unwrap(),
            Some(OperationState::Finalized)
        );
        assert!(
            control.events().is_empty(),
            "reads perform no durable transition"
        );
        drop(app);
        let reopened = open_scratch(&scratch);
        assert_eq!(
            named_git_row(&reopened.connection, "git-mapping"),
            finalized_row
        );
        assert_eq!(
            named_git_row(&reopened.connection, "untouched-git-peer"),
            peer_before
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one public projection table binds all phases and terminal results"
    )]
    fn public_git_reads_preserve_literal_phase_authority_acknowledgement_and_receipt() {
        use crate::{
            application::{
                OperationReceipt, OperationStatus, ServiceApplication, ServiceConfiguration,
            },
            gateway::{
                journal::test_history::named_git_row, GitOperationTargets, OperationTargets,
                TargetRejection,
            },
        };

        for (phase, acknowledgement, token, expected_status) in [
            (
                "authorized",
                Acknowledgement::Unknown,
                "unknown",
                OperationStatus::InProgress,
            ),
            (
                "not_attempted",
                Acknowledgement::Unknown,
                "unknown",
                OperationStatus::NotAttempted(TargetRejection::GitStaleRef),
            ),
            (
                "apply_started",
                Acknowledgement::Unknown,
                "unknown",
                OperationStatus::InProgress,
            ),
            (
                "apply_started",
                Acknowledgement::Updated,
                "updated",
                OperationStatus::InProgress,
            ),
            (
                "apply_started",
                Acknowledgement::ReceiverRejected,
                "receiver_rejected",
                OperationStatus::InProgress,
            ),
            (
                "receiver_observed",
                Acknowledgement::Unknown,
                "unknown",
                OperationStatus::InProgress,
            ),
            (
                "finalized",
                Acknowledgement::Unknown,
                "unknown",
                OperationStatus::Unknown,
            ),
            (
                "finalized",
                Acknowledgement::Updated,
                "updated",
                OperationStatus::Succeeded,
            ),
            (
                "finalized",
                Acknowledgement::ReceiverRejected,
                "receiver_rejected",
                OperationStatus::Failed,
            ),
        ] {
            let scratch = Scratch::new();
            let journal = open_scratch(&scratch);
            let binding = git_binding("public-git-read");
            authored_phase(&journal.connection, &binding, phase);
            let statement = evidence::GitStatement {
                authorization: binding.authorization().clone(),
                authorization_signer: "snapshot-signer".into(),
                authorization_digest: digest(binding.signed_grant()),
                acknowledgement,
                observed: ObservedRef::Commit("b".repeat(40)),
            };
            let receipt = evidence::sign(&statement, &[9; 32], "bridge-receipt-key").unwrap();
            if phase == "finalized" {
                journal
                    .connection
                    .execute(
                        "UPDATE git_ref_operations SET acknowledgement = ?1, receipt_bytes = ?2,
                     receipt_digest = ?3 WHERE operation_id = 'public-git-read'",
                        rusqlite::params![token, receipt, digest(&receipt)],
                    )
                    .unwrap();
            }
            let attempted_acknowledgement = (phase == "apply_started"
                && acknowledgement != Acknowledgement::Unknown)
                .then_some(acknowledgement);
            if let Some(retained) = attempted_acknowledgement {
                journal
                    .connection
                    .execute(
                        "UPDATE git_ref_operations SET acknowledgement = ?1
                         WHERE operation_id = 'public-git-read'",
                        [retained.as_str()],
                    )
                    .unwrap();
            }
            let before = named_git_row(&journal.connection, "public-git-read");
            drop(journal);
            let control = records::Control::default();
            let app = ServiceApplication::open_simulated(
                ServiceConfiguration {
                    journal_path: scratch.0.join("journal.sqlite3"),
                    authorization_trust: vec![trust()],
                    approvals: vec![],
                },
                control.clone(),
            )
            .unwrap();
            let frozen = matches!(phase, "receiver_observed" | "finalized");
            let expected_targets = OperationTargets {
                approved_target: None,
                observed_target: None,
                attempt_target: None,
                git: Some(GitOperationTargets {
                    approval: binding.authorization().clone(),
                    attempted: matches!(phase, "apply_started" | "receiver_observed" | "finalized"),
                    acknowledgement: frozen
                        .then_some(acknowledgement)
                        .or(attempted_acknowledgement),
                    observed_ref: frozen.then(|| ObservedRef::Commit("b".repeat(40))),
                }),
            };
            assert_eq!(
                app.status("public-git-read").unwrap(),
                (expected_status, expected_targets.clone())
            );
            let expected_receipt = if phase == "finalized" {
                OperationReceipt::Ready {
                    bytes: receipt.clone(),
                    sha256: digest(&receipt),
                }
            } else {
                OperationReceipt::NotReady
            };
            assert_eq!(app.receipt("public-git-read").unwrap(), expected_receipt);
            let page = app.history(None).unwrap();
            assert_eq!(page.entries.len(), 1);
            assert_eq!(page.entries[0].operation_id, "public-git-read");
            assert_eq!(
                page.entries[0].status,
                Ok((expected_status, expected_targets))
            );
            assert!(page.next_cursor.is_none());
            assert!(
                control.events().is_empty(),
                "reads perform no durable transition"
            );
            drop(app);
            let reopened = open_scratch(&scratch);
            assert_eq!(
                named_git_row(&reopened.connection, "public-git-read"),
                before
            );
        }
    }

    #[test]
    fn ref_b_without_a_retained_acknowledgement_remains_unknown_at_the_local_writer() {
        use crate::gateway::journal::test_history::named_git_row;

        for defect in [false, true] {
            let scratch = Scratch::new();
            let mut journal = open_scratch(&scratch);
            let binding = git_binding("no-acknowledgement");
            authored_phase(&journal.connection, &binding, "apply_started");
            let control = records::Control::default();
            if defect {
                control.seed(records::Defect::GitInferredAcknowledgement);
            }
            journal.control_storage(control.clone());
            let worker = journal.try_lock_worker().unwrap().unwrap();
            journal
                .freeze_git_observation(&binding, &ObservedRef::Commit("b".repeat(40)), &worker)
                .unwrap();
            let row = named_git_row(&journal.connection, "no-acknowledgement");
            let matches = row["acknowledgement"] == rusqlite::types::Value::Text("unknown".into());
            assert_eq!(
                matches, !defect,
                "ref observation must not invent original acknowledgement"
            );
            if defect {
                assert!(control
                    .defect_reached()
                    .contains(&records::Defect::GitInferredAcknowledgement));
            }
        }
    }

    #[tokio::test]
    async fn git_sqlite_bridge_consumes_all_six_writes_under_three_deliveries() {
        let mut consumed = 0;
        for write in [
            Write::Admission,
            Write::Rejection,
            Write::Attempt,
            Write::Response,
            Write::Observation,
            Write::Receipt,
        ] {
            for delivery in [
                records::Delivery::Confirmed,
                records::Delivery::NoCommit,
                records::Delivery::LostAcknowledgement,
            ] {
                sqlite_bridge(write, delivery, false).await;
                consumed += 1;
            }
        }
        assert_eq!(consumed, 18);
        eprintln!("KAPSEL_SQLITE_DELIVERIES Git consumed={consumed}");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "six independent row transitions each bind one write, not full histories"
    )]
    pub(super) async fn sqlite_bridge(
        write: Write,
        delivery: records::Delivery,
        absent_commit: bool,
    ) -> Vec<(Write, String)> {
        use crate::gateway::{
            git::exploration::Script,
            journal::test_history::{named_git_row, named_kube_row},
        };

        let scratch = Scratch::new();
        let expected_scratch = Scratch::new();
        let mut journal = open_scratch(&scratch);
        let expected_journal = open_scratch(&expected_scratch);
        let binding = git_binding("sqlite-git-bridge");
        let (prior, next) = match write {
            Write::Admission => (None, "authorized"),
            Write::Rejection => (Some("authorized"), "not_attempted"),
            Write::Attempt => (Some("authorized"), "apply_started"),
            Write::Response => (Some("apply_started"), "apply_started"),
            Write::Observation => (Some("apply_started"), "receiver_observed"),
            Write::Receipt => (Some("receiver_observed"), "finalized"),
            Write::Authorization => unreachable!("Git has no separate authorization write"),
        };
        let prior_phase = prior.map(|phase| {
            let expected = authored_phase(&journal.connection, &binding, phase);
            authored_phase(&expected_journal.connection, &binding, phase);
            assert_eq!(
                journal.git_operation(&binding).unwrap(),
                Some(expected.clone())
            );
            expected
        });
        let peer = History::kube("untouched-kube-peer");
        peer.insert(&journal.connection, "finalized");
        let peer_before = named_kube_row(&journal.connection, "untouched-kube-peer");
        let git_peer = git_binding("untouched-git-peer");
        let git_peer_phase = authored_phase(&journal.connection, &git_peer, "finalized");
        assert_eq!(
            journal.git_operation(&git_peer).unwrap(),
            Some(git_peer_phase)
        );
        let git_peer_before = named_git_row(&journal.connection, "untouched-git-peer");
        let before = named_git_row(&journal.connection, "sqlite-git-bridge");
        assert_eq!(
            before,
            named_git_row(&expected_journal.connection, "sqlite-git-bridge")
        );
        expected_journal
            .connection
            .execute("DELETE FROM git_ref_operations", [])
            .unwrap();
        let baseline = authored_phase(&expected_journal.connection, &binding, next);
        let next_phase = if write == Write::Response {
            expected_journal
                .connection
                .execute(
                    "UPDATE git_ref_operations SET acknowledgement = 'receiver_rejected'",
                    [],
                )
                .unwrap();
            GitPhase::Attempted(Some(Acknowledgement::ReceiverRejected))
        } else if write == Write::Observation && absent_commit {
            expected_journal
                .connection
                .execute(
                    concat!(
                        "UPDATE git_ref_operations SET ",
                        "observed_ref_kind = 'missing', observed_commit = NULL"
                    ),
                    [],
                )
                .unwrap();
            GitPhase::Observed {
                acknowledgement: Acknowledgement::Unknown,
                observed: ObservedRef::Missing,
            }
        } else {
            baseline
        };
        let next_row = named_git_row(&expected_journal.connection, "sqlite-git-bridge");
        assert!(!next_row.is_empty());
        assert_ne!(before, next_row);
        let control = records::Control::default();
        control.fail_next(write, delivery);
        journal.control_storage(control.clone());
        let worker = journal.try_lock_worker().unwrap().unwrap();
        let result = match write {
            Write::Admission => journal.insert_git(&binding, &worker).map(|phase| {
                assert_eq!(phase, GitPhase::Authorized);
            }),
            Write::Rejection => journal.reject_git(&binding, GitRejection::StaleRef, &worker),
            Write::Attempt => {
                let script = Script::new(
                    binding.authorization().clone(),
                    scratch.0.join("journal.sqlite3"),
                    control.clone(),
                );
                let prepared = script
                    .receiver()
                    .prepare(binding.authorization())
                    .await
                    .unwrap();
                journal
                    .begin_git_attempt(&binding, prepared, &worker)
                    .map(drop)
            },
            Write::Response => journal.record_git_acknowledgement(
                &binding,
                Acknowledgement::ReceiverRejected,
                &worker,
            ),
            Write::Observation => journal.freeze_git_observation(
                &binding,
                &if absent_commit {
                    ObservedRef::Missing
                } else {
                    ObservedRef::Commit("b".repeat(40))
                },
                &worker,
            ),
            Write::Receipt => {
                let statement = evidence::GitStatement {
                    authorization: binding.authorization().clone(),
                    authorization_signer: "snapshot-signer".into(),
                    authorization_digest: digest(binding.signed_grant()),
                    acknowledgement: Acknowledgement::Unknown,
                    observed: ObservedRef::Commit("b".repeat(40)),
                };
                let bytes = evidence::sign(&statement, &[9; 32], "bridge-receipt-key").unwrap();
                journal.commit_git_receipt(&binding, &bytes, &worker)
            },
            Write::Authorization => unreachable!(),
        };
        match delivery {
            records::Delivery::Confirmed => assert!(result.is_ok(), "{write:?}: {result:?}"),
            records::Delivery::NoCommit | records::Delivery::LostAcknowledgement => {
                assert!(matches!(result, Err(GatewayError::InjectedFault)));
            },
        }
        let events = control.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id, "sqlite-git-bridge");
        assert_eq!(events[0].effect, "Git");
        assert_eq!(events[0].write, write);
        assert_eq!(events[0].delivery, delivery);
        assert!(
            events[0].consumed,
            "targeted write must consume its delivery"
        );
        let (expected_row, expected_phase) = if delivery == records::Delivery::NoCommit {
            (before, prior_phase)
        } else {
            (next_row, Some(next_phase))
        };
        assert_eq!(
            named_git_row(&journal.connection, "sqlite-git-bridge"),
            expected_row
        );
        assert_eq!(journal.git_operation(&binding).unwrap(), expected_phase);
        assert_eq!(
            named_kube_row(&journal.connection, "untouched-kube-peer"),
            peer_before
        );
        assert_eq!(
            named_git_row(&journal.connection, "untouched-git-peer"),
            git_peer_before,
            "same-table peer survives delivery"
        );
        let sql = control.executed_sql();
        assert_eq!(sql.len(), 1);
        assert_eq!(sql[0].0, write);
        drop(worker);
        drop(journal);
        let reopened = open_scratch(&scratch);
        assert_eq!(
            named_git_row(&reopened.connection, "sqlite-git-bridge"),
            expected_row
        );
        assert_eq!(reopened.git_operation(&binding).unwrap(), expected_phase);
        assert_eq!(
            named_git_row(&reopened.connection, "untouched-git-peer"),
            git_peer_before,
            "same-table peer survives reopen"
        );
        assert_eq!(
            named_kube_row(&reopened.connection, "untouched-kube-peer"),
            peer_before
        );
        sql
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one SQL history pins phase, custody and receipt binding"
    )]
    fn git_rows_bind_authority_phase_and_receipt_to_independent_sql_fields() {
        let scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let binding = git_binding("operation");
        let a = binding.authorization();
        // The fixture bypasses production record writes, including their field ordering.
        journal
            .connection
            .execute(
                "INSERT INTO git_ref_operations (operation_id, repository_id, ref_name, old_commit,
             new_commit, authorization_id, authorization_signer_key_id, authorization_grant_digest,
             signed_authorization_grant, state)
             VALUES (?1, 'repository', 'refs/heads/approved', ?2, ?3, 'approval',
                'snapshot-signer', ?4, ?5, 'authorized')",
                rusqlite::params![
                    a.operation_id,
                    "a".repeat(40),
                    "b".repeat(40),
                    digest(binding.signed_grant()),
                    binding.signed_grant()
                ],
            )
            .unwrap();
        let worker = journal.try_lock_worker().unwrap().unwrap();
        for (phase, facts, expected) in [
            ("authorized", "", GitPhase::Authorized),
            (
                "not_attempted",
                ", target_rejection = 'stale_ref'",
                GitPhase::NotAttempted(GitRejection::StaleRef),
            ),
            (
                "not_attempted",
                ", target_rejection = 'invalid_objects'",
                GitPhase::NotAttempted(GitRejection::InvalidObjects),
            ),
            ("apply_started", "", GitPhase::Attempted(None)),
            (
                "apply_started",
                ", acknowledgement = 'updated'",
                GitPhase::Attempted(Some(Acknowledgement::Updated)),
            ),
            (
                "receiver_observed",
                ", acknowledgement = 'unknown', observed_ref_kind = 'missing'",
                GitPhase::Observed {
                    acknowledgement: Acknowledgement::Unknown,
                    observed: ObservedRef::Missing,
                },
            ),
        ] {
            journal
                .connection
                .execute_batch(&format!(
                    "UPDATE git_ref_operations SET state = '{phase}', target_rejection = NULL,
                 acknowledgement = NULL, observed_ref_kind = NULL{facts}"
                ))
                .unwrap();
            assert_eq!(
                journal.git_operation(&binding).unwrap(),
                Some(expected.clone())
            );
            assert_eq!(
                journal
                    .retained_git("operation", &[trust()])
                    .unwrap()
                    .unwrap()
                    .1,
                expected
            );
            if expected != GitPhase::Attempted(None) {
                let before = records::read_git(&journal.connection, "operation").unwrap();
                assert!(matches!(
                    journal.record_git_acknowledgement(&binding, Acknowledgement::Updated, &worker),
                    Err(GatewayError::InvalidTransition)
                ));
                assert_eq!(
                    records::read_git(&journal.connection, "operation").unwrap(),
                    before
                );
            }
            if matches!(expected, GitPhase::Observed { .. }) {
                assert!(matches!(
                    journal.freeze_git_observation(&binding, &ObservedRef::Unknown, &worker),
                    Err(GatewayError::InvalidTransition)
                ));
            }
            Journal::validate_mixed_replacement(
                &scratch.0.join("journal.sqlite3"),
                &[],
                &[git_binding("operation")],
            )
            .unwrap();
        }
        let statement = evidence::GitStatement {
            authorization: a.clone(),
            authorization_signer: "snapshot-signer".into(),
            authorization_digest: digest(binding.signed_grant()),
            acknowledgement: Acknowledgement::Unknown,
            observed: ObservedRef::Missing,
        };
        let mut foreign = statement.clone();
        foreign.observed = ObservedRef::Unknown;
        let bytes = evidence::sign(&foreign, &[9; 32], "receipt-key").unwrap();
        assert!(matches!(
            journal.commit_git_receipt(&binding, &bytes, &worker),
            Err(GatewayError::InvalidPersistedState)
        ));
        let bytes = evidence::sign(&statement, &[9; 32], "receipt-key").unwrap();
        journal
            .commit_git_receipt(&binding, &bytes, &worker)
            .unwrap();
        let expected = GitPhase::Finalized {
            statement: Box::new(statement),
            receipt: FrozenReceipt {
                operation_id: "operation".into(),
                digest: digest(&bytes),
                bytes,
                key_id: "receipt-key".into(),
            },
        };
        assert_eq!(journal.git_operation(&binding).unwrap(), Some(expected));
        drop(worker);
        drop(journal);
        let baseline = scratch.0.join("journal.sqlite3");
        for assignment in [
            "repository_id = 'other'",
            "ref_name = 'refs/heads/other'",
            "old_commit = 'c'",
            "new_commit = 'd'",
            "authorization_id = 'other'",
            "authorization_signer_key_id = 'other'",
            "authorization_grant_digest = '00'",
            "signed_authorization_grant = X'00'",
            "receipt_bytes = NULL",
            "receipt_digest = '00'",
            "receipt_key_id = 'other'",
            "acknowledgement = 'updated'",
            "observed_ref_kind = 'commit'",
            "target_rejection = 'stale_ref'",
            "state = 'requested'",
        ] {
            let corrupt = Scratch::new();
            let path = corrupt.0.join("journal.sqlite3");
            copy_closed_journal(&baseline, &path);
            let journal = open_scratch(&corrupt);
            journal
                .connection
                .execute_batch(&format!("UPDATE git_ref_operations SET {assignment}"))
                .unwrap();
            assert!(journal.git_operation(&binding).is_err(), "{assignment}");
            assert!(
                journal.retained_git("operation", &[trust()]).is_err(),
                "{assignment}"
            );
            let before = std::fs::read(&path).unwrap();
            assert!(
                Journal::validate_mixed_replacement(&path, &[], &[git_binding("operation")])
                    .is_err(),
                "{assignment}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn acknowledgement_and_not_attempted_are_phase_guarded() {
        let scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let worker = journal.try_lock_worker().unwrap().unwrap();
        let original = git_binding("operation");
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
        let scratch = Scratch::new();
        let journal = open_scratch(&scratch);
        let worker = journal.try_lock_worker().unwrap().unwrap();
        History::kube("shared").insert(&journal.connection, "authorized");
        assert!(matches!(
            journal.insert_git(&git_binding("shared"), &worker),
            Err(GatewayError::OperationIdentityConflict)
        ));
        for index in 0..31 {
            journal
                .insert_git(&git_binding(&format!("git-{index}")), &worker)
                .unwrap();
        }
        assert_eq!(capacity::counts(&journal.connection).unwrap(), (32, 32));
        assert!(matches!(
            journal.insert_git(&git_binding("full"), &worker),
            Err(GatewayError::JournalFull)
        ));
        assert_eq!(
            journal.insert_git(&git_binding("git-0"), &worker).unwrap(),
            GitPhase::Authorized
        );
        let binding = git_binding("git-0");
        journal
            .connection
            .execute_batch(
                "UPDATE git_ref_operations SET state='receiver_observed',
             acknowledgement='unknown', observed_ref_kind='missing' WHERE operation_id='git-0'",
            )
            .unwrap();
        let statement = evidence::GitStatement {
            authorization: binding.authorization().clone(),
            authorization_signer: "snapshot-signer".into(),
            authorization_digest: digest(binding.signed_grant()),
            acknowledgement: Acknowledgement::Unknown,
            observed: ObservedRef::Missing,
        };
        let bytes = evidence::sign(&statement, &[9; 32], "receipt-key").unwrap();
        journal
            .commit_git_receipt(&binding, &bytes, &worker)
            .unwrap();
        assert_eq!(capacity::counts(&journal.connection).unwrap(), (32, 31));
        journal
            .insert_git(&git_binding("released-slot"), &worker)
            .unwrap();
        drop(worker);
        drop(journal);
        let reopened = open_scratch(&scratch);
        assert_eq!(capacity::counts(&reopened.connection).unwrap(), (33, 32));
        let Some(GitPhase::Finalized { receipt, .. }) = reopened.git_operation(&binding).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(receipt.bytes, bytes);
    }
}
