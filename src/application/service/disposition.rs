//! Caller-safe execution guidance. Process observations never become historical evidence.

use super::ServiceError;
use crate::SetDeploymentImageStatus;

/// Why a bounded execution pass stopped, not a receiver result or durable fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionCondition {
    /// A safe target read failed. Explicit selection may repeat that read.
    PreflightUnavailable,
    /// Receiver execution material is unavailable, or receiver I/O failed.
    ReceiverUnavailable,
    /// Receipt signing material is unavailable.
    SigningUnavailable,
    /// Another worker owns the journal. No work was queued.
    WorkerContention,
    /// Frozen evidence could not be completed in storage.
    CompletionBlocked,
    /// An execution failure requires operator inspection.
    OperationBlocked,
}

impl ExecutionCondition {
    /// Fixed non-disclosing protocol token, never a raw error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreflightUnavailable => "preflight_unavailable",
            Self::ReceiverUnavailable => "receiver_unavailable",
            Self::SigningUnavailable => "signing_unavailable",
            Self::WorkerContention => "worker_contention",
            Self::CompletionBlocked => "completion_blocked",
            Self::OperationBlocked => "operation_blocked",
        }
    }
}

/// Current-process knowledge supplied by the physical task owner, not persisted in SQLite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionObservation {
    /// No surviving explanation is known. This does not establish a crash or cancellation.
    Unknown,
    /// This process still owns the selected physical job, possibly blocked on storage.
    Active,
    /// This process owns a different selected physical job.
    OtherWorker,
    /// A pass stopped in this process. A new selection invalidates the old explanation.
    Stopped(ExecutionCondition),
}

/// Actionable execution guidance separate from immutable result and target evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionDisposition {
    /// Durable terminal history. Execution cannot reopen it.
    Complete,
    /// No authenticated admission is visible in this snapshot. A commit may still finish.
    AdmissionUnconfirmed,
    /// A physical job is owned, not necessarily making progress.
    Active,
    /// Another worker must retire before explicit same-ID selection.
    WaitingForWorker,
    /// Explicitly select the same ID. The cause is unknown when absent.
    ResumeRequired(Option<ExecutionCondition>),
    /// Obtain operator remediation, then explicitly select the same ID.
    OperatorRequired(ExecutionCondition),
}

impl ExecutionDisposition {
    pub(super) fn project(
        status: SetDeploymentImageStatus,
        observation: ExecutionObservation,
    ) -> Self {
        match status {
            SetDeploymentImageStatus::NotFound => Self::AdmissionUnconfirmed,
            SetDeploymentImageStatus::NotAttempted(_)
            | SetDeploymentImageStatus::Succeeded
            | SetDeploymentImageStatus::Failed
            | SetDeploymentImageStatus::Unknown => Self::Complete,
            SetDeploymentImageStatus::InProgress => match observation {
                ExecutionObservation::Unknown => Self::ResumeRequired(None),
                ExecutionObservation::Active => Self::Active,
                ExecutionObservation::OtherWorker => Self::WaitingForWorker,
                ExecutionObservation::Stopped(ExecutionCondition::WorkerContention) => {
                    Self::ResumeRequired(Some(ExecutionCondition::WorkerContention))
                },
                ExecutionObservation::Stopped(ExecutionCondition::PreflightUnavailable) => {
                    Self::ResumeRequired(Some(ExecutionCondition::PreflightUnavailable))
                },
                ExecutionObservation::Stopped(condition) => Self::OperatorRequired(condition),
            },
        }
    }

    /// Fixed disposition token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::AdmissionUnconfirmed => "admission_unconfirmed",
            Self::Active => "active",
            Self::WaitingForWorker => "waiting_for_worker",
            Self::ResumeRequired(_) => "resume_required",
            Self::OperatorRequired(_) => "operator_required",
        }
    }

    /// Fixed safe next action. It never authorizes a replacement identity or another mutation.
    pub const fn next_action(self) -> &'static str {
        match self {
            Self::Complete => "inspect_result",
            Self::AdmissionUnconfirmed => "read_same_id",
            Self::Active => "wait",
            Self::WaitingForWorker => "wait_then_select_same_id",
            Self::ResumeRequired(_) => "select_same_id",
            Self::OperatorRequired(_) => "contact_operator",
        }
    }

    /// Who owns the next action, independent of the receiver result.
    pub const fn action_owner(self) -> &'static str {
        match self {
            Self::OperatorRequired(_) => "operator",
            _ => "caller",
        }
    }

    /// Known current-process stop reason, absent when knowledge was lost or superseded.
    pub const fn condition(self) -> Option<ExecutionCondition> {
        match self {
            Self::ResumeRequired(condition) => condition,
            Self::OperatorRequired(condition) => Some(condition),
            _ => None,
        }
    }
}

/// Result of one selection pass. Admission is acknowledged separately before advancement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStop {
    /// The pass returned without a known blockage. Read durable history for the result.
    Finished,
    /// Execution stopped without fabricating a terminal receiver result.
    Blocked(ExecutionCondition),
}

impl ServiceStop {
    /// Converts completion into process-local knowledge without exposing error internals.
    pub fn observation(result: Result<Self, ServiceError>) -> ExecutionObservation {
        match result {
            Ok(Self::Finished) => ExecutionObservation::Unknown,
            Ok(Self::Blocked(condition)) => ExecutionObservation::Stopped(condition),
            Err(_) => ExecutionObservation::Stopped(ExecutionCondition::OperationBlocked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gateway::*, OperationTargets, TargetRejection};

    #[test]
    fn durable_terminal_history_overrides_every_process_observation() {
        let observations = [
            ExecutionObservation::Unknown,
            ExecutionObservation::Active,
            ExecutionObservation::OtherWorker,
            ExecutionObservation::Stopped(ExecutionCondition::SigningUnavailable),
        ];
        for observation in observations {
            for status in [
                SetDeploymentImageStatus::Succeeded,
                SetDeploymentImageStatus::Failed,
                SetDeploymentImageStatus::Unknown,
                SetDeploymentImageStatus::NotAttempted(TargetRejection::StaleApproval),
            ] {
                assert_eq!(
                    ExecutionDisposition::project(status, observation),
                    ExecutionDisposition::Complete
                );
            }
            assert_eq!(
                ExecutionDisposition::project(SetDeploymentImageStatus::NotFound, observation),
                ExecutionDisposition::AdmissionUnconfirmed
            );
        }
    }

    #[test]
    fn unfinished_history_explains_who_can_act_without_inventing_a_cause() {
        let status = SetDeploymentImageStatus::InProgress;
        for (observation, disposition, action, owner) in [
            (
                ExecutionObservation::Unknown,
                ExecutionDisposition::ResumeRequired(None),
                "select_same_id",
                "caller",
            ),
            (
                ExecutionObservation::Active,
                ExecutionDisposition::Active,
                "wait",
                "caller",
            ),
            (
                ExecutionObservation::OtherWorker,
                ExecutionDisposition::WaitingForWorker,
                "wait_then_select_same_id",
                "caller",
            ),
            (
                ExecutionObservation::Stopped(ExecutionCondition::PreflightUnavailable),
                ExecutionDisposition::ResumeRequired(Some(
                    ExecutionCondition::PreflightUnavailable,
                )),
                "select_same_id",
                "caller",
            ),
            (
                ExecutionObservation::Stopped(ExecutionCondition::WorkerContention),
                ExecutionDisposition::ResumeRequired(Some(ExecutionCondition::WorkerContention)),
                "select_same_id",
                "caller",
            ),
        ] {
            assert_eq!(
                ExecutionDisposition::project(status, observation),
                disposition
            );
            assert_eq!(disposition.next_action(), action);
            assert_eq!(disposition.action_owner(), owner);
        }
        for condition in [
            ExecutionCondition::ReceiverUnavailable,
            ExecutionCondition::SigningUnavailable,
            ExecutionCondition::CompletionBlocked,
            ExecutionCondition::OperationBlocked,
        ] {
            let disposition =
                ExecutionDisposition::project(status, ExecutionObservation::Stopped(condition));
            assert_eq!(
                disposition,
                ExecutionDisposition::OperatorRequired(condition)
            );
            assert_eq!(disposition.next_action(), "contact_operator");
            assert_eq!(disposition.action_owner(), "operator");
            assert_eq!(disposition.condition(), Some(condition));
        }
    }

    #[test]
    fn error_classification_owns_blockage_without_retaining_raw_diagnostics() {
        use super::super::classify_stop;
        for (error, expected) in [
            (
                ReconciliationError::Advancement(GatewayError::KubernetesTargetObservation),
                ExecutionCondition::PreflightUnavailable,
            ),
            (
                ReconciliationError::Blocked(ReconciliationBlockage::ReceiverUnavailable),
                ExecutionCondition::ReceiverUnavailable,
            ),
            (
                ReconciliationError::Blocked(ReconciliationBlockage::SigningUnavailable),
                ExecutionCondition::SigningUnavailable,
            ),
            (
                ReconciliationError::Blocked(ReconciliationBlockage::WorkerContention),
                ExecutionCondition::WorkerContention,
            ),
            (
                ReconciliationError::Completion,
                ExecutionCondition::CompletionBlocked,
            ),
        ] {
            assert_eq!(classify_stop(error), Ok(ServiceStop::Blocked(expected)));
        }
        assert_eq!(
            classify_stop(ReconciliationError::Submission(
                GatewayError::UntrustedAuthorizationGrant
            )),
            Err(ServiceError::AuthorityUnavailable)
        );
        assert_eq!(
            classify_stop(ReconciliationError::Advancement(GatewayError::JournalFile(
                std::io::Error::other("SECRET /private/path grant credential")
            ))),
            Err(ServiceError::StorageUnavailable)
        );
        let entry = super::super::HistoryEntry {
            operation_id: "hidden".into(),
            status: Err(ServiceError::AuthorityUnavailable),
        };
        assert_eq!(
            entry.execution_status(ExecutionObservation::Active),
            Err(ServiceError::AuthorityUnavailable)
        );
        let entry = super::super::HistoryEntry {
            operation_id: "unfinished".into(),
            status: Ok((
                SetDeploymentImageStatus::InProgress,
                OperationTargets::default(),
            )),
        };
        assert_eq!(
            entry
                .execution_status(ExecutionObservation::Unknown)
                .map(|value| value.2),
            Ok(ExecutionDisposition::ResumeRequired(None))
        );
    }
}
