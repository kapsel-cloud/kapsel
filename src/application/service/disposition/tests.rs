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
            ExecutionDisposition::ResumeRequired(Some(ExecutionCondition::PreflightUnavailable)),
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
        Err(ServiceError::OperationFailure)
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
