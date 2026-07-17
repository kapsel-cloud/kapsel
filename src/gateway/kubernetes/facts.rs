//! Bounded Kubernetes facts and receiver-result classification for the one experiment operation.
//!
//! This module is pure policy. It performs no Kubernetes calls and no durable I/O.

use super::super::{
    validate_immutable_image, GatewayError, OperationResult, SetDeploymentImageRequest,
};

pub(crate) const KUBERNETES_FACT_BYTES_MAX: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetIdentity {
    pub(crate) deployment_uid: String,
    pub(crate) resource_version: String,
}

impl TargetIdentity {
    pub(crate) fn validate(&self) -> Result<(), GatewayError> {
        validate_required_fact(&self.deployment_uid)?;
        validate_required_fact(&self.resource_version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyOutcome {
    pub(crate) accepted: bool,
    pub(crate) requested_generation: Option<i64>,
    pub(crate) deployment_uid: Option<String>,
    pub(crate) resource_version: Option<String>,
}

impl ApplyOutcome {
    pub(crate) fn validate(&self) -> Result<(), GatewayError> {
        validate_optional_fact(self.deployment_uid.as_deref())?;
        validate_optional_fact(self.resource_version.as_deref())?;
        if self.requested_generation.is_some_and(|value| value < 0) {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiverObservation {
    pub(crate) deployment_uid: Option<String>,
    pub(crate) resource_version: Option<String>,
    pub(crate) current_generation: Option<i64>,
    pub(crate) observed_generation: Option<i64>,
    pub(crate) image: Option<String>,
    pub(crate) operation_marker: Option<String>,
    pub(crate) desired_replicas: Option<i32>,
    pub(crate) updated_replicas: Option<i32>,
    pub(crate) available_replicas: Option<i32>,
    pub(crate) unavailable_replicas: Option<i32>,
    pub(crate) rollout_condition_type: Option<String>,
    pub(crate) rollout_condition_status: Option<String>,
    pub(crate) rollout_condition_reason: Option<String>,
}

impl ReceiverObservation {
    pub(crate) fn unknown() -> Self {
        Self {
            deployment_uid: None,
            resource_version: None,
            current_generation: None,
            observed_generation: None,
            image: None,
            operation_marker: None,
            desired_replicas: None,
            updated_replicas: None,
            available_replicas: None,
            unavailable_replicas: None,
            rollout_condition_type: None,
            rollout_condition_status: None,
            rollout_condition_reason: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), GatewayError> {
        validate_optional_fact(self.deployment_uid.as_deref())?;
        validate_optional_fact(self.resource_version.as_deref())?;
        validate_optional_fact(self.operation_marker.as_deref())?;
        validate_optional_fact(self.rollout_condition_type.as_deref())?;
        validate_optional_fact(self.rollout_condition_status.as_deref())?;
        validate_optional_fact(self.rollout_condition_reason.as_deref())?;
        let condition_type_present = self.rollout_condition_type.is_some();
        let condition_status_present = self.rollout_condition_status.is_some();
        let condition_reason_present = self.rollout_condition_reason.is_some();
        if condition_type_present != condition_status_present
            || (!condition_type_present && condition_reason_present)
        {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        if self.current_generation.is_some_and(|value| value < 0)
            || self.observed_generation.is_some_and(|value| value < 0)
            || [
                self.desired_replicas,
                self.updated_replicas,
                self.available_replicas,
                self.unavailable_replicas,
            ]
            .into_iter()
            .flatten()
            .any(|value| value < 0)
        {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        if let Some(image) = &self.image {
            validate_immutable_image(image).map_err(|_| GatewayError::InvalidKubernetesFact)?;
        }
        Ok(())
    }

    pub(crate) fn has_terminal_rollout_signal(&self, request: &SetDeploymentImageRequest) -> bool {
        let operation_matches = self.operation_marker.as_deref()
            == Some(request.operation_id.as_str())
            && self.image.as_deref() == Some(request.immutable_image_digest.as_str());
        let generation_observed = self.current_generation.is_some_and(|generation| {
            self.observed_generation
                .is_some_and(|observed| observed >= generation)
        });
        let replicas_available = self.desired_replicas.is_some()
            && self.updated_replicas == self.desired_replicas
            && self.available_replicas == self.desired_replicas
            && self.unavailable_replicas == Some(0);
        operation_matches
            && generation_observed
            && (self.progress_deadline_exceeded()
                || (replicas_available && self.available_condition()))
    }

    pub(crate) fn requested_generation(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Option<i64> {
        let operation_matches = self.operation_marker.as_deref()
            == Some(request.operation_id.as_str())
            && self.image.as_deref() == Some(request.immutable_image_digest.as_str());
        let receiver_uid_matches =
            outcome.deployment_uid.is_some() && self.deployment_uid == outcome.deployment_uid;
        outcome
            .requested_generation
            .or(if operation_matches && receiver_uid_matches {
                self.current_generation
            } else {
                None
            })
    }

    pub(crate) fn classify(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> OperationResult {
        let operation_matches = self.operation_marker.as_deref()
            == Some(request.operation_id.as_str())
            && self.image.as_deref() == Some(request.immutable_image_digest.as_str());
        let requested_generation = self.requested_generation(request, outcome);
        let Some(requested_generation) = requested_generation else {
            return OperationResult::Unknown;
        };
        let receiver_matches = operation_matches
            && outcome.deployment_uid.is_some()
            && self.deployment_uid == outcome.deployment_uid
            && self.current_generation == Some(requested_generation)
            && self
                .observed_generation
                .is_some_and(|value| value >= requested_generation);
        if !receiver_matches {
            return OperationResult::Unknown;
        }
        if self.progress_deadline_exceeded() {
            return OperationResult::Failed;
        }
        let replicas_available = self.desired_replicas.is_some()
            && self.updated_replicas == self.desired_replicas
            && self.available_replicas == self.desired_replicas
            && self.unavailable_replicas == Some(0);
        if replicas_available && self.available_condition() {
            OperationResult::Succeeded
        } else {
            OperationResult::Unknown
        }
    }

    fn available_condition(&self) -> bool {
        self.rollout_condition_type.as_deref() == Some("Available")
            && self.rollout_condition_status.as_deref() == Some("True")
    }

    fn progress_deadline_exceeded(&self) -> bool {
        self.rollout_condition_type.as_deref() == Some("Progressing")
            && self.rollout_condition_status.as_deref() == Some("False")
            && self.rollout_condition_reason.as_deref() == Some("ProgressDeadlineExceeded")
    }
}

fn validate_required_fact(value: &str) -> Result<(), GatewayError> {
    if value.is_empty() || value.len() > KUBERNETES_FACT_BYTES_MAX || !value.is_ascii() {
        return Err(GatewayError::InvalidKubernetesFact);
    }
    Ok(())
}

fn validate_optional_fact(value: Option<&str>) -> Result<(), GatewayError> {
    if value.is_some_and(|value| {
        value.is_empty() || value.len() > KUBERNETES_FACT_BYTES_MAX || !value.is_ascii()
    }) {
        return Err(GatewayError::InvalidKubernetesFact);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: "op-001".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn unknown_observation(request: &SetDeploymentImageRequest) -> ReceiverObservation {
        ReceiverObservation {
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
            current_generation: Some(2),
            observed_generation: Some(2),
            image: Some(request.immutable_image_digest.clone()),
            operation_marker: Some(request.operation_id.clone()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: None,
            rollout_condition_status: None,
            rollout_condition_reason: None,
        }
    }

    fn apply_outcome() -> ApplyOutcome {
        ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-1".into()),
        }
    }

    #[test]
    fn hostile_facts_fail_before_receiver_state_is_frozen() {
        let request = request();
        let mut oversized_uid = unknown_observation(&request);
        oversized_uid.deployment_uid = Some("u".repeat(KUBERNETES_FACT_BYTES_MAX + 1));
        assert!(matches!(
            oversized_uid.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut oversized_version = unknown_observation(&request);
        oversized_version.resource_version = Some("r".repeat(KUBERNETES_FACT_BYTES_MAX + 1));
        assert!(matches!(
            oversized_version.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut oversized_marker = unknown_observation(&request);
        oversized_marker.operation_marker = Some("m".repeat(KUBERNETES_FACT_BYTES_MAX + 1));
        assert!(matches!(
            oversized_marker.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut invalid_number = unknown_observation(&request);
        invalid_number.updated_replicas = Some(-1);
        assert!(matches!(
            invalid_number.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut oversized_image = unknown_observation(&request);
        oversized_image.image = Some(format!("{}@sha256:{}", "i".repeat(441), "0".repeat(64)));
        assert!(matches!(
            oversized_image.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));
    }

    #[test]
    fn receiver_classification_distinguishes_owned_terminal_facts() {
        let request = request();
        let outcome = apply_outcome();
        let recovered_outcome = ApplyOutcome {
            accepted: false,
            requested_generation: None,
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-0".into()),
        };
        let mut observation = unknown_observation(&request);
        assert_eq!(
            observation.classify(&request, &outcome),
            OperationResult::Unknown
        );
        assert_eq!(
            observation.requested_generation(&request, &recovered_outcome),
            Some(2)
        );
        let mut mismatched_uid = observation.clone();
        mismatched_uid.deployment_uid = Some("replacement-uid".into());
        assert_eq!(
            mismatched_uid.requested_generation(&request, &recovered_outcome),
            None
        );
        let mut missing_stored_uid = recovered_outcome.clone();
        missing_stored_uid.deployment_uid = None;
        assert_eq!(
            observation.requested_generation(&request, &missing_stored_uid),
            None
        );

        observation.updated_replicas = Some(1);
        observation.available_replicas = Some(1);
        observation.unavailable_replicas = Some(0);
        observation.rollout_condition_type = Some("Available".into());
        observation.rollout_condition_status = Some("True".into());
        observation.rollout_condition_reason = Some("DifferentObservedReason".into());
        assert_eq!(
            observation.classify(&request, &outcome),
            OperationResult::Succeeded
        );
        assert_eq!(
            observation.classify(&request, &recovered_outcome),
            OperationResult::Succeeded
        );

        observation.rollout_condition_type = Some("Progressing".into());
        observation.rollout_condition_status = Some("False".into());
        observation.rollout_condition_reason = Some("ProgressDeadlineExceeded".into());
        assert_eq!(
            observation.classify(&request, &outcome),
            OperationResult::Failed
        );
        assert_eq!(
            observation.classify(&request, &recovered_outcome),
            OperationResult::Failed
        );
    }

    #[test]
    fn replica_failure_alone_remains_unknown() {
        let request = request();
        let mut observation = unknown_observation(&request);
        observation.rollout_condition_type = Some("ReplicaFailure".into());
        observation.rollout_condition_status = Some("True".into());
        observation.rollout_condition_reason = Some("FailedCreate".into());

        assert_eq!(
            observation.classify(&request, &apply_outcome()),
            OperationResult::Unknown
        );
        assert!(!observation.has_terminal_rollout_signal(&request));
    }
}
