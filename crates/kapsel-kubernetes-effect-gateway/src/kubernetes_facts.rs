//! Bounded Kubernetes facts and receiver-result classification for the one experiment operation.
//!
//! This module is pure policy. It performs no Kubernetes calls and no durable I/O.

use crate::{validate_immutable_image, GatewayError, OperationResult, SetDeploymentImageRequest};

pub const KUBERNETES_FACT_BYTES_MAX: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetIdentity {
    pub deployment_uid: String,
    pub resource_version: String,
}

impl TargetIdentity {
    pub fn validate(&self) -> Result<(), GatewayError> {
        validate_required_fact(&self.deployment_uid)?;
        validate_required_fact(&self.resource_version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOutcome {
    pub accepted: bool,
    pub requested_generation: Option<i64>,
    pub deployment_uid: Option<String>,
    pub resource_version: Option<String>,
}

impl ApplyOutcome {
    pub fn validate(&self) -> Result<(), GatewayError> {
        validate_optional_fact(self.deployment_uid.as_deref())?;
        validate_optional_fact(self.resource_version.as_deref())?;
        if self.requested_generation.is_some_and(|value| value < 0) {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiverObservation {
    pub deployment_uid: Option<String>,
    pub resource_version: Option<String>,
    pub current_generation: Option<i64>,
    pub observed_generation: Option<i64>,
    pub image: Option<String>,
    pub operation_marker: Option<String>,
    pub desired_replicas: Option<i32>,
    pub updated_replicas: Option<i32>,
    pub available_replicas: Option<i32>,
    pub unavailable_replicas: Option<i32>,
    pub rollout_condition_type: Option<String>,
    pub rollout_condition_status: Option<String>,
    pub rollout_condition_reason: Option<String>,
}

impl ReceiverObservation {
    pub fn unknown() -> Self {
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

    pub fn validate(&self) -> Result<(), GatewayError> {
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

    pub fn has_terminal_rollout_signal(&self, request: &SetDeploymentImageRequest) -> bool {
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

    pub fn requested_generation(
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

    pub fn classify(
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
