//! Bounded Kubernetes facts and receiver-result classification for the one operation.
//!
//! This module is pure policy. It performs no Kubernetes calls and no durable I/O.

use crate::gateway::{
    validate_immutable_image, GatewayError, OperationResult, SetDeploymentImageRequest,
    ValidatedRequest,
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
pub(in crate::gateway) struct ValidatedTargetIdentity {
    deployment_uid: String,
    resource_version: String,
}

impl TryFrom<TargetIdentity> for ValidatedTargetIdentity {
    type Error = GatewayError;

    fn try_from(target: TargetIdentity) -> Result<Self, Self::Error> {
        target.validate()?;
        Ok(Self {
            deployment_uid: target.deployment_uid,
            resource_version: target.resource_version,
        })
    }
}

impl ValidatedTargetIdentity {
    pub(in crate::gateway) fn deployment_uid(&self) -> &str {
        &self.deployment_uid
    }

    pub(in crate::gateway) fn resource_version(&self) -> &str {
        &self.resource_version
    }

    pub(in crate::gateway) fn to_adapter_target(&self) -> TargetIdentity {
        TargetIdentity {
            deployment_uid: self.deployment_uid.clone(),
            resource_version: self.resource_version.clone(),
        }
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

    pub(crate) fn observation_is_complete(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> bool {
        self.observation_result(
            &request.operation_id,
            &request.immutable_image_digest,
            outcome,
        ) != OperationResult::Unknown
    }

    pub(in crate::gateway) fn requested_generation(
        &self,
        request: &ValidatedRequest,
        outcome: &ApplyOutcome,
    ) -> Option<i64> {
        self.requested_generation_for(
            request.operation_id(),
            request.immutable_image_digest(),
            outcome,
        )
    }

    pub(in crate::gateway) fn classify(
        &self,
        request: &ValidatedRequest,
        outcome: &ApplyOutcome,
    ) -> OperationResult {
        self.observation_result(
            request.operation_id(),
            request.immutable_image_digest(),
            outcome,
        )
    }

    fn observation_result(
        &self,
        operation_id: &str,
        immutable_image_digest: &str,
        outcome: &ApplyOutcome,
    ) -> OperationResult {
        let operation_matches = self.operation_marker.as_deref() == Some(operation_id)
            && self.image.as_deref() == Some(immutable_image_digest);
        let replica_counts_establish_availability = self.desired_replicas.is_some()
            && self.updated_replicas == self.desired_replicas
            && self.available_replicas == self.desired_replicas
            && self.unavailable_replicas == Some(0);
        let rollout_available = replica_counts_establish_availability && self.available_condition();
        let progress_deadline_exceeded = self.progress_deadline_exceeded();

        let requested_generation =
            self.requested_generation_for(operation_id, immutable_image_digest, outcome);
        let receiver_establishes_requested_generation =
            requested_generation.is_some_and(|requested_generation| {
                operation_matches
                    && outcome.deployment_uid.is_some()
                    && self.deployment_uid == outcome.deployment_uid
                    && self.current_generation == Some(requested_generation)
                    && self
                        .observed_generation
                        .is_some_and(|observed| observed >= requested_generation)
            });

        if receiver_establishes_requested_generation && progress_deadline_exceeded {
            OperationResult::Failed
        } else if receiver_establishes_requested_generation && rollout_available {
            OperationResult::Succeeded
        } else {
            OperationResult::Unknown
        }
    }

    fn requested_generation_for(
        &self,
        operation_id: &str,
        immutable_image_digest: &str,
        outcome: &ApplyOutcome,
    ) -> Option<i64> {
        let operation_matches = self.operation_marker.as_deref() == Some(operation_id)
            && self.image.as_deref() == Some(immutable_image_digest);
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

    fn validated(request: &SetDeploymentImageRequest) -> ValidatedRequest {
        ValidatedRequest::try_from(request).unwrap()
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
    fn target_identity_validation_produces_proof_only_for_bounded_required_facts() {
        assert!(ValidatedTargetIdentity::try_from(TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "resource-version-1".into(),
        })
        .is_ok());
        assert!(ValidatedTargetIdentity::try_from(TargetIdentity {
            deployment_uid: String::new(),
            resource_version: "resource-version-1".into(),
        })
        .is_err());
        assert!(ValidatedTargetIdentity::try_from(TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "x".repeat(KUBERNETES_FACT_BYTES_MAX + 1),
        })
        .is_err());
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
    #[allow(
        clippy::too_many_lines,
        reason = "one finite partition owns the complete result contract"
    )]
    fn classification_partitions_require_correlation_generation_and_terminal_evidence() {
        use OperationResult::{Failed, Succeeded, Unknown};

        type TextField = fn(&mut ReceiverObservation) -> &mut Option<String>;
        type CountField = fn(&mut ReceiverObservation) -> &mut Option<i32>;

        let request = request();
        let validated = validated(&request);
        let check = |o: &ReceiverObservation, outcome: &ApplyOutcome, expected| {
            assert_eq!(
                o.classify(&validated, outcome),
                expected,
                "{o:?}/{outcome:?}"
            );
            assert_eq!(
                o.observation_is_complete(&request, outcome),
                expected != Unknown
            );
        };
        for failure in [false, true] {
            for recovered in [false, true] {
                let mut outcome = apply_outcome();
                if recovered {
                    outcome.accepted = false;
                    outcome.requested_generation = None;
                }
                let mut terminal = unknown_observation(&request);
                terminal.updated_replicas = Some(1);
                terminal.available_replicas = Some(1);
                terminal.unavailable_replicas = Some(0);
                terminal.observed_generation = Some(9);
                terminal.rollout_condition_type =
                    Some(if failure { "Progressing" } else { "Available" }.into());
                terminal.rollout_condition_status =
                    Some(if failure { "False" } else { "True" }.into());
                terminal.rollout_condition_reason =
                    failure.then(|| "ProgressDeadlineExceeded".into());
                let result = if failure { Failed } else { Succeeded };
                check(&terminal, &outcome, result);
                assert_eq!(terminal.requested_generation(&validated, &outcome), Some(2));

                // Missing and unequal values of each required identity cannot establish a result.
                let identities: [TextField; 3] = [
                    |o| &mut o.deployment_uid,
                    |o| &mut o.operation_marker,
                    |o| &mut o.image,
                ];
                for field in identities {
                    for value in [None, Some("other".into())] {
                        let mut o = terminal.clone();
                        *field(&mut o) = value;
                        check(&o, &outcome, Unknown);
                        assert_eq!(
                            o.requested_generation(&validated, &outcome),
                            if recovered { None } else { Some(2) }
                        );
                    }
                }
                for uid in [None, Some("replacement".into())] {
                    let mut response = outcome.clone();
                    response.deployment_uid = uid;
                    check(&terminal, &response, Unknown);
                    assert_eq!(
                        terminal.requested_generation(&validated, &response),
                        if recovered { None } else { Some(2) }
                    );
                }
                for (generation, expected) in [
                    (None, Unknown),
                    (Some(1), Unknown),
                    (Some(2), result),
                    (Some(9), result),
                ] {
                    let mut o = terminal.clone();
                    o.observed_generation = generation;
                    check(&o, &outcome, expected);
                }
                let mut missing = terminal.clone();
                missing.current_generation = None;
                check(&missing, &outcome, Unknown);
                assert_eq!(
                    missing.requested_generation(&validated, &outcome),
                    if recovered { None } else { Some(2) }
                );
                let mut later = terminal.clone();
                later.current_generation = Some(3);
                check(&later, &outcome, if recovered { result } else { Unknown });
                assert_eq!(
                    later.requested_generation(&validated, &outcome),
                    Some(if recovered { 3 } else { 2 })
                );
                for generation in [1, 3] {
                    let mut response = outcome.clone();
                    response.requested_generation = Some(generation);
                    check(&terminal, &response, Unknown);
                    assert_eq!(
                        terminal.requested_generation(&validated, &response),
                        Some(generation)
                    );
                }

                // Availability counts cannot establish failure or override a deadline failure.
                let counts: [(CountField, i32); 4] = [
                    (|o| &mut o.desired_replicas, 2),
                    (|o| &mut o.updated_replicas, 0),
                    (|o| &mut o.available_replicas, 0),
                    (|o| &mut o.unavailable_replicas, 1),
                ];
                for (field, unequal) in counts {
                    for value in [None, Some(unequal)] {
                        let mut o = terminal.clone();
                        *field(&mut o) = value;
                        check(&o, &outcome, if failure { Failed } else { Unknown });
                    }
                }
                let conditions: [(TextField, &str); 2] = [
                    (|o| &mut o.rollout_condition_type, "ReplicaFailure"),
                    (
                        |o| &mut o.rollout_condition_status,
                        if failure { "True" } else { "False" },
                    ),
                ];
                for (field, unequal) in conditions {
                    for value in [None, Some(unequal.into()), Some("Unknown".into())] {
                        let mut o = terminal.clone();
                        *field(&mut o) = value;
                        check(&o, &outcome, Unknown);
                    }
                }
                for reason in [None, Some("OtherReason".into())] {
                    let mut o = terminal.clone();
                    o.rollout_condition_reason = reason;
                    check(&o, &outcome, if failure { Unknown } else { Succeeded });
                }
                let mut replica_failure = terminal.clone();
                replica_failure.rollout_condition_type = Some("ReplicaFailure".into());
                replica_failure.rollout_condition_status = Some("True".into());
                replica_failure.rollout_condition_reason = Some("FailedCreate".into());
                check(&replica_failure, &outcome, Unknown);
                let mut zero = terminal.clone();
                zero.desired_replicas = Some(0);
                zero.updated_replicas = Some(0);
                zero.available_replicas = Some(0);
                check(&zero, &outcome, result);
                let mut unrelated = terminal.clone();
                unrelated.resource_version = Some("unrelated-version".into());
                let mut response = outcome.clone();
                response.accepted = false;
                response.resource_version = None;
                check(&unrelated, &response, result);
            }
        }
    }
}
