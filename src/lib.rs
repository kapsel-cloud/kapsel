//! Kapsel execution boundary for approved Kubernetes image changes and local Git ref transitions.
//!
//! [`ServiceApplication`] separates caller-selected IDs from operator-owned approvals, receiver
//! authority, signing material and paths. The private gateway records attempts before mutation,
//! recovers without resending, and retains original signed receipts. Each effect defines its own
//! receiver-result rules. This crate exposes no generic capability or provider contract.
//!
//! These interfaces serve the resident service and operator tools. They are not a stable public
//! Rust API. Kapsel makes no production-readiness, exactly-once, causation, receiver-truth,
//! complete-capture or witnessing claim.

mod application;
mod gateway;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod recovery_policy_tests;
#[cfg(test)]
mod simulation_tests;

pub use application::{
    parse_service_operator_document, provision_exact_grant, provision_git_ref_grant,
    provision_snapshot_grant, validate_service_operator_inputs, AgentRequest, ApplicationError,
    ApprovedAction, ExecutionCondition, ExecutionDisposition, ExecutionObservation,
    GrantProvisioning, HistoryEntry, HistoryPage, ServiceAdmission, ServiceApplication,
    ServiceApproval, ServiceConfiguration, ServiceError, ServiceExecution, ServiceOperatorDocument,
    ServiceStop, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    ValidatedServiceOperatorInputs,
};
pub use gateway::{
    inspect_git_receipt, inspect_receipt, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GitAcknowledgement, GitInspectionReport, GitObservedRef, GitOperationTargets,
    GitReceiptStatement, GitReceiverConfiguration, InspectionLimits, InspectionReport,
    InspectionStatus, ObservedTarget, OperationResult, OperationState, OperationTargets,
    ReceiptError, ReceiptReference, ReceiptStatement, ReceiptTrust, TargetRejection,
    GIT_RECEIPT_PURPOSE,
};
#[cfg(test)]
use gateway::{
    test_deployment_patch_document, TestApplyOutcome as ApplyOutcome,
    TestKubernetesDeploymentImageAdapter as KubernetesDeploymentImageAdapter,
    TestReceiverObservation as ReceiverObservation, TestTargetIdentity as TargetIdentity,
};
#[cfg(test)]
use gateway::{DeploymentImageAdapter, Gateway, ReceiptSettings, TargetReadError};
#[cfg(test)]
use gateway::{FaultPoint, GatewayError, SetDeploymentImageRequest};
