//! Pre-V1 Kapsel experiment for one authorized Kubernetes Deployment image change.
//!
//! The [`Application`] composition root separates request-only [`AgentRequest`] from operator-owned
//! authorization, Kubernetes authority, signing material, and paths. The private deep gateway owns
//! the KAP-0038 request, exact authorization, durable lifecycle, Kubernetes interaction, recovery,
//! and prototype receipt. This crate exposes no generic capability or provider contract.
//!
//! This pre-V1 release candidate has no stable Rust or receipt-format compatibility promise and
//! makes no production-readiness, exactly-once, causation, Kubernetes-truth, complete-capture, or
//! witnessing claim.

mod application;
mod gateway;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod simulation_tests;

pub use application::{
    provision_exact_grant, AgentRequest, Application, ApplicationError, GrantProvisioning,
    OperationReport, OperatorConfiguration,
};
pub use gateway::{
    inspect_receipt, AuthorizationTrust, ExactAuthorization, GatewayError, InputField,
    InspectionLimits, InspectionReport, InspectionStatus, OperationResult, OperationState,
    ReceiptError, ReceiptReference, ReceiptStatement, ReceiptTrust, SetDeploymentImageRequest,
    SubmissionResult, TargetRejection,
};

#[cfg(test)]
use gateway::FaultPoint;
#[cfg(test)]
use gateway::{DeploymentImageAdapter, Gateway, ReceiptSettings, TargetReadError};
#[cfg(test)]
use gateway::{
    TestApplyOutcome as ApplyOutcome,
    TestKubernetesDeploymentImageAdapter as KubernetesDeploymentImageAdapter,
    TestReceiverObservation as ReceiverObservation, TestTargetIdentity as TargetIdentity,
};
