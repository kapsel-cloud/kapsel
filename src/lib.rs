//! Kapsel 0.1 experiment for one authorized Kubernetes Deployment image change.
//!
//! The [`Application`] composition root separates request-only [`AgentRequest`] from operator-owned
//! authorization, Kubernetes authority, signing material, and paths. The private deep gateway owns
//! the KAP-0038 request, exact authorization, durable lifecycle, Kubernetes interaction, recovery,
//! and prototype receipt. This crate exposes no generic capability or provider contract.
//!
//! The stable 0.1 artifact has no Rust API or receipt-format compatibility promise and
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
