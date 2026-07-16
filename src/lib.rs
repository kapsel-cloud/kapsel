//! Pre-V1 Kapsel experiment for one authorized Kubernetes Deployment image change.
//!
//! The [`Application`] composition root separates request-only [`AgentRequest`] from operator-owned
//! authorization, Kubernetes authority, signing material, and paths. The private deep gateway owns
//! the KAP-0038 request, exact authorization, durable lifecycle, Kubernetes interaction, recovery,
//! and prototype receipt. This crate exposes no generic capability or provider contract.
//!
//! This alpha has no stable Rust or receipt-format compatibility promise and makes no production-
//! readiness, exactly-once, causation, Kubernetes-truth, complete-capture, or witnessing claim.

mod application;
mod authorization;
mod gateway;
mod journal;
#[cfg(test)]
mod kind_tests;
mod kubernetes_adapter;
mod kubernetes_facts;
mod publication;
mod receipt;

pub use application::{
    provision_exact_grant, AgentRequest, Application, ApplicationError, GrantProvisioning,
    OperationReport, OperatorConfiguration,
};
pub use authorization::AuthorizationTrust;
pub use gateway::{
    ExactAuthorization, GatewayError, InputField, OperationResult, OperationState,
    ReceiptReference, SetDeploymentImageRequest, SubmissionResult, TargetRejection,
};
pub use receipt::{
    inspect_receipt, InspectionLimits, InspectionReport, InspectionStatus, ReceiptError,
    ReceiptStatement, ReceiptTrust,
};

#[cfg(test)]
use gateway::FaultPoint;
use gateway::{
    validate_dns_label, validate_dns_subdomain, validate_identity, validate_immutable_image,
    DeploymentImageAdapter, FrozenReceipt, Gateway, ReceiptSettings, TargetReadError,
    WRITE_STRATEGY,
};
