//! Prototype-scoped gateway for one authorized Kubernetes Deployment image change.
//!
//! This crate owns the KAP-0038 request, exact authorization, durable lifecycle, Kubernetes
//! interaction, and recovery. It deliberately exposes no generic capability or provider contract.

mod authorization;
mod gateway;
mod journal;
#[cfg(test)]
mod kind_tests;
mod kubernetes_adapter;
mod kubernetes_facts;
mod publication;
mod receipt;

pub use authorization::{sign_authorization_grant, AuthorizationTrust};
pub use gateway::{
    ExactAuthorization, Gateway, GatewayError, InputField, OperationResult, OperationState,
    ReceiptReference, ReceiptSettings, SetDeploymentImageRequest, SubmissionResult,
    TargetRejection,
};
pub use receipt::{
    inspect_receipt, InspectionLimits, InspectionReport, InspectionStatus, ReceiptError,
    ReceiptStatement, ReceiptTrust,
};

#[cfg(test)]
use gateway::FaultPoint;
use gateway::{
    validate_dns_label, validate_dns_subdomain, validate_identity, validate_immutable_image,
    DeploymentImageAdapter, FrozenReceipt, TargetReadError, WRITE_STRATEGY,
};
