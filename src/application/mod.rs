//! Operator provisioning and resident-service composition for the two concrete effects.

mod service;

use std::{
    error::Error,
    fmt, fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path},
};

use http_body_util::Limited;
use kube::{config::KubeConfigOptions, Config};
pub use service::{
    parse_service_operator_document, ApprovedAction, ExecutionCondition, ExecutionDisposition,
    ExecutionObservation, HistoryEntry, HistoryPage, ServiceAdmission, ServiceApplication,
    ServiceApproval, ServiceConfiguration, ServiceError, ServiceExecution, ServiceOperatorDocument,
    ServiceStop,
};
use tower_http::map_response_body::MapResponseBodyLayer;

use crate::gateway::{
    sign_authorization_grant, ExactAuthorization, OperationResult, OperationState, TargetRejection,
};

/// Exact Kubernetes operation tuple retained by operator approval and service history.
pub type AgentRequest = crate::gateway::SetDeploymentImageRequest;

pub use kapsel_authority::ValidatedServiceOperatorInputs;

/// Validates the service grant, authorization key, receipt seed, and evaluator trust together.
///
/// The returned value contains only public identity. This function performs no filesystem,
/// network, environment, clock, or durable-state access.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidOperatorConfiguration`] for malformed or inconsistent input.
pub fn validate_service_operator_inputs(
    signed_authorization_grant: &[u8],
    authorization_public_key: &[u8; 32],
    receipt_signing_seed: &[u8; 32],
    receipt_trust: &[u8],
) -> Result<ValidatedServiceOperatorInputs, ApplicationError> {
    kapsel_authority::validate_service_operator_inputs(
        signed_authorization_grant,
        authorization_public_key,
        receipt_signing_seed,
        receipt_trust,
    )
    .map_err(|_| ApplicationError::InvalidOperatorConfiguration)
}

/// Operator-only inputs for provisioning one exact authorization grant.
///
/// This type deliberately does not implement `Debug` because it contains signing material.
pub struct GrantProvisioning<'a> {
    /// Exact operation tuple the owner is authorizing.
    pub authorization: &'a ExactAuthorization,
    /// Owner-controlled Ed25519 signing seed.
    pub signing_seed: &'a [u8; 32],
    /// Public identity for the authorization signing key.
    pub signing_key_id: &'a str,
}

/// Produces a canonical fixed-purpose grant from explicit operator authority.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidGrantProvisioning`] for an invalid tuple or key identity.
pub fn provision_exact_grant(
    provisioning: &GrantProvisioning<'_>,
) -> Result<Vec<u8>, ApplicationError> {
    sign_authorization_grant(
        provisioning.authorization,
        provisioning.signing_seed,
        provisioning.signing_key_id,
    )
    .map_err(|_| ApplicationError::InvalidGrantProvisioning)
}

/// Signs an exact Git transition after checking the operator's fixed receiver and objects.
///
/// Preflight reads the prepared repositories without pushing or admitting an operation.
/// The grant fixes the expected old commit. A later push must still use an exact lease so a ref
/// change after provisioning cannot authorize overwriting that change.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidGrantProvisioning`] for invalid inputs or failed preflight.
pub async fn provision_git_ref_grant(
    authorization: &kapsel_authority::GitRefAuthorization,
    receiver: &crate::GitReceiverConfiguration,
    signing_seed: &[u8; 32],
    signing_key_id: &str,
) -> Result<Vec<u8>, ApplicationError> {
    let grant = kapsel_authority::sign_git_ref_grant(authorization, signing_seed, signing_key_id)
        .map_err(|_| ApplicationError::InvalidGrantProvisioning)?;
    receiver
        .validate_preparation(authorization)
        .await
        .map_err(|_| ApplicationError::InvalidGrantProvisioning)?;
    Ok(grant)
}

/// Acquires the operator-selected Deployment version and signs one snapshot grant.
///
/// The proposal must leave `approved_target` absent. This function reads the Deployment UID and
/// resource version and includes them in the signed approval. The caller supplies a kubeconfig of
/// at most 16 KiB instead of relying on ambient configuration. No Kubernetes mutation or journal
/// creation occurs.
///
/// # Errors
///
/// Returns a bounded configuration or provisioning failure for invalid input or failed acquisition.
pub async fn provision_snapshot_grant(
    provisioning: &GrantProvisioning<'_>,
    kubeconfig: &[u8],
) -> Result<Vec<u8>, ApplicationError> {
    use crate::gateway::{
        ApprovedTarget, DeploymentImageAdapter, KubernetesDeploymentImageAdapter,
    };
    if kubeconfig.len() > 16 * 1024 || provisioning.authorization.approved_target.is_some() {
        return Err(ApplicationError::InvalidGrantProvisioning);
    }
    provision_exact_grant(provisioning)?;
    let client = load_operator_kubernetes_client(kubeconfig).await?;
    let mut adapter = KubernetesDeploymentImageAdapter::new(client);
    let proposal = provisioning.authorization;
    let request = AgentRequest {
        operation_id: proposal.operation_id.clone(),
        namespace: proposal.namespace.clone(),
        deployment: proposal.deployment.clone(),
        container: proposal.container.clone(),
        immutable_image_digest: proposal.immutable_image_digest.clone(),
    };
    let observed = adapter
        .identify(&request)
        .await
        .map_err(|_| ApplicationError::InvalidGrantProvisioning)?;
    let mut authorization = proposal.clone();
    authorization.approved_target = Some(ApprovedTarget {
        uid: observed.deployment_uid,
        resource_version: observed.resource_version,
    });
    provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: provisioning.signing_seed,
        signing_key_id: provisioning.signing_key_id,
    })
}

async fn load_operator_kubernetes_client(bytes: &[u8]) -> Result<kube::Client, ApplicationError> {
    const KUBERNETES_RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(ApplicationError::InvalidOperatorConfiguration);
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(text)
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    let proxy_placeholder_was_added = configure_explicit_kubeconfig(&mut kubeconfig)?;
    let mut client_config =
        Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    if proxy_placeholder_was_added {
        client_config.proxy_url = None;
    }
    // A receiver-side effect followed by 429/503/504 must remain one mutation request.
    client_config.default_retry = false;
    let response_limit =
        MapResponseBodyLayer::new(|body| Limited::new(body, KUBERNETES_RESPONSE_BYTES_MAX));
    Ok(kube::client::ClientBuilder::try_from(client_config)
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?
        .with_layer(&response_limit)
        .build())
}

fn configure_explicit_kubeconfig(
    kubeconfig: &mut kube::config::Kubeconfig,
) -> Result<bool, ApplicationError> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|context| context.name == current)
        .and_then(|context| context.context.as_ref())
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    let cluster_name = context.cluster.clone();
    let user_name = context.user.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|cluster| cluster.name == cluster_name)
        .and_then(|cluster| cluster.cluster.as_mut())
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    if cluster.certificate_authority.is_some() {
        return Err(ApplicationError::InvalidOperatorConfiguration);
    }
    if let Some(user_name) = user_name {
        let user = kubeconfig
            .auth_infos
            .iter()
            .find(|user| user.name == user_name)
            .and_then(|user| user.auth_info.as_ref())
            .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
        if user.token_file.is_some()
            || user.client_certificate.is_some()
            || user.client_key.is_some()
            || user.auth_provider.is_some()
            || user.exec.is_some()
        {
            return Err(ApplicationError::InvalidOperatorConfiguration);
        }
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Read-only exact receipt projection for either service effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetDeploymentImageReceipt {
    /// No durable operation exists for the supplied identity.
    NotFound,
    /// The operation exists but has no finalized receipt.
    NotReady,
    /// Original canonical receipt bytes and their frozen lowercase SHA-256 digest.
    Ready {
        /// Exact bytes read from validated private storage.
        bytes: Vec<u8>,
        /// Expected SHA-256 digest frozen in the lifecycle journal.
        sha256: String,
    },
}

/// Read-only stored status for either effect, separate from current worker activity.
///
/// Each effect defines its own success and failure predicates. `Unknown` is terminal evidence that
/// neither predicate was established, not permission to retry the mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetDeploymentImageStatus {
    /// No durable operation exists for the supplied identity.
    NotFound,
    /// The operation has not reached a terminal disposition.
    InProgress,
    /// The exact target was rejected before a mutation attempt.
    NotAttempted(TargetRejection),
    /// Receiver facts established the bounded success predicate.
    Succeeded,
    /// Receiver facts established the bounded failure predicate.
    Failed,
    /// Receiver facts established neither success nor failure.
    Unknown,
}

fn status_of(
    state: OperationState,
    target_rejection: Option<TargetRejection>,
    result: Option<OperationResult>,
) -> Result<SetDeploymentImageStatus, ServiceError> {
    match state {
        OperationState::Requested
        | OperationState::Authorized
        | OperationState::ApplyStarted
        | OperationState::ReceiverObserved => Ok(SetDeploymentImageStatus::InProgress),
        OperationState::NotAttempted => target_rejection
            .map(SetDeploymentImageStatus::NotAttempted)
            .ok_or(ServiceError::OperationFailure),
        OperationState::Finalized => match result {
            Some(OperationResult::Succeeded) => Ok(SetDeploymentImageStatus::Succeeded),
            Some(OperationResult::Failed) => Ok(SetDeploymentImageStatus::Failed),
            Some(OperationResult::Unknown) => Ok(SetDeploymentImageStatus::Unknown),
            None => Err(ServiceError::OperationFailure),
        },
    }
}

fn validate_journal_path(path: &Path) -> Result<(), ApplicationError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(ApplicationError::InvalidJournalPath);
    }
    let parent = path.parent().ok_or(ApplicationError::InvalidJournalPath)?;
    crate::gateway::validate_private_directory(parent)
        .map_err(|_| ApplicationError::InvalidJournalPath)?;
    validate_private_file_or_missing(path)?;
    let mut worker_lock_path = path.as_os_str().to_os_string();
    worker_lock_path.push(".kap0038-worker.lock");
    validate_private_file_or_missing(Path::new(&worker_lock_path))
}

fn validate_private_file_or_missing(path: &Path) -> Result<(), ApplicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode().trailing_zeros() >= 6 =>
        {
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(ApplicationError::InvalidJournalPath),
    }
}

/// Bounded operator provisioning or service composition failure.
#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "retain existing typed operator failure identities"
)]
pub enum ApplicationError {
    /// An explicit operator input was malformed or inconsistent.
    InvalidOperatorConfiguration,
    /// Operator grant-signing inputs or receiver preflight were invalid.
    InvalidGrantProvisioning,
    /// Journal path is not absolute, private, regular or safely named.
    InvalidJournalPath,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::InvalidOperatorConfiguration => "invalid_operator_configuration",
            Self::InvalidGrantProvisioning => "invalid_grant_provisioning",
            Self::InvalidJournalPath => "invalid_journal_path",
        };
        write!(formatter, "Kapsel application failure: {class}")
    }
}

impl Error for ApplicationError {}

#[cfg(test)]
mod operator_tests;
