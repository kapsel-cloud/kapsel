//! Application-owned composition for the one KAP-0038 operation.
//!
//! This module separates request-only agent intent from operator-owned authorization, Kubernetes
//! authority, receipt signing material, and durable paths. It is not a configuration-file grammar
//! or command adapter.

use std::{
    error::Error,
    fmt, fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use ed25519_dalek::SigningKey;

use crate::{
    authorization::verify_authorization_grant, publication, receipt, AuthorizationTrust,
    ExactAuthorization, Gateway, GatewayError, OperationResult, OperationState, ReceiptReference,
    ReceiptSettings, SetDeploymentImageRequest, SubmissionResult, TargetRejection,
};

/// Request-only caller input for the sole supported operation.
pub type AgentRequest = SetDeploymentImageRequest;

/// Inputs controlled by the operator before an application instance opens durable state.
///
/// The signed grant, trust, Kubernetes client, signing seed, and paths must come from application
/// composition rather than agent request fields. This type deliberately does not implement
/// `Debug`, preventing accidental diagnostics from printing its secret-bearing fields.
pub struct OperatorConfiguration {
    /// Journal location owned by the operator.
    pub journal_path: PathBuf,
    /// Pre-existing owner-private receipt output directory.
    pub receipt_output_directory: PathBuf,
    /// Out-of-band trust for the exact authorization-grant signer.
    pub authorization_trust: AuthorizationTrust,
    /// One owner-signed exact grant used for request submission.
    pub signed_authorization_grant: Vec<u8>,
    /// Kubernetes authority constructed outside agent input.
    pub kubernetes_client: kube::Client,
    /// Receipt-signing seed controlled by the operator.
    pub receipt_signing_seed: [u8; 32],
    /// Public identity for the receipt-signing key.
    pub receipt_signing_key_id: String,
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

/// Produces the canonical fixed-purpose grant supplied later through operator configuration.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidGrantProvisioning`] when the authorization tuple or signing
/// key identity violates the bounded grant grammar.
pub fn provision_exact_grant(
    provisioning: &GrantProvisioning<'_>,
) -> Result<Vec<u8>, ApplicationError> {
    crate::authorization::sign_authorization_grant(
        provisioning.authorization,
        provisioning.signing_seed,
        provisioning.signing_key_id,
    )
    .map_err(|_| ApplicationError::InvalidGrantProvisioning)
}

/// Application-level report shared by future local and MCP adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReport {
    /// Stable operation identity fixed by the configured authorization grant.
    pub operation_id: String,
    /// Current durable lifecycle state.
    pub state: OperationState,
    /// Receiver result, present only after receiver observation.
    pub result: Option<OperationResult>,
    /// Pre-attempt target rejection, distinct from a receiver result.
    pub target_rejection: Option<TargetRejection>,
    /// Frozen receipt reference, present only after finalization.
    pub receipt: Option<ReceiptReference>,
}

/// Compile-time composition root for the evaluator application.
pub struct Application {
    gateway: Gateway,
    kubernetes_client: kube::Client,
    signed_authorization_grant: Vec<u8>,
    authorized_request: AgentRequest,
    receipt_signing_key: SigningKey,
    receipt_signing_key_id: String,
    receipt_output_directory: PathBuf,
}

impl Application {
    /// Validates operator configuration before opening or creating the journal.
    ///
    /// Grant trust, canonical grant bytes, receipt key identity, and output-directory safety are
    /// checked before durable state is opened. Constructing the Kubernetes client and protecting
    /// its credentials remain operator responsibilities.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when grant trust, receipt authority, or paths are
    /// unsafe. Journal open, durability, migration, and filesystem failures are returned as
    /// [`ApplicationError::Gateway`].
    pub fn open(configuration: OperatorConfiguration) -> Result<Self, ApplicationError> {
        let verified = verify_authorization_grant(
            &configuration.signed_authorization_grant,
            &configuration.authorization_trust,
        )
        .map_err(|_| ApplicationError::InvalidAuthorizationConfiguration)?;
        receipt::validate_key_id(&configuration.receipt_signing_key_id)
            .map_err(|_| ApplicationError::InvalidReceiptConfiguration)?;
        publication::validate_private_directory(&configuration.receipt_output_directory)
            .map_err(|_| ApplicationError::InvalidReceiptOutputDirectory)?;
        validate_journal_path(&configuration.journal_path)?;

        let authorized_request = AgentRequest {
            operation_id: verified.authorization.operation_id,
            namespace: verified.authorization.namespace,
            deployment: verified.authorization.deployment,
            container: verified.authorization.container,
            immutable_image_digest: verified.authorization.immutable_image_digest,
        };
        let gateway = Gateway::open(
            &configuration.journal_path,
            configuration.authorization_trust,
        )
        .map_err(ApplicationError::Gateway)?;
        Ok(Self {
            gateway,
            kubernetes_client: configuration.kubernetes_client,
            signed_authorization_grant: configuration.signed_authorization_grant,
            authorized_request,
            receipt_signing_key: SigningKey::from_bytes(&configuration.receipt_signing_seed),
            receipt_signing_key_id: configuration.receipt_signing_key_id,
            receipt_output_directory: configuration.receipt_output_directory,
        })
    }

    /// Submits request-only intent under the operator-configured exact grant.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::Gateway`] when intent is malformed, differs from the configured
    /// exact grant, conflicts with durable facts, or cannot be persisted.
    pub fn submit(&self, request: &AgentRequest) -> Result<SubmissionResult, ApplicationError> {
        self.gateway
            .submit_authorized(request, &self.signed_authorization_grant)
            .map_err(ApplicationError::Gateway)
    }

    /// Submits request-only intent and owns all subsequent lifecycle sequencing.
    ///
    /// # Errors
    ///
    /// Returns a submission or reconciliation error, including bounded Kubernetes ambiguity,
    /// durable-state failure, or receipt-publication failure.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation may occur after request persistence or the durable mutation marker. It does not
    /// establish that Kubernetes was untouched. Reopen the application with the same operator
    /// configuration and call [`Application::reconcile`] to resume without a blind second mutation.
    pub async fn execute(
        &mut self,
        request: &AgentRequest,
    ) -> Result<OperationReport, ApplicationError> {
        self.submit(request)?;
        self.reconcile()
            .await?
            .ok_or(ApplicationError::InvalidApplicationState)
    }

    /// Recovers and advances the configured operation to its next externally blocked or terminal
    /// report without allowing an adapter to sequence durable states.
    ///
    /// # Errors
    ///
    /// Returns a typed gateway error when recovery cannot read or advance durable state, perform
    /// bounded Kubernetes interaction, or publish the frozen receipt.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation preserves the last committed lifecycle state. A later call with the same
    /// operator configuration resumes that exact operation; after `apply_started`, recovery
    /// observes rather than blindly issuing another mutation.
    pub async fn reconcile(&mut self) -> Result<Option<OperationReport>, ApplicationError> {
        loop {
            let Some(report) = self.report()? else {
                return Ok(None);
            };
            match report.state {
                OperationState::Requested => {
                    self.gateway
                        .submit_authorized(
                            &self.authorized_request,
                            &self.signed_authorization_grant,
                        )
                        .map_err(ApplicationError::Gateway)?;
                },
                OperationState::Authorized | OperationState::ApplyStarted => {
                    if self
                        .gateway
                        .run_operation_once(
                            &self.authorized_request.operation_id,
                            self.kubernetes_client.clone(),
                        )
                        .await
                        .map_err(ApplicationError::Gateway)?
                        .is_none()
                    {
                        return self.report();
                    }
                },
                OperationState::ReceiverObserved
                | OperationState::ReceiptPrepared
                | OperationState::ReceiptWritten => {
                    if self
                        .gateway
                        .finalize_operation_receipt_once(
                            &self.authorized_request.operation_id,
                            &ReceiptSettings {
                                signing_seed: self.receipt_signing_key.as_bytes(),
                                key_id: &self.receipt_signing_key_id,
                                output_directory: &self.receipt_output_directory,
                            },
                        )
                        .map_err(ApplicationError::Gateway)?
                        .is_none()
                    {
                        return self.report();
                    }
                },
                OperationState::NotAttempted | OperationState::Finalized => {
                    return Ok(Some(report));
                },
            }
        }
    }

    /// Reports the configured operation without provider or network access.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::Gateway`] when the atomic durable snapshot cannot be read or
    /// contains facts outside the owned lifecycle.
    pub fn report(&self) -> Result<Option<OperationReport>, ApplicationError> {
        let operation_id = &self.authorized_request.operation_id;
        let Some(snapshot) = self
            .gateway
            .operation_snapshot(operation_id)
            .map_err(ApplicationError::Gateway)?
        else {
            return Ok(None);
        };
        Ok(Some(OperationReport {
            operation_id: operation_id.clone(),
            state: snapshot.state,
            result: snapshot.result,
            target_rejection: snapshot.target_rejection,
            receipt: snapshot.receipt,
        }))
    }
}

fn validate_journal_path(path: &Path) -> Result<(), ApplicationError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(ApplicationError::InvalidJournalPath);
    }
    let parent = path.parent().ok_or(ApplicationError::InvalidJournalPath)?;
    publication::validate_private_directory(parent)
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

/// Bounded application composition or operation failure.
#[derive(Debug)]
pub enum ApplicationError {
    /// Operator grant-signing inputs were invalid.
    InvalidGrantProvisioning,
    /// Configured grant bytes or trust were invalid.
    InvalidAuthorizationConfiguration,
    /// Receipt signing-key identity was invalid.
    InvalidReceiptConfiguration,
    /// Journal path was relative, unsafe, symlinked, or outside an owner-private directory.
    InvalidJournalPath,
    /// Receipt output was absent, unsafe, or not owner-private.
    InvalidReceiptOutputDirectory,
    /// Application state did not contain the configured operation after submission.
    InvalidApplicationState,
    /// The deep gateway rejected configuration, intent, durable state, or provider interaction.
    Gateway(GatewayError),
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::InvalidGrantProvisioning => "invalid_grant_provisioning",
            Self::InvalidAuthorizationConfiguration => "invalid_authorization_configuration",
            Self::InvalidReceiptConfiguration => "invalid_receipt_configuration",
            Self::InvalidJournalPath => "invalid_journal_path",
            Self::InvalidReceiptOutputDirectory => "invalid_receipt_output_directory",
            Self::InvalidApplicationState => "invalid_application_state",
            Self::Gateway(_) => "gateway",
        };
        write!(formatter, "Kapsel application failure: {class}")
    }
}

impl Error for ApplicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Gateway(error) => Some(error),
            Self::InvalidGrantProvisioning
            | Self::InvalidAuthorizationConfiguration
            | Self::InvalidReceiptConfiguration
            | Self::InvalidJournalPath
            | Self::InvalidReceiptOutputDirectory
            | Self::InvalidApplicationState => None,
        }
    }
}
