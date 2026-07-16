//! Deep implementation of the one authorized Kubernetes Deployment image operation.
//!
//! This module owns orchestration and its private test seams. The crate root remains a compact map
//! of the caller-visible interface and concrete internal owners.

use std::{
    error::Error,
    fmt,
    future::Future,
    path::{Path, PathBuf},
};

#[cfg(test)]
use crate::authorization::sign_authorization_grant;
use crate::{
    authorization::{verify_authorization_grant, AuthorizationTrust},
    journal::Journal,
    kubernetes_adapter::KubernetesDeploymentImageAdapter,
    kubernetes_facts::{ApplyOutcome, ReceiverObservation, TargetIdentity},
    publication,
    receipt::{self, sign_statement},
};

/// The one bounded Kubernetes effect accepted by the experiment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetDeploymentImageRequest {
    /// Stable local identity for this operation.
    pub operation_id: String,
    /// Exact Kubernetes namespace containing the target Deployment.
    pub namespace: String,
    /// Exact target Deployment name.
    pub deployment: String,
    /// Exact target container name within the Deployment pod template.
    pub container: String,
    /// Narrow named image reference pinned by a lowercase SHA-256 digest.
    pub immutable_image_digest: String,
}

impl SetDeploymentImageRequest {
    fn validate(&self) -> Result<(), GatewayError> {
        validate_identity(InputField::OperationId, &self.operation_id)?;
        validate_dns_label(InputField::Namespace, &self.namespace)?;
        validate_dns_subdomain(InputField::Deployment, &self.deployment)?;
        validate_dns_label(InputField::Container, &self.container)?;
        validate_immutable_image(&self.immutable_image_digest)
    }
}

/// Exact owner-controlled statement embedded in a signed authorization grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactAuthorization {
    /// Stable local identity for the authorization record.
    pub authorization_id: String,
    /// Exact authorized operation identity.
    pub operation_id: String,
    /// Exact authorized Kubernetes namespace.
    pub namespace: String,
    /// Exact authorized Deployment name.
    pub deployment: String,
    /// Exact authorized container name.
    pub container: String,
    /// Exact authorized immutable image reference.
    pub immutable_image_digest: String,
}

impl ExactAuthorization {
    pub(crate) fn validate(&self) -> Result<(), GatewayError> {
        validate_identity(InputField::AuthorizationId, &self.authorization_id)?;
        validate_identity(InputField::OperationId, &self.operation_id)?;
        validate_dns_label(InputField::Namespace, &self.namespace)?;
        validate_dns_subdomain(InputField::Deployment, &self.deployment)?;
        validate_dns_label(InputField::Container, &self.container)?;
        validate_immutable_image(&self.immutable_image_digest)
    }

    fn matches(&self, request: &SetDeploymentImageRequest) -> bool {
        self.operation_id == request.operation_id
            && self.namespace == request.namespace
            && self.deployment == request.deployment
            && self.container == request.container
            && self.immutable_image_digest == request.immutable_image_digest
    }
}

/// Public durable states defined by the KAP-0038 experiment owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// Bounded request facts are durable.
    Requested,
    /// Authentic grant identity, signer, digest, and exact tuple are durable.
    Authorized,
    /// A permanent target rejection was frozen before any mutation attempt.
    NotAttempted,
    /// The provider attempt marker is durable.
    ApplyStarted,
    /// Bounded receiver facts and result are frozen.
    ReceiverObserved,
    /// Exact signed receipt bytes and publication identity are durable.
    ReceiptPrepared,
    /// The frozen receipt bytes are installed at the frozen path.
    ReceiptWritten,
    /// The operation is terminal and read-only.
    Finalized,
}

/// Outcome of submitting an exact authorized request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionResult {
    /// A new authorized operation was recorded.
    Created,
    /// The same authorized operation already exists in this state.
    Existing(OperationState),
}

/// Bounded permanent target rejection recorded before any mutation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetRejection {
    /// Kubernetes reported that the exact Deployment does not exist.
    DeploymentNotFound,
    /// The exact named container does not exist in the target Deployment.
    ContainerNotFound,
    /// The target lacked a valid bounded UID or resource version.
    InvalidTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetReadError {
    Transient,
    Permanent(TargetRejection),
}

/// Receiver result vocabulary owned by the KAP-0038 experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResult {
    /// The requested generation and image reached the bounded available predicate.
    Succeeded,
    /// Kubernetes reported the requested generation exceeded its progress deadline.
    Failed,
    /// Bounded receiver facts established neither defined outcome.
    Unknown,
}

pub(crate) const WRITE_STRATEGY: &str = "conditional-strategic-merge-patch";

pub(crate) trait DeploymentImageAdapter {
    fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> impl Future<Output = Result<TargetIdentity, TargetReadError>> + Send;

    fn apply(
        &mut self,
        request: &SetDeploymentImageRequest,
        target: &TargetIdentity,
    ) -> impl Future<Output = Result<ApplyOutcome, ()>> + Send;

    fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> impl Future<Output = Result<ReceiverObservation, ()>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultPoint {
    RequestedCommitted,
    AuthorizedCommitted,
    TargetRejectedCommitted,
    ApplyStartedCommitted,
    TargetObserved,
    ApplyReturned,
    ApplyOutcomeCommitted,
    ReceiverRead,
    ReceiverObservedCommitted,
    #[cfg(test)]
    ReceiptPreparedCommitted,
    #[cfg(test)]
    ReceiptPublished,
    #[cfg(test)]
    ReceiptWrittenCommitted,
    #[cfg(test)]
    FinalizedCommitted,
}

/// Signing and output settings supplied by application composition.
pub(crate) struct ReceiptSettings<'a> {
    /// Fixed prototype signing seed owned by the application.
    pub(crate) signing_seed: &'a [u8; 32],
    /// External trust key identifier for the signing key.
    pub(crate) key_id: &'a str,
    /// Owner-controlled output directory for immutable receipt bytes.
    pub(crate) output_directory: &'a Path,
}

/// Immutable receipt reference stored after finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptReference {
    /// Path where exact receipt bytes were installed.
    pub path: PathBuf,
    /// SHA-256 digest of exact receipt bytes.
    pub digest: String,
}

pub(crate) struct FrozenReceipt {
    pub(crate) operation_id: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: String,
    pub(crate) path: PathBuf,
    pub(crate) key_id: String,
}

/// SQLite-backed entry point for the one experiment operation.
pub(crate) struct Gateway {
    journal: Journal,
    authorization_trust: AuthorizationTrust,
}

impl Gateway {
    /// Opens or creates the prototype journal.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        authorization_trust: AuthorizationTrust,
    ) -> Result<Self, GatewayError> {
        authorization_trust.validate()?;
        Ok(Self {
            journal: Journal::open(path)?,
            authorization_trust,
        })
    }

    /// Submits one request under an owner-signed exact authorization grant.
    pub(crate) fn submit_authorized(
        &self,
        request: &SetDeploymentImageRequest,
        signed_grant: &[u8],
    ) -> Result<SubmissionResult, GatewayError> {
        self.submit_authorized_with_fault(request, signed_grant, None)
    }

    fn submit_authorized_with_fault(
        &self,
        request: &SetDeploymentImageRequest,
        signed_grant: &[u8],
        fault: Option<FaultPoint>,
    ) -> Result<SubmissionResult, GatewayError> {
        request.validate()?;
        let verified = verify_authorization_grant(signed_grant, &self.authorization_trust)?;
        if !verified.authorization.matches(request) {
            return Err(GatewayError::AuthorizationMismatch);
        }
        if let Some(existing) = self.journal.existing_submission(request, &verified)? {
            if existing == OperationState::Requested {
                self.journal
                    .mark_authorized(&request.operation_id, &verified)?;
                if fault == Some(FaultPoint::AuthorizedCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                return Ok(SubmissionResult::Created);
            }
            return Ok(SubmissionResult::Existing(existing));
        }
        self.journal.insert_requested(request)?;
        if fault == Some(FaultPoint::RequestedCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        self.journal
            .mark_authorized(&request.operation_id, &verified)?;
        if fault == Some(FaultPoint::AuthorizedCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        Ok(SubmissionResult::Created)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        use ed25519_dalek::SigningKey;

        let seed = [7_u8; 32];
        Self::open(
            path,
            AuthorizationTrust {
                key_id: "kap0038-authorization-test-key".into(),
                public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn submit_exact_for_test(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &ExactAuthorization,
    ) -> Result<SubmissionResult, GatewayError> {
        self.submit_exact_with_fault_for_test(request, authorization, None)
    }

    #[cfg(test)]
    fn submit_exact_with_fault_for_test(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &ExactAuthorization,
        fault: Option<FaultPoint>,
    ) -> Result<SubmissionResult, GatewayError> {
        let signed =
            sign_authorization_grant(authorization, &[7_u8; 32], "kap0038-authorization-test-key")?;
        self.submit_authorized_with_fault(request, &signed, fault)
    }

    /// Reads the durable public state for one local operation identity.
    #[cfg(test)]
    pub(crate) fn get(&self, operation_id: &str) -> Result<Option<OperationState>, GatewayError> {
        self.journal.state(operation_id)
    }

    pub(crate) fn operation_snapshot(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::journal::OperationSnapshot>, GatewayError> {
        self.journal.operation_snapshot(operation_id)
    }

    /// Reads a frozen receiver result when observation has completed.
    #[cfg(test)]
    pub(crate) fn result(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationResult>, GatewayError> {
        self.journal.result(operation_id)
    }

    /// Reads a terminal pre-attempt target rejection, distinct from receiver result.
    #[cfg(test)]
    pub(crate) fn target_rejection(
        &self,
        operation_id: &str,
    ) -> Result<Option<TargetRejection>, GatewayError> {
        self.journal.target_rejection(operation_id)
    }

    /// Writes or finalizes one receipt from frozen receiver facts without Kubernetes access.
    #[cfg(test)]
    pub(crate) fn finalize_receipt_once(
        &self,
        settings: &ReceiptSettings<'_>,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.finalize_receipt_once_with_fault(settings, None)
    }

    pub(crate) fn finalize_operation_receipt_once(
        &self,
        operation_id: &str,
        settings: &ReceiptSettings<'_>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        if self
            .journal
            .request_in_state(operation_id, OperationState::ReceiverObserved)?
            .is_some()
        {
            let receipt = self.build_receipt(operation_id, settings)?;
            publication::validate_private_directory(settings.output_directory)
                .map_err(publication_error)?;
            self.journal.prepare_receipt(&receipt)?;
        }
        if let Some(receipt) = self
            .journal
            .frozen_receipt_for(operation_id, OperationState::ReceiptPrepared)?
        {
            publication::publish_receipt(&receipt.path, &receipt.bytes)
                .map_err(publication_error)?;
            self.journal.mark_receipt_written(operation_id)?;
        }
        if let Some(receipt) = self
            .journal
            .frozen_receipt_for(operation_id, OperationState::ReceiptWritten)?
        {
            if !stored_receipt_matches(&receipt.path, &receipt.bytes)? {
                publication::publish_receipt(&receipt.path, &receipt.bytes)
                    .map_err(publication_error)?;
            }
            self.journal.mark_finalized(operation_id)?;
            return Ok(Some(OperationState::Finalized));
        }
        Ok(None)
    }

    #[cfg(test)]
    fn finalize_receipt_once_with_fault(
        &self,
        settings: &ReceiptSettings<'_>,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        if let Some(request) = self
            .journal
            .next_request(OperationState::ReceiverObserved)?
        {
            let receipt = self.build_receipt(&request.operation_id, settings)?;
            publication::validate_private_directory(settings.output_directory)
                .map_err(publication_error)?;
            self.journal.prepare_receipt(&receipt)?;
            if fault == Some(FaultPoint::ReceiptPreparedCommitted) {
                return Err(GatewayError::InjectedFault);
            }
        }
        if self
            .journal
            .next_request(OperationState::ReceiptPrepared)?
            .is_some()
        {
            return self.publish_prepared_receipt(fault);
        }
        self.finalize_written_receipt(fault)
    }

    #[cfg(test)]
    fn publish_prepared_receipt(
        &self,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let receipt = self
            .journal
            .frozen_receipt(OperationState::ReceiptPrepared)?
            .ok_or(GatewayError::InvalidPersistedState)?;
        publication::publish_receipt(&receipt.path, &receipt.bytes).map_err(publication_error)?;
        if fault == Some(FaultPoint::ReceiptPublished) {
            return Err(GatewayError::InjectedFault);
        }
        self.journal.mark_receipt_written(&receipt.operation_id)?;
        self.finalize_written_operation(&receipt.operation_id, fault)
    }

    #[cfg(test)]
    fn finalize_written_receipt(
        &self,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(receipt) = self
            .journal
            .frozen_receipt(OperationState::ReceiptWritten)?
        else {
            return Ok(None);
        };
        if !stored_receipt_matches(&receipt.path, &receipt.bytes)? {
            publication::publish_receipt(&receipt.path, &receipt.bytes)
                .map_err(publication_error)?;
        }
        self.finalize_written_operation(&receipt.operation_id, fault)
    }

    #[cfg(test)]
    fn finalize_written_operation(
        &self,
        operation_id: &str,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        if fault == Some(FaultPoint::ReceiptWrittenCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        self.journal.mark_finalized(operation_id)?;
        if fault == Some(FaultPoint::FinalizedCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        Ok(Some(OperationState::Finalized))
    }

    fn build_receipt(
        &self,
        operation_id: &str,
        settings: &ReceiptSettings<'_>,
    ) -> Result<FrozenReceipt, GatewayError> {
        let statement = self
            .journal
            .receipt_statement(operation_id)?
            .ok_or(GatewayError::InvalidPersistedState)?;
        let bytes = sign_statement(&statement, settings.signing_seed, settings.key_id)
            .map_err(GatewayError::Receipt)?;
        let digest = publication::receipt_digest_hex(&bytes);
        let path = settings
            .output_directory
            .join(publication::receipt_filename(operation_id, &digest));
        if path.to_str().is_none() {
            return Err(GatewayError::ReceiptPublication);
        }
        Ok(FrozenReceipt {
            operation_id: operation_id.to_owned(),
            bytes,
            digest,
            path,
            key_id: settings.key_id.to_owned(),
        })
    }

    /// Reads the terminal receipt reference for a finalized operation.
    #[cfg(test)]
    pub(crate) fn receipt_reference(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptReference>, GatewayError> {
        self.journal.receipt_reference(operation_id)
    }

    /// Advances at most one operation using explicitly supplied Kubernetes authority.
    ///
    /// Application composition owns the client and keeps it outside request-only caller input. The
    /// concrete client does not establish a generic provider interface.
    #[cfg(test)]
    pub(crate) async fn run_once(
        &mut self,
        client: kube::Client,
    ) -> Result<Option<OperationState>, GatewayError> {
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        self.run_once_with_adapter(&mut adapter, None).await
    }

    pub(crate) async fn run_operation_once(
        &mut self,
        operation_id: &str,
        client: kube::Client,
    ) -> Result<Option<OperationState>, GatewayError> {
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        self.run_once_with_adapter_for(&mut adapter, None, Some(operation_id))
            .await
    }

    #[cfg(test)]
    async fn run_operation_once_with_adapter<A: DeploymentImageAdapter + Send>(
        &mut self,
        operation_id: &str,
        adapter: &mut A,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.run_once_with_adapter_for(adapter, None, Some(operation_id))
            .await
    }

    // The exclusive borrow prevents overlapping journal transitions while provider I/O is pending.
    #[allow(clippy::needless_pass_by_ref_mut, dead_code)]
    pub(crate) async fn run_once_with_adapter<A: DeploymentImageAdapter + Send>(
        &mut self,
        adapter: &mut A,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.run_once_with_adapter_for(adapter, fault, None).await
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn run_once_with_adapter_for<A: DeploymentImageAdapter + Send>(
        &mut self,
        adapter: &mut A,
        fault: Option<FaultPoint>,
        operation_id: Option<&str>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        if let Some(request) = self.request_in_state(OperationState::Authorized, operation_id)? {
            let target = match adapter.identify(&request).await {
                Ok(target) => target,
                Err(TargetReadError::Transient) => {
                    self.journal.defer_target_retry(&request.operation_id)?;
                    return Err(GatewayError::KubernetesTargetObservation);
                },
                Err(TargetReadError::Permanent(rejection)) => {
                    self.journal
                        .mark_not_attempted(&request.operation_id, rejection)?;
                    if fault == Some(FaultPoint::TargetRejectedCommitted) {
                        return Err(GatewayError::InjectedFault);
                    }
                    return Ok(Some(OperationState::NotAttempted));
                },
            };
            if fault == Some(FaultPoint::TargetObserved) {
                return Err(GatewayError::InjectedFault);
            }
            self.journal
                .mark_apply_started(&request.operation_id, WRITE_STRATEGY, &target)?;
            if fault == Some(FaultPoint::ApplyStartedCommitted) {
                return Err(GatewayError::InjectedFault);
            }
            let outcome = adapter
                .apply(&request, &target)
                .await
                .map_err(|()| GatewayError::KubernetesApply)?;
            if fault == Some(FaultPoint::ApplyReturned) {
                return Err(GatewayError::InjectedFault);
            }
            self.journal
                .record_apply_outcome(&request.operation_id, &outcome)?;
            if fault == Some(FaultPoint::ApplyOutcomeCommitted) {
                return Err(GatewayError::InjectedFault);
            }
            let observation = adapter
                .observe(&request)
                .await
                .map_err(|()| GatewayError::KubernetesReceiverObservation)?;
            if fault == Some(FaultPoint::ReceiverRead) {
                return Err(GatewayError::InjectedFault);
            }
            self.journal
                .freeze_observation(&request, &outcome, &observation)?;
            if fault == Some(FaultPoint::ReceiverObservedCommitted) {
                return Err(GatewayError::InjectedFault);
            }
            return Ok(Some(OperationState::ReceiverObserved));
        }
        if let Some(request) = self.request_in_state(OperationState::ApplyStarted, operation_id)? {
            let outcome = self
                .journal
                .persisted_apply_outcome(&request.operation_id)?;
            let observation = adapter
                .observe(&request)
                .await
                .map_err(|()| GatewayError::KubernetesReceiverObservation)?;
            self.journal
                .freeze_observation(&request, &outcome, &observation)?;
            if fault == Some(FaultPoint::ReceiverObservedCommitted) {
                return Err(GatewayError::InjectedFault);
            }
            return Ok(Some(OperationState::ReceiverObserved));
        }
        Ok(None)
    }

    fn request_in_state(
        &self,
        state: OperationState,
        operation_id: Option<&str>,
    ) -> Result<Option<SetDeploymentImageRequest>, GatewayError> {
        operation_id.map_or_else(
            || self.journal.next_request(state),
            |operation_id| self.journal.request_in_state(operation_id, state),
        )
    }
}

fn publication_error(_: publication::PublicationError) -> GatewayError {
    GatewayError::ReceiptPublication
}

fn stored_receipt_matches(path: &Path, expected: &[u8]) -> Result<bool, GatewayError> {
    match publication::read_receipt(path) {
        Ok(existing) if existing == expected => Ok(true),
        Ok(_) => Err(GatewayError::ReceiptDigestMismatch),
        Err(publication::PublicationError::MissingDestination) => Ok(false),
        Err(error) => Err(publication_error(error)),
    }
}

/// Name of an input field rejected by the bounded experiment grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputField {
    /// Operation identity.
    OperationId,
    /// Authorization identity.
    AuthorizationId,
    /// Kubernetes namespace.
    Namespace,
    /// Kubernetes Deployment name.
    Deployment,
    /// Kubernetes container name.
    Container,
    /// Immutable named image reference.
    ImmutableImageDigest,
}

/// Failure before or during the experiment's durable submission boundary.
#[derive(Debug)]
pub enum GatewayError {
    /// SQLite rejected a journal operation.
    Database(rusqlite::Error),
    /// The operating system rejected private journal-file protection.
    JournalFile(std::io::Error),
    /// The operating system rejected the crash-released worker lock.
    WorkerLock(std::io::Error),
    /// Hostile or unsupported input failed its named bound.
    InvalidInput(InputField),
    /// Signed authorization-grant bytes violated their bounded canonical shape.
    InvalidAuthorizationGrant,
    /// The signed grant did not authenticate under the configured owner trust.
    UntrustedAuthorizationGrant,
    /// An authentic authorization grant did not exactly match the request.
    AuthorizationMismatch,
    /// An operation identity was reused for different durable facts.
    OperationIdentityConflict,
    /// SQLite contained a state outside the experiment lifecycle.
    InvalidPersistedState,
    /// A guarded durable transition did not affect exactly one row.
    InvalidTransition,
    /// Kubernetes target observation failed without exposing an unbounded diagnostic.
    KubernetesTargetObservation,
    /// Kubernetes conditional image patch failed without exposing an unbounded diagnostic.
    KubernetesApply,
    /// Kubernetes receiver observation failed without exposing an unbounded diagnostic.
    KubernetesReceiverObservation,
    /// Kubernetes returned a malformed or unbounded typed fact.
    InvalidKubernetesFact,
    /// Deterministic test fault stopped execution at a named crash window.
    InjectedFault,
    /// The bounded prototype journal contains its maximum distinct operations.
    JournalFull,
    /// Prototype receipt bytes could not be built or inspected.
    Receipt(receipt::ReceiptError),
    /// Immutable receipt publication failed.
    ReceiptPublication,
    /// Published receipt bytes differ from the durable digest.
    ReceiptDigestMismatch,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::Database(_) => "database",
            Self::JournalFile(_) => "journal_file",
            Self::WorkerLock(_) => "worker_lock",
            Self::InvalidInput(_) => "invalid_input",
            Self::InvalidAuthorizationGrant => "invalid_authorization_grant",
            Self::UntrustedAuthorizationGrant => "untrusted_authorization_grant",
            Self::AuthorizationMismatch => "authorization_mismatch",
            Self::OperationIdentityConflict => "operation_identity_conflict",
            Self::InvalidPersistedState => "invalid_persisted_state",
            Self::InvalidTransition => "invalid_transition",
            Self::KubernetesTargetObservation => "kubernetes_target_observation",
            Self::KubernetesApply => "kubernetes_apply",
            Self::KubernetesReceiverObservation => "kubernetes_receiver_observation",
            Self::InvalidKubernetesFact => "invalid_kubernetes_fact",
            Self::InjectedFault => "injected_fault",
            Self::JournalFull => "journal_full",
            Self::Receipt(_) => "receipt",
            Self::ReceiptPublication => "receipt_publication",
            Self::ReceiptDigestMismatch => "receipt_digest_mismatch",
        };
        write!(formatter, "Kubernetes effect-gateway failure: {class}")
    }
}

impl Error for GatewayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::JournalFile(error) | Self::WorkerLock(error) => Some(error),
            Self::Receipt(error) => Some(error),
            Self::InvalidInput(_)
            | Self::InvalidAuthorizationGrant
            | Self::UntrustedAuthorizationGrant
            | Self::AuthorizationMismatch
            | Self::OperationIdentityConflict
            | Self::InvalidPersistedState
            | Self::InvalidTransition
            | Self::KubernetesTargetObservation
            | Self::KubernetesApply
            | Self::KubernetesReceiverObservation
            | Self::InvalidKubernetesFact
            | Self::InjectedFault
            | Self::JournalFull
            | Self::ReceiptPublication
            | Self::ReceiptDigestMismatch => None,
        }
    }
}

pub(crate) fn validate_identity(field: InputField, value: &str) -> Result<(), GatewayError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(GatewayError::InvalidInput(field));
    }
    Ok(())
}

pub(crate) fn validate_dns_label(field: InputField, value: &str) -> Result<(), GatewayError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes.first().is_some_and(u8::is_ascii_lowercase_or_digit)
        || !bytes.last().is_some_and(u8::is_ascii_lowercase_or_digit)
        || !bytes
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_lowercase_or_digit() || byte == b'-')
    {
        return Err(GatewayError::InvalidInput(field));
    }
    Ok(())
}

pub(crate) fn validate_dns_subdomain(field: InputField, value: &str) -> Result<(), GatewayError> {
    if value.is_empty()
        || value.len() > 253
        || value
            .split('.')
            .any(|label| validate_dns_label(field, label).is_err())
    {
        return Err(GatewayError::InvalidInput(field));
    }
    Ok(())
}

pub(crate) fn validate_immutable_image(value: &str) -> Result<(), GatewayError> {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest));
    }
    let Some((name, digest)) = value.split_once("@sha256:") else {
        return Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest));
    };
    if name.contains('@')
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || name.split('/').any(|component| {
            let bytes = component.as_bytes();
            bytes.is_empty()
                || !bytes.first().is_some_and(u8::is_ascii_lowercase_or_digit)
                || !bytes.last().is_some_and(u8::is_ascii_lowercase_or_digit)
                || !bytes.iter().copied().all(|byte| {
                    byte.is_ascii_lowercase_or_digit() || matches!(byte, b'.' | b'_' | b'-')
                })
        })
    {
        return Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest));
    }
    Ok(())
}

trait AsciiDnsByte {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}

impl AsciiDnsByte for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use rusqlite::{params, Connection};

    use super::*;
    use crate::{journal, kubernetes_facts, *};

    fn database_path(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "kapsel-kap0038-{}-{}-{name}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        directory.join("journal.sqlite3")
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn journal_uses_full_synchronous_rollback_durability() {
        let path = database_path("sqlite-durability");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let journal_mode = gateway
            .journal
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap();
        let synchronous = gateway
            .journal
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(journal_mode, "delete");
        assert_eq!(synchronous, 2);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

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

    fn authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
        ExactAuthorization {
            authorization_id: "auth-001".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
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

    struct FakeAdapter {
        database_path: PathBuf,
        identify_calls: usize,
        apply_calls: usize,
        observe_calls: usize,
        apply_started_seen: bool,
        outcome: ApplyOutcome,
        observation: ReceiverObservation,
    }

    fn failed_adapter(path: &Path, request: &SetDeploymentImageRequest) -> FakeAdapter {
        FakeAdapter {
            database_path: path.to_path_buf(),
            identify_calls: 0,
            apply_calls: 0,
            observe_calls: 0,
            apply_started_seen: false,
            outcome: ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("deployment-uid-1".into()),
                resource_version: Some("resource-version-1".into()),
            },
            observation: {
                let mut observation = unknown_observation(request);
                observation.rollout_condition_type = Some("Progressing".into());
                observation.rollout_condition_status = Some("False".into());
                observation.rollout_condition_reason = Some("ProgressDeadlineExceeded".into());
                observation
            },
        }
    }

    impl DeploymentImageAdapter for FakeAdapter {
        async fn identify(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            self.identify_calls += 1;
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            request: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            self.apply_calls += 1;
            let connection = Connection::open(&self.database_path).map_err(|_| ())?;
            let persisted: (String, i64, String) = connection
                .query_row(
                    "SELECT state, apply_attempted, write_strategy
                     FROM kubernetes_image_operations
                     WHERE operation_id = ?1",
                    [&request.operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|_| ())?;
            self.apply_started_seen =
                persisted == ("apply_started".into(), 1, WRITE_STRATEGY.into());
            Ok(self.outcome.clone())
        }

        async fn observe(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<ReceiverObservation, ()> {
            self.observe_calls += 1;
            Ok(self.observation.clone())
        }
    }

    struct TargetRoutingAdapter {
        permanent: Option<(String, TargetRejection)>,
        transient_once: Option<String>,
        transient_returned: bool,
        identify_order: Vec<String>,
        apply_order: Vec<String>,
        observe_order: Vec<String>,
    }

    impl TargetRoutingAdapter {
        fn permanent(operation_id: &str, rejection: TargetRejection) -> Self {
            Self {
                permanent: Some((operation_id.into(), rejection)),
                transient_once: None,
                transient_returned: false,
                identify_order: Vec::new(),
                apply_order: Vec::new(),
                observe_order: Vec::new(),
            }
        }

        fn transient_once(operation_id: &str) -> Self {
            Self {
                permanent: None,
                transient_once: Some(operation_id.into()),
                transient_returned: false,
                identify_order: Vec::new(),
                apply_order: Vec::new(),
                observe_order: Vec::new(),
            }
        }
    }

    impl DeploymentImageAdapter for TargetRoutingAdapter {
        async fn identify(
            &mut self,
            request: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            self.identify_order.push(request.operation_id.clone());
            if let Some((operation_id, rejection)) = &self.permanent {
                if operation_id == &request.operation_id {
                    return Err(TargetReadError::Permanent(*rejection));
                }
            }
            if self.transient_once.as_deref() == Some(request.operation_id.as_str())
                && !self.transient_returned
            {
                self.transient_returned = true;
                return Err(TargetReadError::Transient);
            }
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            request: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            self.apply_order.push(request.operation_id.clone());
            Ok(ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("deployment-uid-1".into()),
                resource_version: Some("resource-version-1".into()),
            })
        }

        async fn observe(
            &mut self,
            request: &SetDeploymentImageRequest,
        ) -> Result<ReceiverObservation, ()> {
            self.observe_order.push(request.operation_id.clone());
            let mut observation = unknown_observation(request);
            observation.rollout_condition_type = Some("Progressing".into());
            observation.rollout_condition_status = Some("False".into());
            observation.rollout_condition_reason = Some("ProgressDeadlineExceeded".into());
            Ok(observation)
        }
    }

    struct ProcessMutationAdapter {
        ready_path: PathBuf,
        patch_count_path: PathBuf,
    }

    impl DeploymentImageAdapter for ProcessMutationAdapter {
        async fn identify(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            _: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            let count = fs::read_to_string(&self.patch_count_path)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                + 1;
            fs::write(&self.patch_count_path, count.to_string()).map_err(|_| ())?;
            fs::write(&self.ready_path, b"provider-side-effect-complete").map_err(|_| ())?;
            std::future::pending::<Result<ApplyOutcome, ()>>().await
        }

        async fn observe(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<ReceiverObservation, ()> {
            Err(())
        }
    }

    #[test]
    #[ignore = "invoked only as a subprocess by process-kill recovery tests"]
    fn process_kill_child() {
        let scenario = std::env::var("KAPSEL_PROCESS_CHILD_SCENARIO").unwrap();
        let database = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_DATABASE").unwrap());
        let ready = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_READY").unwrap());
        if scenario == "mutation" {
            let patch_count =
                PathBuf::from(std::env::var_os("KAPSEL_PROCESS_PATCH_COUNT").unwrap());
            let mut gateway = Gateway::open_for_test(&database).unwrap();
            let mut adapter = ProcessMutationAdapter {
                ready_path: ready,
                patch_count_path: patch_count,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
                .block_on(gateway.run_once_with_adapter(&mut adapter, None))
                .unwrap();
            unreachable!("the parent must kill the child while apply is pending");
        }
        assert_eq!(scenario, "receipt");
        let output = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_OUTPUT").unwrap());
        let gateway = Gateway::open_for_test(&database).unwrap();
        assert!(matches!(
            gateway.finalize_receipt_once_with_fault(
                &ReceiptSettings {
                    signing_seed: &[31_u8; 32],
                    key_id: "process-receipt-key",
                    output_directory: &output,
                },
                Some(FaultPoint::ReceiptPublished),
            ),
            Err(GatewayError::InjectedFault)
        ));
        fs::write(ready, b"receipt-published").unwrap();
        loop {
            std::thread::park();
        }
    }

    fn spawn_process_child(
        scenario: &str,
        database: &Path,
        ready: &Path,
        patch_count: Option<&Path>,
        output: Option<&Path>,
    ) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::process_kill_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_PROCESS_CHILD_SCENARIO", scenario)
            .env("KAPSEL_PROCESS_DATABASE", database)
            .env("KAPSEL_PROCESS_READY", ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(path) = patch_count {
            command.env("KAPSEL_PROCESS_PATCH_COUNT", path);
        }
        if let Some(path) = output {
            command.env("KAPSEL_PROCESS_OUTPUT", path);
        }
        command.spawn().unwrap()
    }

    fn wait_for_child_seam(child: &mut Child, ready: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if ready.exists() {
                return;
            }
            let status = child.try_wait().unwrap();
            assert!(status.is_none(), "process-kill child exited before seam");
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(ready.exists(), "process-kill child did not reach seam");
    }

    fn kill_child(child: &mut Child) {
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[test]
    fn mutable_image_is_rejected_before_persistence() {
        let path = database_path("mutable-image");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let mut request = request();
        request.immutable_image_digest = "registry.example/example/agent-api:latest".into();
        let authorization = authorization(&request);

        assert!(matches!(
            gateway.submit_exact_for_test(&request, &authorization),
            Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn exact_authorization_is_required_before_persistence() {
        let path = database_path("authorization-mismatch");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let mut authorization = authorization(&request);
        authorization.container = "other".into();

        assert!(matches!(
            gateway.submit_exact_for_test(&request, &authorization),
            Err(GatewayError::AuthorizationMismatch)
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn self_signed_or_malformed_grant_fails_before_persistence() {
        let path = database_path("untrusted-grant");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let self_signed = sign_authorization_grant(
            &authorization(&request),
            &[8_u8; 32],
            "kap0038-authorization-test-key",
        )
        .unwrap();
        assert!(matches!(
            gateway.submit_authorized(&request, &self_signed),
            Err(GatewayError::UntrustedAuthorizationGrant)
        ));
        assert!(matches!(
            gateway.submit_authorized(&request, b"self-asserted"),
            Err(GatewayError::InvalidAuthorizationGrant)
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn exact_submission_is_idempotent_but_changed_identity_facts_conflict() {
        let path = database_path("identity");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let exact_authorization = authorization(&request);

        assert_eq!(
            gateway
                .submit_exact_for_test(&request, &exact_authorization)
                .unwrap(),
            SubmissionResult::Created
        );
        assert_eq!(
            gateway
                .submit_exact_for_test(&request, &exact_authorization)
                .unwrap(),
            SubmissionResult::Existing(OperationState::Authorized)
        );

        let mut changed = request.clone();
        changed.deployment = "other-api".into();
        let changed_authorization = authorization(&changed);
        assert!(matches!(
            gateway.submit_exact_for_test(&changed, &changed_authorization),
            Err(GatewayError::OperationIdentityConflict)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn kubernetes_names_and_identities_enforce_contract_bounds() {
        let path = database_path("input-bounds");
        let invalid_requests = [
            {
                let mut value = request();
                value.operation_id = "../outside".into();
                value
            },
            {
                let mut value = request();
                value.namespace = "Uppercase".into();
                value
            },
            {
                let mut value = request();
                value.namespace = "a".repeat(64);
                value
            },
            {
                let mut value = request();
                value.deployment = format!("{}.valid", "a".repeat(64));
                value
            },
            {
                let mut value = request();
                value.container = "-api".into();
                value
            },
        ];
        for invalid in invalid_requests {
            let gateway = Gateway::open_for_test(&path).unwrap();
            let authorization = authorization(&invalid);
            assert!(matches!(
                gateway.submit_exact_for_test(&invalid, &authorization),
                Err(GatewayError::InvalidInput(_))
            ));
            assert_eq!(gateway.get(&invalid.operation_id).unwrap(), None);
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn contract_bounds_accept_exact_maxima_and_reject_values_above_them() {
        let maximum_path = database_path("exact-maxima");
        let mut maximum = request();
        maximum.operation_id = "o".repeat(128);
        maximum.namespace = "n".repeat(63);
        maximum.deployment = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        maximum.container = "c".repeat(63);
        maximum.immutable_image_digest = format!("{}@sha256:{}", "i".repeat(440), "0".repeat(64));
        let mut maximum_authorization = authorization(&maximum);
        maximum_authorization.authorization_id = "a".repeat(128);
        let maximum_gateway = Gateway::open_for_test(&maximum_path).unwrap();
        assert_eq!(
            maximum_gateway
                .submit_exact_for_test(&maximum, &maximum_authorization)
                .unwrap(),
            SubmissionResult::Created
        );
        drop(maximum_gateway);
        fs::remove_dir_all(maximum_path.parent().unwrap()).unwrap();

        let invalid_path = database_path("above-maxima");
        let invalid_gateway = Gateway::open_for_test(&invalid_path).unwrap();
        let invalid_requests = [
            {
                let mut value = request();
                value.operation_id = "o".repeat(129);
                value
            },
            {
                let mut value = request();
                value.deployment = format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62)
                );
                value
            },
            {
                let mut value = request();
                value.container = "c".repeat(64);
                value
            },
            {
                let mut value = request();
                value.immutable_image_digest =
                    format!("{}@sha256:{}", "i".repeat(441), "0".repeat(64));
                value
            },
        ];
        for invalid in invalid_requests {
            assert!(matches!(
                invalid_gateway.submit_exact_for_test(&invalid, &authorization(&invalid)),
                Err(GatewayError::InvalidInput(_))
            ));
            assert_eq!(invalid_gateway.get(&invalid.operation_id).unwrap(), None);
        }
        let valid_request = request();
        let mut invalid_authorization = authorization(&valid_request);
        invalid_authorization.authorization_id = "a".repeat(129);
        assert!(matches!(
            invalid_gateway.submit_exact_for_test(&valid_request, &invalid_authorization),
            Err(GatewayError::InvalidInput(InputField::AuthorizationId))
        ));
        assert_eq!(
            invalid_gateway.get(&valid_request.operation_id).unwrap(),
            None
        );
        drop(invalid_gateway);
        fs::remove_dir_all(invalid_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn full_journal_preserves_existing_idempotency_and_rejects_new_identity() {
        let path = database_path("journal-capacity");
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        {
            let mut existing = request();
            existing.operation_id = "op-0".into();
            let mut existing_authorization = authorization(&existing);
            existing_authorization.authorization_id = "auth-0".into();
            let signed = sign_authorization_grant(
                &existing_authorization,
                &[7_u8; 32],
                "kap0038-authorization-test-key",
            )
            .unwrap();
            let existing_digest = publication::receipt_digest_hex(&signed);
            let transaction = gateway.journal.connection.transaction().unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO kubernetes_image_operations (
                            operation_id, namespace, deployment, container,
                            immutable_image_digest, authorization_id,
                            authorization_signer_key_id, authorization_grant_digest, state
                         ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                                   'authorized')",
                    )
                    .unwrap();
                for index in 0..journal::OPERATION_COUNT_MAX {
                    insert
                        .execute(params![
                            format!("op-{index}"),
                            request().immutable_image_digest,
                            format!("auth-{index}"),
                            "kap0038-authorization-test-key",
                            if index == 0 {
                                existing_digest.as_str()
                            } else {
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            },
                        ])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }
        let mut existing = request();
        existing.operation_id = "op-0".into();
        let mut existing_authorization = authorization(&existing);
        existing_authorization.authorization_id = "auth-0".into();
        assert_eq!(
            gateway
                .submit_exact_for_test(&existing, &existing_authorization)
                .unwrap(),
            SubmissionResult::Existing(OperationState::Authorized)
        );

        let mut overflow = request();
        overflow.operation_id = "overflow".into();
        assert!(matches!(
            gateway.submit_exact_for_test(&overflow, &authorization(&overflow)),
            Err(GatewayError::JournalFull)
        ));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn requested_recovery_rechecks_exact_authorization_before_advancing() {
        let path = database_path("requested-recovery");
        let request = request();
        let authorization = authorization(&request);
        {
            let gateway = Gateway::open_for_test(&path).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &request,
                    &authorization,
                    Some(FaultPoint::RequestedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::Requested)
            );
        }
        let gateway = Gateway::open_for_test(&path).unwrap();
        let mut mismatch = authorization.clone();
        mismatch.container = "other".into();
        assert!(matches!(
            gateway.submit_exact_for_test(&request, &mismatch),
            Err(GatewayError::AuthorizationMismatch)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Requested)
        );
        assert_eq!(
            gateway
                .submit_exact_for_test(&request, &authorization)
                .unwrap(),
            SubmissionResult::Created
        );
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn authorized_commit_reopens_and_begins_exactly_one_apply() {
        let path = database_path("authorized-recovery");
        let request = request();
        {
            let gateway = Gateway::open_for_test(&path).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &request,
                    &authorization(&request),
                    Some(FaultPoint::AuthorizedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::Authorized)
            );
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        let mut adapter = failed_adapter(&path, &request);
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.identify_calls, 1);
        assert_eq!(adapter.apply_calls, 1);
        assert_eq!(adapter.observe_calls, 1);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn permanent_target_rejection_is_terminal_and_does_not_block_later_operations() {
        let path = database_path("permanent-target-rejection");
        let mut rejected = request();
        rejected.operation_id = "op-a".into();
        let mut later = request();
        later.operation_id = "op-b".into();
        {
            let gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&rejected, &authorization(&rejected))
                .unwrap();
            gateway
                .submit_exact_for_test(&later, &authorization(&later))
                .unwrap();
        }
        let mut adapter = TargetRoutingAdapter::permanent(
            &rejected.operation_id,
            TargetRejection::ContainerNotFound,
        );
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            assert!(matches!(
                gateway
                    .run_once_with_adapter(&mut adapter, Some(FaultPoint::TargetRejectedCommitted),)
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&rejected.operation_id).unwrap(),
                Some(OperationState::NotAttempted)
            );
            assert_eq!(
                gateway.target_rejection(&rejected.operation_id).unwrap(),
                Some(TargetRejection::ContainerNotFound)
            );
            assert_eq!(gateway.result(&rejected.operation_id).unwrap(), None);
            assert_eq!(
                gateway.receipt_reference(&rejected.operation_id).unwrap(),
                None
            );
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.identify_order, ["op-a", "op-b"]);
        assert_eq!(adapter.apply_order, ["op-b"]);
        assert_eq!(adapter.observe_order, ["op-b"]);
        assert_eq!(
            gateway.result(&later.operation_id).unwrap(),
            Some(OperationResult::Failed)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn transient_target_error_defers_fairly_without_head_of_line_blocking() {
        let path = database_path("transient-target-deferral");
        let mut deferred = request();
        deferred.operation_id = "op-a".into();
        let mut later = request();
        later.operation_id = "op-b".into();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&deferred, &authorization(&deferred))
            .unwrap();
        gateway
            .submit_exact_for_test(&later, &authorization(&later))
            .unwrap();
        let mut adapter = TargetRoutingAdapter::transient_once(&deferred.operation_id);

        assert!(matches!(
            gateway.run_once_with_adapter(&mut adapter, None).await,
            Err(GatewayError::KubernetesTargetObservation)
        ));
        assert_eq!(
            gateway.get(&deferred.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.identify_order, ["op-a", "op-b", "op-a"]);
        assert_eq!(adapter.apply_order, ["op-b", "op-a"]);
        assert_eq!(adapter.observe_order, ["op-b", "op-a"]);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn targeted_application_reconciliation_does_not_advance_another_operation() {
        let path = database_path("targeted-application-operation");
        let mut first = request();
        first.operation_id = "op-a".into();
        let mut configured = request();
        configured.operation_id = "op-b".into();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&first, &authorization(&first))
            .unwrap();
        gateway
            .submit_exact_for_test(&configured, &authorization(&configured))
            .unwrap();
        let mut adapter = TargetRoutingAdapter::transient_once("never-transient");

        assert_eq!(
            gateway
                .run_operation_once_with_adapter(&configured.operation_id, &mut adapter)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.identify_order, ["op-b"]);
        assert_eq!(adapter.apply_order, ["op-b"]);
        assert_eq!(adapter.observe_order, ["op-b"]);
        assert_eq!(
            gateway.get(&first.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn targeted_application_finalization_does_not_sign_another_operation() {
        let path = database_path("targeted-application-finalization");
        let output = path.parent().unwrap().join("receipts");
        private_directory(&output);
        let output = fs::canonicalize(output).unwrap();
        let mut first = request();
        first.operation_id = "op-a".into();
        let mut configured = request();
        configured.operation_id = "op-b".into();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&first, &authorization(&first))
            .unwrap();
        gateway
            .submit_exact_for_test(&configured, &authorization(&configured))
            .unwrap();
        gateway
            .run_operation_once_with_adapter(
                &first.operation_id,
                &mut failed_adapter(&path, &first),
            )
            .await
            .unwrap();
        gateway
            .run_operation_once_with_adapter(
                &configured.operation_id,
                &mut failed_adapter(&path, &configured),
            )
            .await
            .unwrap();

        assert_eq!(
            gateway
                .finalize_operation_receipt_once(
                    &configured.operation_id,
                    &ReceiptSettings {
                        signing_seed: &[51_u8; 32],
                        key_id: "targeted-receipt-key",
                        output_directory: &output,
                    },
                )
                .unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(
            gateway.get(&first.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(
            gateway.get(&configured.operation_id).unwrap(),
            Some(OperationState::Finalized)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn target_read_crash_stays_authorized_and_repeats_only_the_safe_get() {
        let path = database_path("target-read-recovery");
        let request = request();
        let mut adapter = failed_adapter(&path, &request);
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            assert!(matches!(
                gateway
                    .run_once_with_adapter(&mut adapter, Some(FaultPoint::TargetObserved))
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::Authorized)
            );
            assert_eq!(adapter.identify_calls, 1);
            assert_eq!(adapter.apply_calls, 0);
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(adapter.identify_calls, 2);
        assert_eq!(adapter.apply_calls, 1);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn process_kill_after_provider_side_effect_recovers_without_second_mutation() {
        let path = database_path("process-kill-mutation");
        let request = request();
        {
            let gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
        }
        let ready = path.parent().unwrap().join("mutation-ready");
        let patch_count = path.parent().unwrap().join("patch-count");
        let mut child = spawn_process_child("mutation", &path, &ready, Some(&patch_count), None);
        wait_for_child_seam(&mut child, &ready);
        assert_eq!(fs::read_to_string(&patch_count).unwrap(), "1");
        kill_child(&mut child);

        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ApplyStarted)
        );
        let mut recovery = failed_adapter(&path, &request);
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut recovery, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(recovery.identify_calls, 0);
        assert_eq!(recovery.apply_calls, 0);
        assert_eq!(recovery.observe_calls, 1);
        assert_eq!(fs::read_to_string(&patch_count).unwrap(), "1");
        assert_eq!(
            gateway.result(&request.operation_id).unwrap(),
            Some(OperationResult::Failed)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn worker_lock_prevents_overlapping_provider_activity() {
        let path = database_path("worker-lock");
        let request = request();
        let first_gateway = Gateway::open_for_test(&path).unwrap();
        first_gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let worker_lock = first_gateway.journal.try_lock_worker().unwrap().unwrap();
        let mut second_gateway = Gateway::open_for_test(&path).unwrap();
        let mut adapter = failed_adapter(&path, &request);

        assert_eq!(
            second_gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            None
        );
        assert_eq!(adapter.identify_calls, 0);
        assert_eq!(adapter.apply_calls, 0);
        assert_eq!(adapter.observe_calls, 0);

        drop(worker_lock);
        assert_eq!(
            second_gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        drop(second_gateway);
        drop(first_gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn restart_after_apply_observes_without_a_blind_second_apply() {
        let path = database_path("apply-recovery");
        let request = request();
        let mut adapter = failed_adapter(&path, &request);
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            assert!(matches!(
                gateway
                    .run_once_with_adapter(&mut adapter, Some(FaultPoint::ApplyReturned))
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ApplyStarted)
            );
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();

        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert!(adapter.apply_started_seen);
        assert_eq!(adapter.identify_calls, 1);
        assert_eq!(adapter.apply_calls, 1);
        assert_eq!(adapter.observe_calls, 1);
        assert_eq!(
            gateway.result(&request.operation_id).unwrap(),
            Some(OperationResult::Failed)
        );
        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.requested_generation(), Some(2));
        assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
        assert_eq!(
            statement.rollout_condition_reason(),
            Some("ProgressDeadlineExceeded")
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn recovery_receipt_does_not_reuse_target_uid_when_receiver_uid_is_missing() {
        let path = database_path("receiver-uid-missing");
        let request = request();
        let mut adapter = failed_adapter(&path, &request);
        adapter.observation = ReceiverObservation::unknown();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            assert!(matches!(
                gateway
                    .run_once_with_adapter(&mut adapter, Some(FaultPoint::ApplyReturned))
                    .await,
                Err(GatewayError::InjectedFault)
            ));
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();
        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.receiver_uid(), None);
        assert_eq!(statement.requested_generation(), None);
        assert_eq!(statement.result(), OperationResult::Unknown);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn every_apply_window_recovers_without_a_second_mutation() {
        let cases = [
            (FaultPoint::TargetObserved, 1, OperationResult::Failed),
            (
                FaultPoint::ApplyStartedCommitted,
                0,
                OperationResult::Failed,
            ),
            (FaultPoint::ApplyReturned, 1, OperationResult::Failed),
            (
                FaultPoint::ApplyOutcomeCommitted,
                1,
                OperationResult::Failed,
            ),
            (FaultPoint::ReceiverRead, 1, OperationResult::Failed),
            (
                FaultPoint::ReceiverObservedCommitted,
                1,
                OperationResult::Failed,
            ),
        ];
        for (index, (fault, expected_apply_calls, expected_result)) in cases.into_iter().enumerate()
        {
            let path = database_path(&format!("fault-window-{index}"));
            let request = request();
            let mut adapter = failed_adapter(&path, &request);
            {
                let mut gateway = Gateway::open_for_test(&path).unwrap();
                gateway
                    .submit_exact_for_test(&request, &authorization(&request))
                    .unwrap();
                assert!(matches!(
                    gateway
                        .run_once_with_adapter(&mut adapter, Some(fault))
                        .await,
                    Err(GatewayError::InjectedFault)
                ));
            }
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            let state = gateway.get(&request.operation_id).unwrap().unwrap();
            if matches!(
                state,
                OperationState::Authorized | OperationState::ApplyStarted
            ) {
                assert_eq!(
                    gateway
                        .run_once_with_adapter(&mut adapter, None)
                        .await
                        .unwrap(),
                    Some(OperationState::ReceiverObserved)
                );
            } else {
                assert_eq!(state, OperationState::ReceiverObserved);
                assert_eq!(
                    gateway
                        .run_once_with_adapter(&mut adapter, None)
                        .await
                        .unwrap(),
                    None
                );
            }
            assert_eq!(adapter.apply_calls, expected_apply_calls);
            assert_eq!(
                gateway.result(&request.operation_id).unwrap(),
                Some(expected_result)
            );
            drop(gateway);
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[tokio::test]
    async fn receipt_statement_retains_exact_available_condition_reason() {
        let path = database_path("receipt-available-reason");
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        adapter.observation.updated_replicas = Some(1);
        adapter.observation.available_replicas = Some(1);
        adapter.observation.unavailable_replicas = Some(0);
        adapter.observation.rollout_condition_type = Some("Available".into());
        adapter.observation.rollout_condition_status = Some("True".into());
        adapter.observation.rollout_condition_reason = Some("DifferentObservedReason".into());
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();

        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.result(), OperationResult::Succeeded);
        assert_eq!(
            statement.rollout_condition_reason(),
            Some("DifferentObservedReason")
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_inspection_reports_frozen_failed_receiver_facts() {
        let path = database_path("receipt-first-tracer");
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );

        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.operation_id, request.operation_id);
        assert_eq!(statement.authorization_id, "auth-001");
        assert_eq!(
            statement.authorization_signer_key_id(),
            "kap0038-authorization-test-key"
        );
        assert_eq!(statement.authorization_grant_digest().len(), 64);
        assert_eq!(statement.write_strategy(), WRITE_STRATEGY);
        assert_eq!(statement.target_uid(), "deployment-uid-1");
        assert_eq!(statement.target_resource_version(), "resource-version-0");
        assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
        assert_eq!(
            statement.observed_image(),
            Some(request.immutable_image_digest.as_str())
        );
        assert_eq!(statement.observed_operation_marker(), Some("op-001"));
        assert_eq!(statement.current_generation(), Some(2));
        assert_eq!(statement.requested_generation(), Some(2));
        assert_eq!(statement.observed_generation(), Some(2));
        assert_eq!(statement.desired_replicas(), Some(1));
        assert_eq!(statement.updated_replicas(), Some(0));
        assert_eq!(statement.available_replicas(), Some(0));
        assert_eq!(statement.unavailable_replicas(), Some(1));
        assert_eq!(statement.result, OperationResult::Failed);
        assert_eq!(
            statement.rollout_condition_reason.as_deref(),
            Some("ProgressDeadlineExceeded")
        );

        let seed = [7_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let trust = ReceiptTrust {
            key_id: "kap0038-test-key".into(),
            public_key: signing_key.verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap();
        let receipt = sign_statement(&statement, &seed, "kap0038-test-key").unwrap();
        let report = inspect_receipt(&receipt, &trust, 150, InspectionLimits::default());

        assert_eq!(report.status(), InspectionStatus::Inspected);
        assert_eq!(report.statement(), Some(&statement));
        assert_eq!(report.non_claims(), Some(statement.non_claims()));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn hostile_receipt_inputs_fail_closed_without_verified_vocabulary() {
        let statement = ReceiptStatement {
            operation_id: "op-001".into(),
            authorization_id: "auth-001".into(),
            authorization_signer_key_id: "kap0038-authorization-test-key".into(),
            authorization_grant_digest: "0".repeat(64),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: request().immutable_image_digest,
            write_strategy: WRITE_STRATEGY.into(),
            target_uid: "deployment-uid-1".into(),
            target_resource_version: "resource-version-0".into(),
            receiver_uid: Some("deployment-uid-1".into()),
            observed_image: Some(request().immutable_image_digest),
            observed_operation_marker: Some("op-001".into()),
            current_generation: Some(2),
            requested_generation: Some(2),
            observed_generation: Some(2),
            observed_resource_version: Some("resource-version-2".into()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
            result: OperationResult::Failed,
        };
        let seed = [8_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let trust = ReceiptTrust {
            key_id: "kap0038-test-key".into(),
            public_key: signing_key.verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap();
        let receipt = sign_statement(&statement, &seed, "kap0038-test-key").unwrap();

        let mut malformed = receipt.clone();
        malformed[0] = b'X';
        assert_eq!(
            inspect_receipt(&malformed, &trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::StructureRejected
        );

        let mut bad_signature = receipt.clone();
        let last = bad_signature.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            inspect_receipt(&bad_signature, &trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::SignatureRejected
        );

        assert_eq!(
            inspect_receipt(&receipt, &trust, 250, InspectionLimits::default()).status(),
            InspectionStatus::UntrustedSigner
        );
        assert!(!format!(
            "{:?}{:?}{:?}{:?}",
            InspectionStatus::StructureRejected,
            InspectionStatus::SignatureRejected,
            InspectionStatus::UntrustedSigner,
            InspectionStatus::Inspected
        )
        .contains("Verified"));
    }

    #[tokio::test]
    async fn receipt_written_reopens_and_finalizes_without_kubernetes() {
        let path = database_path("receipt-finalize-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [11_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            let result = gateway.finalize_receipt_once_with_fault(
                &ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                },
                Some(FaultPoint::ReceiptWrittenCommitted),
            );
            assert!(
                matches!(result, Err(GatewayError::InjectedFault)),
                "{result:?}"
            );
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptWritten)
            );
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert!(reference.path.exists());
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap(),
            None
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_preparation_is_durable_before_external_publication() {
        let path = database_path("receipt-prepared-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_receipt_once_with_fault(
                    &ReceiptSettings {
                        signing_seed: &[13_u8; 32],
                        key_id: "kap0038-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptPreparedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptPrepared)
            );
            assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 0);
        }
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: path.parent().unwrap(),
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path.parent(), Some(output_directory.as_path()));
        assert!(reference.path.exists());
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn process_kill_after_receipt_publication_recovers_frozen_bytes_under_rotation() {
        let path = database_path("process-kill-receipt");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
        }
        let ready = path.parent().unwrap().join("receipt-ready");
        let mut child =
            spawn_process_child("receipt", &path, &ready, None, Some(&output_directory));
        wait_for_child_seam(&mut child, &ready);
        let published_path = fs::read_dir(&output_directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let published_bytes = fs::read(&published_path).unwrap();
        kill_child(&mut child);

        let rotated_directory = path.parent().unwrap().join("rotated-receipts");
        private_directory(&rotated_directory);
        let rotated_directory = fs::canonicalize(rotated_directory).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiptPrepared)
        );
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: &rotated_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path, published_path);
        assert_eq!(fs::read(&reference.path).unwrap(), published_bytes);
        assert_eq!(
            publication::receipt_digest_hex(&published_bytes),
            reference.digest
        );
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&rotated_directory).unwrap().count(), 0);
        let frozen_key_id = gateway
            .journal
            .connection
            .query_row(
                "SELECT receipt_key_id FROM kubernetes_image_operations WHERE operation_id = ?1",
                [&request.operation_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(frozen_key_id, "process-receipt-key");
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_publish_fault_recovers_with_existing_identical_bytes() {
        let path = database_path("receipt-published-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [13_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_receipt_once_with_fault(
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "kap0038-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptPublished)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptPrepared)
            );
        }
        let rotated_directory = path.parent().unwrap().join("rotated-receipts");
        private_directory(&rotated_directory);
        let rotated_directory = fs::canonicalize(rotated_directory).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: &rotated_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path.parent(), Some(output_directory.as_path()));
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&rotated_directory).unwrap().count(), 0);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn finalized_commit_is_terminal_after_reopen() {
        let path = database_path("receipt-finalized-terminal");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [14_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_receipt_once_with_fault(
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "kap0038-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::FinalizedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
        }
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            None
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_publication_collision_does_not_finalize() {
        let path = database_path("receipt-collision");
        let output_directory = path.parent().unwrap().join("receipts");
        let seed = [12_u8; 32];
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();
        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        let receipt = sign_statement(&statement, &seed, "kap0038-test-key").unwrap();
        let digest = publication::receipt_digest_hex(&receipt);
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        fs::write(
            output_directory.join(publication::receipt_filename(
                &request.operation_id,
                &digest,
            )),
            b"different",
        )
        .unwrap();

        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &seed,
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::ReceiptPublication)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiptPrepared)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn finalizer_contender_changes_no_durable_or_public_fact() {
        let path = database_path("receipt-finalizer-lock");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [21_u8; 32];
        let request = request();
        let mut first = Gateway::open_for_test(&path).unwrap();
        first
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        first
            .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
            .await
            .unwrap();
        let worker_lock = first.journal.try_lock_worker().unwrap().unwrap();
        let contender = Gateway::open_for_test(&path).unwrap();

        assert_eq!(
            contender
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            None
        );
        assert_eq!(
            contender.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 0);

        drop(worker_lock);
        assert_eq!(
            contender
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        drop(contender);
        drop(first);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn legacy_self_asserted_authorization_migrates_idempotently_but_fails_closed() {
        let path = database_path("receipt-schema-migration");
        let request = request();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE kubernetes_image_operations (
                    operation_id TEXT PRIMARY KEY NOT NULL,
                    namespace TEXT NOT NULL,
                    deployment TEXT NOT NULL,
                    container TEXT NOT NULL,
                    immutable_image_digest TEXT NOT NULL,
                    authorization_id TEXT,
                    state TEXT NOT NULL,
                    write_strategy TEXT,
                    apply_attempted INTEGER NOT NULL DEFAULT 0,
                    target_uid TEXT,
                    target_resource_version TEXT,
                    apply_accepted INTEGER,
                    requested_generation INTEGER,
                    apply_resource_version TEXT,
                    receiver_uid TEXT,
                    receiver_image TEXT,
                    receiver_operation_marker TEXT,
                    current_generation INTEGER,
                    observed_generation INTEGER,
                    receiver_resource_version TEXT,
                    desired_replicas INTEGER,
                    updated_replicas INTEGER,
                    available_replicas INTEGER,
                    unavailable_replicas INTEGER,
                    available_condition INTEGER,
                    progress_deadline_exceeded INTEGER,
                    result TEXT
                ) STRICT;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container, immutable_image_digest,
                    authorization_id, state, write_strategy, apply_attempted, target_uid,
                    target_resource_version, requested_generation, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, observed_generation,
                    receiver_resource_version, progress_deadline_exceeded, result
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'auth-001', 'receiver_observed', ?6, 1,
                           'deployment-uid-1', 'resource-version-0', NULL, 'deployment-uid-1',
                           ?5, ?1, 2, 2, 'resource-version-2', 1, 'FAILED')",
                params![
                    request.operation_id,
                    request.namespace,
                    request.deployment,
                    request.container,
                    request.immutable_image_digest,
                    WRITE_STRATEGY,
                ],
            )
            .unwrap();
        drop(connection);

        drop(Gateway::open_for_test(&path).unwrap());
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway.journal.receipt_statement(&request.operation_id),
            Err(GatewayError::InvalidPersistedState)
        ));
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[22_u8; 32],
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(fs::read_dir(output_directory).unwrap().count(), 0);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn missing_receipt_written_destination_is_rewritten_with_exact_bytes() {
        let path = database_path("receipt-missing-rewrite");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [23_u8; 32];
        let request = request();
        let reference = {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_receipt_once_with_fault(
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "kap0038-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptWrittenCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            gateway
                .receipt_reference(&request.operation_id)
                .unwrap()
                .unwrap()
        };
        let exact = publication::read_receipt(&reference.path).unwrap();
        fs::remove_file(&reference.path).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(publication::read_receipt(&reference.path).unwrap(), exact);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_utf8_output_path_is_rejected_before_receipt_storage() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = database_path("receipt-non-utf8");
        let output_directory = path
            .parent()
            .unwrap()
            .join(OsString::from_vec(b"receipts-\xff".to_vec()));
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        gateway
            .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
            .await
            .unwrap();

        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[24_u8; 32],
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::ReceiptPublication)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert!(!output_directory.exists());
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn hostile_kubernetes_facts_fail_before_receiver_state_is_frozen() {
        let request = request();
        let mut oversized_uid = unknown_observation(&request);
        oversized_uid.deployment_uid =
            Some("u".repeat(kubernetes_facts::KUBERNETES_FACT_BYTES_MAX + 1));
        assert!(matches!(
            oversized_uid.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut oversized_version = unknown_observation(&request);
        oversized_version.resource_version =
            Some("r".repeat(kubernetes_facts::KUBERNETES_FACT_BYTES_MAX + 1));
        assert!(matches!(
            oversized_version.validate(),
            Err(GatewayError::InvalidKubernetesFact)
        ));

        let mut oversized_marker = unknown_observation(&request);
        oversized_marker.operation_marker =
            Some("m".repeat(kubernetes_facts::KUBERNETES_FACT_BYTES_MAX + 1));
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
    fn receiver_classification_keeps_timeout_and_replica_failure_unknown() {
        let request = request();
        let outcome = ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-1".into()),
        };
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
    fn image_grammar_rejects_every_mutable_or_ambiguous_form() {
        let path = database_path("image-grammar");
        let invalid_images = [
            "registry.example/repo/image:tag",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            concat!(
                "registry.example/repo/image:tag@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "registry.example:5000/repo/image@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "Registry.example/repo/image@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "registry.example/repo/image@sha256:",
                "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        ];
        for image in invalid_images {
            let gateway = Gateway::open_for_test(&path).unwrap();
            let mut request = request();
            request.operation_id = format!("op-{}", image.len());
            request.immutable_image_digest = image.into();
            let authorization = authorization(&request);
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &authorization),
                Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
            ));
            assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
