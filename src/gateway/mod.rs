//! Deep implementation of the one authorized Kubernetes Deployment image operation.
//!
//! This module owns orchestration and its private test seams. The crate root remains a compact map
//! of the caller-visible interface and concrete internal owners.

mod authorization;
#[cfg(feature = "demo-harness")]
mod demo_control;
mod journal;
mod kubernetes;
mod receipt;

use std::{
    error::Error,
    fmt,
    future::Future,
    path::{Path, PathBuf},
};

pub use authorization::AuthorizationTrust;
pub(crate) use authorization::{sign_authorization_grant, verify_authorization_grant};
use journal::Journal;
use kubernetes::{
    ApplyOutcome, KubernetesDeploymentImageAdapter, ReceiverObservation, TargetIdentity,
};
#[cfg(test)]
pub(crate) use kubernetes::{
    ApplyOutcome as TestApplyOutcome,
    KubernetesDeploymentImageAdapter as TestKubernetesDeploymentImageAdapter,
    ReceiverObservation as TestReceiverObservation, TargetIdentity as TestTargetIdentity,
};
pub(crate) use receipt::publication::validate_private_directory;
pub(crate) use receipt::validate_key_id;
pub use receipt::{
    inspect_receipt, InspectionLimits, InspectionReport, InspectionStatus, ReceiptError,
    ReceiptStatement, ReceiptTrust,
};
use receipt::{publication, sign_statement};

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
    ) -> Result<Option<journal::OperationSnapshot>, GatewayError> {
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
            #[cfg(feature = "demo-harness")]
            demo_control::checkpoint_after_receipt_publish()
                .map_err(|()| GatewayError::ReceiptPublication)?;
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
    pub(crate) fn finalize_receipt_once_with_fault(
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
            #[cfg(feature = "demo-harness")]
            demo_control::checkpoint_after_apply().map_err(|()| GatewayError::KubernetesApply)?;
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
mod tests;
