//! Bounded service approval selection and externally authorized retained-history access.
//!
//! This is one application over the sole gateway journal, not one application per approval.

mod disposition;
mod document;
use std::{error::Error, fmt, path::PathBuf};

pub use disposition::{
    ExecutionCondition, ExecutionDisposition, ExecutionObservation, ServiceStop,
};
pub use document::{parse_service_operator_document, ServiceOperatorDocument};

use super::{AgentRequest, Application, SetDeploymentImageReceipt, SetDeploymentImageStatus};
use crate::{
    gateway::{AuthorizationTrust, Gateway, GatewayError, OperationState},
    OperationTargets,
};

/// One exact approval supplied only by the operator, never by socket input.
///
/// Grant bytes are deliberately excluded from diagnostics.
#[derive(Clone)]
pub struct ServiceApproval {
    /// Canonical original signed snapshot grant, at most 4 KiB.
    pub signed_grant: Vec<u8>,
    /// Printable ASCII display label, at most 128 bytes, never an identity key.
    pub label: String,
}

/// Operator-owned composition for bounded approvals and retained history.
///
/// Receiver credentials and receipt signing material are not needed to construct stored reads.
#[derive(Clone)]
pub struct ServiceConfiguration {
    /// Existing private journal location or a new journal within its private parent.
    pub journal_path: PathBuf,
    /// At most 128 separately appointed historical grant keys, with unique identities.
    pub authorization_trust: Vec<AuthorizationTrust>,
    /// At most 32 independently assessed selectable approvals.
    pub approvals: Vec<ServiceApproval>,
}

/// Public handle for a selectable exact approval. Listing does not admit or observe it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovedAction {
    /// One exact Kubernetes image transition at an approved object snapshot.
    Kubernetes {
        /// Stable identity and exact bounded tuple.
        request: AgentRequest,
        /// Original operator-acquired target snapshot.
        approved_target: crate::ApprovedTarget,
        /// Display label, not matching authority.
        label: String,
    },
    /// One exact Git branch transition in an operator-owned repository.
    Git {
        /// Original authenticated repository, ref and commit binding.
        authorization: kapsel_authority::GitRefAuthorization,
        /// Display label, not matching authority.
        label: String,
    },
}

impl ApprovedAction {
    /// Stable caller-selected identity, independent of effect type.
    pub fn operation_id(&self) -> &str {
        match self {
            Self::Kubernetes { request, .. } => &request.operation_id,
            Self::Git { authorization, .. } => &authorization.operation_id,
        }
    }
}

/// Resolved original authority, with a read-only admission snapshot separate from advancement.
enum Selection {
    Kubernetes(AgentRequest, Vec<u8>, Option<OperationState>),
    Git(Vec<u8>, Option<OperationState>),
}

/// One retained identity with authenticated facts or a non-disclosing access failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    /// Retained identity. Its presence is not authentication or action authority.
    pub operation_id: String,
    /// Authenticated stored status and targets, or no action facts when access fails.
    pub status: Result<(SetDeploymentImageStatus, OperationTargets), ServiceError>,
}

impl HistoryEntry {
    /// Adds process-local guidance to this already authenticated history snapshot.
    ///
    /// # Errors
    ///
    /// Preserves the original entry's access failure without disclosing action facts.
    pub fn execution_status(
        self,
        observation: ExecutionObservation,
    ) -> Result<
        (
            SetDeploymentImageStatus,
            OperationTargets,
            ExecutionDisposition,
        ),
        ServiceError,
    > {
        self.status.map(|(status, targets)| {
            (
                status,
                targets,
                ExecutionDisposition::project(status, observation),
            )
        })
    }
}

/// A bounded history page. Concurrent admissions can require restarting pagination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPage {
    /// At most eight retained identities in bytewise ascending order.
    pub entries: Vec<HistoryEntry>,
    /// Last returned identity when another retained identity exists, otherwise absent.
    pub next_cursor: Option<String>,
}

struct SelectableApproval {
    handle: ApprovedAction,
    signed_grant: Vec<u8>,
}

/// Result of bounded admission, separate from receiver result and worker liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAdmission {
    /// This identity has confirmed durable responsibility, including identical resubmission.
    Admitted(crate::OperationState),
    /// New work was not admitted because the journal worker is occupied.
    Busy,
    /// New work was not admitted because retained or unfinished capacity is full.
    Full,
}

/// Operator-owned optional execution materials. Missing materials do not prevent stored reads.
///
/// Signing material is deliberately excluded from diagnostics.
pub struct ServiceExecution {
    /// Explicit receiver client with mutation retries disabled.
    pub kubernetes_client: Option<kube::Client>,
    /// Optional operator-owned fixed local Git receiver material, never socket input.
    pub git_receiver: Option<crate::GitReceiverConfiguration>,
    /// Optional original-completion signing seed and public key identity.
    pub receipt_signing: Option<([u8; 32], String)>,
}

impl ServiceExecution {
    /// Builds optional execution material from bounded operator-owned snapshots,
    /// never ambient input.
    ///
    /// Missing or invalid material stays unavailable independently. No receiver request is made.
    pub async fn from_operator_snapshots(
        kubeconfig: Option<&[u8]>,
        receipt_seed: Option<&[u8]>,
        receipt_signing_key_id: &str,
    ) -> Self {
        let kubernetes_client = match kubeconfig {
            Some(bytes) if bytes.len() <= 16 * 1024 => {
                super::load_operator_kubernetes_client(bytes).await.ok()
            },
            _ => None,
        };
        let receipt_signing = receipt_seed
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .filter(|_| crate::gateway::validate_key_id(receipt_signing_key_id).is_ok())
            .map(|seed| (seed, receipt_signing_key_id.to_owned()));
        Self {
            kubernetes_client,
            git_receiver: None,
            receipt_signing,
        }
    }

    /// Attaches bounded operator-owned Git material without filesystem or receiver I/O.
    ///
    /// Invalid or absent bytes leave Git unavailable without hiding authenticated history.
    #[must_use]
    pub fn with_git_receiver_snapshot(mut self, bytes: Option<&[u8]>) -> Self {
        self.git_receiver = bytes.and_then(crate::GitReceiverConfiguration::from_document);
        self
    }
}

/// One bounded service application, with catalog selection separate from retained history.
pub struct ServiceApplication {
    gateway: Gateway,
    approvals: Vec<SelectableApproval>,
}

impl ServiceApplication {
    /// Validates operator approval and external trust before opening the journal.
    ///
    /// Reads need no Kubernetes client, receipt seed, export directory or current catalog entry.
    /// This method performs no receiver work or automatic recovery.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for invalid configuration, changed configured identities or unsafe
    /// storage. Missing trust for an unselected historical identity does not prevent construction.
    pub fn open(configuration: ServiceConfiguration) -> Result<Self, ServiceError> {
        let approvals = Self::validate_configuration(&configuration)?;
        super::validate_journal_path(&configuration.journal_path)
            .map_err(|_| ServiceError::Configuration)?;
        let gateway = Gateway::open_with_authorities(
            &configuration.journal_path,
            configuration.authorization_trust,
        )
        .map_err(map_gateway_error)?;
        for approval in &approvals {
            match &approval.handle {
                ApprovedAction::Kubernetes { request, .. } => {
                    gateway
                        .authorized_operation(request, &approval.signed_grant)
                        .map_err(map_gateway_error)?;
                },
                ApprovedAction::Git { .. } => {
                    gateway
                        .authorized_git(&approval.signed_grant)
                        .map_err(map_gateway_error)?;
                },
            }
        }
        Ok(Self { gateway, approvals })
    }

    /// Validates a complete cold replacement without creating or modifying journal artifacts.
    ///
    /// The caller must exclude service lifetimes and retain the private storage root. No receiver,
    /// admission, signing or recovery work occurs; validation handles close before this returns.
    ///
    /// # Errors
    ///
    /// Rejects invalid configuration, conflicting retained identities, unsafe storage and journals
    /// requiring recovery. Missing trust for an unselected historical identity remains allowed.
    pub fn validate_replacement(configuration: &ServiceConfiguration) -> Result<(), ServiceError> {
        let approvals = Self::validate_configuration(configuration)?;
        super::validate_journal_path(&configuration.journal_path)
            .map_err(|_| ServiceError::Configuration)?;
        Gateway::validate_replacement_with_git(
            &configuration.journal_path,
            &configuration.authorization_trust,
            approvals
                .iter()
                .filter_map(|approval| match &approval.handle {
                    ApprovedAction::Kubernetes { request, .. } => {
                        Some((request, approval.signed_grant.as_slice()))
                    },
                    ApprovedAction::Git { .. } => None,
                }),
            approvals
                .iter()
                .filter_map(|approval| match &approval.handle {
                    ApprovedAction::Git { .. } => Some(approval.signed_grant.as_slice()),
                    ApprovedAction::Kubernetes { .. } => None,
                }),
        )
        .map_err(map_gateway_error)
    }

    /// Authenticates bounded approvals and independent trust without filesystem or receiver I/O.
    ///
    /// This does not validate journal custody, retained identities or execution readiness.
    /// Publication and opening must still perform their full environment checks.
    ///
    /// # Errors
    ///
    /// Rejects malformed appointments, invalid snapshot grants and duplicate selectable identities.
    pub fn validate_static_configuration(
        configuration: &ServiceConfiguration,
    ) -> Result<(), ServiceError> {
        Self::validate_configuration(configuration).map(|_| ())
    }

    fn validate_configuration(
        configuration: &ServiceConfiguration,
    ) -> Result<Vec<SelectableApproval>, ServiceError> {
        if configuration.approvals.len() > 32 || configuration.authorization_trust.len() > 128 {
            return Err(ServiceError::Configuration);
        }
        let mut bytes = 0_usize;
        for approval in &configuration.approvals {
            if approval.signed_grant.len() > 4096
                || approval.label.len() > 128
                || !approval
                    .label
                    .bytes()
                    .all(|byte| (32..=126).contains(&byte))
            {
                return Err(ServiceError::Configuration);
            }
            bytes = bytes
                .checked_add(approval.signed_grant.len() + approval.label.len())
                .ok_or(ServiceError::Configuration)?;
        }
        if bytes > 160 * 1024 {
            return Err(ServiceError::Configuration);
        }
        // Validate every external appointment and catalog entry before journal creation.
        for (index, trust) in configuration.authorization_trust.iter().enumerate() {
            crate::gateway::validate_authorization_trust(trust)
                .map_err(|_| ServiceError::Configuration)?;
            if configuration.authorization_trust[..index]
                .iter()
                .any(|key| key.key_id == trust.key_id)
            {
                return Err(ServiceError::Configuration);
            }
        }
        let mut approvals: Vec<SelectableApproval> =
            Vec::with_capacity(configuration.approvals.len());
        for approval in &configuration.approvals {
            let handle = approved_handle(approval, &configuration.authorization_trust)?;
            if approvals
                .iter()
                .any(|other| other.handle.operation_id() == handle.operation_id())
            {
                return Err(ServiceError::Configuration);
            }
            approvals.push(SelectableApproval {
                handle,
                signed_grant: approval.signed_grant.clone(),
            });
        }
        Ok(approvals)
    }

    /// Selects original authority, durably admits, and requests one bounded advancement pass.
    ///
    /// The acknowledgement runs only after definite admission or refusal. The journal worker lease
    /// spans the commit, callback and advancement. Terminal reselection only reads.
    /// Known execution blockages return [`ServiceStop::Blocked`], not a receiver result.
    /// Missing execution material leaves admitted work unfinished. A successful return is not
    /// proof of completion; read authenticated status for durable evidence.
    ///
    /// # Errors
    ///
    /// Returns a bounded authority, request or operation failure. An error before acknowledgement
    /// does not prove non-admission when storage commitment is indeterminate.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation does not erase admitted work or authorize replay. The runtime must retain task
    /// ownership while any blocking storage operation can still complete.
    pub async fn select(
        &mut self,
        operation_id: &str,
        execution: ServiceExecution,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<ServiceStop, ServiceError> {
        let selected = self.retained_for_selection(operation_id)?;
        if let Some((_, key_id)) = &execution.receipt_signing {
            crate::gateway::validate_key_id(key_id).map_err(|_| ServiceError::Configuration)?;
        }
        let receipt = execution.receipt_signing.as_ref().map(|(seed, key_id)| {
            crate::gateway::ReceiptSettings {
                signing_seed: seed,
                key_id,
            }
        });
        let callback = |decision| {
            acknowledged(match decision {
                crate::gateway::AdmissionDecision::Admitted(state) => {
                    ServiceAdmission::Admitted(state)
                },
                crate::gateway::AdmissionDecision::Busy => ServiceAdmission::Busy,
                crate::gateway::AdmissionDecision::Full => ServiceAdmission::Full,
            });
        };
        let result = match selected {
            Selection::Kubernetes(request, signed_grant, _) => {
                self.gateway
                    .admit_and_reconcile(
                        &request,
                        &signed_grant,
                        execution.kubernetes_client,
                        receipt.as_ref(),
                        callback,
                    )
                    .await
            },
            Selection::Git(signed_grant, _) => {
                self.gateway
                    .admit_and_reconcile_git(
                        operation_id,
                        &signed_grant,
                        execution.git_receiver.as_ref(),
                        receipt.as_ref(),
                        callback,
                    )
                    .await
            },
        };
        result
            .map(|()| ServiceStop::Finished)
            .or_else(classify_stop)
    }

    /// Reads confirmed admission for a selectable or retained snapshot identity
    /// without advancing it.
    ///
    /// A missing row is only this read snapshot. It cannot prove non-admission while another task's
    /// commit is unsettled. The runtime must separately retain that task's identity and exclusion.
    ///
    /// # Errors
    ///
    /// Rejects unknown or legacy-v1 selections and unavailable original authority. This method does
    /// not acquire a worker, acknowledge new work, or perform receiver I/O.
    pub fn admitted_state(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationState>, ServiceError> {
        self.retained_for_selection(operation_id)
            .map(|selected| match selected {
                Selection::Kubernetes(_, _, state) | Selection::Git(_, state) => state,
            })
    }

    fn retained_for_selection(&self, operation_id: &str) -> Result<Selection, ServiceError> {
        if let Some(retained) = self
            .gateway
            .retained_git(operation_id)
            .map_err(map_gateway_error)?
        {
            return Ok(Selection::Git(retained.signed_grant, Some(retained.state)));
        }
        if let Some(retained) = self
            .gateway
            .retained_operation(operation_id)
            .map_err(map_gateway_error)?
        {
            if retained.operation.targets().approved_target.is_none() {
                return Err(ServiceError::InvalidRequest);
            }
            return Ok(Selection::Kubernetes(
                retained.request,
                retained.signed_grant,
                Some(retained.operation.state()),
            ));
        }
        let approval = self
            .approvals
            .iter()
            .find(|entry| entry.handle.operation_id() == operation_id)
            .ok_or(ServiceError::InvalidRequest)?;
        Ok(match &approval.handle {
            ApprovedAction::Kubernetes { request, .. } => {
                Selection::Kubernetes(request.clone(), approval.signed_grant.clone(), None)
            },
            ApprovedAction::Git { .. } => Selection::Git(approval.signed_grant.clone(), None),
        })
    }

    /// Returns at most eight selectable handles after an optional exact identity cursor.
    ///
    /// Listing is offline and creates no admission responsibility. Order is operator catalog order.
    ///
    /// # Errors
    ///
    /// Returns an input error if the cursor is not a current selectable identity.
    pub fn approved_actions(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<ApprovedAction>, ServiceError> {
        let start = match after {
            None => 0,
            Some(id) => self
                .approvals
                .iter()
                .position(|entry| entry.handle.operation_id() == id)
                .map(|index| index + 1)
                .ok_or(ServiceError::InvalidRequest)?,
        };
        Ok(self
            .approvals
            .iter()
            .skip(start)
            .take(8)
            .map(|entry| entry.handle.clone())
            .collect())
    }

    /// Lists bounded retained history without requiring every historical key to remain available.
    ///
    /// Each entry authenticates independently. Pages and entry projections are separate snapshots.
    /// An inaccessible identity is returned without tuple, target or receipt details.
    ///
    /// # Errors
    ///
    /// Invalid cursor grammar or unreadable identity storage returns a bounded error.
    pub fn history(&self, after: Option<&str>) -> Result<HistoryPage, ServiceError> {
        let mut ids = self.gateway.history_ids(after).map_err(map_gateway_error)?;
        let more = ids.len() > 8;
        ids.truncate(8);
        let next_cursor = if more { ids.last().cloned() } else { None };
        let entries = ids
            .into_iter()
            .map(|operation_id| {
                let status = self.status(&operation_id);
                HistoryEntry {
                    operation_id,
                    status,
                }
            })
            .collect();
        Ok(HistoryPage {
            entries,
            next_cursor,
        })
    }

    /// Reads an admitted action under original retained authority,
    /// independent of catalog membership.
    ///
    /// # Errors
    ///
    /// Missing original trust returns authority-unavailable, not absence. Malformed history returns
    /// a bounded operation error. No receiver call, signing or lifecycle transition occurs.
    pub fn status(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, OperationTargets), ServiceError> {
        if let Some(retained) = self
            .gateway
            .retained_git(operation_id)
            .map_err(map_gateway_error)?
        {
            let status =
                Application::status_of(retained.state, retained.rejection, retained.result)
                    .map_err(|_| ServiceError::OperationFailure)?;
            return Ok((
                status,
                OperationTargets {
                    git: Some(retained.targets),
                    ..OperationTargets::default()
                },
            ));
        }
        let Some(retained) = self
            .gateway
            .retained_operation(operation_id)
            .map_err(map_gateway_error)?
        else {
            return Ok((
                SetDeploymentImageStatus::NotFound,
                OperationTargets::default(),
            ));
        };
        let status = Application::status_of(
            retained.operation.state(),
            retained.operation.target_rejection(),
            retained.operation.result(),
        )
        .map_err(|_| ServiceError::OperationFailure)?;
        Ok((status, retained.operation.targets()))
    }

    /// Projects execution guidance only after authenticating stored history.
    ///
    /// Process ownership is supplied by the runtime and is not a durable liveness claim.
    /// Terminal history always supersedes stale process diagnostics. Reads perform no receiver I/O.
    ///
    /// # Errors
    ///
    /// Returns the same bounded history access failures as [`Self::status`].
    pub fn execution_status(
        &self,
        operation_id: &str,
        observation: ExecutionObservation,
    ) -> Result<
        (
            SetDeploymentImageStatus,
            OperationTargets,
            ExecutionDisposition,
        ),
        ServiceError,
    > {
        let (status, targets) = self.status(operation_id)?;
        Ok((
            status,
            targets,
            ExecutionDisposition::project(status, observation),
        ))
    }

    /// Retrieves the original committed receipt without receiver or signing availability.
    ///
    /// # Errors
    ///
    /// Missing original grant trust or malformed retained evidence fails closed
    /// with a bounded error.
    pub fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ServiceError> {
        if let Some(retained) = self
            .gateway
            .retained_git(operation_id)
            .map_err(map_gateway_error)?
        {
            return Ok(retained
                .receipt
                .map_or(SetDeploymentImageReceipt::NotReady, |(bytes, sha256)| {
                    SetDeploymentImageReceipt::Ready { bytes, sha256 }
                }));
        }
        let Some(retained) = self
            .gateway
            .retained_operation(operation_id)
            .map_err(map_gateway_error)?
        else {
            return Ok(SetDeploymentImageReceipt::NotFound);
        };
        if retained.operation.state() != OperationState::Finalized {
            return Ok(SetDeploymentImageReceipt::NotReady);
        }
        let (bytes, sha256) =
            Gateway::read_loaded_receipt(retained.operation).map_err(map_gateway_error)?;
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 })
    }
}

/// Caller-safe failure classes for the service application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// Operator configuration is invalid or ambiguous.
    Configuration,
    /// Request identity or cursor is invalid.
    InvalidRequest,
    /// Required original grant trust is unavailable or does not authenticate the grant.
    AuthorityUnavailable,
    /// Prior storage artifacts survive without the database needed for continuity.
    StorageMissing,
    /// Retained storage is malformed, corrupt or unsupported by this binary.
    StorageInvalid,
    /// Storage access or a required write failed; commitment may be indeterminate.
    StorageUnavailable,
    /// Durable history or its original authority binding is inconsistent or inaccessible.
    OperationFailure,
}

impl ServiceError {
    /// Fixed operator diagnostic code. Details remain in operator guidance, never raw errors.
    pub const fn operator_diagnostic(self) -> &'static str {
        match self {
            Self::Configuration => "configuration_invalid",
            Self::InvalidRequest => "request_invalid",
            Self::AuthorityUnavailable => "original_authority_unavailable",
            Self::StorageMissing => "storage_history_missing",
            Self::StorageInvalid => "storage_history_invalid",
            Self::StorageUnavailable => "storage_unavailable",
            Self::OperationFailure => "storage_or_operation_blocked",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid_service_configuration",
            Self::InvalidRequest => "invalid_service_request",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::StorageMissing => "storage_history_missing",
            Self::StorageInvalid => "storage_history_invalid",
            Self::StorageUnavailable => "storage_unavailable",
            Self::OperationFailure => "service_operation_failure",
        })
    }
}

impl Error for ServiceError {}

fn approved_handle(
    approval: &ServiceApproval,
    trust: &[AuthorizationTrust],
) -> Result<ApprovedAction, ServiceError> {
    for appointment in trust {
        if let Ok(grant) =
            crate::gateway::verify_authorization_grant(&approval.signed_grant, appointment)
        {
            let facts = grant.authorization;
            let approved_target = facts.approved_target.ok_or(ServiceError::Configuration)?;
            return Ok(ApprovedAction::Kubernetes {
                request: AgentRequest {
                    operation_id: facts.operation_id,
                    namespace: facts.namespace,
                    deployment: facts.deployment,
                    container: facts.container,
                    immutable_image_digest: facts.immutable_image_digest,
                },
                approved_target,
                label: approval.label.clone(),
            });
        }
        if let Ok(grant) =
            kapsel_authority::verify_git_ref_grant(&approval.signed_grant, appointment)
        {
            return Ok(ApprovedAction::Git {
                authorization: grant.into_parts().0,
                label: approval.label.clone(),
            });
        }
    }
    Err(ServiceError::Configuration)
}

fn classify_stop(error: crate::gateway::ReconciliationError) -> Result<ServiceStop, ServiceError> {
    use crate::gateway::{ReconciliationBlockage as Blockage, ReconciliationError as Error};
    let condition = match error {
        Error::Blocked(Blockage::SigningUnavailable) => ExecutionCondition::SigningUnavailable,
        Error::Blocked(Blockage::WorkerContention) => ExecutionCondition::WorkerContention,
        Error::Completion => ExecutionCondition::CompletionBlocked,
        Error::Advancement(GatewayError::KubernetesTargetObservation) => {
            ExecutionCondition::PreflightUnavailable
        },
        Error::Blocked(Blockage::ReceiverUnavailable)
        | Error::Advancement(
            GatewayError::KubernetesApply
            | GatewayError::KubernetesReceiverObservation
            | GatewayError::GitReceiverUnavailable,
        ) => ExecutionCondition::ReceiverUnavailable,
        Error::Submission(error) | Error::Advancement(error) => {
            return Err(map_gateway_error(error));
        },
    };
    Ok(ServiceStop::Blocked(condition))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err consumes the internal error"
)]
fn map_gateway_error(error: GatewayError) -> ServiceError {
    match error {
        GatewayError::UntrustedAuthorizationGrant => ServiceError::AuthorityUnavailable,
        GatewayError::InvalidInput(_) => ServiceError::InvalidRequest,
        GatewayError::MissingJournalHistory => ServiceError::StorageMissing,
        GatewayError::InvalidPersistedState
        | GatewayError::UnsupportedJournalVersion
        | GatewayError::JournalBackupMismatch => ServiceError::StorageInvalid,
        GatewayError::Database(rusqlite::Error::SqliteFailure(error, _))
            if matches!(
                error.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            ServiceError::StorageInvalid
        },
        GatewayError::Database(_)
        | GatewayError::JournalFile(_)
        | GatewayError::JournalBackup(_)
        | GatewayError::WorkerLock(_) => ServiceError::StorageUnavailable,
        _ => ServiceError::OperationFailure,
    }
}
