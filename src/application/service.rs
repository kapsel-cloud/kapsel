//! Bounded service approval selection and externally authorized retained-history access.
//!
//! This is one application over the sole gateway journal, not one application per approval.

mod document;
use std::{error::Error, fmt, path::PathBuf};

pub use document::{parse_service_operator_document, ServiceOperatorDocument};

use super::{AgentRequest, Application, SetDeploymentImageReceipt, SetDeploymentImageStatus};
use crate::{
    gateway::{AuthorizationTrust, Gateway, GatewayError, OperationState},
    OperationTargets,
};

/// One exact approval supplied only by the operator, never by socket input.
///
/// Grant bytes are deliberately excluded from diagnostics.
pub struct ServiceApproval {
    /// Canonical original signed snapshot grant, at most 4 KiB.
    pub signed_grant: Vec<u8>,
    /// Printable ASCII display label, at most 128 bytes, never an identity key.
    pub label: String,
}

/// Operator-owned composition for bounded approvals and retained history.
///
/// Receiver credentials and receipt signing material are not needed to construct stored reads.
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
pub struct ApprovedAction {
    /// Stable operation identity and exact bounded tuple.
    pub request: AgentRequest,
    /// Original operator-acquired target snapshot.
    pub approved_target: crate::ApprovedTarget,
    /// Operator-supplied display label, not matching authority.
    pub label: String,
}

/// One retained identity with authenticated facts or a non-disclosing access failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    /// Retained identity. Its presence is not authentication or action authority.
    pub operation_id: String,
    /// Authenticated stored status and targets, or no action facts when access fails.
    pub status: Result<(SetDeploymentImageStatus, OperationTargets), ServiceError>,
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
            receipt_signing,
        }
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
        let gateway = Gateway::open_with_authorities(
            &configuration.journal_path,
            configuration.authorization_trust,
        )
        .map_err(map_gateway_error)?;
        for approval in &approvals {
            gateway
                .authorized_operation(&approval.handle.request, &approval.signed_grant)
                .map_err(map_gateway_error)?;
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
        Gateway::validate_replacement(
            &configuration.journal_path,
            &configuration.authorization_trust,
            approvals
                .iter()
                .map(|approval| (&approval.handle.request, approval.signed_grant.as_slice())),
        )
        .map_err(map_gateway_error)
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
            let mut verified = None;
            for trust in &configuration.authorization_trust {
                match crate::gateway::verify_authorization_grant(&approval.signed_grant, trust) {
                    Ok(grant) => {
                        verified = Some(grant);
                        break;
                    },
                    Err(GatewayError::UntrustedAuthorizationGrant) => {},
                    Err(_) => return Err(ServiceError::Configuration),
                }
            }
            let grant = verified.ok_or(ServiceError::Configuration)?;
            let facts = grant.authorization;
            let approved_target = facts.approved_target.ok_or(ServiceError::Configuration)?;
            let request = AgentRequest {
                operation_id: facts.operation_id,
                namespace: facts.namespace,
                deployment: facts.deployment,
                container: facts.container,
                immutable_image_digest: facts.immutable_image_digest,
            };
            if approvals
                .iter()
                .any(|other| other.handle.request.operation_id == request.operation_id)
            {
                return Err(ServiceError::Configuration);
            }
            approvals.push(SelectableApproval {
                handle: ApprovedAction {
                    request,
                    approved_target,
                    label: approval.label.clone(),
                },
                signed_grant: approval.signed_grant.clone(),
            });
        }
        super::validate_journal_path(&configuration.journal_path)
            .map_err(|_| ServiceError::Configuration)?;
        Ok(approvals)
    }

    /// Selects original authority, durably admits, and requests one bounded advancement pass.
    ///
    /// The acknowledgement runs only after definite admission or refusal. The journal worker lease
    /// spans the commit, callback and advancement. Terminal reselection only reads.
    /// Missing execution material leaves admitted work unfinished,
    /// with no fabricated receiver result.
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
    ) -> Result<(), ServiceError> {
        let retained = self.retained_for_selection(operation_id)?;
        let (request, signed_grant) = if let Some(retained) = retained {
            (retained.request, retained.signed_grant)
        } else {
            let approval = self
                .approvals
                .iter()
                .find(|entry| entry.handle.request.operation_id == operation_id)
                .ok_or(ServiceError::InvalidRequest)?;
            (
                approval.handle.request.clone(),
                approval.signed_grant.clone(),
            )
        };
        if let Some((_, key_id)) = &execution.receipt_signing {
            crate::gateway::validate_key_id(key_id).map_err(|_| ServiceError::Configuration)?;
        }
        let receipt = execution.receipt_signing.as_ref().map(|(seed, key_id)| {
            crate::gateway::ReceiptSettings {
                signing_seed: seed,
                key_id,
            }
        });
        self.gateway
            .admit_and_reconcile(
                &request,
                &signed_grant,
                execution.kubernetes_client,
                receipt.as_ref(),
                |decision| {
                    acknowledged(match decision {
                        crate::gateway::AdmissionDecision::Admitted(state) => {
                            ServiceAdmission::Admitted(state)
                        },
                        crate::gateway::AdmissionDecision::Busy => ServiceAdmission::Busy,
                        crate::gateway::AdmissionDecision::Full => ServiceAdmission::Full,
                    });
                },
            )
            .await
            .map(|_| ())
            .map_err(|error| match error {
                crate::gateway::ReconciliationError::Submission(error)
                | crate::gateway::ReconciliationError::Advancement(error) => {
                    map_gateway_error(error)
                },
            })
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
            .map(|retained| retained.map(|retained| retained.operation.state()))
    }

    fn retained_for_selection(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::gateway::RetainedOperation>, ServiceError> {
        let retained = self
            .gateway
            .retained_operation(operation_id)
            .map_err(map_gateway_error)?;
        if let Some(retained) = &retained {
            if retained.operation.targets().approved_target.is_none() {
                return Err(ServiceError::InvalidRequest);
            }
        } else if !self
            .approvals
            .iter()
            .any(|entry| entry.handle.request.operation_id == operation_id)
        {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(retained)
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
                .position(|entry| entry.handle.request.operation_id == id)
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

    /// Retrieves the original committed receipt without receiver or signing availability.
    ///
    /// # Errors
    ///
    /// Missing original grant trust or malformed retained evidence fails closed
    /// with a bounded error.
    pub fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ServiceError> {
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
    /// Durable history or its original authority binding is inconsistent or inaccessible.
    OperationFailure,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid_service_configuration",
            Self::InvalidRequest => "invalid_service_request",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::OperationFailure => "service_operation_failure",
        })
    }
}

impl Error for ServiceError {}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err consumes the internal error"
)]
fn map_gateway_error(error: GatewayError) -> ServiceError {
    match error {
        GatewayError::UntrustedAuthorizationGrant => ServiceError::AuthorityUnavailable,
        GatewayError::InvalidInput(_) => ServiceError::InvalidRequest,
        _ => ServiceError::OperationFailure,
    }
}
