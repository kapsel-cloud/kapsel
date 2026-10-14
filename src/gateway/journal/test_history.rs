//! Concrete SQLite histories for decoder and physical-storage fixtures, not lifecycle policy.

use std::{collections::BTreeMap, fmt::Write as _};

use ed25519_dalek::SigningKey;
use rusqlite::{params, types::Value, Connection, OptionalExtension};
use sha2::{Digest as _, Sha256};

use super::{
    git::{GitBinding, GitPhase, GitRejection},
    Journal,
};
use crate::gateway::{
    git::{Acknowledgement, ObservedRef},
    receipt::{git as evidence, sign_statement, ReceiptStatement},
    sign_authorization_grant, verify_authorization_grant, ApprovedTarget, AuthorizationTrust,
    AuthorizedRequest, ExactAuthorization, FrozenReceipt, OperationResult,
    SetDeploymentImageRequest, ValidatedRequest,
};
pub(in crate::gateway) use crate::test_scratch::Scratch;

pub(in crate::gateway) struct History {
    pub request: SetDeploymentImageRequest,
    pub authorized: AuthorizedRequest,
    pub statement: ReceiptStatement,
}

impl History {
    pub(in crate::gateway) fn kube(id: &str) -> Self {
        Self::new(
            SetDeploymentImageRequest {
                operation_id: id.into(),
                namespace: "demo".into(),
                deployment: "agent-api".into(),
                container: "api".into(),
                immutable_image_digest: format!(
                    "registry.example/agent-api@sha256:{}",
                    "0".repeat(64)
                ),
            },
            None,
        )
    }

    pub(in crate::gateway) fn new(
        request: SetDeploymentImageRequest,
        approved_target: Option<ApprovedTarget>,
    ) -> Self {
        Self::with_authority(request, approved_target, "snapshot-auth", "snapshot-signer")
    }

    pub(in crate::gateway) fn with_authority(
        request: SetDeploymentImageRequest,
        approved_target: Option<ApprovedTarget>,
        authorization_id: &str,
        key_id: &str,
    ) -> Self {
        let approval = ExactAuthorization {
            approved_target: approved_target.clone(),
            authorization_id: authorization_id.into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        };
        let signed = sign_authorization_grant(&approval, &[7; 32], key_id).unwrap();
        let mut appointment = trust();
        appointment.key_id = key_id.into();
        let verified = verify_authorization_grant(&signed, &appointment).unwrap();
        let statement = ReceiptStatement {
            approved_target,
            operation_id: request.operation_id.clone(),
            authorization_id: authorization_id.into(),
            authorization_signer_key_id: key_id.into(),
            authorization_grant_digest: digest(&signed),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
            write_strategy: "conditional-strategic-merge-patch".into(),
            target_uid: "target-uid".into(),
            target_resource_version: "target-rv".into(),
            receiver_uid: Some("receiver-uid".into()),
            observed_image: Some(format!(
                "registry.example/receiver@sha256:{}",
                "1".repeat(64)
            )),
            observed_operation_marker: Some("receiver-marker".into()),
            current_generation: Some(7),
            requested_generation: Some(6),
            observed_generation: Some(5),
            observed_resource_version: Some("receiver-rv".into()),
            desired_replicas: Some(5),
            updated_replicas: Some(3),
            available_replicas: Some(2),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
            result: OperationResult::Unknown,
        };
        let authorized =
            AuthorizedRequest::bind(ValidatedRequest::try_from(&request).unwrap(), verified)
                .unwrap();
        Self {
            request,
            authorized,
            statement,
        }
    }

    pub(in crate::gateway) fn authorize(
        &self,
        bytes: &[u8],
    ) -> Result<AuthorizedRequest, super::GatewayError> {
        let verified = verify_authorization_grant(bytes, &trust())
            .map_err(|_| super::GatewayError::InvalidAuthorizationGrant)?;
        AuthorizedRequest::bind(ValidatedRequest::try_from(&self.request).unwrap(), verified)
    }

    pub(in crate::gateway) fn receipt(&self) -> FrozenReceipt {
        let bytes = sign_statement(&self.statement, &[9; 32], "snapshot-receipt-key").unwrap();
        FrozenReceipt {
            operation_id: self.request.operation_id.clone(),
            digest: digest(&bytes),
            bytes,
            key_id: "snapshot-receipt-key".into(),
        }
    }

    // Authored columns bypass both production record mapping and durable-transition writers.
    // Unequal generations/replica counts make field swaps observable in decoded statements.
    pub(in crate::gateway) fn insert(&self, connection: &Connection, phase: &str) {
        let s = &self.statement;
        connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                operation_id, namespace, deployment, container, immutable_image_digest, state,
                authorization_id, authorization_signer_key_id, authorization_grant_digest,
                signed_authorization_grant, approved_uid, approved_resource_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    s.operation_id,
                    s.namespace,
                    s.deployment,
                    s.container,
                    s.immutable_image_digest,
                    phase,
                    s.authorization_id,
                    s.authorization_signer_key_id,
                    s.authorization_grant_digest,
                    self.authorized.authorization().signed_grant,
                    s.approved_target.as_ref().map(|t| &t.uid),
                    s.approved_target.as_ref().map(|t| &t.resource_version)
                ],
            )
            .unwrap();
        if phase == "not_attempted" {
            connection.execute(
                "UPDATE kubernetes_image_operations SET target_rejection = 'deployment_not_found'
                 WHERE operation_id = ?1", [&s.operation_id],
            ).unwrap();
        }
        if matches!(phase, "apply_started" | "receiver_observed" | "finalized") {
            connection.execute(
                "UPDATE kubernetes_image_operations SET write_strategy = ?2, apply_attempted = 1,
                 target_uid = ?3, target_resource_version = ?4, preflight_uid = ?3,
                 preflight_resource_version = ?4 WHERE operation_id = ?1",
                params![s.operation_id, s.write_strategy, s.target_uid, s.target_resource_version],
            ).unwrap();
        }
        if matches!(phase, "receiver_observed" | "finalized") {
            connection
                .execute(
                    "UPDATE kubernetes_image_operations SET result = ?16, receiver_uid = ?2,
                 receiver_image = ?3, receiver_operation_marker = ?4, current_generation = ?5,
                 requested_generation = ?6, observed_generation = ?7,
                 receiver_resource_version = ?8,
                 desired_replicas = ?9, updated_replicas = ?10, available_replicas = ?11,
                 unavailable_replicas = ?12, rollout_condition_type = ?13,
                 rollout_condition_status = ?14, rollout_condition_reason = ?15
                 WHERE operation_id = ?1",
                    params![
                        s.operation_id,
                        s.receiver_uid,
                        s.observed_image,
                        s.observed_operation_marker,
                        s.current_generation,
                        s.requested_generation,
                        s.observed_generation,
                        s.observed_resource_version,
                        s.desired_replicas,
                        s.updated_replicas,
                        s.available_replicas,
                        s.unavailable_replicas,
                        s.rollout_condition_type,
                        s.rollout_condition_status,
                        s.rollout_condition_reason,
                        match s.result {
                            OperationResult::Succeeded => "SUCCEEDED",
                            OperationResult::Failed => "FAILED",
                            OperationResult::Unknown => "UNKNOWN",
                        }
                    ],
                )
                .unwrap();
        }
        if phase == "finalized" {
            let receipt = self.receipt();
            connection.execute(
                "UPDATE kubernetes_image_operations SET receipt_bytes = ?2, receipt_digest = ?3,
                 receipt_key_id = ?4 WHERE operation_id = ?1",
                params![s.operation_id, receipt.bytes, receipt.digest, receipt.key_id],
            ).unwrap();
        }
    }
}

pub(in crate::gateway) fn digest(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

pub(in crate::gateway) fn trust() -> AuthorizationTrust {
    AuthorizationTrust {
        key_id: "snapshot-signer".into(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    }
}

pub(in crate::gateway) fn git_binding(id: &str) -> GitBinding {
    git_binding_with_authority(&kapsel_authority::GitRefAuthorization {
        authorization_id: "approval".into(),
        operation_id: id.into(),
        repository_id: "repository".into(),
        reference: kapsel_authority::APPROVED_GIT_REF.into(),
        old_commit: "a".repeat(40),
        new_commit: "b".repeat(40),
    })
}

pub(in crate::gateway) fn git_binding_with_authority(
    approval: &kapsel_authority::GitRefAuthorization,
) -> GitBinding {
    let bytes =
        kapsel_authority::sign_git_ref_grant(approval, &[7; 32], "snapshot-signer").unwrap();
    GitBinding::verify(&bytes, &[trust()]).unwrap()
}

// Literal SQL supplies valid phases without using a production row writer or decoder.
pub(in crate::gateway) fn insert_git_phase(
    connection: &Connection,
    binding: &GitBinding,
    phase: &str,
) -> GitPhase {
    let a = binding.authorization();
    let statement = evidence::GitStatement {
        authorization: a.clone(),
        authorization_signer: "snapshot-signer".into(),
        authorization_digest: digest(binding.signed_grant()),
        acknowledgement: Acknowledgement::Unknown,
        observed: ObservedRef::Commit(a.new_commit.clone()),
    };
    connection
        .execute(
            "INSERT INTO git_ref_operations (operation_id, repository_id, ref_name, old_commit,
         new_commit, authorization_id, authorization_signer_key_id, authorization_grant_digest,
         signed_authorization_grant, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'snapshot-signer', ?7, ?8, ?9)",
            params![
                a.operation_id,
                a.repository_id,
                a.reference,
                a.old_commit,
                a.new_commit,
                a.authorization_id,
                digest(binding.signed_grant()),
                binding.signed_grant(),
                phase
            ],
        )
        .unwrap();
    match phase {
        "authorized" => GitPhase::Authorized,
        "not_attempted" => {
            connection
                .execute(
                    "UPDATE git_ref_operations SET target_rejection = 'stale_ref'
                 WHERE operation_id = ?1",
                    [&a.operation_id],
                )
                .unwrap();
            GitPhase::NotAttempted(GitRejection::StaleRef)
        },
        "apply_started" => GitPhase::Attempted(None),
        "receiver_observed" | "finalized" => {
            connection
                .execute(
                    "UPDATE git_ref_operations SET acknowledgement = 'unknown',
                 observed_ref_kind = 'commit', observed_commit = ?1 WHERE operation_id = ?2",
                    params![a.new_commit, a.operation_id],
                )
                .unwrap();
            if phase == "receiver_observed" {
                GitPhase::Observed {
                    acknowledgement: Acknowledgement::Unknown,
                    observed: ObservedRef::Commit(a.new_commit.clone()),
                }
            } else {
                let bytes = evidence::sign(&statement, &[9; 32], "bridge-receipt-key").unwrap();
                connection
                    .execute(
                        "UPDATE git_ref_operations SET receipt_bytes = ?1, receipt_digest = ?2,
                     receipt_key_id = 'bridge-receipt-key' WHERE operation_id = ?3",
                        params![bytes, digest(&bytes), a.operation_id],
                    )
                    .unwrap();
                GitPhase::Finalized {
                    statement: Box::new(statement),
                    receipt: FrozenReceipt {
                        operation_id: a.operation_id.clone(),
                        digest: digest(&bytes),
                        bytes,
                        key_id: "bridge-receipt-key".into(),
                    },
                }
            }
        },
        _ => unreachable!("authored phases are fixed test inputs"),
    }
}

// Complete named SQL projection, independent of production column ordering and record mapping.
pub(in crate::gateway) fn named_kube_row(
    connection: &Connection,
    id: &str,
) -> BTreeMap<String, Value> {
    let mut statement = connection
        .prepare(
            "SELECT operation_id, namespace, deployment, container, immutable_image_digest,
         authorization_id, authorization_signer_key_id, authorization_grant_digest,
         signed_authorization_grant, state, write_strategy, target_rejection,
         target_read_failures, apply_attempted, target_uid, target_resource_version,
         apply_accepted, requested_generation, apply_resource_version, receiver_uid,
         receiver_image, receiver_operation_marker, current_generation, observed_generation,
         receiver_resource_version, desired_replicas, updated_replicas, available_replicas,
         unavailable_replicas, available_condition, progress_deadline_exceeded, result,
         receipt_digest, receipt_bytes, receipt_key_id, rollout_condition_type,
         rollout_condition_status, rollout_condition_reason, approved_uid,
         approved_resource_version, preflight_uid, preflight_resource_version
         FROM kubernetes_image_operations WHERE operation_id = ?1",
        )
        .unwrap();
    let names = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    statement
        .query_row([id], |row| {
            names
                .iter()
                .enumerate()
                .map(|(index, name)| row.get(index).map(|value| (name.clone(), value)))
                .collect()
        })
        .optional()
        .unwrap()
        .unwrap_or_default()
}

pub(in crate::gateway) fn named_git_row(
    connection: &Connection,
    id: &str,
) -> BTreeMap<String, Value> {
    let mut statement = connection.prepare(
        "SELECT operation_id, repository_id, ref_name, old_commit, new_commit, authorization_id,
         authorization_signer_key_id, authorization_grant_digest, signed_authorization_grant,
         state, target_rejection, acknowledgement, observed_ref_kind, observed_commit,
         receipt_digest, receipt_bytes, receipt_key_id
         FROM git_ref_operations WHERE operation_id = ?1"
    ).unwrap();
    let names = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    statement
        .query_row([id], |row| {
            names
                .iter()
                .enumerate()
                .map(|(index, name)| row.get(index).map(|value| (name.clone(), value)))
                .collect()
        })
        .optional()
        .unwrap()
        .unwrap_or_default()
}

pub(in crate::gateway) fn stored_rows(connection: &Connection) -> BTreeMap<String, Vec<Value>> {
    let mut statement = connection
        .prepare("SELECT * FROM kubernetes_image_operations")
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                (0..columns)
                    .map(|i| row.get(i))
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

pub(in crate::gateway) fn open_scratch(scratch: &Scratch) -> Journal {
    Journal::open(scratch.0.join("journal.sqlite3")).unwrap()
}
