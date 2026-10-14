//! Independent comparisons of original intent, actual I/O, raw history and original bytes.

use std::collections::BTreeMap;

use rusqlite::types::Value;
use sha2::{Digest, Sha256};

use super::{trace::*, world::*};
use crate::{
    application::{
        ExecutionDisposition, ExecutionObservation, HistoryEntry, OperationReceipt,
        OperationStatus, ServiceApplication, ServiceError,
    },
    gateway::{
        git::{Acknowledgement, ObservedRef},
        inspect_receipt, InspectionLimits, InspectionStatus, OperationResult, OperationTargets,
        StorageControl,
    },
};

#[derive(Default)]
pub(super) struct Checker {
    preflight: Option<(String, String)>,
    rejected: Option<BTreeMap<String, Value>>,
    frozen: Option<BTreeMap<String, Value>>,
    frozen_reads: usize,
    original_bytes: Option<Value>,
}

impl Checker {
    pub(super) fn receipt_bytes_unchanged(&mut self, raw: &BTreeMap<String, Value>) -> bool {
        if let Some(original) = &self.original_bytes {
            return raw.get("receipt_bytes") == Some(original);
        }
        self.original_bytes = raw
            .get("receipt_bytes")
            .filter(|value| **value != Value::Null)
            .cloned();
        true
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keep initial freeze and subsequent temporal comparisons together"
    )]
    pub(super) fn check(
        &mut self,
        store: &Store,
        io: &Observations,
        intent: &Intent,
        event: usize,
    ) -> Checked {
        let require = |condition: bool, law| {
            condition
                .then_some(())
                .ok_or_else(|| Finding::at(law, event, &store.control))
        };
        if let Some(law) = io.violation {
            require(false, law)?;
        }
        require(io.sends.len() <= 1, "at_most_one_mutation")?;
        let mut raw = store.raw(&intent.request.operation_id);
        if raw.is_empty() {
            return Ok(());
        }
        require(intent.matches_record(&raw), "original_authority")?;
        require(receipt_columns_match(&raw, intent), "receipt_columns")?;
        if let Some(original) = &self.rejected {
            require(original == &raw, "rejected_history_immutable")?;
        }
        if text(&raw, "state") == Some("not_attempted") {
            require(io.sends.is_empty(), "rejection_without_mutation")?;
            self.rejected.get_or_insert_with(|| raw.clone());
        }
        if let (Some(uid), Some(version)) = (
            text(&raw, "preflight_uid"),
            text(&raw, "preflight_resource_version"),
        ) {
            let retained = (uid.to_owned(), version.to_owned());
            if self.preflight.as_ref() != Some(&retained) {
                require(
                    io.preflight.as_ref().is_some_and(|target| {
                        target.deployment_uid == uid && target.resource_version == version
                    }),
                    "preflight_io_binding",
                )?;
                self.preflight = Some(retained);
            }
        }
        if integer(&raw, "apply_attempted") == Some(1) {
            require(
                text(&raw, "target_uid") == Some(intent.uid.as_str())
                    && text(&raw, "target_resource_version") == Some(intent.version.as_str()),
                "attempt_binding",
            )?;
        }
        if let Some(accepted) = integer(&raw, "apply_accepted") {
            require(
                io.response.as_ref().is_some_and(|response| {
                    accepted == i64::from(response.accepted)
                        && text(&raw, "apply_resource_version")
                            == response.resource_version.as_deref()
                        && (!matches!(text(&raw, "state"), Some("apply_started"))
                            || integer(&raw, "requested_generation")
                                == response.requested_generation)
                }),
                "durable_response_binding",
            )?;
        }
        require(self.receipt_bytes_unchanged(&raw), "original_receipt_bytes")?;
        if matches!(text(&raw, "state"), Some("receiver_observed" | "finalized")) {
            if self.frozen.is_none() {
                require(text(&raw, "result") == io.expected_result, "initial_result")?;
                let observation = io.returned.as_ref().unwrap();
                let generation = if integer(&raw, "apply_accepted").is_some() {
                    io.response
                        .as_ref()
                        .and_then(|response| response.requested_generation)
                } else {
                    None
                }
                .or(io.inferred_generation);
                require(
                    integer(&raw, "requested_generation") == generation,
                    "durable_response_binding",
                )?;
                require(
                    text(&raw, "receiver_uid") == observation.deployment_uid.as_deref()
                        && text(&raw, "receiver_resource_version")
                            == observation.resource_version.as_deref()
                        && text(&raw, "receiver_image") == observation.image.as_deref()
                        && text(&raw, "receiver_operation_marker")
                            == observation.operation_marker.as_deref()
                        && integer(&raw, "current_generation") == observation.current_generation
                        && integer(&raw, "observed_generation") == observation.observed_generation
                        && integer(&raw, "desired_replicas")
                            == observation.desired_replicas.map(i64::from)
                        && integer(&raw, "updated_replicas")
                            == observation.updated_replicas.map(i64::from)
                        && integer(&raw, "available_replicas")
                            == observation.available_replicas.map(i64::from)
                        && integer(&raw, "unavailable_replicas")
                            == observation.unavailable_replicas.map(i64::from)
                        && text(&raw, "rollout_condition_type")
                            == observation.rollout_condition_type.as_deref()
                        && text(&raw, "rollout_condition_status")
                            == observation.rollout_condition_status.as_deref()
                        && text(&raw, "rollout_condition_reason")
                            == observation.rollout_condition_reason.as_deref(),
                    "frozen_io_binding",
                )?;
            }
            for field in ["state", "receipt_bytes", "receipt_digest", "receipt_key_id"] {
                raw.remove(field);
            }
            if let Some(original) = &self.frozen {
                require(
                    original == &raw && self.frozen_reads == io.reads,
                    "frozen_no_io",
                )?;
            } else {
                self.frozen = Some(raw);
                self.frozen_reads = io.reads;
            }
        }
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep all-peer authenticated projections inside one read-only snapshot boundary"
)]
pub(super) fn check_reads(
    app: &ServiceApplication,
    peers: &[Peer],
    trusted: &[bool],
    control: &StorageControl,
    event: usize,
) -> Checked {
    let require = |condition: bool, law| {
        condition
            .then_some(())
            .ok_or_else(|| Finding::at(law, event, control))
    };
    let before = peers.iter().map(Peer::snapshot).collect::<Vec<_>>();
    let writes_before = control.reached().len();
    let history = app.history(None).unwrap();
    if !peers[0].adapter.store.virtualized {
        let mut ids = peers
            .iter()
            .enumerate()
            .filter(|(index, _)| !before[*index].record.is_empty())
            .map(|(_, peer)| peer.adapter.intent.request.operation_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        require(
            history.next_cursor.is_none()
                && history
                    .entries
                    .iter()
                    .map(|entry| entry.operation_id.clone())
                    .collect::<Vec<_>>()
                    == ids,
            "stored_history_projection",
        )?;
    }
    for (index, peer) in peers.iter().enumerate() {
        let raw = &before[index].record;
        let id = &peer.adapter.intent.request.operation_id;
        if raw.is_empty() {
            require(
                app.status(id) == Ok((OperationStatus::NotFound, OperationTargets::default()))
                    && app.receipt(id) == Ok(OperationReceipt::NotFound)
                    && matches!(
                        app.admitted_state(id),
                        Ok(None) | Err(ServiceError::InvalidRequest)
                    ),
                "original_intent",
            )?;
            require(
                disposition_reads_match(
                    app,
                    id,
                    &Ok((OperationStatus::NotFound, OperationTargets::default())),
                    None,
                ),
                "execution_disposition_projection",
            )?;
            continue;
        }
        let accessible = trusted[index];
        let status = app.status(id);
        let receipt = app.receipt(id);
        let admitted = app.admitted_state(id);
        let projection_access = [status.is_ok(), receipt.is_ok(), admitted.is_ok()];
        // Enumeration is a physical SQL query; the virtual record store owns point reads only.
        let history_matches = peer.adapter.store.virtualized
            || history
                .entries
                .iter()
                .find(|entry| &entry.operation_id == id)
                .is_some_and(|entry| entry.status.is_ok() == accessible);
        require(
            history_matches && projection_access.iter().all(|actual| *actual == accessible),
            "original_trust_disclosure",
        )?;
        if accessible {
            let receipt_matches = match (&receipt, raw.get("receipt_bytes")) {
                (Ok(OperationReceipt::NotReady), Some(Value::Null)) => true,
                (Ok(OperationReceipt::Ready { bytes, sha256 }), Some(Value::Blob(stored))) => {
                    bytes == stored && text(raw, "receipt_digest") == Some(sha256.as_str())
                },
                _ => false,
            };
            require(receipt_matches, "original_receipt_read_bytes")?;
        }
        // Local owners bind full phase/targets; histories retain process-context binding.
        let expected = status;
        require(
            disposition_reads_match(
                app,
                id,
                &expected,
                history
                    .entries
                    .iter()
                    .find(|entry| &entry.operation_id == id),
            ),
            "execution_disposition_projection",
        )?;
    }
    require(
        before == peers.iter().map(Peer::snapshot).collect::<Vec<_>>()
            && writes_before == control.reached().len(),
        "stored_reads_are_read_only",
    )
}

// Bind public reads to authenticated history with no surviving process-local explanation.
pub(super) fn disposition_reads_match(
    app: &ServiceApplication,
    id: &str,
    status: &Result<(OperationStatus, OperationTargets), ServiceError>,
    history: Option<&HistoryEntry>,
) -> bool {
    // Unknown binds lost process knowledge, including after reopen. Active additionally binds
    // observation forwarding in both wrappers; the complete partition belongs to disposition.
    [
        (
            ExecutionObservation::Unknown,
            ExecutionDisposition::ResumeRequired(None),
        ),
        (ExecutionObservation::Active, ExecutionDisposition::Active),
    ]
    .into_iter()
    .all(|(observation, unfinished)| {
        let expected = status.clone().map(|(status, targets)| {
            let disposition = match status {
                OperationStatus::NotFound => ExecutionDisposition::AdmissionUnconfirmed,
                OperationStatus::InProgress => unfinished,
                OperationStatus::Succeeded
                | OperationStatus::Failed
                | OperationStatus::Unknown
                | OperationStatus::NotAttempted(_) => ExecutionDisposition::Complete,
            };
            (status, targets, disposition)
        });
        app.execution_status(id, observation) == expected
            && history.is_none_or(|entry| entry.clone().execution_status(observation) == expected)
    })
}

impl Checker {
    #[allow(
        clippy::too_many_lines,
        reason = "keep Git intent, raw frozen facts and independently returned bytes together"
    )]
    pub(super) fn check_git(
        &mut self,
        app: &ServiceApplication,
        store: &Store,
        intent: &Intent,
        git: &GitPeer,
        event: usize,
        require_progress: bool,
    ) -> Checked {
        let require = |condition: bool, law| {
            condition
                .then_some(())
                .ok_or_else(|| Finding::at(law, event, &store.control))
        };
        let io = git.script.state.lock().unwrap();
        if let Some(law) = io.violation {
            require(false, law)?;
        }
        require(io.sends <= 1, "at_most_one_mutation")?;
        let mut raw = store.raw_effect(&intent.request.operation_id, true);
        if raw.is_empty() {
            return require(!require_progress, "healthy_progress");
        }
        require(receipt_columns_match(&raw, intent), "receipt_columns")?;
        require(self.receipt_bytes_unchanged(&raw), "original_receipt_bytes")?;
        if let Some(original) = &self.rejected {
            require(original == &raw, "rejected_history_immutable")?;
        }
        let approval = &git.authorization;
        let digest = hex(&Sha256::digest(&intent.grant));
        for (field, expected) in [
            ("operation_id", &approval.operation_id),
            ("repository_id", &approval.repository_id),
            ("ref_name", &approval.reference),
            ("old_commit", &approval.old_commit),
            ("new_commit", &approval.new_commit),
            ("authorization_id", &intent.authorization_id),
            ("authorization_signer_key_id", &intent.authorization_key),
            ("authorization_grant_digest", &digest),
        ] {
            require(
                text(&raw, field) == Some(expected.as_str()),
                "original_authority",
            )?;
        }
        require(
            raw.get("signed_authorization_grant") == Some(&Value::Blob(intent.grant.clone())),
            "original_authority",
        )?;
        let acknowledgement = git
            .durable_ack
            .lock()
            .unwrap()
            .unwrap_or(Acknowledgement::Unknown);
        let expected_result = match acknowledgement {
            Acknowledgement::Updated => OperationResult::Succeeded,
            Acknowledgement::RejectedBeforeSend | Acknowledgement::ReceiverRejected => {
                OperationResult::Failed
            },
            Acknowledgement::Unknown => OperationResult::Unknown,
        };
        if matches!(text(&raw, "state"), Some("receiver_observed" | "finalized")) {
            if self.frozen.is_none() {
                require(
                    text(&raw, "acknowledgement") == Some(acknowledgement.as_str()),
                    "git_acknowledgement_binding",
                )?;
                let observed = io.returned_observation.as_ref();
                let bound = match observed {
                    Some(ObservedRef::Commit(commit)) => {
                        text(&raw, "observed_ref_kind") == Some("commit")
                            && text(&raw, "observed_commit") == Some(commit.as_str())
                    },
                    Some(ObservedRef::Missing) => {
                        text(&raw, "observed_ref_kind") == Some("missing")
                            && raw.get("observed_commit") == Some(&Value::Null)
                    },
                    Some(ObservedRef::Unknown) => {
                        text(&raw, "observed_ref_kind") == Some("unknown")
                            && raw.get("observed_commit") == Some(&Value::Null)
                    },
                    None => false,
                };
                require(bound, "frozen_io_binding")?;
            }
            if let Ok(OperationReceipt::Ready { bytes, .. }) = app.receipt(&approval.operation_id) {
                let trust = intent.receipt_trust("kapsel.git-ref-transition-receipt.v1");
                let inspection =
                    crate::inspect_git_receipt(&bytes, &trust, 1, InspectionLimits::default());
                require(
                    inspection.status() == InspectionStatus::Inspected,
                    "original_signer",
                )?;
                require(
                    inspection.statement().is_some_and(|statement| {
                        statement.authorization() == approval
                            && statement.authorization_signer_key_id() == intent.authorization_key
                            && statement.authorization_grant_digest() == digest
                            && statement.acknowledgement() == acknowledgement
                            && Some(statement.observed_ref()) == io.returned_observation.as_ref()
                    }),
                    "receipt_binding",
                )?;
                require(
                    inspection
                        .statement()
                        .is_some_and(|statement| statement.result() == expected_result),
                    "git_result_classification",
                )?;
                // check_reads binds the public bytes/digest to the already authenticated row.
            } else {
                require(!require_progress, "healthy_progress")?;
            }
            for field in ["state", "receipt_bytes", "receipt_digest", "receipt_key_id"] {
                raw.remove(field);
            }
            if let Some(original) = &self.frozen {
                require(
                    original == &raw && self.frozen_reads == io.reads,
                    "frozen_no_io",
                )?;
            } else {
                self.frozen = Some(raw);
                self.frozen_reads = io.reads;
            }
        } else if text(&raw, "state") == Some("not_attempted") {
            require(
                text(&raw, "target_rejection") == Some("stale_ref") && io.sends == 0,
                "rejection_binding",
            )?;
            self.rejected.get_or_insert_with(|| raw.clone());
        } else {
            require(!require_progress, "healthy_progress")?;
        }
        drop(io);
        Ok(())
    }
}

pub(super) fn receipt_columns_match(raw: &BTreeMap<String, Value>, intent: &Intent) -> bool {
    if text(raw, "state") != Some("finalized") {
        return ["receipt_bytes", "receipt_digest", "receipt_key_id"]
            .iter()
            .all(|field| raw.get(*field) == Some(&Value::Null));
    }
    let Some(Value::Blob(bytes)) = raw.get("receipt_bytes") else {
        return false;
    };
    let digest = hex(&Sha256::digest(bytes));
    text(raw, "receipt_digest") == Some(digest.as_str())
        && text(raw, "receipt_key_id") == Some(intent.receipt_key.as_str())
}

pub(super) fn check_terminal(
    app: &ServiceApplication,
    store: &Store,
    io: &Observations,
    intent: &Intent,
    event: usize,
    require_progress: bool,
) -> Checked {
    let control = &store.control;
    let terminal = store.raw(&intent.request.operation_id);
    if text(&terminal, "state") == Some("not_attempted") {
        if text(&terminal, "target_rejection") == Some("stale_approval")
            && (text(&terminal, "preflight_uid") == Some("replacement-uid")
                || (text(&terminal, "preflight_uid") == Some(intent.uid.as_str())
                    && text(&terminal, "preflight_resource_version") == Some("stale-version")))
            && io.sends.is_empty()
        {
            return Ok(());
        }
        return Err(Finding::at("rejection_binding", event, control));
    }
    match app.receipt(&intent.request.operation_id) {
        Ok(OperationReceipt::Ready { bytes, .. }) => {
            let trust = intent.receipt_trust("kapsel.kap0038.kubernetes-effect-receipt.v3");
            let inspection = inspect_receipt(&bytes, &trust, 1, InspectionLimits::default());
            if inspection.status() != InspectionStatus::Inspected {
                return Err(Finding::at("original_signer", event, control));
            }
            if !inspection.statement().is_some_and(|statement| {
                statement.operation_id() == intent.request.operation_id
                    && statement.authorization_id() == intent.authorization_id
                    && statement.authorization_signer_key_id() == intent.authorization_key
                    && statement.authorization_grant_digest() == hex(&Sha256::digest(&intent.grant))
            }) {
                return Err(Finding::at("receipt_binding", event, control));
            }
            // Histories bind original authority and signer; local journal owners bind the complete
            // signed statement to frozen columns. First frozen_io_binding remains event-complete.
        },
        _ if !require_progress => {},
        _ => return Err(Finding::at("healthy_progress", event, control)),
    }
    Ok(())
}
