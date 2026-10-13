//! Independent comparisons of original intent, actual I/O, raw history and original bytes.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

use super::{trace::*, world::*};
use crate::{
    application::{
        ExecutionCondition, ExecutionDisposition, ExecutionObservation, HistoryEntry,
        OperationReceipt, OperationStatus, ServiceApplication, ServiceError,
    },
    gateway::{
        git::{Acknowledgement, ObservedRef},
        inspect_receipt, ApprovedTarget, GitOperationTargets, InspectionLimits, InspectionStatus,
        ObservedTarget, OperationResult, OperationState, OperationTargets, ReceiptStatement,
        ReceiptTrust, StorageControl, TargetRejection,
    },
};

pub(super) fn result_from_io(io: &Observations, intent: &Intent) -> &'static str {
    let Some(observed) = &io.returned else {
        return "UNKNOWN";
    };
    let correlated = observed.deployment_uid.as_deref() == Some(intent.uid.as_str())
        && observed.image.as_deref() == Some(intent.request.immutable_image_digest.as_str())
        && observed.operation_marker.as_deref() == Some(intent.request.operation_id.as_str());
    let generation = io
        .response
        .as_ref()
        .and_then(|response| response.requested_generation)
        .or_else(|| correlated.then_some(observed.current_generation).flatten());
    if !correlated
        || generation.is_none()
        || generation != observed.current_generation
        || observed.observed_generation < generation
    {
        return "UNKNOWN";
    }
    if observed.rollout_condition_type.as_deref() == Some("Progressing")
        && observed.rollout_condition_status.as_deref() == Some("False")
        && observed.rollout_condition_reason.as_deref() == Some("ProgressDeadlineExceeded")
    {
        return "FAILED";
    }
    if observed.desired_replicas.is_some()
        && observed.updated_replicas == observed.desired_replicas
        && observed.available_replicas == observed.desired_replicas
        && observed.unavailable_replicas == Some(0)
        && observed.rollout_condition_type.as_deref() == Some("Available")
        && observed.rollout_condition_status.as_deref() == Some("True")
    {
        "SUCCEEDED"
    } else {
        "UNKNOWN"
    }
}

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

    pub(super) fn check(
        &mut self,
        store: &Store,
        io: &Observations,
        intent: &Intent,
        event: usize,
    ) -> Checked {
        let require = |condition, law| {
            if condition {
                Ok(())
            } else {
                Err(Finding {
                    law,
                    event,
                    defect_reached: store.control.defect_reached(),
                })
            }
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
        require(self.receipt_bytes_unchanged(&raw), "original_receipt_bytes")?;
        if matches!(text(&raw, "state"), Some("receiver_observed" | "finalized")) {
            if self.frozen.is_none() {
                require(
                    text(&raw, "result") == Some(result_from_io(io, intent)),
                    "initial_result",
                )?;
                let observation = io.returned.as_ref().unwrap();
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
    let require = |condition, law| {
        if condition {
            Ok(())
        } else {
            Err(Finding {
                law,
                event,
                defect_reached: control.defect_reached(),
            })
        }
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
                    && app.receipt(id) == Ok(OperationReceipt::NotFound),
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
            let expected = stored_projection(peer, raw);
            let stored_projection_matches =
                expected
                    .as_ref()
                    .is_some_and(|(state, expected_status, targets)| {
                        status
                            .as_ref()
                            .is_ok_and(|(actual_status, actual_targets)| {
                                actual_status == expected_status && actual_targets == targets
                            })
                            && admitted == Ok(Some(*state))
                            && (peer.adapter.store.virtualized
                                || history
                                    .entries
                                    .iter()
                                    .find(|entry| &entry.operation_id == id)
                                    .is_some_and(|entry| entry.status == status))
                    });
            let receipt_matches = match (&receipt, raw.get("receipt_bytes")) {
                (Ok(OperationReceipt::NotReady), Some(Value::Null)) => true,
                (Ok(OperationReceipt::Ready { bytes, sha256 }), Some(Value::Blob(stored))) => {
                    bytes == stored && text(raw, "receipt_digest") == Some(sha256.as_str())
                },
                _ => false,
            };
            require(
                stored_projection_matches && receipt_matches,
                "stored_read_projection",
            )?;
        }
        let expected = if accessible {
            stored_projection(peer, raw)
                .map(|(_, status, targets)| (status, targets))
                .ok_or(ServiceError::OperationFailure)
        } else {
            Err(ServiceError::AuthorityUnavailable)
        };
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

// Observation/disposition pairs come from the caller guidance contract, not its projector.
pub(super) fn disposition_reads_match(
    app: &ServiceApplication,
    id: &str,
    status: &Result<(OperationStatus, OperationTargets), ServiceError>,
    history: Option<&HistoryEntry>,
) -> bool {
    use ExecutionCondition as Condition;
    use ExecutionDisposition as Disposition;
    use ExecutionObservation as Observation;
    let observations = [
        (Observation::Unknown, Disposition::ResumeRequired(None)),
        (Observation::Active, Disposition::Active),
        (Observation::OtherWorker, Disposition::WaitingForWorker),
        (
            Observation::Stopped(Condition::PreflightUnavailable),
            Disposition::ResumeRequired(Some(Condition::PreflightUnavailable)),
        ),
        (
            Observation::Stopped(Condition::WorkerContention),
            Disposition::ResumeRequired(Some(Condition::WorkerContention)),
        ),
        (
            Observation::Stopped(Condition::ReceiverUnavailable),
            Disposition::OperatorRequired(Condition::ReceiverUnavailable),
        ),
        (
            Observation::Stopped(Condition::SigningUnavailable),
            Disposition::OperatorRequired(Condition::SigningUnavailable),
        ),
        (
            Observation::Stopped(Condition::CompletionBlocked),
            Disposition::OperatorRequired(Condition::CompletionBlocked),
        ),
        (
            Observation::Stopped(Condition::OperationBlocked),
            Disposition::OperatorRequired(Condition::OperationBlocked),
        ),
    ];
    observations.into_iter().all(|(observation, unfinished)| {
        let expected = status.clone().map(|(status, targets)| {
            let disposition = match status {
                OperationStatus::NotFound => Disposition::AdmissionUnconfirmed,
                OperationStatus::InProgress => unfinished,
                OperationStatus::Succeeded
                | OperationStatus::Failed
                | OperationStatus::Unknown
                | OperationStatus::NotAttempted(_) => Disposition::Complete,
            };
            (status, targets, disposition)
        });
        app.execution_status(id, observation) == expected
            && history.is_none_or(|entry| entry.clone().execution_status(observation) == expected)
    })
}

// Project already retained facts, not a predicted next lifecycle phase or production classifier.
pub(super) fn stored_projection(
    peer: &Peer,
    raw: &BTreeMap<String, Value>,
) -> Option<(OperationState, OperationStatus, OperationTargets)> {
    use OperationState as State;
    use OperationStatus as Status;
    let state = match text(raw, "state")? {
        "requested" => State::Requested,
        "authorized" => State::Authorized,
        "apply_started" => State::ApplyStarted,
        "receiver_observed" => State::ReceiverObserved,
        "finalized" => State::Finalized,
        "not_attempted" => State::NotAttempted,
        _ => return None,
    };
    let status = match state {
        State::Finalized => {
            if let Some(git) = &peer.git {
                match git
                    .durable_ack
                    .lock()
                    .unwrap()
                    .unwrap_or(Acknowledgement::Unknown)
                {
                    Acknowledgement::Updated => Status::Succeeded,
                    Acknowledgement::RejectedBeforeSend | Acknowledgement::ReceiverRejected => {
                        Status::Failed
                    },
                    Acknowledgement::Unknown => Status::Unknown,
                }
            } else {
                match text(raw, "result")? {
                    "SUCCEEDED" => Status::Succeeded,
                    "FAILED" => Status::Failed,
                    "UNKNOWN" => Status::Unknown,
                    _ => return None,
                }
            }
        },
        State::NotAttempted => Status::NotAttempted(match text(raw, "target_rejection")? {
            "stale_approval" => TargetRejection::StaleApproval,
            "stale_ref" => TargetRejection::GitStaleRef,
            _ => return None,
        }),
        State::Requested | State::Authorized | State::ApplyStarted | State::ReceiverObserved => {
            Status::InProgress
        },
    };
    let targets = if let Some(git) = &peer.git {
        let acknowledgement = match text(raw, "acknowledgement") {
            Some("updated") => Some(Acknowledgement::Updated),
            Some("rejected_before_send") => Some(Acknowledgement::RejectedBeforeSend),
            Some("receiver_rejected") => Some(Acknowledgement::ReceiverRejected),
            Some("unknown") => Some(Acknowledgement::Unknown),
            None => None,
            _ => return None,
        };
        let observed_ref = match text(raw, "observed_ref_kind") {
            Some("commit") => Some(ObservedRef::Commit(text(raw, "observed_commit")?.into())),
            Some("missing") => Some(ObservedRef::Missing),
            Some("unknown") => Some(ObservedRef::Unknown),
            None => None,
            _ => return None,
        };
        OperationTargets {
            git: Some(GitOperationTargets {
                approval: git.authorization.clone(),
                attempted: matches!(
                    state,
                    State::ApplyStarted | State::ReceiverObserved | State::Finalized
                ),
                acknowledgement,
                observed_ref,
            }),
            ..OperationTargets::default()
        }
    } else {
        let intent = &peer.adapter.intent;
        let approved = ApprovedTarget {
            uid: intent.uid.clone(),
            resource_version: intent.version.clone(),
        };
        let observed_target = if matches!(state, State::ReceiverObserved | State::Finalized) {
            Some(ObservedTarget {
                uid: text(raw, "receiver_uid").map(str::to_owned),
                resource_version: text(raw, "receiver_resource_version").map(str::to_owned),
            })
        } else {
            text(raw, "preflight_uid").map(|uid| ObservedTarget {
                uid: Some(uid.into()),
                resource_version: text(raw, "preflight_resource_version").map(str::to_owned),
            })
        };
        OperationTargets {
            approved_target: Some(approved.clone()),
            attempt_target: (integer(raw, "apply_attempted") == Some(1)).then_some(approved),
            observed_target,
            git: None,
        }
    };
    Some((state, status, targets))
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
        let require = |condition, law| {
            if condition {
                Ok(())
            } else {
                Err(Finding {
                    law,
                    event,
                    defect_reached: store.control.defect_reached(),
                })
            }
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
            if let Ok(OperationReceipt::Ready { bytes, sha256 }) =
                app.receipt(&approval.operation_id)
            {
                let trust = ReceiptTrust {
                    key_id: intent.receipt_key.clone(),
                    public_key: SigningKey::from_bytes(&intent.receipt_seed)
                        .verifying_key()
                        .to_bytes(),
                    accepted_purpose: "kapsel.git-ref-transition-receipt.v1".into(),
                    not_before_unix_s: 0,
                    not_after_unix_s: 60,
                }
                .encode()
                .unwrap();
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
                require(
                    raw.get("receipt_bytes") == Some(&Value::Blob(bytes.clone())),
                    "original_receipt_bytes",
                )?;
                require(hex(&Sha256::digest(&bytes)) == sha256, "receipt_digest")?;
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
        return Err(Finding {
            law: "rejection_binding",
            event,
            defect_reached: control.defect_reached(),
        });
    }
    match app.receipt(&intent.request.operation_id) {
        Ok(OperationReceipt::Ready { bytes, sha256 }) => {
            let trust = ReceiptTrust {
                key_id: intent.receipt_key.clone(),
                public_key: SigningKey::from_bytes(&intent.receipt_seed)
                    .verifying_key()
                    .to_bytes(),
                accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
                not_before_unix_s: 0,
                not_after_unix_s: 60,
            }
            .encode()
            .unwrap();
            let inspection = inspect_receipt(&bytes, &trust, 1, InspectionLimits::default());
            if inspection.status() != InspectionStatus::Inspected {
                return Err(Finding {
                    law: "original_signer",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if !inspection
                .statement()
                .is_some_and(|statement| receipt_matches_columns(statement, &terminal, io, intent))
            {
                return Err(Finding {
                    law: "receipt_binding",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            if terminal.get("receipt_bytes") != Some(&Value::Blob(bytes.clone())) {
                return Err(Finding {
                    law: "original_receipt_bytes",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
            let digest = hex(&Sha256::digest(&bytes));
            if digest != sha256 {
                return Err(Finding {
                    law: "receipt_digest",
                    event,
                    defect_reached: control.defect_reached(),
                });
            }
        },
        _ if !require_progress => {},
        _ => {
            return Err(Finding {
                law: "healthy_progress",
                event,
                defect_reached: control.defect_reached(),
            })
        },
    }
    Ok(())
}

// Named columns have already been bound to original intent and actual I/O by event laws.
// This projects public inspected fields, not the production statement builder or classifier.
pub(super) fn receipt_matches_columns(
    statement: &ReceiptStatement,
    raw: &BTreeMap<String, Value>,
    io: &Observations,
    intent: &Intent,
) -> bool {
    let text_fields = [
        ("operation_id", Some(statement.operation_id())),
        ("authorization_id", Some(statement.authorization_id())),
        (
            "authorization_signer_key_id",
            Some(statement.authorization_signer_key_id()),
        ),
        (
            "authorization_grant_digest",
            Some(statement.authorization_grant_digest()),
        ),
        ("namespace", Some(statement.namespace())),
        ("deployment", Some(statement.deployment())),
        ("container", Some(statement.container())),
        (
            "immutable_image_digest",
            Some(statement.immutable_image_digest()),
        ),
        ("write_strategy", Some(statement.write_strategy())),
        (
            "approved_uid",
            statement
                .approved_target()
                .map(|target| target.uid.as_str()),
        ),
        (
            "approved_resource_version",
            statement
                .approved_target()
                .map(|target| target.resource_version.as_str()),
        ),
        ("target_uid", Some(statement.target_uid())),
        (
            "target_resource_version",
            Some(statement.target_resource_version()),
        ),
        ("receiver_uid", statement.receiver_uid()),
        ("receiver_image", statement.observed_image()),
        (
            "receiver_operation_marker",
            statement.observed_operation_marker(),
        ),
        (
            "receiver_resource_version",
            statement.observed_resource_version(),
        ),
        ("rollout_condition_type", statement.rollout_condition_type()),
        (
            "rollout_condition_status",
            statement.rollout_condition_status(),
        ),
        (
            "rollout_condition_reason",
            statement.rollout_condition_reason(),
        ),
    ];
    let integer_fields = [
        ("current_generation", statement.current_generation()),
        ("requested_generation", statement.requested_generation()),
        ("observed_generation", statement.observed_generation()),
        (
            "desired_replicas",
            statement.desired_replicas().map(i64::from),
        ),
        (
            "updated_replicas",
            statement.updated_replicas().map(i64::from),
        ),
        (
            "available_replicas",
            statement.available_replicas().map(i64::from),
        ),
        (
            "unavailable_replicas",
            statement.unavailable_replicas().map(i64::from),
        ),
    ];
    let result = match statement.result() {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    };
    text_fields
        .iter()
        .all(|(column, value)| text(raw, column) == *value)
        && integer_fields
            .iter()
            .all(|(column, value)| integer(raw, column) == *value)
        && result == result_from_io(io, intent)
}
