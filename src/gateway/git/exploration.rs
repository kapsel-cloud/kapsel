//! Test-only receiver events around the real Git continuation and SQLite transitions.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use kapsel_authority::{GitRefAuthorization, APPROVED_GIT_REF};

use super::{Acknowledgement, GitError, GitReceiver, ObservedRef, PreparedTransition};
use crate::gateway::{FaultPoint, Gateway, GatewayError, OperationState, ReceiptSettings};

#[derive(Clone, Copy)]
pub(crate) enum Barrier {
    Preflight,
    Mutation,
    Observation,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "independent receiver faults and dispatch provenance are not lifecycle phases"
)]
pub(crate) struct State {
    pub(crate) reads: usize,
    pub(crate) sends: usize,
    pub(crate) stale: bool,
    pub(crate) unavailable: bool,
    pub(crate) acknowledgement: Acknowledgement,
    pub(crate) observed: ObservedRef,
    pub(crate) barrier: Option<Barrier>,
    pub(crate) resume: Option<Arc<tokio::sync::Notify>>,
    pub(crate) fault: Option<FaultPoint>,
    pub(crate) violation: Option<&'static str>,
    pub(crate) returned_acknowledgement: Option<Acknowledgement>,
    pub(crate) returned_observation: Option<ObservedRef>,
    pub(crate) ref_after_send: Option<ObservedRef>,
    pub(crate) lose_response: bool,
    pub(crate) fresh_attempt: bool,
    kernel: Option<(crate::gateway::StorageControl, GitRefAuthorization)>,
    journal: PathBuf,
    id: String,
}

pub(crate) struct Script {
    pub(crate) state: Arc<Mutex<State>>,
    receiver: GitReceiver,
}

pub(crate) fn approval(id: &str) -> GitRefAuthorization {
    GitRefAuthorization {
        authorization_id: format!("approval-{id}"),
        operation_id: id.into(),
        repository_id: format!("repository-{id}"),
        reference: APPROVED_GIT_REF.into(),
        old_commit: "a".repeat(40),
        new_commit: "b".repeat(40),
    }
}

impl Script {
    pub(crate) fn new(id: &str, journal: PathBuf) -> Self {
        let state = Arc::new(Mutex::new(State {
            reads: 0,
            sends: 0,
            stale: false,
            unavailable: false,
            acknowledgement: Acknowledgement::Updated,
            observed: ObservedRef::Commit("a".repeat(40)),
            barrier: None,
            resume: None,
            fault: None,
            violation: None,
            returned_acknowledgement: None,
            returned_observation: None,
            ref_after_send: None,
            lose_response: false,
            fresh_attempt: false,
            kernel: None,
            journal,
            id: id.into(),
        }));
        let receiver = GitReceiver {
            // No subprocess path is used by this cfg(test)-only scripted receiver.
            executable: PathBuf::new(),
            sender: PathBuf::new(),
            receiver: PathBuf::new(),
            repository_id: approval(id).repository_id,
            packet_trace: None,
            script: Some(Arc::clone(&state)),
        };
        Self { state, receiver }
    }

    pub(crate) fn kernel(
        original: GitRefAuthorization,
        journal: PathBuf,
        control: crate::gateway::StorageControl,
    ) -> Self {
        let mut script = Self::new(&original.operation_id, journal);
        script
            .receiver
            .repository_id
            .clone_from(&original.repository_id);
        script.state.lock().unwrap().kernel = Some((control, original));
        script
    }

    pub(crate) fn receiver(&self) -> &GitReceiver {
        &self.receiver
    }

    pub(crate) fn submit(gateway: &Gateway, id: &str, competing: bool) -> Result<(), GatewayError> {
        let mut approved = approval(id);
        if competing {
            approved.new_commit = "c".repeat(40);
        }
        let grant = kapsel_authority::sign_git_ref_grant(
            &approved,
            &[7; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        let binding = super::GitBinding::verify(&grant, &gateway.authorization_trust)?;
        if gateway.authorized_git(&grant)?.is_some() {
            return Ok(());
        }
        let Some(worker) = gateway.journal.try_lock_worker()? else {
            return Err(GatewayError::InvalidTransition);
        };
        gateway.journal.insert_git(&binding, &worker)?;
        Ok(())
    }

    pub(crate) async fn advance(
        &self,
        gateway: &mut Gateway,
        id: &str,
        signing: Option<&ReceiptSettings<'_>>,
        completion_only: bool,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(worker) = gateway.journal.try_lock_worker()? else {
            return Ok(None);
        };
        let Some((binding, phase)) = gateway
            .journal
            .retained_git(id, &gateway.authorization_trust)?
        else {
            return Ok(None);
        };
        if completion_only && !matches!(phase, super::GitPhase::Observed { .. }) {
            return Ok(None);
        }
        let phase = super::advance(
            &mut gateway.journal,
            &binding,
            Some(&self.receiver),
            signing,
            &worker,
        )
        .await?;
        Ok(Some(phase.state()))
    }
}

async fn wait_for_resume(state: &Mutex<State>) {
    let resume = state.lock().unwrap().resume.clone();
    if let Some(resume) = resume {
        resume.notified().await;
    } else {
        std::future::pending::<()>().await;
    }
}

impl GitReceiver {
    pub(super) fn exploration_fault(&self, point: FaultPoint) -> bool {
        self.script
            .as_ref()
            .is_some_and(|script| script.lock().unwrap().fault == Some(point))
    }

    pub(super) async fn scripted_prepare<'a>(
        &'a self,
        state: &Mutex<State>,
        authorization: &GitRefAuthorization,
    ) -> Result<PreparedTransition<'a>, GitError> {
        let (barrier, target_stale, unavailable) = {
            let mut state = state.lock().unwrap();
            state.reads += 1;
            if state
                .kernel
                .as_ref()
                .is_some_and(|(_, original)| original != authorization)
            {
                state.violation = Some("original_intent");
            }
            (state.barrier, state.stale, state.unavailable)
        };
        if matches!(barrier, Some(Barrier::Preflight)) {
            wait_for_resume(state).await;
        }
        if unavailable {
            return Err(GitError::Unavailable);
        }
        if target_stale {
            return Err(GitError::StaleRef);
        }
        Ok(PreparedTransition {
            receiver: self,
            authorization: authorization.clone(),
        })
    }

    pub(super) async fn scripted_send(
        &self,
        state: &Mutex<State>,
        authorization: &GitRefAuthorization,
    ) -> Acknowledgement {
        let (barrier, acknowledgement) = {
            let mut state = state.lock().unwrap();
            // An independently opened reader must see the marker before any simulated send.
            let committed = if let Some((control, original)) = &state.kernel {
                let phase = control.value(&state.id, "state").or_else(|| {
                    let connection = rusqlite::Connection::open(&state.journal).ok()?;
                    connection
                        .query_row(
                            "SELECT state FROM git_ref_operations WHERE operation_id = ?1",
                            [&state.id],
                            |row| row.get::<_, rusqlite::types::Value>(0),
                        )
                        .ok()
                });
                state.fresh_attempt
                    && original == authorization
                    && phase == Some(rusqlite::types::Value::Text("apply_started".into()))
                    && control.last_delivery(crate::gateway::StorageWrite::Attempt)
                        == Some(crate::gateway::Delivery::Confirmed)
            } else {
                Gateway::open_for_test(&state.journal)
                    .and_then(|gateway| gateway.retained_git(&state.id))
                    .is_ok_and(|operation| {
                        operation.is_some_and(|operation| {
                            operation.state == OperationState::ApplyStarted
                                && operation.targets.attempted
                                && operation.targets.approval == *authorization
                        })
                    })
            };
            if !committed {
                state.violation = Some("dispatch_before_commit");
                return Acknowledgement::Unknown;
            }
            state.sends += 1;
            if state.acknowledgement == Acknowledgement::Updated {
                state.observed = ObservedRef::Commit(authorization.new_commit.clone());
            }
            state.ref_after_send = Some(state.observed.clone());
            let delivered = if state.lose_response {
                Acknowledgement::Unknown
            } else {
                state.acknowledgement
            };
            (state.barrier, delivered)
        };
        if matches!(barrier, Some(Barrier::Mutation)) {
            wait_for_resume(state).await;
        }
        state.lock().unwrap().returned_acknowledgement = Some(acknowledgement);
        acknowledgement
    }

    pub(super) async fn scripted_observe(&self, state: &Mutex<State>) -> ObservedRef {
        let (barrier, observed) = {
            let mut state = state.lock().unwrap();
            state.reads += 1;
            let observed = if state.unavailable {
                ObservedRef::Unknown
            } else {
                state.observed.clone()
            };
            (state.barrier, observed)
        };
        if matches!(barrier, Some(Barrier::Observation)) {
            wait_for_resume(state).await;
        }
        state.lock().unwrap().returned_observation = Some(observed.clone());
        observed
    }
}
