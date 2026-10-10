//! Test-only receiver events around the real Git continuation and SQLite transitions.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use kapsel_authority::GitRefAuthorization;

use super::{Acknowledgement, GitError, GitReceiver, ObservedRef, PreparedTransition};
use crate::gateway::{FaultPoint, StorageControl};

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
    control: StorageControl,
    original: GitRefAuthorization,
    journal: PathBuf,
    id: String,
}

pub(crate) struct Script {
    pub(crate) state: Arc<Mutex<State>>,
    receiver: GitReceiver,
}

impl Script {
    pub(crate) fn new(
        original: GitRefAuthorization,
        journal: PathBuf,
        control: StorageControl,
    ) -> Self {
        let repository_id = original.repository_id.clone();
        let state = Arc::new(Mutex::new(State {
            reads: 0,
            sends: 0,
            stale: false,
            unavailable: false,
            acknowledgement: Acknowledgement::Updated,
            observed: ObservedRef::Commit(original.old_commit.clone()),
            barrier: None,
            resume: None,
            fault: None,
            violation: None,
            returned_acknowledgement: None,
            returned_observation: None,
            ref_after_send: None,
            lose_response: false,
            fresh_attempt: false,
            id: original.operation_id.clone(),
            original,
            control,
            journal,
        }));
        let receiver = GitReceiver {
            // No subprocess path is used by this cfg(test)-only scripted receiver.
            executable: PathBuf::new(),
            sender: PathBuf::new(),
            receiver: PathBuf::new(),
            repository_id,
            packet_trace: None,
            script: Some(Arc::clone(&state)),
        };
        Self { state, receiver }
    }

    pub(crate) fn receiver(&self) -> &GitReceiver {
        &self.receiver
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
            if state.original != *authorization {
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
            let phase = state.control.value(&state.id, "state").or_else(|| {
                let connection = rusqlite::Connection::open(&state.journal).ok()?;
                connection
                    .query_row(
                        "SELECT state FROM git_ref_operations WHERE operation_id = ?1",
                        [&state.id],
                        |row| row.get::<_, rusqlite::types::Value>(0),
                    )
                    .ok()
            });
            let fresh_attempt_committed = state.fresh_attempt
                && state.original == *authorization
                && phase == Some(rusqlite::types::Value::Text("apply_started".into()))
                && state
                    .control
                    .last_delivery(crate::gateway::StorageWrite::Attempt)
                    == Some(crate::gateway::Delivery::Confirmed);
            if !fresh_attempt_committed {
                state.violation = Some("dispatch_before_commit");
                return Acknowledgement::Unknown;
            }

            state.sends += 1;
            if state.acknowledgement == Acknowledgement::Updated {
                state.observed = ObservedRef::Commit(authorization.new_commit.clone());
            }
            state.ref_after_send = Some(state.observed.clone());
            let returned_acknowledgement = if state.lose_response {
                Acknowledgement::Unknown
            } else {
                state.acknowledgement
            };
            (state.barrier, returned_acknowledgement)
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
