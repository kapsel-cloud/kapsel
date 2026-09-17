//! Decision/ownership races at the actual tracked runtime boundary.
use std::sync::atomic::{AtomicBool, Ordering};

use kapsel::OperationState;

use super::{super::protocol::ReadRequest, *};

struct Reads {
    committed: Arc<AtomicBool>,
    probe: Option<(
        std::sync::mpsc::Sender<()>,
        Mutex<std::sync::mpsc::Receiver<()>>,
    )>,
}
impl ApplicationReads for Reads {
    fn read_observed(
        &self,
        request: ReadRequest,
        observation: &dyn Fn(&str) -> kapsel::ExecutionObservation,
        _: &dyn Fn(ServiceError),
    ) -> (Vec<u8>, ResponseClass) {
        let ReadRequest::Status(id) = request else {
            return (invalid_request(), ResponseClass::Ordinary);
        };
        let status = if self.committed.load(Ordering::SeqCst) {
            kapsel::SetDeploymentImageStatus::InProgress
        } else {
            kapsel::SetDeploymentImageStatus::NotFound
        };
        let entry = kapsel::HistoryEntry {
            operation_id: id.clone(),
            status: Ok((status, kapsel::OperationTargets::default())),
        };
        (
            protocol::render_execution_status(entry.execution_status(observation(&id))),
            ResponseClass::Ordinary,
        )
    }

    fn read(&self, _: ReadRequest) -> (Vec<u8>, ResponseClass) {
        (operation_failure(), ResponseClass::Ordinary)
    }
    fn admitted_state(&self, _: &str) -> Result<Option<OperationState>, ServiceError> {
        let snapshot = self
            .committed
            .load(Ordering::SeqCst)
            .then_some(OperationState::Requested);
        if let Some((entered, release)) = &self.probe {
            entered.send(()).unwrap();
            release.lock().unwrap().recv().unwrap();
        }
        Ok(snapshot)
    }
}
struct Execution {
    committed: Arc<AtomicBool>,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    decision: ServiceAdmission,
    stop: kapsel::ServiceStop,
}
impl ApplicationExecution for Execution {
    async fn execute(
        &mut self,
        _: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<kapsel::ServiceStop, ServiceError> {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        if matches!(self.decision, ServiceAdmission::Admitted(_)) {
            self.committed.store(true, Ordering::SeqCst);
        }
        acknowledged(self.decision);
        Ok(self.stop)
    }
}
fn request(id: &str) -> Vec<u8> {
    serde_json::json!({"version":1,"request":"submit_set_deployment_image","operation_id":id})
        .to_string()
        .into_bytes()
}
async fn decision(
    state: &ServerState<Reads, Execution>,
    id: &str,
    duration: Duration,
) -> serde_json::Value {
    let (bytes, _) = dispatch_admitted(
        &request(id),
        state,
        Arc::new(state.connections.clone().try_acquire_owned().unwrap()),
        Instant::now() + duration,
    )
    .await;
    serde_json::from_slice(&bytes).unwrap()
}
fn state(decision: ServiceAdmission) -> ServerState<Reads, Execution> {
    let committed = Arc::new(AtomicBool::new(false));
    ServerState::new(
        Reads {
            committed: committed.clone(),
            probe: None,
        },
        Execution {
            committed,
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
            decision,
            stop: kapsel::ServiceStop::Finished,
        },
    )
}

#[test]
fn bounded_diagnostics_evict_to_unknown_and_reselection_replaces_old_causes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = state(ServiceAdmission::Admitted(OperationState::Authorized));
        let release = {
            let mut execution = state.execution.lock().await;
            execution.stop =
                kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::SigningUnavailable);
            execution.release.clone()
        };
        for index in 0..33 {
            release.add_permits(1);
            assert_eq!(
                decision(&state, &format!("op-{index}"), Duration::from_secs(2)).await["status"],
                "ADMITTED"
            );
            state.jobs.drain().await;
        }
        assert_eq!(state.stopped.lock().unwrap().len(), 32);
        assert_eq!(
            state.observation("op-0"),
            kapsel::ExecutionObservation::Unknown
        );
        assert_eq!(
            state.observation("op-1"),
            kapsel::ExecutionObservation::Stopped(kapsel::ExecutionCondition::SigningUnavailable)
        );
        state.execution.lock().await.stop = kapsel::ServiceStop::Finished;
        release.add_permits(1);
        decision(&state, "op-1", Duration::from_secs(2)).await;
        state.jobs.drain().await;
        assert_eq!(
            state.observation("op-1"),
            kapsel::ExecutionObservation::Unknown
        );
        assert_eq!(state.stopped.lock().unwrap().len(), 32);
    });
}

#[test]
fn deadline_abandons_only_response_and_contention_distinguishes_identity() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = state(ServiceAdmission::Admitted(OperationState::Requested));
        let release = state.execution.lock().await.release.clone();
        state.stopped.lock().unwrap().push_back((
            "one".into(),
            kapsel::ExecutionObservation::Stopped(kapsel::ExecutionCondition::SigningUnavailable),
        ));
        let result = decision(&state, "one", Duration::from_millis(30)).await;
        assert!(state.stopped.lock().unwrap().is_empty());
        assert_eq!(
            state.observation("one"),
            kapsel::ExecutionObservation::Active
        );
        assert_eq!(
            state.observation("two"),
            kapsel::ExecutionObservation::OtherWorker
        );
        assert_eq!(result["status"], "INDETERMINATE");
        assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX - 1);
        let status_request = concat!(
            r#"{"version":1,"request":"get_set_deployment_image_status","#,
            r#""operation_id":"one"}"#,
        )
        .as_bytes();
        let (bytes, _) = dispatch_with_state(status_request, &state).await;
        let absent: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(absent["status"], "NOT_FOUND");
        assert_eq!(absent["execution"]["disposition"], "admission_unconfirmed");
        assert_eq!(absent["execution"]["next_action"], "read_same_id");
        assert!(!state.reads.lock().unwrap().committed.load(Ordering::SeqCst));
        assert_eq!(state.submission.available_permits(), 0);
        let same = decision(&state, "one", Duration::from_secs(1)).await;
        assert_eq!(same["status"], "INDETERMINATE");
        let other = decision(&state, "two", Duration::from_secs(1)).await;
        assert_eq!(other["status"], "NOT_ADMITTED");
        assert_eq!(other["reason"], "BUSY");
        release.add_permits(1);
        state.jobs.drain().await;
        assert!(state.reads.lock().unwrap().committed.load(Ordering::SeqCst));
        assert_eq!(state.submission.available_permits(), 1);
        assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
        assert_eq!(
            state.observation("one"),
            kapsel::ExecutionObservation::Unknown
        );
    });
}

#[test]
fn same_id_completion_during_absence_probe_retains_original_generation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = state(ServiceAdmission::Admitted(OperationState::Requested));
        let (entered, probed) = std::sync::mpsc::channel();
        let (resume, release_probe) = std::sync::mpsc::channel();
        state.reads.lock().unwrap().probe = Some((entered, Mutex::new(release_probe)));
        let execution = state.execution.lock().await;
        let started = execution.entered.clone();
        let release = execution.release.clone();
        drop(execution);
        let first_state = state.clone();
        let first =
            tokio::spawn(
                async move { decision(&first_state, "one", Duration::from_secs(1)).await },
            );
        started.acquire().await.unwrap().forget();
        let probe_state = state.clone();
        let probe =
            tokio::spawn(
                async move { decision(&probe_state, "one", Duration::from_secs(1)).await },
            );
        let deadline = Instant::now() + Duration::from_secs(1);
        while probed.try_recv().is_err() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        release.add_permits(1);
        assert_eq!(first.await.unwrap()["status"], "ADMITTED");
        // Only the probe closure and its shared job lease may remain. This proves the original
        // supervisor AND physical execution released ownership, without relying on a sleep.
        while state.selected.lock().unwrap().strong_count() != 2 {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert_eq!(state.submission.available_permits(), 0);
        resume.send(()).unwrap();
        assert_eq!(probe.await.unwrap()["status"], "INDETERMINATE");
        state.jobs.drain().await;
        assert_eq!(state.submission.available_permits(), 1);
    });
}

#[test]
fn pinless_absence_probe_cannot_refuse_a_completed_matching_successor() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // A occupies execution without admitting the ID whose absence B will read.
        let mut state = state(ServiceAdmission::Busy);
        let committed = state.reads.lock().unwrap().committed.clone();
        let execution = state.execution.lock().await;
        let started = execution.entered.clone();
        let release = execution.release.clone();
        drop(execution);
        let predecessor_state = state.clone();
        let predecessor = tokio::spawn(async move {
            decision(&predecessor_state, "other", Duration::from_secs(2)).await
        });
        started.acquire().await.unwrap().forget();
        let predecessor_owner = state.selected.lock().unwrap().clone();
        let supervisor = state.jobs.first_supervisor().unwrap();
        supervisor.abort();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !supervisor.is_finished() {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert_eq!(
            state.observation("other"),
            kapsel::ExecutionObservation::Active
        );
        assert_eq!(predecessor_owner.strong_count(), 1);
        assert_eq!(state.submission.available_permits(), 0);

        // Run inside B's failed-acquisition/weak-upgrade gap, holding publication exclusion.
        // Only A's surviving blocking closure can retire here; the reactor is deliberately busy.
        let submission = state.submission.clone();
        state.after_failed_acquisition = Some(Arc::new(move || {
            release.add_permits(1);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while predecessor_owner.strong_count() != 0 || submission.available_permits() != 1 {
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            assert!(predecessor_owner.upgrade().is_none());
        }));
        let (entered, probed) = std::sync::mpsc::channel();
        let (resume, release_probe) = std::sync::mpsc::channel();
        state.reads.lock().unwrap().probe = Some((entered, Mutex::new(release_probe)));
        let probe_state = state.clone();
        let probe =
            tokio::spawn(
                async move { decision(&probe_state, "one", Duration::from_secs(2)).await },
            );
        while probed.try_recv().is_err() {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert!(!committed.load(Ordering::SeqCst));
        assert_eq!(state.selected.lock().unwrap().strong_count(), 0);
        assert_eq!(predecessor.await.unwrap()["reason"], "BUSY");
        state.after_failed_acquisition = None;

        // B holds an absence snapshot but no generation pin. C must admit the matching ID and
        // release BOTH its supervisor and physical ownership before B samples current ownership.
        let mut execution = state.execution.lock().await;
        execution.decision = ServiceAdmission::Admitted(OperationState::Requested);
        execution.release.add_permits(1);
        drop(execution);
        let successor = decision(&state, "one", Duration::from_secs(2)).await;
        assert_eq!(successor["status"], "ADMITTED");
        assert!(committed.load(Ordering::SeqCst));
        while state.selected.lock().unwrap().strong_count() != 0
            || state.submission.available_permits() != 1
        {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        resume.send(()).unwrap();
        let result = probe.await.unwrap();
        state.jobs.drain().await;
        assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
        drop(state);
        assert_eq!(result["status"], "INDETERMINATE", "{result}");
    });
}

#[test]
fn callback_is_required_and_capacity_is_only_a_definite_decision() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for admission in [
            ServiceAdmission::Busy,
            ServiceAdmission::Full,
            ServiceAdmission::Admitted(OperationState::Requested),
        ] {
            let state = state(admission);
            state.execution.lock().await.release.add_permits(1);
            let result = decision(&state, "one", Duration::from_secs(1)).await;
            assert_eq!(result["version"], 1);
            match admission {
                ServiceAdmission::Busy => assert_eq!(result["reason"], "BUSY"),
                ServiceAdmission::Full => assert_eq!(result["reason"], "CAPACITY"),
                ServiceAdmission::Admitted(_) => {
                    assert_eq!(result["status"], "ADMITTED");
                    assert_eq!(result["phase"], "requested");
                    assert!(state.reads.lock().unwrap().committed.load(Ordering::SeqCst));
                },
            }
            state.jobs.drain().await;
            drop(state);
        }
    });
}
