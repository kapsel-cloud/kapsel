//! Enumerated caller/supervisor/physical-retirement schedules at the runtime owner.

use std::collections::BTreeSet;

use super::*;

struct Reads(Arc<Mutex<BTreeSet<String>>>);

impl ApplicationReads for Reads {
    fn read(&self, _: protocol::ReadRequest) -> (Vec<u8>, ResponseClass) {
        (operation_failure(), ResponseClass::Ordinary)
    }

    fn admitted_state(&self, id: &str) -> Result<Option<kapsel::OperationState>, ServiceError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .contains(id)
            .then_some(kapsel::OperationState::Requested))
    }
}

struct ReleaseOnDrop(Arc<Semaphore>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        // Assertion failures must also release any fixture jobs waiting for physical work.
        self.0.add_permits(CONNECTIONS_MAX);
    }
}

struct Execution {
    admitted: Arc<Mutex<BTreeSet<String>>>,
    calls: Arc<Mutex<Vec<String>>>,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    acknowledge_before_park: bool,
}

impl ApplicationExecution for Execution {
    async fn execute(
        &mut self,
        id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<kapsel::ServiceStop, ServiceError> {
        self.calls.lock().unwrap().push(id.clone());
        let mut acknowledged = Some(acknowledged);
        if self.acknowledge_before_park {
            self.admitted.lock().unwrap().insert(id.clone());
            acknowledged.take().unwrap()(ServiceAdmission::Admitted(
                kapsel::OperationState::Requested,
            ));
        }
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        if let Some(acknowledged) = acknowledged {
            self.admitted.lock().unwrap().insert(id);
            acknowledged(ServiceAdmission::Admitted(
                kapsel::OperationState::Requested,
            ));
        }
        Ok(kapsel::ServiceStop::Finished)
    }
}

async fn select(state: &ServerState<Reads, Execution>, id: &str) -> serde_json::Value {
    let request = serde_json::to_vec(&serde_json::json!({
        "version": 1, "request": "submit_set_deployment_image", "operation_id": id,
    }))
    .unwrap();
    let (bytes, _) = dispatch_admitted(
        &request,
        state,
        Arc::new(state.connections.clone().try_acquire_owned().unwrap()),
        Instant::now() + Duration::from_secs(2),
    )
    .await;
    serde_json::from_slice(&bytes).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Actor {
    DisconnectCaller,
    AbortSupervisor,
}

#[test]
fn enumerated_lifecycle_physical_retirement_barriers() {
    for acknowledge_before_park in [false, true] {
        for first_id in ["a", "b"] {
            for actors in [
                [Actor::DisconnectCaller, Actor::AbortSupervisor],
                [Actor::AbortSupervisor, Actor::DisconnectCaller],
            ] {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(schedule(first_id, acknowledge_before_park, actors));
            }
        }
    }
}

async fn schedule(first_id: &str, acknowledge_before_park: bool, actors: [Actor; 2]) {
    let second_id = if first_id == "a" { "b" } else { "a" };
    let admitted = Arc::new(Mutex::new(BTreeSet::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let _release_on_unwind = ReleaseOnDrop(release.clone());
    let state = ServerState::new(
        Reads(admitted.clone()),
        Execution {
            admitted: admitted.clone(),
            calls: calls.clone(),
            entered: entered.clone(),
            release: release.clone(),
            acknowledge_before_park,
        },
    );
    let owner = state.clone();
    let id = first_id.to_owned();
    let client = tokio::spawn(async move { select(&owner, &id).await });
    timeout(Duration::from_secs(2), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let supervisor = state.jobs.first_supervisor().unwrap();
    for actor in actors {
        match actor {
            Actor::DisconnectCaller => client.abort(),
            Actor::AbortSupervisor => {
                supervisor.abort();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !supervisor.is_finished() {
                    assert!(Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
            },
        }
        assert_eq!(state.submission.available_permits(), 0, "{actors:?}");
        assert_eq!(
            state.observation(first_id),
            kapsel::ExecutionObservation::Active
        );
        assert_eq!(calls.lock().unwrap().as_slice(), [first_id]);
    }
    let other = select(&state, second_id).await;
    assert_eq!(other["status"], "NOT_ADMITTED");
    assert_eq!(other["reason"], "BUSY");
    let same = select(&state, first_id).await;
    assert_eq!(
        same["status"],
        if acknowledge_before_park {
            "ADMITTED"
        } else {
            "INDETERMINATE"
        }
    );
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "contention must not start another physical execution"
    );

    {
        let retirement = state.jobs.drain();
        tokio::pin!(retirement);
        assert!(timeout(Duration::from_millis(20), &mut retirement)
            .await
            .is_err());
        assert_eq!(state.submission.available_permits(), 0);
        assert!(!admitted.lock().unwrap().contains(second_id));
        release.add_permits(1);
        timeout(Duration::from_secs(2), retirement).await.unwrap();
    }
    let _ = client.await;
    assert_eq!(state.submission.available_permits(), 1);
    assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
    assert!(admitted.lock().unwrap().contains(first_id));

    release.add_permits(1);
    assert_eq!(select(&state, second_id).await["status"], "ADMITTED");
    state.jobs.drain().await;
    drop(state);
    assert_eq!(calls.lock().unwrap().as_slice(), [first_id, second_id]);
    assert_eq!(admitted.lock().unwrap().len(), 2);
}
