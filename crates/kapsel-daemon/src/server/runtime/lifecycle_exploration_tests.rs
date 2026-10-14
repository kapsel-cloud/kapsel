//! Enumerated caller/supervisor/physical-retirement schedules at the runtime owner.

use std::collections::BTreeSet;

use kapsel::{OperationState, ServiceStop};
use tokio::runtime::Builder;

use super::*;

struct RetainedAdmissions(Arc<Mutex<BTreeSet<String>>>);

impl ApplicationReads for RetainedAdmissions {
    fn read(&self, _: protocol::ReadRequest) -> (Vec<u8>, ResponseClass) {
        (operation_failure(), ResponseClass::Ordinary)
    }

    fn admitted_state(&self, id: &str) -> Result<Option<OperationState>, ServiceError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .contains(id)
            .then_some(OperationState::Requested))
    }
}

struct ReleaseOnDrop(Arc<Semaphore>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        // Assertion failures must also release any fixture jobs waiting for physical work.
        self.0.add_permits(CONNECTIONS_MAX);
    }
}

struct ParkedExecution {
    admitted: Arc<Mutex<BTreeSet<String>>>,
    calls: Arc<Mutex<Vec<String>>>,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    acknowledge_before_park: bool,
}

impl ApplicationExecution for ParkedExecution {
    async fn execute(
        &mut self,
        id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<ServiceStop, ServiceError> {
        self.calls.lock().unwrap().push(id.clone());
        let mut acknowledged = Some(acknowledged);
        if self.acknowledge_before_park {
            self.admitted.lock().unwrap().insert(id.clone());
            acknowledged.take().unwrap()(ServiceAdmission::Admitted(OperationState::Requested));
        }

        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();

        if let Some(acknowledged) = acknowledged {
            self.admitted.lock().unwrap().insert(id);
            acknowledged(ServiceAdmission::Admitted(OperationState::Requested));
        }

        Ok(ServiceStop::Finished)
    }
}

async fn submit_and_read_admission(
    state: &ServerState<RetainedAdmissions, ParkedExecution>,
    id: &str,
) -> serde_json::Value {
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
                for abort_before_start in [false, true] {
                    let mut builder = Builder::new_current_thread();
                    if abort_before_start {
                        builder.max_blocking_threads(1);
                    }
                    let runtime = builder.enable_all().build().unwrap();
                    runtime.block_on(run_retirement_schedule(
                        first_id,
                        acknowledge_before_park,
                        actors,
                        abort_before_start,
                    ));
                }
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered registration/abort/retirement schedule"
)]
async fn run_retirement_schedule(
    first_id: &str,
    acknowledge_before_park: bool,
    actors: [Actor; 2],
    abort_before_start: bool,
) {
    let second_id = if first_id == "a" { "b" } else { "a" };
    let admitted = Arc::new(Mutex::new(BTreeSet::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let _release_on_unwind = ReleaseOnDrop(release.clone());
    let state = ServerState::new(
        RetainedAdmissions(admitted.clone()),
        ParkedExecution {
            admitted: admitted.clone(),
            calls: calls.clone(),
            entered: entered.clone(),
            release: release.clone(),
            acknowledge_before_park,
        },
    );

    // Occupy the real blocking pool so the registered closure cannot start until released.
    let (unblock, blocked) = std::sync::mpsc::channel();
    let blocking_peer = if abort_before_start {
        let (started, ready) = tokio::sync::oneshot::channel();
        let peer = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = blocked.recv();
        });
        timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        Some(peer)
    } else {
        None
    };

    let caller_state = state.clone();
    let id = first_id.to_owned();
    let caller = tokio::spawn(async move { submit_and_read_admission(&caller_state, &id).await });
    if abort_before_start {
        timeout(Duration::from_secs(2), async {
            while state.jobs.first_supervisor().is_none() {
                tokio::task::yield_now().await;
            }
            // Let the registered supervisor enqueue its blocking closure, still behind the peer.
            tokio::task::yield_now().await;
        })
        .await
        .unwrap();
    } else {
        timeout(Duration::from_secs(2), entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }

    let supervisor = state.jobs.first_supervisor().unwrap();
    for actor in actors {
        match actor {
            Actor::DisconnectCaller => caller.abort(),
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
        assert_eq!(state.observation(first_id), ExecutionObservation::Active);
        let started_calls = [first_id];
        let expected = if abort_before_start {
            &[][..]
        } else {
            &started_calls[..]
        };
        assert_eq!(calls.lock().unwrap().as_slice(), expected);
    }

    if abort_before_start {
        assert!(!admitted.lock().unwrap().contains(first_id));
        assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX - 1);
        {
            let retirement = state.jobs.drain();
            tokio::pin!(retirement);
            assert!(timeout(Duration::from_millis(20), &mut retirement)
                .await
                .is_err());
            assert_eq!(state.submission.available_permits(), 0);
            unblock.send(()).unwrap();
            timeout(Duration::from_secs(2), entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            assert_eq!(calls.lock().unwrap().as_slice(), [first_id]);
            assert!(timeout(Duration::from_millis(20), &mut retirement)
                .await
                .is_err());
            release.add_permits(1);
            timeout(Duration::from_secs(2), retirement).await.unwrap();
        }
        timeout(Duration::from_secs(2), blocking_peer.unwrap())
            .await
            .unwrap()
            .unwrap();
        let _ = timeout(Duration::from_secs(2), caller).await.unwrap();
        assert_eq!(state.submission.available_permits(), 1);
        assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
        release.add_permits(1);
        assert_eq!(
            submit_and_read_admission(&state, second_id).await["status"],
            "ADMITTED"
        );
        timeout(Duration::from_secs(2), state.jobs.drain())
            .await
            .unwrap();
        assert_eq!(calls.lock().unwrap().as_slice(), [first_id, second_id]);
        assert_eq!(admitted.lock().unwrap().len(), 2);
        return;
    }

    let other_admission = submit_and_read_admission(&state, second_id).await;
    assert_eq!(other_admission["status"], "NOT_ADMITTED");
    assert_eq!(other_admission["reason"], "BUSY");
    let same_admission = submit_and_read_admission(&state, first_id).await;
    assert_eq!(
        same_admission["status"],
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
    let _ = timeout(Duration::from_secs(2), caller).await.unwrap();
    assert_eq!(state.submission.available_permits(), 1);
    assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
    assert!(admitted.lock().unwrap().contains(first_id));

    release.add_permits(1);
    assert_eq!(
        submit_and_read_admission(&state, second_id).await["status"],
        "ADMITTED"
    );
    timeout(Duration::from_secs(2), state.jobs.drain())
        .await
        .unwrap();
    drop(state);
    assert_eq!(calls.lock().unwrap().as_slice(), [first_id, second_id]);
    assert_eq!(admitted.lock().unwrap().len(), 2);
}
