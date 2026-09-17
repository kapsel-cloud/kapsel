use super::*;

#[test]
fn probe_exclusion_is_not_execution_liveness_and_restart_forgets_causes() {
    let state = ServerState::new((), ());
    let selection = Arc::new(Selection {
        operation_id: "a".into(),
        running: Arc::new(AtomicBool::new(true)),
        _permit: state.submission.clone().try_acquire_owned().unwrap(),
    });
    *state.selected.lock().unwrap() = Arc::downgrade(&selection);
    let physical = ExecutionLifetime(selection.running.clone());
    state.stopped.lock().unwrap().push_back((
        "a".into(),
        kapsel::ExecutionObservation::Stopped(kapsel::ExecutionCondition::SigningUnavailable),
    ));
    assert_eq!(state.observation("a"), kapsel::ExecutionObservation::Active);
    drop(physical);
    // A contention probe may still retain this selection's permit, but no physical work survives.
    assert_eq!(
        state.observation("a"),
        kapsel::ExecutionObservation::OtherWorker
    );
    drop(selection);
    assert_eq!(
        state.observation("a"),
        kapsel::ExecutionObservation::Stopped(kapsel::ExecutionCondition::SigningUnavailable)
    );
    let restarted = ServerState::new((), ());
    assert_eq!(
        restarted.observation("a"),
        kapsel::ExecutionObservation::Unknown
    );
}
