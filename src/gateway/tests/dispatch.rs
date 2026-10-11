use super::{
    journal::{AuthorizedOperation, LoadedOperation},
    *,
};

// Evidence for the adopted fresh-commit-to-dispatch boundary, using real journal decisions.

fn observed_target() -> ValidatedTargetIdentity {
    ValidatedTargetIdentity::try_from(TargetIdentity {
        deployment_uid: "deployment-uid-1".into(),
        resource_version: "resource-version-0".into(),
    })
    .unwrap()
}

fn load_authorized(gateway: &Gateway) -> AuthorizedOperation {
    let Some(LoadedOperation::Authorized(operation)) = gateway.journal.operation("op-001").unwrap()
    else {
        panic!("fixture must still be authorized");
    };
    operation
}

#[test]
fn competing_fresh_transitions_issue_one_bound_permission() {
    use std::sync::{Arc, Barrier};

    let path = database_path("dispatch-claimants");
    let request = request();
    let gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();

    drop(gateway);
    let barrier = Arc::new(Barrier::new(2));
    // Array::map starts both threads before either is joined at the shared barrier.
    let claimants = [0, 1].map(|_| {
        let path = path.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let gateway = Gateway::open_for_test(path).unwrap();
            let operation = load_authorized(&gateway);
            barrier.wait();
            match gateway
                .journal
                .begin_attempt(&operation, observed_target(), None)
            {
                Ok(Some(permission)) => {
                    // Even the winner cannot reuse its pre-commit Authorized snapshot.
                    assert!(matches!(
                        gateway
                            .journal
                            .begin_attempt(&operation, observed_target(), None),
                        Err(GatewayError::InvalidTransition)
                    ));
                    Some(permission.into_payload())
                },
                Err(GatewayError::InvalidTransition) => None,
                result => panic!("unexpected claim result: {}", result.is_ok()),
            }
        })
    });
    let dispatch_winners: Vec<_> = claimants
        .into_iter()
        .filter_map(|claimant| claimant.join().unwrap())
        .collect();
    assert_eq!(dispatch_winners.len(), 1);
    assert_eq!(dispatch_winners[0].0, request);
    assert_eq!(dispatch_winners[0].1, observed_target().to_adapter_target());
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert!(matches!(
        gateway.journal.operation("op-001").unwrap(),
        Some(LoadedOperation::ApplyStarted(_))
    ));

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_snapshot_from_another_journal_cannot_authorize_a_different_frozen_action() {
    let first_path = database_path("dispatch-first-action");
    let second_path = database_path("dispatch-second-action");
    let first = Gateway::open_for_test(&first_path).unwrap();
    let second = Gateway::open_for_test(&second_path).unwrap();
    let request = request();
    first
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    let mut different_request = request;
    different_request.container = "different".into();
    second
        .submit_exact_for_test(&different_request, &authorization(&different_request))
        .unwrap();

    let foreign_snapshot = load_authorized(&first);
    assert!(matches!(
        second
            .journal
            .begin_attempt(&foreign_snapshot, observed_target(), None),
        Err(GatewayError::InvalidTransition)
    ));
    assert_eq!(
        second.get("op-001").unwrap(),
        Some(OperationState::Authorized)
    );

    let permission = second
        .journal
        .begin_attempt(&load_authorized(&second), observed_target(), None)
        .unwrap()
        .unwrap();
    assert_eq!(permission.into_payload().0, different_request);

    drop(first);
    drop(second);
    fs::remove_dir_all(first_path.parent().unwrap()).unwrap();
    fs::remove_dir_all(second_path.parent().unwrap()).unwrap();
}
