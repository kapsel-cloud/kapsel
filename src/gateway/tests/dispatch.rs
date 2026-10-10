use super::*;

// Evidence for the adopted fresh-commit-to-dispatch boundary, using real journal decisions.

fn observed_target() -> ValidatedTargetIdentity {
    ValidatedTargetIdentity::try_from(TargetIdentity {
        deployment_uid: "deployment-uid-1".into(),
        resource_version: "resource-version-0".into(),
    })
    .unwrap()
}

fn load_authorized(gateway: &Gateway) -> journal::AuthorizedOperation {
    let Some(journal::LoadedOperation::Authorized(operation)) =
        gateway.journal.operation("op-001").unwrap()
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
    let winners: Vec<_> = claimants
        .into_iter()
        .filter_map(|claimant| claimant.join().unwrap())
        .collect();
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].0, request);
    assert_eq!(winners[0].1, observed_target().to_adapter_target());
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert!(matches!(
        gateway.journal.operation("op-001").unwrap(),
        Some(journal::LoadedOperation::ApplyStarted(_))
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
    let mut different = request;
    different.container = "different".into();
    second
        .submit_exact_for_test(&different, &authorization(&different))
        .unwrap();
    let misplaced = load_authorized(&first);
    assert!(matches!(
        second
            .journal
            .begin_attempt(&misplaced, observed_target(), None),
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
    assert_eq!(permission.into_payload().0, different);
    drop(first);
    drop(second);
    fs::remove_dir_all(first_path.parent().unwrap()).unwrap();
    fs::remove_dir_all(second_path.parent().unwrap()).unwrap();
}

// Poll the real driver until the adapter pauses, then drop the future to model cancellation.
// Target, attempt and recovery decisions still belong to Gateway and Journal.
#[tokio::test]
async fn cancellation_before_and_after_dispatch_preserves_durable_meaning() {
    struct PausingAdapter {
        inner: FakeAdapter,
        before_attempt: bool,
    }
    impl DeploymentImageAdapter for PausingAdapter {
        async fn identify(
            &mut self,
            request: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            if self.before_attempt {
                std::future::pending().await
            } else {
                self.inner.identify(request).await
            }
        }
        async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
            self.inner.apply(permission).await?;
            std::future::pending().await
        }
        async fn observe(
            &mut self,
            request: &SetDeploymentImageRequest,
            outcome: &ApplyOutcome,
        ) -> Result<ReceiverObservation, ()> {
            self.inner.observe(request, outcome).await
        }
    }
    for before_attempt in [true, false] {
        let path = database_path(&format!("dispatch-cancel-{before_attempt}"));
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = PausingAdapter {
            inner: failed_adapter(&path, &request),
            before_attempt,
        };
        let mut execution =
            Box::pin(gateway.run_operation_once_with_adapter(&request.operation_id, &mut adapter));
        assert!(matches!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(execution.as_mut().poll(cx))).await,
            std::task::Poll::Pending
        ));
        drop(execution);
        assert_eq!(
            gateway.get("op-001").unwrap(),
            Some(if before_attempt {
                OperationState::Authorized
            } else {
                OperationState::ApplyStarted
            })
        );
        assert_eq!(gateway.result("op-001").unwrap(), None);
        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter.inner)
            .await
            .unwrap();
        assert_eq!(adapter.inner.apply_calls, 1);
        assert_eq!(
            gateway.result("op-001").unwrap(),
            Some(OperationResult::Failed)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
