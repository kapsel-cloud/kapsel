use super::*;

#[test]
fn service_admission_acknowledges_capacity_but_not_unsettled_commit_errors() {
    let path = database_path("admission-error");
    let gateway = Gateway::open_for_test(&path).unwrap();
    for capacity_refusal in [false, true] {
        let mut acknowledged = false;
        let result = gateway.admit_service_operation(
            None,
            |journal, worker| {
                assert!(journal.owns_worker(worker));
                Err(if capacity_refusal {
                    GatewayError::JournalFull
                } else {
                    GatewayError::InjectedFault
                })
            },
            |decision| {
                assert!(matches!(decision, AdmissionDecision::Full));
                acknowledged = true;
            },
        );
        assert_eq!(acknowledged, capacity_refusal);
        if capacity_refusal {
            assert!(matches!(result, Ok(None)));
        } else {
            assert!(matches!(
                result,
                Err(ReconciliationError::Submission(GatewayError::InjectedFault))
            ));
        }
        assert!(gateway.journal.try_lock_worker().unwrap().is_some());
    }

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn admission_acknowledgement_loss_covers_absent_and_committed_original_authority() {
    for request_committed in [false, true] {
        let path = database_path(if request_committed {
            "admission-committed"
        } else {
            "admission-absent"
        });
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let signed_grant = sign_authorization_grant(
            &authorization(&request),
            &[7; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        let authorized = gateway.bind_authorization(&request, &signed_grant).unwrap();
        let mut acknowledged = false;
        let result = gateway.admit_service_operation(
            None,
            |journal, _| {
                if request_committed {
                    journal.insert_requested(&authorized)?;
                }
                Err(GatewayError::InjectedFault)
            },
            |_| acknowledged = true,
        );
        assert!(matches!(
            result,
            Err(ReconciliationError::Submission(GatewayError::InjectedFault))
        ));
        assert!(
            !acknowledged,
            "unsettled admission must not acknowledge refusal"
        );

        drop(gateway);
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.journal.existing_submission(&authorized).unwrap(),
            request_committed.then_some(OperationState::Requested)
        );
        if request_committed {
            let retained = gateway
                .retained_operation(&request.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(retained.signed_grant, signed_grant);
        }

        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn terminal_service_admission_does_not_acquire_a_worker_or_insert() {
    let path = database_path("terminal-admission");
    let gateway = Gateway::open_for_test(&path).unwrap();
    let worker = gateway.journal.try_lock_worker().unwrap().unwrap();
    for state in [OperationState::Finalized, OperationState::NotAttempted] {
        let mut acknowledged = false;
        let result = gateway.admit_service_operation(
            Some(state),
            |_, _| Err(GatewayError::InjectedFault),
            |decision| {
                assert!(matches!(decision, AdmissionDecision::Admitted(actual) if actual == state));
                acknowledged = true;
            },
        );
        assert!(matches!(result, Ok(None)));
        assert!(acknowledged);
    }
    drop(worker);
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn requested_recovery_rechecks_exact_authorization_before_advancing() {
    let path = database_path("requested-recovery");
    let request = request();
    let authorization = authorization(&request);
    {
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway.submit_exact_with_fault_for_test(
                &request,
                &authorization,
                Some(FaultPoint::RequestedCommitted)
            ),
            Err(GatewayError::InjectedFault)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Requested)
        );
        assert!(matches!(
            gateway.journal.operation(&request.operation_id).unwrap(),
            Some(journal::LoadedOperation::Requested(_))
        ));
    }
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    let mut mismatched_authorization = authorization.clone();
    mismatched_authorization.container = "other".into();
    assert!(matches!(
        gateway.submit_exact_for_test(&request, &mismatched_authorization),
        Err(GatewayError::AuthorizationMismatch)
    ));
    assert_eq!(
        gateway.get(&request.operation_id).unwrap(),
        Some(OperationState::Requested)
    );
    let signed_grant = sign_authorization_grant(
        &authorization,
        &[7; 32],
        "effect-gateway-authorization-test-key",
    )
    .unwrap();
    let (service, mut handle) = tower_test::mock::pair::<
        http::Request<kube::client::Body>,
        http::Response<kube::client::Body>,
    >();
    let client = kube::Client::new(service, "demo");
    let lock_owner = Gateway::open_for_test(&path).unwrap();
    let worker_lock = lock_owner.journal.try_lock_worker().unwrap().unwrap();
    let operation = gateway
        .reconcile(
            &request,
            &signed_grant,
            client.clone(),
            &ReceiptSettings {
                signing_seed: &[51; 32],
                key_id: "receipt-key",
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(operation.state(), OperationState::Authorized);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), handle.next_request())
            .await
            .is_err()
    );
    drop(worker_lock);
    drop(lock_owner);
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn authorized_commit_reopens_and_begins_exactly_one_apply() {
    let path = database_path("authorized-recovery");
    let request = request();
    {
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway.submit_exact_with_fault_for_test(
                &request,
                &authorization(&request),
                Some(FaultPoint::AuthorizedCommitted)
            ),
            Err(GatewayError::InjectedFault)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
    }
    let mut gateway = Gateway::open_for_test(&path).unwrap();

    let mut adapter = failed_rollout_adapter(&path, &request);
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.identify_calls, 1);
    assert_eq!(adapter.apply_calls, 1);
    assert_eq!(adapter.observe_calls, 1);

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn production_writers_reload_as_their_exact_next_phase() {
    let path = database_path("writer-decoder-symmetry");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::Authorized(_))
    ));

    let mut adapter = failed_rollout_adapter(&path, &request);
    assert!(matches!(
        gateway
            .run_operation_once_with_adapter_and_fault(
                &request.operation_id,
                &mut adapter,
                Some(FaultPoint::ApplyStartedCommitted),
            )
            .await,
        Err(GatewayError::InjectedFault)
    ));
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::ApplyStarted(_))
    ));
    assert_eq!(adapter.apply_calls, 0);

    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::ReceiverObserved(_))
    ));
    assert_eq!(adapter.apply_calls, 0);

    let settings = ReceiptSettings {
        signing_seed: &[51_u8; 32],
        key_id: "symmetry-receipt-key",
    };
    assert!(matches!(
        gateway.finalize_operation_receipt_once_with_fault(
            &request.operation_id,
            &settings,
            Some(FaultPoint::BeforeReceiptCommit),
        ),
        Err(GatewayError::InjectedFault)
    ));
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::ReceiverObserved(_))
    ));

    assert!(matches!(
        gateway.finalize_operation_receipt_once_with_fault(
            &request.operation_id,
            &settings,
            Some(FaultPoint::FinalizedCommitted),
        ),
        Err(GatewayError::InjectedFault)
    ));
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::Finalized(_))
    ));

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn apply_outcome_writer_reloads_as_apply_started_with_complete_response_facts() {
    let path = database_path("apply-outcome-writer-decoder-symmetry");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();

    let mut adapter = failed_rollout_adapter(&path, &request);

    assert!(matches!(
        gateway
            .run_operation_once_with_adapter_and_fault(
                &request.operation_id,
                &mut adapter,
                Some(FaultPoint::ApplyOutcomeCommitted),
            )
            .await,
        Err(GatewayError::InjectedFault)
    ));
    assert!(matches!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(journal::LoadedOperation::ApplyStarted(_))
    ));
    assert_eq!(adapter.apply_calls, 1);

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn permanent_target_rejection_is_terminal_and_does_not_block_later_operations() {
    let path = database_path("permanent-target-rejection");
    let mut rejected = request();
    rejected.operation_id = "op-a".into();
    let mut later = request();
    later.operation_id = "op-b".into();
    {
        let gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&rejected, &authorization(&rejected))
            .unwrap();
        gateway
            .submit_exact_for_test(&later, &authorization(&later))
            .unwrap();
    }
    let mut adapter =
        TargetRoutingAdapter::permanent(&rejected.operation_id, TargetRejection::ContainerNotFound);
    {
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway
                .run_operation_once_with_adapter_and_fault(
                    &rejected.operation_id,
                    &mut adapter,
                    Some(FaultPoint::TargetRejectedCommitted),
                )
                .await,
            Err(GatewayError::InjectedFault)
        ));
        assert_eq!(
            gateway.get(&rejected.operation_id).unwrap(),
            Some(OperationState::NotAttempted)
        );
        assert_eq!(
            gateway.target_rejection(&rejected.operation_id).unwrap(),
            Some(TargetRejection::ContainerNotFound)
        );
        assert!(matches!(
            gateway.journal.operation(&rejected.operation_id).unwrap(),
            Some(journal::LoadedOperation::NotAttempted(_))
        ));
        assert_eq!(gateway.result(&rejected.operation_id).unwrap(), None);
        assert_eq!(
            gateway.receipt_reference(&rejected.operation_id).unwrap(),
            None
        );
    }
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&later.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.identify_order, ["op-a", "op-b"]);
    assert_eq!(adapter.apply_order, ["op-b"]);
    assert_eq!(adapter.observe_order, ["op-b"]);
    assert_eq!(
        gateway.result(&later.operation_id).unwrap(),
        Some(OperationResult::Failed)
    );

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn transient_target_error_stays_authorized_and_retries_only_the_safe_get() {
    let path = database_path("transient-target-retry");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    // The retained target_read_failures column is inert, even with a nonzero historical value.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE kubernetes_image_operations SET target_read_failures = 7",
            [],
        )
        .unwrap();
    let original_data_version: i64 = connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .unwrap();

    let mut adapter = TargetRoutingAdapter::transient_once(&request.operation_id);

    assert!(matches!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await,
        Err(GatewayError::KubernetesTargetObservation)
    ));
    assert_eq!(
        gateway.get(&request.operation_id).unwrap(),
        Some(OperationState::Authorized)
    );
    assert_eq!(gateway.result(&request.operation_id).unwrap(), None);
    assert_eq!(
        gateway.receipt_reference(&request.operation_id).unwrap(),
        None
    );
    assert!(adapter.apply_order.is_empty());
    assert!(adapter.observe_order.is_empty());
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "data_version", |row| row.get(0),)
            .unwrap(),
        original_data_version
    );

    drop(gateway);

    let mut gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.identify_order, ["op-001", "op-001"]);
    assert_eq!(adapter.apply_order, ["op-001"]);
    assert_eq!(adapter.observe_order, ["op-001"]);
    assert_eq!(
        connection
            .query_row(
                "SELECT target_read_failures FROM kubernetes_image_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        7
    );

    drop(connection);
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn targeted_gateway_reconciliation_does_not_advance_another_operation() {
    let path = database_path("targeted-gateway-operation");
    let mut first = request();
    first.operation_id = "op-a".into();
    let mut configured = request();
    configured.operation_id = "op-b".into();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&first, &authorization(&first))
        .unwrap();
    gateway
        .submit_exact_for_test(&configured, &authorization(&configured))
        .unwrap();

    let mut adapter = TargetRoutingAdapter::transient_once("never-transient");

    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&configured.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.identify_order, ["op-b"]);
    assert_eq!(adapter.apply_order, ["op-b"]);
    assert_eq!(adapter.observe_order, ["op-b"]);
    assert_eq!(
        gateway.get(&first.operation_id).unwrap(),
        Some(OperationState::Authorized)
    );

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn targeted_gateway_finalization_does_not_sign_another_operation() {
    let path = database_path("targeted-gateway-finalization");
    let mut first = request();
    first.operation_id = "op-a".into();
    let mut configured = request();
    configured.operation_id = "op-b".into();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&first, &authorization(&first))
        .unwrap();
    gateway
        .submit_exact_for_test(&configured, &authorization(&configured))
        .unwrap();
    gateway
        .run_operation_once_with_adapter(
            &first.operation_id,
            &mut failed_rollout_adapter(&path, &first),
        )
        .await
        .unwrap();
    gateway
        .run_operation_once_with_adapter(
            &configured.operation_id,
            &mut failed_rollout_adapter(&path, &configured),
        )
        .await
        .unwrap();

    let receipt_settings = ReceiptSettings {
        signing_seed: &[51_u8; 32],
        key_id: "targeted-receipt-key",
    };
    assert!(matches!(
        gateway.finalize_operation_receipt_once_with_fault(
            &configured.operation_id,
            &receipt_settings,
            Some(FaultPoint::BeforeReceiptCommit),
        ),
        Err(GatewayError::InjectedFault)
    ));
    assert_eq!(
        gateway.get(&first.operation_id).unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        gateway.get(&configured.operation_id).unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        gateway
            .finalize_operation_receipt_once(&configured.operation_id, &receipt_settings)
            .unwrap(),
        Some(OperationState::Finalized)
    );
    assert_eq!(
        gateway.get(&first.operation_id).unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        gateway.get(&configured.operation_id).unwrap(),
        Some(OperationState::Finalized)
    );

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn target_read_crash_stays_authorized_and_repeats_only_the_safe_get() {
    let path = database_path("target-read-recovery");
    let request = request();
    let mut adapter = failed_rollout_adapter(&path, &request);
    {
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        assert!(matches!(
            gateway
                .run_operation_once_with_adapter_and_fault(
                    &request.operation_id,
                    &mut adapter,
                    Some(FaultPoint::TargetObserved),
                )
                .await,
            Err(GatewayError::InjectedFault)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        assert_eq!(adapter.identify_calls, 1);
        assert_eq!(adapter.apply_calls, 0);
    }
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.identify_calls, 2);
    assert_eq!(adapter.apply_calls, 1);

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
