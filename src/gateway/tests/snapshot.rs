use super::*;

fn snapshot_authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
    let mut grant = authorization(request);
    grant.approved_target = Some(ApprovedTarget {
        uid: "deployment-uid-1".into(),
        resource_version: "resource-version-0".into(),
    });
    grant
}

#[tokio::test]
async fn snapshot_replacement_is_rejected_before_and_after_receipt_completion() {
    for finalized in [false, true] {
        let path = database_path(&format!("snapshot-replacement-{finalized}"));
        let request = request();
        let approval = snapshot_authorization(&request);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway.submit_exact_for_test(&request, &approval).unwrap();
        if finalized {
            let mut adapter = failed_rollout_adapter(&path, &request);
            gateway
                .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
                .await
                .unwrap();
            gateway
                .finalize_operation_receipt_once(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &[42; 32],
                        key_id: "snapshot-receipt",
                    },
                )
                .unwrap();
        }

        let original_state = gateway.get(&request.operation_id).unwrap();

        let original_receipt = finalized.then(|| {
            Gateway::read_loaded_receipt(
                gateway
                    .loaded_for_test(&request.operation_id)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
        });

        drop(gateway);
        let gateway = Gateway::open_for_test(&path).unwrap();
        for change_uid in [true, false] {
            let mut replacement = approval.clone();
            let target = replacement.approved_target.as_mut().unwrap();
            if change_uid {
                target.uid = "replacement".into();
            } else {
                target.resource_version = "replacement".into();
            }
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &replacement),
                Err(GatewayError::OperationIdentityConflict)
            ));
            let retained = gateway
                .loaded_for_test(&request.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(retained.targets().approved_target, approval.approved_target);
            assert_eq!(gateway.get(&request.operation_id).unwrap(), original_state);
            if let Some(original_receipt) = &original_receipt {
                assert_eq!(
                    &Gateway::read_loaded_receipt(retained).unwrap(),
                    original_receipt
                );
            }
        }
        gateway.submit_exact_for_test(&request, &approval).unwrap();

        drop(gateway);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn stale_snapshot_is_durable_status_only_without_patch_or_receipt() {
    let stale = [
        ("drifted-version", "deployment-uid-1", "different"),
        ("recreated-object", "recreated", "resource-version-0"),
    ];
    for (case, uid, version) in stale {
        let path = database_path(case);
        let request = request();
        let mut approval = snapshot_authorization(&request);
        approval.approved_target = Some(ApprovedTarget {
            uid: uid.into(),
            resource_version: version.into(),
        });
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway.submit_exact_for_test(&request, &approval).unwrap();

        let mut adapter = failed_rollout_adapter(&path, &request);
        assert_eq!(
            gateway
                .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
                .await
                .unwrap(),
            Some(OperationState::NotAttempted)
        );
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));

        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();

        let retained_operation = gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            retained_operation.target_rejection(),
            Some(TargetRejection::StaleApproval)
        );
        assert_eq!(
            retained_operation.targets().approved_target,
            approval.approved_target
        );
        assert_eq!(
            retained_operation.targets().observed_target,
            Some(ObservedTarget {
                uid: Some("deployment-uid-1".into()),
                resource_version: Some("resource-version-0".into()),
            })
        );
        assert!(retained_operation.targets().attempt_target.is_none());
        assert!(retained_operation.result().is_none());
        assert!(retained_operation.frozen_receipt().is_none());
        assert_eq!(
            gateway
                .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
                .await
                .unwrap(),
            None
        );
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));
    }
}

#[tokio::test]
async fn matching_snapshot_freezes_distinct_approved_observed_and_attempt_targets() {
    let path = database_path("matching-snapshot-targets");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();

    let mut adapter = failed_rollout_adapter(&path, &request);

    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.apply_calls, 1);
    assert_eq!(
        adapter
            .applied_target
            .as_ref()
            .map(|target| (&target.deployment_uid, &target.resource_version)),
        approval
            .approved_target
            .as_ref()
            .map(|target| (&target.uid, &target.resource_version))
    );

    let retained_operation = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    let targets = retained_operation.targets();
    assert_eq!(targets.approved_target, approval.approved_target);
    assert_eq!(targets.attempt_target, approval.approved_target);
    assert_eq!(
        targets.observed_target,
        Some(ObservedTarget {
            uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
        })
    );

    let statement = gateway
        .journal
        .receipt_statement(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        statement.approved_target(),
        approval.approved_target.as_ref()
    );
    assert_eq!(statement.target_uid(), "deployment-uid-1");
    assert_eq!(statement.target_resource_version(), "resource-version-0");
    assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
    assert_eq!(
        statement.observed_resource_version(),
        Some("resource-version-2")
    );
}

#[tokio::test]
async fn snapshot_apply_failure_after_marker_is_attempted_and_recovery_only_observes() {
    let path = database_path("snapshot-patch-conflict");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();

    let mut apply_failure_adapter = failed_rollout_adapter(&path, &request);
    apply_failure_adapter.inject_apply_failure = true;

    assert!(matches!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut apply_failure_adapter)
            .await,
        Err(GatewayError::KubernetesApply)
    ));
    assert_eq!(
        gateway.get(&request.operation_id).unwrap(),
        Some(OperationState::ApplyStarted)
    );
    assert_eq!(apply_failure_adapter.apply_calls, 1);
    assert_eq!(
        apply_failure_adapter
            .applied_target
            .as_ref()
            .map(|target| (&target.deployment_uid, &target.resource_version)),
        approval
            .approved_target
            .as_ref()
            .map(|target| (&target.uid, &target.resource_version))
    );

    let retained_operation = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        retained_operation.targets().approved_target,
        approval.approved_target
    );
    assert_eq!(
        retained_operation.targets().attempt_target,
        approval.approved_target
    );
    assert_eq!(
        retained_operation.targets().observed_target,
        Some(ObservedTarget {
            uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-0".into()),
        })
    );
    assert!(retained_operation.result().is_none());

    drop(gateway);

    let mut gateway = Gateway::open_for_test(&path).unwrap();

    let mut recovery_adapter = failed_rollout_adapter(&path, &request);
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut recovery_adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        (
            recovery_adapter.identify_calls,
            recovery_adapter.apply_calls,
            recovery_adapter.observe_calls
        ),
        (0, 0, 1)
    );

    drop(gateway);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn restart_before_attempt_revalidates_the_original_snapshot_without_refreshing_it() {
    let path = database_path("snapshot-restart-before-attempt");
    let request = request();
    let approval = snapshot_authorization(&request);
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert!(matches!(
        gateway.submit_exact_with_fault_for_test(
            &request,
            &approval,
            Some(FaultPoint::AuthorizedCommitted)
        ),
        Err(GatewayError::InjectedFault)
    ));

    drop(gateway);

    let mut gateway = Gateway::open_for_test(&path).unwrap();

    let mut adapter = failed_rollout_adapter(&path, &request);
    adapter.identified_target.resource_version = "intervening-write".into();
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::NotAttempted)
    );
    assert_eq!(
        (
            adapter.identify_calls,
            adapter.apply_calls,
            adapter.observe_calls
        ),
        (1, 0, 0)
    );

    let retained_operation = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        retained_operation.target_rejection(),
        Some(TargetRejection::StaleApproval)
    );
    assert_eq!(
        retained_operation.targets().approved_target,
        approval.approved_target
    );
    assert!(retained_operation.targets().attempt_target.is_none());

    drop(gateway);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn snapshot_restart_retains_authority_and_marker_recovery_never_resends() {
    for seam in [
        FaultPoint::RequestedCommitted,
        FaultPoint::AuthorizedCommitted,
        FaultPoint::ApplyStartedCommitted,
    ] {
        let path = database_path(&format!("snapshot-{seam:?}"));
        let request = request();
        let approval = snapshot_authorization(&request);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        if seam == FaultPoint::ApplyStartedCommitted {
            gateway.submit_exact_for_test(&request, &approval).unwrap();

            let mut adapter = failed_rollout_adapter(&path, &request);
            let attempt_result = gateway
                .run_operation_once_with_adapter_and_fault(
                    &request.operation_id,
                    &mut adapter,
                    Some(seam),
                )
                .await;
            assert!(matches!(attempt_result, Err(GatewayError::InjectedFault)));
            assert_eq!(adapter.apply_calls, 0);
        } else {
            let submission_result =
                gateway.submit_exact_with_fault_for_test(&request, &approval, Some(seam));
            assert!(matches!(
                submission_result,
                Err(GatewayError::InjectedFault)
            ));
        }

        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        let mut replacement = approval.clone();
        replacement
            .approved_target
            .as_mut()
            .unwrap()
            .resource_version = "replacement".into();
        let replacement_result = gateway.submit_exact_for_test(&request, &replacement);
        assert!(matches!(
            replacement_result,
            Err(GatewayError::OperationIdentityConflict)
        ));
        let legacy_submission_result =
            gateway.submit_exact_for_test(&request, &authorization(&request));
        assert!(matches!(
            legacy_submission_result,
            Err(GatewayError::OperationIdentityConflict)
        ));
        gateway.submit_exact_for_test(&request, &approval).unwrap();

        let mut adapter = failed_rollout_adapter(&path, &request);
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap();
        assert_eq!(
            adapter.apply_calls,
            usize::from(seam != FaultPoint::ApplyStartedCommitted)
        );

        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            statement.approved_target(),
            approval.approved_target.as_ref()
        );

        let bytes = sign_statement(&statement, &[9_u8; 32], "receipt-key").unwrap();
        let trust = ReceiptTrust {
            key_id: "receipt-key".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
            not_before_unix_s: 0,
            not_after_unix_s: 10,
        }
        .encode()
        .unwrap();

        let report = inspect_receipt(&bytes, &trust, 1, InspectionLimits::default());
        assert_eq!(report.status(), InspectionStatus::Inspected);
        assert_eq!(
            report.statement().unwrap().approved_target(),
            approval.approved_target.as_ref()
        );
    }
}
