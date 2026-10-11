//! Single-field authority conflicts and immediate driver failures have no generated phase oracle.
use super::*;

fn snapshot_authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
    let mut approval = authorization(request);
    approval.approved_target = Some(ApprovedTarget {
        uid: "deployment-uid-1".into(),
        resource_version: "resource-version-0".into(),
    });
    approval
}

#[tokio::test]
async fn each_snapshot_field_and_legacy_downgrade_preserve_original_history() {
    let path = database_path("snapshot-conflicts");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();
    for finalize in [false, true] {
        if finalize {
            gateway
                .run_operation_once_with_adapter(
                    &request.operation_id,
                    &mut failed_rollout_adapter(&path, &request),
                )
                .await
                .unwrap();
            gateway
                .finalize_operation_receipt_once(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &[42; 32],
                        key_id: "original",
                    },
                )
                .unwrap();
        }
        let original = gateway.journal.operation(&request.operation_id).unwrap();
        for field in 0..3 {
            let mut changed = approval.clone();
            match field {
                0 => changed.approved_target.as_mut().unwrap().uid = "other".into(),
                1 => changed.approved_target.as_mut().unwrap().resource_version = "other".into(),
                _ => changed.approved_target = None,
            }
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &changed),
                Err(GatewayError::OperationIdentityConflict)
            ));
            assert_eq!(
                gateway.journal.operation(&request.operation_id).unwrap(),
                original
            );
        }
    }
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn apply_failure_stops_at_attempt_with_original_preflight_evidence() {
    let path = database_path("snapshot-apply-error");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();
    let mut adapter = failed_rollout_adapter(&path, &request);
    adapter.inject_apply_failure = true;
    let preflight = ObservedTarget {
        uid: Some(adapter.identified_target.deployment_uid.clone()),
        resource_version: Some(adapter.identified_target.resource_version.clone()),
    };
    assert!(matches!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await,
        Err(GatewayError::KubernetesApply)
    ));
    assert_eq!(
        (
            adapter.identify_calls,
            adapter.apply_calls,
            adapter.observe_calls
        ),
        (1, 1, 0)
    );
    let retained = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.state(), OperationState::ApplyStarted);
    let targets = retained.targets();
    assert_eq!(targets.approved_target, approval.approved_target);
    assert_eq!(targets.attempt_target, approval.approved_target);
    assert_eq!(targets.observed_target, Some(preflight));
    assert!(retained.result().is_none() && retained.frozen_receipt().is_none());
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
