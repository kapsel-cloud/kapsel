//! Completion checks only SQL-owned candidate binding and physical commitment.
use super::{LoadedOperation, *};

#[tokio::test]
async fn full_identity_capacity_ascending_completes_all_remaining_receipts() {
    super::storage::qualify_full_capacity_order("ascending").await;
}

#[tokio::test]
async fn full_identity_capacity_descending_completes_all_remaining_receipts() {
    super::storage::qualify_full_capacity_order("descending").await;
}

#[tokio::test]
async fn full_identity_capacity_alternating_completes_all_remaining_receipts() {
    super::storage::qualify_full_capacity_order("alternating").await;
}

#[tokio::test]
async fn receipt_commit_rejects_wrong_facts_and_foreign_snapshot_without_changing_history() {
    let paths = [
        database_path("receipt-original"),
        database_path("receipt-foreign"),
    ];
    let request = request();
    let mut gateways = paths
        .each_ref()
        .map(|path| Gateway::open_for_test(path).unwrap());
    for (index, gateway) in gateways.iter_mut().enumerate() {
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_rollout_adapter(&paths[index], &request);
        adapter.observation.rollout_condition_reason = Some(format!("reason-{index}"));
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap();
    }
    let snapshots = gateways.each_ref().map(|gateway| {
        let Some(LoadedOperation::ReceiverObserved(operation)) =
            gateway.journal.operation(&request.operation_id).unwrap()
        else {
            unreachable!()
        };
        operation
    });
    let settings = ReceiptSettings {
        signing_seed: &[71; 32],
        key_id: "original-key",
    };
    let foreign = Gateway::build_receipt(&snapshots[1], &settings).unwrap();
    let gateway = &gateways[0];
    let original = super::storage::stored_rows(&gateway.journal.connection);
    assert!(matches!(
        gateway.journal.commit_receipt(&snapshots[0], &foreign),
        Err(GatewayError::InvalidPersistedState)
    ));
    assert!(matches!(
        gateway.journal.commit_receipt(&snapshots[1], &foreign),
        Err(GatewayError::InvalidTransition)
    ));
    assert_eq!(
        super::storage::stored_rows(&gateway.journal.connection),
        original
    );
    let worker = gateway.journal.try_lock_worker().unwrap().unwrap();
    assert_eq!(
        gateway
            .finalize_operation_receipt_once(&request.operation_id, &settings)
            .unwrap(),
        None
    );
    assert_eq!(
        super::storage::stored_rows(&gateway.journal.connection),
        original
    );
    drop(worker);
    let candidate = Gateway::build_receipt(&snapshots[0], &settings).unwrap();
    gateway
        .journal
        .commit_receipt(&snapshots[0], &candidate)
        .unwrap();
    let finalized = super::storage::stored_rows(&gateway.journal.connection);
    assert!(gateway
        .journal
        .commit_receipt(&snapshots[0], &foreign)
        .is_err());
    assert_eq!(
        super::storage::stored_rows(&gateway.journal.connection),
        finalized
    );
    drop(gateways);
    for path in paths {
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn process_exit_before_and_after_receipt_commit_preserves_frozen_observation() {
    for scenario in ["before_receipt_commit", "receipt"] {
        let path = database_path(scenario);
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        gateway
            .run_operation_once_with_adapter(
                &request.operation_id,
                &mut failed_rollout_adapter(&path, &request),
            )
            .await
            .unwrap();
        let frozen = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap();
        drop(gateway);
        let ready = path.parent().unwrap().join("ready");
        let mut child = spawn_process_child(scenario, &path, &ready, None, None);
        wait_for_child_seam(&mut child, &ready);
        kill_child(&mut child);
        let gateway = Gateway::open_for_test(&path).unwrap();
        let loaded = gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap();
        let original_bytes = if scenario == "receipt" {
            Some(Gateway::read_loaded_receipt(loaded).unwrap().0)
        } else {
            assert_eq!(loaded.state(), OperationState::ReceiverObserved);
            None
        };
        gateway
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &[63; 32],
                    key_id: "after-restart",
                },
            )
            .unwrap();
        assert_eq!(
            gateway
                .journal
                .receipt_statement(&request.operation_id)
                .unwrap(),
            frozen
        );
        if let Some(original_bytes) = original_bytes {
            let loaded = gateway
                .journal
                .operation(&request.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                Gateway::read_loaded_receipt(loaded).unwrap().0,
                original_bytes
            );
        }
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
