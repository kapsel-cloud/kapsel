use super::*;

#[test]
#[ignore = "invoked only as a subprocess by process-kill recovery tests"]
fn process_kill_child() {
    let scenario = std::env::var("KAPSEL_PROCESS_CHILD_SCENARIO").unwrap();
    let database = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_DATABASE").unwrap());
    let ready = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_READY").unwrap());
    if scenario == "mutation" {
        let patch_count = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_PATCH_COUNT").unwrap());
        let mut gateway = Gateway::open_for_test(&database).unwrap();

        let mut adapter = ProcessMutationAdapter {
            ready_path: ready,
            patch_count_path: patch_count,
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(gateway.run_operation_once_with_adapter_and_fault(
                "op-001",
                &mut adapter,
                None,
            ))
            .unwrap();
        unreachable!("the parent must kill the child while apply is pending");
    }
    if scenario == "hot_rollback" {
        // Opening must recover genuinely hot history, not only an unused zero-header journal.
        // This external fixture spills an uncommitted edit; owned writes still disable spilling.
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;
             PRAGMA cache_spill=ON; PRAGMA cache_size=1; BEGIN IMMEDIATE;
             UPDATE kubernetes_image_operations SET receipt_bytes=zeroblob(16384)
             WHERE operation_id='op-001'",
            )
            .unwrap();
        connection.cache_flush().unwrap();
        fs::write(ready, b"hot-rollback-before-commit").unwrap();
        loop {
            std::thread::park();
        }
    }
    assert!(matches!(
        scenario.as_str(),
        "receipt" | "before_receipt_commit" | "receipt_sql_executed"
    ));
    if scenario == "receipt_sql_executed" {
        super::storage::park_receipt_after_sql(ready.clone());
    }
    let gateway = Gateway::open_for_test(&database).unwrap();
    assert!(matches!(
        gateway.finalize_operation_receipt_once_with_fault(
            "op-001",
            &ReceiptSettings {
                signing_seed: &[31_u8; 32],
                key_id: "process-receipt-key",
            },
            match scenario.as_str() {
                "receipt" => Some(FaultPoint::FinalizedCommitted),
                "before_receipt_commit" => Some(FaultPoint::BeforeReceiptCommit),
                _ => None,
            },
        ),
        Err(GatewayError::InjectedFault)
    ));
    fs::write(ready, b"receipt-commit-seam").unwrap();
    loop {
        std::thread::park();
    }
}

#[tokio::test]
async fn process_kill_after_provider_side_effect_recovers_without_second_mutation() {
    let path = database_path("process-kill-mutation");
    let request = request();
    {
        let gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
    }
    let ready = path.parent().unwrap().join("mutation-ready");
    let patch_count = path.parent().unwrap().join("patch-count");
    let mut child = spawn_process_child("mutation", &path, &ready, Some(&patch_count));
    wait_for_child_seam(&mut child, &ready);
    assert_eq!(fs::read_to_string(&patch_count).unwrap(), "1");
    kill_child(&mut child);

    let mut gateway = Gateway::open_for_test(&path).unwrap();
    assert_eq!(
        gateway.get(&request.operation_id).unwrap(),
        Some(OperationState::ApplyStarted)
    );
    let mut recovery_adapter = failed_rollout_adapter(&path, &request);
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut recovery_adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(recovery_adapter.identify_calls, 0);
    assert_eq!(recovery_adapter.apply_calls, 0);
    assert_eq!(recovery_adapter.observe_calls, 1);
    assert_eq!(fs::read_to_string(&patch_count).unwrap(), "1");
    assert_eq!(
        gateway.result(&request.operation_id).unwrap(),
        Some(OperationResult::Failed)
    );

    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn worker_lock_prevents_overlapping_provider_activity() {
    let path = database_path("worker-lock");
    let request = request();
    let first_gateway = Gateway::open_for_test(&path).unwrap();
    first_gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    let worker_lock = first_gateway.journal.try_lock_worker().unwrap().unwrap();
    let mut second_gateway = Gateway::open_for_test(&path).unwrap();

    let mut adapter = failed_rollout_adapter(&path, &request);

    assert_eq!(
        second_gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        None
    );
    assert_eq!(adapter.identify_calls, 0);
    assert_eq!(adapter.apply_calls, 0);
    assert_eq!(adapter.observe_calls, 0);

    drop(worker_lock);
    assert_eq!(
        second_gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );

    drop(second_gateway);
    drop(first_gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
