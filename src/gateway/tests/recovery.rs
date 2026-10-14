use super::*;

#[test]
#[ignore = "invoked only as a subprocess by process-kill recovery tests"]
fn process_kill_child() {
    let scenario = std::env::var("KAPSEL_PROCESS_CHILD_SCENARIO").unwrap();
    let database = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_DATABASE").unwrap());
    let ready = PathBuf::from(std::env::var_os("KAPSEL_PROCESS_READY").unwrap());
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
