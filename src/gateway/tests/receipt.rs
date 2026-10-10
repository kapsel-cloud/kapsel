use super::*;

#[tokio::test]
async fn maximal_request_fields_complete_a_bounded_durable_receipt() {
    let path = database_path("maximal-request-receipt");
    let request = SetDeploymentImageRequest {
        operation_id: "o".repeat(128),
        namespace: "n".repeat(63),
        deployment: format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        ),
        container: "c".repeat(63),
        immutable_image_digest: format!("{}@sha256:{}", "i".repeat(440), "0".repeat(64)),
    };
    let mut authorization = authorization(&request);
    authorization.authorization_id = "a".repeat(128);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization)
        .unwrap();
    let mut adapter = failed_adapter(&path, &request);
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(
        gateway
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &[13_u8; 32],
                    key_id: "maximal-request-receipt-key",
                }
            )
            .unwrap(),
        Some(OperationState::Finalized)
    );
    let receipt = Gateway::read_loaded_receipt(
        gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .0;
    assert!(receipt.len() <= receipt::RECEIPT_BYTES_MAX);
    drop(gateway);
    let reopened = Gateway::open_for_test(&path).unwrap();
    assert_eq!(
        Gateway::read_loaded_receipt(
            reopened
                .journal
                .operation(&request.operation_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .0,
        receipt
    );
    drop(reopened);
    for suffix in ["-journal", "-wal", "-shm"] {
        assert!(!PathBuf::from(format!("{}{suffix}", path.display())).exists());
    }
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

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
async fn receipt_statement_retains_exact_available_condition_reason() {
    let path = database_path("receipt-available-reason");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    let mut adapter = failed_adapter(&path, &request);
    adapter.observation.updated_replicas = Some(1);
    adapter.observation.available_replicas = Some(1);
    adapter.observation.unavailable_replicas = Some(0);
    adapter.observation.rollout_condition_type = Some("Available".into());
    adapter.observation.rollout_condition_status = Some("True".into());
    adapter.observation.rollout_condition_reason = Some("DifferentObservedReason".into());
    gateway
        .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
        .await
        .unwrap();

    let statement = gateway
        .journal
        .receipt_statement(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(statement.result(), OperationResult::Succeeded);
    assert_eq!(
        statement.rollout_condition_reason(),
        Some("DifferentObservedReason")
    );
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn receipt_inspection_reports_frozen_failed_receiver_facts() {
    let path = database_path("receipt-first-tracer");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    let mut adapter = failed_adapter(&path, &request);
    assert_eq!(
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap(),
        Some(OperationState::ReceiverObserved)
    );

    let statement = gateway
        .journal
        .receipt_statement(&request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(statement.operation_id, request.operation_id);
    assert_eq!(statement.authorization_id, "auth-001");
    assert_eq!(
        statement.authorization_signer_key_id(),
        "effect-gateway-authorization-test-key"
    );
    assert_eq!(statement.authorization_grant_digest().len(), 64);
    assert_eq!(statement.write_strategy(), WRITE_STRATEGY);
    assert_eq!(statement.target_uid(), "deployment-uid-1");
    assert_eq!(statement.target_resource_version(), "resource-version-0");
    assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
    assert_eq!(
        statement.observed_image(),
        Some(request.immutable_image_digest.as_str())
    );
    assert_eq!(statement.observed_operation_marker(), Some("op-001"));
    assert_eq!(statement.current_generation(), Some(2));
    assert_eq!(statement.requested_generation(), Some(2));
    assert_eq!(statement.observed_generation(), Some(2));
    assert_eq!(statement.desired_replicas(), Some(1));
    assert_eq!(statement.updated_replicas(), Some(0));
    assert_eq!(statement.available_replicas(), Some(0));
    assert_eq!(statement.unavailable_replicas(), Some(1));
    assert_eq!(statement.result, OperationResult::Failed);
    assert_eq!(
        statement.rollout_condition_reason.as_deref(),
        Some("ProgressDeadlineExceeded")
    );

    let seed = [7_u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let trust = ReceiptTrust {
        key_id: "effect-gateway-test-key".into(),
        public_key: signing_key.verifying_key().to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap();
    let receipt = sign_statement(&statement, &seed, "effect-gateway-test-key").unwrap();
    let report = inspect_receipt(&receipt, &trust, 150, InspectionLimits::default());

    assert_eq!(report.status(), InspectionStatus::Inspected);
    assert_eq!(report.statement(), Some(&statement));
    assert_eq!(report.non_claims(), Some(statement.non_claims()));
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn hostile_receipt_inputs_fail_closed_without_verified_vocabulary() {
    let statement = ReceiptStatement {
        approved_target: None,
        operation_id: "op-001".into(),
        authorization_id: "auth-001".into(),
        authorization_signer_key_id: "effect-gateway-authorization-test-key".into(),
        authorization_grant_digest: "0".repeat(64),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: request().immutable_image_digest,
        write_strategy: WRITE_STRATEGY.into(),
        target_uid: "deployment-uid-1".into(),
        target_resource_version: "resource-version-0".into(),
        receiver_uid: Some("deployment-uid-1".into()),
        observed_image: Some(request().immutable_image_digest),
        observed_operation_marker: Some("op-001".into()),
        current_generation: Some(2),
        requested_generation: Some(2),
        observed_generation: Some(2),
        observed_resource_version: Some("resource-version-2".into()),
        desired_replicas: Some(1),
        updated_replicas: Some(0),
        available_replicas: Some(0),
        unavailable_replicas: Some(1),
        rollout_condition_type: Some("Progressing".into()),
        rollout_condition_status: Some("False".into()),
        rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
        result: OperationResult::Failed,
    };
    let seed = [8_u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let trust = ReceiptTrust {
        key_id: "effect-gateway-test-key".into(),
        public_key: signing_key.verifying_key().to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap();
    let receipt = sign_statement(&statement, &seed, "effect-gateway-test-key").unwrap();

    let mut malformed = receipt.clone();
    malformed[0] = b'X';
    assert_eq!(
        inspect_receipt(&malformed, &trust, 150, InspectionLimits::default()).status(),
        InspectionStatus::StructureRejected
    );

    let mut bad_signature = receipt.clone();
    let last = bad_signature.last_mut().unwrap();
    *last ^= 1;
    assert_eq!(
        inspect_receipt(&bad_signature, &trust, 150, InspectionLimits::default()).status(),
        InspectionStatus::SignatureRejected
    );

    assert_eq!(
        inspect_receipt(&receipt, &trust, 250, InspectionLimits::default()).status(),
        InspectionStatus::UntrustedSigner
    );
    assert!(!format!(
        "{:?}{:?}{:?}{:?}",
        InspectionStatus::StructureRejected,
        InspectionStatus::SignatureRejected,
        InspectionStatus::UntrustedSigner,
        InspectionStatus::Inspected
    )
    .contains("Verified"));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::panic,
    reason = "one controlled fixture trace compares rejected candidates and original evidence"
)]
async fn receipt_commit_rejects_wrong_facts_and_foreign_snapshot_without_changing_history() {
    let path = database_path("receipt-facts-binding");
    let foreign_path = database_path("receipt-foreign-binding");
    let request = request();
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    let mut foreign = Gateway::open_for_test(&foreign_path).unwrap();
    for (owner, owner_path, reason) in [
        (&mut gateway, &path, "original-reason"),
        (&mut foreign, &foreign_path, "foreign-reason"),
    ] {
        owner
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(owner_path, &request);
        adapter.observation.rollout_condition_reason = Some(reason.into());
        owner
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap();
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (1, 1));
    }
    let original = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    let journal::LoadedOperation::ReceiverObserved(operation) = original.clone() else {
        panic!("fixture must have frozen facts");
    };
    let journal::LoadedOperation::ReceiverObserved(foreign_operation) = foreign
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap()
    else {
        panic!("foreign fixture must have frozen facts");
    };
    let retained_grant = || {
        gateway
            .journal
            .connection
            .query_row(
                "SELECT signed_authorization_grant FROM kubernetes_image_operations
             WHERE operation_id = ?1",
                [&request.operation_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
    };
    let grant = retained_grant();
    let settings = ReceiptSettings {
        signing_seed: &[71; 32],
        key_id: "original-key",
    };
    let foreign_candidate = Gateway::build_receipt(&foreign_operation, &settings).unwrap();
    // The current snapshot cannot legitimize same-ID bytes for different receiver facts.
    assert!(matches!(
        gateway
            .journal
            .commit_receipt(&operation, &foreign_candidate),
        Err(GatewayError::InvalidPersistedState)
    ));
    // Nor can the foreign snapshot and its matching candidate substitute the frozen row.
    assert!(matches!(
        gateway
            .journal
            .commit_receipt(&foreign_operation, &foreign_candidate),
        Err(GatewayError::InvalidTransition)
    ));
    assert_eq!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(original)
    );
    assert_eq!(retained_grant(), grant);

    let candidate = Gateway::build_receipt(&operation, &settings).unwrap();
    gateway
        .journal
        .commit_receipt(&operation, &candidate)
        .unwrap();
    let finalized = gateway
        .journal
        .operation(&request.operation_id)
        .unwrap()
        .unwrap();
    let evidence = Gateway::read_loaded_receipt(finalized.clone()).unwrap();
    assert!(matches!(
        gateway
            .journal
            .commit_receipt(&operation, &foreign_candidate),
        Err(GatewayError::InvalidTransition)
    ));
    assert_eq!(
        gateway.journal.operation(&request.operation_id).unwrap(),
        Some(finalized)
    );
    assert_eq!(
        Gateway::read_loaded_receipt(
            gateway
                .journal
                .operation(&request.operation_id)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        evidence
    );
    assert_eq!(retained_grant(), grant);
    drop(gateway);
    drop(foreign);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
    fs::remove_dir_all(foreign_path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn finalizer_contender_changes_no_durable_or_public_fact() {
    let path = database_path("receipt-finalizer-lock");
    let output_directory = path.parent().unwrap().join("receipts");
    private_directory(&output_directory);
    let output_directory = fs::canonicalize(output_directory).unwrap();
    let seed = [21_u8; 32];
    let request = request();
    let mut first = Gateway::open_for_test(&path).unwrap();
    first
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    first
        .run_operation_once_with_adapter(
            &request.operation_id,
            &mut failed_adapter(&path, &request),
        )
        .await
        .unwrap();
    let worker_lock = first.journal.try_lock_worker().unwrap().unwrap();
    let contender = Gateway::open_for_test(&path).unwrap();

    assert_eq!(
        contender
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                }
            )
            .unwrap(),
        None
    );
    assert_eq!(
        contender.get(&request.operation_id).unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 0);

    drop(worker_lock);
    assert_eq!(
        contender
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                }
            )
            .unwrap(),
        Some(OperationState::Finalized)
    );
    drop(contender);
    drop(first);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
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
        let mut adapter = failed_adapter(&path, &request);
        gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await
            .unwrap();
        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap();
        drop(gateway);
        let ready = path.parent().unwrap().join("ready");
        let mut child = spawn_process_child(scenario, &path, &ready, None, None);
        wait_for_child_seam(&mut child, &ready);
        kill_child(&mut child);
        let gateway = Gateway::open_for_test(&path).unwrap();
        let old = gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap();
        let old_bytes = if scenario == "receipt" {
            Some(Gateway::read_loaded_receipt(old).unwrap().0)
        } else {
            assert_eq!(old.state(), OperationState::ReceiverObserved);
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
        let (bytes, _) = Gateway::read_loaded_receipt(
            gateway
                .journal
                .operation(&request.operation_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        if let Some(old) = old_bytes {
            assert_eq!(bytes, old);
        }
        assert_eq!(
            gateway
                .journal
                .receipt_statement(&request.operation_id)
                .unwrap(),
            statement
        );
        assert_eq!(adapter.apply_calls, 1);
        assert_eq!(adapter.observe_calls, 1);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
