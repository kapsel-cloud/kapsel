    #[test]
    fn legacy_self_asserted_authorization_migrates_idempotently_but_fails_closed() {
        let path = database_path("receipt-schema-migration");
        let request = request();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE kubernetes_image_operations (
                    operation_id TEXT PRIMARY KEY NOT NULL,
                    namespace TEXT NOT NULL,
                    deployment TEXT NOT NULL,
                    container TEXT NOT NULL,
                    immutable_image_digest TEXT NOT NULL,
                    authorization_id TEXT,
                    state TEXT NOT NULL,
                    write_strategy TEXT,
                    apply_attempted INTEGER NOT NULL DEFAULT 0,
                    target_uid TEXT,
                    target_resource_version TEXT,
                    apply_accepted INTEGER,
                    requested_generation INTEGER,
                    apply_resource_version TEXT,
                    receiver_uid TEXT,
                    receiver_image TEXT,
                    receiver_operation_marker TEXT,
                    current_generation INTEGER,
                    observed_generation INTEGER,
                    receiver_resource_version TEXT,
                    desired_replicas INTEGER,
                    updated_replicas INTEGER,
                    available_replicas INTEGER,
                    unavailable_replicas INTEGER,
                    available_condition INTEGER,
                    progress_deadline_exceeded INTEGER,
                    result TEXT
                ) STRICT;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container, immutable_image_digest,
                    authorization_id, state, write_strategy, apply_attempted, target_uid,
                    target_resource_version, requested_generation, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, observed_generation,
                    receiver_resource_version, progress_deadline_exceeded, result
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'auth-001', 'receiver_observed', ?6, 1,
                           'deployment-uid-1', 'resource-version-0', NULL, 'deployment-uid-1',
                           ?5, ?1, 2, 2, 'resource-version-2', 1, 'FAILED')",
                params![
                    request.operation_id,
                    request.namespace,
                    request.deployment,
                    request.container,
                    request.immutable_image_digest,
                    WRITE_STRATEGY,
                ],
            )
            .unwrap();
        drop(connection);

        drop(Gateway::open_for_test(&path).unwrap());
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway.journal.receipt_statement(&request.operation_id),
            Err(GatewayError::InvalidPersistedState)
        ));
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[22_u8; 32],
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(fs::read_dir(output_directory).unwrap().count(), 0);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
