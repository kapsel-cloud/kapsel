    #[tokio::test]
    async fn missing_receipt_written_destination_is_rewritten_with_exact_bytes() {
        let path = database_path("receipt-missing-rewrite");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [23_u8; 32];
        let request = request();
        let reference = {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_receipt_once_with_fault(
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "kap0038-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptWrittenCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            gateway
                .receipt_reference(&request.operation_id)
                .unwrap()
                .unwrap()
        };
        let exact = publication::read_receipt(&reference.path).unwrap();
        fs::remove_file(&reference.path).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "kap0038-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(publication::read_receipt(&reference.path).unwrap(), exact);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_utf8_output_path_is_rejected_before_receipt_storage() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = database_path("receipt-non-utf8");
        let output_directory = path
            .parent()
            .unwrap()
            .join(OsString::from_vec(b"receipts-\xff".to_vec()));
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        gateway
            .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
            .await
            .unwrap();

        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[24_u8; 32],
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::ReceiptPublication)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert!(!output_directory.exists());
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
