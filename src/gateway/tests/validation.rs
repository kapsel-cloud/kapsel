    #[test]
    fn mutable_image_is_rejected_before_persistence() {
        let path = database_path("mutable-image");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let mut request = request();
        request.immutable_image_digest = "registry.example/example/agent-api:latest".into();
        let authorization = authorization(&request);

        assert!(matches!(
            gateway.submit_exact_for_test(&request, &authorization),
            Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn exact_authorization_is_required_before_persistence() {
        let path = database_path("authorization-mismatch");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let mut authorization = authorization(&request);
        authorization.container = "other".into();

        assert!(matches!(
            gateway.submit_exact_for_test(&request, &authorization),
            Err(GatewayError::AuthorizationMismatch)
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn self_signed_or_malformed_grant_fails_before_persistence() {
        let path = database_path("untrusted-grant");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let self_signed = sign_authorization_grant(
            &authorization(&request),
            &[8_u8; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        assert!(matches!(
            gateway.submit_authorized(&request, &self_signed),
            Err(GatewayError::UntrustedAuthorizationGrant)
        ));
        assert!(matches!(
            gateway.submit_authorized(&request, b"self-asserted"),
            Err(GatewayError::InvalidAuthorizationGrant)
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn exact_submission_is_idempotent_but_changed_identity_facts_conflict() {
        let path = database_path("identity");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let exact_authorization = authorization(&request);

        assert_eq!(
            gateway
                .submit_exact_for_test(&request, &exact_authorization)
                .unwrap(),
            SubmissionResult::Created
        );
        assert_eq!(
            gateway
                .submit_exact_for_test(&request, &exact_authorization)
                .unwrap(),
            SubmissionResult::Existing(OperationState::Authorized)
        );

        let mut changed = request.clone();
        changed.deployment = "other-api".into();
        let changed_authorization = authorization(&changed);
        assert!(matches!(
            gateway.submit_exact_for_test(&changed, &changed_authorization),
            Err(GatewayError::OperationIdentityConflict)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Authorized)
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn duplicate_submission_rejects_inconsistent_requested_row_without_advancing() {
        let path = database_path("inconsistent-requested-duplicate");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        gateway
            .journal
            .connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container,
                    immutable_image_digest, state, apply_attempted
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'requested', 1)",
                params![
                    request.operation_id,
                    request.namespace,
                    request.deployment,
                    request.container,
                    request.immutable_image_digest,
                ],
            )
            .unwrap();

        assert!(matches!(
            gateway.submit_exact_for_test(&request, &authorization(&request)),
            Err(GatewayError::InvalidPersistedState)
        ));
        let persisted = gateway
            .journal
            .connection
            .query_row(
                "SELECT state, apply_attempted, authorization_id
                 FROM kubernetes_image_operations WHERE operation_id = ?1",
                [&request.operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(persisted, ("requested".into(), true, None));

        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn kubernetes_names_and_identities_enforce_contract_bounds() {
        let path = database_path("input-bounds");
        let invalid_requests = [
            {
                let mut value = request();
                value.operation_id = "../outside".into();
                value
            },
            {
                let mut value = request();
                value.namespace = "Uppercase".into();
                value
            },
            {
                let mut value = request();
                value.namespace = "a".repeat(64);
                value
            },
            {
                let mut value = request();
                value.deployment = format!("{}.valid", "a".repeat(64));
                value
            },
            {
                let mut value = request();
                value.container = "-api".into();
                value
            },
        ];
        for invalid in invalid_requests {
            let gateway = Gateway::open_for_test(&path).unwrap();
            let authorization = authorization(&invalid);
            assert!(matches!(
                gateway.submit_exact_for_test(&invalid, &authorization),
                Err(GatewayError::InvalidInput(_))
            ));
            assert_eq!(gateway.get(&invalid.operation_id).unwrap(), None);
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn contract_bounds_accept_exact_maxima_and_reject_values_above_them() {
        let maximum_path = database_path("exact-maxima");
        let mut maximum = request();
        maximum.operation_id = "o".repeat(128);
        maximum.namespace = "n".repeat(63);
        maximum.deployment = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        maximum.container = "c".repeat(63);
        maximum.immutable_image_digest = format!("{}@sha256:{}", "i".repeat(440), "0".repeat(64));
        let mut maximum_authorization = authorization(&maximum);
        maximum_authorization.authorization_id = "a".repeat(128);
        let maximum_gateway = Gateway::open_for_test(&maximum_path).unwrap();
        assert_eq!(
            maximum_gateway
                .submit_exact_for_test(&maximum, &maximum_authorization)
                .unwrap(),
            SubmissionResult::Created
        );
        drop(maximum_gateway);
        fs::remove_dir_all(maximum_path.parent().unwrap()).unwrap();

        let invalid_path = database_path("above-maxima");
        let invalid_gateway = Gateway::open_for_test(&invalid_path).unwrap();
        let invalid_requests = [
            {
                let mut value = request();
                value.operation_id = "o".repeat(129);
                value
            },
            {
                let mut value = request();
                value.deployment = format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62)
                );
                value
            },
            {
                let mut value = request();
                value.container = "c".repeat(64);
                value
            },
            {
                let mut value = request();
                value.immutable_image_digest =
                    format!("{}@sha256:{}", "i".repeat(441), "0".repeat(64));
                value
            },
        ];
        for invalid in invalid_requests {
            assert!(matches!(
                invalid_gateway.submit_exact_for_test(&invalid, &authorization(&invalid)),
                Err(GatewayError::InvalidInput(_))
            ));
            assert_eq!(invalid_gateway.get(&invalid.operation_id).unwrap(), None);
        }
        let valid_request = request();
        let mut invalid_authorization = authorization(&valid_request);
        invalid_authorization.authorization_id = "a".repeat(129);
        assert!(matches!(
            invalid_gateway.submit_exact_for_test(&valid_request, &invalid_authorization),
            Err(GatewayError::InvalidInput(InputField::AuthorizationId))
        ));
        assert_eq!(
            invalid_gateway.get(&valid_request.operation_id).unwrap(),
            None
        );
        drop(invalid_gateway);
        fs::remove_dir_all(invalid_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn full_journal_preserves_existing_idempotency_and_rejects_new_identity() {
        let path = database_path("journal-capacity");
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        {
            let mut existing = request();
            existing.operation_id = "op-0".into();
            let mut existing_authorization = authorization(&existing);
            existing_authorization.authorization_id = "auth-0".into();
            let signed = sign_authorization_grant(
                &existing_authorization,
                &[7_u8; 32],
                "effect-gateway-authorization-test-key",
            )
            .unwrap();
            let existing_digest = publication::receipt_digest_hex(&signed);
            let transaction = gateway.journal.connection.transaction().unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO kubernetes_image_operations (
                            operation_id, namespace, deployment, container,
                            immutable_image_digest, authorization_id,
                            authorization_signer_key_id, authorization_grant_digest, state
                         ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                                   'authorized')",
                    )
                    .unwrap();
                for index in 0..journal::OPERATION_COUNT_MAX {
                    insert
                        .execute(params![
                            format!("op-{index}"),
                            request().immutable_image_digest,
                            format!("auth-{index}"),
                            "effect-gateway-authorization-test-key",
                            if index == 0 {
                                existing_digest.as_str()
                            } else {
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            },
                        ])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }
        let mut existing = request();
        existing.operation_id = "op-0".into();
        let mut existing_authorization = authorization(&existing);
        existing_authorization.authorization_id = "auth-0".into();
        assert_eq!(
            gateway
                .submit_exact_for_test(&existing, &existing_authorization)
                .unwrap(),
            SubmissionResult::Existing(OperationState::Authorized)
        );

        let mut overflow = request();
        overflow.operation_id = "overflow".into();
        assert!(matches!(
            gateway.submit_exact_for_test(&overflow, &authorization(&overflow)),
            Err(GatewayError::JournalFull)
        ));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn concurrent_submissions_cannot_exceed_the_operation_ceiling() {
        use std::sync::{Arc, Barrier};

        let path = database_path("journal-concurrent-capacity");
        let mut setup = Gateway::open_for_test(&path).unwrap();
        {
            let transaction = setup.journal.connection.transaction().unwrap();
            {
                let mut insert = transaction
                    .prepare(
                        "INSERT INTO kubernetes_image_operations (
                            operation_id, namespace, deployment, container,
                            immutable_image_digest, state
                         ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, 'requested')",
                    )
                    .unwrap();
                for index in 0..journal::OPERATION_COUNT_MAX - 1 {
                    insert
                        .execute(params![
                            format!("existing-{index}"),
                            request().immutable_image_digest,
                        ])
                        .unwrap();
                }
            }
            transaction.commit().unwrap();
        }
        drop(setup);

        let first = Gateway::open_for_test(&path).unwrap();
        let second = Gateway::open_for_test(&path).unwrap();
        first
            .journal
            .connection
            .busy_timeout(Duration::from_secs(5))
            .unwrap();
        second
            .journal
            .connection
            .busy_timeout(Duration::from_secs(5))
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let submit = |gateway: Gateway, operation_id: &str, barrier: Arc<Barrier>| {
            let mut request = request();
            request.operation_id = operation_id.into();
            std::thread::spawn(move || {
                barrier.wait();
                gateway.submit_exact_for_test(&request, &authorization(&request))
            })
        };
        let first = submit(first, "concurrent-a", Arc::clone(&barrier));
        let second = submit(second, "concurrent-b", barrier);
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(SubmissionResult::Created)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(GatewayError::JournalFull)))
                .count(),
            1
        );
        assert_eq!(
            Connection::open(&path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM kubernetes_image_operations",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            journal::OPERATION_COUNT_MAX
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn image_grammar_rejects_every_mutable_or_ambiguous_form() {
        let path = database_path("image-grammar");
        let invalid_images = [
            "registry.example/repo/image:tag",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            concat!(
                "registry.example/repo/image:tag@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "registry.example:5000/repo/image@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "Registry.example/repo/image@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            concat!(
                "registry.example/repo/image@sha256:",
                "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        ];
        for image in invalid_images {
            let gateway = Gateway::open_for_test(&path).unwrap();
            let mut request = request();
            request.operation_id = format!("op-{}", image.len());
            request.immutable_image_digest = image.into();
            let authorization = authorization(&request);
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &authorization),
                Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
            ));
            assert_eq!(gateway.get(&request.operation_id).unwrap(), None);
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
