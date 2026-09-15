    #[test]
    fn first_commit_retains_exact_grant_and_rejects_changed_custody() {
        let path = database_path("retained-grant");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let signed = sign_authorization_grant(
            &authorization(&request),
            &[7_u8; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        assert!(matches!(
            gateway.submit_authorized_with_fault(
                &request,
                &signed,
                Some(FaultPoint::RequestedCommitted),
            ),
            Err(GatewayError::InjectedFault)
        ));
        let stored: Vec<u8> = gateway.journal.connection.query_row(
            "SELECT signed_authorization_grant FROM kubernetes_image_operations
             WHERE operation_id = ?1",
            [&request.operation_id],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(stored, signed);
        assert_eq!(gateway.get(&request.operation_id).unwrap(), Some(OperationState::Requested));
        gateway.journal.connection.execute(
            "UPDATE kubernetes_image_operations SET signed_authorization_grant = ?1
             WHERE operation_id = ?2",
            params![b"changed".as_slice(), request.operation_id],
        ).unwrap();
        assert!(matches!(
            gateway.submit_authorized(&request, &signed),
            Err(GatewayError::OperationIdentityConflict)
        ));
        assert_eq!(gateway.get(&request.operation_id).unwrap(), Some(OperationState::Requested));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn history_bounds_bytes_before_copying_corrupted_text_ids() {
        let path = database_path("history-nul-id");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        gateway.submit_exact_for_test(&request, &authorization(&request)).unwrap();
        let corrupt_id = format!("a\0{}", "x".repeat(4096));
        Connection::open(&path).unwrap().execute(
            "UPDATE kubernetes_image_operations SET operation_id = ?1",
            [&corrupt_id],
        ).unwrap();
        // Test the SQL projection, before gateway grammar validation could hide an oversized copy.
        assert!(matches!(
            gateway.journal.history_ids(None),
            Err(GatewayError::Database(rusqlite::Error::InvalidColumnType(
                0, _, rusqlite::types::Type::Null,
            ))),
        ));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn retained_history_uses_external_trust_and_isolates_missing_keys() {
        let path = database_path("retained-trust-isolation");
        let key = |id: &str, seed: u8| AuthorizationTrust {
            key_id: id.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key().to_bytes(),
        };
        let gateway = Gateway::open_with_authorities(
            &path, vec![key("a", 7), key("b", 8)],
        ).unwrap();
        for (id, seed) in [("a", 7), ("b", 8)] {
            let mut operation = request();
            operation.operation_id = id.into();
            let signed = sign_authorization_grant(
                &authorization(&operation), &[seed; 32], id,
            ).unwrap();
            gateway.submit_authorized(&operation, &signed).unwrap();
            let retained = gateway.retained_operation(id).unwrap().unwrap();
            assert_eq!(retained.request, operation);
            assert_eq!(retained.signed_grant, signed);
            assert_eq!(retained.operation.state(), OperationState::Authorized);
        }
        drop(gateway);
        let gateway = Gateway::open_with_authorities(&path, vec![key("b", 8)]).unwrap();
        assert!(matches!(
            gateway.retained_operation("a"), Err(GatewayError::UntrustedAuthorizationGrant),
        ));
        assert_eq!(gateway.retained_operation("b").unwrap().unwrap().request.operation_id, "b");
        assert!(gateway.retained_operation("absent").unwrap().is_none());
        drop(gateway);
        let gateway = Gateway::open_with_authorities(&path, Vec::new()).unwrap();
        assert!(matches!(
            gateway.retained_operation("b"), Err(GatewayError::UntrustedAuthorizationGrant),
        ));
        drop(gateway);
        let gateway = Gateway::open_with_authorities(
            &path, vec![key("a", 7), key("b", 8)],
        ).unwrap();
        assert!(gateway.retained_operation("a").unwrap().is_some());
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

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
        let request = request();
        let exact = authorization(&request);
        let mismatches = [
            {
                let mut value = exact.clone();
                value.operation_id = "other-operation".into();
                ("operation_id", value)
            },
            {
                let mut value = exact.clone();
                value.namespace = "other".into();
                ("namespace", value)
            },
            {
                let mut value = exact.clone();
                value.deployment = "other-api".into();
                ("deployment", value)
            },
            {
                let mut value = exact.clone();
                value.container = "other".into();
                ("container", value)
            },
            {
                let mut value = exact;
                value.immutable_image_digest = concat!(
                    "registry.example/example/other-api@sha256:",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                )
                .into();
                ("immutable_image_digest", value)
            },
        ];

        for (field, mismatched) in mismatches {
            let path = database_path(&format!("authorization-mismatch-{field}"));
            let gateway = Gateway::open_for_test(&path).unwrap();
            assert!(
                matches!(
                    gateway.submit_exact_for_test(&request, &mismatched),
                    Err(GatewayError::AuthorizationMismatch)
                ),
                "{field}"
            );
            assert_eq!(gateway.get(&request.operation_id).unwrap(), None, "{field}");

            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &request,
                    &authorization(&request),
                    Some(FaultPoint::RequestedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &mismatched),
                Err(GatewayError::AuthorizationMismatch)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::Requested),
                "{field}"
            );
            drop(gateway);
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn requested_phase_cannot_be_authorized_with_another_bound_operation() {
        let path = database_path("requested-bound-authorization-mismatch");
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        assert!(matches!(
            gateway.submit_exact_with_fault_for_test(
                &request,
                &authorization(&request),
                Some(FaultPoint::RequestedCommitted),
            ),
            Err(GatewayError::InjectedFault)
        ));
        let loaded = gateway.journal.operation(&request.operation_id).unwrap();
        assert!(matches!(loaded, Some(journal::LoadedOperation::Requested(_))));
        let Some(journal::LoadedOperation::Requested(requested)) = loaded else {
            return;
        };

        let mut other = request.clone();
        other.operation_id = "other-operation".into();
        let signed = sign_authorization_grant(
            &authorization(&other),
            &[7_u8; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        let verified = verify_authorization_grant(
            &signed, &gateway.authorization_trust[0],
        ).unwrap();
        let authorized = AuthorizedRequest::bind(
            ValidatedRequest::try_from(&other).unwrap(),
            verified,
        )
        .unwrap();

        assert!(matches!(
            gateway.journal.mark_authorized(&requested, &authorized),
            Err(GatewayError::InvalidTransition)
        ));
        assert!(matches!(
            gateway.journal.operation(&request.operation_id).unwrap(),
            Some(journal::LoadedOperation::Requested(_))
        ));
        assert_eq!(gateway.get(&other.operation_id).unwrap(), None);

        drop(gateway);
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
    fn shared_grammar_errors_preserve_field_classification_before_persistence() {
        let path = database_path("input-projection");
        let gateway = Gateway::open_for_test(&path).unwrap();
        for field in [
            InputField::OperationId,
            InputField::Namespace,
            InputField::Deployment,
            InputField::Container,
            InputField::ImmutableImageDigest,
            InputField::AuthorizationId,
        ] {
            let mut invalid = request();
            let mut exact = authorization(&invalid);
            let value = match field {
                InputField::OperationId => &mut invalid.operation_id,
                InputField::Namespace => &mut invalid.namespace,
                InputField::Deployment => &mut invalid.deployment,
                InputField::Container => &mut invalid.container,
                InputField::ImmutableImageDigest => &mut invalid.immutable_image_digest,
                InputField::AuthorizationId => &mut exact.authorization_id,
            };
            value.clear();
            assert!(matches!(
                gateway.submit_exact_for_test(&invalid, &exact),
                Err(GatewayError::InvalidInput(actual)) if actual == field
            ));
            assert_eq!(gateway.get(&invalid.operation_id).unwrap(), None);
        }
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
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
                            authorization_signer_key_id, authorization_grant_digest, state,
                            signed_authorization_grant, target_rejection
                         ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                                   'not_attempted', ?6, 'deployment_not_found')",
                    )
                    .unwrap();
                for index in 0..journal::capacity::IDENTITY_CAPACITY {
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
                            signed,
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
            SubmissionResult::Existing(OperationState::NotAttempted)
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
    fn unfinished_capacity_preserves_duplicates_and_releases_only_terminal_slots() {
        let path = database_path("unfinished-capacity");
        let gateway = Gateway::open_for_test(&path).unwrap();
        for index in 0..journal::capacity::UNFINISHED_CAPACITY {
            let mut operation = request();
            operation.operation_id = format!("unfinished-{index}");
            gateway.submit_exact_for_test(&operation, &authorization(&operation)).unwrap();
        }
        let mut existing = request();
        existing.operation_id = "unfinished-0".into();
        assert_eq!(
            gateway.submit_exact_for_test(&existing, &authorization(&existing)).unwrap(),
            SubmissionResult::Existing(OperationState::Authorized),
        );
        let mut next = request();
        next.operation_id = "next".into();
        assert!(matches!(
            gateway.submit_exact_for_test(&next, &authorization(&next)),
            Err(GatewayError::JournalFull)
        ));
        let loaded = gateway.journal.operation(&existing.operation_id).unwrap().unwrap();
        assert_eq!(loaded.state(), OperationState::Authorized);
        if let LoadedOperation::Authorized(operation) = loaded {
            gateway.journal.mark_not_attempted(
                &operation, TargetRejection::DeploymentNotFound,
            ).unwrap();
        }
        gateway.submit_exact_for_test(&next, &authorization(&next)).unwrap();
        drop(gateway);
        let reopened = Gateway::open_for_test(&path).unwrap();
        assert_eq!(reopened.get("next").unwrap(), Some(OperationState::Authorized));
        assert_eq!(reopened.get("unfinished-0").unwrap(), Some(OperationState::NotAttempted));
        drop(reopened);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn concurrent_submissions_at_31_unfinished_preserve_original_authority() {
        use std::sync::Barrier;

        let path = database_path("unfinished-concurrent-last-slot");
        let setup = Gateway::open_for_test(&path).unwrap();
        for index in 0..31 {
            let mut operation = request();
            operation.operation_id = format!("unfinished-{index}");
            setup.submit_exact_for_test(&operation, &authorization(&operation)).unwrap();
        }
        let original = super::storage::stored_rows(&setup.journal.connection);
        drop(setup);
        let barrier = Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let threads = ["last-a", "last-b"].map(|id| {
                let gateway = Gateway::open_for_test(&path).unwrap();
                gateway.journal.connection.busy_timeout(Duration::from_secs(5)).unwrap();
                let barrier = &barrier;
                scope.spawn(move || {
                    let mut operation = request();
                    operation.operation_id = id.into();
                    barrier.wait();
                    gateway.submit_exact_for_test(&operation, &authorization(&operation))
                })
            });
            threads.map(|thread| thread.join().unwrap())
        });
        assert_eq!(results.iter().filter(|result| matches!(result,
            Ok(SubmissionResult::Created))).count(), 1);
        assert_eq!(results.iter().filter(|result| matches!(result,
            Err(GatewayError::JournalFull))).count(), 1);
        let reopened = Gateway::open_for_test(&path).unwrap();
        let rows = super::storage::stored_rows(&reopened.journal.connection);
        assert_eq!(rows.len(), 32);
        for (id, row) in original { assert_eq!(rows.get(&id), Some(&row)); }
        drop(reopened);
        journal::Journal::validate_replacement(&path, &[]).unwrap();
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
                            immutable_image_digest, state, target_rejection
                         ) VALUES (?1, 'demo', 'agent-api', 'api', ?2,
                                   'not_attempted', 'deployment_not_found')",
                    )
                    .unwrap();
                for index in 0..journal::capacity::IDENTITY_CAPACITY - 1 {
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
            journal::capacity::IDENTITY_CAPACITY
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
