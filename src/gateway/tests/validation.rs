//! Admission boundaries and shared SQLite capacity, without another lifecycle scenario world.
use std::sync::Barrier;

use super::{
    journal::{Journal, LoadedOperation},
    *,
};

#[test]
fn every_authority_field_is_bound_before_first_or_requested_admission() {
    for requested in [false, true] {
        let path = database_path(&format!("authority-fields-{requested}"));
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let exact = authorization(&request);
        if requested {
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &request,
                    &exact,
                    Some(FaultPoint::RequestedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
        }
        let original = super::storage::stored_rows(&gateway.journal.connection);
        for field in 0..5 {
            let mut changed = exact.clone();
            let value = match field {
                0 => &mut changed.operation_id,
                1 => &mut changed.namespace,
                2 => &mut changed.deployment,
                3 => &mut changed.container,
                _ => &mut changed.immutable_image_digest,
            };
            *value = if field == 4 {
                format!("other/api@sha256:{}", "0".repeat(64))
            } else {
                "other".into()
            };
            assert!(matches!(
                gateway.submit_exact_for_test(&request, &changed),
                Err(GatewayError::AuthorizationMismatch)
            ));
            assert_eq!(
                super::storage::stored_rows(&gateway.journal.connection),
                original
            );
        }
        let grant = sign_authorization_grant(&exact, &[99; 32], "unappointed").unwrap();
        for bytes in [grant, b"malformed".to_vec()] {
            assert!(gateway.submit_authorized(&request, &bytes).is_err());
            assert_eq!(
                super::storage::stored_rows(&gateway.journal.connection),
                original
            );
        }
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn malformed_requests_preserve_field_errors_and_do_not_insert() {
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
        assert!(matches!(gateway.submit_exact_for_test(&invalid, &exact),
            Err(GatewayError::InvalidInput(actual)) if actual == field));
        assert!(super::storage::stored_rows(&gateway.journal.connection).is_empty());
    }
    let mut mutable = request();
    mutable.immutable_image_digest = "example/api:latest".into();
    assert!(matches!(
        gateway.submit_exact_for_test(&mutable, &authorization(&mutable)),
        Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
    ));
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn history_bounds_raw_id_bytes_before_copying_corrupted_text() {
    let path = database_path("history-nul-id");
    let gateway = Gateway::open_for_test(&path).unwrap();
    let request = request();
    gateway
        .submit_exact_for_test(&request, &authorization(&request))
        .unwrap();
    gateway
        .journal
        .connection
        .execute(
            "UPDATE kubernetes_image_operations SET operation_id = ?1",
            [format!("a\0{}", "x".repeat(4096))],
        )
        .unwrap();
    assert!(matches!(
        gateway.journal.history_ids(None),
        Err(GatewayError::Database(rusqlite::Error::InvalidColumnType(
            0,
            _,
            rusqlite::types::Type::Null,
        )))
    ));
    drop(gateway);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keep last-slot contention, original-row checks and slot-release ordering together"
)]
fn both_capacity_limits_serialize_the_last_slot_and_preserve_existing_identity() {
    for terminal in [false, true] {
        let limit = if terminal {
            journal::capacity::IDENTITY_CAPACITY
        } else {
            journal::capacity::UNFINISHED_CAPACITY
        };
        let path = database_path(&format!("last-slot-{terminal}"));
        let setup = Gateway::open_for_test(&path).unwrap();
        for n in 0..limit - 1 {
            let mut operation = request();
            operation.operation_id = format!("existing-{n}");
            setup
                .submit_exact_for_test(&operation, &authorization(&operation))
                .unwrap();
            if terminal {
                let Some(LoadedOperation::Authorized(authorized)) =
                    setup.journal.operation(&operation.operation_id).unwrap()
                else {
                    unreachable!()
                };
                setup
                    .journal
                    .mark_not_attempted(&authorized, TargetRejection::DeploymentNotFound)
                    .unwrap();
            }
        }
        let original = super::storage::stored_rows(&setup.journal.connection);
        drop(setup);
        let barrier = Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let threads = ["last-a", "last-b"].map(|id| {
                let gateway = Gateway::open_for_test(&path).unwrap();
                gateway
                    .journal
                    .connection
                    .busy_timeout(Duration::from_secs(5))
                    .unwrap();
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
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(SubmissionResult::Created)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(GatewayError::JournalFull)))
                .count(),
            1
        );
        let gateway = Gateway::open_for_test(&path).unwrap();
        let retained = super::storage::stored_rows(&gateway.journal.connection);
        assert_eq!(retained.len(), usize::try_from(limit).unwrap());
        for (id, row) in original {
            assert_eq!(retained.get(&id), Some(&row));
        }
        let mut existing = request();
        existing.operation_id = "existing-0".into();
        let expected = if terminal {
            OperationState::NotAttempted
        } else {
            OperationState::Authorized
        };
        assert_eq!(
            gateway
                .submit_exact_for_test(&existing, &authorization(&existing))
                .unwrap(),
            SubmissionResult::Existing(expected)
        );
        let mut next = request();
        next.operation_id = "next".into();
        assert!(matches!(
            gateway.submit_exact_for_test(&next, &authorization(&next)),
            Err(GatewayError::JournalFull)
        ));
        if !terminal {
            let Some(LoadedOperation::Authorized(authorized)) =
                gateway.journal.operation(&existing.operation_id).unwrap()
            else {
                unreachable!()
            };
            gateway
                .journal
                .mark_not_attempted(&authorized, TargetRejection::DeploymentNotFound)
                .unwrap();
            gateway
                .submit_exact_for_test(&next, &authorization(&next))
                .unwrap();
        }
        drop(gateway);
        Journal::validate_replacement(&path, &[]).unwrap();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
