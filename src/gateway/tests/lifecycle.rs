//! Admission acknowledgement is a mechanical boundary, not a predicted lifecycle.
use super::*;

#[test]
fn receipt_completion_waits_for_the_other_journal_worker_lease() {
    let scratch = journal::test_history::Scratch::new();
    let path = scratch.0.join("journal.sqlite3");
    let owner = Gateway::open(&path, journal::test_history::trust()).unwrap();
    History::kube("receipt-lease").insert(&owner.journal.connection, "receiver_observed");
    let contender = Gateway::open(&path, journal::test_history::trust()).unwrap();
    let before = stored_rows(&owner.journal.connection);
    let worker = owner.journal.try_lock_worker().unwrap().unwrap();
    let settings = ReceiptSettings {
        signing_seed: &[9; 32],
        key_id: "snapshot-receipt-key",
    };
    assert_eq!(
        contender
            .finalize_operation_receipt_once("receipt-lease", &settings)
            .unwrap(),
        None
    );
    assert_eq!(stored_rows(&contender.journal.connection), before);
    drop(worker);
    assert!(contender
        .finalize_operation_receipt_once("receipt-lease", &settings)
        .unwrap()
        .is_some());
}

#[test]
fn admission_acknowledges_only_confirmed_responsibility_or_definite_refusal() {
    for committed in [false, true] {
        let path = database_path(&format!("admission-{committed}"));
        let gateway = Gateway::open_for_test(&path).unwrap();
        let request = request();
        let grant = sign_authorization_grant(
            &authorization(&request),
            &[7; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        let bound = gateway.bind_authorization(&request, &grant).unwrap();
        let mut acknowledged = false;
        let result = gateway.admit_service_operation(
            None,
            |journal, worker| {
                assert!(journal.owns_worker(worker));
                if committed {
                    journal.insert_requested(&bound)?;
                }
                Err(GatewayError::InjectedFault)
            },
            |_| acknowledged = true,
        );
        assert!(matches!(result, Err(ReconciliationError::Submission(_))));
        assert!(!acknowledged);
        assert_eq!(
            gateway.journal.existing_submission(&bound).unwrap(),
            committed.then_some(OperationState::Requested)
        );
        assert!(gateway.journal.try_lock_worker().unwrap().is_some());

        let mut decision = None;
        gateway
            .admit_service_operation(
                None,
                |_, _| Err(GatewayError::JournalFull),
                |actual| decision = Some(actual),
            )
            .unwrap();
        assert!(matches!(decision, Some(AdmissionDecision::Full)));
        let worker = gateway.journal.try_lock_worker().unwrap().unwrap();
        for terminal in [OperationState::Finalized, OperationState::NotAttempted] {
            gateway
                .admit_service_operation(
                    Some(terminal),
                    |_, _| Err(GatewayError::InjectedFault),
                    |actual| {
                        assert!(matches!(actual, AdmissionDecision::Admitted(s) if s == terminal));
                    },
                )
                .unwrap();
        }
        drop(worker);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
