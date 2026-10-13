//! Completion checks SQL-owned candidate binding; storage owns the process commitment windows.
use super::{LoadedOperation, *};

#[test]
fn receipt_commit_rejects_wrong_facts_and_foreign_snapshot_without_changing_history() {
    let paths = [
        database_path("receipt-original"),
        database_path("receipt-foreign"),
    ];
    let gateways = paths
        .each_ref()
        .map(|path| Gateway::open(path, journal::test_history::trust()).unwrap());
    let snapshots = gateways
        .iter()
        .enumerate()
        .map(|(index, gateway)| {
            let mut history = History::kube("snapshot-op");
            history.statement.available_replicas = Some(i32::try_from(index).unwrap());
            history.insert(&gateway.journal.connection, "receiver_observed");
            let Some(LoadedOperation::ReceiverObserved(operation)) =
                gateway.journal.operation("snapshot-op").unwrap()
            else {
                unreachable!()
            };
            assert_eq!(operation.statement(), &history.statement);
            operation
        })
        .collect::<Vec<_>>();
    let settings = ReceiptSettings {
        signing_seed: &[71; 32],
        key_id: "original-key",
    };
    let foreign = Gateway::build_receipt(&snapshots[1], &settings).unwrap();
    let gateway = &gateways[0];
    let original = stored_rows(&gateway.journal.connection);
    assert!(matches!(
        gateway.journal.commit_receipt(&snapshots[0], &foreign),
        Err(GatewayError::InvalidPersistedState)
    ));
    assert!(matches!(
        gateway.journal.commit_receipt(&snapshots[1], &foreign),
        Err(GatewayError::InvalidTransition)
    ));
    assert_eq!(stored_rows(&gateway.journal.connection), original);
    let worker = gateway.journal.try_lock_worker().unwrap().unwrap();
    assert_eq!(
        gateway
            .finalize_operation_receipt_once("snapshot-op", &settings)
            .unwrap(),
        None
    );
    assert_eq!(stored_rows(&gateway.journal.connection), original);
    drop(worker);
    let candidate = Gateway::build_receipt(&snapshots[0], &settings).unwrap();
    gateway
        .journal
        .commit_receipt(&snapshots[0], &candidate)
        .unwrap();
    let finalized = stored_rows(&gateway.journal.connection);
    assert!(gateway
        .journal
        .commit_receipt(&snapshots[0], &foreign)
        .is_err());
    assert_eq!(stored_rows(&gateway.journal.connection), finalized);
    drop(gateways);
    for path in paths {
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
