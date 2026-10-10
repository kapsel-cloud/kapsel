//! Retained legacy authority stays readable but never grants service execution permission.

use super::*;
use crate::application::{
    OperationReceipt, OperationStatus, ServiceApplication, ServiceConfiguration, ServiceError,
    ServiceExecution,
};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one frozen legacy-authority continuation trace"
)]
async fn service_reads_but_cannot_advance_retained_legacy_authority() {
    let path = database_path("legacy-service-inspection");
    let path = path
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join("journal.sqlite3");
    let request = request();
    let trust = AuthorizationTrust {
        key_id: "legacy-fixture".into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    };
    let grant =
        sign_authorization_grant(&authorization(&request), &[7; 32], &trust.key_id).unwrap();
    let mut gateway = Gateway::open(&path, trust.clone()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    gateway.submit_authorized(&request, &grant).unwrap();
    let configuration = || ServiceConfiguration {
        journal_path: path.clone(),
        authorization_trust: vec![trust.clone()],
        approvals: Vec::new(),
    };
    let mut service = ServiceApplication::open(configuration()).unwrap();
    assert_eq!(
        service.receipt(&request.operation_id).unwrap(),
        OperationReceipt::NotReady
    );
    assert_eq!(
        service.status(&request.operation_id).unwrap().0,
        OperationStatus::InProgress
    );
    let connection = Connection::open(&path).unwrap();
    let read_row = || {
        let mut statement = connection
            .prepare("SELECT * FROM kubernetes_image_operations")
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_row([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
    };

    let original_row = read_row();
    let mut selection_callbacks = 0;
    assert_eq!(
        service
            .select(
                &request.operation_id,
                ServiceExecution {
                    git_receiver: None,
                    kubernetes_client: None,
                    receipt_signing: Some(([13; 32], "receipt".into())),
                },
                |_| selection_callbacks += 1
            )
            .await,
        Err(ServiceError::InvalidRequest)
    );
    assert_eq!(selection_callbacks, 0);
    assert_eq!(read_row(), original_row);

    let mut adapter = failed_rollout_adapter(&path, &request);
    gateway
        .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
        .await
        .unwrap();
    gateway
        .finalize_operation_receipt_once(
            &request.operation_id,
            &ReceiptSettings {
                signing_seed: &[13; 32],
                key_id: "legacy-receipt",
            },
        )
        .unwrap();
    let (bytes, sha256) = Gateway::read_loaded_receipt(
        gateway
            .journal
            .operation(&request.operation_id)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        service.receipt(&request.operation_id).unwrap(),
        OperationReceipt::Ready { bytes, sha256 }
    );

    let finalized_row = read_row();

    drop(service);
    let mut service = ServiceApplication::open(configuration()).unwrap();
    assert_eq!(
        service
            .select(
                &request.operation_id,
                ServiceExecution {
                    git_receiver: None,
                    kubernetes_client: None,
                    receipt_signing: None,
                },
                |_| selection_callbacks += 1
            )
            .await,
        Err(ServiceError::InvalidRequest)
    );
    assert_eq!(read_row(), finalized_row);
    assert_eq!(selection_callbacks, 0);

    drop(service);
    drop(gateway);
    drop(connection);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
