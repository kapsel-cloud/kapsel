//! A shared receiver target is a real HTTP preflight conflict, not simulated peer isolation.
use kapsel::{ExecutionCondition, ServiceStop, TargetRejection};
use rusqlite::{types::Value as SqlValue, Connection};

use super::*;

fn row(root: &Path, id: &str) -> Vec<SqlValue> {
    let connection = Connection::open(root.join("journal.sqlite3")).unwrap();
    let mut query = connection
        .prepare("SELECT * FROM kubernetes_image_operations WHERE operation_id = ?1")
        .unwrap();
    let fields = query.column_count();
    query
        .query_row([id], |row| (0..fields).map(|n| row.get(n)).collect())
        .unwrap()
}

#[tokio::test]
async fn shared_target_preflight_rejects_b_without_changing_frozen_a() {
    let mut receiver = Fixture::new(200);
    let mut a = receiver.application();
    let mut execution = receiver.execution().await;
    execution.receipt_signing = None;
    assert_eq!(
        a.select("retry-op", execution, |_| {}).await.unwrap(),
        ServiceStop::Blocked(ExecutionCondition::SigningUnavailable)
    );
    let frozen = row(&receiver.root, "retry-op");
    let approval = ExactAuthorization {
        authorization_id: "b-approval".into(),
        operation_id: "b".into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
        approved_target: Some(ApprovedTarget {
            uid: "uid-1".into(),
            resource_version: "1".into(),
        }),
    };
    let mut b = ServiceApplication::open(ServiceConfiguration {
        journal_path: receiver.root.join("journal.sqlite3"),
        authorization_trust: vec![AuthorizationTrust {
            key_id: "retry-authority".into(),
            public_key: SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
        }],
        approvals: vec![ServiceApproval {
            label: "Same target".into(),
            signed_grant: provision_exact_grant(&GrantProvisioning {
                authorization: &approval,
                signing_seed: &[41; 32],
                signing_key_id: "retry-authority",
            })
            .unwrap(),
        }],
    })
    .unwrap();
    b.select("b", receiver.execution().await, |_| {})
        .await
        .unwrap();
    let (status, targets) = b.status("b").unwrap();
    assert_eq!(
        status,
        OperationStatus::NotAttempted(TargetRejection::StaleApproval)
    );
    assert_eq!(targets.approved_target, approval.approved_target);
    assert_eq!(
        targets.observed_target.unwrap().resource_version.as_deref(),
        Some("2")
    );
    assert!(targets.attempt_target.is_none());
    assert_eq!(row(&receiver.root, "retry-op"), frozen);
    a.select("retry-op", receiver.execution().await, |_| {})
        .await
        .unwrap();
    assert!(matches!(
        a.receipt("retry-op").unwrap(),
        OperationReceipt::Ready { .. }
    ));
    drop(a);
    drop(b);
    let requests = receiver.finish();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.method.as_str())
            .collect::<Vec<_>>(),
        ["GET", "PATCH", "GET", "GET"]
    );
}
