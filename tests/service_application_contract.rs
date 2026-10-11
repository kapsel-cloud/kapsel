//! Concrete admission, pagination, parser and cold-storage boundaries; lifecycle laws live in core.
#![allow(clippy::unwrap_used, reason = "fixture failures must fail the test")]

#[path = "service_application_contract/git.rs"]
mod git;
#[path = "service_application_contract/storage.rs"]
mod storage;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use kapsel::{
    provision_exact_grant, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperationState, OperationStatus, ServiceAdmission, ServiceApplication,
    ServiceApproval, ServiceConfiguration, ServiceError, ServiceExecution,
};
use rusqlite::Connection;

fn root(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("kapsel-application-{name}-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::canonicalize(root).unwrap()
}

fn trust(id: &str, seed: u8) -> AuthorizationTrust {
    AuthorizationTrust {
        key_id: id.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    }
}

fn approval(id: &str, seed: u8) -> ServiceApproval {
    let authorization = ExactAuthorization {
        operation_id: id.into(),
        authorization_id: format!("authorization-{id}"),
        namespace: "demo".into(),
        deployment: id.into(),
        container: "api".into(),
        immutable_image_digest: format!("registry.example/api@sha256:{}", "0".repeat(64)),
        approved_target: Some(ApprovedTarget {
            uid: "uid".into(),
            resource_version: "1".into(),
        }),
    };
    ServiceApproval {
        signed_grant: provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &[seed; 32],
            signing_key_id: id,
        })
        .unwrap(),
        label: format!("Exact action {id}"),
    }
}

fn configuration(root: &Path) -> ServiceConfiguration {
    ServiceConfiguration {
        journal_path: root.join("journal.sqlite3"),
        authorization_trust: vec![trust("a", 41), trust("b", 43)],
        approvals: vec![approval("a", 41), approval("b", 43)],
    }
}

fn offline() -> ServiceExecution {
    ServiceExecution {
        git_receiver: None,
        kubernetes_client: None,
        receipt_signing: None,
    }
}

#[tokio::test]
async fn admission_callback_sees_committed_grant_and_physical_lease_for_both_effects() {
    for git in [false, true] {
        let root = root(&format!("admission-{git}"));
        let mut config = configuration(&root);
        if git {
            config.approvals[0] = git::git_approval("a");
        }
        let grant = config.approvals[0].signed_grant.clone();
        let mut app = ServiceApplication::open(config).unwrap();
        let stopped = app
            .select("a", offline(), |decision| {
                let phase = if git {
                    OperationState::Authorized
                } else {
                    OperationState::Requested
                };
                assert_eq!(decision, ServiceAdmission::Admitted(phase));
                let table = if git {
                    "git_ref_operations"
                } else {
                    "kubernetes_image_operations"
                };
                let connection = Connection::open(root.join("journal.sqlite3")).unwrap();
                let retained: Vec<u8> = connection
                    .query_row(
                        &format!(
                            "SELECT signed_authorization_grant FROM {table} WHERE operation_id='a'"
                        ),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(retained, grant);
                let lock = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(root.join("journal.sqlite3.kap0038-worker.lock"))
                    .unwrap();
                assert!(matches!(lock.try_lock(), Err(fs::TryLockError::WouldBlock)));
            })
            .await
            .unwrap();
        assert_eq!(
            stopped,
            kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::ReceiverUnavailable)
        );
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("journal.sqlite3.kap0038-worker.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        app.select("a", offline(), |decision| {
            assert_eq!(
                decision,
                ServiceAdmission::Admitted(OperationState::Authorized)
            );
        })
        .await
        .unwrap();
        app.select("b", offline(), |decision| {
            assert_eq!(decision, ServiceAdmission::Busy);
        })
        .await
        .unwrap();
        assert_eq!(app.admitted_state("b").unwrap(), None);
        drop(lock);
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn pagination_crosses_the_sql_page_boundary_without_hiding_inaccessible_ids() {
    let root = root("pages");
    let mut config = configuration(&root);
    config.approvals = (0..10)
        .rev()
        .map(|n| approval(&format!("operation-{n:02}"), 41))
        .collect();
    config.authorization_trust = (0..10)
        .map(|n| trust(&format!("operation-{n:02}"), 41))
        .collect();
    let mut app = ServiceApplication::open(config.clone()).unwrap();
    for n in (0..10).rev() {
        app.select(&format!("operation-{n:02}"), offline(), |_| {})
            .await
            .unwrap();
    }
    drop(app);
    config.approvals.clear();
    config.authorization_trust.remove(0);
    let app = ServiceApplication::open(config).unwrap();
    let first = app.history(None).unwrap();
    assert_eq!(first.entries.len(), 8);
    assert_eq!(
        first.entries[0].status,
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(first.next_cursor.as_deref(), Some("operation-07"));
    let second = app.history(first.next_cursor.as_deref()).unwrap();
    assert_eq!(
        second
            .entries
            .iter()
            .map(|e| e.operation_id.as_str())
            .collect::<Vec<_>>(),
        ["operation-08", "operation-09"]
    );
    assert!(second.next_cursor.is_none());
    assert!(app
        .history(Some("operation-09"))
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        app.history(Some("invalid\n")),
        Err(ServiceError::InvalidRequest)
    );
    assert_eq!(
        app.status("operation-01").unwrap().0,
        OperationStatus::InProgress
    );
    drop(app);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cold_validation_is_read_only_including_an_unsettled_rollback_journal() {
    let root = root("cold");
    let config = configuration(&root);
    ServiceApplication::validate_replacement(&config).unwrap();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let mut app = ServiceApplication::open(config.clone()).unwrap();
    app.select("a", offline(), |_| {}).await.unwrap();
    drop(app);
    let path = root.join("journal.sqlite3");
    let original = fs::read(&path).unwrap();
    ServiceApplication::validate_replacement(&config).unwrap();
    let mut changed = config.clone();
    changed.authorization_trust[0] = trust("a", 99);
    changed.approvals[0] = approval("a", 99);
    assert!(ServiceApplication::validate_replacement(&changed).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 9;")
        .unwrap();
    let sidecar = root.join("journal.sqlite3-journal");
    let rollback = fs::read(&sidecar).unwrap();
    assert!(ServiceApplication::validate_replacement(&config).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read(&sidecar).unwrap(), rollback);
    drop(connection);
    fs::remove_dir_all(root).unwrap();
}
