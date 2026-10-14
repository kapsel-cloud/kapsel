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
#[allow(
    clippy::too_many_lines,
    reason = "callback SQL visibility, physical lease and reopened public facts share one witness"
)]
async fn admission_callback_sees_committed_grant_and_physical_lease_for_both_effects() {
    for git in [false, true] {
        let root = root(&format!("admission-{git}"));
        let mut config = configuration(&root);
        if git {
            config.approvals[0] = git::git_approval("a");
        }
        let grant = config.approvals[0].signed_grant.clone();
        let mut app = ServiceApplication::open(config.clone()).unwrap();
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
        let reopened = ServiceApplication::open(config).unwrap();
        let expected_targets = if git {
            kapsel::OperationTargets {
                git: Some(kapsel::GitOperationTargets {
                    approval: kapsel_authority::GitRefAuthorization {
                        operation_id: "a".into(),
                        authorization_id: "git-a".into(),
                        repository_id: "repository-1".into(),
                        reference: "refs/heads/approved".into(),
                        old_commit: "a".repeat(40),
                        new_commit: "b".repeat(40),
                    },
                    attempted: false,
                    acknowledgement: None,
                    observed_ref: None,
                }),
                ..kapsel::OperationTargets::default()
            }
        } else {
            kapsel::OperationTargets {
                approved_target: Some(ApprovedTarget {
                    uid: "uid".into(),
                    resource_version: "1".into(),
                }),
                ..kapsel::OperationTargets::default()
            }
        };
        assert_eq!(
            reopened.status("a").unwrap(),
            (OperationStatus::InProgress, expected_targets)
        );
        assert_eq!(
            reopened.admitted_state("a").unwrap(),
            Some(OperationState::Authorized)
        );
        assert_eq!(
            reopened.receipt("a").unwrap(),
            kapsel::OperationReceipt::NotReady
        );
        assert_eq!(reopened.admitted_state("b").unwrap(), None);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
}

const BINARY_IDS: [&str; 19] = [
    "Operation-04",
    "operation-00",
    "operation-01",
    "operation-02",
    "operation-03",
    "operation-05",
    "operation-06",
    "operation-07",
    "operation-08",
    "operation-09",
    "operation-10",
    "operation-11",
    "operation-12",
    "operation-13",
    "operation-14",
    "operation-15",
    "operation-16",
    "operation-17",
    "operation-18",
];

// Operator order and effect are independent of SQL's binary lexical order.
const CATALOGUE: [(&str, bool); 19] = [
    ("operation-09", true),
    ("operation-02", false),
    ("operation-17", true),
    ("operation-00", false),
    ("operation-12", false),
    ("operation-07", true),
    ("operation-01", true),
    ("operation-16", false),
    ("Operation-04", true),
    ("operation-13", true),
    ("operation-08", false),
    ("operation-18", false),
    ("operation-03", true),
    ("operation-10", false),
    ("operation-15", true),
    ("operation-06", false),
    ("operation-11", true),
    ("operation-05", true),
    ("operation-14", false),
];

fn mixed_configuration(root: &Path, count: usize) -> ServiceConfiguration {
    let retained = &BINARY_IDS[..count];
    ServiceConfiguration {
        journal_path: root.join("journal.sqlite3"),
        authorization_trust: retained.iter().map(|id| trust(id, 41)).collect(),
        approvals: CATALOGUE
            .iter()
            .filter(|(id, _)| retained.contains(id))
            .map(|(id, git)| {
                let mut item = if *git {
                    git::git_approval_with_key(id, id)
                } else {
                    approval(id, 41)
                };
                item.label = format!("label-{id}");
                item
            })
            .collect(),
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "page concatenation, binary cursor and boundary-disclosure witnesses stay together"
)]
async fn pagination_crosses_the_sql_page_boundary_without_hiding_inaccessible_ids() {
    for count in [0, 8, 16, 19] {
        let root = root(&format!("pages-{count}"));
        let mut config = mixed_configuration(&root, count);
        let mut app = ServiceApplication::open(config.clone()).unwrap();
        for (id, _) in CATALOGUE
            .iter()
            .filter(|(id, _)| BINARY_IDS[..count].contains(id))
        {
            app.select(id, offline(), |_| {}).await.unwrap();
        }
        drop(app);
        let before = fs::read(root.join("journal.sqlite3")).unwrap();
        config.approvals.clear();
        let inaccessible = ["operation-07", "operation-08", "operation-16"];
        config
            .authorization_trust
            .retain(|key| !inaccessible.contains(&key.key_id.as_str()));
        let app = ServiceApplication::open(config).unwrap();
        let expected = &BINARY_IDS[..count];
        let mut collected = Vec::new();
        let mut cursor = None;
        loop {
            let page = app.history(cursor.as_deref()).unwrap();
            let end = (collected.len() + 8).min(count);
            let expected_page = &expected[collected.len()..end];
            assert_eq!(
                page.entries
                    .iter()
                    .map(|entry| entry.operation_id.as_str())
                    .collect::<Vec<_>>(),
                expected_page
            );
            assert!(page.entries.len() <= 8);
            for entry in &page.entries {
                if inaccessible.contains(&entry.operation_id.as_str()) {
                    assert_eq!(entry.status, Err(ServiceError::AuthorityUnavailable));
                    assert_eq!(
                        app.receipt(&entry.operation_id),
                        Err(ServiceError::AuthorityUnavailable)
                    );
                } else {
                    let (status, targets) = entry.status.as_ref().unwrap();
                    assert_eq!(*status, OperationStatus::InProgress);
                    let git = CATALOGUE
                        .iter()
                        .find(|(id, _)| *id == entry.operation_id)
                        .unwrap()
                        .1;
                    assert_eq!(targets.git.is_some(), git);
                }
            }
            let expected_cursor = if end < count {
                Some(expected[end - 1])
            } else {
                None
            };
            assert_eq!(page.next_cursor.as_deref(), expected_cursor);
            collected.extend(page.entries.into_iter().map(|entry| entry.operation_id));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
            assert!(collected.len() < count, "cursor requires another row");
        }
        assert_eq!(collected, expected);
        let uppercase_absent = app.history(Some("OPERATION-075")).unwrap();
        assert_eq!(
            uppercase_absent
                .entries
                .iter()
                .map(|entry| entry.operation_id.as_str())
                .collect::<Vec<_>>(),
            &expected[..count.min(8)],
            "uppercase cursor sorts before every retained ID, not between 07 and 08"
        );
        assert_eq!(
            uppercase_absent.next_cursor.as_deref(),
            (count > 8).then_some("operation-07")
        );
        let absent = app.history(Some("operation-075")).unwrap();
        let start = count.min(8);
        let end = count.min(16);
        assert_eq!(
            absent
                .entries
                .iter()
                .map(|entry| entry.operation_id.as_str())
                .collect::<Vec<_>>(),
            &expected[start..end]
        );
        assert_eq!(
            absent.next_cursor.as_deref(),
            (count > 16).then_some("operation-15")
        );
        assert!(app
            .history(Some("operation-18"))
            .unwrap()
            .entries
            .is_empty());
        assert_eq!(
            app.history(Some("invalid\n")),
            Err(ServiceError::InvalidRequest)
        );
        drop(app);
        assert_eq!(
            fs::read(root.join("journal.sqlite3")).unwrap(),
            before,
            "collection reads do not select, sign or persist work"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn approved_actions_use_catalogue_order_and_exact_selectable_identity_cursors() {
    for count in [0, 8, 16, 19] {
        let root = root(&format!("catalogue-pages-{count}"));
        let app = ServiceApplication::open(mixed_configuration(&root, count)).unwrap();
        let before = fs::read(root.join("journal.sqlite3")).unwrap();
        let expected = CATALOGUE
            .iter()
            .filter(|(id, _)| BINARY_IDS[..count].contains(id))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut collected = Vec::new();
        let mut cursor = None;
        loop {
            let page = app.approved_actions(cursor.as_deref()).unwrap();
            let end = (collected.len() + 8).min(count);
            assert_eq!(
                page.iter()
                    .map(kapsel::ApprovedAction::operation_id)
                    .collect::<Vec<_>>(),
                &expected[collected.len()..end]
            );
            assert!(page.len() <= 8);
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|action| action.operation_id().to_owned());
            collected.extend(
                page.into_iter()
                    .map(|action| action.operation_id().to_owned()),
            );
        }
        assert_eq!(collected, expected);
        for absent in ["operation-075", "label-operation-00", "OPERATION-00"] {
            assert_eq!(
                app.approved_actions(Some(absent)),
                Err(ServiceError::InvalidRequest)
            );
        }
        assert!(
            app.history(None).unwrap().entries.is_empty(),
            "enumeration admits nothing"
        );
        drop(app);
        assert_eq!(fs::read(root.join("journal.sqlite3")).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
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
