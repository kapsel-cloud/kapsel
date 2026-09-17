//! Multi-action application tests without the socket adapter or execution credentials.
#![allow(clippy::unwrap_used, reason = "fixture failures must fail the test")]

#[path = "service_application_contract/disposition.rs"]
mod disposition;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use kapsel::{
    provision_exact_grant, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperationState, ServiceAdmission, ServiceApplication, ServiceApproval,
    ServiceConfiguration, ServiceError, ServiceExecution, SetDeploymentImageReceipt,
    SetDeploymentImageStatus,
};

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "kapsel-service-application-{name}-{}",
        std::process::id()
    ));
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
    let facts = ExactAuthorization {
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
            authorization: &facts,
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

fn document(config: &ServiceConfiguration) -> serde_json::Value {
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut output, byte| {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").unwrap();
            output
        })
    };
    serde_json::json!({
        "service_configuration_version": 1,
        "receipt_signing_key_id": "receipt-key",
        "authorization_keys": config.authorization_trust.iter().map(|key| serde_json::json!({
            "key_id": key.key_id, "public_key_hex": hex(&key.public_key),
        })).collect::<Vec<_>>(),
        "approvals": config.approvals.iter().map(|approval| serde_json::json!({
            "label": approval.label, "signed_grant_hex": hex(&approval.signed_grant),
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn versioned_document_composes_without_execution_material_or_private_paths() {
    let root = root("document");
    let config = configuration(&root);
    let document = serde_json::to_vec(&document(&config)).unwrap();
    let parsed = kapsel::parse_service_operator_document(&document, config.journal_path).unwrap();
    assert_eq!(parsed.receipt_signing_key_id, "receipt-key");
    let application = ServiceApplication::open(parsed.configuration).unwrap();
    assert_eq!(application.approved_actions(None).unwrap().len(), 2);
    assert!(application.history(None).unwrap().entries.is_empty());
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn service_document_requires_named_objects_at_every_structure_boundary() {
    let config = configuration(Path::new("/not-opened"));
    let valid = document(&config);
    let root_sequence = serde_json::json!([1, [], [], "receipt-key"]);
    let mut approval_sequence = valid.clone();
    approval_sequence["approvals"] = serde_json::json!([["label", "00"]]);
    let mut key_sequence = valid;
    let key = key_sequence["authorization_keys"][0].clone();
    key_sequence["authorization_keys"] =
        serde_json::json!([[key["key_id"], key["public_key_hex"]]]);
    for document in [root_sequence, approval_sequence, key_sequence] {
        let bytes = serde_json::to_vec(&document).unwrap();
        assert!(
            kapsel::parse_service_operator_document(&bytes, config.journal_path.clone()).is_err()
        );
    }
}

#[test]
fn document_refuses_legacy_grammar_unknown_duplicate_and_out_of_bound_fields() {
    let config = configuration(Path::new("/not-opened"));
    let valid = document(&config);
    let mut cases = Vec::new();
    for (key, value) in [
        ("service_configuration_version", serde_json::json!(0)),
        ("service_configuration_version", serde_json::json!(null)),
        ("receipt_signing_key_id", serde_json::json!("bad\n")),
        ("approvals", serde_json::json!(null)),
        ("authorization_keys", serde_json::json!([null])),
        ("journal_path", serde_json::json!("/caller-selected")),
    ] {
        let mut changed = valid.clone();
        changed[key] = value;
        cases.push(serde_json::to_vec(&changed).unwrap());
    }
    for (array, field, value) in [
        ("approvals", "signed_grant_hex", "FF".to_owned()),
        ("approvals", "signed_grant_hex", "0".to_owned()),
        ("approvals", "signed_grant_hex", "00".repeat(4097)),
        ("approvals", "label", "x".repeat(129)),
        ("approvals", "label", "line\nbreak".to_owned()),
        ("authorization_keys", "public_key_hex", "00".to_owned()),
    ] {
        let mut changed = valid.clone();
        changed[array][0][field] = serde_json::json!(value);
        cases.push(serde_json::to_vec(&changed).unwrap());
    }
    for (array, count) in [("approvals", 33), ("authorization_keys", 129)] {
        let mut changed = valid.clone();
        changed[array] = serde_json::Value::Array(vec![valid[array][0].clone(); count]);
        cases.push(serde_json::to_vec(&changed).unwrap());
    }
    let serialized = serde_json::to_string(&valid).unwrap();
    cases.push(
        serialized
            .replacen('{', "{\"service_configuration_version\":1,", 1)
            .into_bytes(),
    );
    let mut missing = valid;
    missing
        .as_object_mut()
        .unwrap()
        .remove("service_configuration_version");
    cases.push(serde_json::to_vec(&missing).unwrap());
    cases.push(vec![b' '; 160 * 1024 + 1]);
    for bytes in cases {
        assert!(
            kapsel::parse_service_operator_document(&bytes, config.journal_path.clone()).is_err()
        );
    }
}

#[tokio::test]
async fn cold_validation_preserves_journal_bytes_and_original_authority() {
    let root = root("cold-validation");
    ServiceApplication::validate_replacement(&configuration(&root)).unwrap();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    application.select("a", offline(), |_| {}).await.unwrap();
    drop(application);
    let journal = root.join("journal.sqlite3");
    let before = fs::read(&journal).unwrap();
    ServiceApplication::validate_replacement(&configuration(&root)).unwrap();
    let mut removed = configuration(&root);
    removed.approvals.clear();
    removed.authorization_trust.clear();
    ServiceApplication::validate_replacement(&removed).unwrap();
    let mut conflict = configuration(&root);
    conflict.authorization_trust[0] = trust("a", 99);
    conflict.approvals[0] = approval("a", 99);
    assert!(ServiceApplication::validate_replacement(&conflict).is_err());
    let mut invalid = configuration(&root);
    invalid.approvals.push(approval("a", 41));
    assert!(ServiceApplication::validate_replacement(&invalid).is_err());
    assert_eq!(fs::read(&journal).unwrap(), before);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    let reopened = ServiceApplication::open(configuration(&root)).unwrap();
    assert_eq!(
        reopened.admitted_state("a").unwrap(),
        Some(OperationState::Authorized)
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_validation_rejects_lost_history_and_recovery_without_creating_artifacts() {
    for suffix in ["-journal", "-wal", "-shm", ".kap0038-worker.lock"] {
        let root = root(&format!("cold-lost-{suffix}"));
        let artifact = root.join(format!("journal.sqlite3{suffix}"));
        fs::write(&artifact, b"").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ServiceApplication::validate_replacement(&configuration(&root)).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(fs::read(&artifact).unwrap(), b"");
        fs::remove_dir_all(root).unwrap();
    }
    let root = root("cold-recovery");
    drop(ServiceApplication::open(configuration(&root)).unwrap());
    let journal = root.join("journal.sqlite3");
    let before = fs::read(&journal).unwrap();
    // Preserve a real rollback journal with an uncommitted write: validation must not recover it.
    let connection = rusqlite::Connection::open(&journal).unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 9;")
        .unwrap();
    let sidecar = root.join("journal.sqlite3-journal");
    let rollback = fs::read(&sidecar).unwrap();
    assert!(ServiceApplication::validate_replacement(&configuration(&root)).is_err());
    assert_eq!(fs::read(&journal).unwrap(), before);
    assert_eq!(fs::read(&sidecar).unwrap(), rollback);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
    drop(connection);
    fs::remove_dir_all(root).unwrap();
}

fn offline() -> ServiceExecution {
    ServiceExecution {
        kubernetes_client: None,
        receipt_signing: None,
    }
}

#[tokio::test]
async fn optional_operator_snapshots_never_require_or_replace_execution_material() {
    let missing = ServiceExecution::from_operator_snapshots(None, None, "receipt-key").await;
    assert!(missing.kubernetes_client.is_none());
    assert!(missing.receipt_signing.is_none());
    for bytes in [b"malformed".to_vec(), vec![0; 16 * 1024 + 1]] {
        let material =
            ServiceExecution::from_operator_snapshots(Some(&bytes), Some(&[42; 32]), "receipt-key")
                .await;
        assert!(material.kubernetes_client.is_none());
        assert_eq!(
            material.receipt_signing,
            Some(([42; 32], "receipt-key".into()))
        );
    }
    let invalid =
        ServiceExecution::from_operator_snapshots(None, Some(b"invalid seed"), "receipt-key").await;
    assert!(invalid.receipt_signing.is_none());
}

#[tokio::test]
async fn admission_is_durable_before_callback_and_retains_the_worker_lease() {
    let root = root("admission");
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    let projection = ServiceApplication::open(configuration(&root)).unwrap();
    assert_eq!(projection.admitted_state("a").unwrap(), None);
    assert_eq!(
        projection.admitted_state("absent"),
        Err(ServiceError::InvalidRequest)
    );
    let (decision, read) = std::sync::mpsc::channel();
    application
        .select("a", offline(), move |admitted| {
            assert_eq!(
                admitted,
                ServiceAdmission::Admitted(OperationState::Requested)
            );
            // Independent connection sees the complete committed identity before acknowledgement.
            let reader = projection;
            assert_eq!(
                reader.admitted_state("a").unwrap(),
                Some(OperationState::Requested)
            );
            assert_eq!(
                reader.status("a").unwrap().0,
                SetDeploymentImageStatus::InProgress
            );
            let connection = rusqlite::Connection::open(root.join("journal.sqlite3")).unwrap();
            let grant: Vec<u8> = connection
                .query_row(
                    concat!(
                        "SELECT signed_authorization_grant FROM kubernetes_image_operations ",
                        "WHERE operation_id='a'",
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(grant, approval("a", 41).signed_grant);
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("journal.sqlite3.kap0038-worker.lock"))
                .unwrap();
            assert!(matches!(
                lock.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            decision.send(root).unwrap();
        })
        .await
        .unwrap();
    let root = read.recv().unwrap();
    // No receiver materials means admitted A is blocked, not cancelled.
    // B can be selected explicitly.
    application
        .select("b", offline(), |decision| {
            assert_eq!(
                decision,
                ServiceAdmission::Admitted(OperationState::Requested)
            );
        })
        .await
        .unwrap();
    assert_eq!(
        application.status("b").unwrap().0,
        SetDeploymentImageStatus::InProgress
    );
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn catalog_removal_and_missing_trust_do_not_hide_healthy_history() {
    let root = root("history");
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    assert_eq!(application.approved_actions(None).unwrap().len(), 2);
    assert_eq!(
        application.approved_actions(Some("a")).unwrap()[0]
            .request
            .operation_id,
        "b"
    );
    assert_eq!(
        application.status("a").unwrap().0,
        SetDeploymentImageStatus::NotFound
    );
    assert!(matches!(
        application.select("absent", offline(), |_| {}).await,
        Err(ServiceError::InvalidRequest)
    ));
    for id in ["a", "b"] {
        application.select(id, offline(), |_| {}).await.unwrap();
    }
    drop(application);
    let mut config = configuration(&root);
    config.approvals.clear();
    config.authorization_trust.remove(0);
    let mut application = ServiceApplication::open(config).unwrap();
    assert!(application.approved_actions(None).unwrap().is_empty());
    assert_eq!(
        application.status("a"),
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(
        application.admitted_state("a"),
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(
        application.receipt("a"),
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(
        application.select("a", offline(), |_| {}).await,
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(
        application.status("b").unwrap().0,
        SetDeploymentImageStatus::InProgress
    );
    assert_eq!(
        application.receipt("b").unwrap(),
        SetDeploymentImageReceipt::NotReady
    );
    application
        .select("b", offline(), |decision| {
            assert_eq!(
                decision,
                ServiceAdmission::Admitted(OperationState::Authorized)
            );
        })
        .await
        .unwrap();
    drop(application);
    let mut changed = configuration(&root);
    changed.approvals[0] = approval("a", 43);
    changed.authorization_trust[0] = trust("a", 43);
    assert!(matches!(
        ServiceApplication::open(changed),
        Err(ServiceError::OperationFailure)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn history_is_bounded_ordered_and_keeps_inaccessible_ids_visible() {
    let root = root("history-pages");
    let mut config = configuration(&root);
    config.approvals.clear();
    config.authorization_trust.clear();
    for index in (0..10).rev() {
        let id = format!("operation-{index:02}");
        config.approvals.push(approval(&id, 41));
        config.authorization_trust.push(trust(&id, 41));
    }
    let mut application = ServiceApplication::open(config).unwrap();
    assert!(application.history(None).unwrap().entries.is_empty());
    for index in (0..10).rev() {
        application
            .select(&format!("operation-{index:02}"), offline(), |_| {})
            .await
            .unwrap();
    }
    drop(application);
    let mut config = configuration(&root);
    config.approvals.clear();
    config.authorization_trust = (1..10)
        .map(|index| trust(&format!("operation-{index:02}"), 41))
        .collect();
    let application = ServiceApplication::open(config).unwrap();
    let first = application.history(None).unwrap();
    assert_eq!(first.entries.len(), 8);
    assert_eq!(first.entries[0].operation_id, "operation-00");
    assert_eq!(
        first.entries[0].status,
        Err(ServiceError::AuthorityUnavailable)
    );
    assert_eq!(
        first.entries[1].status.as_ref().unwrap().0,
        SetDeploymentImageStatus::InProgress
    );
    assert_eq!(first.next_cursor.as_deref(), Some("operation-07"));
    let second = application.history(first.next_cursor.as_deref()).unwrap();
    assert_eq!(second.entries.len(), 2);
    assert_eq!(second.entries[0].operation_id, "operation-08");
    assert_eq!(second.entries[1].operation_id, "operation-09");
    assert!(second.next_cursor.is_none());
    assert!(application
        .history(Some("operation-09"))
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        application.history(Some("invalid\n")),
        Err(ServiceError::InvalidRequest)
    );
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn contention_preserves_existing_admission_but_refuses_new_work() {
    let root = root("busy");
    let mut application = ServiceApplication::open(configuration(&root)).unwrap();
    application.select("a", offline(), |_| {}).await.unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("journal.sqlite3.kap0038-worker.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    application
        .select("a", offline(), |decision| {
            assert_eq!(
                decision,
                ServiceAdmission::Admitted(OperationState::Authorized)
            );
        })
        .await
        .unwrap();
    application
        .select("b", offline(), |decision| {
            assert_eq!(decision, ServiceAdmission::Busy);
        })
        .await
        .unwrap();
    assert_eq!(
        application.status("b").unwrap().0,
        SetDeploymentImageStatus::NotFound
    );
    lock.unlock().unwrap();
    drop(application);
    fs::remove_dir_all(root).unwrap();
}
