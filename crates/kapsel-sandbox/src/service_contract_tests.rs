//! Exported sandbox service contract tests.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled fixture failures must stop the contract test"
)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{
    AdmissionDisposition, BackupPublicationState, CleanupAbsenceEvidence, CleanupObjectAbsence,
    CleanupRole, CleanupState, DispatchLease, ExecutionState, ProvisionedObject,
    ProvisioningSpecification, RetentionRole, Scenario, SchedulerRole, SchedulerStep, Service,
    ServiceError, StoppedBackupService,
};
use ed25519_dalek::{Signer, SigningKey};
use http::{Request, StatusCode};
use kapsel::{
    inspect_receipt, provision_exact_grant, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, InspectionLimits, InspectionStatus, OperatorConfiguration, ReceiptTrust,
};
use tower_test::mock;

const NOW: i64 = 1_774_051_200;

fn test_authority_identity() -> crate::GenerationIdentity {
    crate::test_authority_identity()
}

fn authority_identity(generation: u64, byte: &str) -> crate::GenerationIdentity {
    crate::GenerationIdentity::new(generation, byte.repeat(32)).unwrap()
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture(name: &str) -> (PathBuf, Service) {
    let root = std::env::temp_dir().join(format!("kapsel-sandbox-{name}-{}", std::process::id()));
    if root.exists() {
        crate::test_authority::remove_root(&root);
    }
    private_directory(&root);
    private_directory(&root.join("receipts"));
    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW,
    )
    .unwrap();
    (root, service)
}

fn key(index: u8) -> String {
    format!("{index:032x}")
}

#[test]
fn collects_only_unreferenced_noncurrent_authority() {
    let (root, service) = fixture("authority-collection");
    crate::test_authority::rotate(&root, [8; 32]);
    assert!(service.collect_unused_authority().unwrap());
    assert!(!root
        .join("fixed-authority/generations/generation-00000000000000000001")
        .exists());
    assert!(root
        .join("fixed-authority/generations/generation-00000000000000000002")
        .exists());
    assert!(!service.collect_unused_authority().unwrap());
    crate::test_authority::remove_root(&root);
}

#[test]
fn backup_publication_requires_positive_generation_and_capture_time() {
    let (root, service) = fixture("backup-positive-identities");
    service.set_global_stop(true).unwrap();
    assert_eq!(
        service.begin_backup_publication(0, NOW),
        Err(ServiceError::Unavailable)
    );
    assert_eq!(
        service.begin_backup_publication(1, 0),
        Err(ServiceError::Unavailable)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn malformed_backup_rows_fail_before_orphan_receipt_cleanup() {
    let (root, service) = fixture("backup-malformed-preflight");
    drop(service);
    let orphan = root.join("receipts/.sandbox-orphan.receipt.pending-test");
    fs::write(&orphan, b"must remain").unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            concat!(
                "INSERT INTO backup_authority_references VALUES ",
                "('pending', 1, ?1)"
            ),
            ["ab".repeat(32)],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        Service::open_for_test(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW,
        ),
        Err(ServiceError::Unavailable)
    ));
    assert_eq!(fs::read(&orphan).unwrap(), b"must remain");
    crate::test_authority::remove_root(&root);
}

#[test]
fn stopped_backup_service_reads_and_resumes_exact_pending_publication() {
    let (root, service) = fixture("backup-pending-resume");
    service.set_global_stop(true).unwrap();
    drop(service);
    let backup = StoppedBackupService::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
    )
    .unwrap();
    assert_eq!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Empty
    );
    let pending = backup.begin_publication(1, NOW + 1).unwrap();
    assert_eq!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Pending(pending.clone())
    );
    assert_eq!(backup.resume_pending().unwrap(), pending);
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    connection
        .execute(
            "INSERT INTO tombstones VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "b".repeat(64),
                "c".repeat(64),
                NOW + 2,
                i64::try_from(test_authority_identity().generation).unwrap(),
                test_authority_identity().manifest_digest
            ],
        )
        .unwrap();
    drop(connection);
    assert_eq!(backup.resume_pending(), Err(ServiceError::Unavailable));
    assert!(matches!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Pending(_)
    ));
    crate::test_authority::remove_root(&root);
}

#[test]
fn stopped_backup_open_never_cleans_or_recovers_source() {
    let (root, service) = fixture("backup-nonrecovering-open");
    service.set_global_stop(true).unwrap();
    drop(service);
    let object_name =
        "sandbox-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-".to_owned() + &"b".repeat(64) + ".receipt";
    let object = root.join("receipts").join(&object_name);
    fs::write(&object, b"unchanged orphan").unwrap();
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO receipt_publications VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["missing-run", "b".repeat(64), object_name, NOW],
        )
        .unwrap();
    drop(connection);

    assert!(StoppedBackupService::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
    )
    .is_err());
    assert_eq!(fs::read(object).unwrap(), b"unchanged orphan");
    assert_eq!(
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM receipt_publications", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn stopped_backup_service_orders_two_exact_authority_references() {
    let (root, service) = fixture("backup-two-references");
    let first = test_authority_identity();
    let second = crate::test_authority::rotate(&root, [8; 32]);
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    for (index, identity) in [&first, &second].into_iter().enumerate() {
        connection
            .execute(
                "INSERT INTO tombstones VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("{index:064x}"),
                    format!("{:064x}", index + 10),
                    NOW + 10,
                    i64::try_from(identity.generation).unwrap(),
                    identity.manifest_digest
                ],
            )
            .unwrap();
    }
    drop(connection);
    service.set_global_stop(true).unwrap();
    drop(service);
    let backup = StoppedBackupService::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
    )
    .unwrap();
    let pending = backup.begin_publication(1, NOW + 1).unwrap();
    assert_eq!(pending.authorities, vec![first, second]);
    assert_eq!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Pending(pending)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn stopped_backup_service_rejects_unstaged_and_nonconsecutive_rows() {
    for (name, rows) in [
        (
            "unstaged-reference",
            concat!(
                "INSERT INTO backup_generations VALUES ('pending', 1, NULL, 'pending', 1);",
                "INSERT INTO backup_authority_references VALUES ('pending', 99, '",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');"
            ),
        ),
        (
            "nonconsecutive",
            concat!(
                "INSERT INTO backup_generations VALUES ('current', 1, '",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ",
                "'current', 1);",
                "INSERT INTO backup_generations VALUES ('pending', 3, NULL, 'pending', 2);"
            ),
        ),
    ] {
        let (root, service) = fixture(&format!("backup-malformed-{name}"));
        service.set_global_stop(true).unwrap();
        drop(service);
        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        connection.execute_batch(rows).unwrap();
        drop(connection);
        assert!(StoppedBackupService::open_for_test(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
        )
        .is_err());
        assert_eq!(
            rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                .unwrap()
                .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            if name == "unstaged-reference" { 1 } else { 2 }
        );
        crate::test_authority::remove_root(&root);
    }
}

#[test]
fn pending_and_published_backup_references_block_authority_collection() {
    let (root, service) = fixture("backup-authority-reference");
    service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    crate::test_authority::rotate(&root, [8; 32]);
    service.set_global_stop(true).unwrap();

    let pending = service.begin_backup_publication(1, NOW + 2).unwrap();
    assert_eq!(pending.authorities, vec![test_authority_identity()]);
    assert!(pending.predecessor.is_none());
    let backup = StoppedBackupService::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
    )
    .unwrap();
    assert_eq!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Pending(pending)
    );
    drop(backup);
    assert!(!service.collect_unused_authority().unwrap());

    let digest = "cd".repeat(32);
    assert_eq!(service.finish_backup_publication(1, &digest).unwrap(), None);
    assert!(!service.collect_unused_authority().unwrap());
    crate::test_authority::remove_root(&root);
}

#[test]
fn backup_replacement_holds_old_and_new_references_until_byte_deletion() {
    let (root, service) = fixture("backup-reference-replacement");
    service.set_global_stop(true).unwrap();
    service.begin_backup_publication(1, NOW + 1).unwrap();
    service
        .finish_backup_publication(1, &"ab".repeat(32))
        .unwrap();
    let second = service.begin_backup_publication(2, NOW + 2).unwrap();
    assert_eq!(second.predecessor, Some((1, "ab".repeat(32))));
    assert_eq!(
        service
            .finish_backup_publication(2, &"cd".repeat(32))
            .unwrap(),
        Some(1)
    );
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    service.finish_backup_deletion(1).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn restored_pending_backup_becomes_the_only_current_owner_atomically() {
    let (root, service) = fixture("backup-restored-pending");
    service.set_global_stop(true).unwrap();
    service.begin_backup_publication(1, NOW + 1).unwrap();
    service
        .finish_backup_publication(1, &"ab".repeat(32))
        .unwrap();
    let selected = service.begin_backup_publication(2, NOW + 2).unwrap();
    drop(service);
    let backup = StoppedBackupService::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
    )
    .unwrap();
    backup
        .restore_publication(&selected, &"cd".repeat(32))
        .unwrap();
    assert_eq!(
        backup.publication_state().unwrap(),
        BackupPublicationState::Current(crate::PublishedBackup {
            generation: 2,
            captured_at: NOW + 2,
            manifest_digest: "cd".repeat(32),
            authorities: selected.authorities,
        })
    );

    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row(
                concat!(
                    "SELECT slot, generation, manifest_digest FROM backup_generations ",
                    "WHERE slot = 'current'"
                ),
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                )),
            )
            .unwrap(),
        ("current".into(), 2, "cd".repeat(32))
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn empty_stopped_backup_has_no_ambient_authority_reference() {
    let (root, service) = fixture("backup-empty-authority-reference");
    service.set_global_stop(true).unwrap();
    let pending = service.begin_backup_publication(1, NOW + 1).unwrap();
    assert!(pending.authorities.is_empty());
    crate::test_authority::remove_root(&root);
}

#[test]
fn malformed_authority_collection_fails_before_database_or_authority_mutation() {
    for (name, corrupt) in [
        (
            "schema",
            concat!(
                "DROP TABLE authority_collection; ",
                "CREATE TABLE authority_collection (generation TEXT)"
            ),
        ),
        (
            "digest",
            "INSERT INTO authority_collection VALUES (1, 1, 'AB')",
        ),
        (
            "singleton",
            concat!(
                "PRAGMA ignore_check_constraints = ON; ",
                "INSERT INTO authority_collection VALUES ",
                "(2, 1, 'abababababababababababababababababababababababababababababababab')"
            ),
        ),
    ] {
        let (root, service) = fixture(&format!("authority-collection-malformed-{name}"));
        drop(service);
        let database = root.join("sandbox.sqlite3");
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute_batch(corrupt)
            .unwrap();
        let database_before = fs::read(&database).unwrap();
        let generations_before = fs::read_dir(root.join("fixed-authority/generations"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(matches!(
            Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW),
            Err(ServiceError::Unavailable)
        ));
        assert_eq!(fs::read(&database).unwrap(), database_before);
        assert_eq!(
            fs::read_dir(root.join("fixed-authority/generations"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            generations_before
        );
        crate::test_authority::remove_root(&root);
    }
}

#[test]
fn malformed_collection_filesystem_fails_before_database_mutation() {
    for case in ["missing-current", "wrong-mode", "symlink", "hardlink"] {
        let (root, service) = fixture(&format!("authority-collection-filesystem-{case}"));
        let first_digest = crate::test_authority::manifest_digest([7; 32]);
        crate::test_authority::rotate(&root, [8; 32]);
        let database = root.join("sandbox.sqlite3");
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute(
                "INSERT INTO authority_collection VALUES (1, 1, ?1)",
                [&first_digest],
            )
            .unwrap();
        drop(service);
        let generations = root.join("fixed-authority/generations");
        let original = generations.join("generation-00000000000000000001");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let collecting = generations.join(".collecting-generation-00000000000000000001");
        fs::rename(&original, &collecting).unwrap();
        let authorization_seed = collecting.join("authorization-signing-seed");
        match case {
            "missing-current" => {
                let current = generations.join("generation-00000000000000000002");
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
                fs::remove_dir_all(current).unwrap();
            },
            "wrong-mode" => {
                fs::set_permissions(&authorization_seed, fs::Permissions::from_mode(0o600))
                    .unwrap();
            },
            "symlink" => {
                fs::remove_file(&authorization_seed).unwrap();
                symlink("receipt-signing-seed", authorization_seed).unwrap();
            },
            "hardlink" => {
                fs::remove_file(&authorization_seed).unwrap();
                fs::hard_link(collecting.join("receipt-signing-seed"), authorization_seed).unwrap();
            },
            _ => unreachable!(),
        }
        let database_before = fs::read(&database).unwrap();
        assert!(matches!(
            Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW),
            Err(ServiceError::Unavailable)
        ));
        assert_eq!(fs::read(&database).unwrap(), database_before);
        crate::test_authority::remove_root(&root);
    }
}

#[test]
fn authority_collection_record_recovers_partial_filesystem_deletion_on_open() {
    let (root, service) = fixture("authority-collection-recovery");
    let first_digest = crate::test_authority::manifest_digest([7; 32]);
    crate::test_authority::rotate(&root, [8; 32]);
    let database = root.join("sandbox.sqlite3");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "INSERT INTO authority_collection VALUES (1, 1, ?1)",
            [&first_digest],
        )
        .unwrap();
    let generations = root.join("fixed-authority/generations");
    let original = generations.join("generation-00000000000000000001");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let collecting = generations.join(".collecting-generation-00000000000000000001");
    fs::rename(&original, &collecting).unwrap();
    fs::remove_file(collecting.join("authorization-signing-seed")).unwrap();
    drop(service);
    let reopened = Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW).unwrap();
    assert!(!collecting.exists());
    let pending: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM authority_collection", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(pending, 0);
    drop(reopened);
    crate::test_authority::remove_root(&root);
}

#[test]
fn tombstone_and_orphan_dispatch_references_block_collection() {
    let (root, service) = fixture("authority-collection-reference-matrix");
    let first_digest = crate::test_authority::manifest_digest([7; 32]);
    crate::test_authority::rotate(&root, [8; 32]);
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO tombstones VALUES (?1, ?2, ?3, 1, ?4)",
            rusqlite::params!["run-digest", "key-digest", NOW + 100, first_digest],
        )
        .unwrap();
    assert!(!service.collect_unused_authority().unwrap());
    connection.execute("DELETE FROM tombstones", []).unwrap();
    connection
        .execute(
            "INSERT INTO tombstones VALUES (?1, ?2, ?3, 7, ?4)",
            rusqlite::params!["other-run", "other-key", NOW + 100, "cd".repeat(32)],
        )
        .unwrap();
    assert_eq!(
        service.collect_unused_authority(),
        Err(ServiceError::Unavailable)
    );
    connection.execute("DELETE FROM tombstones", []).unwrap();
    let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let inputs = crate::runner_process::INPUT_NAMES
        .into_iter()
        .map(|name| (name, vec![1]))
        .collect::<Vec<_>>();
    service
        .authority_reader()
        .publish_runner_inputs(run_id, 1, &inputs)
        .unwrap();
    assert_eq!(
        service.collect_unused_authority(),
        Err(ServiceError::Unavailable)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn queued_or_epoch_mismatched_dispatch_ownership_blocks_collection() {
    let (root, service) = fixture("authority-collection-dispatch-owner");
    let queued = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let inputs = crate::runner_process::INPUT_NAMES
        .into_iter()
        .map(|name| (name, vec![1]))
        .collect::<Vec<_>>();
    service
        .authority_reader()
        .publish_runner_inputs(&queued.run_id, 1, &inputs)
        .unwrap();
    crate::test_authority::rotate(&root, [8; 32]);
    assert_eq!(
        service.collect_unused_authority(),
        Err(ServiceError::Unavailable)
    );
    crate::test_authority::remove_root(&root);

    let (root, service) = fixture("authority-collection-dispatch-epoch");
    let admission = service.admit(&key(2), Scenario::Healthy, NOW).unwrap();
    service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    service
        .authority_reader()
        .publish_runner_inputs(&admission.run_id, 2, &inputs)
        .unwrap();
    crate::test_authority::rotate(&root, [8; 32]);
    assert_eq!(
        service.collect_unused_authority(),
        Err(ServiceError::Unavailable)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn retained_receipt_trust_uses_the_durable_generation_after_rotation() {
    let (root, service) = fixture("retained-receipt-trust");
    let trust = crate::test_authority::configure_receipt_trust(&root);
    let authority = service.authority_reader().current_identity().unwrap();
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    service.dispatch_next(NOW + 1, &authority).unwrap();
    let object_name = format!("sandbox-{}-{}.receipt", admission.run_id, "ab".repeat(32));
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE runs SET receipt_available = 1 WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipts VALUES (?1, ?2, ?3)",
            rusqlite::params![admission.run_id, "ab".repeat(32), object_name],
        )
        .unwrap();
    crate::test_authority::rotate(&root, [8; 32]);
    assert_eq!(
        service.retained_public_trust(&admission.run_id).unwrap(),
        trust
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn durable_run_pin_blocks_authority_collection() {
    let (root, service) = fixture("authority-collection-reference");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    crate::test_authority::rotate(&root, [8; 32]);
    assert!(!service.collect_unused_authority().unwrap());
    assert!(root
        .join("fixed-authority/generations/generation-00000000000000000001")
        .exists());
    assert_eq!(
        service.snapshot(&admission.run_id, NOW + 1).unwrap().run_id,
        admission.run_id
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn authority_pin_is_atomic_recovered_exactly_and_corruption_fails_closed() {
    let (root, service) = fixture("authority-pin");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let authority = crate::GenerationIdentity::new(7, "ab".repeat(32)).unwrap();
    let lease = service.dispatch_next(NOW + 1, &authority).unwrap();
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    let stored: (i64, String, i64) = connection
        .query_row(
            concat!(
                "SELECT authority_generation, authority_manifest_digest, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored, (7, "ab".repeat(32), 2));

    let recovered = service
        .recover_run(&admission.run_id, Some(&lease), NOW + 2)
        .unwrap();
    assert_ne!(lease, recovered);
    let after_recovery: (i64, String, i64) = connection
        .query_row(
            concat!(
                "SELECT authority_generation, authority_manifest_digest, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after_recovery, stored);

    connection
        .execute(
            "UPDATE runs SET authority_generation = NULL WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();
    let lease_before: (String, i64, i64, i64) = connection
        .query_row(
            concat!(
                "SELECT lease_id, lease_epoch, lease_expires_at, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        service.recover_run(&admission.run_id, Some(&recovered), NOW + 3),
        Err(ServiceError::Unavailable)
    );
    let lease_after: (String, i64, i64, i64) = connection
        .query_row(
            concat!(
                "SELECT lease_id, lease_epoch, lease_expires_at, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(lease_after, lease_before);
    crate::test_authority::remove_root(&root);
}

#[test]
fn mixed_queued_authority_pin_cannot_dispatch_or_mutate_lifecycle() {
    let (root, service) = fixture("authority-mixed-queued");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE runs SET authority_manifest_digest = ?2 WHERE run_id = ?1",
            rusqlite::params![admission.run_id, "cd".repeat(32)],
        )
        .unwrap();
    let before: (String, bool, i64) = connection
        .query_row(
            concat!(
                "SELECT execution_state, active, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        service.dispatch_next(NOW + 1, &test_authority_identity()),
        Err(ServiceError::Unavailable)
    );
    let after: (String, bool, i64) = connection
        .query_row(
            concat!(
                "SELECT execution_state, active, ",
                "(SELECT COUNT(*) FROM events WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after, before);
    crate::test_authority::remove_root(&root);
}

#[test]
fn authority_migration_requires_stopped_and_drained_complete_legacy_schema() {
    for (name, stopped, expect_success) in [
        ("authority-migration-stopped", true, true),
        ("authority-migration-unstopped", false, false),
    ] {
        let (root, service) = fixture(name);
        drop(service);
        let database = root.join("sandbox.sqlite3");
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("UPDATE service_state SET stopped = ?1", [stopped])
            .unwrap();
        connection
            .execute_batch(
                "ALTER TABLE runs DROP COLUMN authority_generation;
                 ALTER TABLE runs DROP COLUMN authority_manifest_digest;
                 ALTER TABLE tombstones DROP COLUMN authority_generation;
                 ALTER TABLE tombstones DROP COLUMN authority_manifest_digest;",
            )
            .unwrap();
        drop(connection);
        let opened = Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW);
        assert_eq!(opened.is_ok(), expect_success);
        crate::test_authority::remove_root(&root);
    }

    let (root, service) = fixture("authority-migration-non-drained");
    service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    drop(service);
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute("UPDATE service_state SET stopped = 1", [])
        .unwrap();
    connection
        .execute_batch(
            "ALTER TABLE runs DROP COLUMN authority_generation;
             ALTER TABLE runs DROP COLUMN authority_manifest_digest;
             ALTER TABLE tombstones DROP COLUMN authority_generation;
             ALTER TABLE tombstones DROP COLUMN authority_manifest_digest;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&root);
}

#[test]
fn authority_preflight_rejects_partial_and_malformed_schema_before_migration() {
    let (partial_root, partial_service) = fixture("authority-migration-partial");
    drop(partial_service);
    let partial_database = partial_root.join("sandbox.sqlite3");
    let partial = rusqlite::Connection::open(&partial_database).unwrap();
    partial
        .execute_batch("ALTER TABLE runs DROP COLUMN authority_generation;")
        .unwrap();
    drop(partial);
    assert!(matches!(
        Service::open_for_test(
            &partial_database,
            partial_root.join("receipts"),
            [7; 32],
            NOW
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&partial_root);

    let (root, service) = fixture("authority-real-preflight");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    drop(service);
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE runs SET authority_generation = CAST(1.5 AS REAL) WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();
    connection
        .execute_batch("ALTER TABLE runs DROP COLUMN cleanup_epoch;")
        .unwrap();
    drop(connection);
    assert!(matches!(
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW + 2),
        Err(ServiceError::Unavailable)
    ));
    let columns: Vec<String> = rusqlite::Connection::open(&database)
        .unwrap()
        .prepare("PRAGMA table_info(runs)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!columns.iter().any(|name| name == "cleanup_epoch"));
    crate::test_authority::remove_root(&root);
}

fn verify_target(
    service: &Service,
    lease: &DispatchLease,
    namespace_uid: &str,
    now_unix_s: i64,
) -> ProvisioningSpecification {
    let specification = service
        .provisioning_specification(lease, now_unix_s)
        .unwrap();
    let (boundary, behavior_records) = Service::cluster_boundary_specification().unwrap();
    let boundary = crate::ClusterBoundaryObservation {
        objects: boundary
            .into_iter()
            .enumerate()
            .map(|(index, object)| {
                let mut body = object.canonical_body;
                body["metadata"]["uid"] = serde_json::json!(format!("boundary-{index}"));
                body["metadata"]["resourceVersion"] = serde_json::json!("17");
                crate::ObservedPolicyObject { body }
            })
            .collect(),
        behavior_records,
    };
    let run_objects = specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let mut body = object.canonical_body.clone();
            body["metadata"]["uid"] = serde_json::json!(if index == 0 {
                namespace_uid.to_owned()
            } else {
                format!("{namespace_uid}-object-{index}")
            });
            body["metadata"]["resourceVersion"] = serde_json::json!("17");
            crate::ObservedPolicyObject { body }
        })
        .collect();
    service
        .verify_observed_cluster(
            lease,
            &crate::ObservedClusterComposition {
                boundary,
                run_objects,
                generated_children: Vec::new(),
                owned_orphans: Vec::new(),
            },
            now_unix_s,
        )
        .unwrap();
    specification
}

fn provisioned_objects(
    specification: &ProvisioningSpecification,
    namespace_uid: &str,
) -> Vec<ProvisionedObject> {
    specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| ProvisionedObject {
            identity: object.identity.clone(),
            uid: if index == 0 {
                namespace_uid.to_owned()
            } else {
                format!("{namespace_uid}-object-{index}")
            },
            owner_label: specification.cleanup_identity.clone(),
            content_digest: object.content_digest.clone(),
        })
        .collect()
}

fn cleanup_absence_from_database(
    database: &Path,
    run_id: &str,
    namespace_uid: &str,
) -> CleanupAbsenceEvidence {
    let connection = rusqlite::Connection::open(database).unwrap();
    let plan_digest = "a".repeat(64);
    let observation_id = format!("observation-{run_id}");
    connection
        .execute(
            concat!(
                "UPDATE runs SET cleanup_attempt = cleanup_attempt + 1, ",
                "cleanup_plan_digest = ?2, cleanup_plan_issued = 1, ",
                "cleanup_pending_observation_id = ?3 WHERE run_id = ?1"
            ),
            rusqlite::params![run_id, plan_digest, observation_id],
        )
        .unwrap();
    let cleanup_attempt = connection
        .query_row(
            "SELECT cleanup_attempt FROM runs WHERE run_id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut statement = connection
        .prepare(
            "SELECT identity, uid, owner_label FROM provisioned_object_owners WHERE run_id = ?1",
        )
        .unwrap();
    let objects = statement
        .query_map([run_id], |row| {
            let identity = row.get::<_, String>(0)?;
            let parts = identity.split('/').collect::<Vec<_>>();
            let (kind, namespace, name) = match parts.as_slice() {
                ["Namespace", name] => ("Namespace".to_owned(), None, (*name).to_owned()),
                [kind, namespace, name] => (
                    (*kind).to_owned(),
                    Some((*namespace).to_owned()),
                    (*name).to_owned(),
                ),
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(CleanupObjectAbsence {
                kind,
                namespace,
                name,
                uid: row.get(1)?,
                owner_label: row.get(2)?,
                present: false,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    CleanupAbsenceEvidence {
        namespace_uid: namespace_uid.to_owned(),
        cleanup_epoch: format!("cleanup-{run_id}-1"),
        cleanup_attempt,
        plan_digest,
        observation_id,
        objects,
        owned_orphans: Vec::new(),
    }
}

fn application_configuration(
    root: &Path,
    run_id: &str,
    scenario: Scenario,
) -> (
    OperatorConfiguration,
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
) {
    let operation_id = format!("sandbox-{run_id}");
    let image = match scenario {
        Scenario::Healthy => concat!(
            "registry.k8s.io/pause@sha256:",
            "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
        ),
        Scenario::UnavailableImage => concat!(
            "registry.k8s.io/pause@sha256:",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    };
    let request = kapsel::AgentRequest {
        operation_id: operation_id.clone(),
        namespace: format!("sandbox-{run_id}"),
        deployment: "sandbox-target".into(),
        container: "target".into(),
        immutable_image_digest: image.into(),
    };
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        authorization_id: format!("auth-{run_id}"),
        operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "sandbox-authorization-key",
    })
    .unwrap();
    let journal_root = root.join(run_id);
    if !journal_root.exists() {
        private_directory(&journal_root);
        private_directory(&journal_root.join("gateway-receipts"));
    }
    let (transport, handle) = mock::pair();
    (
        OperatorConfiguration {
            journal_path: fs::canonicalize(&journal_root)
                .unwrap()
                .join("journal.sqlite3"),
            receipt_output_directory: fs::canonicalize(journal_root.join("gateway-receipts"))
                .unwrap(),
            authorization_trust: AuthorizationTrust {
                key_id: "sandbox-authorization-key".into(),
                public_key: authorization_key.verifying_key().to_bytes(),
            },
            signed_authorization_grant: grant,
            kubernetes_client: kube::Client::new(transport, "sandbox"),
            receipt_signing_seed: [42; 32],
            receipt_signing_key_id: "sandbox-receipt-key".into(),
        },
        handle,
    )
}

#[test]
fn raw_seed_known_answer_is_pure_ed25519() {
    let seed = hex_bytes::<32>(
        "9d61b19deffd5a60ba844af492ec2cc4\
         4449c5697b326919703bac031cae7f60",
    );
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        hex_bytes::<32>(
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a"
        )
    );
    assert_eq!(
        signing_key.sign(b"").to_bytes(),
        hex_bytes::<64>(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b"
        )
    );
}

fn hex_bytes<const N: usize>(value: &str) -> [u8; N] {
    let value = value.replace([' ', '\n'], "");
    assert_eq!(value.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

#[test]
fn database_entry_rejects_symlink_and_permissive_file_before_sqlite_open() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-database-entry-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    private_directory(&root.join("receipts"));
    let database = root.join("sandbox.sqlite3");
    let target = root.join("redirect-target");
    fs::write(&target, b"must remain unchanged").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &database).unwrap();
    assert!(matches!(
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW),
        Err(ServiceError::Unavailable)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"must remain unchanged");
    fs::remove_file(&database).unwrap();
    fs::remove_file(&target).unwrap();

    fs::write(&database, []).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW),
        Err(ServiceError::Unavailable)
    ));
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::remove_file(&database).unwrap();
    Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW).unwrap();
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn admission_is_durable_idempotent_stopped_and_bounded() {
    let (root, service) = fixture("admission");
    let database = root.join("sandbox.sqlite3");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    assert_eq!(first.disposition, AdmissionDisposition::Created);
    drop(service);

    let service =
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW + 1).unwrap();
    let replay = service.admit(&key(1), Scenario::Healthy, NOW + 1).unwrap();
    assert_eq!(replay.disposition, AdmissionDisposition::Replayed);
    assert_eq!(replay.run_id, first.run_id);
    assert_eq!(
        service.admit(&key(1), Scenario::UnavailableImage, NOW + 1),
        Err(ServiceError::IdempotencyConflict)
    );
    service.set_global_stop(true).unwrap();
    assert_eq!(
        service.admit(&key(2), Scenario::Healthy, NOW + 1),
        Err(ServiceError::Unavailable)
    );
    assert_eq!(
        service
            .admit(&key(1), Scenario::Healthy, NOW + 1)
            .unwrap()
            .run_id,
        first.run_id
    );
    service.set_global_stop(false).unwrap();
    for index in 2..=32 {
        service.admit(&key(index), Scenario::Healthy, NOW).unwrap();
    }
    assert_eq!(
        service.admit(&key(33), Scenario::Healthy, NOW),
        Err(ServiceError::CapacitySaturated)
    );
    assert_eq!(
        service
            .dispatch_next(NOW + 2, &test_authority_identity())
            .unwrap()
            .run_id,
        first.run_id
    );
    assert_eq!(
        service.dispatch_next(NOW + 2, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn reopen_rejects_more_than_one_durable_active_reservation() {
    let (root, service) = fixture("historical-active-overflow");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let second = service.admit(&key(2), Scenario::Healthy, NOW + 1).unwrap();
    assert_eq!(
        service
            .dispatch_next(NOW + 2, &test_authority_identity())
            .unwrap()
            .run_id,
        first.run_id
    );
    drop(service);
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            concat!(
                "UPDATE runs SET active = 1, execution_state = 'running', dispatched_at = ?2, ",
                "deadline_at = ?3, lease_id = 'historical-overflow', lease_epoch = 1, ",
                "lease_expires_at = ?4 WHERE run_id = ?1"
            ),
            rusqlite::params![second.run_id, NOW + 2, NOW + 182, NOW + 32],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE cleanup_records SET active = 1 WHERE run_id = ?1",
            [&second.run_id],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Service::open_for_test(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW + 3,
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&root);
}

#[test]
fn corrupt_capacity_state_fails_closed_on_reopen_and_dispatch() {
    let (missing_root, missing_service) = fixture("missing-capacity-row");
    let missing = missing_service
        .admit(&key(1), Scenario::Healthy, NOW)
        .unwrap();
    rusqlite::Connection::open(missing_root.join("sandbox.sqlite3"))
        .unwrap()
        .execute(
            "DELETE FROM cleanup_records WHERE run_id = ?1",
            [&missing.run_id],
        )
        .unwrap();
    assert_eq!(
        missing_service.dispatch_next(NOW + 1, &test_authority_identity()),
        Err(ServiceError::Unavailable)
    );
    let state: (String, bool) = rusqlite::Connection::open(missing_root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT execution_state, active FROM runs WHERE run_id = ?1",
            [&missing.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("queued".into(), false));
    drop(missing_service);
    assert!(matches!(
        Service::open_for_test(
            missing_root.join("sandbox.sqlite3"),
            missing_root.join("receipts"),
            [7; 32],
            NOW + 1,
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&missing_root);

    let (noncanonical_root, noncanonical_service) = fixture("noncanonical-capacity");
    let noncanonical = noncanonical_service
        .admit(&key(1), Scenario::Healthy, NOW)
        .unwrap();
    drop(noncanonical_service);
    let connection = rusqlite::Connection::open(noncanonical_root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE runs SET active = 2 WHERE run_id = ?1",
            [&noncanonical.run_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE cleanup_records SET active = 2 WHERE run_id = ?1",
            [&noncanonical.run_id],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        Service::open_for_test(
            noncanonical_root.join("sandbox.sqlite3"),
            noncanonical_root.join("receipts"),
            [7; 32],
            NOW + 1,
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&noncanonical_root);
}

#[test]
fn corrupt_capacity_variants_and_late_update_rollback_are_rejected() {
    let (orphan_root, orphan_service) = fixture("orphan-capacity-row");
    drop(orphan_service);
    rusqlite::Connection::open(orphan_root.join("sandbox.sqlite3"))
        .unwrap()
        .execute(
            concat!(
                "INSERT INTO cleanup_records VALUES ",
                "('orphan', 'cleanup-orphan', NULL, 'unverified', 'pending', 0, 0, NULL, 0)"
            ),
            [],
        )
        .unwrap();
    assert!(matches!(
        Service::open_for_test(
            orphan_root.join("sandbox.sqlite3"),
            orphan_root.join("receipts"),
            [7; 32],
            NOW + 1,
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&orphan_root);

    let (mismatch_root, mismatch_service) = fixture("mismatched-capacity-row");
    let mismatch = mismatch_service
        .admit(&key(1), Scenario::Healthy, NOW)
        .unwrap();
    mismatch_service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    drop(mismatch_service);
    rusqlite::Connection::open(mismatch_root.join("sandbox.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE cleanup_records SET active = 0 WHERE run_id = ?1",
            [&mismatch.run_id],
        )
        .unwrap();
    assert!(matches!(
        Service::open_for_test(
            mismatch_root.join("sandbox.sqlite3"),
            mismatch_root.join("receipts"),
            [7; 32],
            NOW + 2,
        ),
        Err(ServiceError::Unavailable)
    ));
    crate::test_authority::remove_root(&mismatch_root);

    let (rollback_root, rollback_service) = fixture("capacity-update-rollback");
    let rollback = rollback_service
        .admit(&key(1), Scenario::Healthy, NOW)
        .unwrap();
    rusqlite::Connection::open(rollback_root.join("sandbox.sqlite3"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER ignore_cleanup_activation BEFORE UPDATE OF active ON cleanup_records
             WHEN NEW.active = 1 BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    assert_eq!(
        rollback_service.dispatch_next(NOW + 1, &test_authority_identity()),
        Err(ServiceError::Unavailable)
    );
    let state: (String, bool, bool) =
        rusqlite::Connection::open(rollback_root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                concat!(
                    "SELECT runs.execution_state, runs.active, cleanup_records.active FROM runs ",
                    "JOIN cleanup_records ON cleanup_records.run_id = runs.run_id ",
                    "WHERE runs.run_id = ?1"
                ),
                [&rollback.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(state, ("queued".into(), false, false));
    crate::test_authority::remove_root(&rollback_root);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one authority test keeps the before-mutation database evidence contiguous"
)]
fn cleanup_authority_mismatch_and_unrelated_corruption_hold_before_transition() {
    let (root, service) = fixture("cleanup-authority-hold");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let pinned = test_authority_identity();
    service.dispatch_next(NOW + 1, &pinned).unwrap();
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            concat!(
                "UPDATE runs SET provisioning_closed = 1, runner_revoked = 1, ",
                "runner_process_absent = 1, journal_handoff = 1, runner_state_retired = 1, ",
                "cleanup_resource_state = 'owned', cleanup_state = 'pending' WHERE run_id = ?1"
            ),
            [&admission.run_id],
        )
        .unwrap();
    connection
        .execute(
            concat!(
                "UPDATE cleanup_records SET namespace_uid = 'namespace-uid', ",
                "resource_state = 'owned', state = 'pending', active = 1, eligible = 1 ",
                "WHERE run_id = ?1"
            ),
            [&admission.run_id],
        )
        .unwrap();
    let cleanup = CleanupRole::new(service.clone());
    let before: (String, i64) = connection
        .query_row(
            concat!(
                "SELECT cleanup_records.state, runs.last_sequence FROM cleanup_records ",
                "JOIN runs ON runs.run_id = cleanup_records.run_id WHERE runs.run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        cleanup.next(NOW + 2, &authority_identity(8, "cd")),
        Err(ServiceError::Unavailable)
    );
    let after_wrong: (String, i64) = connection
        .query_row(
            concat!(
                "SELECT cleanup_records.state, runs.last_sequence FROM cleanup_records ",
                "JOIN runs ON runs.run_id = cleanup_records.run_id WHERE runs.run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(after_wrong, before);
    connection
        .execute(
            "UPDATE cleanup_records SET state = 'running', started_at = ?2 WHERE run_id = ?1",
            rusqlite::params![admission.run_id, NOW + 2],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runs SET cleanup_state = 'running' WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();

    let unrelated = service.admit(&key(2), Scenario::Healthy, NOW + 2).unwrap();
    connection
        .execute(
            "UPDATE runs SET authority_generation = CAST(1.5 AS REAL) WHERE run_id = ?1",
            [&unrelated.run_id],
        )
        .unwrap();
    let running_before: (String, i64) = connection
        .query_row(
            concat!(
                "SELECT cleanup_records.state, runs.last_sequence FROM cleanup_records ",
                "JOIN runs ON runs.run_id = cleanup_records.run_id WHERE runs.run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        cleanup.next(NOW + 3, &pinned),
        Err(ServiceError::Unavailable)
    );
    connection
        .execute(
            "UPDATE runs SET authority_generation = NULL WHERE run_id = ?1",
            [&unrelated.run_id],
        )
        .unwrap();
    connection
        .execute(
            concat!(
                "INSERT INTO tombstones (run_digest, key_digest, delete_at, ",
                "authority_generation, authority_manifest_digest) ",
                "VALUES ('run-digest', 'key-digest', ?1, CAST(1.5 AS REAL), ?2)"
            ),
            rusqlite::params![NOW + 1000, "ef".repeat(32)],
        )
        .unwrap();
    assert_eq!(
        cleanup.next(NOW + 3, &pinned),
        Err(ServiceError::Unavailable)
    );
    let running_after: (String, i64) = connection
        .query_row(
            concat!(
                "SELECT cleanup_records.state, runs.last_sequence FROM cleanup_records ",
                "JOIN runs ON runs.run_id = cleanup_records.run_id WHERE runs.run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(running_after, running_before);
    crate::test_authority::remove_root(&root);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one role test keeps serialized scheduling and exact cleanup evidence contiguous"
)]
fn local_roles_recover_before_dispatch_and_release_only_after_exact_cleanup() {
    let (root, service) = fixture("local-roles");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let second = service
        .admit(&key(2), Scenario::UnavailableImage, NOW + 1)
        .unwrap();
    let mut scheduler = SchedulerRole::new(service.clone());
    let first_lease = match scheduler
        .run_once(NOW + 2, Some(&test_authority_identity()))
        .unwrap()
    {
        SchedulerStep::Dispatched(lease) => lease,
        other => panic!("unexpected scheduler step: {other:?}"),
    };
    assert_eq!(first_lease.run_id, first.run_id);
    assert!(matches!(
        scheduler
            .run_once(NOW + 3, Some(&test_authority_identity()))
            .unwrap(),
        SchedulerStep::Active(_)
    ));

    let mut restarted_scheduler = SchedulerRole::new(service.clone());
    assert_eq!(
        restarted_scheduler
            .run_once(NOW + 3, Some(&test_authority_identity()))
            .unwrap(),
        SchedulerStep::Waiting
    );
    let recovered = match restarted_scheduler
        .run_once(NOW + 33, Some(&test_authority_identity()))
        .unwrap()
    {
        SchedulerStep::Recovered(lease) => lease,
        other => panic!("unexpected scheduler recovery: {other:?}"),
    };
    let specification = verify_target(&service, &recovered, "local-role-namespace-uid", NOW + 33);
    service
        .record_setup_failure(&recovered, &specification.cleanup_identity, NOW + 34)
        .unwrap();

    RetentionRole::new(service.clone())
        .run_once(NOW + 35)
        .unwrap();
    let cleanup = CleanupRole::new(service.clone());
    let work = cleanup
        .next(NOW + 35, &test_authority_identity())
        .unwrap()
        .unwrap();
    assert_eq!(work.run_id, first.run_id);
    assert_eq!(work.cleanup_identity, specification.cleanup_identity);
    assert_eq!(work.namespace_uid, "local-role-namespace-uid");
    assert!(!work.escalated);
    assert_eq!(
        restarted_scheduler
            .run_once(NOW + 35, Some(&test_authority_identity()))
            .unwrap(),
        SchedulerStep::Active(recovered.clone())
    );
    cleanup.fail(&work, NOW + 36).unwrap();
    cleanup.fail(&work, NOW + 37).unwrap();
    assert_eq!(
        restarted_scheduler
            .run_once(NOW + 36, Some(&test_authority_identity()))
            .unwrap(),
        SchedulerStep::Active(recovered)
    );
    assert!(
        !cleanup
            .next(NOW + 934, &test_authority_identity())
            .unwrap()
            .unwrap()
            .escalated
    );
    assert!(
        cleanup
            .next(NOW + 935, &test_authority_identity())
            .unwrap()
            .unwrap()
            .escalated
    );
    assert!(
        cleanup
            .next(NOW + 936, &test_authority_identity())
            .unwrap()
            .unwrap()
            .escalated
    );

    let exact_absence = cleanup_absence_from_database(
        &root.join("sandbox.sqlite3"),
        &first.run_id,
        "local-role-namespace-uid",
    );
    service
        .complete_cleanup(
            &work.run_id,
            &work.cleanup_identity,
            &exact_absence,
            NOW + 37,
        )
        .unwrap();
    let second_lease = match restarted_scheduler
        .run_once(NOW + 37, Some(&test_authority_identity()))
        .unwrap()
    {
        SchedulerStep::Dispatched(lease) => lease,
        other => panic!("unexpected second dispatch: {other:?}"),
    };
    assert_eq!(second_lease.run_id, second.run_id);
    crate::test_authority::remove_root(&root);
}

#[test]
fn queued_age_does_not_consume_dispatch_window_or_block_fair_order() {
    let (root, service) = fixture("queued-dispatch-deadline");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let second = service.admit(&key(2), Scenario::Healthy, NOW + 10).unwrap();
    let third = service.admit(&key(3), Scenario::Healthy, NOW + 20).unwrap();
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    let admitted: (i64, Option<i64>, String, String) = connection
        .query_row(
            concat!(
                "SELECT deadline_seconds, deadline_at, policy_inventory, ",
                "policy_inventory_digest FROM runs WHERE run_id = ?1"
            ),
            [&first.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(admitted.0, 180);
    assert_eq!(admitted.1, None);
    assert!(!admitted.2.is_empty());
    assert_eq!(admitted.3.len(), 64);
    let inventory: serde_json::Value = serde_json::from_str(&admitted.2).unwrap();
    let identities = inventory
        .as_array()
        .unwrap()
        .iter()
        .map(|object| object["identity"].as_str().unwrap())
        .collect::<Vec<_>>();
    let runner_identity = format!("Role/sandbox-{}/sandbox-runner", first.run_id);
    let binding_identity = format!("RoleBinding/sandbox-{}/sandbox-runner", first.run_id);
    assert!(identities.contains(&runner_identity.as_str()));
    assert!(identities.contains(&binding_identity.as_str()));

    let first_lease = service
        .dispatch_next(NOW + 1_000, &test_authority_identity())
        .unwrap();
    assert_eq!(first_lease.run_id, first.run_id);
    let first_specification = service
        .provisioning_specification(&first_lease, NOW + 1_000)
        .unwrap();
    assert_eq!(first_specification.deadline_at_unix_s, NOW + 1_180);
    service
        .record_setup_failure_without_resources(
            &first_lease,
            &first_specification.cleanup_identity,
            NOW + 1_000,
        )
        .unwrap();
    let second_lease = service
        .dispatch_next(NOW + 1_001, &test_authority_identity())
        .unwrap();
    assert_eq!(second_lease.run_id, second.run_id);
    let second_specification = service
        .provisioning_specification(&second_lease, NOW + 1_001)
        .unwrap();
    assert_eq!(second_specification.deadline_at_unix_s, NOW + 1_181);
    service
        .record_setup_failure_without_resources(
            &second_lease,
            &second_specification.cleanup_identity,
            NOW + 1_001,
        )
        .unwrap();
    let third_lease = service
        .dispatch_next(NOW + 1_002, &test_authority_identity())
        .unwrap();
    assert_eq!(third_lease.run_id, third.run_id);
    assert_eq!(
        service
            .provisioning_specification(&third_lease, NOW + 1_002)
            .unwrap()
            .deadline_at_unix_s,
        NOW + 1_182
    );
    crate::test_authority::remove_root(&root);
}

#[test]
fn serialized_dispatch_waits_for_prior_object_absence() {
    let (root, service) = fixture("serialized-prior-absence");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let second = service.admit(&key(2), Scenario::Healthy, NOW + 1).unwrap();
    let first_lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    let specification = verify_target(&service, &first_lease, "prior-namespace-uid", NOW + 1);
    service
        .record_setup_failure(&first_lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    service
        .start_cleanup(
            &first.run_id,
            &specification.cleanup_identity,
            "prior-namespace-uid",
            &test_authority_identity(),
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        service.dispatch_next(NOW + 3, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );

    let exact_absence = cleanup_absence_from_database(
        &root.join("sandbox.sqlite3"),
        &first.run_id,
        "prior-namespace-uid",
    );
    let mut still_present = exact_absence.clone();
    still_present.objects[4].present = true;
    assert_eq!(
        service.complete_cleanup(
            &first.run_id,
            &specification.cleanup_identity,
            &still_present,
            NOW + 4,
        ),
        Err(ServiceError::InvalidTransition)
    );
    assert_eq!(
        service.dispatch_next(NOW + 4, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    service
        .complete_cleanup(
            &first.run_id,
            &specification.cleanup_identity,
            &exact_absence,
            NOW + 5,
        )
        .unwrap();
    assert_eq!(
        service
            .dispatch_next(NOW + 5, &test_authority_identity())
            .unwrap()
            .run_id,
        second.run_id
    );
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test preserves policy evidence, rejection, and cleanup restart proof"
)]
async fn application_rejection_and_cleanup_remain_separate_across_restart() {
    let (root, service) = fixture("application");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let queued = service
        .admit(&key(2), Scenario::UnavailableImage, NOW + 1)
        .unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    assert_eq!(
        service.dispatch_next(NOW + 1, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    assert_eq!(lease.run_id, admission.run_id);
    assert_eq!(
        service.recoverable_runs().unwrap().as_slice(),
        std::slice::from_ref(&admission.run_id)
    );
    let specification = verify_target(&service, &lease, "namespace-uid-1", NOW + 1);
    let stored_objects: String = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT provisioned_objects FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<ProvisionedObject>>(&stored_objects).unwrap(),
        provisioned_objects(&specification, "namespace-uid-1")
    );
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let responder = tokio::spawn(async move {
        let (_, send) = handle.next_request().await.unwrap();
        send.send_response(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "reason": "NotFound",
                        "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    let report = service
        .execute_application(&lease, configuration, NOW + 2)
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(report.execution_state, ExecutionState::NotAttempted);
    assert_eq!(
        report.target_rejection.as_deref(),
        Some("DEPLOYMENT_NOT_FOUND")
    );

    let before = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(before.execution_state, ExecutionState::NotAttempted);
    assert_eq!(before.receiver_result, None);
    assert_eq!(before.cleanup_state, CleanupState::Pending);
    assert_eq!(
        service.dispatch_next(NOW + 3, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    assert_eq!(
        service.start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "other-uid",
            &test_authority_identity(),
            NOW + 3,
        ),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "namespace-uid-1",
            &test_authority_identity(),
            NOW + 3,
        )
        .unwrap();
    service
        .fail_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "namespace-uid-1",
            NOW + 4,
        )
        .unwrap();
    let failed = service.snapshot(&admission.run_id, NOW + 4).unwrap();
    assert_eq!(failed.cleanup_state, CleanupState::Failed);
    assert_eq!(failed.receiver_result, None);
    assert_eq!(
        service.dispatch_next(NOW + 4, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 5,
    )
    .unwrap();
    assert_eq!(
        service.dispatch_next(NOW + 5, &test_authority_identity()),
        Err(ServiceError::ActiveSaturated)
    );
    let assert_mismatch = |evidence: &CleanupAbsenceEvidence| {
        assert_eq!(
            service.complete_cleanup(
                &admission.run_id,
                &specification.cleanup_identity,
                evidence,
                NOW + 5,
            ),
            Err(ServiceError::OwnershipMismatch)
        );
    };
    let exact_absence = cleanup_absence_from_database(
        &root.join("sandbox.sqlite3"),
        &admission.run_id,
        "namespace-uid-1",
    );
    let mut wrong_kind = exact_absence.clone();
    wrong_kind.objects[2].kind = "OtherKind".into();
    assert_mismatch(&wrong_kind);
    let mut wrong_namespace = exact_absence.clone();
    wrong_namespace.objects[2].namespace = Some("other-namespace".into());
    assert_mismatch(&wrong_namespace);
    let mut wrong_name = exact_absence.clone();
    wrong_name.objects[2].name = "other-name".into();
    assert_mismatch(&wrong_name);
    let mut wrong_uid = exact_absence.clone();
    wrong_uid.objects[2].uid = "other-object-uid".into();
    assert_mismatch(&wrong_uid);
    let mut wrong_owner = exact_absence.clone();
    wrong_owner.objects[2].owner_label = "cleanup-other".into();
    assert_mismatch(&wrong_owner);
    let mut still_present = exact_absence.clone();
    still_present.objects[7].present = true;
    assert_eq!(
        service.complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &still_present,
            NOW + 5,
        ),
        Err(ServiceError::InvalidTransition)
    );
    let mut missing = exact_absence.clone();
    missing.objects.pop();
    assert_eq!(
        service.complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &missing,
            NOW + 5,
        ),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &exact_absence,
            NOW + 5,
        )
        .unwrap();
    let terminal = service.snapshot(&admission.run_id, NOW + 5).unwrap();
    assert_eq!(terminal.execution_state, ExecutionState::NotAttempted);
    assert_eq!(terminal.cleanup_state, CleanupState::Succeeded);
    assert!(!terminal.receipt_available);
    assert!(service.recoverable_runs().unwrap().is_empty());
    assert_eq!(
        service
            .dispatch_next(NOW + 5, &test_authority_identity())
            .unwrap()
            .run_id,
        queued.run_id
    );
    let verifier: Vec<u8> = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT handoff_credential_verifier FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(verifier.is_empty());
    let page = service.events(&admission.run_id, 0, 64, NOW + 5).unwrap();
    assert_eq!(page.events.len(), 6);
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
async fn pre_submit_marker_crash_submits_same_request_on_reconciliation() {
    let (root, service) = fixture("pre-submit-crash");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    verify_target(&service, &lease, "pre-submit-namespace-uid", NOW + 1);
    let database = root.join("sandbox.sqlite3");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE runs SET application_invoked = 1 WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();
    assert!(!root.join(&admission.run_id).exists());
    drop(service);

    let service =
        Service::open_for_test(&database, root.join("receipts"), [7; 32], NOW + 2).unwrap();
    let recovered = service
        .recover_run(&admission.run_id, Some(&lease), NOW + 2)
        .unwrap();
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    let terminal = service
        .reconcile_application(&recovered, configuration, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    responder.await.unwrap();
    assert_eq!(terminal.operation_id, admission.operation_id);
    assert_eq!(terminal.execution_state, ExecutionState::NotAttempted);
    assert_eq!(
        terminal.target_rejection.as_deref(),
        Some("DEPLOYMENT_NOT_FOUND")
    );
    let page = service.events(&admission.run_id, 0, 64, NOW + 2).unwrap();
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.target_rejection.as_deref() == Some("DEPLOYMENT_NOT_FOUND"))
            .count(),
        1
    );
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test proves cancellation at provider ambiguity and lease recovery"
)]
async fn uncertain_invocation_recovers_with_one_mutation_and_same_operation() {
    let (root, service) = fixture("uncertain-invocation");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    verify_target(&service, &lease, "uncertain-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let target = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": old_image}]}}},
        "status": {"observedGeneration": 1}
    });
    let patched = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": image}]}}}
    });
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&target).unwrap(),
                ))
                .unwrap(),
        );
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::PATCH);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&patched).unwrap(),
                ))
                .unwrap(),
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });
    let interrupted = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        service.execute_application(&lease, configuration, NOW + 2),
    )
    .await;
    assert!(interrupted.is_err());
    responder.abort();
    let running = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(running.execution_state, ExecutionState::Running);
    assert_eq!(running.receiver_result, None);
    service
        .record_deadline(&admission.run_id, NOW + 181)
        .unwrap();
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 182,
    )
    .unwrap();
    let recovered_lease = service
        .recover_run(&admission.run_id, None, NOW + 182)
        .unwrap();
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let observed = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
            "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": image}]}}},
        "status": {"observedGeneration": 2, "updatedReplicas": 1,
            "availableReplicas": 1, "unavailableReplicas": 0,
            "conditions": [{"type": "Available", "status": "True",
                "reason": "MinimumReplicasAvailable"}]}
    });
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&observed).unwrap(),
                ))
                .unwrap(),
        );
    });
    let terminal = service
        .reconcile_application(&recovered_lease, configuration, NOW + 182)
        .await
        .unwrap()
        .unwrap();
    responder.await.unwrap();
    assert_eq!(terminal.operation_id, admission.operation_id);
    assert_eq!(terminal.receiver_result.as_deref(), Some("SUCCEEDED"));
    let receipt = service.receipt(&admission.run_id, NOW + 183).unwrap();
    let page = service.events(&admission.run_id, 0, 64, NOW + 183).unwrap();
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    drop(service);
    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 184,
    )
    .unwrap();
    assert_eq!(
        service.receipt(&admission.run_id, NOW + 184).unwrap(),
        receipt
    );
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test keeps the Application, receipt, and restart proof contiguous"
)]
async fn report_and_receipt_reference_crash_recovers_exact_bytes() {
    let (root, service) = fixture("healthy-application");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    verify_target(&service, &lease, "healthy-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let responses = vec![
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}},
            "status": {"observedGeneration": 2, "updatedReplicas": 1,
                "availableReplicas": 1, "unavailableReplicas": 0,
                "conditions": [{"type": "Available", "status": "True",
                    "reason": "MinimumReplicasAvailable"}]}
        }),
    ];
    let responder = tokio::spawn(async move {
        for body in responses {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        }
    });
    let database = root.join("sandbox.sqlite3");
    let receipt_directory = root.join("receipts");
    let held_receipt_directory = root.join("receipts-held");
    fs::rename(&receipt_directory, &held_receipt_directory).unwrap();
    fs::write(&receipt_directory, b"block receipt object creation").unwrap();
    assert!(matches!(
        service
            .execute_application(&lease, configuration, NOW + 2)
            .await,
        Err(crate::RunError::Handoff(crate::HandoffError::Rejected))
    ));
    responder.await.unwrap();
    fs::remove_file(&receipt_directory).unwrap();
    fs::rename(&held_receipt_directory, &receipt_directory).unwrap();
    let snapshot = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::Terminal);
    assert_eq!(snapshot.receiver_result.as_deref(), Some("SUCCEEDED"));
    assert!(!snapshot.receipt_available);

    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch(concat!(
            "CREATE TRIGGER fail_receipt_reference BEFORE INSERT ON receipts ",
            "BEGIN SELECT RAISE(ABORT, 'injected receipt reference crash'); END;"
        ))
        .unwrap();
    let (configuration, _unused_handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    assert!(matches!(
        service
            .reconcile_application(&lease, configuration, NOW + 3)
            .await,
        Err(crate::RunError::Handoff(crate::HandoffError::Rejected))
    ));
    let receipt_path = fs::read_dir(&receipt_directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "receipt")
        })
        .unwrap();
    let object_bytes_before_recovery = fs::read(&receipt_path).unwrap();
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_receipt_reference;")
        .unwrap();
    service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert!(receipt_path.exists());
    let pending_publication: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending_publication, 1);
    drop(service);

    let service = Service::open_for_test(&database, &receipt_directory, [7; 32], NOW + 4).unwrap();
    let (configuration, _unused_handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let recovered = service
        .reconcile_application(&lease, configuration, NOW + 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.execution_state, ExecutionState::Terminal);
    assert_eq!(recovered.operation_id, admission.operation_id);
    assert_eq!(recovered.receiver_result.as_deref(), Some("SUCCEEDED"));
    let receipt = service.receipt(&admission.run_id, NOW + 4).unwrap();
    assert_eq!(receipt, object_bytes_before_recovery);
    let page = service.events(&admission.run_id, 0, 64, NOW + 4).unwrap();
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.kind == "execution.terminal")
            .count(),
        1
    );
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.kind == "receipt.available")
            .count(),
        1
    );
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test proves the fixed unavailable-image Application classification"
)]
async fn unavailable_image_application_preserves_failed_receiver_result() {
    let (root, service) = fixture("unavailable-application");
    let admission = service
        .admit(&key(1), Scenario::UnavailableImage, NOW)
        .unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    verify_target(&service, &lease, "unavailable-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::UnavailableImage);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let responses = vec![
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}},
            "status": {"observedGeneration": 2, "updatedReplicas": 1,
                "availableReplicas": 0, "unavailableReplicas": 1,
                "conditions": [{"type": "Progressing", "status": "False",
                    "reason": "ProgressDeadlineExceeded"}]}
        }),
    ];
    let responder = tokio::spawn(async move {
        for body in responses {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        }
    });
    let snapshot = service
        .execute_application(&lease, configuration, NOW + 2)
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::Terminal);
    assert_eq!(snapshot.receiver_result.as_deref(), Some("FAILED"));
    assert!(snapshot.receipt_available);
    let receipt = service.receipt(&admission.run_id, NOW + 3).unwrap();
    let receipt_seed = [42_u8; 32];
    let trust = ReceiptTrust {
        key_id: "sandbox-receipt-key".into(),
        public_key: SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: NOW - 1,
        not_after_unix_s: NOW + 100,
    }
    .encode()
    .unwrap();
    let inspection = inspect_receipt(&receipt, &trust, NOW + 3, InspectionLimits::default());
    assert_eq!(inspection.status(), InspectionStatus::Inspected);
    assert_eq!(
        inspection.statement().unwrap().result(),
        kapsel::OperationResult::Failed
    );
    let gateway_receipt = fs::read(
        fs::read_dir(root.join(&admission.run_id).join("gateway-receipts"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();
    assert_eq!(gateway_receipt, receipt);
    crate::test_authority::remove_root(&root);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one test keeps policy mismatch, lease recovery, and deadline proof together"
)]
async fn policy_deadline_and_scheduler_lease_fail_closed_before_application() {
    let (root, service) = fixture("policy-lease");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    assert_eq!(specification.policy_revision, "sandbox-policy-v3");
    assert_eq!(specification.deadline_seconds, 180);
    assert_eq!(specification.deadline_at_unix_s, NOW + 181);
    assert_eq!(specification.required_objects.len(), 10);
    assert_eq!(
        specification.required_objects[0].identity,
        format!("Namespace/sandbox-{}", admission.run_id)
    );
    assert_eq!(
        specification.required_objects[1].identity,
        format!("ServiceAccount/sandbox-{}/sandbox-target", admission.run_id)
    );
    assert_eq!(
        specification.required_objects[2].identity,
        format!("Role/sandbox-{}/sandbox-runner", admission.run_id)
    );
    assert_eq!(
        service.recover_run(&admission.run_id, None, NOW + 2),
        Err(ServiceError::LeaseBusy)
    );
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 2,
    )
    .unwrap();
    let recovered = service
        .recover_run(&admission.run_id, Some(&lease), NOW + 2)
        .unwrap();
    let recovered_specification = service
        .provisioning_specification(&recovered, NOW + 2)
        .unwrap();
    assert_eq!(recovered_specification, specification);
    assert_eq!(
        service.provisioning_specification(&lease, NOW + 2),
        Err(ServiceError::LeaseBusy)
    );
    let (boundary_objects, behavior_records) = Service::cluster_boundary_specification().unwrap();
    let boundary = crate::ClusterBoundaryObservation {
        objects: boundary_objects
            .into_iter()
            .enumerate()
            .map(|(index, object)| {
                let mut body = object.canonical_body;
                body["metadata"]["uid"] = serde_json::json!(format!("boundary-{index}"));
                body["metadata"]["resourceVersion"] = serde_json::json!("17");
                crate::ObservedPolicyObject { body }
            })
            .collect(),
        behavior_records,
    };
    let mut run_objects = specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let mut body = object.canonical_body.clone();
            body["metadata"]["uid"] = serde_json::json!(if index == 0 {
                "policy-namespace-uid".into()
            } else {
                format!("policy-object-{index}")
            });
            body["metadata"]["resourceVersion"] = serde_json::json!("17");
            crate::ObservedPolicyObject { body }
        })
        .collect::<Vec<_>>();
    run_objects[6].body["spec"]["hard"]["pods"] = serde_json::json!("2");
    assert_eq!(
        service.verify_observed_cluster(
            &recovered,
            &crate::ObservedClusterComposition {
                boundary,
                run_objects,
                generated_children: Vec::new(),
                owned_orphans: Vec::new(),
            },
            NOW + 2,
        ),
        Err(ServiceError::PolicyMismatch)
    );
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    assert!(matches!(
        service
            .execute_application(&recovered, configuration, NOW + 2)
            .await,
        Err(crate::RunError::Service(ServiceError::PolicyMismatch))
    ));
    let provider_request =
        tokio::time::timeout(std::time::Duration::from_millis(20), handle.next_request()).await;
    assert!(matches!(provider_request, Ok(None) | Err(_)));
    service
        .record_setup_failure(&recovered, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "policy-namespace-uid",
            &test_authority_identity(),
            NOW + 2,
        )
        .unwrap();
    let exact_absence = cleanup_absence_from_database(
        &root.join("sandbox.sqlite3"),
        &admission.run_id,
        "policy-namespace-uid",
    );
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &exact_absence,
            NOW + 2,
        )
        .unwrap();
    let deadline_admission = service.admit(&key(2), Scenario::Healthy, NOW).unwrap();
    service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    assert_eq!(
        service.record_deadline(&deadline_admission.run_id, NOW + 180),
        Err(ServiceError::InvalidTransition)
    );
    service
        .record_deadline(&deadline_admission.run_id, NOW + 181)
        .unwrap();
    let deadline_snapshot = service
        .snapshot(&deadline_admission.run_id, NOW + 181)
        .unwrap();
    assert_eq!(deadline_snapshot.execution_state, ExecutionState::Running);
    assert_eq!(deadline_snapshot.receiver_result, None);
    crate::test_authority::remove_root(&root);
}

#[test]
fn pagination_every_cursor_is_snapshot_consistent_during_append_and_bounded() {
    let (root, service) = fixture("event-pagination");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    let specification = verify_target(&service, &lease, "pagination-namespace-uid", NOW + 1);
    service
        .record_setup_failure(&lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    let service = std::sync::Arc::new(service);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader = std::sync::Arc::clone(&service);
    let reader_barrier = std::sync::Arc::clone(&barrier);
    let reader_run_id = admission.run_id.clone();
    let reader_thread = std::thread::spawn(move || {
        reader_barrier.wait();
        reader.events(&reader_run_id, 0, 64, NOW + 3).unwrap()
    });
    barrier.wait();
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "pagination-namespace-uid",
            &test_authority_identity(),
            NOW + 3,
        )
        .unwrap();
    let concurrent_page = reader_thread.join().unwrap();
    assert_eq!(
        concurrent_page.events.last().map(|event| event.sequence),
        Some(concurrent_page.last_sequence)
    );
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &cleanup_absence_from_database(
                &root.join("sandbox.sqlite3"),
                &admission.run_id,
                "pagination-namespace-uid",
            ),
            NOW + 4,
        )
        .unwrap();
    let all = service.events(&admission.run_id, 0, 64, NOW + 4).unwrap();
    for after in 0..=all.last_sequence {
        let page = service
            .events(&admission.run_id, after, 64, NOW + 4)
            .unwrap();
        let expected = all
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(page.events, expected);
        assert_eq!(page.last_sequence, all.last_sequence);
    }
    assert_eq!(
        service.events(&admission.run_id, 0, 65, NOW + 4),
        Err(ServiceError::InvalidRequest)
    );
    assert!(all.events.len() <= 64);
    crate::test_authority::remove_root(&root);
}

#[test]
fn no_resource_setup_cleanup_survives_restart_and_expires() {
    let (root, service) = fixture("no-resource-cleanup");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service
        .dispatch_next(NOW + 1, &test_authority_identity())
        .unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    assert_eq!(
        service.record_setup_failure_without_resources(&lease, "cleanup-wrong", NOW + 2),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .record_setup_failure_without_resources(&lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    let active: i64 = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM cleanup_records WHERE active = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, 0);
    let page = service.events(&admission.run_id, 0, 64, NOW + 2).unwrap();
    assert_eq!(page.events.len(), 5);
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 3,
    )
    .unwrap();
    let snapshot = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::ServiceFailed);
    assert_eq!(snapshot.cleanup_state, CleanupState::Succeeded);
    assert_eq!(snapshot.receiver_result, None);
    assert!(service.recoverable_runs().unwrap().is_empty());
    service.sweep_retention(NOW + 86_400).unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    let retained: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let tombstones: i64 = connection
        .query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(tombstones, 1);
    drop(connection);
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 172_800,
    )
    .unwrap();
    service.sweep_retention(NOW + 172_800).unwrap();
    let tombstones: i64 = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tombstones, 0);
    let replacement = service
        .admit(&key(1), Scenario::UnavailableImage, NOW + 172_800)
        .unwrap();
    assert_ne!(replacement.run_id, admission.run_id);
    crate::test_authority::remove_root(&root);
}

#[test]
fn queued_expiry_restarts_then_uses_current_authority_and_converges() {
    let (root, service) = fixture("queued-expiry-restart");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    drop(service);

    let current = crate::test_authority::rotate(&root, [8; 32]);
    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 86_400,
    )
    .unwrap();
    RetentionRole::new(service.clone())
        .run_once(NOW + 86_400)
        .unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    let retained: i64 = connection
        .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
        .unwrap();
    let tombstone: (i64, String) = connection
        .query_row(
            "SELECT authority_generation, authority_manifest_digest FROM tombstones",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(
        tombstone,
        (
            i64::try_from(current.generation()).unwrap(),
            current.manifest_digest().to_owned(),
        )
    );
    drop(connection);
    drop(service);

    let service = Service::open_for_test(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 172_800,
    )
    .unwrap();
    RetentionRole::new(service).run_once(NOW + 172_800).unwrap();
    let counts: (i64, i64) = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM tombstones)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0));
    assert!(!admission.run_id.is_empty());
    crate::test_authority::remove_root(&root);
}

#[test]
fn dispatched_expiry_preserves_pin_across_staged_rotation() {
    let (root, service) = fixture("dispatched-expiry-pin");
    service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let pinned = test_authority_identity();
    service.dispatch_next(NOW + 1, &pinned).unwrap();
    let rotated = crate::test_authority::rotate(&root, [8; 32]);
    assert_ne!(pinned, rotated);
    service.sweep_retention(NOW + 86_400).unwrap();
    let tombstone: (i64, String) = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT authority_generation, authority_manifest_digest FROM tombstones",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        tombstone,
        (
            i64::try_from(pinned.generation()).unwrap(),
            pinned.manifest_digest().to_owned(),
        )
    );
    assert_eq!(
        service.admit(&key(1), Scenario::Healthy, NOW + 86_401),
        Err(ServiceError::RunExpired)
    );
    crate::test_authority::remove_root(&root);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps hostile parsing and bounded error disclosure contiguous"
)]
fn strict_http_translation_rejects_hostile_or_authority_input_without_echo() {
    let (root, service) = fixture("http");
    let body = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .header("idempotency-key", key(1))
        .body(body)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    let run_id = value["run_id"].as_str().unwrap();
    assert_eq!(run_id.len(), 32);
    let text = String::from_utf8(response.body().clone()).unwrap();
    assert!(!text.contains(&key(1)));
    assert!(!text.contains("journal"));
    assert!(!text.contains("credential"));

    let hostile = br#"{"api_version":"v1","scenario":"healthy","namespace":"owned"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", hostile.len())
        .header("idempotency-key", key(2))
        .header("authorization", "secret")
        .body(hostile)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(response.body().clone()).unwrap();
    assert!(!text.contains("secret"));
    assert!(!text.contains("owned"));

    let bounded = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let query_request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs?forwarded=true")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", bounded.len())
        .header("idempotency-key", key(6))
        .body(bounded.clone())
        .unwrap();
    assert_eq!(
        service.handle_http(&query_request, NOW).status(),
        StatusCode::BAD_REQUEST
    );
    for header_name in [
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-client-cert",
        "x-client-cert",
        "x-amzn-mtls-clientcert",
        "x-arr-clientcert",
        "traceparent",
        "x-b3-traceid",
        "baggage",
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/sandbox/v1/runs")
            .header("host", "kapsel.invalid")
            .header("content-type", "application/json")
            .header("content-length", bounded.len())
            .header("idempotency-key", key(6))
            .header(header_name, "hostile-routing-value")
            .body(bounded.clone())
            .unwrap();
        assert_eq!(
            service.handle_http(&request, NOW).status(),
            StatusCode::BAD_REQUEST,
            "header {header_name} must fail closed"
        );
    }

    let path = format!("/sandbox/v1/runs/{run_id}/events?after=0&limit=64");
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "kapsel.invalid")
        .body(Vec::new())
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::OK);
    let event_value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(event_value["events"].as_array().unwrap().len(), 1);

    let duplicate = br#"{"api_version":"v1","scenario":"healthy","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", duplicate.len())
        .header("idempotency-key", key(3))
        .body(duplicate)
        .unwrap();
    assert_eq!(
        service.handle_http(&request, NOW).status(),
        StatusCode::BAD_REQUEST
    );

    let unsupported = br#"{"api_version":"v2","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v2/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", unsupported.len())
        .header("idempotency-key", key(4))
        .body(unsupported)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(value["error"]["code"], "unsupported_version");

    service.set_global_stop(true).unwrap();
    let unavailable = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", unavailable.len())
        .header("idempotency-key", key(5))
        .body(unavailable)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "30");
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(value["error"]["code"], "service_unavailable");
    crate::test_authority::remove_root(&root);
}
