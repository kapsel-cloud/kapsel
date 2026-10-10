//! Storage diagnostics preserve caller uncertainty and never manufacture fresh history.

use super::*;

#[tokio::test]
async fn lost_or_empty_database_with_history_artifacts_refuses_startup_and_publication() {
    for empty in [false, true] {
        let root = root(if empty {
            "storage-empty"
        } else {
            "storage-missing"
        });
        let mut application = ServiceApplication::open(configuration(&root)).unwrap();
        application.select("a", offline(), |_| {}).await.unwrap();
        let original_status = application.status("a").unwrap();
        drop(application);

        let journal = root.join("journal.sqlite3");
        let displaced = root.join("displaced.sqlite3");
        fs::rename(&journal, &displaced).unwrap();
        let original_journal_bytes = fs::read(&displaced).unwrap();
        if empty {
            fs::write(&journal, []).unwrap();
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(matches!(
            ServiceApplication::open(configuration(&root)),
            Err(ServiceError::StorageMissing)
        ));
        assert!(ServiceApplication::validate_replacement(&configuration(&root)).is_err());
        assert_eq!(fs::read(&displaced).unwrap(), original_journal_bytes);
        if empty {
            assert_eq!(fs::metadata(&journal).unwrap().len(), 0);
            fs::remove_file(&journal).unwrap();
        } else {
            assert!(!journal.exists());
        }

        // Restore custody of the exact displaced current file, never a stale snapshot.
        fs::rename(&displaced, &journal).unwrap();
        let application = ServiceApplication::open(configuration(&root)).unwrap();
        assert_eq!(application.status("a").unwrap(), original_status);
        assert_eq!(fs::read(&journal).unwrap(), original_journal_bytes);
        drop(application);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn missing_history_sidecars_never_create_a_database() {
    for suffix in ["-journal", "-wal", "-shm", ".kap0038-worker.lock"] {
        let root = root(&format!("storage-orphan-{suffix}"));
        let artifact = root.join(format!("journal.sqlite3{suffix}"));
        fs::write(&artifact, b"retained").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600)).unwrap();
        for publication in [false, true] {
            let result = if publication {
                ServiceApplication::validate_replacement(&configuration(&root))
            } else {
                ServiceApplication::open(configuration(&root)).map(|_| ())
            };
            assert_eq!(result, Err(ServiceError::StorageMissing));
            assert_eq!(fs::read(&artifact).unwrap(), b"retained");
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn invalid_and_inaccessible_history_have_distinct_non_disclosing_diagnostics() {
    for inaccessible in [false, true] {
        let root = root(if inaccessible {
            "storage-custody"
        } else {
            "storage-invalid"
        });

        let journal = root.join("journal.sqlite3");
        fs::write(&journal, b"not a database; private fixture content").unwrap();
        fs::set_permissions(
            &journal,
            fs::Permissions::from_mode(if inaccessible { 0o000 } else { 0o600 }),
        )
        .unwrap();
        let expected = if inaccessible {
            ServiceError::StorageUnavailable
        } else {
            ServiceError::StorageInvalid
        };
        let opened = ServiceApplication::open(configuration(&root));
        assert!(matches!(opened, Err(error) if error == expected));
        assert_eq!(
            ServiceApplication::validate_replacement(&configuration(&root)),
            Err(expected)
        );
        assert!(!expected.operator_diagnostic().contains("fixture"));
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            fs::read(&journal).unwrap(),
            b"not a database; private fixture content"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
