    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    fn write_upgrade_backup(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let backup = PathBuf::from(format!("{}.kapsel-v011.backup", path.display()));
        let digest_path = PathBuf::from(format!("{}.sha256", backup.display()));
        fs::copy(path, &backup).unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = Sha256::digest(fs::read(&backup).unwrap());
        let digest = digest.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        });
        fs::write(&digest_path, format!("{digest}\n")).unwrap();
        fs::set_permissions(&digest_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn journal_version(path: &Path) -> u32 {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn set_journal_version(path: &Path, version: u32) {
        let connection = Connection::open(path).unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
    }

    fn create_unmarked_current_journal(path: &Path) {
        drop(Gateway::open_for_test(path).unwrap());
        set_journal_version(path, 0);
    }

    fn assert_unmarked_refusal_preserves_bytes(path: &Path) {
        let before = fs::read(path).unwrap();
        assert!(matches!(
            Gateway::open_for_test(path),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(journal_version(path), 0);
    }

    #[test]
    fn fresh_journal_initializes_directly_and_reopens_without_another_write() {
        let path = database_path("fresh-version-marker");
        drop(Gateway::open_for_test(&path).unwrap());
        assert_eq!(journal_version(&path), 2);
        assert!(!PathBuf::from(format!("{}.kapsel-v011.backup", path.display())).exists());

        let before = fs::read(&path).unwrap();
        drop(Gateway::open_for_test(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), before);

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn exact_unmarked_store_requires_and_verifies_backup_before_atomic_marker() {
        let path = database_path("verified-upgrade-marker");
        let request = request();
        let gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        drop(gateway);
        set_journal_version(&path, 0);
        let row_before: Vec<String> = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT operation_id, namespace, deployment, container,
                        immutable_image_digest, state
                 FROM kubernetes_image_operations",
                [],
                |row| (0..6).map(|index| row.get(index)).collect(),
            )
            .unwrap();
        write_upgrade_backup(&path);

        drop(Gateway::open_for_test(&path).unwrap());
        assert_eq!(journal_version(&path), 2);
        let row_after: Vec<String> = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT operation_id, namespace, deployment, container,
                        immutable_image_digest, state
                 FROM kubernetes_image_operations",
                [],
                |row| (0..6).map(|index| row.get(index)).collect(),
            )
            .unwrap();
        assert_eq!(row_after, row_before);

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn missing_or_changed_backup_refuses_without_marking_source() {
        for changed_backup in [false, true] {
            let path = database_path(if changed_backup {
                "changed-upgrade-backup"
            } else {
                "missing-upgrade-backup"
            });
            drop(Gateway::open_for_test(&path).unwrap());
            set_journal_version(&path, 0);
            if changed_backup {
                write_upgrade_backup(&path);
                let backup = PathBuf::from(format!("{}.kapsel-v011.backup", path.display()));
                fs::write(&backup, b"not the source database").unwrap();
            }
            let before = fs::read(&path).unwrap();

            assert!(matches!(
                Gateway::open_for_test(&path),
                Err(
                    GatewayError::JournalBackup(_) | GatewayError::JournalBackupMismatch
                )
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(journal_version(&path), 0);

            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn unknown_or_newer_marker_refuses_without_touching_the_store() {
        for version in [1, 3] {
            let path = database_path(&format!("unsupported-version-marker-{version}"));
            drop(Gateway::open_for_test(&path).unwrap());
            set_journal_version(&path, version);
            let before = fs::read(&path).unwrap();

            assert!(matches!(
                Gateway::open_for_test(&path),
                Err(GatewayError::UnsupportedJournalVersion)
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(journal_version(&path), version);

            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn wal_or_unsupported_header_mode_refuses_before_sqlite_mutation() {
        let wal_path = database_path("wal-upgrade-refusal");
        create_unmarked_current_journal(&wal_path);
        let connection = Connection::open(&wal_path).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA journal_mode = WAL", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        drop(connection);
        let wal_before = fs::read(&wal_path).unwrap();
        assert!(matches!(
            Gateway::open_for_test(&wal_path),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        fs::remove_dir_all(wal_path.parent().unwrap()).unwrap();

        let unsupported_path = database_path("unsupported-header-mode-refusal");
        create_unmarked_current_journal(&unsupported_path);
        let mut bytes = fs::read(&unsupported_path).unwrap();
        bytes[18] = 3;
        bytes[19] = 3;
        fs::write(&unsupported_path, &bytes).unwrap();
        assert!(matches!(
            Gateway::open_for_test(&unsupported_path),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(fs::read(&unsupported_path).unwrap(), bytes);
        fs::remove_dir_all(unsupported_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn extra_schema_objects_and_generated_columns_refuse_without_marking() {
        let cases = [
            (
                "extra-table",
                "CREATE TABLE unexpected(value TEXT) STRICT;",
            ),
            (
                "extra-view",
                "CREATE VIEW unexpected AS SELECT operation_id FROM \
                 kubernetes_image_operations;",
            ),
            (
                "extra-trigger",
                "CREATE TRIGGER unexpected AFTER INSERT ON kubernetes_image_operations \
                 BEGIN SELECT 1; END;",
            ),
            (
                "explicit-index",
                "CREATE INDEX unexpected ON kubernetes_image_operations(state);",
            ),
            (
                "generated-column",
                "ALTER TABLE kubernetes_image_operations ADD COLUMN unexpected TEXT \
                 GENERATED ALWAYS AS (state) VIRTUAL;",
            ),
        ];
        for (name, change) in cases {
            let path = database_path(name);
            create_unmarked_current_journal(&path);
            Connection::open(&path)
                .unwrap()
                .execute_batch(change)
                .unwrap();
            write_upgrade_backup(&path);
            assert_unmarked_refusal_preserves_bytes(&path);
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn changed_checks_collations_and_constraints_refuse_without_marking() {
        let cases = [
            (
                "changed-check",
                "state TEXT NOT NULL CHECK (state <> '')",
            ),
            ("changed-collation", "state TEXT COLLATE NOCASE NOT NULL"),
            ("changed-constraint", "state TEXT NOT NULL UNIQUE"),
        ];
        for (name, changed_declaration) in cases {
            let path = database_path(name);
            create_unmarked_current_journal(&path);
            let connection = Connection::open(&path).unwrap();
            let original: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'table' AND name = 'kubernetes_image_operations'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let changed = original.replace("state TEXT NOT NULL", changed_declaration);
            assert_ne!(changed, original);
            connection
                .execute_batch("DROP TABLE kubernetes_image_operations")
                .unwrap();
            connection.execute_batch(&changed).unwrap();
            drop(connection);
            write_upgrade_backup(&path);
            assert_unmarked_refusal_preserves_bytes(&path);
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn symlink_and_dangling_symlink_inputs_refuse_without_source_mutation() {
        use std::os::unix::fs::symlink;

        let source_path = database_path("source-symlink");
        create_unmarked_current_journal(&source_path);
        let real_source = source_path.with_extension("real");
        fs::rename(&source_path, &real_source).unwrap();
        symlink(&real_source, &source_path).unwrap();
        let source_before = fs::read(&real_source).unwrap();
        assert!(matches!(
            Gateway::open_for_test(&source_path),
            Err(GatewayError::JournalFile(_))
        ));
        assert_eq!(fs::read(&real_source).unwrap(), source_before);
        fs::remove_dir_all(source_path.parent().unwrap()).unwrap();

        let dangling_source = database_path("dangling-source-symlink");
        symlink(dangling_source.with_extension("missing"), &dangling_source).unwrap();
        assert!(matches!(
            Gateway::open_for_test(&dangling_source),
            Err(GatewayError::JournalFile(_))
        ));
        fs::remove_dir_all(dangling_source.parent().unwrap()).unwrap();

        for artifact in ["backup", "digest"] {
            for dangling in [false, true] {
                let path = database_path(&format!("{artifact}-symlink-{dangling}"));
                create_unmarked_current_journal(&path);
                write_upgrade_backup(&path);
                let backup = PathBuf::from(format!("{}.kapsel-v011.backup", path.display()));
                let digest = PathBuf::from(format!("{}.sha256", backup.display()));
                let selected = if artifact == "backup" { &backup } else { &digest };
                let real = selected.with_extension("real");
                if dangling {
                    fs::remove_file(selected).unwrap();
                } else {
                    fs::rename(selected, &real).unwrap();
                }
                symlink(&real, selected).unwrap();
                let before = fs::read(&path).unwrap();
                assert!(matches!(
                    Gateway::open_for_test(&path),
                    Err(GatewayError::JournalBackup(_))
                ));
                assert_eq!(fs::read(&path).unwrap(), before);
                fs::remove_dir_all(path.parent().unwrap()).unwrap();
            }
        }
    }

    #[test]
    fn multiply_linked_source_backup_or_digest_refuses_without_marking() {
        for artifact in ["source", "backup", "digest"] {
            let path = database_path(&format!("multiply-linked-{artifact}"));
            create_unmarked_current_journal(&path);
            write_upgrade_backup(&path);
            let backup = PathBuf::from(format!("{}.kapsel-v011.backup", path.display()));
            let digest = PathBuf::from(format!("{}.sha256", backup.display()));
            let selected = match artifact {
                "source" => &path,
                "backup" => &backup,
                "digest" => &digest,
                _ => unreachable!(),
            };
            fs::hard_link(selected, selected.with_extension("hardlink")).unwrap();
            let before = fs::read(&path).unwrap();
            assert!(matches!(
                Gateway::open_for_test(&path),
                Err(GatewayError::JournalFile(_) | GatewayError::JournalBackup(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn symlinked_parent_refuses_before_journal_open() {
        use std::os::unix::fs::symlink;

        let root = database_path("symlinked-parent-root")
            .parent()
            .unwrap()
            .to_path_buf();
        fs::remove_dir_all(&root).unwrap();
        let real_parent = root.with_extension("real");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_parent, &root).unwrap();
        assert!(matches!(
            Gateway::open_for_test(root.join("journal.sqlite3")),
            Err(GatewayError::JournalFile(_))
        ));
        fs::remove_file(&root).unwrap();
        fs::remove_dir_all(&real_parent).unwrap();
    }

    #[test]
    fn legacy_self_asserted_authorization_migrates_idempotently_but_fails_closed() {
        let path = database_path("receipt-schema-migration");
        let request = request();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE kubernetes_image_operations (
                    operation_id TEXT PRIMARY KEY NOT NULL,
                    namespace TEXT NOT NULL,
                    deployment TEXT NOT NULL,
                    container TEXT NOT NULL,
                    immutable_image_digest TEXT NOT NULL,
                    authorization_id TEXT,
                    state TEXT NOT NULL,
                    write_strategy TEXT,
                    apply_attempted INTEGER NOT NULL DEFAULT 0,
                    target_uid TEXT,
                    target_resource_version TEXT,
                    apply_accepted INTEGER,
                    requested_generation INTEGER,
                    apply_resource_version TEXT,
                    receiver_uid TEXT,
                    receiver_image TEXT,
                    receiver_operation_marker TEXT,
                    current_generation INTEGER,
                    observed_generation INTEGER,
                    receiver_resource_version TEXT,
                    desired_replicas INTEGER,
                    updated_replicas INTEGER,
                    available_replicas INTEGER,
                    unavailable_replicas INTEGER,
                    available_condition INTEGER,
                    progress_deadline_exceeded INTEGER,
                    result TEXT
                ) STRICT;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container, immutable_image_digest,
                    authorization_id, state, write_strategy, apply_attempted, target_uid,
                    target_resource_version, requested_generation, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, observed_generation,
                    receiver_resource_version, progress_deadline_exceeded, result
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'auth-001', 'receiver_observed', ?6, 1,
                           'deployment-uid-1', 'resource-version-0', NULL, 'deployment-uid-1',
                           ?5, ?1, 2, 2, 'resource-version-2', 1, 'FAILED')",
                params![
                    request.operation_id,
                    request.namespace,
                    request.deployment,
                    request.container,
                    request.immutable_image_digest,
                    WRITE_STRATEGY,
                ],
            )
            .unwrap();
        drop(connection);
        write_upgrade_backup(&path);

        drop(Gateway::open_for_test(&path).unwrap());
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert!(matches!(
            gateway.journal.receipt_statement(&request.operation_id),
            Err(GatewayError::InvalidPersistedState)
        ));
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[22_u8; 32],
                key_id: "kap0038-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::InvalidPersistedState)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(fs::read_dir(output_directory).unwrap().count(), 0);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
