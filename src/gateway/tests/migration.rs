use std::os::unix::fs::symlink;

use rusqlite::types::Value;

use super::{Journal, *};

fn current_journal(path: &Path) {
    drop(Gateway::open_for_test(path).unwrap());
}

fn assert_invalid_unchanged(path: &Path) {
    let before = fs::read(path).unwrap();
    assert!(matches!(
        Journal::validate_replacement(path, &[]),
        Err(GatewayError::InvalidPersistedState)
    ));
    assert!(matches!(
        Gateway::open_for_test(path),
        Err(GatewayError::InvalidPersistedState)
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn format_six_reopens_original_history_without_rewriting_schema_rows_or_version() {
    let path = database_path("current-history");
    let gateway = Gateway::open(&path, journal::test_history::trust()).unwrap();
    assert_eq!(
        gateway
            .journal
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        6
    );
    assert!(!PathBuf::from(format!("{}.kapsel-v011.backup", path.display())).exists());
    for phase in ["authorized", "finalized"] {
        History::kube(phase).insert(&gateway.journal.connection, phase);
    }
    let original_rows = stored_rows(&gateway.journal.connection);
    drop(gateway);
    let before = fs::read(&path).unwrap();
    Journal::validate_replacement(&path, &[]).unwrap();
    let reopened = Gateway::open(&path, journal::test_history::trust()).unwrap();
    assert_eq!(stored_rows(&reopened.journal.connection), original_rows);
    for (id, phase) in [
        ("authorized", OperationState::Authorized),
        ("finalized", OperationState::Finalized),
    ] {
        assert_eq!(reopened.get(id).unwrap(), Some(phase));
        assert!(reopened.retained_operation(id).unwrap().is_some());
    }
    assert_eq!(
        Gateway::read_loaded_receipt(reopened.loaded_for_test("finalized").unwrap().unwrap())
            .unwrap()
            .0,
        History::kube("finalized").receipt().bytes
    );
    drop(reopened);
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn prior_construction_and_unknown_versions_are_refused_unchanged() {
    for version in [0_u32, 1, 2, 3, 4, 5, 7] {
        let path = database_path(&format!("version-{version}"));
        let gateway = Gateway::open_for_test(&path).unwrap();
        History::kube("retained-original").insert(&gateway.journal.connection, "authorized");
        gateway
            .journal
            .connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        drop(gateway);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            Gateway::open_for_test(&path),
            Err(GatewayError::UnsupportedJournalVersion)
        ));
        assert!(matches!(
            Journal::validate_replacement(&path, &[]),
            Err(GatewayError::UnsupportedJournalVersion)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    let path = database_path("format-five-construction");
    Connection::open(&path)
        .unwrap()
        .execute_batch(include_str!("format5-before-direct-create.sql"))
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Gateway::open_for_test(&path),
        Err(GatewayError::UnsupportedJournalVersion)
    ));
    assert!(Journal::validate_replacement(&path, &[]).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn persisted_byte_and_count_boundaries_are_checked_on_every_reopen() {
    for (name, field, at_limit, over_limit) in [
        (
            "blob",
            "receipt_bytes",
            Value::Blob(vec![0; 16384]),
            Value::Blob(vec![0; 16385]),
        ),
        (
            "utf8",
            "authorization_id",
            Value::Text("é".repeat(8192)),
            Value::Text("é".repeat(8193)),
        ),
        (
            "grant",
            "signed_authorization_grant",
            Value::Blob(vec![0; 4096]),
            Value::Blob(vec![0; 4097]),
        ),
    ] {
        let path = database_path(name);
        let gateway = Gateway::open_for_test(&path).unwrap();
        History::kube("boundary").insert(&gateway.journal.connection, "authorized");
        gateway
            .journal
            .connection
            .execute(
                &format!("UPDATE kubernetes_image_operations SET {field} = ?1"),
                [at_limit],
            )
            .unwrap();
        drop(gateway);
        drop(Gateway::open_for_test(&path).unwrap());
        Journal::validate_replacement(&path, &[]).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute(
                &format!("UPDATE kubernetes_image_operations SET {field} = ?1"),
                [over_limit],
            )
            .unwrap();
        assert_invalid_unchanged(&path);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    let path = database_path("persisted-count");
    current_journal(&path);
    Connection::open(&path)
        .unwrap()
        .execute(
            "WITH RECURSIVE numbers(value) AS (
            SELECT 1 UNION ALL SELECT value + 1 FROM numbers WHERE value < 504)
         INSERT INTO kubernetes_image_operations
            (operation_id, namespace, deployment, container, immutable_image_digest, state)
         SELECT 'op-' || value, 'demo', 'agent-api', 'api', ?1, 'not_attempted' FROM numbers",
            [request().immutable_image_digest],
        )
        .unwrap();
    drop(Gateway::open_for_test(&path).unwrap());
    Journal::validate_replacement(&path, &[]).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO kubernetes_image_operations
         (operation_id, namespace, deployment, container, immutable_image_digest, state)
         VALUES ('overflow', 'demo', 'agent-api', 'api', ?1, 'authorized')",
            [request().immutable_image_digest],
        )
        .unwrap();
    assert_invalid_unchanged(&path);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn orphan_pages_and_unsupported_header_modes_refuse_before_mutation() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    for name in ["orphan", "wal", "header"] {
        let path = database_path(name);
        current_journal(&path);
        match name {
            "orphan" => {
                let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_len(64 * 1024 * 1024).unwrap();
                file.seek(SeekFrom::Start(28)).unwrap();
                file.write_all(&16_384_u32.to_be_bytes()).unwrap();
                file.sync_all().unwrap();
            },
            "wal" => {
                assert_eq!(
                    Connection::open(&path)
                        .unwrap()
                        .query_row("PRAGMA journal_mode = WAL", [], |row| row
                            .get::<_, String>(0))
                        .unwrap(),
                    "wal"
                );
            },
            _ => {
                let mut bytes = fs::read(&path).unwrap();
                bytes[18..20].fill(3);
                fs::write(&path, bytes).unwrap();
            },
        }
        assert_invalid_unchanged(&path);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn nonexact_schema_is_refused_without_rewriting() {
    for change in [
        "CREATE TABLE unexpected(value TEXT) STRICT;",
        "CREATE VIEW unexpected AS SELECT operation_id FROM kubernetes_image_operations;",
        "CREATE TRIGGER unexpected AFTER INSERT ON kubernetes_image_operations
         BEGIN SELECT 1; END;",
        "CREATE INDEX unexpected ON kubernetes_image_operations(state);",
        "ALTER TABLE kubernetes_image_operations ADD COLUMN unexpected TEXT
         GENERATED ALWAYS AS (state) VIRTUAL;",
        "state TEXT NOT NULL CHECK (state <> '')",
        "state TEXT COLLATE NOCASE NOT NULL",
        "state TEXT NOT NULL UNIQUE",
    ] {
        let path = database_path("changed-schema");
        current_journal(&path);
        let connection = Connection::open(&path).unwrap();
        if change.starts_with("state ") {
            let original: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name = 'kubernetes_image_operations'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let changed = original.replace("state TEXT NOT NULL", change);
            assert_ne!(changed, original);
            connection
                .execute_batch("DROP TABLE kubernetes_image_operations")
                .unwrap();
            connection.execute_batch(&changed).unwrap();
        } else {
            connection.execute_batch(change).unwrap();
        }
        drop(connection);
        assert_invalid_unchanged(&path);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[test]
fn unsafe_artifact_sizes_and_modes_refuse_before_sqlite_reads() {
    for (suffix, size, mode) in [
        ("", 64 * 1024 * 1024 + 1, 0o600),
        ("-journal", 65 * 1024 * 1024 + 1, 0o600),
        ("", 0, 0o700),
        ("", 0, 0o4600),
        (".kap0038-worker.lock", 0, 0o4600),
        ("-journal", 8, 0o4600),
    ] {
        let path = database_path("unsafe-artifact");
        current_journal(&path);
        let artifact = PathBuf::from(format!("{}{suffix}", path.display()));
        if size != 0 {
            fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&artifact)
                .unwrap()
                .set_len(size)
                .unwrap();
        }
        fs::set_permissions(&artifact, fs::Permissions::from_mode(mode)).unwrap();
        let result = Gateway::open_for_test(&path);
        match (suffix, size) {
            ("", 0) => assert!(matches!(result, Err(GatewayError::JournalFile(_)))),
            ("", _) => assert!(matches!(result, Err(GatewayError::InvalidPersistedState))),
            (".kap0038-worker.lock", _) => {
                assert!(matches!(result, Err(GatewayError::WorkerLock(_))));
            },
            ("-journal", 8) => assert!(matches!(result, Err(GatewayError::JournalBackup(_)))),
            _ => assert!(matches!(result, Err(GatewayError::JournalBackupMismatch))),
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    let path = database_path("special-parent");
    current_journal(&path);
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o2700)).unwrap();
    assert!(matches!(
        Gateway::open_for_test(&path),
        Err(GatewayError::JournalFile(_))
    ));
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn linked_sources_and_parents_refuse_without_mutating_history() {
    for kind in ["symlink", "dangling", "hardlink", "parent"] {
        let path = database_path(kind);
        current_journal(&path);
        let original = fs::read(&path).unwrap();
        let real = path.with_extension("real");
        match kind {
            "hardlink" => fs::hard_link(&path, &real).unwrap(),
            "parent" => {
                let parent = path.parent().unwrap();
                let relocated = parent.with_extension("real");
                fs::rename(parent, &relocated).unwrap();
                symlink(&relocated, parent).unwrap();
            },
            _ => {
                fs::rename(&path, &real).unwrap();
                symlink(
                    if kind == "dangling" {
                        path.with_extension("missing")
                    } else {
                        real.clone()
                    },
                    &path,
                )
                .unwrap();
            },
        }
        assert!(matches!(
            Gateway::open_for_test(&path),
            Err(GatewayError::JournalFile(_))
        ));
        assert!(matches!(
            Journal::validate_replacement(&path, &[]),
            Err(GatewayError::JournalFile(_))
        ));
        let preserved = if kind == "parent" {
            path.parent()
                .unwrap()
                .with_extension("real")
                .join("journal.sqlite3")
        } else {
            real
        };
        assert_eq!(fs::read(preserved).unwrap(), original);
        if kind == "parent" {
            fs::remove_file(path.parent().unwrap()).unwrap();
            fs::remove_dir_all(path.parent().unwrap().with_extension("real")).unwrap();
        } else {
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }
}
