//! Black-box proof for the fixed native listener and operator stop process.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled fixture failures must stop the black-box process test"
)]

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{Scenario, Service};
use sha2::{Digest, Sha256};

mod common;

const REQUEST_HEAD_OVERFLOW_PADDING: usize = 8 * 1024;

fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-listener-{}-{name}",
        std::process::id()
    ));
    if root.exists() {
        common::remove_root(&root);
    }
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let state_parent = root.join("state-parent");
    fs::create_dir(&state_parent).unwrap();
    fs::set_permissions(&state_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let restore_lock = state_parent.join(".kapsel-sandbox-restore.lock");
    fs::write(&restore_lock, []).unwrap();
    fs::set_permissions(&restore_lock, fs::Permissions::from_mode(0o600)).unwrap();
    let state_root = state_parent.join("state");
    let receipts = state_root.join("receipts");
    let key = root.join("digest.key");
    fs::write(&key, [7_u8; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o440)).unwrap();
    common::authority_root(&root, [7; 32]);
    (state_root.join("sandbox.sqlite3"), receipts, key)
}

fn arguments(database: &Path, _receipts: &Path, _key: &Path) -> Vec<String> {
    let mut arguments = vec![
        "--state-root".into(),
        database.parent().unwrap().display().to_string(),
    ];
    arguments.extend(common::authority_arguments(
        database
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    ));
    arguments
}

fn start(database: &Path, receipts: &Path, key: &Path) -> (Child, String) {
    if !database.exists() {
        initialize(database, receipts, key);
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"));
    command
        .arg("serve")
        .args(arguments(database, receipts, key))
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    let address = line.strip_prefix("LISTEN_ADDR=").unwrap().trim().to_owned();
    (child, address)
}

fn request(address: &str, bytes: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(bytes).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("listener read failed: {error}"),
        }
    }
    response
}

fn expect_receive_timeout(address: &str, partial_request: &[u8]) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(7)))
        .unwrap();
    stream.write_all(partial_request).unwrap();
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        outcome => panic!("partial request did not close after receive timeout: {outcome:?}"),
    }
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4));
    assert!(elapsed < Duration::from_secs(6));
}

fn admission(key: &str) -> Vec<u8> {
    let body = br#"{"api_version":"v1","scenario":"healthy"}"#;
    format!(
        concat!(
            "POST /sandbox/v1/runs HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "content-type: application/json\r\n",
            "content-length: {}\r\n",
            "idempotency-key: {}\r\n\r\n"
        ),
        body.len(),
        key
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn prepare_pre_slice_state(name: &str, stopped: bool) -> (PathBuf, PathBuf, PathBuf, Vec<u8>) {
    let (database, receipts, key) = fixture(name);
    let state_root = database.parent().unwrap();
    fs::create_dir(state_root).unwrap();
    fs::set_permissions(state_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&receipts).unwrap();
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(state_root.join("runner")).unwrap();
    fs::set_permissions(state_root.join("runner"), fs::Permissions::from_mode(0o700)).unwrap();
    let service = Service::open(
        &database,
        &receipts,
        &common::authority_configuration(state_root.parent().unwrap().parent().unwrap(), [7; 32]),
        1_774_051_200,
    )
    .unwrap();
    service.set_global_stop(stopped).unwrap();
    drop(service);
    let database_bytes = fs::read(&database).unwrap();
    (database, receipts, key, database_bytes)
}

fn initialize(database: &Path, receipts: &Path, key: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(database, receipts, key))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn state_command(command_name: &str, database: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg(command_name)
        .args([
            "--state-root",
            &database.parent().unwrap().display().to_string(),
        ])
        .output()
        .unwrap()
}

fn operate(command_name: &str, database: &Path) {
    let output = state_command(command_name, database);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn state_root_init_is_canonical_and_legacy_component_flags_are_rejected() {
    let (database, receipts, digest_key) = fixture("state-root-contract");
    initialize(&database, &receipts, &digest_key);
    let state_root = database.parent().unwrap();
    let entries = fs::read_dir(state_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        entries,
        [
            ".backup.lock",
            "deployment.json",
            "receipts",
            "restore.ready",
            "runner",
            "sandbox.sqlite3",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    for name in ["deployment.json", "restore.ready"] {
        let bytes = fs::read(state_root.join(name)).unwrap();
        assert!(!bytes.ends_with(b"\n"));
        let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    }
    let deployment: serde_json::Value =
        serde_json::from_slice(&fs::read(state_root.join("deployment.json")).unwrap()).unwrap();
    assert_eq!(deployment["target"], "test-architecture");
    let runner_digest =
        Sha256::digest(fs::read(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness")).unwrap())
            .iter()
            .fold(String::new(), |mut output, byte| {
                write!(&mut output, "{byte:02x}").unwrap();
                output
            });
    assert_eq!(deployment["runner_sha256"], runner_digest);
    assert_eq!(
        deployment["gateway_schema_sha256"],
        "0062a67e9bb09b60bb9472386b51b57552f17fb8aa749dace321100951d66521"
    );
    for legacy in [
        "--database",
        "--receipts",
        "--runner-generation-root",
        "--runner-generations",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
            .args([
                "stop",
                "--state-root",
                state_root.to_str().unwrap(),
                legacy,
                database.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    for lock in [
        state_root
            .parent()
            .unwrap()
            .join(".kapsel-sandbox-restore.lock"),
        state_root.join(".backup.lock"),
    ] {
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock)
            .unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
            .args(["stop", "--state-root", state_root.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        drop(held);
    }
    fs::remove_file(state_root.join("restore.ready")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .args(["stop", "--state-root", state_root.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stopped: bool = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT stopped FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!stopped);
    common::remove_root(state_root);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one hostile matrix restores every exact state-root corruption before the next case"
)]
fn hostile_state_inventory_and_records_fail_before_database_mutation() {
    let (database, receipts, key) = fixture("state-root-hostile");
    initialize(&database, &receipts, &key);
    let root = database.parent().unwrap();
    let assert_rejected = || {
        for command in ["stop", "clear-stop"] {
            assert_eq!(
                state_command(command, &database).status.code(),
                Some(2),
                "{command} accepted incomplete or malformed state",
            );
        }
        let stopped: bool = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stopped);
    };

    let deployment = root.join("deployment.json");
    let deployment_bytes = fs::read(&deployment).unwrap();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o4400)).unwrap();
    assert_rejected();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&deployment, [&deployment_bytes[..], b"\n"].concat()).unwrap();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o400)).unwrap();
    assert_rejected();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&deployment, &deployment_bytes).unwrap();
    let mut incompatible: serde_json::Value = serde_json::from_slice(&deployment_bytes).unwrap();
    incompatible["policy"] = serde_json::json!("sandbox-policy-v2");
    fs::write(&deployment, serde_json::to_vec(&incompatible).unwrap()).unwrap();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o400)).unwrap();
    assert_rejected();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&deployment, &deployment_bytes).unwrap();
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o400)).unwrap();

    let ready = root.join("restore.ready");
    let ready_bytes = fs::read(&ready).unwrap();
    let mut malformed: serde_json::Value = serde_json::from_slice(&ready_bytes).unwrap();
    malformed["unknown"] = serde_json::json!(true);
    fs::write(&ready, serde_json::to_vec(&malformed).unwrap()).unwrap();
    fs::set_permissions(&ready, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::write(&ready, &ready_bytes).unwrap();
    let mut zero_time: serde_json::Value = serde_json::from_slice(&ready_bytes).unwrap();
    zero_time["completed_at"] = serde_json::json!(0);
    fs::write(&ready, serde_json::to_vec(&zero_time).unwrap()).unwrap();
    assert_rejected();
    fs::write(&ready, &ready_bytes).unwrap();
    let mut zero_generation: serde_json::Value = serde_json::from_slice(&ready_bytes).unwrap();
    zero_generation["source"] = serde_json::json!("restored");
    zero_generation["generation"] = serde_json::json!(0);
    zero_generation["manifest_sha256"] = serde_json::json!("ab".repeat(32));
    fs::write(&ready, serde_json::to_vec(&zero_generation).unwrap()).unwrap();
    assert_rejected();
    fs::write(&ready, &ready_bytes).unwrap();

    let incomplete = root.join("restore.incomplete");
    fs::write(&incomplete, b"{}").unwrap();
    fs::set_permissions(&incomplete, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::remove_file(incomplete).unwrap();

    let external_database = root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("external.sqlite3");
    fs::hard_link(&database, &external_database).unwrap();
    assert_rejected();
    fs::remove_file(&external_database).unwrap();
    fs::rename(&database, &external_database).unwrap();
    symlink(&external_database, &database).unwrap();
    assert_rejected();
    fs::remove_file(&database).unwrap();
    fs::rename(&external_database, &database).unwrap();

    let receipt = receipts.join(format!(
        "sandbox-{}-{}.receipt",
        "01".repeat(16),
        "ab".repeat(32)
    ));
    fs::write(&receipt, b"receipt").unwrap();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
    assert_rejected();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
    let receipt_link = receipt.with_file_name("sandbox-hardlink.receipt");
    fs::hard_link(&receipt, &receipt_link).unwrap();
    assert_rejected();
    fs::remove_file(receipt_link).unwrap();
    fs::remove_file(receipt).unwrap();
    let receipt_extra = receipts.join("sandbox-hostile.receipt");
    fs::write(&receipt_extra, b"receipt").unwrap();
    fs::set_permissions(&receipt_extra, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::remove_file(receipt_extra).unwrap();
    let receipt_symlink = receipts.join("sandbox-symlink.receipt");
    symlink(&deployment, &receipt_symlink).unwrap();
    assert_rejected();
    fs::remove_file(receipt_symlink).unwrap();

    let runner_file = root.join("runner/runner-generation.json");
    fs::write(&runner_file, b"runner").unwrap();
    fs::set_permissions(&runner_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert_rejected();
    fs::set_permissions(&runner_file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::remove_file(runner_file).unwrap();
    let runner_extra = root.join("runner/hostile");
    fs::write(&runner_extra, b"runner").unwrap();
    fs::set_permissions(&runner_extra, fs::Permissions::from_mode(0o600)).unwrap();
    assert_rejected();
    fs::remove_file(runner_extra).unwrap();
    let runner_symlink = root.join("runner/hostile-link");
    symlink(&deployment, &runner_symlink).unwrap();
    assert_rejected();
    fs::remove_file(runner_symlink).unwrap();
    let short_socket =
        std::env::temp_dir().join(format!("kapsel-hostile-{}.sock", std::process::id()));
    let _ = fs::remove_file(&short_socket);
    let socket = std::os::unix::net::UnixListener::bind(&short_socket).unwrap();
    let runner_socket = root.join("runner/hostile.sock");
    fs::rename(&short_socket, &runner_socket).unwrap();
    assert_rejected();
    drop(socket);
    fs::remove_file(runner_socket).unwrap();

    let external_link = root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("deployment-hardlink");
    fs::hard_link(&deployment, &external_link).unwrap();
    assert_rejected();
    fs::remove_file(external_link).unwrap();

    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn exact_incomplete_init_temporary_recovers_and_converges() {
    let (database, receipts, key) = fixture("state-root-init-recovery");
    let state_root = database.parent().unwrap();
    let outer = state_root.parent().unwrap().parent().unwrap();
    let authority = outer.join("fixed-authority");
    let held_authority = outer.join("held-authority");
    fs::rename(&authority, &held_authority).unwrap();
    let first = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(2));
    assert!(!state_root.exists());
    assert!(state_root
        .parent()
        .unwrap()
        .join(".state.initializing")
        .is_dir());
    fs::rename(&held_authority, &authority).unwrap();
    initialize(&database, &receipts, &key);
    assert!(state_root.join("restore.ready").is_file());
    assert!(!state_root
        .parent()
        .unwrap()
        .join(".state.initializing")
        .exists());
    common::remove_root(outer);
}

#[test]
fn stopped_drained_pre_slice_state_migrates_without_changing_existing_rows() {
    let (database, receipts, key, _) = prepare_pre_slice_state("state-root-migration", true);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE backup_authority_references; DROP TABLE backup_generations; VACUUM;",
        )
        .unwrap();
    let stopped_before: i64 = connection
        .query_row(
            "SELECT stopped FROM service_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    initialize(&database, &receipts, &key);
    let root = database.parent().unwrap();
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
        stopped_before
    );
    assert_eq!(
        connection
            .query_row(
                concat!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ",
                    "('backup_generations', 'backup_authority_references')"
                ),
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert!(root.join(".backup.lock").is_file());
    assert!(root.join("deployment.json").is_file());
    assert!(root.join("restore.ready").is_file());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn stopped_migration_resumes_exact_table_and_deployment_prefixes() {
    for (name, keep_deployment) in [("tables", false), ("deployment", true)] {
        let (database, receipts, key, _) =
            prepare_pre_slice_state(&format!("state-root-migration-prefix-{name}"), true);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "DROP TABLE backup_authority_references; DROP TABLE backup_generations; VACUUM;",
            )
            .unwrap();
        drop(connection);
        initialize(&database, &receipts, &key);
        let root = database.parent().unwrap();
        fs::remove_file(root.join("restore.ready")).unwrap();
        if !keep_deployment {
            fs::remove_file(root.join("deployment.json")).unwrap();
        }
        initialize(&database, &receipts, &key);
        assert!(root.join("deployment.json").is_file());
        assert!(root.join("restore.ready").is_file());
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .query_row(
                    concat!(
                        "SELECT (SELECT COUNT(*) FROM backup_generations) + ",
                        "(SELECT COUNT(*) FROM backup_authority_references)"
                    ),
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        common::remove_root(root.parent().unwrap().parent().unwrap());
    }
}

#[test]
fn pre_slice_runner_generation_refuses_without_migration_markers() {
    let (database, receipts, key, before) =
        prepare_pre_slice_state("state-root-migration-runner", true);
    let runner_entry = database
        .parent()
        .unwrap()
        .join("runner/generation-00000000000000000001");
    fs::create_dir(&runner_entry).unwrap();
    fs::set_permissions(&runner_entry, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&database).unwrap(), before);
    let root = database.parent().unwrap();
    assert!(!root.join(".backup.lock").exists());
    assert!(!root.join("deployment.json").exists());
    assert!(!root.join("restore.ready").exists());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn unreferenced_pre_slice_receipt_refuses_without_cleanup() {
    let (database, receipts, key, before) =
        prepare_pre_slice_state("state-root-migration-orphan-receipt", true);
    let orphan = receipts.join(format!(
        "sandbox-{}-{}.receipt",
        "01".repeat(16),
        "ab".repeat(32)
    ));
    fs::write(&orphan, b"orphan").unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&database).unwrap(), before);
    assert_eq!(fs::read(&orphan).unwrap(), b"orphan");
    let root = database.parent().unwrap();
    assert!(!root.join(".backup.lock").exists());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn transitional_pre_slice_state_refuses_before_cleanup_or_marker_mutation() {
    let (database, receipts, key, _) =
        prepare_pre_slice_state("state-root-migration-hostile", true);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "INSERT INTO receipt_publications VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "01".repeat(16),
                "ab".repeat(32),
                "sandbox-pending.receipt",
                1_774_051_200_i64,
            ],
        )
        .unwrap();
    drop(connection);
    let before = fs::read(&database).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&database).unwrap(), before);
    let pending: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM receipt_publications", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(pending, 1);
    let root = database.parent().unwrap();
    assert!(!root.join(".backup.lock").exists());
    assert!(!root.join("deployment.json").exists());
    assert!(!root.join("restore.ready").exists());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn malformed_pre_slice_schema_refuses_before_migration_mutation() {
    let (database, receipts, key, _) = prepare_pre_slice_state("state-root-migration-schema", true);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch("CREATE TABLE shadow_state(value INTEGER);")
        .unwrap();
    drop(connection);
    let before = fs::read(&database).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&database).unwrap(), before);
    let root = database.parent().unwrap();
    assert!(!root.join(".backup.lock").exists());
    assert!(!root.join("deployment.json").exists());
    assert!(!root.join("restore.ready").exists());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn nonstopped_pre_slice_state_refuses_without_leaving_migration_bytes() {
    let (database, receipts, key, database_before) =
        prepare_pre_slice_state("state-root-migration-rejected", false);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("init")
        .args(arguments(&database, &receipts, &key))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&database).unwrap(), database_before);
    let root = database.parent().unwrap();
    assert!(!root.join(".backup.lock").exists());
    assert!(!root.join("deployment.json").exists());
    assert!(!root.join("restore.ready").exists());
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn running_service_refuses_state_root_path_substitution_before_admission() {
    let (database, receipts, key) = fixture("running-substitution");
    let root = database.parent().unwrap().to_owned();
    let (mut child, address) = start(&database, &receipts, &key);
    let moved = root.with_file_name("moved-state");
    fs::rename(&root, &moved).unwrap();
    symlink(&moved, &root).unwrap();
    let response = request(&address, &admission("abababababababababababababababab"));
    assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    let runs: i64 = rusqlite::Connection::open(moved.join("sandbox.sqlite3"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(runs, 0);
    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_file(&root).unwrap();
    fs::rename(&moved, &root).unwrap();
    common::remove_root(root.parent().unwrap().parent().unwrap());
}

#[test]
fn native_listener_and_operator_stop_preserve_the_public_boundary() {
    let (database, receipts, digest_key) = fixture("stop");
    let root = database.parent().unwrap().to_owned();
    let (mut child, address) = start(&database, &receipts, &digest_key);

    let first_key = "01010101010101010101010101010101";
    let first = request(&address, &admission(first_key));
    assert!(first.starts_with(b"HTTP/1.1 201 Created\r\n"));
    assert!(!String::from_utf8_lossy(&first).contains(first_key));

    let unavailable_key = digest_key.with_file_name("digest-key-unavailable");
    fs::rename(&digest_key, &unavailable_key).unwrap();
    operate("stop", &database);
    fs::rename(&unavailable_key, &digest_key).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let (mut child, address) = start(&database, &receipts, &digest_key);
    let stopped = request(&address, &admission("02020202020202020202020202020202"));
    assert!(stopped.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(String::from_utf8_lossy(&stopped).contains("service_unavailable"));

    let replay = request(&address, &admission(first_key));
    assert!(replay.starts_with(b"HTTP/1.1 200 OK\r\n"));
    fs::rename(&digest_key, &unavailable_key).unwrap();
    operate("clear-stop", &database);
    fs::rename(&unavailable_key, &digest_key).unwrap();
    let resumed = request(&address, &admission("03030303030303030303030303030303"));
    assert!(resumed.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    common::remove_root(&root);
}

#[test]
fn raw_framing_and_body_bounds_fail_before_admission() {
    let (database, receipts, digest_key) = fixture("bounds");
    let root = database.parent().unwrap().to_owned();
    let (mut child, address) = start(&database, &receipts, &digest_key);
    let rejected_key = "04040404040404040404040404040404";
    let oversized = format!(
        concat!(
            "POST /sandbox/v1/runs HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "content-type: application/json\r\n",
            "content-length: 513\r\n",
            "idempotency-key: {}\r\n\r\n"
        ),
        rejected_key
    );
    let response = request(&address, oversized.as_bytes());
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

    let conflicting = format!(
        concat!(
            "POST /sandbox/v1/runs HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "content-type: application/json\r\n",
            "content-length: 1\r\n",
            "content-length: 1\r\n",
            "idempotency-key: {}\r\n\r\nx"
        ),
        rejected_key
    );
    assert!(request(&address, conflicting.as_bytes()).is_empty());
    let oversized_head = format!(
        concat!(
            "GET /sandbox/v1/runs/04040404040404040404040404040404 HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "x-padding: {}\r\n\r\n"
        ),
        "x".repeat(REQUEST_HEAD_OVERFLOW_PADDING)
    );
    assert!(oversized_head.len() > 8 * 1024);
    assert!(request(&address, oversized_head.as_bytes()).is_empty());

    let oversized_request_line = format!(
        "GET /{} HTTP/1.1\r\nhost: kapsel.invalid\r\n\r\n",
        "x".repeat(512)
    );
    assert!(oversized_request_line.find("\r\n").unwrap() > 512);
    assert!(request(&address, oversized_request_line.as_bytes()).is_empty());

    let mut too_many_headers = String::from(concat!(
        "GET /sandbox/v1/runs/04040404040404040404040404040404 HTTP/1.1\r\n",
        "host: kapsel.invalid\r\n"
    ));
    for index in 0..16 {
        write!(too_many_headers, "x-{index}: value\r\n").unwrap();
    }
    too_many_headers.push_str("\r\n");
    assert!(request(&address, too_many_headers.as_bytes()).is_empty());

    let oversized_header_value = format!(
        concat!(
            "GET /sandbox/v1/runs/04040404040404040404040404040404 HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "x-value: {}\r\n\r\n"
        ),
        "x".repeat(257)
    );
    assert!(request(&address, oversized_header_value.as_bytes()).is_empty());

    let accepted = request(&address, &admission(rejected_key));
    assert!(accepted.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    common::remove_root(&root);
}

#[test]
fn exact_raw_limits_are_accepted() {
    let (database, receipts, digest_key) = fixture("exact-bounds");
    let root = database.parent().unwrap().to_owned();
    let (mut child, address) = start(&database, &receipts, &digest_key);

    let exact_line_uri = format!("/{}", "x".repeat(498));
    let exact_line = format!("GET {exact_line_uri} HTTP/1.1\r\nhost: kapsel.invalid\r\n\r\n");
    assert_eq!(exact_line.find("\r\n").unwrap(), 512);
    assert!(!request(&address, exact_line.as_bytes()).is_empty());

    let mut exact_header_count = admission("06060606060606060606060606060606");
    let split = exact_header_count
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let mut extra_headers = String::new();
    for index in 0..12 {
        write!(extra_headers, "x-{index}: v\r\n").unwrap();
    }
    exact_header_count.splice(split + 2..split + 2, extra_headers.bytes());
    let response = request(&address, &exact_header_count);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));

    let mut exact_header_value = admission("07070707070707070707070707070707");
    let split = exact_header_value
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    exact_header_value.splice(
        split + 2..split + 2,
        format!("x-value: {}\r\n", "x".repeat(256)).bytes(),
    );
    let response = request(&address, &exact_header_value);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));

    let exact_head_prefix = concat!(
        "GET /sandbox/v1/runs/04040404040404040404040404040404 HTTP/1.1\r\n",
        "host: kapsel.invalid\r\n"
    );
    let exact_head_suffix = ": v\r\n\r\n";
    let header_name_length = 8 * 1024 - exact_head_prefix.len() - exact_head_suffix.len();
    let exact_head = format!(
        "{exact_head_prefix}{}{exact_head_suffix}",
        "x".repeat(header_name_length)
    );
    assert_eq!(exact_head.len(), 8 * 1024);
    assert!(!request(&address, exact_head.as_bytes()).is_empty());

    let mut exact_body = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    exact_body.resize(512, b' ');
    let exact_body_request = concat!(
        "POST /sandbox/v1/runs HTTP/1.1\r\n",
        "host: kapsel.invalid\r\n",
        "content-type: application/json\r\n",
        "content-length: 512\r\n",
        "idempotency-key: 08080808080808080808080808080808\r\n\r\n"
    )
    .bytes()
    .chain(exact_body)
    .collect::<Vec<_>>();
    let response = request(&address, &exact_body_request);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    common::remove_root(&root);
}

#[test]
fn receive_deadlines_close_partial_headers_and_bodies() {
    let (database, receipts, digest_key) = fixture("receive-timeouts");
    let root = database.parent().unwrap().to_owned();
    let (mut child, address) = start(&database, &receipts, &digest_key);

    expect_receive_timeout(&address, b"GET /sandbox/v1/runs/");
    expect_receive_timeout(
        &address,
        concat!(
            "POST /sandbox/v1/runs HTTP/1.1\r\n",
            "host: kapsel.invalid\r\n",
            "content-type: application/json\r\n",
            "content-length: 1\r\n",
            "idempotency-key: 05050505050505050505050505050505\r\n\r\n"
        )
        .as_bytes(),
    );

    let accepted = request(&address, &admission("05050505050505050505050505050505"));
    assert!(accepted.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    common::remove_root(&root);
}

#[test]
fn retention_role_opens_only_system_state_and_rejects_transport_configuration() {
    let (database, receipts, digest_key) = fixture("retention-role");
    let root = database.parent().unwrap().to_owned();
    initialize(&database, &receipts, &digest_key);
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let service = Service::open(
        &database,
        &receipts,
        &common::authority_configuration(
            database
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
            [7; 32],
        ),
        now - 172_800,
    )
    .unwrap();
    service
        .admit(
            "09090909090909090909090909090909",
            Scenario::Healthy,
            now - 172_800,
        )
        .unwrap();
    drop(service);

    for extra in [
        ["--origin", "https://kapsel.invalid"],
        ["--listen", "127.0.0.1:0"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
            .arg("retention")
            .args(arguments(&database, &receipts, &digest_key))
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let retained: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(retained, 1);
    }

    let mut role = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
        .arg("retention")
        .args(arguments(&database, &receipts, &digest_key))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        let retained: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .unwrap();
        if retained == 0 {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(role.try_wait().unwrap().is_none());
    role.kill().unwrap();
    let output = role.wait_with_output().unwrap();
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    common::remove_root(&root);
}

#[test]
fn runner_mode_rejects_system_state_arguments_before_opening_any_input() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-runner-boundary-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = root.join("system-state.sqlite3");
    fs::write(&sentinel, b"must-not-open").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o000)).unwrap();
    for arguments in [
        vec!["runner", "--database", sentinel.to_str().unwrap()],
        vec![
            "runner-bootstrap",
            "--operator-composition",
            root.join("missing.json").to_str().unwrap(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("usage") || stderr.contains("bootstrap arguments are invalid"));
        assert!(!stderr.contains(sentinel.to_str().unwrap()));
    }
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), b"must-not-open");
    common::remove_root(&root);
}

#[test]
fn superseded_controller_and_stager_commands_are_unreachable() {
    for command in [
        "scheduler-state-serve",
        "cleanup-state-serve",
        "scheduler",
        "cleanup",
        "stage-controller-tls",
        "stage-tombstone-key",
        "stage-authorization-grant",
        "stage-receipt-signing",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox-test-harness"))
            .arg(command)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains(command));
        assert!(stderr.contains("init|serve|handoff-serve|controller|retention|stop|clear-stop"));
    }
}
