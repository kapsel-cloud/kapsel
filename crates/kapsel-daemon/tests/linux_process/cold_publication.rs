//! Real entrypoint exclusion, startup/receiver stop barriers and cold history continuity.
use super::*;

fn spawn_publisher(root: &Path) -> ChildGuard {
    let mut command = installed_command(root, 1, &["--replace-operator-config"]);
    command.stdin(Stdio::piped());
    ChildGuard::new(command.spawn().unwrap())
}

fn wait_for_retirement(mut child: ChildGuard) -> Output {
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "child did not retire");
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn publish_operator_document(root: &Path, bytes: &[u8]) -> Output {
    let mut child = spawn_publisher(root);
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    wait_for_retirement(child)
}

fn assert_outcome(output: &Output, exit: i32, line: &[u8]) {
    assert_eq!(output.status.code(), Some(exit));
    assert_eq!(output.stdout, line);
    assert!(output.stderr.is_empty());
}

fn terminate(child: &ChildGuard) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
}

fn assert_lifecycle_excluded(root: &Path) {
    // Keep stdin open: a contender consuming authority would hang instead of exiting.
    let contender = spawn_publisher(root);
    assert_outcome(&wait_for_retirement(contender), 4, b"NOT_PUBLISHED\n");
    let output = wait_for_retirement(spawn_installed(root, 1));
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"kapseld: provisioning_unavailable\n");
}

#[test]
fn publisher_publisher_and_publisher_daemon_contend_before_authority_consumption() {
    let root = installation_root("cold-publisher-contention");
    let operator_document_path = root.join("etc/kapsel/operator.json");
    let bytes = fs::read(&operator_document_path).unwrap();
    let mut first = spawn_publisher(&root);
    wait_for_marker(&mut first, &root.join("control/publisher.ready"));

    // Invalid active authority must not matter to either contender before exclusion fails.
    private_file(&operator_document_path, b"invalid authority");
    assert_lifecycle_excluded(&root);
    assert!(!root.join("var/lib/kapsel/journal.sqlite3").exists());

    first.stdin.take().unwrap().write_all(&bytes).unwrap();
    assert_outcome(&wait_for_retirement(first), 0, b"PUBLISHED\n");
    assert_eq!(fs::read(&operator_document_path).unwrap(), bytes);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sigterm_during_startup_retains_exclusion_then_retires_without_binding() {
    let root = installation_root("cold-startup-stop");
    let mut command = installed_command(
        &root,
        10,
        &[
            "--operator-config",
            "/etc/kapsel/operator.json",
            "--socket",
            "/run/kapsel/kapseld.sock",
        ],
    );
    command.env("KAPSELD_TEST_PAUSE_STARTUP", "1");
    let mut first = ChildGuard::new(command.spawn().unwrap());
    wait_for_marker(&mut first, &root.join("control/startup.ready"));
    assert_lifecycle_excluded(&root);

    terminate(&first);
    wait_for_marker(&mut first, &root.join("control/stop.ready"));
    assert_lifecycle_excluded(&root);
    assert!(first.try_wait().unwrap().is_none());
    assert!(!root.join("run/kapsel/kapseld.sock").exists());

    fs::write(root.join("control/startup.release"), b"").unwrap();
    let output = wait_for_retirement(first);
    assert!(output.status.success());
    assert!(!root.join("run/kapsel/kapseld.sock").exists());

    let bytes = fs::read(root.join("etc/kapsel/operator.json")).unwrap();
    assert_outcome(&publish_operator_document(&root, &bytes), 0, b"PUBLISHED\n");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sigterm_drains_provider_before_publication_and_catalog_key_removal_preserves_receipt() {
    let server = success_server();
    let root = installation_root_with_url("cold-provider-stop", &server.url);
    let socket = root.join("run/kapsel/kapseld.sock");
    let mut first = spawn_installed(&root, 10);
    let mut submission = connect(&socket);
    write_frame(&mut submission, submit_request().as_bytes());
    assert_admitted(&mut submission, "requested");
    server
        .observation_started
        .recv_timeout(FIXTURE_TIMEOUT)
        .unwrap();
    assert_lifecycle_excluded(&root);
    terminate(&first);
    wait_for_marker(&mut first, &root.join("control/stop.ready"));
    assert_lifecycle_excluded(&root);
    assert!(first.try_wait().unwrap().is_none());
    // A stopped listener cannot accept a new caller, even while the provider job is retained.
    assert!(UnixStream::connect(&socket).is_err());
    server.release_observation.send(()).unwrap();
    assert!(wait_for_retirement(first).status.success());

    let journal = root.join("var/lib/kapsel/journal.sqlite3");
    let original_journal = fs::read(&journal).unwrap();
    let connection =
        rusqlite::Connection::open_with_flags(&journal, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let original_receipt: Vec<u8> = connection
        .query_row(
            "SELECT receipt_bytes FROM kubernetes_image_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    let operator_document_path = root.join("etc/kapsel/operator.json");
    let mut candidate: serde_json::Value =
        serde_json::from_slice(&fs::read(&operator_document_path).unwrap()).unwrap();
    candidate["approvals"] = serde_json::json!([]);
    let with_trust = serde_json::to_vec(&candidate).unwrap();
    assert_outcome(
        &publish_operator_document(&root, &with_trust),
        0,
        b"PUBLISHED\n",
    );
    assert_eq!(fs::read(&journal).unwrap(), original_journal);
    let next = spawn_installed(&root, 1);
    let mut receipt = connect(&socket);
    write_frame(
        &mut receipt,
        br#"{"request":"get_set_deployment_image_receipt","operation_id":"process-op"}"#,
    );
    let response: serde_json::Value = serde_json::from_slice(&read_frame(&mut receipt)).unwrap();
    assert_eq!(response["status"], "READY");
    assert_eq!(response["receipt_hex"], lowercase_hex(&original_receipt));
    assert!(wait_for_retirement(next).status.success());

    candidate["authorization_keys"] = serde_json::json!([]);
    let without_trust = serde_json::to_vec(&candidate).unwrap();
    assert_outcome(
        &publish_operator_document(&root, &without_trust),
        0,
        b"PUBLISHED\n",
    );
    let next = spawn_installed(&root, 1);
    let mut receipt = connect(&socket);
    write_frame(
        &mut receipt,
        br#"{"request":"get_set_deployment_image_receipt","operation_id":"process-op"}"#,
    );
    let response: serde_json::Value = serde_json::from_slice(&read_frame(&mut receipt)).unwrap();
    assert_eq!(response["error_class"], "authority_unavailable");
    assert!(wait_for_retirement(next).status.success());
    assert_eq!(fs::read(&journal).unwrap(), original_journal);

    assert_outcome(
        &publish_operator_document(&root, &with_trust),
        0,
        b"PUBLISHED\n",
    );
    server.finish();
    fs::remove_dir_all(root).unwrap();
}
