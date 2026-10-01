//! Real daemon diagnostics remain bounded while admitted history stays available offline.
use super::*;

fn command(root: &Path) -> Command {
    let mut command = installed_command(
        root,
        1,
        &[
            "--operator-config",
            "/etc/kapsel/operator.json",
            "--socket",
            "/run/kapsel/kapseld.sock",
        ],
    );
    command.env_remove("KAPSELD_TEST_CONNECTIONS");
    command
}

fn start(root: &Path) -> ChildGuard {
    ChildGuard::new(command(root).spawn().unwrap())
}

fn stop(mut child: ChildGuard) -> Output {
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "diagnostics must not hold retirement"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    output
}

fn status(socket: &Path) -> serde_json::Value {
    let mut stream = connect(socket);
    write_frame(
        &mut stream,
        br#"{"request":"get_set_deployment_image_status","operation_id":"process-op"}"#,
    );
    serde_json::from_slice(&read_frame(&mut stream)).unwrap()
}

fn repeated_read_failures(socket: &Path) {
    for _ in 0..8 {
        assert_eq!(
            status(socket),
            serde_json::json!({
                "status":"ERROR", "error_class":"authority_unavailable",
            })
        );
        for request in [
            concat!(
                r#"{"request":"get_set_deployment_image_receipt","#,
                r#""operation_id":"process-op"}"#
            ),
            r#"{"request":"list_operation_history","after":null}"#,
        ] {
            let mut stream = connect(socket);
            write_frame(&mut stream, request.as_bytes());
            let value: serde_json::Value =
                serde_json::from_slice(&read_frame(&mut stream)).unwrap();
            let error = if value["status"] == "READY" {
                &value["entries"][0]
            } else {
                &value
            };
            assert_eq!(error["error_class"], "authority_unavailable");
            assert!(error.get("execution").is_none());
        }
    }
}

#[test]
fn full_stderr_cannot_hold_execution_status_or_graceful_retirement() {
    let root = installation_root("diagnostic-backpressure");
    private_file(
        &root.join("etc/kapsel/kubeconfig.yaml"),
        b"invalid-material",
    );
    let (mut writer, _reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut filled = 0;
    loop {
        match writer.write(&[b'x'; 4096]) {
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fixture fill failed: {error}"),
        }
        assert!(filled < 16 * 1024 * 1024);
    }
    writer.set_nonblocking(false).unwrap();
    let fd = std::os::fd::OwnedFd::from(writer.try_clone().unwrap());
    let child = ChildGuard::new(command(&root).stderr(Stdio::from(fd)).spawn().unwrap());
    let socket = root.join("run/kapsel/kapseld.sock");
    let mut selection = connect(&socket);
    write_frame(&mut selection, submit_request().as_bytes());
    assert_admitted(&mut selection, "requested");
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    loop {
        let observed = status(&socket);
        if observed["execution"]["disposition"] == "operator_required" {
            assert_eq!(observed["execution"]["condition"], "receiver_unavailable");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "sink cannot retain physical execution"
        );
        thread::sleep(Duration::from_millis(5));
    }
    stop(child);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admitted_without_credentials_survives_disconnect_restart_and_authority_loss() {
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let root = installation_root_with_url(
        "disposition",
        &format!("http://{}", receiver.local_addr().unwrap()),
    );
    private_file(
        &root.join("etc/kapsel/kubeconfig.yaml"),
        b"SECRET-CREDENTIAL /private/path",
    );
    let socket = root.join("run/kapsel/kapseld.sock");
    let child = start(&root);
    let mut selection = connect(&socket);
    write_frame(&mut selection, submit_request().as_bytes());
    drop(selection);
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    loop {
        let observed = status(&socket);
        if observed["execution"]["disposition"] == "operator_required" {
            assert_eq!(observed["status"], "IN_PROGRESS");
            assert_eq!(observed["execution"]["condition"], "receiver_unavailable");
            assert_eq!(observed["execution"]["action_owner"], "operator");
            break;
        }
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    assert_eq!(stop(child).stderr, b"kapseld: receiver_unavailable\n");
    let frozen = fs::read(root.join("var/lib/kapsel/journal.sqlite3")).unwrap();
    let child = start(&root);
    let observed = status(&socket);
    assert_eq!(observed["execution"]["disposition"], "resume_required");
    assert!(observed["execution"]["condition"].is_null());
    assert_eq!(stop(child).stderr, b"");
    assert_eq!(
        fs::read(root.join("var/lib/kapsel/journal.sqlite3")).unwrap(),
        frozen
    );
    let path = root.join("etc/kapsel/operator.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["approvals"] = serde_json::json!([]);
    document["authorization_keys"] = serde_json::json!([]);
    private_file(&path, &serde_json::to_vec(&document).unwrap());
    let child = start(&root);
    repeated_read_failures(&socket);
    let mut selection = connect(&socket);
    write_frame(&mut selection, submit_request().as_bytes());
    let refused: serde_json::Value = serde_json::from_slice(&read_frame(&mut selection)).unwrap();
    assert_eq!(refused["error_class"], "authority_unavailable");
    // One read-access class and one explicit selection failure, never another from rendering.
    assert_eq!(
        stop(child).stderr,
        concat!(
            "kapseld: original_authority_unavailable\n",
            "kapseld: original_authority_unavailable\n",
        )
        .as_bytes()
    );
    assert!(
        matches!(receiver.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    private_file(&path, b"SECRET-GRANT /private/configuration");
    let output = start(&root).wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"kapseld: configuration_invalid\n");
    fs::remove_dir_all(root).unwrap();
}
