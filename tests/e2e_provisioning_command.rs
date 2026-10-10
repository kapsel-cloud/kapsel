//! The operator command provisions exact grants without overwriting files or accepting bad seeds.

#![allow(
    clippy::unwrap_used,
    reason = "controlled binary fixtures fail immediately"
)]

use std::{
    fs,
    io::{Read, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "kapsel-e2e-{name}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct SnapshotServer {
    kubeconfig: PathBuf,
    done: mpsc::Receiver<Result<(), String>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl SnapshotServer {
    fn wait(mut self) {
        let result = self.done.recv_timeout(Duration::from_secs(3));
        assert!(
            result.is_ok(),
            "snapshot fixture server did not finish before deadline"
        );
        self.handle.take().unwrap().join().unwrap();
        result.unwrap().unwrap();
    }
}

fn snapshot_command_output(mut command: Command) -> Result<Output, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return Ok(child.wait_with_output().unwrap());
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            return Err(format!(
                "command timed out; stdout={:?} stderr={:?}",
                output.stdout, output.stderr
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "snapshot fixture deadline elapsed".into())
}

fn read_http_request_line(reader: &mut impl Read) -> Result<String, String> {
    const REQUEST_HEAD_BYTES_MAX: usize = 4096;
    let mut bytes = Vec::new();
    let mut chunk = [0; 32];
    loop {
        let length = reader.read(&mut chunk).map_err(|error| error.to_string())?;
        if length == 0 {
            return Err("connection closed before request headers".into());
        }
        bytes.extend_from_slice(&chunk[..length]);
        if bytes.len() > REQUEST_HEAD_BYTES_MAX {
            return Err("request headers exceeded bounded fixture limit".into());
        }
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let end = bytes
                .windows(2)
                .position(|window| window == b"\r\n")
                .ok_or("request headers ended without request line")?;
            return std::str::from_utf8(&bytes[..end])
                .map(str::to_owned)
                .map_err(|error| error.to_string());
        }
    }
}

struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let timeout = remaining(self.deadline).map_err(std::io::Error::other)?;
        self.stream.set_read_timeout(Some(timeout))?;
        let length = self.stream.read(output)?;
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "snapshot fixture read deadline elapsed",
            ));
        }
        Ok(length)
    }
}

fn snapshot_kubeconfig(root: &Path) -> SnapshotServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (done_sender, done) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = serve_snapshot_deployment(&listener);
        done_sender.send(result).unwrap();
    });
    let kubeconfig = root.join("kubeconfig.yaml");
    fs::write(
        &kubeconfig,
        format!(
            concat!(
                "apiVersion: v1\n",
                "kind: Config\n",
                "clusters:\n",
                "- name: local\n",
                "  cluster:\n",
                "    server: http://{}\n",
                "contexts:\n",
                "- name: local\n",
                "  context:\n",
                "    cluster: local\n",
                "    user: local\n",
                "current-context: local\n",
                "users:\n",
                "- name: local\n",
                "  user:\n",
                "    token: local-token\n"
            ),
            address
        ),
    )
    .unwrap();
    SnapshotServer {
        kubeconfig,
        done,
        handle: Some(handle),
    }
}

fn write_valid_authorization(path: &Path) {
    fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("example/api@sha256:{}", "a".repeat(64)),
        }))
        .unwrap(),
    )
    .unwrap();
}

fn serve_snapshot_deployment(listener: &TcpListener) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                remaining(deadline).map_err(|_| {
                    String::from("snapshot fixture server saw no request before deadline")
                })?;
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => return Err(error.to_string()),
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    let request_line = read_http_request_line(&mut DeadlineStream {
        stream: &mut stream,
        deadline,
    })?;
    if !request_line.starts_with("GET /apis/apps/v1/namespaces/demo/deployments/agent-api ") {
        return Err(format!("unexpected request line: {request_line}"));
    }

    let deployment_body = serde_json::to_vec(&serde_json::json!({
        "apiVersion":"apps/v1",
        "kind":"Deployment",
        "metadata":{"uid":"deployment-uid-1","resourceVersion":"resource-version-0"},
        "spec":{"template":{"spec":{"containers":[{"name":"api"}]}}},
    }))
    .unwrap();
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        deployment_body.len()
    )
    .map_err(|error| error.to_string())?;
    remaining(deadline)?;
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&deployment_body)
        .map_err(|error| error.to_string())?;
    remaining(deadline).map(|_| ())
}

#[test]
fn operator_can_provision_exact_grant_without_overwriting_or_accepting_bad_seeds() {
    let root = std::env::temp_dir().join(format!("kapsel-e2e-provision-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let authorization = root.join("authorization.json");
    let seed = root.join("owner.seed");
    let grant = root.join("grant.bin");
    fs::write(
        &authorization,
        serde_json::to_vec(&serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("example/api@sha256:{}", "a".repeat(64)),
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&seed, [7; 32]).unwrap();
    let run = |output: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .arg("provision-grant")
            .arg("--authorization")
            .arg(&authorization)
            .arg("--signing-seed")
            .arg(&seed)
            .args(["--signing-key-id", "owner-key"])
            .arg("--output")
            .arg(output)
            .output()
            .unwrap()
    };

    let output = run(&grant);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"command\":\"provision-grant\",\"status\":\"PROVISIONED\"}\n"
    );
    assert_eq!(
        fs::metadata(&grant).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let original_grant_bytes = fs::read(&grant).unwrap();
    assert_eq!(run(&grant).status.code(), Some(3));
    assert_eq!(fs::read(&grant).unwrap(), original_grant_bytes);

    for length in [31, 33] {
        fs::write(&seed, vec![7; length]).unwrap();
        let destination = root.join(format!("bad-{length}.grant"));
        assert_eq!(run(&destination).status.code(), Some(3));
        assert!(!destination.exists());
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fragmented_snapshot_fixture_request_line_is_accepted() {
    struct FragmentedRead {
        fragments: std::collections::VecDeque<&'static [u8]>,
    }

    impl Read for FragmentedRead {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let Some(fragment) = self.fragments.pop_front() else {
                return Ok(0);
            };
            let length = fragment.len().min(output.len());
            output[..length].copy_from_slice(&fragment[..length]);
            assert_eq!(
                length,
                fragment.len(),
                "fixture fragments must fit in parser buffer"
            );
            Ok(length)
        }
    }

    let mut input = FragmentedRead {
        fragments: [
            &b"GET /de"[..],
            &b"mo HTTP/1.1\r"[..],
            &b"\nHost: local\r\n\r"[..],
            &b"\n"[..],
        ]
        .into(),
    };
    assert_eq!(
        read_http_request_line(&mut input).unwrap(),
        "GET /demo HTTP/1.1"
    );
}

#[test]
fn snapshot_grant_output_write_failure_uses_snapshot_command_and_preserves_file() {
    let root = TestRoot::new("snapshot-provision");
    let authorization = root.path().join("authorization.json");
    let seed = root.path().join("owner.seed");
    let grant = root.path().join("grant.bin");
    let original_grant_bytes = b"existing grant bytes";
    fs::write(
        &authorization,
        serde_json::to_vec(&serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("example/api@sha256:{}", "a".repeat(64)),
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&seed, [7; 32]).unwrap();
    fs::write(&grant, original_grant_bytes).unwrap();
    let server = snapshot_kubeconfig(root.path());

    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel"));
    command
        .arg("provision-snapshot-grant")
        .arg("--kubeconfig")
        .arg(&server.kubeconfig)
        .arg("--authorization")
        .arg(&authorization)
        .arg("--signing-seed")
        .arg(&seed)
        .args(["--signing-key-id", "owner-key"])
        .arg("--output")
        .arg(&grant);
    let output = snapshot_command_output(command).unwrap();

    server.wait();
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"{\"command\":\"provision-snapshot-grant\",\"status\":\"ERROR\",\
          \"error_class\":\"operator_configuration\"}\n"
    );
    assert_eq!(fs::read(&grant).unwrap(), original_grant_bytes);
}

#[test]
fn malformed_snapshot_kubeconfig_is_operator_configuration_failure() {
    let root = TestRoot::new("snapshot-malformed-kubeconfig");
    let authorization = root.path().join("authorization.json");
    let kubeconfig = root.path().join("kubeconfig.yaml");
    let seed = root.path().join("owner.seed");
    let grant = root.path().join("grant.bin");
    write_valid_authorization(&authorization);
    fs::write(&kubeconfig, b"not: [valid").unwrap();
    fs::write(&seed, [7; 32]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .arg("provision-snapshot-grant")
        .arg("--authorization")
        .arg(&authorization)
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .arg("--signing-seed")
        .arg(&seed)
        .args(["--signing-key-id", "owner-key"])
        .arg("--output")
        .arg(&grant)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        output.stdout,
        b"{\"command\":\"provision-snapshot-grant\",\"status\":\"ERROR\",\
          \"error_class\":\"operator_configuration\"}\n"
    );
    assert_eq!(
        output.stderr,
        b"Kapsel command failure: operator_configuration\n"
    );
    assert!(!grant.exists());
}

#[test]
fn malformed_snapshot_authorization_remains_command_input_failure() {
    let root = TestRoot::new("snapshot-malformed-authorization");
    let authorization = root.path().join("authorization.json");
    let kubeconfig = root.path().join("kubeconfig.yaml");
    let seed = root.path().join("owner.seed");
    let grant = root.path().join("grant.bin");
    fs::write(&authorization, b"not json").unwrap();
    fs::write(&kubeconfig, b"not: [valid").unwrap();
    fs::write(&seed, [7; 32]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .arg("provision-snapshot-grant")
        .arg("--authorization")
        .arg(&authorization)
        .arg("--kubeconfig")
        .arg(&kubeconfig)
        .arg("--signing-seed")
        .arg(&seed)
        .args(["--signing-key-id", "owner-key"])
        .arg("--output")
        .arg(&grant)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stdout,
        b"{\"command\":\"provision-snapshot-grant\",\"status\":\"ERROR\",\
          \"error_class\":\"command_input\"}\n"
    );
    assert!(!grant.exists());
}

#[test]
fn direct_execution_commands_are_rejected_before_reading_operator_or_request_paths() {
    for command in ["operate", "mcp"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([command, "--operator-config", "/unavailable/operator.json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            output.stdout,
            b"{\"command\":\"kapsel\",\"status\":\"ERROR\",\"error_class\":\"command_input\"}\n"
        );
        assert!(output.stderr.len() < 4096);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(!help.contains("kapsel operate"));
    assert!(!help.contains("kapsel mcp --"));
    assert!(help.contains("kapseld"));
    assert!(help.contains("kapsel inspect"));
}
