//! Linux real-process proof for the compile-time service test harness.

#![cfg(all(target_os = "linux", feature = "test-harness"))]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled process fixtures must fail the Linux gate immediately"
)]

use std::{
    fmt::Write as _,
    fs,
    io::{Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener as StdUnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use kapsel::{
    provision_exact_grant, ExactAuthorization, GrantProvisioning, InspectionLimits,
    InspectionStatus, ReceiptTrust,
};
use rusqlite::Connection;
use serde_json::Value;
use sha2::Digest as _;

#[path = "linux_process/cold_publication.rs"]
mod cold_publication;
#[path = "linux_process/disposition.rs"]
mod disposition;

const IMAGE: &str = concat!(
    "registry.example/agent-api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);
const OLD_IMAGE: &str = concat!(
    "registry.example/agent-api@sha256:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
const DEPLOYMENT_PATH: &str = "/apis/apps/v1/namespaces/demo/deployments/agent-api";
const PATCH_DEPLOYMENT_PATH: &str = "/apis/apps/v1/namespaces/demo/deployments/agent-api?";
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);

#[path = "support/child.rs"]
mod child;
use child::ChildGuard;
fn root(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("kapseld-linux-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    path
}

fn effective_uid() -> u32 {
    numeric_identity("-u")
}

fn effective_gid() -> u32 {
    numeric_identity("-g")
}

fn numeric_identity(argument: &str) -> u32 {
    let output = ChildGuard::output(Command::new("id").arg(argument)).unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn kapseld_executable() -> PathBuf {
    std::env::var_os("KAPSELD_TEST_EXECUTABLE").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_kapseld")),
        PathBuf::from,
    )
}

fn spawn_installed(root: &Path, connections: usize) -> ChildGuard {
    spawn_installed_with_arguments(
        root,
        connections,
        &[
            "--operator-config",
            "/etc/kapsel/operator.json",
            "--socket",
            "/run/kapsel/kapseld.sock",
        ],
    )
}

fn spawn_installed_with_arguments(
    root: &Path,
    connections: usize,
    arguments: &[&str],
) -> ChildGuard {
    ChildGuard::new(
        installed_command(root, connections, arguments)
            .spawn()
            .unwrap(),
    )
}

fn spawn_installed_with_seam(root: &Path, connections: usize, seam: &str) -> ChildGuard {
    let mut command = installed_command(
        root,
        connections,
        &[
            "--operator-config",
            "/etc/kapsel/operator.json",
            "--socket",
            "/run/kapsel/kapseld.sock",
        ],
    );
    command
        .env("KAPSEL_DEMO_CONTROL_DIRECTORY", root.join("control"))
        .env("KAPSEL_DEMO_PAUSE", seam);
    ChildGuard::new(command.spawn().unwrap())
}

fn installed_command(root: &Path, connections: usize, arguments: &[&str]) -> Command {
    let mut command = Command::new(kapseld_executable());
    command
        .args(arguments)
        .env("KAPSELD_TEST_INSTALLATION_ROOT", root)
        .env("KAPSELD_TEST_CONNECTIONS", connections.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn connect(socket: &Path) -> UnixStream {
    connect_with_timeout(socket, Duration::from_secs(5))
}

fn connect_with_timeout(socket: &Path, timeout: Duration) -> UnixStream {
    let deadline = Instant::now() + timeout;
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => {
                stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                return stream;
            },
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => panic!("kapseld did not bind: {error}"),
        }
    }
}

fn wait_for_socket(socket: &Path) {
    // A killed daemon leaves its pathname behind. Successful connection, not existence, proves
    // the replacement listener is bound. The fixture connection budget includes this probe.
    drop(connect(socket));
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) {
    // Keep hostile raw members intact while supplying the common versioned envelope.
    let versioned = if body.first() == Some(&b'{') {
        [b"{\"version\":1,".as_slice(), &body[1..]].concat()
    } else {
        body.to_vec()
    };
    let body = versioned.as_slice();
    stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut response).unwrap();
    remove_top_level_version(&response)
}

fn remove_top_level_version(body: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(body).unwrap();
    let object = value.as_object_mut().unwrap();
    assert_eq!(object.remove("version"), Some(serde_json::json!(1)));
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn process_read_frame_payload_removes_only_top_level_version() {
    let payload =
        remove_top_level_version(br#"{"version":1,"status":"READY","service":{"version":1}}"#);
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        serde_json::json!({"status":"READY","service":{"version":1}})
    );
}

fn assert_admission_unconfirmed(stream: &mut UnixStream) {
    let response: Value = serde_json::from_slice(&read_frame(stream)).unwrap();
    assert_eq!(
        response,
        serde_json::json!({
            "status":"NOT_FOUND", "execution": {
                "disposition":"admission_unconfirmed", "condition":null,
                "next_action":"read_same_id", "action_owner":"caller"},
        })
    );
}

fn assert_admitted(stream: &mut UnixStream, phase: &str) {
    let response: Value = serde_json::from_slice(&read_frame(stream)).unwrap();
    assert_eq!(
        response,
        serde_json::json!({"status":"ADMITTED","phase":phase})
    );
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn submit_request() -> String {
    r#"{"request":"submit_set_deployment_image","operation_id":"process-op"}"#.into()
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn installation_root(name: &str) -> PathBuf {
    installation_root_with_url(name, "http://127.0.0.1:1234")
}

fn installation_root_with_url(name: &str, kubernetes_url: &str) -> PathBuf {
    let root = root(name);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for (directory, mode) in [
        ("etc", 0o700),
        ("etc/kapsel", 0o700),
        ("var", 0o700),
        ("var/lib", 0o700),
        ("var/lib/kapsel", 0o700),
        ("var/lib/kapsel/receipts", 0o700),
        ("run", 0o700),
        ("run/kapsel", 0o750),
        ("control", 0o700),
    ] {
        let path = root.join(directory);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let root = fs::canonicalize(root).unwrap();
    let authorization_seed = [111_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &ExactAuthorization {
            approved_target: Some(kapsel::ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "1".into(),
            }),
            authorization_id: "service-auth".into(),
            operation_id: "process-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: IMAGE.into(),
        },
        signing_seed: &authorization_seed,
        signing_key_id: "service-owner-key",
    })
    .unwrap();
    private_file(&root.join("etc/kapsel/grant.bin"), &grant);
    private_file(
        &root.join("etc/kapsel/authorization.pub"),
        &authorization_key.verifying_key().to_bytes(),
    );
    private_file(
        &root.join("etc/kapsel/kubeconfig.yaml"),
        format!(
            concat!(
                "apiVersion: v1\nkind: Config\ncurrent-context: fixture\n",
                "clusters:\n- name: fixture\n  cluster:\n",
                "    server: {}\n",
                "contexts:\n- name: fixture\n  context:\n",
                "    cluster: fixture\n    user: fixture\n",
                "users:\n- name: fixture\n  user: {{}}\n"
            ),
            kubernetes_url
        )
        .as_bytes(),
    );
    private_file(&root.join("etc/kapsel/receipt.seed"), &[112_u8; 32]);
    private_file(
        &root.join("etc/kapsel/operator.json"),
        &serde_json::to_vec(&serde_json::json!({
            "service_configuration_version": 1,
            "authorization_keys": [{
                "key_id":"service-owner-key",
                "public_key_hex":lowercase_hex(&authorization_key.verifying_key().to_bytes()),
            }],
            "approvals": [{"label":"process action","signed_grant_hex":lowercase_hex(&grant)}],
            "receipt_signing_key_id": "service-receipt-key"
        }))
        .unwrap(),
    );
    root
}

fn deployment(resource_version: &str, generation: i64, observed: bool) -> String {
    let mut value = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "agent-api",
            "namespace": "demo",
            "uid": "uid-1",
            "resourceVersion": resource_version,
            "generation": generation
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {
                "metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{
                    "name": "api",
                    "image": if generation == 1 { OLD_IMAGE } else { IMAGE }
                }]}
            }
        }
    });
    if observed {
        value["metadata"]["annotations"] = serde_json::json!({
            "kapsel.dev/kap0038-operation-id": "process-op"
        });
        value["status"] = serde_json::json!({
            "observedGeneration": 2,
            "updatedReplicas": 1,
            "availableReplicas": 1,
            "unavailableReplicas": 0,
            "conditions": [{
                "type": "Available",
                "status": "True",
                "reason": "MinimumReplicasAvailable"
            }]
        });
    }
    value.to_string()
}

fn accept_with_timeout(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "provider fixture accept timed out"
                );
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => panic!("provider fixture accept failed: {error}"),
        }
    }
}

fn read_http_request(listener: &TcpListener) -> (TcpStream, String, String, Vec<u8>) {
    read_http_stream(accept_with_timeout(listener))
}

fn read_http_stream(mut stream: TcpStream) -> (TcpStream, String, String, Vec<u8>) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();

    let mut bytes = Vec::new();
    let request_bytes = loop {
        let mut chunk = [0_u8; 4096];
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("provider fixture read failed: {error}"),
        };
        assert!(
            read > 0,
            "provider fixture request ended before framing completed"
        );
        bytes.extend_from_slice(&chunk[..read]);
        assert!(
            bytes.len() <= 16 * 1024,
            "provider fixture request exceeded bound"
        );
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
        let total = header_end + content_length;
        if bytes.len() >= total {
            break total;
        }
    };
    assert_eq!(
        bytes.len(),
        request_bytes,
        "provider fixture rejected trailing request bytes"
    );
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;

    let request_line = std::str::from_utf8(&bytes[..header_end])
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let mut fields = request_line.split_ascii_whitespace();
    let method = fields.next().unwrap().to_owned();
    let path = fields.next().unwrap().to_owned();
    assert_eq!(fields.next(), Some("HTTP/1.1"));
    assert_eq!(fields.next(), None);
    (stream, method, path, bytes[header_end..].to_vec())
}

fn assert_provider_request(
    method: &str,
    path: &str,
    body: &[u8],
    expected_method: &str,
    expected_path: &str,
) {
    assert_eq!(method, expected_method);
    assert_eq!(path, expected_path);
    if expected_method == "PATCH" {
        assert_eq!(
            serde_json::from_slice::<Value>(body).unwrap(),
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "agent-api",
                    "namespace": "demo",
                    "uid": "uid-1",
                    "resourceVersion": "1",
                    "annotations": {
                        "kapsel.dev/kap0038-operation-id": "process-op"
                    }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "api", "image": IMAGE}]
                        }
                    }
                }
            })
        );
    } else {
        assert!(body.is_empty());
    }
}

fn write_http_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
            "content-length: {}\r\nconnection: close\r\n\r\n"
        ),
        body.len()
    )
    .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

struct SuccessServer {
    url: String,
    patch_count: Arc<AtomicUsize>,
    request_count: Arc<AtomicUsize>,
    stop: mpsc::Sender<()>,
    observation_started: mpsc::Receiver<()>,
    release_observation: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl SuccessServer {
    fn finish(self) {
        let _ = self.stop.send(());
        self.thread.join().unwrap();
        assert_eq!(self.request_count.load(Ordering::Relaxed), 3);
        assert_eq!(self.patch_count.load(Ordering::Relaxed), 1);
    }
}

fn success_server() -> SuccessServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let patch_count = Arc::new(AtomicUsize::new(0));
    let server_patch_count = patch_count.clone();
    let request_count = Arc::new(AtomicUsize::new(0));
    let server_request_count = request_count.clone();
    let (stop, stopped) = mpsc::channel();
    let (observation_started_tx, observation_started) = mpsc::channel();
    let (release_observation, release_observation_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        for (index, (expected_method, expected_path, response_body)) in [
            ("GET", DEPLOYMENT_PATH, deployment("1", 1, false)),
            ("PATCH", PATCH_DEPLOYMENT_PATH, deployment("2", 2, false)),
            ("GET", DEPLOYMENT_PATH, deployment("3", 2, true)),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, method, path, request_body) = read_http_request(&listener);
            server_request_count.fetch_add(1, Ordering::Relaxed);
            if method == "PATCH" {
                server_patch_count.fetch_add(1, Ordering::Relaxed);
            }
            assert_provider_request(
                &method,
                &path,
                &request_body,
                expected_method,
                expected_path,
            );
            if index == 2 {
                observation_started_tx.send(()).unwrap();
                release_observation_rx
                    .recv_timeout(FIXTURE_TIMEOUT)
                    .unwrap();
            }
            write_http_response(&mut stream, &response_body);
        }
        // Remain a live receiver until every restarted process and client has exited.
        // Drain queued connections before accepting shutdown, so late calls cannot hide.
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let (_, method, path, _) = read_http_stream(stream);
                    server_request_count.fetch_add(1, Ordering::Relaxed);
                    if method == "PATCH" {
                        server_patch_count.fetch_add(1, Ordering::Relaxed);
                    }
                    panic!("unexpected provider request after completion: {method} {path}");
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    match stopped.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {},
                    }
                    thread::sleep(Duration::from_millis(10));
                },
                Err(error) => panic!("provider fixture late-request check failed: {error}"),
            }
        }
    });
    SuccessServer {
        url,
        patch_count,
        request_count,
        stop,
        observation_started,
        release_observation,
        thread,
    }
}

fn kill(child: &mut ChildGuard) {
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
}

fn wait_for_marker(child: &mut Child, marker: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "kapseld did not reach fault seam"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "kapseld exited before fault seam"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct FreshCaller {
    script: PathBuf,
    reference: PathBuf,
    socket: PathBuf,
}

impl FreshCaller {
    fn new(root: &Path, socket: &Path) -> Self {
        let script = root.join("fresh_session_caller.py");
        fs::write(
            &script,
            include_str!("../../../examples/fresh_session_caller.py").replace(
                "BRIDGE = \"/usr/bin/kapsel-service-mcp\"",
                &format!("BRIDGE = \"{}\"", env!("CARGO_BIN_EXE_kapsel-service-mcp")),
            ),
        )
        .unwrap();
        Self {
            script,
            reference: root.join("operation.ref"),
            socket: socket.into(),
        }
    }

    fn command(&self, action: &str, arguments: &[&str]) -> Command {
        let mut command = Command::new("python3");
        command
            .arg(&self.script)
            .args(["--service", "fixture-history-1", "--reference"])
            .arg(&self.reference)
            .arg(action)
            .args(arguments)
            .env("KAPSELD_TEST_CLIENT_SOCKET", &self.socket);
        command
    }

    fn run(&self, action: &str, arguments: &[&str]) -> Value {
        let output = ChildGuard::output(&mut self.command(action, arguments)).unwrap();
        assert!(
            output.status.success(),
            "caller {action}: {:?}; stdout: {}; stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the proxy places actual caller loss after durable admission but before delivery"
)]
fn mcp_caller_loss_preserves_reference_and_service_admission() {
    let root = installation_root("mcp-caller-loss");
    private_file(&root.join("etc/kapsel/kubeconfig.yaml"), b"unavailable");
    let socket = root.join("run/kapsel/kapseld.sock");
    let service = spawn_installed(&root, 3);
    wait_for_socket(&socket);
    let fresh = FreshCaller::new(&root, &socket);
    // Hold the service's durable acknowledgement outside the bridge. Kill the thin caller while
    // the acknowledgement is undelivered, without cancelling the service-owned worker.
    let proxy_socket = root.join("mcp-proxy.sock");
    let proxy_listener = StdUnixListener::bind(&proxy_socket).unwrap();
    let service_socket = socket;
    let (ack_tx, ack_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let proxy = thread::spawn(move || {
        let (mut caller, _) = proxy_listener.accept().unwrap();
        caller.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
        let mut prefix = [0_u8; 4];
        caller.read_exact(&mut prefix).unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        caller.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["request"], "submit_set_deployment_image");
        assert_eq!(request["operation_id"], "process-op");
        let mut service = UnixStream::connect(service_socket).unwrap();
        service.write_all(&prefix).unwrap();
        service.write_all(&body).unwrap();
        service.shutdown(Shutdown::Write).unwrap();
        assert_admitted(&mut service, "requested");
        ack_tx.send(()).unwrap();
        release_rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
        drop(caller);
    });

    let mut caller = ChildGuard::new(
        fresh
            .command("start", &["process-op"])
            .env("KAPSELD_TEST_CLIENT_SOCKET", &proxy_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    ack_rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
    assert!(fresh.reference.exists());
    kill(&mut caller);
    let second_start = ChildGuard::output(&mut fresh.command("start", &["process-op"])).unwrap();
    assert_eq!(second_start.status.code(), Some(4));
    release_tx.send(()).unwrap();
    proxy.join().unwrap();
    let original = fs::read(&fresh.reference).unwrap();
    assert_eq!(fresh.run("read", &[])["service"]["status"], "IN_PROGRESS");
    assert_eq!(fs::read(&fresh.reference).unwrap(), original);
    assert!(service.wait_with_output().unwrap().status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_startup_refuses_an_invalid_private_root_before_binding() {
    let root = installation_root("invalid-root");
    let state = root.join("var/lib/kapsel");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
    let before = fs::metadata(&state).unwrap();
    let output = spawn_installed(&root, 1).wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"kapseld: provisioning_unavailable\n");
    assert!(!root.join("run/kapsel/kapseld.sock").exists());
    assert!(!state.join("journal.sqlite3").exists());
    let after = fs::metadata(&state).unwrap();
    assert_eq!(
        (after.dev(), after.ino(), after.mode()),
        (before.dev(), before.ino(), before.mode())
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_startup_rebinds_stale_socket_and_uses_fixed_inputs() {
    let root = installation_root("ordinary-startup");
    let socket = root.join("run/kapsel/kapseld.sock");
    let stale = StdUnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    drop(stale);
    let child = spawn_installed(&root, 1);
    let mut status = connect(&socket);
    write_frame(
        &mut status,
        br#"{"request":"get_set_deployment_image_status","operation_id":"process-op"}"#,
    );
    assert_admission_unconfirmed(&mut status);

    // A response proves startup completed chmod and identity checks, not just bind.
    let metadata = fs::symlink_metadata(&socket).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), effective_uid());
    assert_eq!(metadata.gid(), effective_gid());
    assert_eq!(metadata.mode() & 0o7777, 0o660);
    assert_eq!(metadata.nlink(), 1);

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(socket.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one process trace proves snapshot recovery and export without replay"
)]
fn ordinary_restart_reuses_frozen_snapshot_receipt_under_rotated_configuration() {
    let server = success_server();
    let root = installation_root_with_url("receipt-recovery", &server.url);
    let socket = root.join("run/kapsel/kapseld.sock");
    let journal = root.join("var/lib/kapsel/journal.sqlite3");
    let receipts = root.join("var/lib/kapsel/receipts");
    fs::remove_dir(&receipts).unwrap();
    let document_path = root.join("etc/kapsel/operator.json");
    let mut document: Value = serde_json::from_slice(&fs::read(&document_path).unwrap()).unwrap();

    let fresh = FreshCaller::new(&root, &socket);
    let mut first = spawn_installed_with_seam(&root, 10, "after_apply");
    wait_for_socket(&socket);
    let admission = fresh.run("start", &["process-op"]);
    assert_eq!(admission["service"]["status"], "ADMITTED");
    assert_eq!(admission["service"]["phase"], "requested");
    let reference = fs::read(&fresh.reference).unwrap();
    wait_for_marker(&mut first, &root.join("control/after-apply.ready"));
    kill(&mut first);
    assert!(socket.exists());

    let mut publication = spawn_installed_with_seam(&root, 10, "after_receipt_commit");
    wait_for_socket(&socket);
    let current = fresh.run("read", &[]);
    assert_eq!(current["service"]["status"], "IN_PROGRESS");
    assert_eq!(
        current["service"]["execution"]["disposition"],
        "resume_required"
    );
    let resumed = fresh.run("resume", &[]);
    assert_eq!(resumed["reference"]["operation_id"], "process-op");
    assert_eq!(resumed["service"]["status"], "ADMITTED");
    assert_eq!(resumed["service"]["phase"], "apply_started");
    assert_eq!(fs::read(&fresh.reference).unwrap(), reference);
    server
        .observation_started
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    server.release_observation.send(()).unwrap();
    wait_for_marker(
        &mut publication,
        &root.join("control/after-receipt-commit.ready"),
    );
    assert!(socket.exists());
    let connection = Connection::open(&journal).unwrap();
    let (state, frozen, signer): (String, Vec<u8>, String) = connection
        .query_row(
            "SELECT state, receipt_bytes, receipt_key_id FROM kubernetes_image_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(state, "finalized");
    assert_eq!(signer, "service-receipt-key");
    drop(connection);
    kill(&mut publication);

    private_file(&root.join("etc/kapsel/receipt.seed"), &[113_u8; 32]);
    document["receipt_signing_key_id"] = "rotated-receipt-key".into();
    private_file(&document_path, &serde_json::to_vec(&document).unwrap());
    let child = spawn_installed(&root, 3);
    wait_for_socket(&socket);
    let response = fresh.run("receipt", &[])["service"].clone();
    let expected_hex = lowercase_hex(&frozen);
    let expected_digest = lowercase_hex(&sha2::Sha256::digest(&frozen));
    assert_eq!(response["status"], "READY");
    assert_eq!(response["receipt_hex"], expected_hex);
    assert_eq!(response["receipt_sha256"], expected_digest);
    let run_client = |destination: &Path| {
        ChildGuard::output(
            Command::new(env!("CARGO_BIN_EXE_kapsel-service-client"))
                .env("KAPSELD_TEST_CLIENT_SOCKET", &socket)
                .args(["receipt", "process-op", destination.to_str().unwrap()]),
        )
        .unwrap()
    };
    let exported = root.join("exported.receipt");
    assert!(run_client(&exported).status.success());
    assert_eq!(fs::read(&exported).unwrap(), frozen);
    let trust = ReceiptTrust {
        key_id: signer.clone(),
        public_key: SigningKey::from_bytes(&[112_u8; 32])
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap();
    assert_eq!(
        kapsel::inspect_receipt(&frozen, &trust, 150, InspectionLimits::default()).status(),
        InspectionStatus::Inspected
    );

    if let Ok(inspector) = std::env::var("KAPSEL_TEST_INSPECT") {
        let trust_path = root.join("detached.trust");
        fs::write(&trust_path, trust).unwrap();
        let output = ChildGuard::output(
            Command::new(inspector)
                .arg("inspect")
                .arg("--receipt")
                .arg(&exported)
                .arg("--trust")
                .arg(&trust_path)
                .args(["--evaluation-time-unix-s", "150"]),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["status"],
            "INSPECTED"
        );
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!receipts.exists());
    assert!(!root.join("missing-rotated-receipts").exists());
    let connection = Connection::open(&journal).unwrap();
    let retained: (Vec<u8>, String) = connection
        .query_row(
            "SELECT receipt_bytes, receipt_key_id FROM kubernetes_image_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (frozen, signer));
    drop(connection);
    fs::remove_file(&socket).unwrap();
    let connection = Connection::open(&journal).unwrap();
    connection
        .execute(
            "UPDATE kubernetes_image_operations SET receipt_bytes = ?1",
            [b"different frozen receipt bytes".as_slice()],
        )
        .unwrap();
    drop(connection);

    let corrupt = fs::read(&journal).unwrap();
    let output = spawn_installed(&root, 1).wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(!socket.exists());
    assert_eq!(fs::read(&journal).unwrap(), corrupt);
    server.finish();
    fs::remove_dir_all(root).unwrap();
}
