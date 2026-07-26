//! Black-box proof for the fixed native listener and operator stop process.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled fixture failures must stop the black-box process test"
)]

use std::{
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    ops::{Deref, DerefMut},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{CleanupState, Scenario, Service};
use sha2::{Digest, Sha256};

const REQUEST_HEAD_OVERFLOW_PADDING: usize = 8 * 1024;

struct ChildGuard(Child);

impl Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-listener-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let receipts = root.join("receipts");
    fs::create_dir(&receipts).unwrap();
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
    let key = root.join("digest.key");
    fs::write(&key, [7_u8; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o440)).unwrap();
    (root.join("sandbox.db"), receipts, key)
}

fn arguments(database: &Path, receipts: &Path, key: &Path) -> Vec<String> {
    vec![
        "--database".into(),
        database.display().to_string(),
        "--receipts".into(),
        receipts.display().to_string(),
        "--digest-key-file".into(),
        key.display().to_string(),
    ]
}

fn start(database: &Path, receipts: &Path, key: &Path) -> (Child, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"));
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

fn initialize(database: &Path, receipts: &Path, key: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("init")
        .args(arguments(database, receipts, key))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn start_mock_kubernetes(root: &Path) -> (Child, u16) {
    let script = root.join("mock-kubernetes.py");
    fs::write(
        &script,
        r#"import http.server, json, ssl, sys
objects = {}
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args):
        pass
    def reply(self, status, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        if self.path.split("?", 1)[0] == "/apis/authentication.k8s.io/v1/tokenreviews":
            assert self.headers.get("authorization") == "Bearer system-kubernetes-token"
            assert body["spec"] == {
                "audiences": ["https://kapsel.dev/sandbox/controller-state/v1"],
                "token": "scheduler-state-token"
            }
            body["status"] = {
                "authenticated": True,
                "audiences": ["https://kapsel.dev/sandbox/controller-state/v1"],
                "user": {
                    "username": "system:serviceaccount:kapsel-sandbox-system:sandbox-scheduler",
                    "uid": "scheduler-uid"
                }
            }
            self.reply(201, body)
            return
        assert self.headers.get("authorization") == "Bearer scheduler-kubernetes-token"
        name = body["metadata"]["name"]
        body["metadata"]["uid"] = "uid-" + str(len(objects))
        body["metadata"]["resourceVersion"] = "1"
        body["metadata"]["creationTimestamp"] = "2026-07-25T00:00:00Z"
        objects[self.path.split("?", 1)[0] + "/" + name] = body
        self.reply(201, body)
    def do_GET(self):
        assert self.headers.get("authorization") == "Bearer scheduler-kubernetes-token"
        path = self.path.split("?", 1)[0]
        if path in objects:
            self.reply(200, objects[path])
        else:
            self.reply(404, {
                "apiVersion":"v1", "kind":"Status", "status":"Failure",
                "reason":"NotFound", "code":404
            })
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
print("LISTEN_PORT=" + str(server.server_port), flush=True)
server.serve_forever()
"#,
    )
    .unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kubernetes-api");
    let mut child = Command::new("python3")
        .arg("-u")
        .arg(script)
        .arg(fixture.join("cert.pem"))
        .arg(fixture.join("key.pem"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line
        .strip_prefix("LISTEN_PORT=")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (child, port)
}

#[allow(
    clippy::too_many_lines,
    reason = "one mock keeps TokenReview, exact ownership scans, and UID-safe deletion contiguous"
)]
fn start_mock_cleanup_kubernetes(
    root: &Path,
    run_id: &str,
    cleanup_identity: &str,
) -> (Child, u16) {
    let script = root.join("mock-cleanup-kubernetes.py");
    fs::write(
        &script,
        r#"import http.server, json, ssl, sys, urllib.parse
run_id = sys.argv[3]
owner = sys.argv[4]
namespace_name = "sandbox-" + run_id
runner_name = "runner-" + run_id
namespace_path = "/api/v1/namespaces/" + namespace_name
runner_path = "/api/v1/namespaces/kapsel-sandbox-runners/pods/" + runner_name
objects = {
    namespace_path: {
        "apiVersion":"v1", "kind":"Namespace",
        "metadata":{"name":namespace_name, "uid":"uid-namespace",
                    "resourceVersion":"1",
                    "labels":{"kapsel.dev/cleanup-owner":owner}}
    },
    runner_path: {
        "apiVersion":"v1", "kind":"Pod",
        "metadata":{"name":runner_name, "namespace":"kapsel-sandbox-runners",
                    "uid":"uid-runner", "resourceVersion":"1",
                    "labels":{"kapsel.dev/cleanup-owner":owner}}
    }
}
list_paths = {
    "/api/v1/namespaces/kapsel-sandbox-runners/serviceaccounts",
    "/api/v1/namespaces/kapsel-sandbox-runners/configmaps",
    "/api/v1/namespaces/kapsel-sandbox-runners/secrets",
    "/api/v1/namespaces/kapsel-sandbox-runners/persistentvolumeclaims",
    "/api/v1/namespaces/kapsel-sandbox-runners/pods"
}
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, format, *args):
        pass
    def reply(self, status, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def path_only(self):
        return urllib.parse.urlsplit(self.path).path
    def do_POST(self):
        assert self.headers.get("authorization") == "Bearer system-kubernetes-token"
        assert self.path_only() == "/apis/authentication.k8s.io/v1/tokenreviews"
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        assert body["spec"] == {
            "audiences": ["https://kapsel.dev/sandbox/controller-state/v1"],
            "token": "cleanup-state-token"
        }
        body["status"] = {
            "authenticated": True,
            "audiences": ["https://kapsel.dev/sandbox/controller-state/v1"],
            "user": {
                "username": "system:serviceaccount:kapsel-sandbox-system:sandbox-cleanup",
                "uid": "cleanup-uid"
            }
        }
        self.reply(201, body)
    def do_GET(self):
        assert self.headers.get("authorization") == "Bearer cleanup-kubernetes-token"
        path = self.path_only()
        if path in list_paths:
            items = []
            if path.endswith("/pods") and runner_path in objects:
                items = [objects[runner_path]]
            self.reply(200, {
                "apiVersion":"v1", "kind":"List",
                "metadata":{"resourceVersion":"1"}, "items":items
            })
        elif path in objects:
            self.reply(200, objects[path])
        else:
            self.reply(404, {
                "apiVersion":"v1", "kind":"Status", "status":"Failure",
                "reason":"NotFound", "code":404
            })
    def do_DELETE(self):
        assert self.headers.get("authorization") == "Bearer cleanup-kubernetes-token"
        path = self.path_only()
        assert path in objects
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        assert body["preconditions"]["uid"] == objects[path]["metadata"]["uid"]
        if path == namespace_path:
            assert runner_path not in objects
        del objects[path]
        self.reply(200, {
            "apiVersion":"v1", "kind":"Status", "status":"Success",
            "reason":"Deleted", "code":200
        })
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
print("LISTEN_PORT=" + str(server.server_port), flush=True)
server.serve_forever()
"#,
    )
    .unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kubernetes-api");
    let mut child = Command::new("python3")
        .arg("-u")
        .arg(script)
        .arg(fixture.join("cert.pem"))
        .arg(fixture.join("key.pem"))
        .arg(run_id)
        .arg(cleanup_identity)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line
        .strip_prefix("LISTEN_PORT=")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (child, port)
}

fn operate(command_name: &str, database: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg(command_name)
        .args(["--database", &database.display().to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
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

    let unavailable_receipts = root.join("receipts-unavailable");
    let unavailable_key = root.join("digest-key-unavailable");
    fs::rename(&receipts, &unavailable_receipts).unwrap();
    fs::rename(&digest_key, &unavailable_key).unwrap();
    operate("stop", &database);
    fs::rename(&unavailable_receipts, &receipts).unwrap();
    fs::rename(&unavailable_key, &digest_key).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let (mut child, address) = start(&database, &receipts, &digest_key);
    let stopped = request(&address, &admission("02020202020202020202020202020202"));
    assert!(stopped.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(String::from_utf8_lossy(&stopped).contains("service_unavailable"));

    let replay = request(&address, &admission(first_key));
    assert!(replay.starts_with(b"HTTP/1.1 200 OK\r\n"));
    fs::rename(&receipts, &unavailable_receipts).unwrap();
    fs::rename(&digest_key, &unavailable_key).unwrap();
    operate("clear-stop", &database);
    fs::rename(&unavailable_receipts, &receipts).unwrap();
    fs::rename(&unavailable_key, &digest_key).unwrap();
    let resumed = request(&address, &admission("03030303030303030303030303030303"));
    assert!(resumed.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
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
    fs::remove_dir_all(root).unwrap();
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
    fs::remove_dir_all(root).unwrap();
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
    fs::remove_dir_all(root).unwrap();
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
    let service = Service::open(&database, &receipts, [7; 32], now - 172_800).unwrap();
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
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
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

    let mut role = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
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
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(role.try_wait().unwrap().is_none());
    role.kill().unwrap();
    let output = role.wait_with_output().unwrap();
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scheduler_role_rejects_system_state_and_uses_distinct_remote_state_inputs() {
    let (database, receipts, digest_key) = fixture("scheduler-role");
    let root = database.parent().unwrap().to_owned();
    initialize(&database, &receipts, &digest_key);
    let ca = root.join("controller-ca.pem");
    let state_token = root.join("state-token");
    let kubernetes_ca = root.join("kubernetes-ca.pem");
    let kubernetes_token = root.join("kubernetes-token");
    fs::write(&ca, b"must-not-open").unwrap();
    fs::write(&state_token, b"must-not-open").unwrap();
    fs::write(&kubernetes_ca, b"must-not-open").unwrap();
    fs::write(&kubernetes_token, b"must-not-open").unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(&digest_key, fs::Permissions::from_mode(0o000)).unwrap();
    let state_arguments = [
        "--state-endpoint",
        "127.0.0.1:8082",
        "--state-ca-bundle",
        ca.to_str().unwrap(),
        "--state-ca-sha256",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--state-ca-root-count",
        "1",
        "--state-token",
        state_token.to_str().unwrap(),
    ];
    let kubernetes_arguments = [
        "--kubernetes-ca",
        kubernetes_ca.to_str().unwrap(),
        "--kubernetes-token",
        kubernetes_token.to_str().unwrap(),
    ];

    for forbidden in [
        vec!["--database", database.to_str().unwrap()],
        vec!["--receipts", receipts.to_str().unwrap()],
        vec!["--digest-key-file", digest_key.to_str().unwrap()],
        vec!["--handoff-endpoint", "127.0.0.1:8081"],
        vec!["--origin", "https://kapsel.invalid"],
        vec!["--listen", "127.0.0.1:0"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
            .arg("scheduler")
            .args(state_arguments)
            .args(kubernetes_arguments)
            .args(forbidden)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("scheduler")
        .args(&state_arguments[..8])
        .args(["--state-token", kubernetes_token.to_str().unwrap()])
        .args(kubernetes_arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "kapsel-sandbox: scheduler state token must be distinct from ",
            "Kubernetes API authority\n"
        )
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("scheduler")
        .args(state_arguments)
        .args(kubernetes_arguments)
        .env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "kapsel-sandbox: scheduler Kubernetes configuration is unavailable\n"
    );
    assert_eq!(fs::read(&ca).unwrap(), b"must-not-open");
    assert_eq!(fs::read(&state_token).unwrap(), b"must-not-open");
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&digest_key, fs::Permissions::from_mode(0o440)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native-process vector keeps scheduler authority and state separation contiguous"
)]
fn native_scheduler_process_crosses_authenticated_state_and_distinct_kubernetes_tokens() {
    let (database, receipts, digest_key) = fixture("scheduler-process");
    let root = database.parent().unwrap().to_owned();
    initialize(&database, &receipts, &digest_key);
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let service = Service::open(&database, &receipts, [7; 32], now).unwrap();
    let admission = service
        .admit("10101010101010101010101010101010", Scenario::Healthy, now)
        .unwrap();
    drop(service);

    let state_fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/controller-transport/current");
    let state_certificate = root.join("state.crt");
    let state_private_key = root.join("state.key");
    let state_ca = root.join("state-ca.crt");
    for (source, destination, mode) in [
        ("cert.pem", &state_certificate, 0o400),
        ("key.pem", &state_private_key, 0o600),
        ("ca.pem", &state_ca, 0o400),
    ] {
        fs::copy(state_fixture.join(source), destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
    }
    let state_token = root.join("state-token");
    let scheduler_kubernetes_token = root.join("scheduler-kubernetes-token");
    let system_kubernetes_token = root.join("system-kubernetes-token");
    for (path, bytes) in [
        (&state_token, b"scheduler-state-token".as_slice()),
        (
            &scheduler_kubernetes_token,
            b"scheduler-kubernetes-token".as_slice(),
        ),
        (
            &system_kubernetes_token,
            b"system-kubernetes-token".as_slice(),
        ),
    ] {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let kubernetes_ca =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kubernetes-api/ca.pem");
    let (kubernetes, kubernetes_port) = start_mock_kubernetes(&root);
    let mut kubernetes = ChildGuard(kubernetes);
    let kubernetes_port = kubernetes_port.to_string();

    let state = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("scheduler-state-serve")
        .args(arguments(&database, &receipts, &digest_key))
        .args(["--listen", "127.0.0.1:8082"])
        .args(["--handoff-endpoint", "127.0.0.1:8081"])
        .args(["--state-certificate", state_certificate.to_str().unwrap()])
        .args(["--state-private-key", state_private_key.to_str().unwrap()])
        .args(["--scheduler-service-account-uid", "scheduler-uid"])
        .args(["--kubernetes-ca", kubernetes_ca.to_str().unwrap()])
        .args([
            "--kubernetes-token",
            system_kubernetes_token.to_str().unwrap(),
        ])
        .env("KUBERNETES_SERVICE_HOST", "127.0.0.1")
        .env("KUBERNETES_SERVICE_PORT", &kubernetes_port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut state = ChildGuard(state);
    let started = Instant::now();
    loop {
        if TcpStream::connect("127.0.0.1:8082").is_ok() {
            break;
        }
        assert!(state.try_wait().unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(10));
    }

    let ca_digest = Sha256::digest(fs::read(&state_ca).unwrap());
    let ca_digest = ca_digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        });
    let scheduler = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("scheduler")
        .args(["--state-endpoint", "127.0.0.1:8082"])
        .args(["--state-ca-bundle", state_ca.to_str().unwrap()])
        .args(["--state-ca-sha256", &ca_digest])
        .args(["--state-ca-root-count", "1"])
        .args(["--state-token", state_token.to_str().unwrap()])
        .args(["--kubernetes-ca", kubernetes_ca.to_str().unwrap()])
        .args([
            "--kubernetes-token",
            scheduler_kubernetes_token.to_str().unwrap(),
        ])
        .env("KUBERNETES_SERVICE_HOST", "127.0.0.1")
        .env("KUBERNETES_SERVICE_PORT", &kubernetes_port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut scheduler = ChildGuard(scheduler);
    let started = Instant::now();
    let first_verifier = loop {
        assert!(scheduler.try_wait().unwrap().is_none());
        let row = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                concat!(
                    "SELECT policy_verified, handoff_credential_verifier FROM runs ",
                    "WHERE run_id = ?1"
                ),
                [&admission.run_id],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .unwrap();
        if row.0 {
            break row.1;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(scheduler.try_wait().unwrap().is_none());
    let connection = rusqlite::Connection::open(&database).unwrap();
    let (verifier, slots, registered): (Vec<u8>, i64, i64) = connection
        .query_row(
            concat!(
                "SELECT handoff_credential_verifier, ",
                "(SELECT COUNT(*) FROM external_resource_slots WHERE run_id = ?1), ",
                "(SELECT COUNT(*) FROM external_resource_slots WHERE run_id = ?1 ",
                "AND uid IS NOT NULL) FROM runs WHERE run_id = ?1"
            ),
            [&admission.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(verifier, first_verifier);
    assert_eq!(slots, 9);
    assert_eq!(registered, 0);
    let service = Service::open(&database, &receipts, [7; 32], now + 2).unwrap();
    let snapshot = service.snapshot(&admission.run_id, now + 2).unwrap();
    assert!(snapshot.receiver_result.is_none());
    assert!(!snapshot.receipt_available);

    scheduler.kill().unwrap();
    scheduler.wait().unwrap();
    state.kill().unwrap();
    state.wait().unwrap();
    kubernetes.kill().unwrap();
    kubernetes.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one vector keeps cleanup state, Kubernetes authority, and frozen facts contiguous"
)]
fn native_cleanup_process_crosses_authenticated_state_and_uid_safe_kubernetes_completion() {
    let (database, receipts, digest_key) = fixture("cleanup-process");
    let root = database.parent().unwrap().to_owned();
    initialize(&database, &receipts, &digest_key);
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let service = Service::open(&database, &receipts, [7; 32], now).unwrap();
    let admission = service
        .admit("11111111111111111111111111111111", Scenario::Healthy, now)
        .unwrap();
    service.dispatch_next(now + 1).unwrap();
    let cleanup_identity: String = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT cleanup_identity FROM cleanup_records WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let namespace_name = format!("sandbox-{}", admission.run_id);
    let runner_name = format!("runner-{}", admission.run_id);
    let receipt_bytes = b"frozen-native-cleanup-receipt";
    let receipt_digest =
        Sha256::digest(receipt_bytes)
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                write!(output, "{byte:02x}").unwrap();
                output
            });
    let receipt_name = format!("sandbox-{}-{receipt_digest}.receipt", admission.run_id);
    fs::write(receipts.join(&receipt_name), receipt_bytes).unwrap();
    fs::set_permissions(
        receipts.join(&receipt_name),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch(&format!(
            concat!(
                "UPDATE runs SET execution_state = 'terminal', receiver_result = 'UNKNOWN', ",
                "receipt_available = 1, namespace_uid = 'uid-namespace', ",
                "cleanup_resource_state = 'owned' WHERE run_id = '{run}'; ",
                "UPDATE cleanup_records SET namespace_uid = 'uid-namespace', ",
                "resource_state = 'owned', eligible = 1 WHERE run_id = '{run}'; ",
                "INSERT INTO provisioned_object_owners VALUES ",
                "('uid-namespace', '{run}', 'Namespace/{namespace}', '{owner}'); ",
                "INSERT INTO provisioned_object_owners VALUES ",
                "('uid-runner', '{run}', 'Pod/kapsel-sandbox-runners/{runner}', '{owner}'); ",
                "INSERT INTO receipts VALUES ('{run}', '{digest}', '{receipt}');"
            ),
            run = admission.run_id,
            namespace = namespace_name,
            runner = runner_name,
            owner = cleanup_identity,
            digest = receipt_digest,
            receipt = receipt_name,
        ))
        .unwrap();
    let before = service.snapshot(&admission.run_id, now + 2).unwrap();
    let frozen_before = service.receipt(&admission.run_id, now + 2).unwrap();
    assert_eq!(before.receiver_result.as_deref(), Some("UNKNOWN"));
    assert!(before.target_rejection.is_none());
    assert!(before.receipt_available);
    drop(service);

    let state_fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/controller-transport/current");
    let state_certificate = root.join("state.crt");
    let state_private_key = root.join("state.key");
    let state_ca = root.join("state-ca.crt");
    for (source, destination, mode) in [
        ("cert.pem", &state_certificate, 0o400),
        ("key.pem", &state_private_key, 0o600),
        ("ca.pem", &state_ca, 0o400),
    ] {
        fs::copy(state_fixture.join(source), destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
    }
    let state_token = root.join("cleanup-state-token");
    let cleanup_kubernetes_token = root.join("cleanup-kubernetes-token");
    let system_kubernetes_token = root.join("system-kubernetes-token");
    for (path, bytes) in [
        (&state_token, b"cleanup-state-token".as_slice()),
        (
            &cleanup_kubernetes_token,
            b"cleanup-kubernetes-token".as_slice(),
        ),
        (
            &system_kubernetes_token,
            b"system-kubernetes-token".as_slice(),
        ),
    ] {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let kubernetes_ca =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kubernetes-api/ca.pem");
    let (kubernetes, kubernetes_port) =
        start_mock_cleanup_kubernetes(&root, &admission.run_id, &cleanup_identity);
    let mut kubernetes = ChildGuard(kubernetes);
    let kubernetes_port = kubernetes_port.to_string();

    let state = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup-state-serve")
        .args(arguments(&database, &receipts, &digest_key))
        .args(["--listen", "127.0.0.1:8083"])
        .args(["--state-certificate", state_certificate.to_str().unwrap()])
        .args(["--state-private-key", state_private_key.to_str().unwrap()])
        .args(["--cleanup-service-account-uid", "cleanup-uid"])
        .args(["--kubernetes-ca", kubernetes_ca.to_str().unwrap()])
        .args([
            "--kubernetes-token",
            system_kubernetes_token.to_str().unwrap(),
        ])
        .env("KUBERNETES_SERVICE_HOST", "127.0.0.1")
        .env("KUBERNETES_SERVICE_PORT", &kubernetes_port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut state = ChildGuard(state);
    std::thread::sleep(Duration::from_millis(100));
    assert!(state.try_wait().unwrap().is_none());

    let ca_digest = Sha256::digest(fs::read(&state_ca).unwrap()).iter().fold(
        String::with_capacity(64),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    );
    let cleanup = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup")
        .args(["--state-endpoint", "127.0.0.1:8083"])
        .args(["--state-ca-bundle", state_ca.to_str().unwrap()])
        .args(["--state-ca-sha256", &ca_digest])
        .args(["--state-ca-root-count", "1"])
        .args(["--state-token", state_token.to_str().unwrap()])
        .args(["--kubernetes-ca", kubernetes_ca.to_str().unwrap()])
        .args([
            "--kubernetes-token",
            cleanup_kubernetes_token.to_str().unwrap(),
        ])
        .env("KUBERNETES_SERVICE_HOST", "127.0.0.1")
        .env("KUBERNETES_SERVICE_PORT", &kubernetes_port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut cleanup = ChildGuard(cleanup);
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    loop {
        let state_value: String = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT cleanup_state FROM runs WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        if state_value == "succeeded" {
            break;
        }
        if let Some(status) = cleanup.try_wait().unwrap() {
            let mut stderr = String::new();
            cleanup
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            kubernetes.kill().unwrap();
            kubernetes.wait().unwrap();
            let mut kubernetes_stderr = String::new();
            if let Some(stderr) = kubernetes.stderr.as_mut() {
                stderr.read_to_string(&mut kubernetes_stderr).unwrap();
            }
            panic!("cleanup process exited {status}: {stderr}; Kubernetes: {kubernetes_stderr}");
        }
        if let Some(status) = state.try_wait().unwrap() {
            let mut stderr = String::new();
            state
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("cleanup-state process exited {status}: {stderr}");
        }
        assert!(started.elapsed() < Duration::from_secs(8));
        std::thread::sleep(Duration::from_millis(20));
    }

    let service = Service::open(&database, &receipts, [7; 32], now + 3).unwrap();
    let after = service.snapshot(&admission.run_id, now + 3).unwrap();
    assert_eq!(after.cleanup_state, CleanupState::Succeeded);
    assert_eq!(after.receiver_result, before.receiver_result);
    assert_eq!(after.target_rejection, before.target_rejection);
    assert_eq!(after.receipt_available, before.receipt_available);
    assert_eq!(
        service.receipt(&admission.run_id, now + 3).unwrap(),
        frozen_before
    );
    assert_eq!(frozen_before, receipt_bytes);

    cleanup.kill().unwrap();
    cleanup.wait().unwrap();
    state.kill().unwrap();
    state.wait().unwrap();
    kubernetes.kill().unwrap();
    kubernetes.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one black-box vector keeps both cleanup role authority boundaries contiguous"
)]
fn cleanup_roles_enforce_remote_state_and_system_authority_split() {
    let (database, receipts, digest_key) = fixture("cleanup-role");
    let root = database.parent().unwrap().to_owned();
    initialize(&database, &receipts, &digest_key);
    let ca = root.join("controller-ca.pem");
    let state_token = root.join("state-token");
    let kubernetes_ca = root.join("kubernetes-ca.pem");
    let kubernetes_token = root.join("kubernetes-token");
    for path in [&ca, &state_token, &kubernetes_ca, &kubernetes_token] {
        fs::write(path, b"must-not-open").unwrap();
    }
    let state_arguments = [
        "--state-endpoint",
        "127.0.0.1:8083",
        "--state-ca-bundle",
        ca.to_str().unwrap(),
        "--state-ca-sha256",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--state-ca-root-count",
        "1",
        "--state-token",
        state_token.to_str().unwrap(),
    ];
    let kubernetes_arguments = [
        "--kubernetes-ca",
        kubernetes_ca.to_str().unwrap(),
        "--kubernetes-token",
        kubernetes_token.to_str().unwrap(),
    ];

    for forbidden in [
        vec!["--database", database.to_str().unwrap()],
        vec!["--receipts", receipts.to_str().unwrap()],
        vec!["--digest-key-file", digest_key.to_str().unwrap()],
        vec!["--handoff-endpoint", "127.0.0.1:8081"],
        vec!["--origin", "https://kapsel.invalid"],
        vec!["--listen", "127.0.0.1:0"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
            .arg("cleanup")
            .args(state_arguments)
            .args(kubernetes_arguments)
            .args(forbidden)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup")
        .args(&state_arguments[..8])
        .args(["--state-token", kubernetes_token.to_str().unwrap()])
        .args(kubernetes_arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "kapsel-sandbox: cleanup state token must be distinct from ",
            "Kubernetes API authority\n"
        )
    );

    let state_token_alias = root.join("state-token-alias");
    fs::hard_link(&kubernetes_token, &state_token_alias).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup")
        .args(&state_arguments[..8])
        .args(["--state-token", state_token_alias.to_str().unwrap()])
        .args(kubernetes_arguments)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "kapsel-sandbox: cleanup state token must be distinct from ",
            "Kubernetes API authority\n"
        )
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup")
        .args(state_arguments)
        .args(kubernetes_arguments)
        .env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "kapsel-sandbox: cleanup Kubernetes configuration is unavailable\n"
    );

    let listener_arguments = [
        "--listen",
        "127.0.0.1:8083",
        "--state-certificate",
        ca.to_str().unwrap(),
        "--state-private-key",
        state_token.to_str().unwrap(),
        "--cleanup-service-account-uid",
        "cleanup-uid",
        "--kubernetes-ca",
        kubernetes_ca.to_str().unwrap(),
        "--kubernetes-token",
        kubernetes_token.to_str().unwrap(),
    ];
    for forbidden in [
        vec!["--state-endpoint", "127.0.0.1:8083"],
        vec!["--state-token", state_token.to_str().unwrap()],
        vec!["--handoff-endpoint", "127.0.0.1:8081"],
        vec!["--scheduler-service-account-uid", "scheduler-uid"],
        vec!["--origin", "https://kapsel.invalid"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
            .arg("cleanup-state-serve")
            .args(arguments(&database, &receipts, &digest_key))
            .args(listener_arguments)
            .args(forbidden)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg("cleanup-state-serve")
        .args(arguments(&database, &receipts, &digest_key))
        .args(listener_arguments)
        .args(["--listen", "127.0.0.1:8082"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    fs::remove_dir_all(root).unwrap();
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
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .args([
            "runner",
            "--database",
            sentinel.to_str().unwrap(),
            "--operator-composition",
            root.join("missing.json").to_str().unwrap(),
            "--handoff",
            root.join("missing-handoff").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "kapsel-sandbox: runner arguments are invalid\n"
    );
    let composition = root.join("composition.json");
    fs::write(
        &composition,
        serde_json::to_vec(&serde_json::json!({
            "request": root.join("request.json"),
            "signed_authorization_grant": root.join("grant.bin"),
            "authorization_trust": root.join("trust.json"),
            "kubernetes_api_server": root.join("api-server"),
            "kubernetes_ca": root.join("ca.crt"),
            "kubernetes_namespace": root.join("namespace"),
            "kubernetes_token": root.join("token"),
            "journal": sentinel,
            "receipt_directory": root.join("receipt-outbox"),
            "receipt_signing_seed": root.join("seed"),
            "receipt_signing_key_id": root.join("key-id")
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&composition, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .args([
            "runner",
            "--operator-composition",
            composition.to_str().unwrap(),
            "--handoff",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "kapsel-sandbox: runner state paths are invalid\n"
    );
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), b"must-not-open");
    fs::remove_dir_all(root).unwrap();
}
