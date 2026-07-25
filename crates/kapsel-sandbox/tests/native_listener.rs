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
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{Scenario, Service};

const REQUEST_HEAD_OVERFLOW_PADDING: usize = 8 * 1024;

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
