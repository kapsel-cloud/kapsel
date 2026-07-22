//! Black-box proof for the fixed native listener and operator stop process.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled fixture failures must stop the black-box process test"
)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

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

fn operate(command_name: &str, database: &Path, receipts: &Path, key: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .arg(command_name)
        .args(arguments(database, receipts, key))
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

    operate("stop", &database, &receipts, &digest_key);
    child.kill().unwrap();
    child.wait().unwrap();
    let (mut child, address) = start(&database, &receipts, &digest_key);
    let stopped = request(&address, &admission("02020202020202020202020202020202"));
    assert!(stopped.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(String::from_utf8_lossy(&stopped).contains("service_unavailable"));

    let replay = request(&address, &admission(first_key));
    assert!(replay.starts_with(b"HTTP/1.1 200 OK\r\n"));
    operate("clear-stop", &database, &receipts, &digest_key);
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

    let accepted = request(&address, &admission(rejected_key));
    assert!(accepted.starts_with(b"HTTP/1.1 201 Created\r\n"));

    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}
