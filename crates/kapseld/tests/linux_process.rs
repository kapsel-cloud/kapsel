//! Linux real-process proof for the compile-time KAP-0074 Slices 2 and 3 harness.

#![cfg(all(target_os = "linux", feature = "test-harness"))]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled process fixtures must fail the Linux gate immediately"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn root(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("kapseld-linux-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    path
}

fn effective_gid() -> u32 {
    let output = Command::new("id").arg("-g").output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn spawn(socket: &Path, expected_gid: u32, connections: usize) -> Child {
    Command::new(env!("CARGO_BIN_EXE_kapseld"))
        .env("KAPSELD_TEST_SOCKET", socket)
        .env("KAPSELD_TEST_EXPECTED_GID", expected_gid.to_string())
        .env("KAPSELD_TEST_CONNECTIONS", connections.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn connect(socket: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            },
            Err(error) => panic!("kapseld did not bind: {error}"),
        }
    }
}

fn wait_for_socket(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "kapseld did not bind");
        thread::sleep(Duration::from_millis(10));
    }
}

fn group_gid(group: &str) -> u32 {
    let output = Command::new("getent")
        .args(["group", group])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap()
        .parse()
        .unwrap()
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut response).unwrap();
    response
}

fn submit_request() -> String {
    format!(
        concat!(
            "{{\"request\":\"submit_set_deployment_image\",",
            "\"operation_id\":\"process-op\",\"namespace\":\"demo\",",
            "\"deployment\":\"agent-api\",\"container\":\"api\",",
            "\"immutable_image_digest\":\"{}\"}}"
        ),
        concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    )
}

#[test]
fn matching_effective_gid_crosses_the_real_kapseld_process() {
    let root = root("allow");
    let socket = root.join("kapseld.sock");
    let child = spawn(&socket, effective_gid(), 1);
    let mut stream = connect(&socket);
    write_frame(
        &mut stream,
        br#"{"request":"get_set_deployment_image_status","operation_id":"missing"}"#,
    );
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert_eq!(
        response,
        [
            &(u32::try_from(br#"{"status":"NOT_FOUND"}"#.len())
                .unwrap()
                .to_be_bytes())[..],
            br#"{"status":"NOT_FOUND"}"#,
        ]
        .concat()
    );
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disconnect_busy_and_reconnect_status_cross_the_real_process() {
    let root = root("execution");
    let socket = root.join("kapseld.sock");
    let child = spawn(&socket, effective_gid(), 4);

    let mut disconnected = connect(&socket);
    write_frame(&mut disconnected, submit_request().as_bytes());
    drop(disconnected);

    let mut status = UnixStream::connect(&socket).unwrap();
    write_frame(
        &mut status,
        br#"{"request":"get_set_deployment_image_status","operation_id":"process-op"}"#,
    );
    assert_eq!(read_frame(&mut status), br#"{"status":"IN_PROGRESS"}"#);

    let mut competing = UnixStream::connect(&socket).unwrap();
    write_frame(&mut competing, submit_request().as_bytes());
    assert_eq!(read_frame(&mut competing), br#"{"status":"BUSY"}"#);

    let mut completed = UnixStream::connect(&socket).unwrap();
    write_frame(
        &mut completed,
        br#"{"request":"get_set_deployment_image_status","operation_id":"process-op"}"#,
    );
    assert_eq!(
        read_frame(&mut completed),
        br#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#
    );

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn saturated_ninth_is_closed_and_new_tenth_succeeds_after_recovery() {
    let root = root("saturation");
    let socket = root.join("kapseld.sock");
    let child = spawn(&socket, effective_gid(), 10);
    let mut admitted = vec![connect(&socket)];
    for _ in 1..8 {
        admitted.push(UnixStream::connect(&socket).unwrap());
    }
    thread::sleep(Duration::from_millis(50));

    let mut ninth = UnixStream::connect(&socket).unwrap();
    ninth
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut denied = Vec::new();
    match ninth.read_to_end(&mut denied) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => panic!("unexpected saturated-peer read failure: {error}"),
    }
    assert!(denied.is_empty());

    drop(admitted.remove(0));
    let mut tenth = UnixStream::connect(&socket).unwrap();
    write_frame(
        &mut tenth,
        br#"{"request":"get_set_deployment_image_status","operation_id":"tenth"}"#,
    );
    tenth
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut prefix = [0_u8; 4];
    tenth.read_exact(&mut prefix).unwrap();
    let mut response = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    tenth.read_exact(&mut response).unwrap();
    assert_eq!(response, br#"{"status":"NOT_FOUND"}"#);
    drop(admitted);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires an existing supplementary docker group and sg on the authorized Linux host"]
fn distinct_effective_gid_is_denied_before_frame_read() {
    let root = root("distinct-gid");
    let socket = root.join("kapseld.sock");
    let server_gid = effective_gid();
    let caller_gid = group_gid("docker");
    assert_ne!(server_gid, caller_gid);
    let child = spawn(&socket, server_gid, 1);
    wait_for_socket(&socket);

    let client = root.join("client.py");
    fs::write(
        &client,
        concat!(
            "import os, socket, time\n",
            "assert os.getegid() == int(os.environ['KAPSELD_DISTINCT_GID'])\n",
            "stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "stream.settimeout(1.0)\n",
            "started = time.monotonic()\n",
            "stream.connect(os.environ['KAPSELD_DISTINCT_GID_SOCKET'])\n",
            "assert stream.recv(1) == b''\n",
            "assert time.monotonic() - started < 1.0\n",
        ),
    )
    .unwrap();
    let command = format!("python3 {}", client.display());
    let output = Command::new("sg")
        .args(["docker", "-c", &command])
        .env("KAPSELD_DISTINCT_GID", caller_gid.to_string())
        .env("KAPSELD_DISTINCT_GID_SOCKET", &socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let server_output = child.wait_with_output().unwrap();
    assert!(server_output.status.success());
    assert!(server_output.stdout.is_empty());
    assert!(server_output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn different_expected_gid_is_denied_before_body_disclosure() {
    let root = root("deny");
    let socket = root.join("kapseld.sock");
    let expected_gid = effective_gid().wrapping_add(1);
    let child = spawn(&socket, expected_gid, 1);
    let mut stream = connect(&socket);
    let _ = stream.write_all(b"SECRET_UNAUTHENTICATED_BODY");
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => panic!("unexpected denied-peer read failure: {error}"),
    }
    assert!(response.is_empty());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}
