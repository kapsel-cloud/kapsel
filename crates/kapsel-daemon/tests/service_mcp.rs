//! Black-box stdio/socket composition; exhaustive reply grammar lives at its decoder.
#![cfg(feature = "test-harness")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "fail-fast bounded bridge fixtures"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::Shutdown,
    os::unix::net::UnixListener,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn root() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kapsel-mcp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn bridge(socket: &Path, input: &[u8]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kapsel-service-mcp"))
        .env("KAPSELD_TEST_CLIENT_SOCKET", socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn run_raw(input: &[u8], exchanges: &[(Value, Value)]) -> Vec<Value> {
    let root = root();
    let socket = root.join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let exchanges = exchanges.to_vec();
    let (stop, stopped) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut count = 0;
        loop {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    match stopped.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {},
                    }
                    assert!(Instant::now() < deadline, "bridge fixture timed out");
                    thread::sleep(Duration::from_millis(1));
                    continue;
                },
                Err(error) => panic!("bridge fixture accept: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (expected, response) = exchanges
                .get(count)
                .unwrap_or_else(|| panic!("unexpected socket access {count}"));
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let length = u32::from_be_bytes(prefix) as usize;
            assert!((1..=16 * 1024).contains(&length));
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), *expected);
            assert_eq!(stream.read(&mut [0]).unwrap(), 0, "request must half-close");
            let body = serde_json::to_vec(response).unwrap();
            stream
                .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&body).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            count += 1;
        }
        assert_eq!(count, exchanges.len(), "missing socket access");
    });
    let responses = bridge(&socket, input);
    let _ = stop.send(());
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
    responses
}

fn run(lines: &[Value], exchanges: &[(Value, Value)]) -> Vec<Value> {
    let mut input = Vec::new();
    for line in lines {
        writeln!(&mut input, "{line}").unwrap();
    }
    run_raw(&input, exchanges)
}

fn handshake() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ]
}

fn tool(id: i32, name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":name,"arguments":arguments}})
}

fn request(name: &str, id: &str) -> Value {
    json!({"version":1,"request":name,"operation_id":id})
}

fn service(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn caller_reads_and_explicit_submission_preserve_exact_service_facts() {
    let mut lines = handshake();
    lines.push(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let calls = [
        (
            "kapsel.list_approved_actions",
            json!({"after":null}),
            json!({"version":1,"request":"list_approved_actions","after":null}),
            json!({"version":1,"status":"READY","entries":[],"next_cursor":null}),
        ),
        (
            "kapsel.get_status",
            json!({"operation_id":"op-1"}),
            request("get_set_deployment_image_status", "op-1"),
            json!({"version":1,"status":"NOT_FOUND","execution":{
                "disposition":"admission_unconfirmed","condition":null,
                "next_action":"read_same_id","action_owner":"caller"}}),
        ),
        (
            "kapsel.submit",
            json!({"operation_id":"op-2"}),
            request("submit_set_deployment_image", "op-2"),
            json!({"version":1,"status":"ADMITTED","phase":"requested"}),
        ),
        (
            "kapsel.get_receipt",
            json!({"operation_id":"op-2"}),
            request("get_set_deployment_image_receipt", "op-2"),
            json!({"version":1,"status":"NOT_READY"}),
        ),
    ];
    let mut exchanges = Vec::new();
    for (index, (name, args, request, response)) in calls.iter().enumerate() {
        lines.push(tool(i32::try_from(index + 3).unwrap(), name, args));
        exchanges.push((request.clone(), response.clone()));
    }
    let responses = run(&lines, &exchanges);
    assert_eq!(responses.len(), 6);
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 5);
    for (response, (_, arguments, _, expected)) in responses[2..].iter().zip(&calls) {
        assert_eq!(service(response)["service"], *expected);
        assert_eq!(service(response)["operation_id"], arguments["operation_id"]);
        assert_eq!(response["result"]["isError"], false);
    }
}

#[test]
fn authority_failure_invalid_reply_and_nonadmission_are_not_interchangeable() {
    let mut lines = handshake();
    let exchanges = [
        (
            request("get_set_deployment_image_status", "op-1"),
            json!({"version":1,"status":"ERROR","error_class":"authority_unavailable"}),
        ),
        (
            request("submit_set_deployment_image", "op-1"),
            json!({"version":1,"status":"ADMITTED"}),
        ),
        (
            request("submit_set_deployment_image", "op-1"),
            json!({"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}),
        ),
    ];
    for (id, name) in [
        (2, "kapsel.get_status"),
        (3, "kapsel.submit"),
        (4, "kapsel.submit"),
    ] {
        lines.push(tool(id, name, &json!({"operation_id":"op-1"})));
    }
    let responses = run(&lines, &exchanges);
    assert_eq!(
        service(&responses[1])["service"]["error_class"],
        "authority_unavailable"
    );
    assert_eq!(
        service(&responses[2])["service"]["error_class"],
        "response_invalid"
    );
    assert_eq!(service(&responses[3])["service"]["status"], "NOT_ADMITTED");
    assert_eq!(service(&responses[3])["service"]["reason"], "CAPACITY");
    assert_eq!(responses[1]["result"]["isError"], true);
    assert_eq!(responses[2]["result"]["isError"], true);
    assert_eq!(responses[3]["result"]["isError"], false);
}

#[test]
fn hostile_and_duplicate_arguments_are_rejected_before_any_socket_access() {
    let mut lines = handshake();
    for arguments in [
        json!({"operation_id":"op-1","grant":"SECRET"}),
        json!({"operation_id":"../oops"}),
        json!({"operation_id":1}),
    ] {
        lines.push(tool(2, "kapsel.submit", &arguments));
    }
    for response in &run(&lines, &[])[1..] {
        assert_eq!(response["error"]["code"], -32602);
    }
    let mut raw = Vec::new();
    for line in handshake() {
        writeln!(&mut raw, "{line}").unwrap();
    }
    raw.extend_from_slice(
        concat!(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"#,
            r#""name":"kapsel.submit","arguments":{"#,
            r#""operation_id":"op-1","operation_id":"op-2"}}}"#,
            "\n",
        )
        .as_bytes(),
    );
    assert_eq!(run_raw(&raw, &[])[1]["error"]["code"], -32700);
}

#[test]
fn an_unbound_transport_reports_uncertainty_not_nonadmission() {
    let root = root();
    let mut lines = handshake();
    lines.push(tool(2, "kapsel.submit", &json!({"operation_id":"op-1"})));
    let mut input = Vec::new();
    for line in lines {
        writeln!(&mut input, "{line}").unwrap();
    }
    let responses = bridge(&root.join("absent"), &input);
    assert_eq!(
        service(&responses[1])["service"]["error_class"],
        "service_exchange_uncertain"
    );
    assert_eq!(responses[1]["result"]["isError"], true);
    fs::remove_dir_all(root).unwrap();
}
