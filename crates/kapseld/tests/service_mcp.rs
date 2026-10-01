//! Black-box bounded stdio bridge tests against a fixed service socket fixture.
#![cfg(feature = "test-harness")]
#![allow(
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::panic,
    reason = "test fixture failures must stop the test"
)]

use std::{
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::Shutdown,
    os::unix::net::UnixListener,
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
const BIN: &str = env!("CARGO_BIN_EXE_kapsel-service-mcp");

fn run(lines: &[Value], exchanges: &[(Value, Value)]) -> Vec<Value> {
    let mut input = Vec::new();
    for line in lines {
        writeln!(&mut input, "{line}").unwrap();
    }
    run_raw(&input, exchanges)
}

fn run_raw(input: &[u8], exchanges: &[(Value, Value)]) -> Vec<Value> {
    let root = std::env::temp_dir().join(format!(
        "kapsel-mcp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let socket = root.join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let exchanges = exchanges.to_vec();
    let (stop, stopped) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut request_count = 0;
        loop {
            let mut conn = match listener.accept() {
                Ok((conn, _)) => conn,
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
            conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            conn.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (expected_request, response) = exchanges
                .get(request_count)
                .unwrap_or_else(|| panic!("unexpected service request {}", request_count + 1));
            let mut prefix = [0; 4];
            conn.read_exact(&mut prefix).unwrap();
            let length = u32::from_be_bytes(prefix) as usize;
            assert!((1..=16 * 1024).contains(&length));
            let mut body = vec![0; length];
            conn.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                &request,
                expected_request,
                "service request {}",
                request_count + 1
            );
            let mut extra = [0; 1];
            assert_eq!(conn.read(&mut extra).unwrap(), 0);
            request_count += 1;
            let bytes = serde_json::to_vec(response).unwrap();
            conn.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
                .unwrap();
            conn.write_all(&bytes).unwrap();
            conn.shutdown(Shutdown::Write).unwrap();
        }
        assert_eq!(request_count, exchanges.len(), "missing service requests");
    });
    let mut child = Command::new(BIN)
        .env("KAPSELD_TEST_CLIENT_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let _ = stop.send(());
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
    BufReader::new(output.stdout.as_slice())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn operation_request(kind: &str, id: &str) -> Value {
    json!({"version":1,"request":kind,"operation_id":id})
}

fn handshake() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ]
}
fn tool(id: i32, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":name,"arguments":arguments}})
}

#[test]
fn read_and_submit_are_separate_and_preserve_service_facts() {
    let mut lines = handshake();
    lines.push(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    lines.push(tool(
        3,
        "kapsel.list_approved_actions",
        json!({"after":null}),
    ));
    lines.push(tool(4, "kapsel.get_status", json!({"operation_id":"op-1"})));
    lines.push(tool(5, "kapsel.submit", json!({"operation_id":"op-2"})));
    lines.push(tool(
        6,
        "kapsel.get_receipt",
        json!({"operation_id":"op-2"}),
    ));
    let responses = run(
        &lines,
        &[
            (
                json!({"version":1,"request":"list_approved_actions","after":null}),
                json!({"version":1,"status":"READY","entries":[],"next_cursor":null}),
            ),
            (
                operation_request("get_set_deployment_image_status", "op-1"),
                json!({"version":1,"status":"IN_PROGRESS","execution":{
                    "disposition":"resume_required","condition":null,
                    "next_action":"select_same_id","action_owner":"caller"}}),
            ),
            (
                operation_request("submit_set_deployment_image", "op-2"),
                json!({"version":1,"status":"ADMITTED","phase":"apply_started"}),
            ),
            (
                operation_request("get_set_deployment_image_receipt", "op-2"),
                json!({"version":1,"status":"NOT_READY"}),
            ),
        ],
    );
    assert_eq!(responses.len(), 6);
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 5);
    assert_eq!(responses[2]["result"]["isError"], false);
    let read: Value = serde_json::from_str(
        responses[3]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(read["operation_id"], "op-1");
    assert_eq!(
        read["service"]["execution"]["disposition"],
        "resume_required"
    );
    let admitted: Value = serde_json::from_str(
        responses[4]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(admitted["operation_id"], "op-2");
    assert_eq!(admitted["service"]["phase"], "apply_started");
}

#[test]
fn history_access_failure_and_receipt_unavailability_remain_distinct() {
    let mut lines = handshake();
    lines.push(tool(
        2,
        "kapsel.list_operation_history",
        json!({"after":"op-previous"}),
    ));
    lines.push(tool(3, "kapsel.get_status", json!({"operation_id":"op-1"})));
    lines.push(tool(
        4,
        "kapsel.get_receipt",
        json!({"operation_id":"op-1"}),
    ));
    let responses = run(
        &lines,
        &[
            (
                json!({"version":1,"request":"list_operation_history","after":"op-previous"}),
                json!({"version":1,"status":"READY","entries":[{"operation_id":"op-1",
                    "status":"ERROR","error_class":"authority_unavailable"}],"next_cursor":null}),
            ),
            (
                operation_request("get_set_deployment_image_status", "op-1"),
                json!({"version":1,"status":"ERROR","error_class":"authority_unavailable"}),
            ),
            (
                operation_request("get_set_deployment_image_receipt", "op-1"),
                json!({"version":1,"status":"NOT_READY"}),
            ),
        ],
    );
    let parse = |index: usize| -> Value {
        serde_json::from_str(
            responses[index]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        parse(1)["service"]["entries"][0]["error_class"],
        "authority_unavailable"
    );
    assert_eq!(parse(2)["service"]["error_class"], "authority_unavailable");
    assert_eq!(responses[2]["result"]["isError"], true);
    assert_eq!(parse(3)["service"]["status"], "NOT_READY");
    assert_eq!(responses[3]["result"]["isError"], false);
}

#[test]
fn hostile_tool_arguments_never_reach_service() {
    let mut lines = handshake();
    for args in [
        json!({"operation_id":"op-1","grant":"bad"}),
        json!({"operation_id":"../oops"}),
        json!({"operation_id":1}),
    ] {
        lines.push(tool(3, "kapsel.submit", args));
    }
    let responses = run(&lines, &[]);
    assert_eq!(responses.len(), 4);
    for response in &responses[1..] {
        assert_eq!(response["error"]["code"], -32602);
    }
}

#[test]
fn incomplete_admission_facts_are_not_relayed_as_decisions() {
    let mut lines = handshake();
    for id in 2..=5 {
        lines.push(tool(id, "kapsel.submit", json!({"operation_id":"op-1"})));
    }
    let responses = run(
        &lines,
        &[
            (
                operation_request("submit_set_deployment_image", "op-1"),
                json!({"version":1,"status":"ADMITTED"}),
            ),
            (
                operation_request("submit_set_deployment_image", "op-1"),
                json!({"version":1,"status":"ADMITTED","phase":"surprise"}),
            ),
            (
                operation_request("submit_set_deployment_image", "op-1"),
                json!({"version":1,"status":"NOT_ADMITTED"}),
            ),
            (
                operation_request("submit_set_deployment_image", "op-1"),
                json!({"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}),
            ),
        ],
    );
    for response in &responses[1..4] {
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("response_invalid"));
        assert_eq!(response["result"]["isError"], true);
    }
    assert!(responses[4]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("NOT_ADMITTED"));
}

#[test]
fn duplicate_nested_json_is_rejected_before_socket_access() {
    let mut input = Vec::new();
    for message in handshake() {
        writeln!(&mut input, "{message}").unwrap();
    }
    input
        .write_all(
            concat!(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"#,
                r#""name":"kapsel.submit","arguments":{"#,
                r#""operation_id":"op-1","operation_id":"op-2"}}}"#,
                "\n",
            )
            .as_bytes(),
        )
        .unwrap();
    let responses = run_raw(&input, &[]);
    assert_eq!(responses[1]["error"]["code"], -32700);
}

#[test]
fn transport_failure_is_not_non_admission() {
    let mut lines = handshake();
    lines.push(tool(2, "kapsel.submit", json!({"operation_id":"op-1"})));
    // An unbound socket models a lost admission response, not a definite refusal.
    let root = std::env::temp_dir().join(format!("kapsel-mcp-absent-{}", std::process::id()));
    let output = Command::new(BIN)
        .env("KAPSELD_TEST_CLIENT_SOCKET", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = output.stdin.as_ref().unwrap();
    for line in lines {
        writeln!(input, "{line}").unwrap();
    }
    let output = output.wait_with_output().unwrap();
    let responses: Vec<Value> = BufReader::new(output.stdout.as_slice())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect();
    let text = responses[1]["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("service_exchange_uncertain"));
    assert!(!text.contains("NOT_ADMITTED"));
}
