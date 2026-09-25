//! Black-box bounded stdio bridge tests against a fixed service socket fixture.
#![cfg(feature = "test-harness")]
#![allow(
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    reason = "test fixture failures must stop the test"
)]

use std::{
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::Shutdown,
    os::unix::net::UnixListener,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);
const BIN: &str = env!("CARGO_BIN_EXE_kapsel-service-mcp");

fn run(lines: &[Value], replies: &[Value]) -> Vec<Value> {
    let root = std::env::temp_dir().join(format!(
        "kapsel-mcp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let socket = root.join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    let replies = replies.to_vec();
    let server = thread::spawn(move || {
        for response in replies {
            let (mut conn, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            conn.read_exact(&mut prefix).unwrap();
            let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
            conn.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["version"], 1);
            let mut extra = [0; 1];
            assert_eq!(conn.read(&mut extra).unwrap(), 0);
            let bytes = serde_json::to_vec(&response).unwrap();
            conn.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
                .unwrap();
            conn.write_all(&bytes).unwrap();
            conn.shutdown(Shutdown::Write).unwrap();
        }
    });
    let mut child = Command::new(BIN)
        .env("KAPSELD_TEST_CLIENT_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for line in lines {
        writeln!(input, "{line}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
    BufReader::new(output.stdout.as_slice())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
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
    lines.push(tool(5, "kapsel.submit", json!({"operation_id":"op-1"})));
    lines.push(tool(
        6,
        "kapsel.get_receipt",
        json!({"operation_id":"op-1"}),
    ));
    let responses = run(
        &lines,
        &[
            json!({"version":1,"status":"READY","entries":[],"next_cursor":null}),
            json!({"version":1,"status":"IN_PROGRESS","execution":{
            "disposition":"resume_required","condition":null,
            "next_action":"select_same_id","action_owner":"caller"}}),
            json!({"version":1,"status":"ADMITTED","phase":"apply_started"}),
            json!({"version":1,"status":"NOT_READY"}),
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
    assert_eq!(admitted["operation_id"], "op-1");
    assert_eq!(admitted["service"]["phase"], "apply_started");
}

#[test]
fn history_access_failure_and_receipt_unavailability_remain_distinct() {
    let mut lines = handshake();
    lines.push(tool(
        2,
        "kapsel.list_operation_history",
        json!({"after":null}),
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
            json!({"version":1,"status":"READY","entries":[{"operation_id":"op-1",
            "status":"ERROR","error_class":"authority_unavailable"}],"next_cursor":null}),
            json!({"version":1,"status":"ERROR","error_class":"authority_unavailable"}),
            json!({"version":1,"status":"NOT_READY"}),
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
            json!({"version":1,"status":"ADMITTED"}),
            json!({"version":1,"status":"ADMITTED","phase":"surprise"}),
            json!({"version":1,"status":"NOT_ADMITTED"}),
            json!({"version":1,"status":"NOT_ADMITTED","reason":"CAPACITY"}),
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
    let mut child = Command::new(BIN)
        .env("KAPSELD_TEST_CLIENT_SOCKET", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for message in handshake() {
        writeln!(input, "{message}").unwrap();
    }
    input.write_all(br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kapsel.submit","arguments":{"operation_id":"op-1","operation_id":"op-2"}}}
"#).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    let responses: Vec<Value> = BufReader::new(output.stdout.as_slice())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect();
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
