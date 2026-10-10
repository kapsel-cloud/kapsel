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

fn execution(disposition: &str, condition: Value, next_action: &str, owner: &str) -> Value {
    json!({
        "disposition": disposition,
        "condition": condition,
        "next_action": next_action,
        "action_owner": owner,
    })
}

fn kubernetes_status(status: &str, execution: Value) -> Value {
    json!({
        "version": 1,
        "status": status,
        "effect": "kubernetes.set_deployment_image",
        "approved_target": {"uid": "uid-1", "resource_version": "10"},
        "attempt_target": null,
        "observed_target": null,
        "execution": execution,
    })
}

fn git_status(status: &str, execution: Value) -> Value {
    json!({
        "version": 1,
        "status": status,
        "effect": "git.transition_ref",
        "git": {
            "repository_id": "repo-1",
            "reference": "refs/heads/main",
            "old_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "new_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "attempted": true,
            "acknowledgement": "updated",
            "observed_ref": {
                "kind": "commit",
                "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        },
        "execution": execution,
    })
}

fn service_text(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
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
                kubernetes_status(
                    "IN_PROGRESS",
                    execution("resume_required", Value::Null, "select_same_id", "caller"),
                ),
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
    let read = service_text(&responses[3]);
    assert_eq!(read["operation_id"], "op-1");
    assert_eq!(
        read["service"]["execution"]["disposition"],
        "resume_required"
    );
    let admitted = service_text(&responses[4]);
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
    let parse = |index: usize| -> Value { service_text(&responses[index]) };
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
#[allow(
    clippy::too_many_lines,
    reason = "canonical guidance tuples stay adjacent to exact unchanged-value assertions"
)]
fn status_response_accepts_only_canonical_execution_guidance() {
    let allowed = [
        kubernetes_status(
            "IN_PROGRESS",
            execution("active", Value::Null, "wait", "caller"),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "waiting_for_worker",
                Value::Null,
                "wait_then_select_same_id",
                "caller",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution("resume_required", Value::Null, "select_same_id", "caller"),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "resume_required",
                json!("preflight_unavailable"),
                "select_same_id",
                "caller",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "resume_required",
                json!("worker_contention"),
                "select_same_id",
                "caller",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "operator_required",
                json!("receiver_unavailable"),
                "contact_operator",
                "operator",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "operator_required",
                json!("signing_unavailable"),
                "contact_operator",
                "operator",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "operator_required",
                json!("completion_blocked"),
                "contact_operator",
                "operator",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "operator_required",
                json!("operation_blocked"),
                "contact_operator",
                "operator",
            ),
        ),
        kubernetes_status(
            "SUCCEEDED",
            execution("complete", Value::Null, "inspect_result", "caller"),
        ),
        json!({"version":1,"status":"NOT_FOUND","execution":execution(
            "admission_unconfirmed", Value::Null, "read_same_id", "caller"
        )}),
    ];
    let mut lines = handshake();
    let exchanges: Vec<_> = allowed
        .iter()
        .enumerate()
        .map(|(index, response)| {
            lines.push(tool(
                i32::try_from(index + 2).unwrap(),
                "kapsel.get_status",
                json!({"operation_id":"op-1"}),
            ));
            (
                operation_request("get_set_deployment_image_status", "op-1"),
                response.clone(),
            )
        })
        .collect();
    let responses = run(&lines, &exchanges);
    for (response, expected) in responses[1..].iter().zip(allowed) {
        let text = service_text(response);
        assert_eq!(text["operation_id"], "op-1");
        assert_eq!(text["service"], expected);
        assert_eq!(response["result"]["isError"], false);
    }
}

#[test]
fn status_response_validates_effect_specific_target_shapes() {
    let mut kube_not_attempted = kubernetes_status(
        "NOT_ATTEMPTED",
        execution("complete", Value::Null, "inspect_result", "caller"),
    );
    kube_not_attempted["target_rejection"] = json!("STALE_APPROVAL");
    let git_unknown = git_status(
        "UNKNOWN",
        execution("complete", Value::Null, "inspect_result", "caller"),
    );
    let mut git_stale = git_status(
        "NOT_ATTEMPTED",
        execution("complete", Value::Null, "inspect_result", "caller"),
    );
    git_stale["target_rejection"] = json!("GIT_STALE_REF");
    let mut git_invalid = git_stale.clone();
    git_invalid["target_rejection"] = json!("GIT_INVALID_OBJECTS");
    let accepted = [
        json!({"version":1,"status":"NOT_FOUND","execution":execution(
            "admission_unconfirmed", Value::Null, "read_same_id", "caller"
        )}),
        kube_not_attempted,
        git_unknown,
        git_stale,
        git_invalid,
    ];
    let mut lines = handshake();
    let exchanges: Vec<_> = accepted
        .iter()
        .enumerate()
        .map(|(index, response)| {
            lines.push(tool(
                i32::try_from(index + 2).unwrap(),
                "kapsel.get_status",
                json!({"operation_id":"op-1"}),
            ));
            (
                operation_request("get_set_deployment_image_status", "op-1"),
                response.clone(),
            )
        })
        .collect();
    let responses = run(&lines, &exchanges);
    for (response, expected) in responses[1..].iter().zip(accepted) {
        let text = service_text(response);
        assert_eq!(text["service"], expected);
        assert_eq!(response["result"]["isError"], false);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "hostile reply variants stay adjacent to their common opaque-error assertions"
)]
fn malformed_status_guidance_and_extra_fields_are_response_errors() {
    let mut extra_execution = kubernetes_status(
        "IN_PROGRESS",
        execution("resume_required", Value::Null, "select_same_id", "caller"),
    );
    extra_execution["execution"]["extra"] = json!(true);
    let malformed = [
        json!({"version":1,"status":"IN_PROGRESS"}),
        json!({"version":1,"status":"IN_PROGRESS","execution":[]}),
        kubernetes_status(
            "IN_PROGRESS",
            execution("surprise", Value::Null, "wait", "caller"),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution(
                "resume_required",
                json!("receiver_unavailable"),
                "select_same_id",
                "caller",
            ),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution("resume_required", Value::Null, "wait", "caller"),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution("active", Value::Null, "wait", "operator"),
        ),
        kubernetes_status(
            "IN_PROGRESS",
            execution("complete", Value::Null, "inspect_result", "caller"),
        ),
        kubernetes_status(
            "SUCCEEDED",
            execution("active", Value::Null, "wait", "caller"),
        ),
        {
            let mut response = kubernetes_status(
                "IN_PROGRESS",
                execution("active", Value::Null, "wait", "caller"),
            );
            response["unexpected"] = json!(true);
            response
        },
        extra_execution,
        {
            let mut response = kubernetes_status(
                "IN_PROGRESS",
                execution("active", Value::Null, "wait", "caller"),
            );
            response.as_object_mut().unwrap().remove("approved_target");
            response
        },
        {
            let mut response = kubernetes_status(
                "IN_PROGRESS",
                execution("active", Value::Null, "wait", "caller"),
            );
            response["approved_target"] = json!({"uid":"uid-1"});
            response
        },
        {
            let mut response = kubernetes_status(
                "NOT_ATTEMPTED",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["target_rejection"] = json!("GIT_STALE_REF");
            response
        },
        {
            let mut response = kubernetes_status(
                "NOT_ATTEMPTED",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["target_rejection"] = json!("stale_approval");
            response
        },
        {
            let mut response = git_status(
                "NOT_ATTEMPTED",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["target_rejection"] = json!("STALE_APPROVAL");
            response
        },
        {
            let mut response = git_status(
                "UNKNOWN",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["git"]["acknowledgement"] = json!("surprise");
            response
        },
        {
            let mut response = git_status(
                "UNKNOWN",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["git"]["observed_ref"] = json!({"kind":"tag","commit":null});
            response
        },
        {
            let mut response = git_status(
                "UNKNOWN",
                execution("complete", Value::Null, "inspect_result", "caller"),
            );
            response["git"]["observed_ref"]["extra"] = json!(true);
            response
        },
    ];
    let mut lines = handshake();
    let exchanges: Vec<_> = malformed
        .into_iter()
        .enumerate()
        .map(|(index, response)| {
            lines.push(tool(
                i32::try_from(index + 2).unwrap(),
                "kapsel.get_status",
                json!({"operation_id":"op-1"}),
            ));
            (
                operation_request("get_set_deployment_image_status", "op-1"),
                response,
            )
        })
        .collect();
    let responses = run(&lines, &exchanges);
    for response in &responses[1..] {
        let text = service_text(response);
        assert_eq!(text["service"]["error_class"], "response_invalid");
        assert_eq!(response["result"]["isError"], true);
    }
}

#[test]
fn history_entries_use_the_same_status_shape() {
    let mut entry = git_status(
        "UNKNOWN",
        execution("complete", Value::Null, "inspect_result", "caller"),
    );
    entry.as_object_mut().unwrap().remove("version");
    entry["operation_id"] = json!("op-1");
    let mut lines = handshake();
    lines.push(tool(
        2,
        "kapsel.list_operation_history",
        json!({"after":null}),
    ));
    let expected = json!({"version":1,"status":"READY","entries":[entry],"next_cursor":null});
    let responses = run(
        &lines,
        &[(
            json!({"version":1,"request":"list_operation_history","after":null}),
            expected.clone(),
        )],
    );
    assert_eq!(service_text(&responses[1])["service"], expected);
}

#[test]
fn invalid_service_envelopes_remain_response_errors() {
    let mut lines = handshake();
    let exchanges: Vec<_> = [
        json!({"status":"ADMITTED","phase":"authorized"}),
        json!({"version":2,"status":"ADMITTED","phase":"authorized"}),
        json!({"version":1.0,"status":"ADMITTED","phase":"authorized"}),
        json!({"version":1,"status":"ACCEPTED","phase":"authorized"}),
    ]
    .into_iter()
    .zip(2..)
    .map(|(response, id)| {
        lines.push(tool(id, "kapsel.submit", json!({"operation_id":"op-1"})));
        (
            operation_request("submit_set_deployment_image", "op-1"),
            response,
        )
    })
    .collect();
    let responses = run(&lines, &exchanges);
    for response in &responses[1..] {
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("response_invalid"));
        assert!(!text.contains("NOT_ADMITTED"));
        assert!(!text.contains("service_exchange_uncertain"));
        assert_eq!(response["result"]["isError"], true);
    }
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
    // An unbound socket exercises the bridge's uncertain delivery result. It does not model
    // actual admission or prove that a request reached the service.
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
