//! Black-box contract tests for the fixed MCP stdio adapter.

#![allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the end-to-end test immediately"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use ed25519_dalek::SigningKey;
use kapsel::{provision_exact_grant, ExactAuthorization, GrantProvisioning};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const IMAGE: &str = concat!(
    "registry.example/agent-api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);

struct Fixture {
    root: PathBuf,
    request: PathBuf,
    operator_config: PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn fixture() -> Fixture {
    fixture_with_receiver(None)
}

fn successful_fixture() -> Fixture {
    fixture_with_receiver(Some("SUCCEEDED"))
}

fn not_attempted_fixture() -> Fixture {
    fixture_with_receiver(Some("NOT_ATTEMPTED"))
}

fn failed_fixture() -> Fixture {
    fixture_with_receiver(Some("FAILED"))
}

fn unknown_fixture() -> Fixture {
    fixture_with_receiver(Some("UNKNOWN"))
}

fn fixture_with_receiver(receiver_result: Option<&'static str>) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "kapsel-e2e-mcp-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    private_directory(&root.join("receipts"));

    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        authorization_id: "mcp-auth-1".into(),
        operation_id: "mcp-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "mcp-authorization-key",
    })
    .unwrap();
    private_file(&root.join("grant.bin"), &grant);
    private_file(
        &root.join("authorization.pub"),
        &authorization_key.verifying_key().to_bytes(),
    );
    private_file(&root.join("receipt.seed"), &[42_u8; 32]);
    let (address, server) = receiver_result.map_or_else(
        || (String::from("127.0.0.1:9"), None),
        |receiver_result| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || serve_outcome(&listener, receiver_result));
            (address.to_string(), Some(server))
        },
    );
    private_file(
        &root.join("kubeconfig.yaml"),
        format!(
            concat!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                "  cluster:\n    server: http://{address}\ncontexts:\n- name: fixture\n",
                "  context:\n    cluster: fixture\n    user: fixture\n",
                "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
            ),
            address = address
        )
        .as_bytes(),
    );
    let request = root.join("request.json");
    private_file(
        &request,
        format!(
            concat!(
                "{{\"operation_id\":\"mcp-op-1\",\"namespace\":\"demo\",",
                "\"deployment\":\"agent-api\",\"container\":\"api\",",
                "\"immutable_image_digest\":\"{IMAGE}\"}}"
            ),
            IMAGE = IMAGE
        )
        .as_bytes(),
    );
    let operator_config = root.join("operator.json");
    private_file(
        &operator_config,
        format!(
            concat!(
                "{{\"signed_authorization_grant\":\"{}/grant.bin\",",
                "\"authorization_key_id\":\"mcp-authorization-key\",",
                "\"authorization_public_key\":\"{}/authorization.pub\",",
                "\"kubeconfig\":\"{}/kubeconfig.yaml\",",
                "\"journal\":\"{}/journal.sqlite3\",",
                "\"receipt_directory\":\"{}/receipts\",",
                "\"receipt_signing_seed\":\"{}/receipt.seed\",",
                "\"receipt_signing_key_id\":\"mcp-receipt-key\"}}"
            ),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display()
        )
        .as_bytes(),
    );
    Fixture {
        root,
        request,
        operator_config,
        server,
    }
}

fn serve_outcome(listener: &TcpListener, receiver_result: &str) {
    if receiver_result == "NOT_ATTEMPTED" {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "Status", "status": "Failure",
            "reason": "NotFound", "message": "SECRET_PROVIDER_CANARY", "code": 404
        })
        .to_string();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        write!(
            stream,
            concat!(
                "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n",
                "content-length: {}\r\nconnection: close\r\n\r\n"
            ),
            body.len()
        )
        .unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        return;
    }
    let old_image = concat!(
        "registry.example/agent-api@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let failed = receiver_result == "FAILED";
    let responses = [
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
                "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
                "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": IMAGE}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo",
                "uid": if receiver_result == "UNKNOWN" { "other-uid" } else { "uid-1" },
                "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": "mcp-op-1"}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": IMAGE}]}}},
            "status": {"observedGeneration": 2,
                "updatedReplicas": i32::from(!failed),
                "availableReplicas": i32::from(!failed),
                "unavailableReplicas": i32::from(failed),
                "conditions": [if failed {
                    serde_json::json!({"type": "Progressing", "status": "False",
                        "reason": "ProgressDeadlineExceeded"})
                } else {
                    serde_json::json!({"type": "Available", "status": "True",
                        "reason": "MinimumReplicasAvailable"})
                }]}
        }),
    ];
    for body in responses.map(|value| value.to_string()) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
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
}

fn run_session(fixture: &Fixture, messages: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = spawn_mcp(fixture);
    let mut input = child.stdin.take().unwrap();
    for message in messages {
        serde_json::to_writer(&mut input, message).unwrap();
        input.write_all(b"\n").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .all(|line| line.len() <= 8 * 1024));
    parse_responses(&output.stdout)
}

fn spawn_mcp(fixture: &Fixture) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "mcp",
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn run_raw_session(fixture: &Fixture, bytes: &[u8]) -> std::process::Output {
    let mut child = spawn_mcp(fixture);
    let mut input = child.stdin.take().unwrap();
    input.write_all(bytes).unwrap();
    drop(input);
    child.wait_with_output().unwrap()
}

fn parse_responses(bytes: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn initialization_lists_exactly_the_fixed_request_only_tool() {
    let fixture = fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "initialize-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "kapsel-test", "version": "1"}
                }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        ],
    );

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0],
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "initialize-1",
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kapsel", "version": "0.1.0-rc.1"}
            }
        })
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(
        tools[0],
        serde_json::json!({
            "name": "kubernetes.set_deployment_image",
            "description": "Request one authorized immutable Kubernetes Deployment image change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[A-Za-z0-9._:-]+$"
                    },
                    "namespace": {
                        "type": "string", "minLength": 1, "maxLength": 63,
                        "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                    },
                    "deployment": {"type": "string", "minLength": 1, "maxLength": 253},
                    "container": {
                        "type": "string", "minLength": 1, "maxLength": 63,
                        "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                    },
                    "immutable_image_digest": {
                        "type": "string", "minLength": 1, "maxLength": 512
                    }
                },
                "required": [
                    "operation_id", "namespace", "deployment", "container",
                    "immutable_image_digest"
                ],
                "additionalProperties": false
            }
        })
    );
}

#[test]
fn lifecycle_and_dispatch_errors_remain_bounded() {
    let fixture = fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "init", "method": "initialize",
                "params": {"protocolVersion": "1900-01-01", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "second.tool", "arguments": {}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "kubernetes.set_deployment_image",
                    "arguments": {"operation_id": 7}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 999, "reason": "SECRET_CANCEL_CANARY"}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "kubernetes.set_deployment_image", "arguments": {}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": null, "method": "tools/list"}),
            serde_json::json!({"jsonrpc": "2.0", "id": true, "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "x".repeat(129), "method": "tools/list"
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"}),
        ],
    );

    assert_eq!(responses.len(), 11);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert_eq!(responses[1]["id"], "init");
    assert_eq!(responses[1]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert_eq!(responses[3]["error"]["code"], -32600);
    assert_eq!(responses[4]["error"]["code"], -32601);
    assert_eq!(responses[5]["error"]["code"], -32602);
    assert_eq!(responses[6]["error"]["code"], -32602);
    assert_eq!(responses[7]["error"]["code"], -32600);
    assert_eq!(responses[7]["id"], serde_json::Value::Null);
    assert_eq!(responses[8]["error"]["code"], -32600);
    assert_eq!(responses[8]["id"], serde_json::Value::Null);
    assert_eq!(responses[9]["error"]["code"], -32600);
    assert_eq!(responses[9]["id"], serde_json::Value::Null);
    assert_eq!(responses[10]["id"], "list");
    let serialized = serde_json::to_vec(&responses).unwrap();
    assert!(!serialized
        .windows(b"SECRET_CANCEL_CANARY".len())
        .any(|window| window == b"SECRET_CANCEL_CANARY"));
    assert!(serialized.len() < 8 * 1024);
}

#[test]
fn mutable_image_and_exact_grant_mismatch_are_request_rejections() {
    let fixture = fixture();
    let call = |id: u64, container: &str, image: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "kubernetes.set_deployment_image", "arguments": {
                "operation_id": "mcp-op-1", "namespace": "demo",
                "deployment": "agent-api", "container": container,
                "immutable_image_digest": image
            }}
        })
    };
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            call(2, "api", "registry.example/agent-api:latest"),
            call(3, "other", IMAGE),
        ],
    );
    for response in &responses[1..] {
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["content"][0]["text"],
            r#"{"status":"ERROR","error_class":"request_rejected"}"#
        );
    }
    assert_eq!(
        fs::read_dir(fixture.root.join("receipts")).unwrap().count(),
        0
    );
}

#[test]
fn application_outcome_vocabulary_remains_distinct() {
    for (create, expected_state, expected_result) in [
        (
            not_attempted_fixture as fn() -> Fixture,
            "NOT_ATTEMPTED",
            None,
        ),
        (
            failed_fixture as fn() -> Fixture,
            "FINALIZED",
            Some("FAILED"),
        ),
        (
            unknown_fixture as fn() -> Fixture,
            "FINALIZED",
            Some("UNKNOWN"),
        ),
    ] {
        let mut fixture = create();
        let responses = run_session(
            &fixture,
            &[
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"}}
                }),
                serde_json::json!({
                    "jsonrpc": "2.0", "method": "notifications/initialized"
                }),
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "kubernetes.set_deployment_image", "arguments": {
                        "operation_id": "mcp-op-1", "namespace": "demo",
                        "deployment": "agent-api", "container": "api",
                        "immutable_image_digest": IMAGE
                    }}
                }),
            ],
        );
        let report: serde_json::Value = serde_json::from_str(
            responses[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["state"], expected_state);
        assert_eq!(
            report["result"],
            expected_result.map_or(serde_json::Value::Null, serde_json::Value::from)
        );
        if expected_state == "NOT_ATTEMPTED" {
            assert_eq!(report["target_rejection"], "DEPLOYMENT_NOT_FOUND");
        }
        assert_eq!(responses[1]["result"]["isError"], false);
        fixture.server.take().unwrap().join().unwrap();
    }
}

#[test]
fn untrusted_operator_configuration_exits_before_protocol_traffic() {
    let fixture = fixture();
    private_file(&fixture.root.join("authorization.pub"), &[99_u8; 32]);
    let child = spawn_mcp(&fixture);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 4096);
    for canary in [
        b"grant.bin".as_slice(),
        b"authorization.pub",
        b"receipt.seed",
    ] {
        assert!(!output
            .stderr
            .windows(canary.len())
            .any(|window| window == canary));
    }
}

#[test]
fn duplicate_and_oversized_frames_fail_without_disclosure() {
    let fixture = fixture();
    let output = run_raw_session(
        &fixture,
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"#,
            r#""protocolVersion":"2025-11-25","#,
            r#""protocolVersion":"SECRET_DUPLICATE_CANARY","capabilities":{},"#,
            r#""clientInfo":{"name":"test","version":"1"}}}"#,
            "\n"
        )
        .as_bytes(),
    );
    assert_eq!(output.status.code(), Some(0));
    let responses = parse_responses(&output.stdout);
    assert_eq!(responses[0]["error"]["code"], -32700);
    assert!(!output
        .stdout
        .windows(b"SECRET_DUPLICATE_CANARY".len())
        .any(|window| window == b"SECRET_DUPLICATE_CANARY"));

    let output = run_raw_session(&fixture, &vec![b'x'; 16 * 1024 + 1]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 4096);
}

#[test]
fn framing_boundaries_reject_incomplete_utf8_and_batch_input() {
    let fixture = fixture();

    let output = run_raw_session(&fixture, &[0xff, b'\n']);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["error"]["code"], -32700);

    let output = run_raw_session(&fixture, b"[]\n");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["error"]["code"], -32600);

    let output = run_raw_session(&fixture, br#"{"jsonrpc":"2.0"}"#);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let initialize = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"#,
        r#""protocolVersion":"2025-11-25","capabilities":{},"#,
        r#""clientInfo":{"name":"test","version":"1"}}}"#
    );
    let mut exact_frame = initialize.as_bytes().to_vec();
    exact_frame.resize(16 * 1024 - 1, b' ');
    exact_frame.push(b'\n');
    let output = run_raw_session(&fixture, &exact_frame);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["id"], 1);
}

#[test]
fn tool_call_matches_the_local_request_and_typed_outcome() {
    let mut fixture = successful_fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "kapsel-test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
                "params": {
                    "name": "kubernetes.set_deployment_image",
                    "_meta": {"progressToken": "ignored-but-valid"},
                    "arguments": {
                        "operation_id": "mcp-op-1", "namespace": "demo",
                        "deployment": "agent-api", "container": "api",
                        "immutable_image_digest": IMAGE
                    }
                }
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "call-2", "method": "tools/call",
                "params": {
                    "name": "kubernetes.set_deployment_image",
                    "arguments": {
                        "operation_id": "mcp-op-1", "namespace": "demo",
                        "deployment": "agent-api", "container": "api",
                        "immutable_image_digest": IMAGE
                    }
                }
            }),
        ],
    );
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[1]["id"], "call-1");
    assert_eq!(responses[1]["result"]["isError"], false);
    let report: serde_json::Value = serde_json::from_str(
        responses[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["operation_id"], "mcp-op-1");
    assert_eq!(report["state"], "FINALIZED");
    assert_eq!(report["result"], "SUCCEEDED");
    assert_eq!(report["target_rejection"], serde_json::Value::Null);
    assert_eq!(responses[2]["id"], "call-2");
    assert_eq!(
        responses[2]["result"]["content"][0]["text"],
        responses[1]["result"]["content"][0]["text"]
    );
    fixture.server.take().unwrap().join().unwrap();

    let local = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(0));
    let local_report: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    for field in [
        "operation_id",
        "state",
        "result",
        "target_rejection",
        "receipt_file",
        "receipt_sha256",
    ] {
        assert_eq!(report[field], local_report[field], "field {field}");
    }
}
