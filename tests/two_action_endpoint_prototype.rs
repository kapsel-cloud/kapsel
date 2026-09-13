//! Isolated two-identity endpoint, driven by scripts/prototype-two-actions.py, never installed.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "maintainer-owned prototype assertions fail closed on invalid fixture evidence"
)]

use std::{
    fmt::Write as _,
    fs,
    io::{Read, Write},
    net::TcpStream,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use kapsel::{
    provision_exact_grant, AgentRequest, Application, ApprovedTarget, AuthorizationTrust,
    ExactAuthorization, GrantProvisioning, OperatorConfiguration, SetDeploymentImageReceipt,
    SetDeploymentImageStatus,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_test::mock;

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Select { operation_id: String },
    Status { operation_id: String },
    Receipt { operation_id: String },
}

impl Command {
    fn identity(&self) -> &str {
        match self {
            Self::Select { operation_id }
            | Self::Status { operation_id }
            | Self::Receipt { operation_id } => operation_id,
        }
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn requests(root: &Path) -> [AgentRequest; 2] {
    let values: [Value; 2] =
        serde_json::from_slice(&fs::read(root.join("requests.json")).unwrap()).unwrap();
    values.map(|value| AgentRequest {
        operation_id: value["operation_id"].as_str().unwrap().into(),
        namespace: value["namespace"].as_str().unwrap().into(),
        deployment: value["deployment"].as_str().unwrap().into(),
        container: value["container"].as_str().unwrap().into(),
        immutable_image_digest: value["immutable_image_digest"].as_str().unwrap().into(),
    })
}

// Deliberately one HTTP/1 request and no retry; receiver logs independently count actual requests.
fn forward(address: &str, method: &str, uri: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "{method} {uri} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\n\
         Content-Type: application/strategic-merge-patch+json\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut bytes = Vec::new();
    stream.take(32 * 1024).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() < 32 * 1024);
    let split = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&bytes[..split]).unwrap();
    let code = headers
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (code, bytes[split + 4..].to_vec())
}

fn approve(root: &Path, index: usize, replacement: bool) {
    let request = requests(root)[index].clone();
    let address = fs::read_to_string(root.join("receiver")).unwrap();
    let uri = format!(
        "/apis/apps/v1/namespaces/demo/deployments/{}",
        request.deployment
    );
    let (code, body) = forward(&address, "GET", &uri, &[]);
    assert_eq!(code, 200);
    let target: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        target["spec"]["template"]["spec"]["containers"][0]["name"],
        "api"
    );
    let authorization = ExactAuthorization {
        authorization_id: if replacement {
            "replacement"
        } else {
            &request.operation_id
        }
        .into(),
        operation_id: request.operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
        approved_target: Some(ApprovedTarget {
            uid: target["metadata"]["uid"].as_str().unwrap().into(),
            resource_version: target["metadata"]["resourceVersion"]
                .as_str()
                .unwrap()
                .into(),
        }),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &[41; 32],
        signing_key_id: "prototype-authority",
    })
    .unwrap();
    let name = if replacement {
        "replacement.grant".into()
    } else {
        format!("{index}.grant")
    };
    private_write(&root.join(name), &grant);
}

async fn checkpoint(root: &Path, seam: &str) {
    if fs::read_to_string(root.join("pause")).is_ok_and(|value| value == seam) {
        private_write(&root.join("paused"), seam.as_bytes());
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.join("continue").exists() {
            assert!(Instant::now() < deadline, "prototype checkpoint timed out");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

fn application(root: &Path, index: usize) -> Application {
    let (service, mut handle) =
        mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
    let address = fs::read_to_string(root.join("receiver")).unwrap();
    let control = root.to_owned();
    tokio::spawn(async move {
        while let Some((request, send)) = handle.next_request().await {
            let method = request.method().to_string();
            let uri = request.uri().path_and_query().unwrap().to_string();
            let body = request.into_body().collect().await.unwrap().to_bytes();
            assert!(body.len() <= 4096);
            if method == "GET" {
                checkpoint(&control, "authorized").await;
            }
            if method == "PATCH" {
                checkpoint(&control, "before-http").await;
            }
            let is_patch = method == "PATCH";
            let address = address.clone();
            let (code, bytes) =
                tokio::task::spawn_blocking(move || forward(&address, &method, &uri, &body))
                    .await
                    .unwrap();
            if is_patch {
                checkpoint(&control, "after-http").await;
            }
            send.send_response(
                http::Response::builder()
                    .status(code)
                    .body(kube::client::Body::from(bytes))
                    .unwrap(),
            );
        }
    });
    Application::open(OperatorConfiguration {
        journal_path: root.join("journal.sqlite3"),
        receipt_output_directory: None,
        authorization_trust: AuthorizationTrust {
            key_id: "prototype-authority".into(),
            public_key: SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
        },
        signed_authorization_grant: fs::read(root.join(format!("{index}.grant"))).unwrap(),
        kubernetes_client: kube::Client::new(service, "demo"),
        receipt_signing_seed: [42; 32],
        receipt_signing_key_id: "prototype-receipt".into(),
    })
    .unwrap()
}

fn status(application: &Application, identity: &str) -> Value {
    let Ok(status) = application.read_set_deployment_image_status(identity) else {
        return json!({"error": "operation_failure"});
    };
    match status {
        SetDeploymentImageStatus::NotFound => json!({"status": "NOT_FOUND"}),
        SetDeploymentImageStatus::InProgress => json!({"status": "IN_PROGRESS"}),
        SetDeploymentImageStatus::NotAttempted(reason) => {
            json!({"status": "NOT_ATTEMPTED", "target_rejection": format!("{reason:?}")})
        },
        SetDeploymentImageStatus::Succeeded => json!({"status": "SUCCEEDED"}),
        SetDeploymentImageStatus::Failed => json!({"status": "FAILED"}),
        SetDeploymentImageStatus::Unknown => json!({"status": "UNKNOWN"}),
    }
}

fn receipt(application: &Application, identity: &str) -> Value {
    match application.read_set_deployment_image_receipt(identity) {
        Ok(SetDeploymentImageReceipt::NotFound) => json!({"status": "NOT_FOUND"}),
        Ok(SetDeploymentImageReceipt::NotReady) => json!({"status": "NOT_READY"}),
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 }) => {
            let mut hex = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            json!({"status": "READY", "receipt_hex": hex, "receipt_sha256": sha256})
        },
        Err(_) => json!({"error": "operation_failure"}),
    }
}

fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Option<Command> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).ok()?;
    let length = u32::from_be_bytes(prefix) as usize;
    if !(1..=4096).contains(&length) {
        return None;
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).ok()?;
    if stream.read(&mut [0; 1]).ok()? != 0 {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

type Execution = tokio::task::JoinHandle<(usize, Application)>;

struct Endpoint {
    root: PathBuf,
    requests: [AgentRequest; 2],
    executions: [Option<Application>; 2],
    reads: [Application; 2],
    running: Option<Execution>,
}

impl Endpoint {
    fn open(root: PathBuf) -> Self {
        let requests = requests(&root);
        assert_ne!(requests[0].operation_id, requests[1].operation_id);
        let executions = [Some(application(&root, 0)), Some(application(&root, 1))];
        let reads = [application(&root, 0), application(&root, 1)];
        for index in 0..2 {
            assert!(reads[index].request_matches_authorized_grant(&requests[index]));
        }
        Self {
            root,
            requests,
            executions,
            reads,
            running: None,
        }
    }

    async fn collect_finished(&mut self) {
        if self
            .running
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            let (index, application) = self.running.take().unwrap().await.unwrap();
            self.executions[index] = Some(application);
        }
    }

    fn respond(&mut self, command: Option<Command>) -> Value {
        let Some(command) = command else {
            return json!({"error": "invalid_request"});
        };
        let Some(index) = self
            .requests
            .iter()
            .position(|request| request.operation_id == command.identity())
        else {
            return json!({"error": "unknown_identity"});
        };
        match command {
            Command::Status { operation_id } => status(&self.reads[index], &operation_id),
            Command::Receipt { operation_id } => receipt(&self.reads[index], &operation_id),
            Command::Select { .. } if self.running.is_some() => json!({"status": "BUSY"}),
            Command::Select { .. } => {
                let mut application = self.executions[index].take().unwrap();
                let request = self.requests[index].clone();
                let control = self.root.clone();
                self.running = Some(tokio::spawn(async move {
                    checkpoint(&control, "accepted").await;
                    let result = application.execute(&request).await;
                    private_write(
                        &control.join("execution-result"),
                        if result.is_ok() {
                            b"completed"
                        } else {
                            b"operation_failure"
                        },
                    );
                    (index, application)
                }));
                json!({"status": "ACCEPTED"})
            },
        }
    }
}

async fn serve(root: PathBuf) {
    let mut endpoint = Endpoint::open(root.clone());
    // No startup reconciliation or selected-ID store: all advancement requires caller selection.
    let socket = root.join("endpoint.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    private_write(&root.join("ready"), b"ready");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        endpoint.collect_finished().await;
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(2)).await;
                continue;
            },
            Err(error) => panic!("prototype accept failed: {error}"),
        };
        let response = endpoint.respond(read_frame(&mut stream));
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(bytes.len() <= 40 * 1024);
        let _ = stream.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        let _ = stream.write_all(&bytes);
    }
    panic!("prototype endpoint exceeded its bounded run");
}

#[test]
#[ignore = "operator/caller workflow is scripts/prototype-two-actions.py"]
fn two_action_endpoint_child() {
    let root = fs::canonicalize(std::env::var("PROTOTYPE_ROOT").unwrap()).unwrap();
    let mode = std::env::var("PROTOTYPE_MODE").unwrap();
    match mode.as_str() {
        "approve-a" => approve(&root, 0, false),
        "approve-b" => approve(&root, 1, false),
        "replacement-a" => approve(&root, 0, true),
        "serve" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve(root)),
        _ => panic!("invalid operator-only prototype mode"),
    }
}
