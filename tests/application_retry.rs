//! Configured HTTP composition: exact requests and disabled mutation retries, not lifecycle laws.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "bounded, maintainer-owned loopback fixtures fail the test on invalid evidence"
)]

#[path = "application_retry/service_selection.rs"]
mod service_selection;

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use kapsel::{
    provision_exact_grant, AgentRequest, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperationReceipt, OperationStatus, ServiceApplication, ServiceApproval,
    ServiceConfiguration, ServiceExecution,
};
use serde_json::{json, Value};

const IMAGE: &str = concat!(
    "example/api@sha256:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);

#[derive(Clone, Debug, PartialEq)]
struct WireRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct Fixture {
    root: PathBuf,
    kubeconfig: Vec<u8>,
    stop: mpsc::Sender<()>,
    server: Option<thread::JoinHandle<Vec<WireRequest>>>,
}

impl Fixture {
    fn new(status: u16) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "kapsel-application-retry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        // Refuse a collision. Never erase another run's retained evidence to make a test pass.
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped) = mpsc::channel();
        let server = thread::spawn(move || serve(&listener, &stopped, status));
        let kubeconfig = format!(
            concat!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                "  cluster:\n    server: http://{address}\ncontexts:\n- name: fixture\n",
                "  context:\n    cluster: fixture\n    user: fixture\n",
                "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
            ),
            address = address
        )
        .into_bytes();
        Self {
            root,
            kubeconfig,
            stop,
            server: Some(server),
        }
    }

    fn application(&self) -> ServiceApplication {
        let request = request();
        let seed = [41; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &ExactAuthorization {
                authorization_id: "retry-approval".into(),
                operation_id: request.operation_id,
                namespace: request.namespace,
                deployment: request.deployment,
                container: request.container,
                immutable_image_digest: request.immutable_image_digest,
                approved_target: Some(ApprovedTarget {
                    uid: "uid-1".into(),
                    resource_version: "1".into(),
                }),
            },
            signing_seed: &seed,
            signing_key_id: "retry-authority",
        })
        .unwrap();
        ServiceApplication::open(ServiceConfiguration {
            journal_path: self.root.join("journal.sqlite3"),
            authorization_trust: vec![AuthorizationTrust {
                key_id: "retry-authority".into(),
                public_key,
            }],
            approvals: vec![ServiceApproval {
                label: "Retry fixture".into(),
                signed_grant: grant,
            }],
        })
        .unwrap()
    }

    fn execution(&self) -> impl std::future::Future<Output = ServiceExecution> + Send + '_ {
        ServiceExecution::from_operator_snapshots(
            Some(&self.kubeconfig),
            Some(&[42; 32]),
            "retry-receipt",
        )
    }

    fn finish(&mut self) -> Vec<WireRequest> {
        self.stop.send(()).unwrap();
        self.server.take().unwrap().join().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn request() -> AgentRequest {
    AgentRequest {
        operation_id: "retry-op".into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    }
}

fn deployment(changed: bool) -> Value {
    let generation = if changed { 2 } else { 1 };
    json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {
            "name": "api", "namespace": "demo", "uid": "uid-1",
            "resourceVersion": if changed { "2" } else { "1" }, "generation": generation,
            "annotations": {
                "kapsel.dev/kap0038-operation-id": if changed { "retry-op" } else { "" }
            }
        },
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "api"}},
            "template": {"spec": {"containers": [{"name": "api", "image":
                if changed { IMAGE } else { "example/api:old" }}]}}},
        "status": {"observedGeneration": generation, "updatedReplicas": 1,
            "availableReplicas": 1, "unavailableReplicas": 0,
            "conditions": [{"type": "Available", "status": "True",
                "reason": "MinimumReplicasAvailable"}]}
    })
}

fn serve(listener: &TcpListener, stopped: &mpsc::Receiver<()>, status: u16) -> Vec<WireRequest> {
    let mut requests = Vec::new();
    let mut patch_count = 0;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stopped.try_recv().is_ok() {
                    return requests;
                }
                assert!(Instant::now() < deadline, "loopback receiver timed out");
                thread::sleep(Duration::from_millis(1));
                continue;
            },
            Err(error) => panic!("receiver accept: {error}"),
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = read_request(&mut stream);
        let code = match request.method.as_str() {
            "GET" => 200,
            "PATCH" => {
                patch_count += 1;
                // The first request acts, but its response is ambiguous. A repeated stale request
                // conflicts. Count it anyway: absence of a second stored change is not no-replay.
                if patch_count == 1 {
                    status
                } else {
                    409
                }
            },
            method => panic!("unexpected method: {method}"),
        };
        requests.push(request);
        assert!(requests.len() <= 8, "unbounded client requests");
        if code == 0 {
            // Complete request received, response connection lost.
            continue;
        }
        let body = if code == 200 {
            deployment(patch_count > 0)
        } else {
            json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "FixtureAmbiguity", "code": code})
        };
        let body = serde_json::to_vec(&body).unwrap();
        write!(
            stream,
            concat!(
                "HTTP/1.1 {code} Fixture\r\ncontent-type: application/json\r\n",
                "content-length: {}\r\nconnection: close\r\n\r\n"
            ),
            body.len(),
            code = code
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    }
}

fn read_request(stream: &mut TcpStream) -> WireRequest {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let count = match stream.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.unwrap(),
        };
        assert!(count > 0, "incomplete request");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 16 * 1024);
        let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = std::str::from_utf8(&bytes[..body_start]).unwrap();
        let body_bytes = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, length)| length.trim().parse::<usize>().unwrap());
        assert!(body_bytes <= 16 * 1024);
        if bytes.len() >= body_start + body_bytes {
            assert_eq!(bytes.len(), body_start + body_bytes);
            return WireRequest {
                method: headers.split_ascii_whitespace().next().unwrap().into(),
                path: headers.split_ascii_whitespace().nth(1).unwrap().into(),
                body: bytes[body_start..].to_vec(),
            };
        }
    }
}

#[tokio::test]
async fn configured_client_sends_once_for_success_and_ambiguous_responses() {
    let mut counts = Vec::new();
    for status in [200, 429, 503, 504, 0] {
        let mut fixture = Fixture::new(status);
        let mut application = fixture.application();
        let stop = application
            .select("retry-op", fixture.execution().await, |_| {})
            .await
            .unwrap();
        let expected = if status == 200 {
            kapsel::ServiceStop::Finished
        } else {
            kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::ReceiverUnavailable)
        };
        assert_eq!(stop, expected);
        drop(application);

        let requests = fixture.finish();
        let patches: Vec<_> = requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .collect();
        for patch in &patches {
            let body: Value = serde_json::from_slice(&patch.body).unwrap();
            assert_eq!(body["metadata"]["uid"], "uid-1");
            assert_eq!(body["metadata"]["resourceVersion"], "1");
            assert_eq!(
                body["spec"]["template"]["spec"]["containers"][0]["image"],
                IMAGE
            );
        }
        counts.push((status, patches.len()));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "GET")
                .count(),
            if status == 200 { 2 } else { 1 }
        );
    }
    assert_eq!(counts, [(200, 1), (429, 1), (503, 1), (504, 1), (0, 1)]);
}
