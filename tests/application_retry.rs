//! Count real HTTP requests beneath the operator-document application path, including recovery.

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
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use kapsel::{
    provision_exact_grant, AgentRequest, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperationState, ServiceApplication, ServiceApproval, ServiceConfiguration,
    ServiceExecution, SetDeploymentImageReceipt, SetDeploymentImageStatus,
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
    paused: mpsc::Receiver<()>,
    resume: mpsc::Sender<()>,
}

impl Fixture {
    fn new(status: u16) -> Self {
        Self::with_pause(status, false)
    }

    fn with_pause(status: u16, pause_first_patch: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kapsel-application-retry-{}-{status}-{pause_first_patch}",
            std::process::id()
        ));
        // Refuse a collision. Never erase another run's retained evidence to make a test pass.
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped) = mpsc::channel();
        let (pause, paused) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let server = thread::spawn(move || {
            let hold = pause_first_patch.then_some((pause, resumed));
            serve(&listener, &stopped, status, hold)
        });
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
            paused,
            resume,
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
        let _ = self.resume.send(());
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

fn serve(
    listener: &TcpListener,
    stopped: &mpsc::Receiver<()>,
    status: u16,
    mut hold: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
) -> Vec<WireRequest> {
    let mut requests = Vec::new();
    let mut patches = 0;
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
                patches += 1;
                // The first request acts, but its response is ambiguous. A repeated stale request
                // conflicts. Count it anyway: absence of a second stored change is not no-replay.
                if patches == 1 {
                    status
                } else {
                    409
                }
            },
            method => panic!("unexpected method: {method}"),
        };
        requests.push(request);
        if patches == 1 {
            if let Some((pause, resumed)) = hold.take() {
                pause.send(()).unwrap();
                resumed.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        }
        assert!(requests.len() <= 8, "unbounded client requests");
        if code == 0 {
            // Complete request received, response connection lost.
            continue;
        }
        let body = if code == 200 {
            deployment(patches > 0)
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
        let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let end = end + 4;
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, length)| length.trim().parse::<usize>().unwrap());
        assert!(length <= 16 * 1024);
        if bytes.len() >= end + length {
            assert_eq!(bytes.len(), end + length);
            return WireRequest {
                method: headers.split_ascii_whitespace().next().unwrap().into(),
                path: headers.split_ascii_whitespace().nth(1).unwrap().into(),
                body: bytes[end..].to_vec(),
            };
        }
    }
}

#[tokio::test]
async fn healthy_dispatch_and_restart_preserve_one_http_request_and_original_receipt() {
    let mut fixture = Fixture::new(200);
    let mut application = fixture.application();
    assert_eq!(application.admitted_state("retry-op").unwrap(), None);
    application
        .select("retry-op", fixture.execution().await, |_| {})
        .await
        .unwrap();
    assert_eq!(
        application.status("retry-op").unwrap().0,
        SetDeploymentImageStatus::Succeeded
    );
    let original = application.receipt("retry-op").unwrap();
    let report = application.status("retry-op").unwrap();
    drop(application);
    let mut application = fixture.application();
    assert_eq!(application.status("retry-op").unwrap(), report);
    application
        .select("retry-op", fixture.execution().await, |_| {})
        .await
        .unwrap();
    assert_eq!(application.status("retry-op").unwrap(), report);
    assert_eq!(application.receipt("retry-op").unwrap(), original);
    drop(application);
    let requests = fixture.finish();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2
    );
}

#[tokio::test]
async fn cancelled_application_dispatch_recovers_without_resending_to_available_receiver() {
    let mut fixture = Fixture::with_pause(0, true);
    let mut application = fixture.application();
    let mut execution = Box::pin(application.select("retry-op", fixture.execution().await, |_| {}));
    tokio::select! {
        result = &mut execution => panic!("response must still be pending: {result:?}"),
        () = async {
            let deadline = Instant::now() + Duration::from_secs(5);
            while fixture.paused.try_recv().is_err() {
                assert!(Instant::now() < deadline, "PATCH not received");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        } => {}
    }
    // The original worker still owns exclusion while its PATCH response is pending.
    let mut contender = fixture.application();
    contender
        .select("retry-op", fixture.execution().await, |decision| {
            assert_eq!(
                decision,
                kapsel::ServiceAdmission::Admitted(OperationState::ApplyStarted)
            );
        })
        .await
        .unwrap();
    assert_eq!(
        contender.admitted_state("retry-op").unwrap(),
        Some(OperationState::ApplyStarted)
    );
    drop(contender);
    drop(execution);
    drop(application);
    fixture.resume.send(()).unwrap();
    let mut application = fixture.application();
    application
        .select("retry-op", fixture.execution().await, |_| {})
        .await
        .unwrap();
    assert_eq!(
        application.status("retry-op").unwrap().0,
        SetDeploymentImageStatus::Succeeded
    );
    let original = application.receipt("retry-op").unwrap();
    let report = application.status("retry-op").unwrap();
    application
        .select("retry-op", fixture.execution().await, |_| {})
        .await
        .unwrap();
    assert_eq!(application.status("retry-op").unwrap(), report);
    assert_eq!(application.receipt("retry-op").unwrap(), original);
    drop(application);
    let requests = fixture.finish();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PATCH")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2
    );
}

#[tokio::test]
async fn ambiguous_patch_responses_never_trigger_hidden_client_retries() {
    let mut counts = Vec::new();
    for status in [429, 503, 504, 0] {
        let mut fixture = Fixture::new(status);
        let mut application = fixture.application();
        assert_eq!(
            application
                .select("retry-op", fixture.execution().await, |_| {})
                .await
                .unwrap(),
            kapsel::ServiceStop::Blocked(kapsel::ExecutionCondition::ReceiverUnavailable)
        );
        drop(application);
        let mut application = fixture.application();
        application
            .select("retry-op", fixture.execution().await, |_| {})
            .await
            .unwrap();
        assert_eq!(
            application.admitted_state("retry-op").unwrap(),
            Some(OperationState::Finalized)
        );
        let report = application.status("retry-op").unwrap();
        assert_eq!(report.0, SetDeploymentImageStatus::Succeeded);
        assert_eq!(report.1.attempt_target, report.1.approved_target);
        let original = application.receipt("retry-op").unwrap();
        assert!(matches!(original, SetDeploymentImageReceipt::Ready { .. }));
        application
            .select("retry-op", fixture.execution().await, |_| {})
            .await
            .unwrap();
        assert_eq!(application.status("retry-op").unwrap(), report);
        assert_eq!(application.receipt("retry-op").unwrap(), original);
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
            2
        );
    }
    assert_eq!(counts, [(429, 1), (503, 1), (504, 1), (0, 1)]);
}
