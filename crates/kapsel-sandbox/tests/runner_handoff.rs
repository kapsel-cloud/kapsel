//! Real-process proof for the fixed private runner handoff.

#![allow(
    clippy::panic,
    clippy::similar_names,
    clippy::unwrap_used,
    clippy::zombie_processes,
    reason = "fixture failures stop the test; returned children are killed and waited by the owner"
)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use http::StatusCode;
use kapsel::{
    inspect_receipt, provision_exact_grant, AgentRequest, Application, AuthorizationTrust,
    ExactAuthorization, GrantProvisioning, InspectionLimits, InspectionStatus, OperationResult,
    OperationState, OperatorConfiguration, ReceiptTrust, TargetRejection,
};
use kapsel_sandbox::{
    run_application_handoff, AuthorityConfiguration, AuthorityController, ControllerConfiguration,
    ControllerRole, DispatchLease, ExecutionState, Scenario, Service,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use sha2::{Digest, Sha256};
use tower_test::mock;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[derive(serde::Serialize)]
struct TestManifest {
    version: u8,
    generation: u64,
    previous_generation: Option<u64>,
    files: Vec<TestManifestFile>,
}

#[derive(serde::Serialize)]
struct TestManifestFile {
    name: String,
    length: u64,
    sha256: String,
}

#[derive(serde::Serialize)]
struct TestCurrentRecord {
    version: u8,
    generation: u64,
    manifest_digest: String,
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn authority_payloads(
    handoff_endpoint: SocketAddr,
    kubernetes_endpoint: SocketAddr,
) -> Vec<(&'static str, Vec<u8>)> {
    let receipt_key = SigningKey::from_bytes(&[42_u8; 32]);
    vec![
        ("authorization-signing-seed", vec![41_u8; 32]),
        (
            "authorization-signing-key-id",
            b"sandbox-authorization-key".to_vec(),
        ),
        ("receipt-signing-seed", vec![42_u8; 32]),
        ("receipt-signing-key-id", b"sandbox-receipt-key".to_vec()),
        ("tombstone-digest-key", vec![7_u8; 32]),
        (
            "runner-kubernetes-api-server",
            format!("https://{kubernetes_endpoint}").into_bytes(),
        ),
        (
            "runner-kubernetes-ca.pem",
            include_bytes!("fixtures/localhost-ca.pem").to_vec(),
        ),
        ("runner-kubernetes-token", b"runner-token".to_vec()),
        (
            "cleanup-kubernetes-api-server",
            format!("https://{kubernetes_endpoint}").into_bytes(),
        ),
        (
            "cleanup-kubernetes-ca.pem",
            include_bytes!("fixtures/localhost-ca.pem").to_vec(),
        ),
        ("cleanup-kubernetes-token", b"cleanup-token".to_vec()),
        (
            "handoff-endpoint",
            handoff_endpoint.to_string().into_bytes(),
        ),
        (
            "public-receipt-trust.json",
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "key_id": "sandbox-receipt-key",
                "public_key_hex": lower_hex(&receipt_key.verifying_key().to_bytes()),
                "accepted_purpose": "kapsel.kap0038.kubernetes-effect-receipt.v2",
                "not_before_unix_s": 1,
                "not_after_unix_s": 4_102_444_800_i64,
            }))
            .unwrap(),
        ),
    ]
}

fn test_manifest(
    handoff_endpoint: SocketAddr,
    kubernetes_endpoint: SocketAddr,
) -> (Vec<u8>, String) {
    let payloads = authority_payloads(handoff_endpoint, kubernetes_endpoint);
    let manifest = serde_json::to_vec(&TestManifest {
        version: 1,
        generation: 1,
        previous_generation: None,
        files: payloads
            .iter()
            .map(|(name, payload)| TestManifestFile {
                name: (*name).to_owned(),
                length: u64::try_from(payload.len()).unwrap(),
                sha256: lower_hex(&Sha256::digest(payload)),
            })
            .collect(),
    })
    .unwrap();
    let digest = lower_hex(&Sha256::digest(&manifest));
    (manifest, digest)
}

fn distinct_test_identity(current: u32) -> u32 {
    if current == 65_532 {
        65_531
    } else {
        65_532
    }
}

fn fixed_authority_root(
    root: &Path,
    handoff_endpoint: SocketAddr,
    kubernetes_endpoint: SocketAddr,
) -> PathBuf {
    let authority = root.join("fixed-authority");
    if authority.exists() {
        return authority;
    }
    private_directory(&authority);
    private_directory(&authority.join("incoming"));
    private_directory(&authority.join("generations"));
    private_directory(&authority.join("dispatch"));
    let generation = authority
        .join("generations")
        .join("generation-00000000000000000001");
    private_directory(&generation);
    for (name, payload) in authority_payloads(handoff_endpoint, kubernetes_endpoint) {
        fs::write(generation.join(name), payload).unwrap();
        fs::set_permissions(generation.join(name), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let (manifest, digest) = test_manifest(handoff_endpoint, kubernetes_endpoint);
    fs::write(generation.join("manifest.json"), manifest).unwrap();
    fs::set_permissions(
        generation.join("manifest.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o500)).unwrap();
    let current = serde_json::to_vec(&TestCurrentRecord {
        version: 1,
        generation: 1,
        manifest_digest: digest,
    })
    .unwrap();
    fs::write(authority.join("current"), current).unwrap();
    fs::set_permissions(authority.join("current"), fs::Permissions::from_mode(0o400)).unwrap();
    authority
}

const IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
);
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn remove_fixture_root(path: impl AsRef<Path>) {
    let path = path.as_ref();
    let generation = path.join("fixed-authority/generations/generation-00000000000000000001");
    if generation.exists() {
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::remove_dir_all(path).unwrap();
}

fn fixture(
    handoff_endpoint: SocketAddr,
    kubernetes_endpoint: SocketAddr,
) -> (PathBuf, Service, AuthorityController) {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-runner-handoff-process-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    if root.exists() {
        remove_fixture_root(&root);
    }
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    private_directory(&root.join("receipts"));
    let authority_root = fixed_authority_root(&root, handoff_endpoint, kubernetes_endpoint);
    let controller_uid = rustix::process::geteuid().as_raw();
    let controller_gid = rustix::process::getegid().as_raw();
    let staging_uid = if controller_uid == 65_532 {
        65_531
    } else {
        65_532
    };
    let staging_gid = if controller_gid == 65_532 {
        65_531
    } else {
        65_532
    };
    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        &AuthorityConfiguration::new(
            authority_root,
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
        ),
        now(),
    )
    .unwrap();
    let authority = AuthorityController::new(service.clone());
    (root, service, authority)
}

fn verify_target(service: &Service, lease: &DispatchLease, at: i64) {
    let specification = service.provisioning_specification(lease, at).unwrap();
    let (boundary, behavior_records) = Service::cluster_boundary_specification().unwrap();
    let boundary = kapsel_sandbox::ClusterBoundaryObservation {
        objects: boundary
            .into_iter()
            .enumerate()
            .map(|(index, object)| {
                let mut body = object.canonical_body;
                body["metadata"]["uid"] = serde_json::json!(format!("boundary-{index}"));
                body["metadata"]["resourceVersion"] = serde_json::json!("17");
                kapsel_sandbox::ObservedPolicyObject { body }
            })
            .collect(),
        behavior_records,
    };
    let run_objects = specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let mut body = object.canonical_body.clone();
            body["metadata"]["uid"] = serde_json::json!(if index == 0 {
                "handoff-namespace-uid".into()
            } else {
                format!("handoff-object-{index}")
            });
            body["metadata"]["resourceVersion"] = serde_json::json!("17");
            kapsel_sandbox::ObservedPolicyObject { body }
        })
        .collect();
    service
        .verify_observed_cluster(
            lease,
            &kapsel_sandbox::ObservedClusterComposition {
                boundary,
                run_objects,
                generated_children: Vec::new(),
                owned_orphans: Vec::new(),
            },
            at,
        )
        .unwrap();
}

fn application(
    root: &Path,
    run_id: &str,
) -> (
    Application,
    AgentRequest,
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
) {
    let request = AgentRequest {
        operation_id: format!("sandbox-{run_id}"),
        namespace: format!("sandbox-{run_id}"),
        deployment: "sandbox-target".into(),
        container: "target".into(),
        immutable_image_digest: concat!(
            "registry.k8s.io/pause@sha256:",
            "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
        )
        .into(),
    };
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &ExactAuthorization {
            authorization_id: format!("auth-{run_id}"),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        },
        signing_seed: &authorization_seed,
        signing_key_id: "sandbox-authorization-key",
    })
    .unwrap();
    let gateway = root.join(run_id);
    private_directory(&gateway);
    private_directory(&gateway.join("receipt-outbox"));
    let (transport, handle) = mock::pair();
    let application = Application::open(OperatorConfiguration {
        journal_path: fs::canonicalize(&gateway).unwrap().join("gateway.sqlite3"),
        receipt_output_directory: fs::canonicalize(gateway.join("receipt-outbox")).unwrap(),
        authorization_trust: AuthorizationTrust {
            key_id: "sandbox-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        },
        signed_authorization_grant: grant,
        kubernetes_client: kube::Client::new(transport, "sandbox"),
        receipt_signing_seed: [42; 32],
        receipt_signing_key_id: "sandbox-receipt-key".into(),
    })
    .unwrap();
    (application, request, handle)
}

fn start_handoff(root: &Path, address: std::net::SocketAddr) -> Child {
    let controller_uid = rustix::process::geteuid().as_raw();
    let controller_gid = rustix::process::getegid().as_raw();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"));
    command.args([
        "handoff-serve",
        "--database",
        root.join("sandbox.sqlite3").to_str().unwrap(),
        "--receipts",
        root.join("receipts").to_str().unwrap(),
        "--listen",
        &address.to_string(),
        "--authority-root",
        root.join("fixed-authority").to_str().unwrap(),
        "--controller-uid",
        &controller_uid.to_string(),
        "--controller-gid",
        &controller_gid.to_string(),
        "--staging-uid",
        &distinct_test_identity(controller_uid).to_string(),
        "--staging-gid",
        &distinct_test_identity(controller_gid).to_string(),
    ]);
    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..500 {
        if TcpStream::connect(address).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("private handoff process did not listen")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeOutcome {
    NotAttempted,
    Succeeded,
    Unknown,
}

#[allow(
    clippy::if_not_else,
    reason = "the three finalized outcomes share the long deployment response sequence"
)]
fn start_kubernetes_fixture(
    listener: TcpListener,
    outcome: NativeOutcome,
    run_id: &str,
) -> thread::JoinHandle<()> {
    let operation_id = format!("sandbox-{run_id}");
    let responses = if outcome != NativeOutcome::NotAttempted {
        let old_image = concat!(
            "registry.k8s.io/pause@sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        vec![
            serde_json::json!({
                "apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                    "template": {"metadata": {"labels": {"app": "sandbox"}},
                        "spec": {"containers": [{"name": "target", "image": old_image}]}}},
                "status": {"observedGeneration": 1}
            })
            .to_string(),
            serde_json::json!({
                "apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                    "template": {"metadata": {"labels": {"app": "sandbox"}},
                        "spec": {"containers": [{"name": "target", "image": IMAGE}]}}}
            })
            .to_string(),
            serde_json::json!({
                "apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"uid": if outcome == NativeOutcome::Unknown {
                        "replacement-deployment-uid"
                    } else {
                        "deployment-uid"
                    }, "resourceVersion": "3", "generation": 2,
                    "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                    "template": {"metadata": {"labels": {"app": "sandbox"}},
                        "spec": {"containers": [{"name": "target", "image": IMAGE}]}}},
                "status": {"observedGeneration": 2, "updatedReplicas": 1,
                    "availableReplicas": 1, "unavailableReplicas": 0,
                    "conditions": [{"type": "Available", "status": "True",
                        "reason": "MinimumReplicasAvailable"}]}
            })
            .to_string(),
        ]
    } else {
        vec![serde_json::json!({
            "apiVersion": "v1", "kind": "Status", "status": "Failure",
            "reason": "NotFound", "code": 404
        })
        .to_string()]
    };
    let server = thread::spawn(move || {
        for body in responses {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = tls_server_stream(stream);
            let mut request = [0_u8; 16 * 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            let status = if outcome == NativeOutcome::NotAttempted {
                "404 Not Found"
            } else {
                "200 OK"
            };
            write!(
                stream,
                concat!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\n",
                    "content-length: {}\r\nconnection: close\r\n\r\n"
                ),
                status,
                body.len()
            )
            .unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        }
    });
    server
}

struct PreparedProcessFixture {
    root: PathBuf,
    service: Service,
    run_id: String,
    launch_at: i64,
    handoff_address: SocketAddr,
}

#[allow(
    clippy::too_many_lines,
    reason = "the production process fixture materializes every exact projected runner input"
)]
fn prepare_process_fixture(
    kubernetes_address: SocketAddr,
    idempotency_digit: char,
) -> PreparedProcessFixture {
    let handoff_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let handoff_address = handoff_probe.local_addr().unwrap();
    drop(handoff_probe);
    let (root, service, authority) = fixture(handoff_address, kubernetes_address);
    let at = now();
    let admission = service
        .admit(
            &idempotency_digit.to_string().repeat(32),
            Scenario::Healthy,
            at,
        )
        .unwrap();
    let lease = authority.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    PreparedProcessFixture {
        root,
        service,
        run_id: admission.run_id,
        launch_at: at + 31,
        handoff_address,
    }
}

fn fixed_controller_role(root: &Path, service: &Service) -> ControllerRole {
    let generations = root.join("runner-generations");
    private_directory(&generations);
    let controller_uid = rustix::process::getuid().as_raw();
    let controller_gid = rustix::process::getgid().as_raw();
    #[cfg(target_os = "linux")]
    let (runner_uid, runner_gid) = (65_532, 65_532);
    #[cfg(not(target_os = "linux"))]
    let (runner_uid, runner_gid) = (controller_uid, controller_gid);
    ControllerRole::new(
        service.clone(),
        ControllerConfiguration::new(generations, runner_uid, runner_gid),
    )
}

fn reopened_controller_role(fixture: &PreparedProcessFixture) -> ControllerRole {
    let controller_uid = rustix::process::getuid().as_raw();
    let controller_gid = rustix::process::getgid().as_raw();
    #[cfg(target_os = "linux")]
    let (runner_uid, runner_gid) = (65_532, 65_532);
    #[cfg(not(target_os = "linux"))]
    let (runner_uid, runner_gid) = (controller_uid, controller_gid);
    ControllerRole::new(
        fixture.service.clone(),
        ControllerConfiguration::new(
            fixture.root.join("runner-generations"),
            runner_uid,
            runner_gid,
        ),
    )
}

fn launch_after_lease_expiry(controller: &mut ControllerRole, now_unix_s: i64) -> u64 {
    let Some(run) = controller.run_once(now_unix_s).unwrap() else {
        panic!("expired scheduler lease must recover into a production launch");
    };
    run.generation()
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the snapshot preserves independent durable retirement facts for exact comparison"
)]
struct RetirementSnapshot {
    lease_epoch: i64,
    operation_id: String,
    application_invoked: bool,
    report_count: i64,
    runner_revoked: bool,
    process_absent: bool,
    journal_handoff: bool,
    retiring: bool,
    retired: bool,
    verifier_bytes: i64,
}

#[cfg(target_os = "linux")]
fn retirement_snapshot(database: &Path, run_id: &str) -> RetirementSnapshot {
    rusqlite::Connection::open(database)
        .unwrap()
        .query_row(
            concat!(
                "SELECT lease_epoch, operation_id, application_invoked, ",
                "(SELECT COUNT(*) FROM application_reports WHERE run_id = ?1), ",
                "runner_revoked, runner_process_absent, journal_handoff, ",
                "runner_state_retiring, runner_state_retired, ",
                "length(handoff_credential_verifier) FROM runs WHERE run_id = ?1"
            ),
            [run_id],
            |row| {
                Ok(RetirementSnapshot {
                    lease_epoch: row.get(0)?,
                    operation_id: row.get(1)?,
                    application_invoked: row.get(2)?,
                    report_count: row.get(3)?,
                    runner_revoked: row.get(4)?,
                    process_absent: row.get(5)?,
                    journal_handoff: row.get(6)?,
                    retiring: row.get(7)?,
                    retired: row.get(8)?,
                    verifier_bytes: row.get(9)?,
                })
            },
        )
        .unwrap()
}

fn wait_for_database_value(path: &Path, query: &str, expected: &str) {
    for _ in 0..1_000 {
        if rusqlite::Connection::open(path)
            .and_then(|connection| connection.query_row(query, [], |row| row.get::<_, String>(0)))
            .is_ok_and(|value| value == expected)
        {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("database coordination value did not reach {expected}");
}

fn success_bodies(run_id: &str) -> [String; 3] {
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    [
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        })
        .to_string(),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": IMAGE}]}}}
        })
        .to_string(),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": format!("sandbox-{run_id}")}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": IMAGE}]}}},
            "status": {"observedGeneration": 2, "updatedReplicas": 1,
                "availableReplicas": 1, "unavailableReplicas": 0,
                "conditions": [{"type": "Available", "status": "True",
                    "reason": "MinimumReplicasAvailable"}]}
        })
        .to_string(),
    ]
}

fn tls_server_stream(stream: TcpStream) -> StreamOwned<ServerConnection, TcpStream> {
    let certificate = CertificateDer::from(include_bytes!("fixtures/localhost-cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/localhost-key.der").to_vec(),
    ));
    let configuration = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    StreamOwned::new(
        ServerConnection::new(Arc::new(configuration)).unwrap(),
        stream,
    )
}

fn read_fixture_request(stream: &mut impl Read) {
    let mut request = [0_u8; 16 * 1024];
    assert!(stream.read(&mut request).unwrap() > 0);
}

fn write_fixture_response(stream: &mut impl Write, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
            "content-length: {}\r\nconnection: close\r\n\r\n"
        ),
        body.len()
    )?;
    stream.write_all(body.as_bytes())
}

fn serve_success(listener: TcpListener, run_id: &str) -> thread::JoinHandle<()> {
    let bodies = success_bodies(run_id);
    thread::spawn(move || {
        for body in bodies {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = tls_server_stream(stream);
            read_fixture_request(&mut stream);
            write_fixture_response(&mut stream, &body).unwrap();
        }
    })
}

#[allow(
    clippy::if_not_else,
    clippy::too_many_lines,
    reason = "one native fixture locks projected inputs, empty state, both processes, and ownership"
)]
fn run_native_runner_case(outcome: NativeOutcome) {
    #[cfg(target_os = "linux")]
    if !rustix::process::geteuid().is_root() {
        return;
    }
    let handoff_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let handoff_address = handoff_probe.local_addr().unwrap();
    drop(handoff_probe);
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let kubernetes_address = kubernetes_listener.local_addr().unwrap();
    let (root, service, authority) = fixture(handoff_address, kubernetes_address);
    let at = now();
    let admission = service
        .admit(
            &format!(
                "{:032x}",
                match outcome {
                    NativeOutcome::NotAttempted => 3,
                    NativeOutcome::Succeeded => 2,
                    NativeOutcome::Unknown => 4,
                }
            ),
            Scenario::Healthy,
            at,
        )
        .unwrap();
    let lease = authority.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    let mut handoff_process = start_handoff(&root, handoff_address);
    let kubernetes_server =
        start_kubernetes_fixture(kubernetes_listener, outcome, &admission.run_id);

    let mut controller = fixed_controller_role(&root, &service);
    launch_after_lease_expiry(&mut controller, at + 31);
    let runner_status = controller.wait().unwrap();
    let _ = handoff_process.kill();
    handoff_process.wait().unwrap();
    let mut handoff_stderr = String::new();
    handoff_process
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut handoff_stderr)
        .unwrap();
    let invoked: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT application_invoked FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let failed_snapshot = service.snapshot(&admission.run_id, now()).unwrap();
    let runner_failure = format!(
        "runner={runner_status:?}; handoff={handoff_stderr}; invoked={invoked}; \
         snapshot={failed_snapshot:?}"
    );
    assert!(runner_status.success(), "{runner_failure}");
    kubernetes_server.join().unwrap();

    let snapshot = service.snapshot(&admission.run_id, now()).unwrap();
    assert!(root.join("sandbox.sqlite3").is_file());
    assert!(!root.join("gateway.sqlite3").exists());
    if outcome != NativeOutcome::NotAttempted {
        let expected_result = match outcome {
            NativeOutcome::Succeeded => OperationResult::Succeeded,
            NativeOutcome::Unknown => OperationResult::Unknown,
            NativeOutcome::NotAttempted => unreachable!(),
        };
        assert_eq!(snapshot.execution_state, ExecutionState::Terminal);
        assert_eq!(
            snapshot.receiver_result.as_deref(),
            Some(match expected_result {
                OperationResult::Succeeded => "SUCCEEDED",
                OperationResult::Failed => "FAILED",
                OperationResult::Unknown => "UNKNOWN",
            })
        );
        assert!(snapshot.receipt_available);
        let system_receipt = service.receipt(&admission.run_id, now()).unwrap();
        let receipt_key = SigningKey::from_bytes(&[42_u8; 32]);
        let trust = ReceiptTrust {
            key_id: "sandbox-receipt-key".into(),
            public_key: receipt_key.verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: at - 60,
            not_after_unix_s: at + 60,
        }
        .encode()
        .unwrap();
        let inspection = inspect_receipt(&system_receipt, &trust, at, InspectionLimits::default());
        assert_eq!(inspection.status(), InspectionStatus::Inspected);
        assert_eq!(
            inspection.statement().unwrap().result(),
            expected_result,
            "the separately trusted receipt classifier must agree with system projection"
        );
        assert_eq!(fs::read_dir(root.join("receipts")).unwrap().count(), 1);
    } else {
        assert_eq!(snapshot.execution_state, ExecutionState::NotAttempted);
        assert_eq!(snapshot.receiver_result, None);
        assert_eq!(
            snapshot.target_rejection.as_deref(),
            Some("DEPLOYMENT_NOT_FOUND")
        );
        assert!(!snapshot.receipt_available);
        assert!(fs::read_dir(root.join("receipts"))
            .unwrap()
            .next()
            .is_none());
    }
    remove_fixture_root(root);
}

#[test]
fn production_runner_process_handles_projected_inputs_and_receipt_free_rejection() {
    run_native_runner_case(NativeOutcome::NotAttempted);
}

#[test]
fn production_runner_process_finalizes_and_installs_exact_immutable_receipt() {
    run_native_runner_case(NativeOutcome::Succeeded);
}

#[test]
fn production_runner_preserves_unknown_receipt_and_separate_classifier_meaning() {
    run_native_runner_case(NativeOutcome::Unknown);
}

fn process_loss_before_invocation_recovers() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '5');
    let gate = TcpListener::bind(fixture.handoff_address).unwrap();
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let launch_at = fixture.launch_at;
    launch_after_lease_expiry(&mut controller, launch_at);
    let (mut uncommitted, _) = gate.accept().unwrap();
    let mut length = [0_u8; 4];
    uncommitted.read_exact(&mut length).unwrap();
    let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
    uncommitted.read_exact(&mut request).unwrap();
    assert!(!request.is_empty());
    drop(controller);
    drop(uncommitted);
    drop(gate);
    let invoked: bool = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT application_invoked FROM runs WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!invoked);

    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = reopened_controller_role(&fixture);
    let replacement_generation = launch_after_lease_expiry(&mut controller, launch_at + 31);
    assert_eq!(replacement_generation, 2);
    assert!(controller.wait().unwrap().success());
    let journal_count = fs::read_dir(fixture.root.join("runner-generations"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("run/gateway.sqlite3").is_file())
        .count();
    assert_eq!(journal_count, 0);
    kubernetes.join().unwrap();
    assert_eq!(
        fixture
            .service
            .snapshot(&fixture.run_id, now())
            .unwrap()
            .receiver_result
            .as_deref(),
        Some("SUCCEEDED")
    );
    handoff.kill().unwrap();
    handoff.wait().unwrap();
    remove_fixture_root(fixture.root);
}

fn process_loss_after_invocation_ack_recovers() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '6');
    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let launch_at = fixture.launch_at;
    launch_after_lease_expiry(&mut controller, launch_at);
    let (blocked_get, _) = kubernetes_listener.accept().unwrap();
    let mut blocked_get = tls_server_stream(blocked_get);
    read_fixture_request(&mut blocked_get);
    let invoked: bool = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT application_invoked FROM runs WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        invoked,
        "Kubernetes cannot be called before durable invocation ACK"
    );
    launch_after_lease_expiry(&mut controller, launch_at + 31);
    drop(blocked_get);

    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    assert!(controller.wait().unwrap().success());
    kubernetes.join().unwrap();
    assert_eq!(
        fixture
            .service
            .snapshot(&fixture.run_id, now())
            .unwrap()
            .receiver_result
            .as_deref(),
        Some("SUCCEEDED")
    );
    handoff.kill().unwrap();
    handoff.wait().unwrap();
    remove_fixture_root(fixture.root);
}

fn process_loss_after_apply_started_reconciles_without_second_patch() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '7');
    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let patch_seen = Arc::new(AtomicBool::new(false));
    let release_patch = Arc::new(AtomicBool::new(false));
    let server_patch_seen = Arc::clone(&patch_seen);
    let server_release = Arc::clone(&release_patch);
    let bodies = success_bodies(&fixture.run_id);
    let kubernetes = thread::spawn(move || {
        let (first_get, _) = kubernetes_listener.accept().unwrap();
        let mut first_get = tls_server_stream(first_get);
        read_fixture_request(&mut first_get);
        write_fixture_response(&mut first_get, &bodies[0]).unwrap();
        let (patch, _) = kubernetes_listener.accept().unwrap();
        let mut patch = tls_server_stream(patch);
        read_fixture_request(&mut patch);
        server_patch_seen.store(true, Ordering::Release);
        while !server_release.load(Ordering::Acquire) {
            thread::yield_now();
        }
        let _ = write_fixture_response(&mut patch, &bodies[1]);
        let (recovered_get, _) = kubernetes_listener.accept().unwrap();
        let mut recovered_get = tls_server_stream(recovered_get);
        read_fixture_request(&mut recovered_get);
        write_fixture_response(&mut recovered_get, &bodies[2]).unwrap();
    });
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let launch_at = fixture.launch_at;
    let generation = launch_after_lease_expiry(&mut controller, launch_at);
    while !patch_seen.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(1));
    }
    let journal = fixture
        .root
        .join("runner-generations")
        .join(format!("generation-{generation:020}/run/gateway.sqlite3"));
    wait_for_database_value(
        &journal,
        "SELECT state FROM kubernetes_image_operations LIMIT 1",
        "apply_started",
    );
    launch_after_lease_expiry(&mut controller, launch_at + 31);
    release_patch.store(true, Ordering::Release);
    assert!(controller.wait().unwrap().success());
    kubernetes.join().unwrap();
    assert_eq!(
        fixture
            .service
            .snapshot(&fixture.run_id, now())
            .unwrap()
            .receiver_result
            .as_deref(),
        Some("SUCCEEDED")
    );
    handoff.kill().unwrap();
    handoff.wait().unwrap();
    remove_fixture_root(fixture.root);
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "the process proof owns one complete terminal-report restart and replay seam"
)]
fn process_loss_after_terminal_report_replays_after_system_restart() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '8');
    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let receipt_directory = fixture.root.join("receipts");
    let held_receipt_directory = fixture.root.join("receipts-held");
    fs::rename(&receipt_directory, &held_receipt_directory).unwrap();
    fs::write(&receipt_directory, b"block receipt object creation").unwrap();

    let launch_at = fixture.launch_at;
    let first_generation = launch_after_lease_expiry(&mut controller, launch_at);
    for _ in 0..10_000 {
        let connection = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3")).unwrap();
        let reports: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM application_reports WHERE run_id = ?1",
                [&fixture.run_id],
                |row| row.get(0),
            )
            .unwrap();
        let publications: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&fixture.run_id],
                |row| row.get(0),
            )
            .unwrap();
        if reports == 1 && publications == 1 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let connection = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3")).unwrap();
    let reports: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM application_reports WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let publications: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let receipts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM receipts WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let receipt_available: bool = connection
        .query_row(
            "SELECT receipt_available FROM runs WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reports, 1);
    assert_eq!(publications, 1);
    assert_eq!(receipts, 0);
    assert!(!receipt_available);
    drop(connection);
    let first_outbox = fixture.root.join("runner-generations").join(format!(
        "generation-{first_generation:020}/run/receipt-outbox"
    ));
    let frozen_receipt = fs::read(
        fs::read_dir(&first_outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap();

    handoff.kill().unwrap();
    handoff.wait().unwrap();
    let _first_status = controller.wait().unwrap();
    drop(controller);
    kubernetes.join().unwrap();
    fs::remove_file(&receipt_directory).unwrap();
    fs::rename(&held_receipt_directory, &receipt_directory).unwrap();

    let mut restarted = start_handoff(&fixture.root, fixture.handoff_address);
    let mut controller = reopened_controller_role(&fixture);
    let replay_generation = launch_after_lease_expiry(&mut controller, launch_at + 31);
    let _ = replay_generation;
    assert!(controller.wait().unwrap().success());
    let snapshot = fixture.service.snapshot(&fixture.run_id, now()).unwrap();
    assert_eq!(snapshot.receiver_result.as_deref(), Some("SUCCEEDED"));
    assert!(snapshot.receipt_available);
    assert_eq!(
        fixture.service.receipt(&fixture.run_id, now()).unwrap(),
        frozen_receipt
    );
    assert!(fs::read_dir(fixture.root.join("runner-generations"))
        .unwrap()
        .next()
        .is_none());
    let connection = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3")).unwrap();
    let completed: (i64, i64) = connection
        .query_row(
            concat!(
                "SELECT (SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1), ",
                "(SELECT COUNT(*) FROM receipts WHERE run_id = ?1)"
            ),
            [&fixture.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(completed, (0, 1));
    restarted.kill().unwrap();
    restarted.wait().unwrap();
    remove_fixture_root(fixture.root);
}

#[cfg(target_os = "linux")]
fn controller_restart_converges_retirement_before_recovery(restart_offset_seconds: i64) {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '9');
    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let launch_at = fixture.launch_at;
    launch_after_lease_expiry(&mut controller, launch_at);
    for _ in 0..10_000 {
        if fixture
            .service
            .snapshot(&fixture.run_id, now())
            .unwrap()
            .receipt_available
        {
            break;
        }
        thread::yield_now();
    }
    let receipt = fixture.service.receipt(&fixture.run_id, now()).unwrap();
    let dispatch_run = fixture
        .root
        .join("fixed-authority/dispatch")
        .join(&fixture.run_id);
    assert_eq!(fs::read_dir(&dispatch_run).unwrap().count(), 1);
    let database = fixture.root.join("sandbox.sqlite3");
    let before = retirement_snapshot(&database, &fixture.run_id);
    let connection = rusqlite::Connection::open(&database).unwrap();
    // Exact crash-seam injection for the atomic Service::begin_runner_retirement transaction.
    // The controller and retained host generation are deliberately dropped before host retirement.
    let changed = connection
        .execute(
            concat!(
                "UPDATE runs SET runner_revoked = 1, runner_process_absent = 1, ",
                "journal_handoff = 1, handoff_credential_verifier = X'', ",
                "runner_state_retiring = 1 WHERE run_id = ?1 AND provisioning_closed = 1 ",
                "AND runner_revoked = 0 AND runner_state_retiring = 0 ",
                "AND runner_state_retired = 0 AND execution_state = 'terminal' AND NOT EXISTS ",
                "(SELECT 1 FROM receipt_publications WHERE ",
                "receipt_publications.run_id = runs.run_id)"
            ),
            [&fixture.run_id],
        )
        .unwrap();
    assert_eq!(changed, 1);
    drop(connection);
    let intent = retirement_snapshot(&database, &fixture.run_id);
    assert!(intent.runner_revoked);
    assert!(intent.process_absent);
    assert!(intent.journal_handoff);
    assert!(intent.retiring);
    assert!(!intent.retired);
    assert_eq!(intent.verifier_bytes, 0);
    drop(controller);
    kubernetes.join().unwrap();

    let mut restarted = reopened_controller_role(&fixture);
    assert!(restarted
        .run_once(launch_at + restart_offset_seconds)
        .unwrap()
        .is_none());
    let after = retirement_snapshot(&database, &fixture.run_id);
    assert_eq!(after.lease_epoch, before.lease_epoch);
    assert_eq!(after.operation_id, before.operation_id);
    assert_eq!(after.application_invoked, before.application_invoked);
    assert_eq!(after.report_count, before.report_count);
    assert!(after.runner_revoked);
    assert!(after.process_absent);
    assert!(after.journal_handoff);
    assert!(after.retiring);
    assert!(after.retired);
    assert_eq!(after.verifier_bytes, 0);
    assert!(!dispatch_run.exists());
    assert_eq!(
        fixture.service.receipt(&fixture.run_id, now()).unwrap(),
        receipt
    );
    assert!(fs::read_dir(fixture.root.join("runner-generations"))
        .unwrap()
        .next()
        .is_none());
    handoff.kill().unwrap();
    handoff.wait().unwrap();
    remove_fixture_root(fixture.root);
}

#[cfg(target_os = "linux")]
#[test]
fn production_process_loss_matrix_converges_at_owned_handoff_seams() {
    if !rustix::process::geteuid().is_root() {
        return;
    }
    process_loss_before_invocation_recovers();
    process_loss_after_invocation_ack_recovers();
    process_loss_after_apply_started_reconciles_without_second_patch();
    process_loss_after_terminal_report_replays_after_system_restart();
    controller_restart_converges_retirement_before_recovery(1);
    controller_restart_converges_retirement_before_recovery(31);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn production_process_loss_before_terminal_report_converges_on_non_linux() {
    process_loss_before_invocation_recovers();
    process_loss_after_invocation_ack_recovers();
    process_loss_after_apply_started_reconciles_without_second_patch();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn terminal_report_and_receipt_bytes_survive_non_linux_service_reopen_without_host_replacement() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '8');
    let mut handoff = start_handoff(&fixture.root, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(&fixture.root, &fixture.service);
    let launch_at = fixture.launch_at;
    launch_after_lease_expiry(&mut controller, launch_at);
    assert!(controller.wait().unwrap().success());
    kubernetes.join().unwrap();

    let receipt_before = fixture.service.receipt(&fixture.run_id, now()).unwrap();
    assert!(fs::read_dir(fixture.root.join("runner-generations"))
        .unwrap()
        .next()
        .is_none());
    let reports: i64 = rusqlite::Connection::open(fixture.root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM application_reports WHERE run_id = ?1",
            [&fixture.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reports, 1);

    handoff.kill().unwrap();
    handoff.wait().unwrap();
    drop(controller);
    drop(fixture.service);
    let controller_uid = rustix::process::geteuid().as_raw();
    let controller_gid = rustix::process::getegid().as_raw();
    let reopened = Service::open(
        fixture.root.join("sandbox.sqlite3"),
        fixture.root.join("receipts"),
        &AuthorityConfiguration::new(
            fixture.root.join("fixed-authority"),
            controller_uid,
            controller_gid,
            if controller_uid == 65_532 {
                65_531
            } else {
                65_532
            },
            if controller_gid == 65_532 {
                65_531
            } else {
                65_532
            },
        ),
        now(),
    )
    .unwrap();
    let snapshot = reopened.snapshot(&fixture.run_id, now()).unwrap();
    assert_eq!(snapshot.receiver_result.as_deref(), Some("SUCCEEDED"));
    assert!(snapshot.receipt_available);
    assert_eq!(
        reopened.receipt(&fixture.run_id, now()).unwrap(),
        receipt_before
    );
    remove_fixture_root(fixture.root);
}

#[tokio::test]
async fn separate_system_process_commits_invocation_and_receipt_free_rejection() {
    let handoff_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = handoff_probe.local_addr().unwrap();
    drop(handoff_probe);
    let kubernetes_probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let kubernetes_address = kubernetes_probe.local_addr().unwrap();
    drop(kubernetes_probe);
    let (root, service, authority) = fixture(address, kubernetes_address);
    let at = now();
    let admission = service
        .admit(&"1".repeat(32), Scenario::Healthy, at)
        .unwrap();
    let lease = authority.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    let mut child = start_handoff(&root, address);
    let assignment = service.handoff_assignment(&lease, address, at).unwrap();
    let (application, request, mut handle) = application(&root, &admission.run_id);
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    let report = run_application_handoff(application, &request, &assignment)
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(report.state, OperationState::NotAttempted);
    assert_eq!(
        report.target_rejection,
        Some(TargetRejection::DeploymentNotFound)
    );
    let snapshot = service.snapshot(&admission.run_id, now()).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::NotAttempted);
    assert_eq!(snapshot.receiver_result, None);
    assert_eq!(
        snapshot.target_rejection.as_deref(),
        Some("DEPLOYMENT_NOT_FOUND")
    );
    assert!(!snapshot.receipt_available);
    assert!(service.receipt(&admission.run_id, now()).is_err());
    child.kill().unwrap();
    child.wait().unwrap();
    remove_fixture_root(root);
}
