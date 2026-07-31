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
    os::unix::fs::{symlink, PermissionsExt},
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
    run_application_handoff, ControllerConfiguration, ControllerRole, DispatchLease,
    ExecutionState, ProvisionedObject, ProvisionedTarget, ProvisioningSpecification, Scenario,
    Service,
};
use tower_test::mock;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
);
const TEST_CA: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIBuDCCAWqgAwIBAgICAcgwBQYDK2VwMC4xLDAqBgNVBAMMI3Bvbnl0b3duIEVk\n",
    "RFNBIGxldmVsIDIgaW50ZXJtZWRpYXRlMB4XDTE5MDgxNjEzMjg1MVoXDTI1MDIw\n",
    "NTEzMjg1MVowGTEXMBUGA1UEAwwOdGVzdHNlcnZlci5jb20wKjAFBgMrZXADIQAQ\n",
    "9M4hrE+Ucw4QUmaKOeKfphklBJi1qsqtX4u+knbseqOBwDCBvTAMBgNVHRMBAf8E\n",
    "AjAAMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUa/gnV4+a22BUKTouAYX6nfLnPKYw\n",
    "RAYDVR0jBD0wO4AUFxIwU406tG3CsPWkHWqfuUT48auhIKQeMBwxGjAYBgNVBAMM\n",
    "EXBvbnl0b3duIEVkRFNBIENBggF7MDsGA1UdEQQ0MDKCDnRlc3RzZXJ2ZXIuY29t\n",
    "ghVzZWNvbmQudGVzdHNlcnZlci5jb22CCWxvY2FsaG9zdDAFBgMrZXADQQApDiBQ\n",
    "ns3fuvsWuFpIS+osj2B/gQ0b6eBAZ1UBxRyDlAo5++JZ0PtaEROyGo2t2gqi2Lyz\n",
    "47mLyGCvqgVbC6cH\n",
    "-----END CERTIFICATE-----\n"
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

fn fixture() -> (PathBuf, Service, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-runner-handoff-process-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    private_directory(&root.join("receipts"));
    let digest_key = root.join("digest.key");
    fs::write(&digest_key, [7_u8; 32]).unwrap();
    fs::set_permissions(&digest_key, fs::Permissions::from_mode(0o440)).unwrap();
    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        now(),
    )
    .unwrap();
    (root, service, digest_key)
}

fn verify_target(service: &Service, lease: &DispatchLease, at: i64) {
    let specification = service.provisioning_specification(lease, at).unwrap();
    service
        .verify_provisioned_target(
            lease,
            &ProvisionedTarget {
                namespace_uid: "handoff-namespace-uid".into(),
                policy_revision: specification.policy_revision.clone(),
                policy_inventory_digest: specification.policy_inventory_digest.clone(),
                cleanup_identity: specification.cleanup_identity.clone(),
                objects: provisioned_objects(&specification),
            },
            at,
        )
        .unwrap();
}

fn provisioned_objects(specification: &ProvisioningSpecification) -> Vec<ProvisionedObject> {
    specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| ProvisionedObject {
            identity: object.identity.clone(),
            uid: if index == 0 {
                "handoff-namespace-uid".into()
            } else {
                format!("handoff-object-{index}")
            },
            owner_label: specification.cleanup_identity.clone(),
            content_digest: object.content_digest.clone(),
        })
        .collect()
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

fn start_handoff(root: &Path, digest_key: &Path, address: std::net::SocketAddr) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_kapsel-sandbox"))
        .args([
            "handoff-serve",
            "--database",
            root.join("sandbox.sqlite3").to_str().unwrap(),
            "--receipts",
            root.join("receipts").to_str().unwrap(),
            "--digest-key-file",
            digest_key.to_str().unwrap(),
            "--listen",
            &address.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(address).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("private handoff process did not listen")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn projected_volume(root: &Path, files: &[(&str, Vec<u8>)]) {
    private_directory(root);
    fs::set_permissions(root, fs::Permissions::from_mode(0o750)).unwrap();
    let generation_name = "..2026_07_24_00_00_00.000000001";
    let generation = root.join(generation_name);
    private_directory(&generation);
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o750)).unwrap();
    symlink(generation_name, root.join("..data")).unwrap();
    for (name, bytes) in files {
        let target = generation.join(name);
        fs::write(&target, bytes).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o440)).unwrap();
        symlink(Path::new("..data").join(name), root.join(name)).unwrap();
    }
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
    outcome: NativeOutcome,
    run_id: &str,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
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
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 16 * 1024];
            let _ = stream.read(&mut request).unwrap();
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
    (address, server)
}

struct PreparedProcessFixture {
    root: PathBuf,
    service: Service,
    digest_key: PathBuf,
    run_id: String,
    launch_at: i64,
    handoff_address: SocketAddr,
    composition_path: PathBuf,
    handoff_path: PathBuf,
}

#[allow(
    clippy::too_many_lines,
    reason = "the production process fixture materializes every exact projected runner input"
)]
fn prepare_process_fixture(
    kubernetes_address: SocketAddr,
    idempotency_digit: char,
) -> PreparedProcessFixture {
    let (root, service, digest_key) = fixture();
    let at = now();
    let admission = service
        .admit(
            &idempotency_digit.to_string().repeat(32),
            Scenario::Healthy,
            at,
        )
        .unwrap();
    let lease = service.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let handoff_address = probe.local_addr().unwrap();
    drop(probe);
    let assignment = service
        .handoff_assignment(&lease, handoff_address, at)
        .unwrap();

    let input_root = root.join("projected");
    private_directory(&input_root);
    let composition_mount = input_root.join("composition");
    let authorization_mount = input_root.join("authorization");
    let kubernetes_mount = input_root.join("kubernetes");
    let signing_mount = input_root.join("receipt-signing");
    let handoff_mount = input_root.join("handoff");
    let state_volume = root.join("gateway-volume");
    private_directory(&state_volume);

    let request = serde_json::to_vec(&serde_json::json!({
        "operation_id": admission.operation_id,
        "namespace": format!("sandbox-{}", admission.run_id),
        "deployment": "sandbox-target",
        "container": "target",
        "immutable_image_digest": IMAGE
    }))
    .unwrap();
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &ExactAuthorization {
            authorization_id: format!("auth-{}", admission.run_id),
            operation_id: admission.operation_id.clone(),
            namespace: format!("sandbox-{}", admission.run_id),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: IMAGE.into(),
        },
        signing_seed: &authorization_seed,
        signing_key_id: "sandbox-authorization-key",
    })
    .unwrap();
    projected_volume(
        &authorization_mount,
        &[
            ("signed-grant.json", grant),
            (
                "trust.json",
                serde_json::to_vec(&serde_json::json!({
                    "key_id": "sandbox-authorization-key",
                    "public_key_hex": hex(&authorization_key.verifying_key().to_bytes())
                }))
                .unwrap(),
            ),
        ],
    );
    projected_volume(
        &kubernetes_mount,
        &[
            (
                "api-server",
                format!("http://{kubernetes_address}").into_bytes(),
            ),
            ("ca.crt", TEST_CA.as_bytes().to_vec()),
            ("namespace", b"kapsel-sandbox-runners".to_vec()),
            ("token", b"fixed-projected-token".to_vec()),
        ],
    );
    projected_volume(
        &signing_mount,
        &[
            ("seed", vec![42_u8; 32]),
            ("key-id", b"sandbox-receipt-key".to_vec()),
        ],
    );
    projected_volume(
        &handoff_mount,
        &[
            ("credential", assignment.credential().to_vec()),
            ("endpoint", assignment.endpoint().to_string().into_bytes()),
            ("lease-id", assignment.lease_id().as_bytes().to_vec()),
        ],
    );
    let journal_path = state_volume.join("run/gateway.sqlite3");
    let receipt_outbox = state_volume.join("run/receipt-outbox");
    let composition = serde_json::to_vec(&serde_json::json!({
        "request": composition_mount.join("request.json"),
        "signed_authorization_grant": authorization_mount.join("signed-grant.json"),
        "authorization_trust": authorization_mount.join("trust.json"),
        "kubernetes_api_server": kubernetes_mount.join("api-server"),
        "kubernetes_ca": kubernetes_mount.join("ca.crt"),
        "kubernetes_namespace": kubernetes_mount.join("namespace"),
        "kubernetes_token": kubernetes_mount.join("token"),
        "journal": journal_path,
        "receipt_directory": receipt_outbox,
        "receipt_signing_seed": signing_mount.join("seed"),
        "receipt_signing_key_id": signing_mount.join("key-id")
    }))
    .unwrap();
    projected_volume(
        &composition_mount,
        &[
            ("operator-configuration.json", composition),
            ("request.json", request),
        ],
    );
    PreparedProcessFixture {
        root,
        service,
        digest_key,
        run_id: admission.run_id,
        launch_at: at + 31,
        handoff_address,
        composition_path: composition_mount.join("operator-configuration.json"),
        handoff_path: handoff_mount,
    }
}

fn fixed_controller_role(
    root: &Path,
    composition_path: &Path,
    handoff_path: &Path,
    service: &Service,
    handoff_endpoint: SocketAddr,
) -> ControllerRole {
    let composition: serde_json::Value =
        serde_json::from_slice(&fs::read(composition_path).unwrap()).unwrap();
    let inputs = root.join("runner-host-inputs");
    private_directory(&inputs);
    let source = |field: &str| PathBuf::from(composition[field].as_str().unwrap());
    for (name, bytes) in [
        ("request.json", fs::read(source("request")).unwrap()),
        (
            "signed-authorization-grant.bin",
            fs::read(source("signed_authorization_grant")).unwrap(),
        ),
        (
            "authorization-trust.json",
            fs::read(source("authorization_trust")).unwrap(),
        ),
        (
            "kubernetes-api-server",
            fs::read(source("kubernetes_api_server")).unwrap(),
        ),
        (
            "kubernetes-ca.pem",
            fs::read(source("kubernetes_ca")).unwrap(),
        ),
        (
            "kubernetes-namespace",
            fs::read(source("kubernetes_namespace")).unwrap(),
        ),
        (
            "kubernetes-token",
            fs::read(source("kubernetes_token")).unwrap(),
        ),
        (
            "receipt-signing-seed",
            fs::read(source("receipt_signing_seed")).unwrap(),
        ),
        (
            "receipt-signing-key-id",
            fs::read(source("receipt_signing_key_id")).unwrap(),
        ),
        (
            "handoff-endpoint",
            fs::read(handoff_path.join("endpoint")).unwrap(),
        ),
        (
            "handoff-lease-id",
            fs::read(handoff_path.join("lease-id")).unwrap(),
        ),
        (
            "handoff-credential",
            fs::read(handoff_path.join("credential")).unwrap(),
        ),
    ] {
        fs::write(inputs.join(name), bytes).unwrap();
        fs::set_permissions(inputs.join(name), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let generations = root.join("runner-generations");
    private_directory(&generations);
    let controller_uid = rustix::process::geteuid().as_raw();
    let controller_gid = rustix::process::getegid().as_raw();
    #[cfg(target_os = "linux")]
    let (runner_uid, runner_gid) = (65_532, 65_532);
    #[cfg(not(target_os = "linux"))]
    let (runner_uid, runner_gid) = (controller_uid, controller_gid);
    let _ = (controller_uid, controller_gid);
    ControllerRole::new(
        service.clone(),
        ControllerConfiguration::new(
            inputs,
            generations,
            runner_uid,
            runner_gid,
            handoff_endpoint,
        ),
    )
}

fn reopened_controller_role(fixture: &PreparedProcessFixture) -> ControllerRole {
    let controller_uid = rustix::process::geteuid().as_raw();
    let controller_gid = rustix::process::getegid().as_raw();
    #[cfg(target_os = "linux")]
    let (runner_uid, runner_gid) = (65_532, 65_532);
    #[cfg(not(target_os = "linux"))]
    let (runner_uid, runner_gid) = (controller_uid, controller_gid);
    let _ = (controller_uid, controller_gid);
    ControllerRole::new(
        fixture.service.clone(),
        ControllerConfiguration::new(
            fixture.root.join("runner-host-inputs"),
            fixture.root.join("runner-generations"),
            runner_uid,
            runner_gid,
            fixture.handoff_address,
        ),
    )
}

fn launch_after_lease_expiry(controller: &mut ControllerRole, now_unix_s: i64) -> u64 {
    let Some(run) = controller.run_once(now_unix_s).unwrap() else {
        panic!("expired scheduler lease must recover into a production launch");
    };
    run.generation()
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

fn read_fixture_request(stream: &mut TcpStream) {
    let mut request = [0_u8; 16 * 1024];
    let _ = stream.read(&mut request).unwrap();
}

fn write_fixture_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
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
            let (mut stream, _) = listener.accept().unwrap();
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
    let (root, service, digest_key) = fixture();
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
    let lease = service.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let handoff_address = probe.local_addr().unwrap();
    drop(probe);
    let mut handoff_process = start_handoff(&root, &digest_key, handoff_address);
    let assignment = service
        .handoff_assignment(&lease, handoff_address, at)
        .unwrap();
    let (kubernetes_address, kubernetes_server) =
        start_kubernetes_fixture(outcome, &admission.run_id);

    let input_root = root.join("projected");
    private_directory(&input_root);
    let composition_mount = input_root.join("composition");
    let authorization_mount = input_root.join("authorization");
    let kubernetes_mount = input_root.join("kubernetes");
    let signing_mount = input_root.join("receipt-signing");
    let handoff_mount = input_root.join("handoff");
    let state_volume = root.join("gateway-volume");
    private_directory(&state_volume);
    assert!(fs::read_dir(&state_volume).unwrap().next().is_none());

    let operation_id = admission.operation_id.clone();
    let request = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "namespace": format!("sandbox-{}", admission.run_id),
        "deployment": "sandbox-target",
        "container": "target",
        "immutable_image_digest": IMAGE
    }))
    .unwrap();
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &ExactAuthorization {
            authorization_id: format!("auth-{}", admission.run_id),
            operation_id: admission.operation_id.clone(),
            namespace: format!("sandbox-{}", admission.run_id),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: IMAGE.into(),
        },
        signing_seed: &authorization_seed,
        signing_key_id: "sandbox-authorization-key",
    })
    .unwrap();
    let trust = serde_json::to_vec(&serde_json::json!({
        "key_id": "sandbox-authorization-key",
        "public_key_hex": hex(&authorization_key.verifying_key().to_bytes())
    }))
    .unwrap();
    projected_volume(
        &authorization_mount,
        &[("signed-grant.json", grant), ("trust.json", trust)],
    );
    projected_volume(
        &kubernetes_mount,
        &[
            (
                "api-server",
                format!("http://{kubernetes_address}").into_bytes(),
            ),
            ("ca.crt", TEST_CA.as_bytes().to_vec()),
            ("namespace", b"kapsel-sandbox-runners".to_vec()),
            ("token", b"fixed-projected-token".to_vec()),
        ],
    );
    projected_volume(
        &signing_mount,
        &[
            ("seed", vec![42_u8; 32]),
            ("key-id", b"sandbox-receipt-key".to_vec()),
        ],
    );
    projected_volume(
        &handoff_mount,
        &[
            ("credential", assignment.credential().to_vec()),
            ("endpoint", assignment.endpoint().to_string().into_bytes()),
            ("lease-id", assignment.lease_id().as_bytes().to_vec()),
        ],
    );
    let journal = state_volume.join("run/gateway.sqlite3");
    let receipt_outbox = state_volume.join("run/receipt-outbox");
    let composition = serde_json::to_vec(&serde_json::json!({
        "request": composition_mount.join("request.json"),
        "signed_authorization_grant": authorization_mount.join("signed-grant.json"),
        "authorization_trust": authorization_mount.join("trust.json"),
        "kubernetes_api_server": kubernetes_mount.join("api-server"),
        "kubernetes_ca": kubernetes_mount.join("ca.crt"),
        "kubernetes_namespace": kubernetes_mount.join("namespace"),
        "kubernetes_token": kubernetes_mount.join("token"),
        "journal": journal,
        "receipt_directory": receipt_outbox,
        "receipt_signing_seed": signing_mount.join("seed"),
        "receipt_signing_key_id": signing_mount.join("key-id")
    }))
    .unwrap();
    projected_volume(
        &composition_mount,
        &[
            ("operator-configuration.json", composition),
            ("request.json", request),
        ],
    );

    let composition_path = composition_mount.join("operator-configuration.json");
    let generations = root.join("runner-generations");
    let mut controller = fixed_controller_role(
        &root,
        &composition_path,
        &handoff_mount,
        &service,
        handoff_address,
    );
    let generation = launch_after_lease_expiry(&mut controller, at + 31);
    let runner_generation = generations.join(format!("generation-{generation:020}"));
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
    assert!(fs::read_dir(&state_volume).unwrap().next().is_none());
    let mut run_entries = fs::read_dir(runner_generation.join("run"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    run_entries.sort();
    assert_eq!(
        run_entries,
        [
            "gateway.sqlite3",
            "gateway.sqlite3.kap0038-worker.lock",
            "receipt-outbox"
        ]
    );
    assert!(runner_generation.join("run/gateway.sqlite3").is_file());
    assert!(!runner_generation.join("sandbox.sqlite3").exists());
    assert!(root.join("sandbox.sqlite3").is_file());
    assert!(!root.join("gateway.sqlite3").exists());
    let outbox_files = fs::read_dir(runner_generation.join("run/receipt-outbox"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
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
        assert_eq!(outbox_files.len(), 1);
        let system_receipt = service.receipt(&admission.run_id, now()).unwrap();
        assert_eq!(fs::read(&outbox_files[0]).unwrap(), system_receipt);
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
        assert!(outbox_files.is_empty());
        assert!(fs::read_dir(root.join("receipts"))
            .unwrap()
            .next()
            .is_none());
    }
    fs::remove_dir_all(root).unwrap();
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
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
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

    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
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
    assert_eq!(journal_count, 1);
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
    fs::remove_dir_all(fixture.root).unwrap();
}

fn process_loss_after_invocation_ack_recovers() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '6');
    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
    let launch_at = fixture.launch_at;
    launch_after_lease_expiry(&mut controller, launch_at);
    let (mut blocked_get, _) = kubernetes_listener.accept().unwrap();
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
    fs::remove_dir_all(fixture.root).unwrap();
}

fn process_loss_after_apply_started_reconciles_without_second_patch() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '7');
    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let patch_seen = Arc::new(AtomicBool::new(false));
    let release_patch = Arc::new(AtomicBool::new(false));
    let server_patch_seen = Arc::clone(&patch_seen);
    let server_release = Arc::clone(&release_patch);
    let bodies = success_bodies(&fixture.run_id);
    let kubernetes = thread::spawn(move || {
        let (mut first_get, _) = kubernetes_listener.accept().unwrap();
        read_fixture_request(&mut first_get);
        write_fixture_response(&mut first_get, &bodies[0]).unwrap();
        let (mut patch, _) = kubernetes_listener.accept().unwrap();
        read_fixture_request(&mut patch);
        server_patch_seen.store(true, Ordering::Release);
        while !server_release.load(Ordering::Acquire) {
            thread::yield_now();
        }
        let _ = write_fixture_response(&mut patch, &bodies[1]);
        let (mut recovered_get, _) = kubernetes_listener.accept().unwrap();
        read_fixture_request(&mut recovered_get);
        write_fixture_response(&mut recovered_get, &bodies[2]).unwrap();
    });
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
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
    fs::remove_dir_all(fixture.root).unwrap();
}

#[cfg(target_os = "linux")]
fn process_loss_after_terminal_report_replays_after_system_restart() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '8');
    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
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

    let mut restarted = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let mut controller = reopened_controller_role(&fixture);
    let replay_generation = launch_after_lease_expiry(&mut controller, launch_at + 31);
    let outbox = fixture.root.join("runner-generations").join(format!(
        "generation-{replay_generation:020}/run/receipt-outbox"
    ));
    assert!(controller.wait().unwrap().success());
    let snapshot = fixture.service.snapshot(&fixture.run_id, now()).unwrap();
    assert_eq!(snapshot.receiver_result.as_deref(), Some("SUCCEEDED"));
    assert!(snapshot.receipt_available);
    assert_eq!(
        fixture.service.receipt(&fixture.run_id, now()).unwrap(),
        frozen_receipt
    );
    assert_eq!(
        fs::read(
            fs::read_dir(outbox)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path()
        )
        .unwrap(),
        frozen_receipt
    );
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
    fs::remove_dir_all(fixture.root).unwrap();
}

#[cfg(target_os = "linux")]
fn controller_loss_after_receipt_publication_replays_exact_bytes() {
    let kubernetes_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = prepare_process_fixture(kubernetes_listener.local_addr().unwrap(), '9');
    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
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
    assert!(controller.wait().unwrap().success());
    drop(controller);
    kubernetes.join().unwrap();
    handoff.kill().unwrap();
    handoff.wait().unwrap();

    let mut restarted = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let mut controller = reopened_controller_role(&fixture);
    launch_after_lease_expiry(&mut controller, launch_at + 31);
    assert!(controller.wait().unwrap().success());
    assert_eq!(
        fixture.service.receipt(&fixture.run_id, now()).unwrap(),
        receipt
    );
    let journals = fs::read_dir(fixture.root.join("runner-generations"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("run/gateway.sqlite3").is_file())
        .count();
    assert_eq!(journals, 1);
    restarted.kill().unwrap();
    restarted.wait().unwrap();
    fs::remove_dir_all(fixture.root).unwrap();
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
    controller_loss_after_receipt_publication_replays_exact_bytes();
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
    let mut handoff = start_handoff(&fixture.root, &fixture.digest_key, fixture.handoff_address);
    let kubernetes = serve_success(kubernetes_listener, &fixture.run_id);
    let mut controller = fixed_controller_role(
        &fixture.root,
        &fixture.composition_path,
        &fixture.handoff_path,
        &fixture.service,
        fixture.handoff_address,
    );
    let launch_at = fixture.launch_at;
    let generation = launch_after_lease_expiry(&mut controller, launch_at);
    assert!(controller.wait().unwrap().success());
    kubernetes.join().unwrap();

    let receipt_before = fixture.service.receipt(&fixture.run_id, now()).unwrap();
    let outbox = fixture
        .root
        .join("runner-generations")
        .join(format!("generation-{generation:020}/run/receipt-outbox"));
    let outbox_path = fs::read_dir(outbox)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(fs::read(outbox_path).unwrap(), receipt_before);
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
    let reopened = Service::open(
        fixture.root.join("sandbox.sqlite3"),
        fixture.root.join("receipts"),
        [7; 32],
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
    fs::remove_dir_all(fixture.root).unwrap();
}

#[tokio::test]
async fn separate_system_process_commits_invocation_and_receipt_free_rejection() {
    let (root, service, digest_key) = fixture();
    let at = now();
    let admission = service
        .admit(&"1".repeat(32), Scenario::Healthy, at)
        .unwrap();
    let lease = service.dispatch_next(at).unwrap();
    verify_target(&service, &lease, at);
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let mut child = start_handoff(&root, &digest_key, address);
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
    fs::remove_dir_all(root).unwrap();
}
