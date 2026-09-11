//! Real-adapter recovery and frozen receipts against independent receiver facts.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "regression assertions"
)]

mod receiver;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

fn request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "comparison-op".into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: receiver::IMAGE.into(),
    }
}

fn grant(request: &SetDeploymentImageRequest) -> Vec<u8> {
    sign_authorization_grant(
        &ExactAuthorization {
            authorization_id: "comparison-approval".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
            approved_target: Some(ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "opaque-1".into(),
            }),
        },
        &[7; 32],
        "effect-gateway-authorization-test-key",
    )
    .unwrap()
}

fn inspected_statement(bytes: &[u8]) -> ReceiptStatement {
    let trust = ReceiptTrust {
        key_id: "comparison-receipt".into(),
        public_key: SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
        not_before_unix_s: 0,
        not_after_unix_s: i64::MAX,
    }
    .encode()
    .unwrap();
    let inspection = inspect_receipt(bytes, &trust, 1, InspectionLimits::default());
    assert_eq!(inspection.status(), InspectionStatus::Inspected);
    inspection.statement().unwrap().clone()
}

// Wrap only loss placement, not approval, dispatch payload, observations or classification.
struct CutAdapter {
    inner: KubernetesDeploymentImageAdapter,
    cut: String,
}
impl DeploymentImageAdapter for CutAdapter {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        self.inner.identify(request).await
    }
    async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
        if self.cut == "pre-send" {
            std::process::exit(73);
        }
        let result = self.inner.apply(permission).await;
        if self.cut == "lost-response" {
            std::process::exit(73);
        }
        result
    }
    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        self.inner.observe(request, outcome).await
    }
}

async fn run_operation(root: &Path, client: kube::Client, cut: &str) -> Value {
    let mut gateway = Gateway::open_for_test(root.join("kapsel.sqlite3")).unwrap();
    let request = request();
    gateway
        .submit_authorized(&request, &grant(&request))
        .unwrap();
    let mut adapter = CutAdapter {
        inner: KubernetesDeploymentImageAdapter::new(client),
        cut: cut.into(),
    };
    // A post-marker conflict is attempted, never a stale-approval rejection.
    if gateway
        .run_once_with_adapter(&mut adapter, None)
        .await
        .is_err()
    {
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();
    }
    gateway
        .finalize_receipt_once(&ReceiptSettings {
            signing_seed: &[42; 32],
            key_id: "comparison-receipt",
        })
        .unwrap();
    let result = match gateway.result("comparison-op").unwrap() {
        Some(OperationResult::Succeeded) => "SUCCEEDED",
        Some(OperationResult::Failed) => "FAILED",
        Some(OperationResult::Unknown) => "UNKNOWN",
        None => panic!("receiver scenario must reach a result"),
    };
    let (bytes, digest) =
        Gateway::read_loaded_receipt(gateway.loaded_for_test("comparison-op").unwrap().unwrap())
            .unwrap();
    assert_eq!(digest, hex_digest(&bytes));
    inspected_statement(&bytes);
    json!({"result":result,"frozen":bytes})
}

#[tokio::test(start_paused = true)]
async fn receiver_recovery_child() {
    let Ok(root) = std::env::var("KAPSEL_RECEIVER_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let case = std::env::var("KAPSEL_RECEIVER_CASE").unwrap();
    let cut = std::env::var("KAPSEL_RECEIVER_CUT").unwrap();
    let (client, receiver) = receiver::client(root, &case, cut == "lost-response");
    let report = run_operation(root, client, &cut).await;
    fs::write(
        root.join("caller-output.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    receiver.abort();
}

fn child(root: &Path, case: &str, cut: &str) {
    let log = fs::File::create(root.join("child.log")).unwrap();
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "gateway::receiver_recovery_tests::receiver_recovery_child",
            "--nocapture",
        ])
        .env("KAPSEL_RECEIVER_ROOT", root)
        .env("KAPSEL_RECEIVER_CASE", case)
        .env("KAPSEL_RECEIVER_CUT", cut)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = process.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            process.kill().unwrap();
            process.wait().unwrap();
            panic!("child deadline: {case}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let log = fs::read_to_string(root.join("child.log")).unwrap();
    assert!(log.len() <= 64 * 1024);
    assert_eq!(
        status.code(),
        Some(if cut == "none" { 0 } else { 73 }),
        "{case}: {log}"
    );
}

fn output(root: &Path) -> Value {
    serde_json::from_slice(&fs::read(root.join("caller-output.json")).unwrap()).unwrap()
}
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
}

// Check frozen facts against receiver-owned evidence, independently of Kapsel's classifier.
#[allow(
    clippy::too_many_lines,
    reason = "keep the independent evidence assertions together"
)]
fn assert_retained_facts(case: &str, output: &Value, receiver: &Value) {
    let bytes: Vec<u8> = serde_json::from_value(output["frozen"].clone()).unwrap();
    let request = request();
    let requested = match case {
        "pre-send" | "target-replacement" | "intervening-writer" | "preflight-race" => None,
        "retained-marker" => Some(3),
        _ => Some(2),
    };
    let statement = inspected_statement(&bytes);
    assert_eq!(statement.approved_target.as_ref().unwrap().uid, "uid-1");
    assert_eq!(
        statement.approved_target.as_ref().unwrap().resource_version,
        "opaque-1"
    );
    assert_eq!(statement.target_uid, "uid-1");
    assert_eq!(statement.target_resource_version, "opaque-1");
    assert_eq!(statement.operation_id, request.operation_id);
    assert_eq!(statement.namespace, request.namespace);
    assert_eq!(statement.deployment, request.deployment);
    assert_eq!(statement.container, request.container);
    assert_eq!(
        statement.immutable_image_digest,
        request.immutable_image_digest
    );
    assert_eq!(json!(statement.receiver_uid), receiver["metadata"]["uid"]);
    assert_eq!(
        json!(statement.observed_resource_version),
        receiver["metadata"]["resourceVersion"]
    );
    assert_eq!(
        json!(statement.current_generation),
        receiver["metadata"]["generation"]
    );
    assert_eq!(statement.requested_generation, requested);
    assert_eq!(
        json!(statement.observed_generation),
        receiver["status"]["observedGeneration"]
    );
    assert_eq!(
        json!(statement.observed_image),
        receiver["spec"]["template"]["spec"]["containers"][0]["image"]
    );
    assert_eq!(
        json!(statement.observed_operation_marker),
        receiver["metadata"]["annotations"]["kapsel.dev/kap0038-operation-id"]
    );
    assert_eq!(
        json!(statement.desired_replicas),
        receiver["spec"]["replicas"]
    );
    assert_eq!(
        json!(statement.updated_replicas),
        receiver["status"]["updatedReplicas"]
    );
    assert_eq!(
        json!(statement.available_replicas),
        receiver["status"]["availableReplicas"]
    );
    assert_eq!(
        json!(statement.unavailable_replicas),
        json!(receiver["status"]["unavailableReplicas"]
            .as_i64()
            .unwrap_or(0))
    );
    let condition = &receiver["status"]["conditions"][0];
    assert_eq!(json!(statement.rollout_condition_type), condition["type"]);
    assert_eq!(
        json!(statement.rollout_condition_status),
        condition["status"]
    );
    assert_eq!(
        json!(statement.rollout_condition_reason),
        condition["reason"]
    );
}

struct Workspace(PathBuf);
impl Workspace {
    fn new(case: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kapsel-receiver-recovery-{}-{case}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[test]
fn receiver_recovery_scenarios() {
    let only = std::env::var("KAPSEL_RECEIVER_ONLY").ok();
    let mut executed = 0;
    for (case, expected, patches, gets, cut) in [
        ("failed", "FAILED", 1, 2, "none"),
        ("pre-send", "UNKNOWN", 0, 31, "pre-send"),
        ("lost-response", "SUCCEEDED", 1, 2, "lost-response"),
        ("target-replacement", "UNKNOWN", 1, 2, "lost-response"),
        ("intervening-writer", "UNKNOWN", 1, 31, "lost-response"),
        ("retained-marker", "SUCCEEDED", 1, 2, "lost-response"),
        ("preflight-race", "UNKNOWN", 1, 31, "none"),
        ("slow-rollout", "UNKNOWN", 1, 31, "none"),
    ] {
        if only.as_deref().is_some_and(|selected| selected != case) {
            continue;
        }
        executed += 1;
        let root = Workspace::new(case);
        receiver::initialize(&root.0);
        child(&root.0, case, cut);
        if cut != "none" {
            if matches!(
                case,
                "target-replacement" | "intervening-writer" | "retained-marker"
            ) {
                receiver::intervene(&root.0, case);
            }
            child(&root.0, case, "none");
        }
        let original = output(&root.0);
        assert_eq!(original["result"], expected, "{case}");
        let evidence = receiver::read(&root.0);
        assert_retained_facts(case, &original, &evidence["object"]);
        let requests = evidence["requests"].as_array().unwrap();
        assert_eq!(
            requests.iter().filter(|r| r["method"] == "PATCH").count(),
            patches
        );
        assert_eq!(
            requests.iter().filter(|r| r["method"] == "GET").count(),
            gets
        );
        let persisted = if case == "preflight-race" { 0 } else { patches };
        assert_eq!(evidence["persisted_patches"], persisted);
        assert_eq!(
            evidence["writer_changes"],
            usize::from(matches!(
                case,
                "target-replacement" | "intervening-writer" | "retained-marker" | "preflight-race"
            ))
        );
        if case == "slow-rollout" {
            receiver::intervene(&root.0, case);
        }
        let before_reconnect = receiver::read(&root.0);
        child(&root.0, case, "none");
        assert_eq!(
            output(&root.0),
            original,
            "offline reconnect changes frozen evidence"
        );
        assert_eq!(
            receiver::read(&root.0),
            before_reconnect,
            "offline reconnect sends a request"
        );
        println!(
            "[receiver recovery] {case}: PATCH={patches}, GET={gets}, \
                persisted={persisted}, result={expected}, frozen_sha256={}",
            hex_digest(&serde_json::from_value::<Vec<u8>>(original["frozen"].clone()).unwrap())
        );
    }
    assert_eq!(
        executed,
        if only.is_some() { 1 } else { 8 },
        "scenario selection"
    );
}
