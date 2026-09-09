//! Bounded executable protected-tool comparison. No product command or adopted alternative.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "experiment assertions"
)]

mod alternative;
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

fn approval() -> alternative::Approval {
    alternative::Approval {
        request: alternative::Request {
            operation: "comparison-op".into(),
            namespace: "demo".into(),
            deployment: "api".into(),
            container: "api".into(),
            image: receiver::IMAGE.into(),
        },
        uid: "uid-1".into(),
        version: "opaque-1".into(),
    }
}

fn gateway_request(request: &alternative::Request) -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: request.operation.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.image.clone(),
    }
}

fn grant(approved: &alternative::Approval) -> Vec<u8> {
    sign_authorization_grant(
        &ExactAuthorization {
            authorization_id: "comparison-approval".into(),
            operation_id: approved.request.operation.clone(),
            namespace: approved.request.namespace.clone(),
            deployment: approved.request.deployment.clone(),
            container: approved.request.container.clone(),
            immutable_image_digest: approved.request.image.clone(),
            approved_target: Some(ApprovedTarget {
                uid: approved.uid.clone(),
                resource_version: approved.version.clone(),
            }),
        },
        &[7; 32],
        "effect-gateway-authorization-test-key",
    )
    .unwrap()
}

fn mismatches(request: &alternative::Request) -> Vec<alternative::Request> {
    let mut requests = Vec::new();
    for field in 0..5 {
        let mut changed = request.clone();
        match field {
            0 => changed.operation = "other-op".into(),
            1 => changed.namespace = "other".into(),
            2 => changed.deployment = "other".into(),
            3 => changed.container = "other".into(),
            4 => changed.image = receiver::OTHER.into(),
            _ => unreachable!(),
        }
        requests.push(changed);
    }
    requests
}

fn replacement_approvals(original: &alternative::Approval) -> [alternative::Approval; 2] {
    let mut uid = original.clone();
    uid.uid = "replacement-approval".into();
    let mut version = original.clone();
    version.version = "replacement-version".into();
    [uid, version]
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

async fn kapsel_arm(
    root: &Path,
    client: kube::Client,
    cut: &str,
    approved: &alternative::Approval,
) -> Value {
    let path = root.join("kapsel.sqlite3");
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    let signed = grant(approved);
    let before = receiver::read(root);
    for wrong in mismatches(&approved.request) {
        assert!(gateway
            .submit_authorized(&gateway_request(&wrong), &signed)
            .is_err());
    }
    assert_eq!(receiver::read(root), before);
    let request = gateway_request(&approved.request);
    gateway.submit_authorized(&request, &signed).unwrap();
    for changed in replacement_approvals(approved) {
        assert!(gateway
            .submit_authorized(&request, &grant(&changed))
            .is_err());
    }
    assert_eq!(receiver::read(root), before);
    let mut adapter = CutAdapter {
        inner: KubernetesDeploymentImageAdapter::new(client),
        cut: cut.into(),
    };
    // Two independently opened worker-lock handles: the contender must perform no I/O.
    let contender = Gateway::open_for_test(&path).unwrap();
    let lock = contender.journal.try_lock_worker().unwrap().unwrap();
    assert!(gateway
        .run_once_with_adapter(&mut adapter, None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(receiver::read(root), before);
    drop(lock);
    drop(contender);
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
        None => {
            assert_eq!(
                gateway.target_rejection("comparison-op").unwrap(),
                Some(TargetRejection::StaleApproval)
            );
            "NOT_ATTEMPTED"
        },
    };
    let original = if result == "NOT_ATTEMPTED" {
        let targets = gateway
            .loaded_for_test("comparison-op")
            .unwrap()
            .unwrap()
            .targets();
        serde_json::to_vec(
            &json!({"approved_uid":targets.approved_target.as_ref().unwrap().uid,
            "approved_version":targets.approved_target.as_ref().unwrap().resource_version,
            "observed_uid":targets.observed_target.as_ref().unwrap().uid,
            "observed_version":targets.observed_target.as_ref().unwrap().resource_version,
            "reason":"STALE_APPROVAL"}),
        )
        .unwrap()
    } else {
        let (bytes, digest) = Gateway::read_loaded_receipt(
            gateway.loaded_for_test("comparison-op").unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(digest, hex_digest(&bytes));
        inspected_statement(&bytes);
        bytes
    };
    let before_offline = receiver::read(root);
    for _ in 0..2 {
        gateway.submit_authorized(&request, &signed).unwrap();
        assert!(gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap()
            .is_none());
    }
    assert_eq!(receiver::read(root), before_offline);
    json!({"result":result,"frozen":original})
}

async fn typed_arm(
    root: &Path,
    client: kube::Client,
    cut: &str,
    approved: &alternative::Approval,
) -> Value {
    let mut tool = alternative::Tool::open(root);
    assert!(tool.approve(approved));
    let before = receiver::read(root);
    let retained_before = tool.retained();
    for changed in replacement_approvals(approved) {
        assert!(!tool.approve(&changed));
    }
    assert!(tool.approve(approved));
    assert_eq!(tool.retained(), retained_before);
    for wrong in mismatches(&approved.request) {
        assert!(!tool.execute(&wrong, client.clone(), cut).await);
    }
    assert_eq!(receiver::read(root), before);
    let contender = alternative::Tool::open(root);
    contender.lock();
    assert!(!tool.execute(&approved.request, client.clone(), cut).await);
    assert_eq!(receiver::read(root), before);
    contender.unlock();
    drop(contender);
    assert!(tool.execute(&approved.request, client.clone(), cut).await);
    let original = tool.retained().unwrap();
    let parsed: Value = serde_json::from_str(&original).unwrap();
    let before_offline = receiver::read(root);
    for _ in 0..2 {
        assert!(tool.execute(&approved.request, client.clone(), cut).await);
        assert_eq!(tool.retained().unwrap(), original);
    }
    assert_eq!(receiver::read(root), before_offline);
    json!({"result":parsed["result"],"frozen":original.as_bytes()})
}

#[tokio::test(start_paused = true)]
async fn comparison_child() {
    let Ok(root) = std::env::var("KAPSEL_COMPARISON_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let case = std::env::var("KAPSEL_COMPARISON_CASE").unwrap();
    let arm = std::env::var("KAPSEL_COMPARISON_ARM").unwrap();
    let cut = std::env::var("KAPSEL_COMPARISON_CUT").unwrap();
    let approved: alternative::Approval =
        serde_json::from_slice(&fs::read(root.join("approval.json")).unwrap()).unwrap();
    let (client, receiver) = receiver::client(root, &case, cut == "lost-response");
    let report = match arm.as_str() {
        "kapsel" => kapsel_arm(root, client, &cut, &approved).await,
        "typed" => typed_arm(root, client, &cut, &approved).await,
        _ => panic!("unknown arm"),
    };
    fs::write(
        root.join("caller-output.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    receiver.abort();
}

fn child(root: &Path, case: &str, arm: &str, cut: &str) {
    let log = fs::File::create(root.join("child.log")).unwrap();
    let mut process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "gateway::protected_tool_tests::comparison_child",
            "--nocapture",
        ])
        .env("KAPSEL_COMPARISON_ROOT", root)
        .env("KAPSEL_COMPARISON_CASE", case)
        .env("KAPSEL_COMPARISON_ARM", arm)
        .env("KAPSEL_COMPARISON_CUT", cut)
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
            panic!("child deadline: {case}/{arm}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let log = fs::read_to_string(root.join("child.log")).unwrap();
    assert!(log.len() <= 64 * 1024);
    assert_eq!(
        status.code(),
        Some(if cut == "none" { 0 } else { 73 }),
        "{case}/{arm}: {log}"
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

// Check frozen facts against receiver-owned evidence, independently of either classifier.
#[allow(
    clippy::too_many_lines,
    reason = "keep the independent evidence assertions together"
)]
fn assert_retained_facts(arm: &str, case: &str, output: &Value, receiver: &Value) {
    let bytes: Vec<u8> = serde_json::from_value(output["frozen"].clone()).unwrap();
    let approved = approval();
    let stale = case.starts_with("stale-");
    let requested = match case {
        "pre-send" | "target-replacement" | "intervening-writer" | "preflight-race" => None,
        "retained-marker" => Some(3),
        _ => Some(2),
    };
    if arm == "typed" {
        let retained: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            retained["approved"],
            serde_json::to_value(&approved).unwrap()
        );
        let object: k8s_openapi::api::apps::v1::Deployment =
            serde_json::from_value(receiver.clone()).unwrap();
        if stale {
            assert_eq!(retained["reason"], "STALE_APPROVAL");
            assert_eq!(
                retained["observed"],
                serde_json::to_value(object.metadata).unwrap()
            );
        } else {
            assert_eq!(retained["observed"], serde_json::to_value(object).unwrap());
            assert_eq!(retained["requested_generation"], json!(requested));
            assert_eq!(retained["attribution"], "not_established");
        }
    } else if stale {
        let retained: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(retained["reason"], "STALE_APPROVAL");
        assert_eq!(retained["approved_uid"], approved.uid);
        assert_eq!(retained["approved_version"], approved.version);
        assert_eq!(retained["observed_uid"], receiver["metadata"]["uid"]);
        assert_eq!(
            retained["observed_version"],
            receiver["metadata"]["resourceVersion"]
        );
    } else {
        let statement = inspected_statement(&bytes);
        assert_eq!(
            statement.approved_target.as_ref().unwrap().uid,
            approved.uid
        );
        assert_eq!(
            statement.approved_target.as_ref().unwrap().resource_version,
            approved.version
        );
        assert_eq!(statement.target_uid, approved.uid);
        assert_eq!(statement.target_resource_version, approved.version);
        assert_eq!(statement.operation_id, approved.request.operation);
        assert_eq!(statement.namespace, approved.request.namespace);
        assert_eq!(statement.deployment, approved.request.deployment);
        assert_eq!(statement.container, approved.request.container);
        assert_eq!(statement.immutable_image_digest, approved.request.image);
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
}

struct Workspace(PathBuf);
impl Workspace {
    fn new(case: &str, arm: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kapsel-protected-tool-{}-{case}-{arm}",
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
fn protected_tool_comparison() {
    let only = std::env::var("KAPSEL_COMPARISON_ONLY").ok();
    let mut executed = 0;
    for (case, expected, patches, gets, cut) in [
        ("healthy", "SUCCEEDED", 1, 2, "none"),
        ("failed", "FAILED", 1, 2, "none"),
        ("pre-send", "UNKNOWN", 0, 31, "pre-send"),
        ("lost-response", "SUCCEEDED", 1, 2, "lost-response"),
        ("reconnect", "SUCCEEDED", 1, 2, "none"),
        ("stale-status", "NOT_ATTEMPTED", 0, 1, "none"),
        ("stale-annotation", "NOT_ATTEMPTED", 0, 1, "none"),
        ("stale-identity", "NOT_ATTEMPTED", 0, 1, "none"),
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
        let mut arm_evidence = Vec::new();
        for arm in ["kapsel", "typed"] {
            let root = Workspace::new(case, arm);
            receiver::initialize(&root.0, case);
            fs::write(
                root.0.join("approval.json"),
                serde_json::to_vec(&approval()).unwrap(),
            )
            .unwrap();
            child(&root.0, case, arm, cut);
            if cut != "none" {
                if matches!(
                    case,
                    "target-replacement" | "intervening-writer" | "retained-marker"
                ) {
                    receiver::intervene(&root.0, case);
                }
                child(&root.0, case, arm, "none");
            }
            let original = output(&root.0);
            assert_eq!(original["result"], expected, "{case}/{arm}");
            let evidence = receiver::read(&root.0);
            assert_retained_facts(arm, case, &original, &evidence["object"]);
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
            if case == "slow-rollout" {
                receiver::intervene(&root.0, case);
            }
            let before_reconnect = receiver::read(&root.0);
            child(&root.0, case, arm, "none");
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
                "[protected tool] {case}/{arm}: PATCH={patches}, GET={gets}, \
                persisted={persisted}, result={expected}, frozen_sha256={}",
                hex_digest(&serde_json::from_value::<Vec<u8>>(original["frozen"].clone()).unwrap())
            );
            let next_action = match original["result"].as_str().unwrap() {
                "SUCCEEDED" => "inspect_application_behavior",
                "FAILED" => "investigate_receiver_failure",
                "UNKNOWN" => "human_handoff_no_retry",
                "NOT_ATTEMPTED" => "operator_decides_whether_to_approve_new_action",
                _ => panic!("unknown result"),
            };
            println!("[scripted caller] {case}/{arm}: {next_action}");
            arm_evidence.push(evidence);
        }
        assert_eq!(
            arm_evidence[0], arm_evidence[1],
            "receiver evidence differs between arms: {case}"
        );
    }
    assert!(executed > 0, "unknown reduced comparison case");
}
