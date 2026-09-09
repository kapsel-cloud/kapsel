//! Disposable later-observation experiment. Not a product API or lifecycle.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "experiment assertions"
)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use k8s_openapi::api::apps::v1::Deployment;
use kapsel::{
    inspect_receipt, provision_exact_grant, AgentRequest, Application, ApprovedTarget,
    AuthorizationTrust, ExactAuthorization, GrantProvisioning, InspectionLimits, InspectionStatus,
    OperationResult, OperatorConfiguration, ReceiptStatement, ReceiptTrust,
    SetDeploymentImageReceipt, SetDeploymentImageStatus,
};
use kube::{Api, Client};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower_test::mock;

const IMAGE: &str =
    "registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c";
const MARKER: &str = "kapsel.dev/kap0038-operation-id";
const GET_BOUND: Duration = Duration::from_secs(2);

struct Original {
    bytes: Vec<u8>,
    digest: String,
    statement: ReceiptStatement,
}

impl Original {
    fn retrieve(application: &Application, operation: &str) -> Self {
        let SetDeploymentImageReceipt::Ready { bytes, sha256 } = application
            .read_set_deployment_image_receipt(operation)
            .unwrap()
        else {
            panic!("not ready")
        };
        let computed = Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut text, byte| {
                use std::fmt::Write;
                write!(text, "{byte:02x}").unwrap();
                text
            });
        assert_eq!(sha256, computed);
        let trust = ReceiptTrust {
            key_id: "later-receipt".into(),
            public_key: SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
            not_before_unix_s: 0,
            not_after_unix_s: i64::MAX,
        }
        .encode()
        .unwrap();
        let report = inspect_receipt(&bytes, &trust, 1, InspectionLimits::default());
        assert_eq!(report.status(), InspectionStatus::Inspected);
        let statement = report.statement().unwrap().clone();
        assert_eq!(statement.operation_id(), operation);
        assert_eq!(statement.result(), OperationResult::Unknown);
        Self {
            bytes,
            digest: sha256,
            statement,
        }
    }
}

// One private, disposable row per original action. A NULL result means consumed with no retained
// observation, never permission to retry. This is deliberately not in the gateway journal.
struct Slot(Connection);
impl Slot {
    fn open(root: &Path) -> Self {
        let path = root.join("supplement.sqlite3");
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
        }
        let db = Connection::open(path).unwrap();
        db.execute_batch(
            "PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS observation (
            operation TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT);",
        )
        .unwrap();
        Self(db)
    }

    fn reserve(&self, original: &Original) -> bool {
        let inserted = self
            .0
            .execute(
                "INSERT OR IGNORE INTO observation(operation,digest) VALUES (?1,?2)",
                params![original.statement.operation_id(), original.digest],
            )
            .unwrap()
            == 1;
        let digest: String = self
            .0
            .query_row(
                "SELECT digest FROM observation WHERE operation=?1",
                [original.statement.operation_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            digest, original.digest,
            "same action cannot acquire a replacement receipt"
        );
        inserted
    }

    fn retained(&self, original: &Original) -> Value {
        let result: Option<String> = self
            .0
            .query_row(
                "SELECT result FROM observation WHERE operation=?1 AND digest=?2",
                params![original.statement.operation_id(), original.digest],
                |row| row.get(0),
            )
            .unwrap();
        result.map_or_else(
            || json!({"acquisition": "consumed_without_evidence"}),
            |text| serde_json::from_str(&text).unwrap(),
        )
    }

    #[allow(
        clippy::needless_pass_by_ref_mut,
        reason = "exclusive SQLite borrow keeps the future Send"
    )]
    async fn follow_up(&mut self, original: &Original, operator_client: Client) -> Value {
        if !self.reserve(original) {
            return self.retained(original);
        }
        // Target and image come from the inspected original bytes, not continuation input.
        let statement = &original.statement;
        let started_unix_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let api = Api::<Deployment>::namespaced(operator_client, statement.namespace());
        let later = match tokio::time::timeout(GET_BOUND, api.get(statement.deployment())).await {
            Ok(Ok(deployment)) => describe(statement, &deployment),
            Ok(Err(_)) => json!({"acquisition": "read_error"}),
            Err(_) => json!({"acquisition": "deadline"}),
        };
        let result = json!({"operation_id": statement.operation_id(),
            "original_receipt_sha256": original.digest, "earlier_result": "UNKNOWN",
            "later": later, "started_unix_s": started_unix_s,
            "attribution": "not_established"});
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.len() <= 4096);
        assert_eq!(
            self.0
                .execute(
                    "UPDATE observation SET result=?1
            WHERE operation=?2 AND digest=?3 AND result IS NULL",
                    params![text, statement.operation_id(), original.digest]
                )
                .unwrap(),
            1
        );
        result
    }
}

fn describe(original: &ReceiptStatement, deployment: &Deployment) -> Value {
    let spec = deployment.spec.as_ref();
    let status = deployment.status.as_ref();
    let image = spec
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|s| s.containers.iter().find(|c| c.name == original.container()))
        .and_then(|c| c.image.as_deref());
    let marker = deployment
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(MARKER));
    let same_uid = deployment.metadata.uid.as_deref() == Some(original.target_uid());
    let generation = deployment.metadata.generation;
    let generation_relation = match (original.requested_generation(), generation) {
        (Some(a), Some(b)) if a == b => "same",
        (Some(a), Some(b)) if b > a => "superseding",
        _ => "unestablished",
    };
    let available = spec.zip(status).is_some_and(|(s, t)| {
        let desired = s.replicas.unwrap_or(1);
        desired > 0
            && t.updated_replicas == Some(desired)
            && t.available_replicas == Some(desired)
            && t.unavailable_replicas.unwrap_or(0) == 0
            && generation
                .zip(t.observed_generation)
                .is_some_and(|(g, o)| o >= g)
            && t.conditions.as_ref().is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|c| c.type_ == "Available" && c.status == "True")
            })
    });
    // Report current state, never re-run the historical receiver-result classifier.
    json!({"acquisition": "observed", "same_uid": same_uid,
        "generation_relation": generation_relation,
        "original_requested_generation": original.requested_generation(),
        "observed_generation_now": generation,
        "requested_image_present": image == Some(original.immutable_image_digest()),
        "operation_marker_present": marker.map(String::as_str) == Some(original.operation_id()),
        "deployment_available_now": available})
}

fn next_action(evidence: &Value) -> &'static str {
    let later = &evidence["later"];
    if later["same_uid"] == true
        && later["generation_relation"] == "same"
        && later["requested_image_present"] == true
        && later["operation_marker_present"] == true
        && later["deployment_available_now"] == true
    {
        "inspect_application_behavior_without_retry"
    } else {
        "operator_inspects_receiver_or_intervening_state"
    }
}

fn request() -> AgentRequest {
    AgentRequest {
        operation_id: "later-op".into(),
        namespace: "kapsel-later-observation".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    }
}

fn application(root: &Path, client: Client, target: ApprovedTarget) -> Application {
    let request = request();
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &ExactAuthorization {
            approved_target: Some(target),
            authorization_id: "later-authority".into(),
            operation_id: request.operation_id,
            namespace: request.namespace,
            deployment: request.deployment,
            container: request.container,
            immutable_image_digest: request.immutable_image_digest,
        },
        signing_seed: &[41; 32],
        signing_key_id: "later-authority",
    })
    .unwrap();
    Application::open(OperatorConfiguration {
        journal_path: root.join("journal.sqlite3"),
        receipt_output_directory: None,
        authorization_trust: AuthorizationTrust {
            key_id: "later-authority".into(),
            public_key: SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
        },
        signed_authorization_grant: grant,
        kubernetes_client: client,
        receipt_signing_seed: [42; 32],
        receipt_signing_key_id: "later-receipt".into(),
    })
    .unwrap()
}

struct Workspace(PathBuf);
impl Workspace {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("kapsel-later-{}-{name}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

type Handle = mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>;
fn client() -> (Client, Handle) {
    let (service, handle) = mock::pair();
    (Client::new(service, &request().namespace), handle)
}
fn fixture(healthy: bool) -> Value {
    json!({"apiVersion":"apps/v1", "kind":"Deployment",
        "metadata":{"name":"agent-api", "namespace":request().namespace,
            "uid":"uid-1", "resourceVersion":"1", "generation":2,
            "annotations":{MARKER:request().operation_id}},
        "spec":{"replicas":1, "selector":{"matchLabels":{"app":"agent-api"}},
            "template":{"metadata":{"labels":{"app":"agent-api"}},
                "spec":{"containers":[{"name":"api", "image":IMAGE}]}}},
        "status":{"observedGeneration":2, "updatedReplicas":1,
            "availableReplicas":i32::from(healthy), "unavailableReplicas":i32::from(!healthy),
            "conditions":[{"type":"Available", "status":if healthy {"True"} else {"False"}}]}})
}
async fn respond(handle: &mut Handle, method: &str, body: &Value, status: u16) {
    let (request, send) = handle.next_request().await.unwrap();
    assert_eq!(request.method(), method);
    assert_eq!(
        request.uri().path(),
        "/apis/apps/v1/namespaces/kapsel-later-observation/deployments/agent-api"
    );
    send.send_response(
        http::Response::builder()
            .status(status)
            .body(kube::client::Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap(),
    );
}
fn target() -> ApprovedTarget {
    ApprovedTarget {
        uid: "uid-1".into(),
        resource_version: "1".into(),
    }
}

async fn original_fixture(root: &Path) -> Original {
    let (client, mut handle) = client();
    let mut app = application(root, client, target());
    let receiver = tokio::spawn(async move {
        respond(&mut handle, "GET", &fixture(false), 200).await;
        respond(&mut handle, "PATCH", &fixture(false), 200).await;
        // Keep the rollout pending through the actual bounded observation loop. Paused test time
        // advances its clock, not the receiver facts or the historical classifier.
        for _ in 0..30 {
            respond(&mut handle, "GET", &fixture(false), 200).await;
        }
        handle
    });
    assert_eq!(
        app.execute(&request()).await.unwrap().result,
        Some(OperationResult::Unknown)
    );
    let mut handle = receiver.await.unwrap();
    let original = Original::retrieve(&app, &request().operation_id);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), handle.next_request())
            .await
            .is_err()
    );
    original
}

#[tokio::test(start_paused = true)]
async fn one_observation_preserves_original_and_exposes_ambiguity() {
    for scenario in [
        "healthy",
        "recreated",
        "superseding",
        "same-image",
        "retained-marker",
        "unavailable",
        "deadline",
    ] {
        let root = Workspace::new(scenario);
        let original = original_fixture(&root.0).await;
        let (client, mut handle) = client();
        let mut later = fixture(true);
        match scenario {
            "recreated" => later["metadata"]["uid"] = json!("replacement"),
            "superseding" | "retained-marker" => {
                later["metadata"]["generation"] = json!(4);
                later["status"]["observedGeneration"] = json!(4);
            },
            "same-image" => later["metadata"]["annotations"] = json!({}),
            _ => {},
        }
        let receiver = tokio::spawn(async move {
            if scenario == "deadline" {
                let (request, _send) = handle.next_request().await.unwrap();
                assert_eq!(request.method(), "GET");
                tokio::time::sleep(GET_BOUND + Duration::from_millis(50)).await;
            } else {
                respond(
                    &mut handle,
                    "GET",
                    &later,
                    if scenario == "unavailable" { 503 } else { 200 },
                )
                .await;
            }
            handle
        });
        let mut slot = Slot::open(&root.0);
        let evidence = slot.follow_up(&original, client.clone()).await;
        assert_eq!(evidence["earlier_result"], "UNKNOWN");
        assert_eq!(evidence["attribution"], "not_established");
        match scenario {
            "recreated" => assert_eq!(evidence["later"]["same_uid"], false),
            "superseding" | "retained-marker" => {
                assert_eq!(evidence["later"]["generation_relation"], "superseding");
            },
            "same-image" => assert_eq!(evidence["later"]["operation_marker_present"], false),
            "unavailable" => assert_eq!(evidence["later"]["acquisition"], "read_error"),
            "deadline" => assert_eq!(evidence["later"]["acquisition"], "deadline"),
            _ => assert_eq!(evidence["later"]["deployment_available_now"], true),
        }
        drop(slot);
        let app = application(&root.0, client.clone(), target());
        let reconnected = Original::retrieve(&app, &request().operation_id);
        assert_eq!(reconnected.bytes, original.bytes);
        assert_eq!(
            app.read_set_deployment_image_status(&request().operation_id)
                .unwrap(),
            SetDeploymentImageStatus::Unknown
        );
        assert_eq!(
            Slot::open(&root.0).follow_up(&reconnected, client).await,
            evidence
        );
        let mut handle = receiver.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), handle.next_request())
                .await
                .is_err()
        );
        println!(
            "[later observation] {scenario}: original_patch_requests=1 \
             followup_gets=1 followup_patches=0 {evidence}"
        );
    }
}

#[tokio::test]
async fn loss_child() {
    let Ok(root) = std::env::var("KAPSEL_LATER_LOSS_ROOT") else {
        return;
    };
    let (client, _) = client();
    let app = application(Path::new(&root), client, target());
    let original = Original::retrieve(&app, &request().operation_id);
    assert!(Slot::open(Path::new(&root)).reserve(&original));
    // Real process exit after acknowledged consumption, before GET or result persistence.
    std::process::exit(73);
}

#[tokio::test(start_paused = true)]
async fn process_loss_consumes_slot_without_reopening_action() {
    let root = Workspace::new("loss");
    let original = original_fixture(&root.0).await;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "loss_child", "--nocapture"])
        .env("KAPSEL_LATER_LOSS_ROOT", &root.0)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let (client, mut handle) = client();
    let app = application(&root.0, client.clone(), target());
    let reconnected = Original::retrieve(&app, &request().operation_id);
    assert_eq!(reconnected.bytes, original.bytes);
    assert_eq!(
        Slot::open(&root.0).follow_up(&reconnected, client).await["acquisition"],
        "consumed_without_evidence"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), handle.next_request())
            .await
            .is_err()
    );
}

async fn live_client(user_agent: &'static str) -> Client {
    use http_body_util::Limited;
    use tower_http::map_response_body::MapResponseBodyLayer;
    let mut config = kube::Config::infer().await.unwrap();
    config.default_retry = false;
    config.headers.push((
        http::header::USER_AGENT,
        http::HeaderValue::from_static(user_agent),
    ));
    let bound = MapResponseBodyLayer::new(|body| Limited::new(body, 1024 * 1024));
    kube::client::ClientBuilder::try_from(config)
        .unwrap()
        .with_layer(&bound)
        .build()
}

#[tokio::test]
#[ignore = "requires the disposable audited kind launcher"]
async fn live_slow_rollout() {
    assert_eq!(std::env::var("KAPSEL_LATER_KIND").as_deref(), Ok("1"));
    let root = Workspace::new("kind");
    let admin = live_client("kapsel-later-operator").await;
    let api = Api::<Deployment>::namespaced(admin.clone(), &request().namespace);
    let deployment = api.get(&request().deployment).await.unwrap();
    let approved = ApprovedTarget {
        uid: deployment.metadata.uid.unwrap(),
        resource_version: deployment.metadata.resource_version.unwrap(),
    };
    let execution = live_client("kapsel-later-execution").await;
    let mut app = application(&root.0, execution.clone(), approved.clone());
    let report = app.execute(&request()).await.unwrap();
    assert_eq!(report.result, Some(OperationResult::Unknown));
    let original = Original::retrieve(&app, &request().operation_id);
    drop(app);
    // Operator waits outside the prototype. The follow-up itself has only one two-second GET.
    tokio::time::timeout(Duration::from_secs(150), async {
        loop {
            let deployment = api.get(&request().deployment).await.unwrap();
            if describe(&original.statement, &deployment)["deployment_available_now"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .unwrap();
    let observer = live_client("kapsel-later-followup").await;
    let evidence = Slot::open(&root.0)
        .follow_up(&original, observer.clone())
        .await;
    assert_eq!(evidence["later"]["deployment_available_now"], true);
    assert_eq!(evidence["later"]["same_uid"], true);
    assert_eq!(evidence["later"]["generation_relation"], "same");
    assert_eq!(
        next_action(&evidence),
        "inspect_application_behavior_without_retry"
    );
    let mut restarted = application(&root.0, execution, approved);
    restarted.reconcile().await.unwrap();
    let reconnected = Original::retrieve(&restarted, &request().operation_id);
    assert_eq!(reconnected.bytes, original.bytes);
    assert_eq!(
        Slot::open(&root.0).follow_up(&reconnected, observer).await,
        evidence
    );
    println!(
        "[later live] {evidence} next_action={}",
        next_action(&evidence)
    );
}
