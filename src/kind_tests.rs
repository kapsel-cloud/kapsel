//! Explicit live-cluster proof for the KAP-0038 Deployment-image operation.

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

use ed25519_dalek::SigningKey;

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{Container, Namespace, PodSpec, PodTemplateSpec},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use kube::{
    api::{Api, DeleteParams, PostParams},
    Client,
};

use crate::{
    inspect_receipt, DeploymentImageAdapter, ExactAuthorization, FaultPoint, Gateway, GatewayError,
    InspectionLimits, InspectionStatus, KubernetesDeploymentImageAdapter, OperationResult,
    OperationState, ReceiptSettings, ReceiptTrust, SetDeploymentImageRequest,
};

const NAMESPACE: &str = "kapsel-kap0038";
const FAILED_NAMESPACE: &str = "kapsel-kap0038-failed";
const DEPLOYMENT: &str = "image-demo";
const FAILED_DEPLOYMENT: &str = "image-demo-failed";
const TARGET_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
);
const FAILED_IMAGE: &str = concat!(
    "registry.example.invalid/kapsel/unhealthy@sha256:",
    "1111111111111111111111111111111111111111111111111111111111111111"
);
const FIXTURE_IMAGE: &str = "registry.k8s.io/pause:3.10.1";

struct CountingAdapter {
    inner: KubernetesDeploymentImageAdapter,
    apply_calls: usize,
}

impl CountingAdapter {
    fn new(client: Client) -> Self {
        Self {
            inner: KubernetesDeploymentImageAdapter::new(client),
            apply_calls: 0,
        }
    }
}

impl DeploymentImageAdapter for CountingAdapter {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<crate::TargetIdentity, crate::TargetReadError> {
        self.inner.identify(request).await
    }

    async fn apply(
        &mut self,
        request: &SetDeploymentImageRequest,
        target: &crate::TargetIdentity,
    ) -> Result<crate::ApplyOutcome, ()> {
        self.apply_calls += 1;
        self.inner.apply(request, target).await
    }

    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<crate::ReceiverObservation, ()> {
        self.inner.observe(request).await
    }
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_changes_exactly_one_container_through_the_gateway() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(NAMESPACE.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_gateway_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind gateway proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.delete(NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind cleanup exceeded 10 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(cleanup.is_ok(), "kind fixture cleanup failed");
    proof.unwrap();
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_failed_rollout_recovers_and_inspects_classifier_complete_receipt() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(FAILED_NAMESPACE.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_failed_rollout_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind failed-rollout proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.delete(FAILED_NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind failed-rollout cleanup exceeded 10 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(
        cleanup.is_ok(),
        "kind failed-rollout fixture cleanup failed"
    );
    proof.unwrap();
}

async fn run_gateway_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(NAMESPACE, DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, DEPLOYMENT).await?;
    let request = request();
    let authorization = ExactAuthorization {
        authorization_id: "kind-auth-001".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    };
    let directory = private_test_directory_for("success");
    let database = directory.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&database)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    let mut adapter = KubernetesDeploymentImageAdapter::new(client.clone());
    match gateway
        .run_once_with_adapter(&mut adapter, Some(FaultPoint::ApplyReturned))
        .await
    {
        Err(GatewayError::InjectedFault) => {},
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("kind fault injection did not stop after the patch".into()),
    }
    assert_eq!(
        gateway.get(&request.operation_id)?,
        Some(OperationState::ApplyStarted)
    );
    drop(gateway);
    let mut gateway = Gateway::open_for_test(&database)?;

    let state = gateway.run_once(client).await?;

    assert_eq!(state, Some(OperationState::ReceiverObserved));
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Succeeded)
    );
    let observed = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.get(DEPLOYMENT),
    )
    .await??;
    let containers = &observed
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .ok_or("missing fixture pod spec")?
        .containers;
    assert_eq!(containers.len(), 2);
    assert_eq!(
        containers
            .iter()
            .find(|container| container.name == "target")
            .and_then(|container| container.image.as_deref()),
        Some(TARGET_IMAGE)
    );
    assert_eq!(
        containers
            .iter()
            .find(|container| container.name == "untouched")
            .and_then(|container| container.image.as_deref()),
        Some(FIXTURE_IMAGE)
    );
    drop(gateway);
    fs::remove_dir_all(directory)?;
    Ok(())
}

async fn run_failed_rollout_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), FAILED_NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(FAILED_NAMESPACE, FAILED_DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, FAILED_DEPLOYMENT).await?;
    let request = failed_request();
    let authorization = ExactAuthorization {
        authorization_id: "kind-failed-auth-001".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    };
    let directory = private_test_directory_for("failed");
    let receipt_directory = directory.join("receipts");
    fs::create_dir(&receipt_directory)?;
    fs::set_permissions(&receipt_directory, fs::Permissions::from_mode(0o700))?;
    let database = directory.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&database)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    let mut first_adapter = CountingAdapter::new(client.clone());
    match gateway
        .run_once_with_adapter(&mut first_adapter, Some(FaultPoint::ApplyReturned))
        .await
    {
        Err(GatewayError::InjectedFault) => {},
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("kind failed-rollout fault did not stop after patch".into()),
    }
    assert_eq!(first_adapter.apply_calls, 1);
    drop(gateway);

    let mut gateway = Gateway::open_for_test(&database)?;
    let mut recovery_adapter = CountingAdapter::new(client);
    assert_eq!(
        gateway
            .run_once_with_adapter(&mut recovery_adapter, None)
            .await?,
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(recovery_adapter.apply_calls, 0);
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Failed)
    );

    let receipt_seed = [41_u8; 32];
    assert_eq!(
        gateway.finalize_receipt_once(&ReceiptSettings {
            signing_seed: &receipt_seed,
            key_id: "kind-failed-receipt-key",
            output_directory: &receipt_directory,
        })?,
        Some(OperationState::Finalized)
    );
    let reference = gateway
        .receipt_reference(&request.operation_id)?
        .ok_or("missing failed-rollout receipt reference")?;
    let receipt_bytes = fs::read(reference.path)?;
    let trust = ReceiptTrust {
        key_id: "kind-failed-receipt-key".into(),
        public_key: SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()?;
    let report = inspect_receipt(&receipt_bytes, &trust, 150, InspectionLimits::default());
    assert_eq!(report.status(), InspectionStatus::Inspected);
    let statement = report.statement().ok_or("missing inspected statement")?;
    assert_eq!(statement.result(), OperationResult::Failed);
    assert_eq!(
        statement.rollout_condition_reason(),
        Some("ProgressDeadlineExceeded")
    );
    assert_eq!(statement.observed_image(), Some(FAILED_IMAGE));
    assert_eq!(
        statement.observed_operation_marker(),
        Some("kind-failed-op-001")
    );
    drop(gateway);
    fs::remove_dir_all(directory)?;
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn wait_for_deployment_rollout(
    deployments: &Api<Deployment>,
    deployment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let deployment = deployments.get(deployment_name).await?;
            let generation = deployment.metadata.generation;
            let ready = deployment.status.as_ref().is_some_and(|status| {
                status.observed_generation == generation
                    && status.available_replicas == Some(1)
                    && status.updated_replicas == Some(1)
            });
            if ready {
                return Ok::<(), kube::Error>(());
            }
            println!("waiting for the disposable kind fixture rollout");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| "fixture rollout exceeded 30 seconds")??;
    Ok(())
}

fn request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-op-001".into(),
        namespace: NAMESPACE.into(),
        deployment: DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: TARGET_IMAGE.into(),
    }
}

fn failed_request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-failed-op-001".into(),
        namespace: FAILED_NAMESPACE.into(),
        deployment: FAILED_DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: FAILED_IMAGE.into(),
    }
}

fn fixture_deployment_for(namespace: &str, deployment: &str) -> Deployment {
    let labels = BTreeMap::from([("app".into(), deployment.into())]);
    Deployment {
        metadata: ObjectMeta {
            name: Some(deployment.into()),
            namespace: Some(namespace.into()),
            ..ObjectMeta::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..LabelSelector::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![
                        Container {
                            name: "target".into(),
                            image: Some(FIXTURE_IMAGE.into()),
                            ..Container::default()
                        },
                        Container {
                            name: "untouched".into(),
                            image: Some(FIXTURE_IMAGE.into()),
                            ..Container::default()
                        },
                    ],
                    ..PodSpec::default()
                }),
            },
            progress_deadline_seconds: Some(15),
            ..DeploymentSpec::default()
        }),
        ..Deployment::default()
    }
}

fn private_test_directory_for(scenario: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kapsel-kind-proof-{}-{scenario}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::canonicalize(path).unwrap()
}
