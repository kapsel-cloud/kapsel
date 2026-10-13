//! Concrete Kubernetes Deployment-image adapter for the effect gateway.
//!
//! This module owns one conditional strategic image patch and bounded Deployment observation. It
//! is not a generic Kubernetes adapter interface.

use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use kube::{
    api::{Api, Patch, PatchParams},
    Client,
};
use serde_json::{json, Value};
use tokio::time::Instant;

use super::facts::{ApplyOutcome, ReceiverObservation, TargetIdentity};
use crate::gateway::{
    DeploymentImageAdapter, DispatchPermission, SetDeploymentImageRequest, TargetReadError,
    TargetRejection,
};

const OPERATION_ANNOTATION: &str = "kapsel.dev/kap0038-operation-id";
const OBSERVATION_ATTEMPTS_MAX: usize = 180;
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
const OBSERVATION_DEADLINE: Duration = Duration::from_secs(180);
const PROVIDER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const _: () = assert!(OBSERVATION_ATTEMPTS_MAX > 0);
const _: () = assert!(
    (OBSERVATION_ATTEMPTS_MAX as u64 - 1) * OBSERVATION_INTERVAL.as_secs()
        < OBSERVATION_DEADLINE.as_secs()
);

pub(crate) struct KubernetesDeploymentImageAdapter {
    client: Client,
    observation_attempts: usize,
    observation_interval: Duration,
    observation_deadline: Duration,
    provider_request_timeout: Duration,
}

impl KubernetesDeploymentImageAdapter {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            observation_attempts: OBSERVATION_ATTEMPTS_MAX,
            observation_interval: OBSERVATION_INTERVAL,
            observation_deadline: OBSERVATION_DEADLINE,
            provider_request_timeout: PROVIDER_REQUEST_TIMEOUT,
        }
    }

    fn deployments(&self, namespace: &str) -> Api<Deployment> {
        Api::namespaced(self.client.clone(), namespace)
    }

    async fn observe_until_terminal(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
        deadline: Instant,
    ) -> ReceiverObservation {
        let mut latest_observation = ReceiverObservation::unknown();
        for read_index in 0..self.observation_attempts {
            if Instant::now() >= deadline {
                return ReceiverObservation::unknown();
            }
            let read_deadline = deadline.min(Instant::now() + self.provider_request_timeout);
            let response = tokio::time::timeout_at(
                read_deadline,
                self.deployments(&request.namespace)
                    .get(&request.deployment),
            )
            .await;
            if Instant::now() >= deadline {
                return ReceiverObservation::unknown();
            }

            latest_observation = match response {
                Ok(Ok(deployment)) => receiver_observation(request, &deployment),
                Ok(Err(_)) | Err(_) => ReceiverObservation::unknown(),
            };

            if latest_observation.observation_is_complete(request, outcome)
                || read_index + 1 == self.observation_attempts
            {
                break;
            }

            tokio::time::sleep(self.observation_interval).await;
        }
        latest_observation
    }
}

impl DeploymentImageAdapter for KubernetesDeploymentImageAdapter {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        let deployment = tokio::time::timeout(
            self.provider_request_timeout,
            self.deployments(&request.namespace)
                .get(&request.deployment),
        )
        .await
        .map_err(|_| TargetReadError::Transient)?
        .map_err(target_get_error)?;

        let container_exists = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .is_some_and(|spec| {
                spec.containers
                    .iter()
                    .any(|container| container.name == request.container)
            });
        if !container_exists {
            return Err(TargetReadError::Permanent(
                TargetRejection::ContainerNotFound,
            ));
        }

        let deployment_uid = deployment
            .metadata
            .uid
            .ok_or(TargetReadError::Permanent(TargetRejection::InvalidTarget))?;
        let resource_version = deployment
            .metadata
            .resource_version
            .ok_or(TargetReadError::Permanent(TargetRejection::InvalidTarget))?;

        let target = TargetIdentity {
            deployment_uid,
            resource_version,
        };
        target
            .validate()
            .map_err(|_| TargetReadError::Permanent(TargetRejection::InvalidTarget))?;
        Ok(target)
    }

    async fn apply(&mut self, permission: DispatchPermission) -> Result<ApplyOutcome, ()> {
        let (request, target) = permission.into_payload();
        let deployment = tokio::time::timeout(
            self.provider_request_timeout,
            self.deployments(&request.namespace).patch(
                &request.deployment,
                &PatchParams::default(),
                &Patch::Strategic(deployment_patch_document(&request, &target)),
            ),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        let deployment_uid = deployment.metadata.uid.ok_or(())?;
        if deployment_uid != target.deployment_uid {
            return Err(());
        }

        let resource_version = deployment.metadata.resource_version.ok_or(())?;
        Ok(ApplyOutcome {
            accepted: true,
            requested_generation: deployment.metadata.generation,
            deployment_uid: Some(deployment_uid),
            resource_version: Some(resource_version),
        })
    }

    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        let deadline = Instant::now() + self.observation_deadline;
        Ok(tokio::time::timeout_at(
            deadline,
            self.observe_until_terminal(request, outcome, deadline),
        )
        .await
        .unwrap_or_else(|_| ReceiverObservation::unknown()))
    }
}

fn target_get_error(error: kube::Error) -> TargetReadError {
    match error {
        kube::Error::Api(response) if response.code == 404 => {
            TargetReadError::Permanent(TargetRejection::DeploymentNotFound)
        },
        _ => TargetReadError::Transient,
    }
}

fn deployment_patch_document(
    request: &SetDeploymentImageRequest,
    target: &TargetIdentity,
) -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": request.deployment,
            "namespace": request.namespace,
            "uid": target.deployment_uid,
            "resourceVersion": target.resource_version,
            "annotations": {
                OPERATION_ANNOTATION: request.operation_id,
            },
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": request.container,
                        "image": request.immutable_image_digest,
                    }],
                },
            },
        },
    })
}

fn receiver_observation(
    request: &SetDeploymentImageRequest,
    deployment: &Deployment,
) -> ReceiverObservation {
    let image = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .and_then(|spec| {
            spec.containers
                .iter()
                .find(|container| container.name == request.container)
        })
        .and_then(|container| container.image.clone());

    let operation_marker = deployment
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(OPERATION_ANNOTATION))
        .cloned();

    let status = deployment.status.as_ref();
    let conditions = status.and_then(|status| status.conditions.as_ref());
    let rollout_condition = conditions.and_then(|conditions| {
        conditions
            .iter()
            .find(|condition| {
                condition.type_ == "Progressing"
                    && condition.status == "False"
                    && condition.reason.as_deref() == Some("ProgressDeadlineExceeded")
            })
            .or_else(|| {
                conditions
                    .iter()
                    .find(|condition| condition.type_ == "Available" && condition.status == "True")
            })
    });

    ReceiverObservation {
        deployment_uid: deployment.metadata.uid.clone(),
        resource_version: deployment.metadata.resource_version.clone(),
        current_generation: deployment.metadata.generation,
        observed_generation: status.and_then(|status| status.observed_generation),
        image,
        operation_marker,
        desired_replicas: deployment.spec.as_ref().and_then(|spec| spec.replicas),
        updated_replicas: status.map(|status| status.updated_replicas.unwrap_or(0)),
        available_replicas: status.map(|status| status.available_replicas.unwrap_or(0)),
        unavailable_replicas: status.map(|status| status.unavailable_replicas.unwrap_or(0)),
        rollout_condition_type: rollout_condition.map(|condition| condition.type_.clone()),
        rollout_condition_status: rollout_condition.map(|condition| condition.status.clone()),
        rollout_condition_reason: rollout_condition.and_then(|condition| condition.reason.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        future::{pending, Future},
        sync::atomic::Ordering,
    };

    use http::{Method, Request, Response, StatusCode};
    use kube::client::Body;
    use serde_json::json;
    use tower_test::mock;

    use super::*;
    use crate::gateway::{OperationResult, ValidatedRequest};

    fn request() -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: "op-001".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "resource-version-1".into(),
        }
    }

    fn apply_outcome() -> ApplyOutcome {
        ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
        }
    }

    fn deployment_response(progress_deadline_exceeded: bool) -> Value {
        let request = request();
        let conditions = if progress_deadline_exceeded {
            json!([{
                "type": "Progressing",
                "status": "False",
                "reason": "ProgressDeadlineExceeded"
            }])
        } else {
            json!([{
                "type": "Available",
                "status": "True",
                "reason": "MinimumReplicasAvailable"
            }])
        };
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "deployment-uid-1",
                "resourceVersion": "resource-version-2",
                "generation": 2,
                "annotations": {
                    OPERATION_ANNOTATION: "op-001"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {"app": "agent-api"}
                },
                "template": {
                    "metadata": {
                        "labels": {"app": "agent-api"}
                    },
                    "spec": {
                        "containers": [{
                            "name": "api",
                            "image": request.immutable_image_digest
                        }]
                    }
                }
            },
            "status": {
                "observedGeneration": 2,
                "replicas": 1,
                "updatedReplicas": i32::from(!progress_deadline_exceeded),
                "availableReplicas": i32::from(!progress_deadline_exceeded),
                "unavailableReplicas": i32::from(progress_deadline_exceeded),
                "conditions": conditions
            }
        })
    }

    fn test_adapter() -> (
        KubernetesDeploymentImageAdapter,
        mock::Handle<Request<Body>, Response<Body>>,
    ) {
        test_adapter_with_attempts(1)
    }

    fn test_adapter_with_attempts(
        observation_attempts: usize,
    ) -> (
        KubernetesDeploymentImageAdapter,
        mock::Handle<Request<Body>, Response<Body>>,
    ) {
        let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(mock_service, "default");
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        adapter.observation_attempts = observation_attempts;
        adapter.observation_interval = Duration::ZERO;
        adapter.observation_deadline = Duration::from_secs(1);
        (adapter, handle)
    }

    // Drive the real kube client, retaining every request. An unused reply detects premature
    // completion; an extra request detects retries or read-budget overruns. No lifecycle model.
    async fn exchange<T>(
        work: impl Future<Output = T>,
        mut handle: mock::Handle<Request<Body>, Response<Body>>,
        replies: Vec<(StatusCode, Value)>,
    ) -> (T, Vec<Request<Body>>) {
        tokio::pin!(work);
        let mut replies = replies.into_iter();
        let mut wires = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = &mut work => {
                        assert!(replies.next().is_none(), "completed before planned receiver I/O");
                        return (result, wires);
                    }
                    next = handle.next_request() => {
                        let (wire, send) = next.unwrap();
                        assert_eq!(
                            wire.uri().path(),
                            "/apis/apps/v1/namespaces/demo/deployments/agent-api"
                        );
                        let (status, document) = replies
                            .next()
                            .expect("unexpected receiver request");
                        wires.push(wire);
                        send.send_response(
                            Response::builder()
                                .status(status)
                                .body(Body::from(serde_json::to_vec(&document).unwrap()))
                                .unwrap()
                        );
                    }
                }
            }
        })
        .await
        .expect("bounded adapter exchange")
    }

    #[tokio::test]
    async fn exchange_controls_detect_unused_replies_and_additional_reads() {
        for extra_read in [false, true] {
            let (mut adapter, handle) = test_adapter_with_attempts(2);
            let checked = tokio::spawn(async move {
                if extra_read {
                    let _ = exchange(
                        adapter.observe(&request(), &apply_outcome()),
                        handle,
                        vec![(StatusCode::OK, progressing_response())],
                    )
                    .await;
                } else {
                    let _ = exchange(
                        adapter.identify(&request()),
                        handle,
                        vec![(StatusCode::OK, deployment_response(false)); 2],
                    )
                    .await;
                }
            });
            let error = checked.await.unwrap_err();
            assert!(error.is_panic());
            let payload = error.into_panic();
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap();
            assert!(
                message.contains(if extra_read {
                    "unexpected receiver request"
                } else {
                    "completed before planned receiver I/O"
                }),
                "{message}"
            );
        }
    }

    fn progressing_response() -> Value {
        let mut response = deployment_response(false);
        response["status"]["updatedReplicas"] = json!(0);
        response["status"]["availableReplicas"] = json!(0);
        response["status"]["unavailableReplicas"] = json!(1);
        response["status"]["conditions"] = json!([{
            "type": "Progressing",
            "status": "True",
            "reason": "ReplicaSetUpdated"
        }]);
        response
    }

    #[tokio::test]
    async fn identification_binds_one_get_to_target_and_error_partitions() {
        let request = request();
        for (pointer, value, rejection) in [
            ("", Value::Null, None),
            (
                "/spec/template/spec/containers/0/name",
                json!("other"),
                Some(TargetRejection::ContainerNotFound),
            ),
            (
                "/metadata/uid",
                Value::Null,
                Some(TargetRejection::InvalidTarget),
            ),
            (
                "/metadata/resourceVersion",
                Value::Null,
                Some(TargetRejection::InvalidTarget),
            ),
        ] {
            let (mut adapter, handle) = test_adapter();
            let mut document = deployment_response(false);
            if !pointer.is_empty() {
                *document.pointer_mut(pointer).unwrap() = value;
            }
            let (result, wires) = exchange(
                adapter.identify(&request),
                handle,
                vec![(StatusCode::OK, document)],
            )
            .await;
            assert_eq!(wires.len(), 1);
            assert_eq!(wires[0].method(), Method::GET);
            let expected = rejection.map_or_else(
                || {
                    Ok(TargetIdentity {
                        deployment_uid: "deployment-uid-1".into(),
                        resource_version: "resource-version-2".into(),
                    })
                },
                |reason| Err(TargetReadError::Permanent(reason)),
            );
            assert_eq!(result, expected, "{pointer}");
        }
        for (code, expected) in [
            (
                StatusCode::NOT_FOUND,
                TargetReadError::Permanent(TargetRejection::DeploymentNotFound),
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                TargetReadError::Transient,
            ),
        ] {
            let (mut adapter, handle) = test_adapter();
            let document = json!({"kind": "Status", "status": "Failure", "reason": "NotFound",
                "message": "fixture read failure", "code": code.as_u16()});
            let (result, wires) =
                exchange(adapter.identify(&request), handle, vec![(code, document)]).await;
            assert_eq!(result, Err(expected));
            assert_eq!(wires.len(), 1);
            assert_eq!(wires[0].method(), Method::GET);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn target_and_apply_requests_each_have_a_deadline() {
        for apply in [false, true] {
            let (mut adapter, mut handle) = test_adapter();
            let responder = tokio::spawn(async move {
                let (wire, _send) = handle.next_request().await.unwrap();
                assert_eq!(
                    wire.method(),
                    if apply { Method::PATCH } else { Method::GET }
                );
                pending::<()>().await;
            });
            let start = Instant::now();
            if apply {
                assert_eq!(
                    adapter
                        .apply(crate::gateway::dispatch_permission_for_test(
                            &request(),
                            &target()
                        ))
                        .await,
                    Err(())
                );
            } else {
                assert_eq!(
                    adapter.identify(&request()).await,
                    Err(TargetReadError::Transient)
                );
            }
            assert_eq!(start.elapsed(), Duration::from_secs(10));
            responder.abort();
        }
    }

    #[tokio::test]
    async fn conditional_patch_wire_and_response_binding_are_exact() {
        let request = request();
        for (pointer, value) in [
            ("", Value::Null),
            ("/metadata/uid", Value::Null),
            ("/metadata/resourceVersion", Value::Null),
            ("/metadata/uid", json!("replacement-uid")),
        ] {
            let (mut adapter, handle) = test_adapter();
            let mut document = deployment_response(false);
            if !pointer.is_empty() {
                *document.pointer_mut(pointer).unwrap() = value;
            }
            let permission = crate::gateway::dispatch_permission_for_test(&request, &target());
            let (result, mut wires) = exchange(
                adapter.apply(permission),
                handle,
                vec![(StatusCode::OK, document)],
            )
            .await;
            if pointer.is_empty() {
                assert_eq!(result, Ok(apply_outcome()));
            } else {
                assert_eq!(result, Err(()), "{pointer}");
            }
            assert_eq!(wires.len(), 1);
            let wire = wires.pop().unwrap();
            assert_eq!(wire.method(), Method::PATCH);
            let query: BTreeMap<_, _> = wire
                .uri()
                .query()
                .unwrap()
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .collect();
            assert!(!query.contains_key("fieldManager"));
            assert!(!query.contains_key("force"));
            assert_eq!(
                wire.headers().get("content-type").unwrap(),
                "application/strategic-merge-patch+json"
            );
            let body: Value =
                serde_json::from_slice(&wire.into_body().collect_bytes().await.unwrap()).unwrap();
            // Independent wire vector, not the production patch-document constructor.
            assert_eq!(
                body,
                json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": "agent-api",
                        "namespace": "demo",
                        "uid": "deployment-uid-1",
                        "resourceVersion": "resource-version-1",
                        "annotations": { "kapsel.dev/kap0038-operation-id": "op-001" }
                    },
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                "name": "api",
                                "image": request.immutable_image_digest
                            }]
                            }
                        }
                    }
                })
            );
        }
    }

    #[test]
    fn deployment_decoding_preserves_selected_receiver_facts() {
        let mut document = deployment_response(false);
        document["metadata"]["uid"] = json!("decoded-uid");
        document["metadata"]["resourceVersion"] = json!("opaque-version");
        document["metadata"]["generation"] = json!(17);
        document["metadata"]["annotations"][OPERATION_ANNOTATION] = json!("decoded-marker");
        document["spec"]["replicas"] = json!(7);
        document["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                json!({"name": "other", "image": "not-the-selected-image"}),
            );
        document["status"]["observedGeneration"] = json!(19);
        document["status"]["updatedReplicas"] = json!(5);
        document["status"]["availableReplicas"] = json!(3);
        document["status"]["unavailableReplicas"] = json!(2);
        document["status"]["conditions"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"
            }));
        let deployment = serde_json::from_value(document).unwrap();
        assert_eq!(
            receiver_observation(&request(), &deployment),
            ReceiverObservation {
                deployment_uid: Some("decoded-uid".into()),
                resource_version: Some("opaque-version".into()),
                current_generation: Some(17),
                observed_generation: Some(19),
                image: Some(request().immutable_image_digest),
                operation_marker: Some("decoded-marker".into()),
                desired_replicas: Some(7),
                updated_replicas: Some(5),
                available_replicas: Some(3),
                unavailable_replicas: Some(2),
                rollout_condition_type: Some("Progressing".into()),
                rollout_condition_status: Some("False".into()),
                rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
            }
        );
    }

    #[tokio::test]
    async fn observation_scripts_bind_fields_and_terminal_reads() {
        let request = request();
        let outcome = apply_outcome();
        let mut stale = deployment_response(false);
        stale["status"]["observedGeneration"] = json!(1);
        let mut reason = deployment_response(false);
        reason["status"]["conditions"][0]["reason"] = json!("DifferentObservedReason");
        let mut nonzero = deployment_response(false);
        nonzero["status"]
            .as_object_mut()
            .unwrap()
            .remove("unavailableReplicas");
        let mut omitted = deployment_response(false);
        omitted["spec"]["replicas"] = json!(0);
        for field in [
            "updatedReplicas",
            "availableReplicas",
            "unavailableReplicas",
        ] {
            omitted["status"].as_object_mut().unwrap().remove(field);
        }
        for (case, documents, expected) in [
            (
                "stale",
                vec![stale, deployment_response(true)],
                OperationResult::Failed,
            ),
            ("reason", vec![reason], OperationResult::Succeeded),
            ("zeros", vec![omitted], OperationResult::Succeeded),
            ("nonzero", vec![nonzero], OperationResult::Succeeded),
            (
                "settling",
                vec![
                    progressing_response(),
                    progressing_response(),
                    deployment_response(true),
                ],
                OperationResult::Failed,
            ),
            (
                "budget",
                vec![progressing_response(); 3],
                OperationResult::Unknown,
            ),
        ] {
            let attempts = documents.len() + usize::from(case != "budget");
            let (mut adapter, handle) = test_adapter_with_attempts(attempts);
            let replies = documents
                .into_iter()
                .map(|value| (StatusCode::OK, value))
                .collect();
            let (result, wires) =
                exchange(adapter.observe(&request, &outcome), handle, replies).await;
            let observation = result.unwrap();
            assert!(wires.iter().all(|wire| wire.method() == Method::GET));
            assert_eq!(
                observation.classify(&ValidatedRequest::try_from(&request).unwrap(), &outcome),
                expected,
                "{case}"
            );
            assert_eq!(
                observation.observation_is_complete(&request, &outcome),
                case != "budget"
            );
            assert_eq!(observation.current_generation, Some(2));
            assert_eq!(observation.observed_generation, Some(2));
            if case == "reason" {
                assert_eq!(
                    observation.rollout_condition_type.as_deref(),
                    Some("Available")
                );
                assert_eq!(
                    observation.rollout_condition_status.as_deref(),
                    Some("True")
                );
                assert_eq!(
                    observation.rollout_condition_reason.as_deref(),
                    Some("DifferentObservedReason")
                );
            } else if case == "zeros" {
                assert_eq!(
                    (
                        observation.updated_replicas,
                        observation.available_replicas,
                        observation.unavailable_replicas
                    ),
                    (Some(0), Some(0), Some(0))
                );
            } else if case == "nonzero" {
                assert_eq!(
                    (
                        observation.updated_replicas,
                        observation.available_replicas,
                        observation.unavailable_replicas
                    ),
                    (Some(1), Some(1), Some(0))
                );
            }
        }
    }

    #[tokio::test]
    async fn missing_deployment_exhausts_read_budget_without_receiver_facts() {
        let request = request();
        let outcome = apply_outcome();
        let (mut adapter, handle) = test_adapter_with_attempts(180);
        let missing =
            json!({"kind": "Status", "status": "Failure", "reason": "NotFound", "code": 404});
        let (result, wires) = exchange(
            adapter.observe(&request, &outcome),
            handle,
            vec![(StatusCode::NOT_FOUND, missing); 180],
        )
        .await;
        assert_eq!(result.unwrap(), ReceiverObservation::unknown());
        assert_eq!(wires.len(), 180);
        assert!(wires.iter().all(|wire| wire.method() == Method::GET));
    }

    #[tokio::test]
    async fn provisional_signals_do_not_preempt_sufficient_classifier_evidence() {
        let request = request();
        let outcome = apply_outcome();
        for (pointer, value) in [
            ("/status/unavailableReplicas", json!(1)),
            ("/metadata/uid", json!("replacement")),
            ("/metadata/generation", json!(3)),
            (
                "/metadata/annotations/kapsel.dev~1kap0038-operation-id",
                json!("other"),
            ),
            (
                "/spec/template/spec/containers/0/image",
                json!(format!("registry.example/api@sha256:{}", "a".repeat(64))),
            ),
        ] {
            let (mut adapter, handle) = test_adapter_with_attempts(3);
            let mut provisional = deployment_response(false);
            *provisional.pointer_mut(pointer).unwrap() = value;
            if pointer == "/metadata/generation" {
                provisional["status"]["observedGeneration"] = json!(3);
            }
            let (result, wires) = exchange(
                adapter.observe(&request, &outcome),
                handle,
                vec![
                    (StatusCode::OK, provisional),
                    (StatusCode::OK, deployment_response(false)),
                ],
            )
            .await;
            assert_eq!(wires.len(), 2);
            assert!(wires.iter().all(|wire| wire.method() == Method::GET));
            assert_eq!(
                result
                    .unwrap()
                    .classify(&ValidatedRequest::try_from(&request).unwrap(), &outcome),
                OperationResult::Succeeded,
                "{pointer}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn production_policy_observes_beyond_thirty_seconds_and_bounds_read_count() {
        for ready_after in [60, 181] {
            let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
            let mut adapter =
                KubernetesDeploymentImageAdapter::new(Client::new(mock_service, "default"));
            let start = Instant::now();
            let responder = tokio::spawn(async move {
                let mut reads = 0;
                while let Some((request, send)) = handle.next_request().await {
                    assert_eq!(request.method(), Method::GET);
                    reads += 1;
                    let settled = start.elapsed() >= Duration::from_secs(ready_after);
                    let response = if settled {
                        deployment_response(false)
                    } else {
                        progressing_response()
                    };
                    send.send_response(Response::new(Body::from(
                        serde_json::to_vec(&response).unwrap(),
                    )));
                }
                reads
            });

            let request = request();
            let outcome = apply_outcome();
            let observation = adapter.observe(&request, &outcome).await.unwrap();
            let expected = if ready_after == 60 {
                OperationResult::Succeeded
            } else {
                OperationResult::Unknown
            };

            assert_eq!(
                observation.classify(&ValidatedRequest::try_from(&request).unwrap(), &outcome),
                expected
            );
            assert_eq!(start.elapsed().as_secs(), ready_after.min(179));

            drop(adapter);
            assert_eq!(responder.await.unwrap(), (ready_after + 1).min(180));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn interrupted_passes_only_resume_on_invocation_with_fresh_budgets() {
        let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let mut adapter =
            KubernetesDeploymentImageAdapter::new(Client::new(mock_service, "default"));
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = reads.clone();
        let responder = tokio::spawn(async move {
            while let Some((request, send)) = handle.next_request().await {
                assert_eq!(request.method(), Method::GET);
                counted.fetch_add(1, Ordering::Relaxed);
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&progressing_response()).unwrap(),
                )));
            }
        });

        let start = Instant::now();
        for _ in 0..3 {
            assert!(tokio::time::timeout(
                Duration::from_secs(60),
                adapter.observe(&request(), &apply_outcome()),
            )
            .await
            .is_err());
            let before = reads.load(Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(20)).await;
            assert_eq!(reads.load(Ordering::Relaxed), before);
        }
        assert!(start.elapsed() > OBSERVATION_DEADLINE);

        let resumed = Instant::now();
        let before = reads.load(Ordering::Relaxed);
        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();
        assert!(!observation.observation_is_complete(&request(), &apply_outcome()));
        assert_eq!(resumed.elapsed(), Duration::from_secs(179));
        assert_eq!(reads.load(Ordering::Relaxed) - before, 180);

        drop(adapter);
        responder.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn observation_rejects_evidence_at_the_elapsed_boundary() {
        for response_after in [9, 10, 11] {
            let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
            let mut adapter =
                KubernetesDeploymentImageAdapter::new(Client::new(mock_service, "default"));
            adapter.observation_deadline = Duration::from_secs(10);
            let responder = tokio::spawn(async move {
                let (_, send) = handle.next_request().await.unwrap();
                tokio::time::sleep(Duration::from_secs(response_after)).await;
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&deployment_response(false)).unwrap(),
                )));
            });
            let start = Instant::now();
            let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();
            assert_eq!(
                observation.observation_is_complete(&request(), &apply_outcome()),
                response_after < 10
            );
            assert!(start.elapsed() <= Duration::from_secs(10));
            responder.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_reads_have_individual_deadlines_and_a_shared_pass_deadline() {
        let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let mut adapter =
            KubernetesDeploymentImageAdapter::new(Client::new(mock_service, "default"));
        let responder = tokio::spawn(async move {
            let mut pending_responses = Vec::new();
            while let Some((request, send)) = handle.next_request().await {
                assert_eq!(request.method(), Method::GET);
                pending_responses.push(send);
            }
            pending_responses.len()
        });
        let start = Instant::now();
        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();
        assert_eq!(observation, ReceiverObservation::unknown());
        assert_eq!(start.elapsed(), Duration::from_secs(180));

        drop(adapter);
        assert_eq!(responder.await.unwrap(), 17);
    }
}
