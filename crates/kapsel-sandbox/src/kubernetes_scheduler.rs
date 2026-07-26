//! Concrete Kubernetes scheduler for the fixed sandbox policy.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration};

use kube::{
    api::{Api, DynamicObject, PostParams},
    core::{ApiResource, GroupVersionKind},
    Client,
};
use serde_json::Value;

use crate::{
    kubernetes_policy,
    scheduler_state::{SchedulerStateClient, SchedulerStateError},
    DispatchLease, ProvisionedObject, ProvisionedTarget,
};

const FIELD_MANAGER: &str = "kapsel-sandbox-scheduler";

/// Runs the private scheduler continuously.
///
/// This offline slice deliberately stops after exact policy verification; runner creation remains
/// blocked on the later key-staging composition.
///
/// # Errors
///
/// Returns one bounded fixed diagnostic when time or scheduler reconciliation is unavailable.
pub async fn run_scheduler_role(
    state_endpoint: SocketAddr,
    state_ca_bundle: PathBuf,
    state_ca_sha256: [u8; 32],
    state_ca_root_count: u8,
    state_token: PathBuf,
    client: Client,
) -> Result<(), &'static str> {
    let state = SchedulerStateClient::new(
        state_endpoint,
        state_ca_bundle,
        state_ca_sha256,
        state_ca_root_count,
        state_token,
    )
    .map_err(|_| "scheduler state configuration is unavailable")?;
    let mut scheduler = Scheduler::new(state, client);
    loop {
        scheduler
            .run_once_with_clock(&|| unix_time().map_err(|_| SchedulerError::Clock))
            .await
            .map_err(|_| "scheduler reconciliation failed")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct Scheduler {
    state: SchedulerStateClient,
    client: Client,
    current_leases: HashMap<String, DispatchLease>,
}

impl Scheduler {
    fn new(state: SchedulerStateClient, client: Client) -> Self {
        Self {
            state,
            client,
            current_leases: HashMap::new(),
        }
    }

    #[cfg(test)]
    async fn run_once_at(&mut self, now: i64) -> Result<(), SchedulerError> {
        self.run_once_with_clock(&|| Ok(now)).await
    }

    #[allow(
        clippy::unused_self,
        reason = "test-only local codec time mirrors system-supplied listener time"
    )]
    fn appoint_test_operation_time(&self, now: i64) {
        #[cfg(test)]
        self.state.set_test_now(now);
        let _ = now;
    }

    async fn run_once_with_clock<F>(&mut self, clock: &F) -> Result<(), SchedulerError>
    where
        F: Fn() -> Result<i64, SchedulerError> + Sync,
    {
        let active = self.state.list_recoverable().await?;
        let mut foreign_lease = false;
        for active_run in &active {
            let run_id = &active_run.run_id;
            let Some(policy_verified) = active_run.policy_verified else {
                self.current_leases.remove(run_id);
                continue;
            };
            let now = clock()?;
            self.appoint_test_operation_time(now);
            let current = self.current_leases.get(run_id).cloned();
            let claimed = match current.as_ref() {
                None => self.claim_recovery(run_id, None).await,
                Some(current) if now < current.expires_at_unix_s.saturating_sub(5) => {
                    Ok(current.clone())
                },
                Some(current) => self.claim_recovery(run_id, Some(current)).await,
            };
            let lease = match claimed {
                Ok(lease) => lease,
                Err(SchedulerError::Busy) => {
                    foreign_lease = true;
                    continue;
                },
                Err(error) => return Err(error),
            };
            match self
                .provision_bounded(&lease, !policy_verified, clock)
                .await
            {
                Ok(()) => {},
                Err(SchedulerError::Deadline) => {
                    let deadline_now = clock()?;
                    self.appoint_test_operation_time(deadline_now);
                    match self.state.append_deadline(&lease).await {
                        Ok(()) | Err(SchedulerStateError::Denied) => {},
                        Err(error) => return Err(error.into()),
                    }
                },
                Err(error) => return Err(error),
            }
            self.current_leases.insert(run_id.clone(), lease);
        }
        if foreign_lease {
            return Ok(());
        }
        let dispatch_now = clock()?;
        self.appoint_test_operation_time(dispatch_now);
        let lease = match self.state.reserve_next().await {
            Ok(lease) => lease,
            Err(SchedulerStateError::NotFound | SchedulerStateError::Saturated) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let run_id = lease.run_id.clone();
        self.provision_bounded(&lease, true, clock).await?;
        self.current_leases.insert(run_id, lease);
        Ok(())
    }

    async fn provision_bounded<F>(
        &self,
        lease: &DispatchLease,
        allow_create: bool,
        clock: &F,
    ) -> Result<(), SchedulerError>
    where
        F: Fn() -> Result<i64, SchedulerError> + Sync,
    {
        tokio::time::timeout(
            Duration::from_secs(20),
            self.provision_exact_policy(lease, allow_create, clock),
        )
        .await
        .map_err(|_| SchedulerError::Kubernetes)?
    }

    async fn claim_recovery(
        &self,
        run_id: &str,
        previous: Option<&DispatchLease>,
    ) -> Result<DispatchLease, SchedulerError> {
        match self.state.recover_lease(run_id, previous).await {
            Ok(lease) => Ok(lease),
            Err(SchedulerStateError::Busy) => Err(SchedulerError::Busy),
            Err(error) => Err(error.into()),
        }
    }

    async fn provision_exact_policy<F>(
        &self,
        lease: &DispatchLease,
        allow_create: bool,
        clock: &F,
    ) -> Result<(), SchedulerError>
    where
        F: Fn() -> Result<i64, SchedulerError> + Sync,
    {
        let provisioning_now = clock()?;
        self.appoint_test_operation_time(provisioning_now);
        let specification =
            self.state
                .read_provisioning(lease)
                .await
                .map_err(|error| match error {
                    SchedulerStateError::Deadline => SchedulerError::Deadline,
                    _ => SchedulerError::State,
                })?;
        let rendered = kubernetes_policy::render(&specification.run_id);
        if rendered.len() != specification.required_objects.len()
            || rendered
                .iter()
                .zip(&specification.required_objects)
                .any(|(body, requirement)| {
                    body.identity != requirement.identity
                        || kubernetes_policy::content_digest(&body.body)
                            != requirement.content_digest
                })
        {
            return Err(SchedulerError::Policy);
        }

        let mut objects = Vec::with_capacity(rendered.len());
        for object in rendered {
            let lease_check_now = clock()?;
            self.appoint_test_operation_time(lease_check_now);
            self.state
                .read_provisioning(lease)
                .await
                .map_err(|error| match error {
                    SchedulerStateError::Deadline => SchedulerError::Deadline,
                    _ => SchedulerError::State,
                })?;
            let observed = create_or_observe(&self.client, &object.body, allow_create).await?;
            let metadata = observed
                .get("metadata")
                .and_then(Value::as_object)
                .ok_or(SchedulerError::Policy)?;
            let uid = metadata
                .get("uid")
                .and_then(Value::as_str)
                .ok_or(SchedulerError::Policy)?;
            let owner = metadata
                .get("labels")
                .and_then(Value::as_object)
                .and_then(|labels| labels.get("kapsel.dev/cleanup-owner"))
                .and_then(Value::as_str)
                .ok_or(SchedulerError::Policy)?;
            if owner != specification.cleanup_identity
                || kubernetes_policy::observed_content_digest(&object.body, &observed)
                    != Some(kubernetes_policy::content_digest(&object.body))
            {
                return Err(SchedulerError::Policy);
            }
            objects.push(ProvisionedObject {
                identity: object.identity,
                uid: uid.to_owned(),
                owner_label: owner.to_owned(),
                content_digest: kubernetes_policy::content_digest(&object.body),
            });
        }
        let namespace_uid = objects
            .first()
            .map(|object| object.uid.clone())
            .ok_or(SchedulerError::Policy)?;
        let verification_now = clock()?;
        self.appoint_test_operation_time(verification_now);
        self.state
            .commit_policy(
                lease,
                &ProvisionedTarget {
                    namespace_uid,
                    policy_revision: specification.policy_revision,
                    policy_inventory_digest: specification.policy_inventory_digest,
                    cleanup_identity: specification.cleanup_identity,
                    objects,
                },
            )
            .await?;
        let registration_now = clock()?;
        self.appoint_test_operation_time(registration_now);
        let inventory = self.state.read_external_resources(lease).await?;
        if !inventory.invocation_eligible {
            return Ok(());
        }
        let assignment_now = clock()?;
        self.appoint_test_operation_time(assignment_now);
        let _assignment = self.state.derive_assignment(lease).await?;
        Ok(())
    }
}

async fn create_or_observe(
    client: &Client,
    expected: &Value,
    allow_create: bool,
) -> Result<Value, SchedulerError> {
    let kind = expected
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(SchedulerError::Policy)?;
    let api_version = expected
        .get("apiVersion")
        .and_then(Value::as_str)
        .ok_or(SchedulerError::Policy)?;
    let metadata = expected
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or(SchedulerError::Policy)?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or(SchedulerError::Policy)?;
    let resource = api_resource(api_version, kind)?;
    let api: Api<DynamicObject> = match metadata.get("namespace").and_then(Value::as_str) {
        Some(namespace) => Api::namespaced_with(client.clone(), namespace, &resource),
        None if kind == "Namespace" => Api::all_with(client.clone(), &resource),
        None => return Err(SchedulerError::Policy),
    };
    if let Some(existing) = api
        .get_opt(name)
        .await
        .map_err(|_| SchedulerError::Kubernetes)?
    {
        return serde_json::to_value(existing).map_err(|_| SchedulerError::Policy);
    }
    if !allow_create {
        return Err(SchedulerError::Policy);
    }
    let object: DynamicObject =
        serde_json::from_value(expected.clone()).map_err(|_| SchedulerError::Policy)?;
    let created = match api
        .create(
            &PostParams {
                field_manager: Some(FIELD_MANAGER.into()),
                ..PostParams::default()
            },
            &object,
        )
        .await
    {
        Ok(created) => created,
        Err(kube::Error::Api(response)) if response.code == 409 => api
            .get(name)
            .await
            .map_err(|_| SchedulerError::Kubernetes)?,
        Err(_) => return Err(SchedulerError::Kubernetes),
    };
    serde_json::to_value(created).map_err(|_| SchedulerError::Policy)
}

pub(crate) fn api_resource(api_version: &str, kind: &str) -> Result<ApiResource, SchedulerError> {
    let (group, version) = api_version
        .split_once('/')
        .map_or(("", api_version), |(group, version)| (group, version));
    let plural = match kind {
        "Namespace" => "namespaces",
        "ConfigMap" => "configmaps",
        "PersistentVolumeClaim" => "persistentvolumeclaims",
        "Pod" => "pods",
        "Secret" => "secrets",
        "ServiceAccount" => "serviceaccounts",
        "Role" => "roles",
        "RoleBinding" => "rolebindings",
        "ResourceQuota" => "resourcequotas",
        "LimitRange" => "limitranges",
        "NetworkPolicy" => "networkpolicies",
        "Deployment" => "deployments",
        "Service" => "services",
        _ => return Err(SchedulerError::Policy),
    };
    Ok(ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(group, version, kind),
        plural,
    ))
}

fn unix_time() -> Result<i64, &'static str> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system time is out of range")
}

#[derive(Debug)]
pub(crate) enum SchedulerError {
    State,
    Kubernetes,
    Policy,
    Busy,
    Clock,
    Deadline,
}

impl From<SchedulerStateError> for SchedulerError {
    fn from(error: SchedulerStateError) -> Self {
        match error {
            SchedulerStateError::Busy => Self::Busy,
            SchedulerStateError::Deadline => Self::Deadline,
            _ => Self::State,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
    };

    use http::{Response, StatusCode};
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tower_test::mock;

    use super::*;
    use crate::{Scenario, Service};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: i64 = 1_774_051_200;
    const RUN: &str = "0123456789abcdef0123456789abcdef";

    fn fixture() -> (std::path::PathBuf, Service) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-scheduler-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("receipts")).unwrap();
        fs::set_permissions(root.join("receipts"), fs::Permissions::from_mode(0o700)).unwrap();
        let service = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW,
        )
        .unwrap();
        service
            .admit_with_run_id(&"1".repeat(32), Scenario::Healthy, NOW, RUN)
            .unwrap();
        (root, service)
    }

    fn build_scheduler(service: &Service, client: Client) -> Scheduler {
        Scheduler::new(
            SchedulerStateClient::local(service.clone(), "127.0.0.1:8081".parse().unwrap()),
            client,
        )
    }

    fn response(body: &Value, status: StatusCode) -> Response<kube::client::Body> {
        Response::builder()
            .status(status)
            .body(kube::client::Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn status(reason: &str, code: u16) -> Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": reason,
            "code": code
        })
    }

    fn observed(mut body: Value, index: usize) -> Value {
        body["metadata"]["uid"] = Value::String(format!("uid-{index}"));
        body["metadata"]["resourceVersion"] = Value::String("1".into());
        body["metadata"]["creationTimestamp"] = Value::String("2026-07-25T00:00:00Z".into());
        body
    }

    fn state_tls_fixture(root: &std::path::Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, [u8; 32]) {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/controller-transport/current");
        let certificate = root.join("scheduler-state.crt");
        let private_key = root.join("scheduler-state.key");
        let ca_bundle = root.join("scheduler-state-ca.crt");
        let state_token = root.join("scheduler-state-token");
        for (source_name, destination, mode) in [
            ("cert.pem", &certificate, 0o400),
            ("key.pem", &private_key, 0o600),
            ("ca.pem", &ca_bundle, 0o400),
        ] {
            fs::copy(source.join(source_name), destination).unwrap();
            fs::set_permissions(destination, fs::Permissions::from_mode(mode)).unwrap();
        }
        fs::write(&state_token, b"scheduler-state-token").unwrap();
        fs::set_permissions(&state_token, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = Sha256::digest(fs::read(&ca_bundle).unwrap()).into();
        (certificate, private_key, ca_bundle, state_token, digest)
    }

    fn token_review_client(count: usize) -> (Client, tokio::task::JoinHandle<()>) {
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            for _ in 0..count {
                let (request, send) = handle.next_request().await.unwrap();
                let body: Value =
                    serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                assert_eq!(body["spec"]["token"], "scheduler-state-token");
                send.send_response(response(
                    &serde_json::json!({
                        "apiVersion":"authentication.k8s.io/v1",
                        "kind":"TokenReview",
                        "metadata":{},
                        "spec":body["spec"],
                        "status":{
                            "authenticated":true,
                            "audiences":["https://kapsel.dev/sandbox/controller-state/v1"],
                            "user":{
                                "username":concat!(
                                    "system:serviceaccount:kapsel-sandbox-system:",
                                    "sandbox-scheduler"
                                ),
                                "uid":"scheduler-uid"
                            }
                        }
                    }),
                    StatusCode::CREATED,
                ));
            }
        });
        (Client::new(transport, "default"), server)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test helper keeps one concrete TLS composition explicit"
    )]
    async fn start_state_server(
        service: Service,
        certificate: PathBuf,
        private_key: PathBuf,
        ca_bundle: PathBuf,
        state_token: PathBuf,
        ca_digest: [u8; 32],
        now: i64,
        request_count: usize,
        lost_operation: Option<&'static str>,
    ) -> (
        SchedulerStateClient,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        crate::controller_state_transport::allow_test_bound_port(endpoint.port());
        let inputs = crate::controller_state_transport::server_inputs(certificate, private_key);
        let binding = crate::controller_state_transport::role_binding(
            crate::controller_state_transport::Role::Scheduler,
            "scheduler-uid".to_owned(),
        )
        .unwrap();
        let (token_review, token_review_server) = token_review_client(request_count);
        let state_server = tokio::spawn(async move {
            for _ in 0..request_count {
                let (connection, _) = listener.accept().await.unwrap();
                let service = service.clone();
                let result = crate::controller_state_transport::handle_connection(
                    connection,
                    &inputs,
                    &binding,
                    token_review.clone(),
                    move |payload| async move {
                        let response = crate::scheduler_state::handle(
                            &service,
                            &payload,
                            "127.0.0.1:8081".parse().unwrap(),
                            now,
                        );
                        if lost_operation.is_some_and(|operation| {
                            String::from_utf8_lossy(&payload)
                                .contains(&format!(r#""operation":"{operation}""#))
                        }) {
                            vec![0, 0, 0, 2, b'x']
                        } else {
                            response
                        }
                    },
                )
                .await;
                if lost_operation.is_some() && result.is_err() {
                    return;
                }
                result.unwrap();
            }
        });
        let client =
            SchedulerStateClient::new(endpoint, ca_bundle, ca_digest, 1, state_token).unwrap();
        (client, state_server, token_review_server)
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one production-adapter restart vector keeps ambiguous commit recovery contiguous"
    )]
    async fn remote_scheduler_recovers_lost_policy_commit_response_without_public_change() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        let (root, service) = fixture();
        let (certificate, private_key, ca_bundle, state_token, ca_digest) =
            state_tls_fixture(&root);
        let rendered = kubernetes_policy::render(RUN);
        let (kubernetes_transport, mut kubernetes_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let created = rendered
            .iter()
            .enumerate()
            .map(|(index, item)| observed(item.body.clone(), index))
            .collect::<Vec<_>>();
        let kubernetes_server = tokio::spawn(async move {
            for body in created {
                let (_, send) = kubernetes_handle.next_request().await.unwrap();
                send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
                let (request, send) = kubernetes_handle.next_request().await.unwrap();
                assert_eq!(request.method(), http::Method::POST);
                send.send_response(response(&body, StatusCode::CREATED));
            }
        });
        let (state, state_server, token_reviews) = start_state_server(
            service.clone(),
            certificate.clone(),
            private_key.clone(),
            ca_bundle.clone(),
            state_token.clone(),
            ca_digest,
            NOW + 1,
            15,
            Some("commit_policy"),
        )
        .await;
        let mut scheduler = Scheduler::new(state, Client::new(kubernetes_transport, "default"));
        assert!(scheduler.run_once_at(NOW + 1).await.is_err());
        state_server.await.unwrap();
        token_reviews.await.unwrap();
        kubernetes_server.await.unwrap();
        assert_eq!(service.scheduler_policy_status(RUN).unwrap(), Some(true));
        let after_commit = service.snapshot(RUN, NOW + 2).unwrap();
        let events_after_commit = service.events(RUN, 0, 64, NOW + 2).unwrap();
        assert!(after_commit.receiver_result.is_none());
        assert!(!after_commit.receipt_available);

        let (kubernetes_transport, mut kubernetes_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let observed_objects = rendered
            .iter()
            .enumerate()
            .map(|(index, item)| observed(item.body.clone(), index))
            .collect::<Vec<_>>();
        let kubernetes_server = tokio::spawn(async move {
            for body in observed_objects {
                let (request, send) = kubernetes_handle.next_request().await.unwrap();
                assert_eq!(request.method(), http::Method::GET);
                send.send_response(response(&body, StatusCode::OK));
            }
        });
        let (state, state_server, token_reviews) = start_state_server(
            service.clone(),
            certificate,
            private_key,
            ca_bundle,
            state_token,
            ca_digest,
            NOW + 32,
            17,
            None,
        )
        .await;
        let mut restarted = Scheduler::new(state, Client::new(kubernetes_transport, "default"));
        restarted.run_once_at(NOW + 32).await.unwrap();
        state_server.await.unwrap();
        token_reviews.await.unwrap();
        kubernetes_server.await.unwrap();
        let after_recovery = service.snapshot(RUN, NOW + 32).unwrap();
        assert_eq!(after_recovery.receiver_result, after_commit.receiver_result);
        assert_eq!(
            after_recovery.receipt_available,
            after_commit.receipt_available
        );
        assert_eq!(after_recovery.cleanup_state, after_commit.cleanup_state);
        assert_eq!(
            service.events(RUN, 0, 64, NOW + 32).unwrap(),
            events_after_commit
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table proves each remaining production-adapter ambiguity seam"
    )]
    async fn remote_scheduler_recovers_reserve_and_provisioning_response_loss() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        for (case, operation, first_requests, resources_created) in [
            ("reserve", "reserve_next", 2, false),
            ("provisioning", "read_provisioning", 3, false),
        ] {
            let (root, service) = fixture();
            let (certificate, private_key, ca_bundle, state_token, ca_digest) =
                state_tls_fixture(&root);
            let rendered = kubernetes_policy::render(RUN);
            let (kubernetes_transport, mut kubernetes_handle) = mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let first_kubernetes = if resources_created {
                let created = rendered
                    .iter()
                    .enumerate()
                    .map(|(index, item)| observed(item.body.clone(), index))
                    .collect::<Vec<_>>();
                tokio::spawn(async move {
                    for body in created {
                        let (_, send) = kubernetes_handle.next_request().await.unwrap();
                        send.send_response(response(
                            &status("NotFound", 404),
                            StatusCode::NOT_FOUND,
                        ));
                        let (_, send) = kubernetes_handle.next_request().await.unwrap();
                        send.send_response(response(&body, StatusCode::CREATED));
                    }
                })
            } else {
                tokio::spawn(async move {
                    assert!(tokio::time::timeout(
                        Duration::from_millis(100),
                        kubernetes_handle.next_request(),
                    )
                    .await
                    .is_err());
                })
            };
            let (state, state_server, token_reviews) = start_state_server(
                service.clone(),
                certificate.clone(),
                private_key.clone(),
                ca_bundle.clone(),
                state_token.clone(),
                ca_digest,
                NOW + 1,
                first_requests,
                Some(operation),
            )
            .await;
            let mut scheduler = Scheduler::new(state, Client::new(kubernetes_transport, "default"));
            assert!(scheduler.run_once_at(NOW + 1).await.is_err(), "{case}");
            state_server.await.unwrap();
            token_reviews.await.unwrap();
            first_kubernetes.await.unwrap();
            let after_loss = service.snapshot(RUN, NOW + 2).unwrap();
            let events_after_loss = service.events(RUN, 0, 64, NOW + 2).unwrap();
            assert!(after_loss.receiver_result.is_none(), "{case}");
            assert!(!after_loss.receipt_available, "{case}");

            let (kubernetes_transport, mut kubernetes_handle) = mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let expected_objects = rendered
                .iter()
                .enumerate()
                .map(|(index, item)| observed(item.body.clone(), index))
                .collect::<Vec<_>>();
            let second_kubernetes = tokio::spawn(async move {
                for body in expected_objects {
                    let (_, send) = kubernetes_handle.next_request().await.unwrap();
                    if resources_created {
                        send.send_response(response(&body, StatusCode::OK));
                    } else {
                        send.send_response(response(
                            &status("NotFound", 404),
                            StatusCode::NOT_FOUND,
                        ));
                        let (_, send) = kubernetes_handle.next_request().await.unwrap();
                        send.send_response(response(&body, StatusCode::CREATED));
                    }
                }
            });
            let (state, state_server, token_reviews) = start_state_server(
                service.clone(),
                certificate,
                private_key,
                ca_bundle,
                state_token,
                ca_digest,
                NOW + 32,
                17,
                None,
            )
            .await;
            let mut restarted = Scheduler::new(state, Client::new(kubernetes_transport, "default"));
            restarted.run_once_at(NOW + 32).await.unwrap();
            state_server.await.unwrap();
            token_reviews.await.unwrap();
            second_kubernetes.await.unwrap();
            let after_recovery = service.snapshot(RUN, NOW + 32).unwrap();
            assert_eq!(
                after_recovery.receiver_result, after_loss.receiver_result,
                "{case}"
            );
            assert_eq!(
                after_recovery.receipt_available, after_loss.receipt_available,
                "{case}"
            );
            assert_eq!(
                after_recovery.cleanup_state, after_loss.cleanup_state,
                "{case}"
            );
            assert_eq!(
                service.events(RUN, 0, 64, NOW + 32).unwrap(),
                events_after_loss,
                "{case}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn lost_registration_response_then_exact_retry_converges() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        let (root, service) = fixture();
        let lease = service.dispatch_next(NOW + 1).unwrap();
        let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
        let objects = kubernetes_policy::render(RUN)
            .into_iter()
            .enumerate()
            .map(|(index, object)| ProvisionedObject {
                identity: object.identity,
                uid: format!("policy-uid-{index}"),
                owner_label: specification.cleanup_identity.clone(),
                content_digest: kubernetes_policy::content_digest(&object.body),
            })
            .collect();
        service
            .verify_provisioned_target(
                &lease,
                &ProvisionedTarget {
                    namespace_uid: "policy-uid-0".into(),
                    policy_revision: specification.policy_revision,
                    policy_inventory_digest: specification.policy_inventory_digest,
                    cleanup_identity: specification.cleanup_identity.clone(),
                    objects,
                },
                NOW + 1,
            )
            .unwrap();
        let slot = service
            .external_resource_inventory(&lease, NOW + 1)
            .unwrap()
            .slots
            .remove(0);
        let (certificate, private_key, ca_bundle, state_token, ca_digest) =
            state_tls_fixture(&root);
        let (client, server, token_reviews) = start_state_server(
            service.clone(),
            certificate.clone(),
            private_key.clone(),
            ca_bundle.clone(),
            state_token.clone(),
            ca_digest,
            NOW + 1,
            1,
            Some("register_external_resource"),
        )
        .await;
        assert_eq!(
            client
                .register_external_resource(
                    &lease,
                    &slot,
                    "external-uid-0",
                    &specification.cleanup_identity,
                )
                .await,
            Err(SchedulerStateError::Transport)
        );
        server.await.unwrap();
        token_reviews.await.unwrap();
        assert_eq!(
            service
                .external_resource_inventory(&lease, NOW + 1)
                .unwrap()
                .slots[0]
                .uid
                .as_deref(),
            Some("external-uid-0")
        );

        let (client, server, token_reviews) = start_state_server(
            service.clone(),
            certificate,
            private_key,
            ca_bundle,
            state_token,
            ca_digest,
            NOW + 1,
            1,
            None,
        )
        .await;
        client
            .register_external_resource(
                &lease,
                &slot,
                "external-uid-0",
                &specification.cleanup_identity,
            )
            .await
            .unwrap();
        server.await.unwrap();
        token_reviews.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn token_review_outage_prevents_state_and_kubernetes_dispatch() {
        let _network = crate::controller_state_transport::tests::TEST_NETWORK
            .lock()
            .await;
        let (root, service) = fixture();
        let baseline = service.events(RUN, 0, 64, NOW).unwrap();
        let (certificate, private_key, ca_bundle, state_token, ca_digest) =
            state_tls_fixture(&root);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        crate::controller_state_transport::allow_test_bound_port(endpoint.port());
        let inputs = crate::controller_state_transport::server_inputs(certificate, private_key);
        let binding = crate::controller_state_transport::role_binding(
            crate::controller_state_transport::Role::Scheduler,
            "scheduler-uid".to_owned(),
        )
        .unwrap();
        let (token_transport, mut token_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let token_server = tokio::spawn(async move {
            let (_, send) = token_handle.next_request().await.unwrap();
            send.send_response(response(
                &status("Unavailable", 503),
                StatusCode::SERVICE_UNAVAILABLE,
            ));
        });
        let dispatches = Arc::new(AtomicUsize::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let state_server = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.unwrap();
            crate::controller_state_transport::handle_connection(
                connection,
                &inputs,
                &binding,
                Client::new(token_transport, "default"),
                move |_| async move {
                    observed_dispatches.fetch_add(1, Ordering::Relaxed);
                    vec![0, 0, 0, 1, b'x']
                },
            )
            .await
            .unwrap();
        });
        let state =
            SchedulerStateClient::new(endpoint, ca_bundle, ca_digest, 1, state_token).unwrap();
        let (kubernetes_transport, mut kubernetes_handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let no_kubernetes = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(100), kubernetes_handle.next_request())
                .await
                .is_err()
        });
        let mut scheduler = Scheduler::new(state, Client::new(kubernetes_transport, "default"));
        assert!(scheduler.run_once_at(NOW).await.is_err());
        state_server.await.unwrap();
        token_server.await.unwrap();
        assert!(no_kubernetes.await.unwrap());
        assert_eq!(dispatches.load(Ordering::Relaxed), 0);
        assert_eq!(service.events(RUN, 0, 64, NOW).unwrap(), baseline);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn creates_exact_policy_then_restart_observes_before_fresh_dispatch() {
        let (root, service) = fixture();
        let rendered = kubernetes_policy::render(RUN);
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server_bodies = rendered
            .iter()
            .enumerate()
            .map(|(index, item)| observed(item.body.clone(), index))
            .collect::<Vec<_>>();
        let server = tokio::spawn(async move {
            for body in &server_bodies {
                let name = body["metadata"]["name"].as_str().unwrap();
                let (get, send) = handle.next_request().await.unwrap();
                assert_eq!(get.method(), http::Method::GET);
                assert!(get.uri().path().ends_with(&format!("/{name}")));
                send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
                let (create, send) = handle.next_request().await.unwrap();
                assert_eq!(create.method(), http::Method::POST);
                assert!(!create.uri().path().ends_with(&format!("/{name}")));
                assert_eq!(
                    create.uri().query(),
                    Some("&fieldManager=kapsel-sandbox-scheduler")
                );
                let request_body: Value =
                    serde_json::from_slice(&create.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                let mut expected_request = body.clone();
                for key in ["creationTimestamp", "resourceVersion", "uid"] {
                    expected_request["metadata"]
                        .as_object_mut()
                        .unwrap()
                        .remove(key);
                }
                assert_eq!(request_body, expected_request);
                send.send_response(response(body, StatusCode::CREATED));
            }
        });
        let mut scheduler = build_scheduler(&service, Client::new(transport, "default"));
        scheduler.run_once_at(NOW + 1).await.unwrap();
        server.await.unwrap();
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);

        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let observed_bodies = rendered
            .iter()
            .enumerate()
            .map(|(index, item)| observed(item.body.clone(), index))
            .collect::<Vec<_>>();
        let server = tokio::spawn(async move {
            for body in observed_bodies {
                let (request, send) = handle.next_request().await.unwrap();
                assert_eq!(request.method(), http::Method::GET);
                send.send_response(response(&body, StatusCode::OK));
            }
        });
        let service = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW + 32,
        )
        .unwrap();
        let mut restarted = build_scheduler(&service, Client::new(transport, "default"));
        restarted.run_once_at(NOW + 32).await.unwrap();
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn create_conflict_is_observed_once_and_still_requires_exact_content() {
        let expected = kubernetes_policy::render(RUN).remove(0).body;
        let observed = observed(expected.clone(), 0);
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(response(
                &status("AlreadyExists", 409),
                StatusCode::CONFLICT,
            ));
            let (retry, send) = handle.next_request().await.unwrap();
            assert_eq!(retry.method(), http::Method::GET);
            send.send_response(response(&observed, StatusCode::OK));
        });
        let actual = create_or_observe(&Client::new(transport, "default"), &expected, true)
            .await
            .unwrap();
        assert_eq!(
            kubernetes_policy::observed_content_digest(&expected, &actual),
            Some(kubernetes_policy::content_digest(&expected))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn expired_clock_cannot_commit_policy_verification() {
        let (root, service) = fixture();
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        tokio::spawn(async move {
            while let Some((_, send)) = handle.next_request().await {
                send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
            }
        });
        let mut scheduler = build_scheduler(&service, Client::new(transport, "default"));
        let clock = std::sync::atomic::AtomicI64::new(NOW + 1);
        let result = scheduler
            .run_once_with_clock(&|| Ok(clock.fetch_add(31, Ordering::Relaxed)))
            .await;
        assert!(result.is_err());
        let verified: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT policy_verified FROM runs WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!verified);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn foreign_lease_does_not_starve_later_expired_recovery() {
        let (root, service) = fixture();
        let later = "fedcba9876543210fedcba9876543210";
        service
            .admit_with_run_id(&"2".repeat(32), Scenario::Healthy, NOW, later)
            .unwrap();
        let first = service.dispatch_next(NOW + 20).unwrap();
        assert_eq!(first.run_id, RUN);
        let second = service.dispatch_next(NOW + 1).unwrap();
        assert_eq!(second.run_id, later);

        let rendered = kubernetes_policy::render(later);
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            for (index, object) in rendered.into_iter().enumerate() {
                let (_, send) = handle.next_request().await.unwrap();
                send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
                let (_, send) = handle.next_request().await.unwrap();
                send.send_response(response(&observed(object.body, index), StatusCode::CREATED));
            }
        });
        let mut scheduler = build_scheduler(&service, Client::new(transport, "default"));
        scheduler.run_once_at(NOW + 32).await.unwrap();
        server.await.unwrap();
        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        let first_verified: bool = connection
            .query_row(
                "SELECT policy_verified FROM runs WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        let (second_verified, second_epoch): (bool, i64) = connection
            .query_row(
                "SELECT policy_verified, lease_epoch FROM runs WHERE run_id = ?1",
                [later],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!first_verified);
        assert!(second_verified);
        assert_eq!(second_epoch, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn invoked_run_is_skipped_before_lease_or_kubernetes_mutation() {
        let (root, service) = fixture();
        let lease = service.dispatch_next(NOW + 1).unwrap();
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE runs SET application_invoked = 1 WHERE run_id = ?1",
                [RUN],
            )
            .unwrap();
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let no_request = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(50), handle.next_request())
                .await
                .is_err()
        });
        let mut scheduler = build_scheduler(&service, Client::new(transport, "default"));
        scheduler.run_once_at(NOW + 2).await.unwrap();
        assert!(no_request.await.unwrap());
        let epoch: i64 = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT lease_epoch FROM runs WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(epoch, lease.epoch);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn hostile_observation_fails_before_policy_verification() {
        let (root, service) = fixture();
        let rendered = kubernetes_policy::render(RUN);
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let mut first = observed(rendered[0].body.clone(), 0);
        first["metadata"]["labels"]["kapsel.dev/cleanup-owner"] =
            Value::String("cleanup-other".into());
        tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(response(&first, StatusCode::OK));
        });
        let mut scheduler = build_scheduler(&service, Client::new(transport, "default"));
        assert!(scheduler.run_once_at(NOW + 1).await.is_err());
        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        let verified: bool = connection
            .query_row(
                "SELECT policy_verified FROM runs WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!verified);
        fs::remove_dir_all(root).unwrap();
    }
}
