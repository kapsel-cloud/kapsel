//! Concrete Kubernetes scheduler for the fixed sandbox policy.

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use kube::{
    api::{Api, DynamicObject, PostParams},
    core::{ApiResource, GroupVersionKind},
    Client,
};
use serde_json::Value;

use crate::{
    kubernetes_policy, DispatchLease, ProvisionedObject, ProvisionedTarget, Service, ServiceError,
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
    service: Service,
    client: Client,
    handoff_endpoint: SocketAddr,
) -> Result<(), &'static str> {
    let mut scheduler = Scheduler::new(service, client, handoff_endpoint);
    loop {
        scheduler
            .run_once_with_clock(&|| unix_time().map_err(|_| SchedulerError::Clock))
            .await
            .map_err(|_| "scheduler reconciliation failed")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct Scheduler {
    service: Service,
    client: Client,
    current_leases: HashMap<String, DispatchLease>,
    handoff_endpoint: SocketAddr,
}

impl Scheduler {
    fn new(service: Service, client: Client, handoff_endpoint: SocketAddr) -> Self {
        Self {
            service,
            client,
            current_leases: HashMap::new(),
            handoff_endpoint,
        }
    }

    #[cfg(test)]
    async fn run_once_at(&mut self, now: i64) -> Result<(), SchedulerError> {
        self.run_once_with_clock(&|| Ok(now)).await
    }

    async fn run_once_with_clock<F>(&mut self, clock: &F) -> Result<(), SchedulerError>
    where
        F: Fn() -> Result<i64, SchedulerError> + Sync,
    {
        let active = self.service.recoverable_runs()?;
        let mut foreign_lease = false;
        for run_id in &active {
            let Some(policy_verified) = self.service.scheduler_policy_status(run_id)? else {
                self.current_leases.remove(run_id);
                continue;
            };
            let now = clock()?;
            let claimed = self.current_leases.get(run_id).map_or_else(
                || self.claim_recovery(run_id, None, now),
                |current| {
                    if now < current.expires_at_unix_s.saturating_sub(5) {
                        Ok(current.clone())
                    } else {
                        self.claim_recovery(run_id, Some(current), now)
                    }
                },
            );
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
                    match self.service.record_deadline(run_id, deadline_now) {
                        Ok(()) | Err(ServiceError::InvalidTransition) => {},
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
        let lease = match self.service.dispatch_next(dispatch_now) {
            Ok(lease) => lease,
            Err(ServiceError::RunNotFound | ServiceError::ActiveSaturated) => return Ok(()),
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

    fn claim_recovery(
        &self,
        run_id: &str,
        previous: Option<&DispatchLease>,
        now: i64,
    ) -> Result<DispatchLease, SchedulerError> {
        match self.service.recover_run(run_id, previous, now) {
            Ok(lease) => Ok(lease),
            Err(ServiceError::LeaseBusy) => Err(SchedulerError::Busy),
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
        let specification = self
            .service
            .provisioning_specification(lease, clock()?)
            .map_err(|error| match error {
                ServiceError::DeadlineExceeded => SchedulerError::Deadline,
                _ => SchedulerError::Service,
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
            self.service
                .provisioning_specification(lease, clock()?)
                .map_err(|error| match error {
                    ServiceError::DeadlineExceeded => SchedulerError::Deadline,
                    _ => SchedulerError::Service,
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
        self.service.verify_provisioned_target(
            lease,
            &ProvisionedTarget {
                namespace_uid,
                policy_revision: specification.policy_revision,
                policy_inventory_digest: specification.policy_inventory_digest,
                cleanup_identity: specification.cleanup_identity,
                objects,
            },
            verification_now,
        )?;
        let _assignment =
            self.service
                .handoff_assignment(lease, self.handoff_endpoint, clock()?)?;
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
    Service,
    Kubernetes,
    Policy,
    Busy,
    Clock,
    Deadline,
}

impl From<ServiceError> for SchedulerError {
    fn from(_: ServiceError) -> Self {
        Self::Service
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use http::{Response, StatusCode};
    use tower_test::mock;

    use super::*;
    use crate::Scenario;

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
        let mut scheduler = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
        scheduler.run_once_at(NOW + 1).await.unwrap();
        server.await.unwrap();
        assert_eq!(scheduler.service.recoverable_runs().unwrap(), vec![RUN]);

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
        let mut restarted = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
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
        let mut scheduler = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
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
        let mut scheduler = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
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
        let mut scheduler = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
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
        let mut scheduler = Scheduler::new(
            service,
            Client::new(transport, "default"),
            "127.0.0.1:8081".parse().unwrap(),
        );
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
