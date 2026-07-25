//! UID-safe Kubernetes cleanup for the fixed sandbox deployment.

use std::time::Duration;

use kube::{
    api::{Api, DeleteParams, DynamicObject, ListParams, Preconditions},
    Client,
};
use rusqlite::OptionalExtension;
use serde_json::Value;

use crate::{
    kubernetes_scheduler::api_resource, object_identity_parts, CleanupAbsenceEvidence,
    CleanupObjectAbsence, Service, ServiceError,
};

const CLEANUP_ESCALATION_SECONDS: i64 = 15 * 60;

pub(crate) struct CleanupCandidate {
    run_id: String,
    cleanup_identity: String,
    namespace_uid: String,
    state: String,
    started_at: Option<i64>,
    escalated: bool,
    objects: Vec<RecordedObject>,
}

#[derive(Clone)]
struct RecordedObject {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    owner_label: String,
}

/// Runs the private UID-safe cleanup reconciler continuously.
///
/// # Errors
///
/// Returns a bounded diagnostic only when durable cleanup ownership or time is unavailable. A
/// Kubernetes request failure remains retryable durable cleanup state and does not stop the role.
pub async fn run_cleanup_role(service: Service, client: Client) -> Result<(), &'static str> {
    let reconciler = CleanupReconciler { service, client };
    loop {
        reconciler
            .run_once(unix_time()?)
            .await
            .map_err(|_| "cleanup reconciliation failed")?;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct CleanupReconciler {
    service: Service,
    client: Client,
}

impl CleanupReconciler {
    async fn run_once(&self, now: i64) -> Result<(), CleanupError> {
        for candidate in self.service.cleanup_candidates()? {
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                self.reconcile_candidate(&candidate, now),
            )
            .await
            .map_err(|_| CleanupError::Kubernetes)
            .and_then(|result| result);
            if result.is_err() {
                self.record_failure(&candidate, now)?;
            }
        }
        Ok(())
    }

    async fn reconcile_candidate(
        &self,
        candidate: &CleanupCandidate,
        now: i64,
    ) -> Result<(), CleanupError> {
        if candidate.state == "pending" {
            self.service.start_cleanup(
                &candidate.run_id,
                &candidate.cleanup_identity,
                &candidate.namespace_uid,
                now,
            )?;
        }
        scan_external_orphans(&self.client, candidate).await?;
        for object in candidate
            .objects
            .iter()
            .filter(|object| object.kind != "Namespace")
        {
            if should_request_delete(candidate, object) {
                request_uid_safe_delete(&self.client, object).await?;
            }
        }
        for object in candidate
            .objects
            .iter()
            .filter(|object| object.kind == "Namespace")
        {
            request_uid_safe_delete(&self.client, object).await?;
        }
        let mut evidence = Vec::with_capacity(candidate.objects.len());
        for object in &candidate.objects {
            let present = observe_exact(&self.client, object).await?;
            evidence.push(CleanupObjectAbsence {
                kind: object.kind.clone(),
                namespace: object.namespace.clone(),
                name: object.name.clone(),
                uid: object.uid.clone(),
                owner_label: object.owner_label.clone(),
                present,
            });
        }
        if evidence.iter().all(|object| !object.present) {
            self.service.complete_cleanup(
                &candidate.run_id,
                &candidate.cleanup_identity,
                &CleanupAbsenceEvidence {
                    namespace_uid: candidate.namespace_uid.clone(),
                    objects: evidence,
                },
                now,
            )?;
        } else {
            self.escalate_if_due(candidate, now)?;
        }
        Ok(())
    }

    fn record_failure(&self, candidate: &CleanupCandidate, now: i64) -> Result<(), CleanupError> {
        match self.service.cleanup_record_state(&candidate.run_id)? {
            Some(state) if state == "pending" => {
                self.service.start_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )?;
                self.service.fail_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )?;
            },
            Some(state) if state == "running" => {
                self.service.fail_cleanup(
                    &candidate.run_id,
                    &candidate.cleanup_identity,
                    &candidate.namespace_uid,
                    now,
                )?;
            },
            Some(state) if state == "failed" => {},
            _ => return Err(CleanupError::Service),
        }
        self.escalate_if_due(candidate, now)
    }

    fn escalate_if_due(&self, candidate: &CleanupCandidate, now: i64) -> Result<(), CleanupError> {
        let started_at = candidate.started_at.unwrap_or(now);
        if !candidate.escalated && now.saturating_sub(started_at) >= CLEANUP_ESCALATION_SECONDS {
            self.service
                .escalate_cleanup(&candidate.run_id, &candidate.cleanup_identity, now)?;
        }
        Ok(())
    }
}

fn should_request_delete(candidate: &CleanupCandidate, object: &RecordedObject) -> bool {
    object.kind == "Namespace"
        || object
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != format!("sandbox-{}", candidate.run_id))
}

async fn scan_external_orphans(
    client: &Client,
    candidate: &CleanupCandidate,
) -> Result<(), CleanupError> {
    const EXTERNAL_KINDS: [&str; 5] = [
        "ServiceAccount",
        "ConfigMap",
        "Secret",
        "PersistentVolumeClaim",
        "Pod",
    ];
    let selector = format!("kapsel.dev/cleanup-owner={}", candidate.cleanup_identity);
    for kind in EXTERNAL_KINDS {
        let resource = api_resource("v1", kind).map_err(|_| CleanupError::Ownership)?;
        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), "kapsel-sandbox-runners", &resource);
        let objects = api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|_| CleanupError::Kubernetes)?;
        for observed in objects {
            let value = serde_json::to_value(observed).map_err(|_| CleanupError::Ownership)?;
            let metadata = value
                .get("metadata")
                .and_then(Value::as_object)
                .ok_or(CleanupError::Ownership)?;
            let name = metadata
                .get("name")
                .and_then(Value::as_str)
                .ok_or(CleanupError::Ownership)?;
            let uid = metadata
                .get("uid")
                .and_then(Value::as_str)
                .ok_or(CleanupError::Ownership)?;
            let Some(recorded) = candidate.objects.iter().find(|object| {
                object.kind == kind
                    && object.namespace.as_deref() == Some("kapsel-sandbox-runners")
                    && object.name == name
                    && object.uid == uid
            }) else {
                return Err(CleanupError::Ownership);
            };
            validate_observed_identity(recorded, &value)?;
        }
    }
    Ok(())
}

async fn request_uid_safe_delete(
    client: &Client,
    object: &RecordedObject,
) -> Result<(), CleanupError> {
    let Some(observed) = get_object(client, object).await? else {
        return Ok(());
    };
    validate_observed_identity(object, &observed)?;
    let api = object_api(client, object)?;
    api.delete(
        &object.name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(object.uid.clone()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        },
    )
    .await
    .map_err(|_| CleanupError::Kubernetes)?;
    Ok(())
}

async fn observe_exact(client: &Client, object: &RecordedObject) -> Result<bool, CleanupError> {
    let Some(observed) = get_object(client, object).await? else {
        return Ok(false);
    };
    validate_observed_identity(object, &observed)?;
    Ok(true)
}

async fn get_object(
    client: &Client,
    object: &RecordedObject,
) -> Result<Option<Value>, CleanupError> {
    let api = object_api(client, object)?;
    api.get_opt(&object.name)
        .await
        .map_err(|_| CleanupError::Kubernetes)?
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| CleanupError::Ownership)
}

fn object_api(
    client: &Client,
    object: &RecordedObject,
) -> Result<Api<DynamicObject>, CleanupError> {
    let api_version = match object.kind.as_str() {
        "Namespace"
        | "ConfigMap"
        | "PersistentVolumeClaim"
        | "Pod"
        | "Secret"
        | "ServiceAccount"
        | "ResourceQuota"
        | "LimitRange"
        | "Service" => "v1",
        "Role" | "RoleBinding" => "rbac.authorization.k8s.io/v1",
        "NetworkPolicy" => "networking.k8s.io/v1",
        "Deployment" => "apps/v1",
        _ => return Err(CleanupError::Ownership),
    };
    let resource = api_resource(api_version, &object.kind).map_err(|_| CleanupError::Ownership)?;
    match object.namespace.as_deref() {
        Some(namespace) => Ok(Api::namespaced_with(client.clone(), namespace, &resource)),
        None if object.kind == "Namespace" => Ok(Api::all_with(client.clone(), &resource)),
        None => Err(CleanupError::Ownership),
    }
}

fn validate_observed_identity(
    expected: &RecordedObject,
    observed: &Value,
) -> Result<(), CleanupError> {
    let metadata = observed
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or(CleanupError::Ownership)?;
    let uid = metadata
        .get("uid")
        .and_then(Value::as_str)
        .ok_or(CleanupError::Ownership)?;
    let owner = metadata
        .get("labels")
        .and_then(Value::as_object)
        .and_then(|labels| labels.get("kapsel.dev/cleanup-owner"))
        .and_then(Value::as_str)
        .ok_or(CleanupError::Ownership)?;
    if uid != expected.uid || owner != expected.owner_label {
        return Err(CleanupError::Ownership);
    }
    Ok(())
}

impl Service {
    fn cleanup_candidates(&self) -> Result<Vec<CleanupCandidate>, ServiceError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT cleanup_records.run_id, cleanup_records.cleanup_identity, ",
                "cleanup_records.namespace_uid, cleanup_records.state, ",
                "cleanup_records.started_at, cleanup_records.escalated FROM cleanup_records ",
                "JOIN runs ON runs.run_id = cleanup_records.run_id ",
                "WHERE cleanup_records.active = 1 AND cleanup_records.eligible = 1 ",
                "AND cleanup_records.resource_state = 'owned' ORDER BY runs.admission_order"
            ))
            .map_err(super::storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .map_err(super::storage_error)?;
        let records = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(super::storage_error)?;
        records
            .into_iter()
            .map(
                |(run_id, cleanup_identity, namespace_uid, state, started_at, escalated)| {
                    let namespace_uid = namespace_uid.ok_or(ServiceError::OwnershipMismatch)?;
                    let mut statement = connection
                        .prepare(concat!(
                            "SELECT identity, uid, owner_label FROM provisioned_object_owners ",
                            "WHERE run_id = ?1 ORDER BY uid"
                        ))
                        .map_err(super::storage_error)?;
                    let objects = statement
                        .query_map([&run_id], |row| {
                            let identity = row.get::<_, String>(0)?;
                            let (kind, namespace, name) = object_identity_parts(&identity)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                            Ok(RecordedObject {
                                kind,
                                namespace,
                                name,
                                uid: row.get(1)?,
                                owner_label: row.get(2)?,
                            })
                        })
                        .map_err(super::storage_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(super::storage_error)?;
                    if objects.is_empty()
                        || objects
                            .iter()
                            .any(|object| object.owner_label != cleanup_identity)
                    {
                        return Err(ServiceError::OwnershipMismatch);
                    }
                    Ok(CleanupCandidate {
                        run_id,
                        cleanup_identity,
                        namespace_uid,
                        state,
                        started_at,
                        escalated,
                        objects,
                    })
                },
            )
            .collect()
    }

    fn cleanup_record_state(&self, run_id: &str) -> Result<Option<String>, ServiceError> {
        super::bounded_identity(run_id)?;
        self.connection()?
            .query_row(
                "SELECT state FROM cleanup_records WHERE run_id = ?1 AND active = 1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::storage_error)
    }

    fn escalate_cleanup(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        now: i64,
    ) -> Result<(), ServiceError> {
        super::bounded_identity(run_id)?;
        super::bounded_identity(cleanup_identity)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                concat!(
                    "UPDATE cleanup_records SET escalated = 1 WHERE run_id = ?1 ",
                    "AND cleanup_identity = ?2 AND active = 1 AND eligible = 1 ",
                    "AND state = 'failed' AND escalated = 0 AND started_at IS NOT NULL ",
                    "AND ?3 - started_at >= ?4"
                ),
                rusqlite::params![run_id, cleanup_identity, now, CLEANUP_ESCALATION_SECONDS],
            )
            .map_err(super::storage_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ServiceError::InvalidTransition)
        }
    }
}

fn unix_time() -> Result<i64, &'static str> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system time is out of range")
}

#[derive(Debug)]
enum CleanupError {
    Kubernetes,
    Ownership,
    Service,
}

impl From<ServiceError> for CleanupError {
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
    use crate::{kubernetes_policy, ProvisionedObject, ProvisionedTarget, Scenario};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: i64 = 1_774_051_200;
    const RUN: &str = "0123456789abcdef0123456789abcdef";

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
            "status": if code < 400 { "Success" } else { "Failure" },
            "reason": reason,
            "code": code
        })
    }

    fn observed(mut body: Value, index: usize) -> Value {
        body["metadata"]["uid"] = Value::String(format!("uid-{index:02}"));
        body["metadata"]["resourceVersion"] = Value::String("1".into());
        body
    }

    fn fixture() -> (std::path::PathBuf, Service, Vec<Value>) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-cleanup-{}-{}",
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
        let lease = service.dispatch_next(NOW + 1).unwrap();
        let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
        let rendered = kubernetes_policy::render(RUN);
        let objects = rendered
            .iter()
            .enumerate()
            .map(|(index, object)| ProvisionedObject {
                identity: object.identity.clone(),
                uid: format!("uid-{index:02}"),
                owner_label: specification.cleanup_identity.clone(),
                content_digest: kubernetes_policy::content_digest(&object.body),
            })
            .collect();
        service
            .verify_provisioned_target(
                &lease,
                &ProvisionedTarget {
                    namespace_uid: "uid-00".into(),
                    policy_revision: specification.policy_revision,
                    policy_inventory_digest: specification.policy_inventory_digest,
                    cleanup_identity: specification.cleanup_identity,
                    objects,
                },
                NOW + 1,
            )
            .unwrap();
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE cleanup_records SET eligible = 1 WHERE run_id = ?1",
                [RUN],
            )
            .unwrap();
        (
            root,
            service,
            rendered.into_iter().map(|object| object.body).collect(),
        )
    }

    fn downgrade_cleanup_schema(database: &std::path::Path) {
        let connection = rusqlite::Connection::open(database).unwrap();
        connection
            .execute_batch(concat!(
                "PRAGMA foreign_keys = OFF; ",
                "CREATE TABLE cleanup_records_legacy (",
                "run_id TEXT PRIMARY KEY, cleanup_identity TEXT NOT NULL, ",
                "namespace_uid TEXT, resource_state TEXT NOT NULL, state TEXT NOT NULL, ",
                "active INTEGER NOT NULL, eligible INTEGER NOT NULL); ",
                "INSERT INTO cleanup_records_legacy SELECT run_id, cleanup_identity, ",
                "namespace_uid, resource_state, state, active, eligible FROM cleanup_records; ",
                "DROP TABLE cleanup_records; ",
                "ALTER TABLE cleanup_records_legacy RENAME TO cleanup_records;"
            ))
            .unwrap();
    }

    fn cleanup_client(
        bodies: Vec<Value>,
        absent_after_delete: bool,
    ) -> (Client, tokio::task::JoinHandle<()>) {
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            for _ in 0..5 {
                let (list, send) = handle.next_request().await.unwrap();
                assert_eq!(list.method(), http::Method::GET);
                assert!(list.uri().query().is_some_and(|query| {
                    query.contains("labelSelector=kapsel.dev%2Fcleanup-owner%3Dcleanup-")
                }));
                send.send_response(response(
                    &serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "List",
                        "metadata": {"resourceVersion": "1"},
                        "items": []
                    }),
                    StatusCode::OK,
                ));
            }
            for index in [2_usize, 0] {
                let (get, send) = handle.next_request().await.unwrap();
                assert_eq!(get.method(), http::Method::GET);
                send.send_response(response(
                    &observed(bodies[index].clone(), index),
                    StatusCode::OK,
                ));
                let (delete, send) = handle.next_request().await.unwrap();
                assert_eq!(delete.method(), http::Method::DELETE);
                let body: Value =
                    serde_json::from_slice(&delete.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                assert_eq!(body["preconditions"]["uid"], format!("uid-{index:02}"));
                send.send_response(response(&status("Deleted", 200), StatusCode::OK));
            }
            for (index, body) in bodies.into_iter().enumerate() {
                let (get, send) = handle.next_request().await.unwrap();
                assert_eq!(get.method(), http::Method::GET);
                if absent_after_delete {
                    send.send_response(response(&status("NotFound", 404), StatusCode::NOT_FOUND));
                } else {
                    send.send_response(response(&observed(body, index), StatusCode::OK));
                }
            }
        });
        (Client::new(transport, "default"), server)
    }

    #[tokio::test]
    async fn delete_acceptance_holds_capacity_until_every_recorded_uid_is_absent() {
        let (root, service, bodies) = fixture();
        let (client, server) = cleanup_client(bodies.clone(), false);
        CleanupReconciler {
            service: Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 2,
            )
            .unwrap(),
            client,
        }
        .run_once(NOW + 2)
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);

        let (client, server) = cleanup_client(bodies, true);
        CleanupReconciler {
            service: Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 3,
            )
            .unwrap(),
            client,
        }
        .run_once(NOW + 3)
        .await
        .unwrap();
        server.await.unwrap();
        assert!(service.recoverable_runs().unwrap().is_empty());
        assert_eq!(
            service.snapshot(RUN, NOW + 3).unwrap().cleanup_state,
            crate::CleanupState::Succeeded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn replacement_uid_is_never_deleted_and_cleanup_remains_active() {
        let (root, service, bodies) = fixture();
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        tokio::spawn(async move {
            for _ in 0..5 {
                let (_, send) = handle.next_request().await.unwrap();
                send.send_response(response(
                    &serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "List",
                        "metadata": {"resourceVersion": "1"},
                        "items": []
                    }),
                    StatusCode::OK,
                ));
            }
            let (_, send) = handle.next_request().await.unwrap();
            let mut replacement = observed(bodies[2].clone(), 2);
            replacement["metadata"]["uid"] = Value::String("replacement-uid".into());
            send.send_response(response(&replacement, StatusCode::OK));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request())
                    .await
                    .is_err()
            );
        });
        CleanupReconciler {
            service: Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 2,
            )
            .unwrap(),
            client: Client::new(transport, "default"),
        }
        .run_once(NOW + 2)
        .await
        .unwrap();
        let snapshot = service.snapshot(RUN, NOW + 2).unwrap();
        assert_eq!(snapshot.cleanup_state, crate::CleanupState::Failed);
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unrecorded_owner_label_orphan_is_escalated_but_never_deleted() {
        let (root, service, _bodies) = fixture();
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        tokio::spawn(async move {
            let (list, send) = handle.next_request().await.unwrap();
            assert_eq!(list.method(), http::Method::GET);
            send.send_response(response(
                &serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ServiceAccountList",
                    "metadata": {"resourceVersion": "1"},
                    "items": [{
                        "apiVersion": "v1",
                        "kind": "ServiceAccount",
                        "metadata": {
                            "name": "unrecorded",
                            "namespace": "kapsel-sandbox-runners",
                            "uid": "unrecorded-uid",
                            "labels": {"kapsel.dev/cleanup-owner": format!("cleanup-{RUN}")}
                        }
                    }]
                }),
                StatusCode::OK,
            ));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request())
                    .await
                    .is_err()
            );
        });
        CleanupReconciler {
            service: Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 2,
            )
            .unwrap(),
            client: Client::new(transport, "default"),
        }
        .run_once(NOW + 2)
        .await
        .unwrap();
        assert_eq!(
            service.snapshot(RUN, NOW + 2).unwrap().cleanup_state,
            crate::CleanupState::Failed
        );
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn legacy_running_and_failed_rows_recover_durable_escalation_start() {
        for initially_failed in [false, true] {
            let (root, service, _bodies) = fixture();
            let cleanup_identity = format!("cleanup-{RUN}");
            service
                .start_cleanup(RUN, &cleanup_identity, "uid-00", NOW + 2)
                .unwrap();
            if initially_failed {
                service
                    .fail_cleanup(RUN, &cleanup_identity, "uid-00", NOW + 3)
                    .unwrap();
            }
            drop(service);
            downgrade_cleanup_schema(&root.join("sandbox.sqlite3"));

            let reopened = Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 100,
            )
            .unwrap();
            let (state, started_at): (String, i64) = reopened
                .connection()
                .unwrap()
                .query_row(
                    "SELECT state, started_at FROM cleanup_records WHERE run_id = ?1",
                    [RUN],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(started_at, NOW + 2);
            if initially_failed {
                assert_eq!(state, "failed");
            } else {
                assert_eq!(state, "running");
                reopened
                    .fail_cleanup(RUN, &cleanup_identity, "uid-00", NOW + 902)
                    .unwrap();
            }
            let candidate = reopened.cleanup_candidates().unwrap().remove(0);
            let (transport, _handle) = mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            CleanupReconciler {
                service: Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 902,
                )
                .unwrap(),
                client: Client::new(transport, "default"),
            }
            .escalate_if_due(&candidate, NOW + 902)
            .unwrap();
            let escalated: bool = reopened
                .connection()
                .unwrap()
                .query_row(
                    "SELECT escalated FROM cleanup_records WHERE run_id = ?1",
                    [RUN],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(escalated);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn malformed_legacy_cleanup_without_started_event_uses_safe_epoch_fallback() {
        let (root, service, _bodies) = fixture();
        let cleanup_identity = format!("cleanup-{RUN}");
        service
            .start_cleanup(RUN, &cleanup_identity, "uid-00", NOW + 2)
            .unwrap();
        drop(service);
        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        connection
            .execute(
                "DELETE FROM events WHERE run_id = ?1 AND kind = 'cleanup.started'",
                [RUN],
            )
            .unwrap();
        drop(connection);
        downgrade_cleanup_schema(&root.join("sandbox.sqlite3"));
        let reopened = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [7; 32],
            NOW + 100,
        )
        .unwrap();
        let started_at: i64 = reopened
            .connection()
            .unwrap()
            .query_row(
                "SELECT started_at FROM cleanup_records WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(started_at, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn failed_cleanup_escalates_once_after_fifteen_minutes() {
        let (root, service, _bodies) = fixture();
        service
            .start_cleanup(RUN, &format!("cleanup-{RUN}"), "uid-00", NOW + 2)
            .unwrap();
        service
            .fail_cleanup(RUN, &format!("cleanup-{RUN}"), "uid-00", NOW + 2)
            .unwrap();
        let candidate = service.cleanup_candidates().unwrap().remove(0);
        let reconciler = CleanupReconciler {
            service: Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [7; 32],
                NOW + 902,
            )
            .unwrap(),
            client:
                Client::new(
                    mock::pair::<
                        http::Request<kube::client::Body>,
                        http::Response<kube::client::Body>,
                    >()
                    .0,
                    "default",
                ),
        };
        reconciler.escalate_if_due(&candidate, NOW + 901).unwrap();
        let escalated: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT escalated FROM cleanup_records WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!escalated);
        reconciler.escalate_if_due(&candidate, NOW + 902).unwrap();
        let escalated: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT escalated FROM cleanup_records WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert!(escalated);
        fs::remove_dir_all(root).unwrap();
    }
}
