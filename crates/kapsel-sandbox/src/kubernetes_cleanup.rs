//! UID-safe Kubernetes cleanup for the fixed sandbox deployment.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use kube::{
    api::{Api, DeleteParams, DynamicObject, ListParams, Preconditions},
    Client,
};
use rusqlite::OptionalExtension;
use serde_json::Value;

use crate::{
    cleanup_state::{CleanupStateClient, CleanupStateError},
    kubernetes_scheduler::api_resource,
    object_identity_parts, CleanupAbsenceEvidence, CleanupObjectAbsence, Service, ServiceError,
};

pub(super) const CLEANUP_ESCALATION_SECONDS: i64 = 15 * 60;
type StoredCleanupEscalation = (
    String,
    Option<String>,
    String,
    bool,
    bool,
    Option<i64>,
    bool,
);

pub(super) struct CleanupCandidate {
    pub(super) run_id: String,
    pub(super) cleanup_identity: String,
    pub(super) namespace_uid: String,
    pub(super) state: String,
    pub(super) started_at: Option<i64>,
    pub(super) escalated: bool,
    pub(super) objects: Vec<RecordedObject>,
}

#[derive(Clone)]
pub(super) struct RecordedObject {
    pub(super) kind: String,
    pub(super) namespace: Option<String>,
    pub(super) name: String,
    pub(super) uid: String,
    pub(super) owner_label: String,
}

/// Runs the private UID-safe cleanup reconciler continuously.
///
/// # Errors
///
/// Returns a bounded diagnostic only when remote cleanup-state configuration or time is
/// unavailable. Authenticated state and Kubernetes reconciliation failures remain retryable and do
/// not stop the role.
pub async fn run_cleanup_role(
    state_endpoint: SocketAddr,
    state_ca_bundle: PathBuf,
    state_ca_sha256: [u8; 32],
    state_ca_root_count: u8,
    state_token: PathBuf,
    client: Client,
) -> Result<(), &'static str> {
    let state = CleanupStateClient::new(
        state_endpoint,
        state_ca_bundle,
        state_ca_sha256,
        state_ca_root_count,
        state_token,
    )
    .map_err(|_| "cleanup state configuration is unavailable")?;
    let reconciler = CleanupReconciler { state, client };
    loop {
        let _ = reconciler.run_once(unix_time()?).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct CleanupReconciler {
    state: CleanupStateClient,
    client: Client,
}

impl CleanupReconciler {
    async fn run_once(&self, now: i64) -> Result<(), CleanupError> {
        self.appoint_test_operation_time(now);
        for candidate in self.state.list_candidates().await? {
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                self.reconcile_candidate(&candidate, now),
            )
            .await
            .map_err(|_| CleanupError::Kubernetes)
            .and_then(|result| result);
            match result {
                Ok(()) => {},
                Err(CleanupError::State) => return Err(CleanupError::State),
                Err(CleanupError::Kubernetes | CleanupError::Ownership) => {
                    self.record_failure(&candidate, now).await?;
                },
            }
        }
        Ok(())
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

    async fn reconcile_candidate(
        &self,
        candidate: &CleanupCandidate,
        now: i64,
    ) -> Result<(), CleanupError> {
        if candidate.state == "pending" {
            self.state.start_cleanup(candidate).await?;
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
            self.state
                .complete_cleanup(
                    candidate,
                    &CleanupAbsenceEvidence {
                        namespace_uid: candidate.namespace_uid.clone(),
                        objects: evidence,
                    },
                )
                .await?;
        } else {
            self.record_failure(candidate, now).await?;
        }
        Ok(())
    }

    async fn record_failure(
        &self,
        candidate: &CleanupCandidate,
        now: i64,
    ) -> Result<(), CleanupError> {
        let durable = self
            .state
            .list_candidates()
            .await?
            .into_iter()
            .find(|durable| same_candidate(durable, candidate))
            .ok_or(CleanupError::State)?;
        match durable.state.as_str() {
            "pending" => {
                self.state.start_cleanup(&durable).await?;
                self.state.record_failure(&durable).await?;
            },
            "running" => self.state.record_failure(&durable).await?,
            "failed" => {},
            _ => return Err(CleanupError::State),
        }
        let failed = self
            .state
            .list_candidates()
            .await?
            .into_iter()
            .find(|failed| same_candidate(failed, candidate))
            .ok_or(CleanupError::State)?;
        self.escalate_if_due(&failed, now).await
    }

    async fn escalate_if_due(
        &self,
        candidate: &CleanupCandidate,
        now: i64,
    ) -> Result<(), CleanupError> {
        self.appoint_test_operation_time(now);
        if candidate.state == "failed"
            && !candidate.escalated
            && candidate.started_at.is_some_and(|started_at| {
                now.saturating_sub(started_at) >= CLEANUP_ESCALATION_SECONDS
            })
        {
            self.state.escalate_cleanup(candidate).await?;
        }
        Ok(())
    }
}

fn same_candidate(left: &CleanupCandidate, right: &CleanupCandidate) -> bool {
    left.run_id == right.run_id
        && left.cleanup_identity == right.cleanup_identity
        && left.namespace_uid == right.namespace_uid
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
    pub(super) fn cleanup_candidates(&self) -> Result<Vec<CleanupCandidate>, ServiceError> {
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

    pub(super) fn escalate_cleanup(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        namespace_uid: &str,
        now: i64,
    ) -> Result<(), ServiceError> {
        super::bounded_hex_128(run_id)?;
        super::bounded_identity(cleanup_identity)?;
        super::bounded_identity(namespace_uid)?;
        super::timestamp(now)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(super::storage_error)?;
        let stored: Option<StoredCleanupEscalation> = transaction
            .query_row(
                concat!(
                    "SELECT cleanup_identity, namespace_uid, state, active, eligible, ",
                    "started_at, escalated FROM cleanup_records WHERE run_id = ?1"
                ),
                [run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(super::storage_error)?;
        let Some((owner, uid, state, active, eligible, started_at, escalated)) = stored else {
            return Err(ServiceError::RunNotFound);
        };
        if owner != cleanup_identity || uid.as_deref() != Some(namespace_uid) {
            return Err(ServiceError::OwnershipMismatch);
        }
        let started_at = started_at.ok_or(ServiceError::InvalidTransition)?;
        if !active
            || !eligible
            || state != "failed"
            || now.saturating_sub(started_at) < CLEANUP_ESCALATION_SECONDS
        {
            return Err(ServiceError::InvalidTransition);
        }
        if !escalated {
            let changed = transaction
                .execute(
                    concat!(
                        "UPDATE cleanup_records SET escalated = 1 WHERE run_id = ?1 ",
                        "AND cleanup_identity = ?2 AND namespace_uid = ?3 AND active = 1 ",
                        "AND eligible = 1 AND state = 'failed' AND escalated = 0"
                    ),
                    rusqlite::params![run_id, cleanup_identity, namespace_uid],
                )
                .map_err(super::storage_error)?;
            if changed != 1 {
                return Err(ServiceError::InvalidTransition);
            }
        }
        transaction.commit().map_err(super::storage_error)
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
    State,
}

impl From<CleanupStateError> for CleanupError {
    fn from(_: CleanupStateError) -> Self {
        Self::State
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

    #[test]
    fn registered_external_inventory_extends_exact_cleanup_to_twenty_objects() {
        let (root, service, _bodies) = fixture();
        let (lease_id, epoch, expires_at): (String, i64, i64) =
            rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                .unwrap()
                .query_row(
                    "SELECT lease_id, lease_epoch, lease_expires_at FROM runs WHERE run_id = ?1",
                    [RUN],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
        let lease = crate::DispatchLease {
            run_id: RUN.into(),
            lease_id,
            epoch,
            expires_at_unix_s: expires_at,
            handoff_credential: [0; 32],
        };
        let owner = format!("cleanup-{RUN}");
        let slots = service
            .external_resource_inventory(&lease, NOW + 1)
            .unwrap()
            .slots;
        for (index, slot) in slots.iter().enumerate() {
            service
                .register_external_resource(
                    &lease,
                    &slot.identity,
                    &format!("external-uid-{index:02}"),
                    &owner,
                    NOW + 1,
                )
                .unwrap();
        }
        let candidate = service.cleanup_candidates().unwrap().remove(0);
        assert_eq!(candidate.objects.len(), 20);
        for kind in ["PersistentVolumeClaim", "ConfigMap", "Secret", "Pod"] {
            assert!(candidate.objects.iter().any(|object| object.kind == kind));
        }
        assert!(candidate
            .objects
            .iter()
            .filter(|object| object.namespace.as_deref() == Some("kapsel-sandbox-runners"))
            .all(|object| should_request_delete(&candidate, object)));
        service
            .start_cleanup(RUN, &owner, "uid-00", NOW + 2)
            .unwrap();
        let evidence = CleanupAbsenceEvidence {
            namespace_uid: "uid-00".into(),
            objects: candidate
                .objects
                .iter()
                .map(|object| CleanupObjectAbsence {
                    kind: object.kind.clone(),
                    namespace: object.namespace.clone(),
                    name: object.name.clone(),
                    uid: object.uid.clone(),
                    owner_label: object.owner_label.clone(),
                    present: false,
                })
                .collect(),
        };
        service
            .complete_cleanup(RUN, &owner, &evidence, NOW + 3)
            .unwrap();
        assert!(service.recoverable_runs().unwrap().is_empty());
        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        for table in [
            "external_resource_slots",
            "provisioned_object_owners",
            "cleanup_records",
        ] {
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE run_id = ?1"),
                    [RUN],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        assert_eq!(
            service.snapshot(RUN, NOW + 3).unwrap().cleanup_state,
            crate::CleanupState::Succeeded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn delete_acceptance_holds_capacity_until_every_recorded_uid_is_absent() {
        let (root, service, bodies) = fixture();
        let (client, server) = cleanup_client(bodies.clone(), false);
        CleanupReconciler {
            state: CleanupStateClient::local(
                Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 2,
                )
                .unwrap(),
            ),
            client,
        }
        .run_once(NOW + 2)
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);

        let (client, server) = cleanup_client(bodies, true);
        CleanupReconciler {
            state: CleanupStateClient::local(
                Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 3,
                )
                .unwrap(),
            ),
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
    async fn finalizer_partial_presence_coalesces_failure_then_escalates_once() {
        let (root, service, bodies) = fixture();
        for now in [NOW + 2, NOW + 902, NOW + 903] {
            let (client, server) = cleanup_client(bodies.clone(), false);
            CleanupReconciler {
                state: CleanupStateClient::local(
                    Service::open(
                        root.join("sandbox.sqlite3"),
                        root.join("receipts"),
                        [7; 32],
                        now,
                    )
                    .unwrap(),
                ),
                client,
            }
            .run_once(now)
            .await
            .unwrap();
            server.await.unwrap();
            let (state, escalated, failures): (String, bool, i64) =
                rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                    .unwrap()
                    .query_row(
                        concat!(
                            "SELECT cleanup_records.state, cleanup_records.escalated, ",
                            "(SELECT COUNT(*) FROM events WHERE run_id = ?1 ",
                            "AND kind = 'cleanup.failed') FROM cleanup_records ",
                            "WHERE cleanup_records.run_id = ?1"
                        ),
                        [RUN],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .unwrap();
            assert_eq!(state, "failed");
            assert_eq!(failures, 1);
            assert_eq!(escalated, now >= NOW + 902);
        }
        assert_eq!(service.recoverable_runs().unwrap(), vec![RUN]);
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
            state: CleanupStateClient::local(
                Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 2,
                )
                .unwrap(),
            ),
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
            state: CleanupStateClient::local(
                Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 2,
                )
                .unwrap(),
            ),
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
                state: CleanupStateClient::local(
                    Service::open(
                        root.join("sandbox.sqlite3"),
                        root.join("receipts"),
                        [7; 32],
                        NOW + 902,
                    )
                    .unwrap(),
                ),
                client: Client::new(transport, "default"),
            }
            .escalate_if_due(&candidate, NOW + 902)
            .await
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
            state: CleanupStateClient::local(
                Service::open(
                    root.join("sandbox.sqlite3"),
                    root.join("receipts"),
                    [7; 32],
                    NOW + 902,
                )
                .unwrap(),
            ),
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
        reconciler
            .escalate_if_due(&candidate, NOW + 901)
            .await
            .unwrap();
        let escalated: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT escalated FROM cleanup_records WHERE run_id = ?1",
                [RUN],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!escalated);
        reconciler
            .escalate_if_due(&candidate, NOW + 902)
            .await
            .unwrap();
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
