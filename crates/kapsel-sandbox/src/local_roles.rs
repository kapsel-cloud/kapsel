//! Concrete local maintenance roles for the serialized sandbox controller host.

use http_body_util::Limited;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use tower_http::map_response_body::MapResponseBodyLayer;

use crate::{
    object_identity_parts, storage_error, timestamp, CleanupAbsenceEvidence, CleanupObjectAbsence,
    CleanupState, DispatchLease, Service, ServiceError, PROVISIONED_OBJECT_OWNERS_MAX,
    PROVISIONED_OBJECT_OWNERS_MAX_USIZE,
};

const CLEANUP_ESCALATION_SECONDS: i64 = 15 * 60;
#[cfg(not(test))]
const KUBERNETES_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const KUBERNETES_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(not(test))]
const CLEANUP_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const CLEANUP_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);
const KUBERNETES_RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;
type CleanupCandidate = (String, String, String, CleanupState, Option<i64>, bool);

/// One bounded scheduler reconciliation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerStep {
    /// No queued run was available or another unexpired process lease owns recovery.
    Waiting,
    /// The local role still owns the current active lease.
    Active(DispatchLease),
    /// The local role recovered the sole active run under a fresh lease generation.
    Recovered(DispatchLease),
    /// The local role dispatched the oldest queued run.
    Dispatched(DispatchLease),
}

/// Serial scheduler role over the concrete sandbox service transitions.
pub struct SchedulerRole {
    service: Service,
    current: Option<DispatchLease>,
}

impl SchedulerRole {
    /// Creates one process-local scheduler role for the owner-private service state.
    pub fn new(service: Service) -> Self {
        Self {
            service,
            current: None,
        }
    }

    /// Recovers the sole active run before considering one FIFO dispatch.
    ///
    /// # Errors
    ///
    /// Returns a bounded service error when durable capacity, lease, time, or storage state is
    /// invalid. An unexpired lease owned by another process returns [`SchedulerStep::Waiting`].
    pub fn run_once(&mut self, now_unix_s: i64) -> Result<SchedulerStep, ServiceError> {
        timestamp(now_unix_s)?;
        if let Some(run_id) = self.service.sole_active_run()? {
            if let Some(current) = self.current.as_ref().filter(|lease| lease.run_id == run_id) {
                if now_unix_s < current.expires_at_unix_s.saturating_sub(5) {
                    return Ok(SchedulerStep::Active(current.clone()));
                }
                let recovered = self
                    .service
                    .recover_run(&run_id, Some(current), now_unix_s)?;
                self.current = Some(recovered.clone());
                return Ok(SchedulerStep::Recovered(recovered));
            }
            return match self.service.recover_run(&run_id, None, now_unix_s) {
                Ok(recovered) => {
                    self.current = Some(recovered.clone());
                    Ok(SchedulerStep::Recovered(recovered))
                },
                Err(ServiceError::LeaseBusy) => Ok(SchedulerStep::Waiting),
                Err(error) => Err(error),
            };
        }

        self.current = None;
        match self.service.dispatch_next(now_unix_s) {
            Ok(lease) => {
                self.current = Some(lease.clone());
                Ok(SchedulerStep::Dispatched(lease))
            },
            Err(ServiceError::RunNotFound) => Ok(SchedulerStep::Waiting),
            Err(error) => Err(error),
        }
    }
}

/// Periodic public-retention role over the concrete sandbox service transition.
pub struct RetentionRole {
    service: Service,
}

impl RetentionRole {
    /// Creates one local retention role.
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    /// Runs one bounded expiry and tombstone sweep.
    ///
    /// # Errors
    ///
    /// Returns a time, storage, or immutable-object deletion failure.
    pub fn run_once(&self, now_unix_s: i64) -> Result<(), ServiceError> {
        self.service.sweep_retention(now_unix_s)
    }
}

/// One exact object identity owned by the active cleanup generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupOwnedObject {
    /// Exact Kubernetes kind.
    pub kind: String,
    /// Exact namespace, absent only for the owned Namespace object.
    pub namespace: Option<String>,
    /// Exact object name.
    pub name: String,
    /// Immutable UID recorded before deletion.
    pub uid: String,
    /// Exact cleanup owner marker.
    pub owner_label: String,
}

/// The sole cleanup work item selected from durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupWork {
    /// Public run identity.
    pub run_id: String,
    /// Exact server-owned cleanup identity.
    pub cleanup_identity: String,
    /// Immutable namespace UID recorded before cleanup.
    pub namespace_uid: String,
    /// Append-only exact object inventory.
    pub objects: Vec<CleanupOwnedObject>,
    /// Whether the one fifteen-minute escalation is durably due or already emitted.
    pub escalated: bool,
}

/// One bounded API observation for a recorded cleanup row.
#[derive(Clone, Debug, Eq, PartialEq)]
enum CleanupApiObservation {
    /// The exact object was already absent.
    Absent,
    /// One complete bounded object body was returned.
    Present(serde_json::Value),
}

/// One response bound to the identity selected from durable [`CleanupWork`].
#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupRowObservation {
    /// Exact kind requested by the observer.
    pub kind: String,
    /// Exact namespace requested by the observer.
    pub namespace: Option<String>,
    /// Exact name requested by the observer.
    pub name: String,
    /// Bounded response for that exact request.
    pub response: CleanupApiObservation,
}

/// Complete bounded responses for one cleanup attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupObservation {
    /// Exactly one response for every append-only inventory row.
    pub rows: Vec<CleanupRowObservation>,
    /// Any object returned by the fixed owner-marker scan.
    pub owned_orphans: Vec<serde_json::Value>,
}

/// Frozen Kubernetes propagation for one UID-preconditioned delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
enum CleanupPropagation {
    /// Stop a controller without cascading past recorded children.
    Orphan,
    /// Delete one leaf or namespaced policy object.
    Background,
    /// Wait for Namespace-owned deletion to complete.
    Foreground,
}

/// One exact delete generated solely from durable cleanup inventory.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct CleanupDeleteRequest {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid_precondition: String,
    propagation: CleanupPropagation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupDeletePlan {
    run_id: String,
    cleanup_identity: String,
    cleanup_attempt: i64,
    plan_digest: String,
    requests: Vec<CleanupDeleteRequest>,
}

/// UID- and owner-safe local cleanup role over concrete service transitions.
pub struct CleanupRole {
    service: Service,
}

/// Concrete fixed-authority Kubernetes cleanup role.
pub struct KubernetesCleanupRole {
    role: CleanupRole,
    client: kube::Client,
}

impl KubernetesCleanupRole {
    /// Binds one fixed Kubernetes authority to the concrete cleanup role.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when the fixed Kubernetes client cannot be constructed.
    pub fn new(service: Service, configuration: kube::Config) -> Result<Self, ServiceError> {
        Ok(Self {
            role: CleanupRole::new(service),
            client: bounded_kubernetes_client(configuration)?,
        })
    }

    /// Runs at most one closed cleanup attempt selected from durable service state.
    ///
    /// Every failed attempt is durably coalesced through [`CleanupRole::fail`] before the error is
    /// returned. The caller supplies no work, observation, plan, endpoint, or credential.
    ///
    /// # Errors
    ///
    /// Returns a bounded API, ownership, presence, transition, time, or storage failure.
    pub async fn run_once(&self, now_unix_s: i64) -> Result<bool, ServiceError> {
        let Some(work) = self.role.next(now_unix_s)? else {
            return Ok(false);
        };
        let result = cleanup_attempt_deadline(self.role.run_kubernetes_attempt_with_client(
            &work,
            self.client.clone(),
            now_unix_s,
        ))
        .await;
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                self.role.fail(&work, now_unix_s)?;
                Err(error)
            },
        }
    }
}

impl CleanupRole {
    /// Creates one local cleanup role.
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    /// Selects the sole eligible cleanup item and durably starts cleanup when pending.
    ///
    /// # Errors
    ///
    /// Returns a bounded ownership, state, time, or storage failure. More than one active cleanup
    /// item fails closed.
    pub fn next(&self, now_unix_s: i64) -> Result<Option<CleanupWork>, ServiceError> {
        timestamp(now_unix_s)?;
        let candidate = self.service.cleanup_candidate()?;
        let Some((run_id, cleanup_identity, namespace_uid, state, started_at, escalated)) =
            candidate
        else {
            return Ok(None);
        };
        if state == CleanupState::Pending {
            self.service
                .start_cleanup(&run_id, &cleanup_identity, &namespace_uid, now_unix_s)?;
        } else if !matches!(state, CleanupState::Running | CleanupState::Failed) {
            return Err(ServiceError::InvalidTransition);
        }
        let escalated = if state == CleanupState::Failed
            && !escalated
            && started_at.is_some_and(|started| {
                now_unix_s.saturating_sub(started) >= CLEANUP_ESCALATION_SECONDS
            }) {
            self.service
                .mark_cleanup_escalated(&run_id, &cleanup_identity, now_unix_s)?;
            true
        } else {
            escalated
        };
        Ok(Some(CleanupWork {
            objects: self
                .service
                .cleanup_owned_objects(&run_id, &cleanup_identity)?,
            run_id,
            cleanup_identity,
            namespace_uid,
            escalated,
        }))
    }

    /// Appends newly observed Deployment children by exact UID before deriving another plan.
    ///
    /// # Errors
    ///
    /// Rejects wrong ancestry, template, owner, identity, count, size, or durable state.
    fn refresh_generated_children(
        &self,
        work: &CleanupWork,
        children: &[crate::ObservedPolicyObject],
    ) -> Result<CleanupWork, ServiceError> {
        self.service.append_observed_generated_children(
            &work.run_id,
            &work.cleanup_identity,
            children,
        )?;
        let mut refreshed = work.clone();
        refreshed.objects = self
            .service
            .cleanup_owned_objects(&work.run_id, &work.cleanup_identity)?;
        Ok(refreshed)
    }

    /// Derives the only allowed UID-preconditioned deletion plan from durable work.
    ///
    /// # Errors
    ///
    /// Rejects omitted, reordered, reused, wrong-owner/revision, finalizing, unrelated,
    /// oversized, or unavailable evidence without issuing a delete.
    fn deletion_plan(
        &self,
        work: &CleanupWork,
        observation: &CleanupObservation,
    ) -> Result<CleanupDeletePlan, ServiceError> {
        if observation.rows.len() != work.objects.len() || !observation.owned_orphans.is_empty() {
            return Err(ServiceError::OwnershipMismatch);
        }
        let ordered = ordered_cleanup_objects(&work.objects)?;
        let mut requests = Vec::new();
        for (expected, observed) in ordered.iter().zip(&observation.rows) {
            if observed.kind != expected.kind
                || observed.namespace != expected.namespace
                || observed.name != expected.name
            {
                return Err(ServiceError::OwnershipMismatch);
            }
            match &observed.response {
                CleanupApiObservation::Absent => {},
                CleanupApiObservation::Present(body) => {
                    verify_cleanup_body(expected, body)?;
                    requests.push(CleanupDeleteRequest {
                        kind: expected.kind.clone(),
                        namespace: expected.namespace.clone(),
                        name: expected.name.clone(),
                        uid_precondition: expected.uid.clone(),
                        propagation: cleanup_propagation(&expected.kind),
                    });
                },
            }
        }
        let plan_bytes = serde_json::to_vec(&requests).map_err(|_| ServiceError::Unavailable)?;
        let plan_digest = crate::sha256_hex(&plan_bytes);
        let cleanup_attempt = self.service.begin_cleanup_attempt(
            &work.run_id,
            &work.cleanup_identity,
            &plan_digest,
        )?;
        Ok(CleanupDeletePlan {
            run_id: work.run_id.clone(),
            cleanup_identity: work.cleanup_identity.clone(),
            cleanup_attempt,
            plan_digest,
            requests,
        })
    }

    /// Records one coalesced retryable cleanup failure without changing operation outcome.
    ///
    /// # Errors
    ///
    /// Returns a bounded ownership, transition, time, or storage failure.
    pub fn fail(&self, work: &CleanupWork, now_unix_s: i64) -> Result<(), ServiceError> {
        match self.service.fail_cleanup(
            &work.run_id,
            &work.cleanup_identity,
            &work.namespace_uid,
            now_unix_s,
        ) {
            Ok(()) => Ok(()),
            Err(ServiceError::InvalidTransition) => {
                let current = self.service.cleanup_candidate()?;
                if current.as_ref().is_some_and(
                    |(run_id, cleanup_identity, namespace_uid, state, _, _)| {
                        run_id == &work.run_id
                            && cleanup_identity == &work.cleanup_identity
                            && namespace_uid == &work.namespace_uid
                            && *state == CleanupState::Failed
                    },
                ) {
                    Ok(())
                } else {
                    Err(ServiceError::InvalidTransition)
                }
            },
            Err(error) => Err(error),
        }
    }

    async fn run_kubernetes_attempt_with_client(
        &self,
        work: &CleanupWork,
        client: kube::Client,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let current = self
            .next(now_unix_s)?
            .ok_or(ServiceError::InvalidTransition)?;
        if current.run_id != work.run_id || current.cleanup_identity != work.cleanup_identity {
            return Err(ServiceError::OwnershipMismatch);
        }
        let children = observe_generated_children(client.clone(), &current).await?;
        let refreshed = self.refresh_generated_children(&current, &children)?;
        let mut observation = observe_kubernetes_cleanup(client.clone(), &refreshed).await?;
        consume_known_owner_scan(&refreshed, &mut observation)?;
        let plan = self.deletion_plan(&refreshed, &observation)?;
        self.execute_kubernetes_attempt_with_client(&refreshed, &plan, client, now_unix_s)
            .await
    }

    async fn execute_kubernetes_attempt_with_client(
        &self,
        work: &CleanupWork,
        plan: &CleanupDeletePlan,
        client: kube::Client,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        if plan.run_id != work.run_id || plan.cleanup_identity != work.cleanup_identity {
            return Err(ServiceError::OwnershipMismatch);
        }
        verify_cleanup_plan_integrity(plan)?;
        for request in &plan.requests {
            issue_kubernetes_delete(client.clone(), request).await?;
        }
        self.service.mark_cleanup_plan_issued(
            &work.run_id,
            &work.cleanup_identity,
            plan.cleanup_attempt,
            &plan.plan_digest,
        )?;
        let observation_id = self.service.begin_cleanup_observation(
            &work.run_id,
            &work.cleanup_identity,
            plan.cleanup_attempt,
            &plan.plan_digest,
        )?;
        let observation = observe_kubernetes_cleanup(client, work).await?;
        self.complete_observation(work, plan, &observation, observation_id, now_unix_s)
    }

    fn complete_observation(
        &self,
        work: &CleanupWork,
        plan: &CleanupDeletePlan,
        observation: &CleanupObservation,
        observation_id: String,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        if observation.rows.len() != work.objects.len() || !observation.owned_orphans.is_empty() {
            return Err(ServiceError::OwnershipMismatch);
        }
        let ordered = ordered_cleanup_objects(&work.objects)?;
        let mut objects = Vec::with_capacity(ordered.len());
        for (expected, observed) in ordered.iter().zip(&observation.rows) {
            if observed.kind != expected.kind
                || observed.namespace != expected.namespace
                || observed.name != expected.name
                || observed.response != CleanupApiObservation::Absent
            {
                return Err(ServiceError::OwnershipMismatch);
            }
            objects.push(CleanupObjectAbsence {
                kind: expected.kind.clone(),
                namespace: expected.namespace.clone(),
                name: expected.name.clone(),
                uid: expected.uid.clone(),
                owner_label: expected.owner_label.clone(),
                present: false,
            });
        }
        let evidence = CleanupAbsenceEvidence {
            namespace_uid: work.namespace_uid.clone(),
            cleanup_epoch: format!("cleanup-{}-1", work.run_id),
            cleanup_attempt: plan.cleanup_attempt,
            plan_digest: plan.plan_digest.clone(),
            observation_id,
            objects,
            owned_orphans: Vec::new(),
        };
        self.service
            .complete_cleanup(&work.run_id, &work.cleanup_identity, &evidence, now_unix_s)
    }
}

async fn cleanup_attempt_deadline<T>(
    future: impl std::future::Future<Output = Result<T, ServiceError>>,
) -> Result<T, ServiceError> {
    tokio::time::timeout(CLEANUP_ATTEMPT_TIMEOUT, future)
        .await
        .map_err(|_| ServiceError::Unavailable)?
}

fn bounded_kubernetes_client(configuration: kube::Config) -> Result<kube::Client, ServiceError> {
    let response_limit =
        MapResponseBodyLayer::new(|body| Limited::new(body, KUBERNETES_RESPONSE_BYTES_MAX));
    Ok(kube::client::ClientBuilder::try_from(configuration)
        .map_err(|_| ServiceError::Unavailable)?
        .with_layer(&response_limit)
        .build())
}

fn cleanup_api_resource(kind: &str) -> Result<kube::core::ApiResource, ServiceError> {
    let (group, version, plural) = match kind {
        "Namespace" => ("", "v1", "namespaces"),
        "ServiceAccount" => ("", "v1", "serviceaccounts"),
        "ConfigMap" => ("", "v1", "configmaps"),
        "Secret" => ("", "v1", "secrets"),
        "Service" => ("", "v1", "services"),
        "Pod" => ("", "v1", "pods"),
        "PersistentVolumeClaim" => ("", "v1", "persistentvolumeclaims"),
        "Deployment" => ("apps", "v1", "deployments"),
        "ReplicaSet" => ("apps", "v1", "replicasets"),
        "Job" => ("batch", "v1", "jobs"),
        "EndpointSlice" => ("discovery.k8s.io", "v1", "endpointslices"),
        "Role" => ("rbac.authorization.k8s.io", "v1", "roles"),
        "RoleBinding" => ("rbac.authorization.k8s.io", "v1", "rolebindings"),
        "ResourceQuota" => ("", "v1", "resourcequotas"),
        "LimitRange" => ("", "v1", "limitranges"),
        "NetworkPolicy" => ("networking.k8s.io", "v1", "networkpolicies"),
        _ => return Err(ServiceError::OwnershipMismatch),
    };
    Ok(kube::core::ApiResource::from_gvk_with_plural(
        &kube::core::GroupVersionKind::gvk(group, version, kind),
        plural,
    ))
}

fn cleanup_api(
    client: kube::Client,
    kind: &str,
    namespace: Option<&str>,
) -> Result<kube::Api<kube::core::DynamicObject>, ServiceError> {
    let resource = cleanup_api_resource(kind)?;
    match namespace {
        Some(namespace) => Ok(kube::Api::namespaced_with(client, namespace, &resource)),
        None if kind == "Namespace" => Ok(kube::Api::all_with(client, &resource)),
        None => Err(ServiceError::OwnershipMismatch),
    }
}

fn consume_known_owner_scan(
    work: &CleanupWork,
    observation: &mut CleanupObservation,
) -> Result<(), ServiceError> {
    let mut seen = std::collections::HashSet::new();
    for body in &observation.owned_orphans {
        let kind = body
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::OwnershipMismatch)?;
        let namespace = body
            .pointer("/metadata/namespace")
            .and_then(serde_json::Value::as_str);
        let name = body
            .pointer("/metadata/name")
            .and_then(serde_json::Value::as_str)
            .ok_or(ServiceError::OwnershipMismatch)?;
        let expected = work
            .objects
            .iter()
            .find(|object| {
                object.kind == kind
                    && object.namespace.as_deref() == namespace
                    && object.name == name
            })
            .ok_or(ServiceError::OwnershipMismatch)?;
        if !seen.insert(expected.uid.as_str()) {
            return Err(ServiceError::OwnershipMismatch);
        }
        verify_cleanup_body(expected, body)?;
    }
    observation.owned_orphans.clear();
    Ok(())
}

fn verify_cleanup_plan_integrity(plan: &CleanupDeletePlan) -> Result<(), ServiceError> {
    let plan_bytes = serde_json::to_vec(&plan.requests).map_err(|_| ServiceError::Unavailable)?;
    if crate::sha256_hex(&plan_bytes) != plan.plan_digest {
        return Err(ServiceError::OwnershipMismatch);
    }
    Ok(())
}

async fn issue_kubernetes_delete(
    client: kube::Client,
    request: &CleanupDeleteRequest,
) -> Result<(), ServiceError> {
    let api = cleanup_api(client, &request.kind, request.namespace.as_deref())?;
    let propagation_policy = match request.propagation {
        CleanupPropagation::Orphan => kube::api::PropagationPolicy::Orphan,
        CleanupPropagation::Background => kube::api::PropagationPolicy::Background,
        CleanupPropagation::Foreground => kube::api::PropagationPolicy::Foreground,
    };
    let parameters = kube::api::DeleteParams {
        propagation_policy: Some(propagation_policy),
        preconditions: Some(kube::api::Preconditions {
            uid: Some(request.uid_precondition.clone()),
            resource_version: None,
        }),
        ..kube::api::DeleteParams::default()
    };
    match tokio::time::timeout(
        KUBERNETES_REQUEST_TIMEOUT,
        api.delete(&request.name, &parameters),
    )
    .await
    .map_err(|_| ServiceError::Unavailable)?
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(()),
        Err(_) => Err(ServiceError::Unavailable),
    }
}

async fn observe_generated_children(
    client: kube::Client,
    work: &CleanupWork,
) -> Result<Vec<crate::ObservedPolicyObject>, ServiceError> {
    let namespace = format!("sandbox-{}", work.run_id);
    let selector = format!(
        "kapsel.dev/cleanup-owner={},kapsel.dev/sandbox-run-id={}",
        work.cleanup_identity, work.run_id
    );
    let mut children = Vec::new();
    for (kind, maximum) in [("ReplicaSet", 2_usize), ("Pod", 1_usize)] {
        let api = cleanup_api(client.clone(), kind, Some(&namespace))?;
        let parameters = kube::api::ListParams::default().labels(&selector);
        let listed = tokio::time::timeout(KUBERNETES_REQUEST_TIMEOUT, api.list(&parameters))
            .await
            .map_err(|_| ServiceError::Unavailable)?
            .map_err(|_| ServiceError::Unavailable)?;
        if serde_json::to_vec(&listed)
            .map_or(true, |bytes| bytes.len() > KUBERNETES_RESPONSE_BYTES_MAX)
            || listed.items.len() > maximum
            || children.len().saturating_add(listed.items.len()) > 3
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        for body in listed.items {
            children.push(crate::ObservedPolicyObject {
                body: bounded_kubernetes_value(body)?,
            });
        }
    }
    Ok(children)
}

async fn observe_kubernetes_cleanup(
    client: kube::Client,
    work: &CleanupWork,
) -> Result<CleanupObservation, ServiceError> {
    let ordered = ordered_cleanup_objects(&work.objects)?;
    let namespace_object = ordered
        .iter()
        .find(|object| object.kind == "Namespace")
        .ok_or(ServiceError::OwnershipMismatch)?;
    let namespace_api = cleanup_api(client.clone(), "Namespace", None)?;
    let namespace_body = tokio::time::timeout(
        KUBERNETES_REQUEST_TIMEOUT,
        namespace_api.get_opt(&namespace_object.name),
    )
    .await
    .map_err(|_| ServiceError::Unavailable)?
    .map_err(|_| ServiceError::Unavailable)?;
    if namespace_body.is_none() {
        return Ok(CleanupObservation {
            rows: ordered
                .iter()
                .map(|object| CleanupRowObservation {
                    kind: object.kind.clone(),
                    namespace: object.namespace.clone(),
                    name: object.name.clone(),
                    response: CleanupApiObservation::Absent,
                })
                .collect(),
            owned_orphans: Vec::new(),
        });
    }
    let mut rows = Vec::with_capacity(ordered.len());
    for object in ordered {
        let body = if object.kind == "Namespace" {
            namespace_body.clone()
        } else {
            let api = cleanup_api(client.clone(), &object.kind, object.namespace.as_deref())?;
            tokio::time::timeout(KUBERNETES_REQUEST_TIMEOUT, api.get_opt(&object.name))
                .await
                .map_err(|_| ServiceError::Unavailable)?
                .map_err(|_| ServiceError::Unavailable)?
        };
        let response = match body {
            Some(body) => CleanupApiObservation::Present(bounded_kubernetes_value(body)?),
            None => CleanupApiObservation::Absent,
        };
        rows.push(CleanupRowObservation {
            kind: object.kind.clone(),
            namespace: object.namespace.clone(),
            name: object.name.clone(),
            response,
        });
    }
    let namespace = format!("sandbox-{}", work.run_id);
    let selector = format!("kapsel.dev/cleanup-owner={}", work.cleanup_identity);
    let mut owned_orphans = Vec::new();
    for kind in [
        "ServiceAccount",
        "Pod",
        "Deployment",
        "ReplicaSet",
        "Role",
        "RoleBinding",
        "ResourceQuota",
        "LimitRange",
        "NetworkPolicy",
    ] {
        let api = cleanup_api(client.clone(), kind, Some(&namespace))?;
        let parameters = kube::api::ListParams::default().labels(&selector);
        let listed = tokio::time::timeout(KUBERNETES_REQUEST_TIMEOUT, api.list(&parameters))
            .await
            .map_err(|_| ServiceError::Unavailable)?
            .map_err(|_| ServiceError::Unavailable)?;
        if serde_json::to_vec(&listed)
            .map_or(true, |bytes| bytes.len() > KUBERNETES_RESPONSE_BYTES_MAX)
            || listed.items.len() > cleanup_list_max(kind)
            || owned_orphans.len().saturating_add(listed.items.len())
                > PROVISIONED_OBJECT_OWNERS_MAX_USIZE
        {
            return Err(ServiceError::OwnershipMismatch);
        }
        for body in listed.items {
            owned_orphans.push(bounded_kubernetes_value(body)?);
        }
    }
    Ok(CleanupObservation {
        rows,
        owned_orphans,
    })
}

fn cleanup_list_max(kind: &str) -> usize {
    match kind {
        "ServiceAccount" | "ReplicaSet" | "Role" | "RoleBinding" => 2,
        "Pod" | "Deployment" | "ResourceQuota" | "LimitRange" | "NetworkPolicy" => 1,
        _ => 0,
    }
}

fn bounded_kubernetes_value(
    body: kube::core::DynamicObject,
) -> Result<serde_json::Value, ServiceError> {
    let value = serde_json::to_value(body).map_err(|_| ServiceError::Unavailable)?;
    if serde_json::to_vec(&value).map_or(true, |bytes| bytes.len() > KUBERNETES_RESPONSE_BYTES_MAX)
    {
        Err(ServiceError::Unavailable)
    } else {
        Ok(value)
    }
}

fn verify_cleanup_body(
    expected: &CleanupOwnedObject,
    body: &serde_json::Value,
) -> Result<(), ServiceError> {
    if serde_json::to_vec(body).map_or(true, |bytes| bytes.len() > KUBERNETES_RESPONSE_BYTES_MAX) {
        return Err(ServiceError::Unavailable);
    }
    let labels = body
        .pointer("/metadata/labels")
        .and_then(serde_json::Value::as_object)
        .ok_or(ServiceError::OwnershipMismatch)?;
    let exact = body.get("kind").and_then(serde_json::Value::as_str)
        == Some(expected.kind.as_str())
        && body
            .pointer("/metadata/name")
            .and_then(serde_json::Value::as_str)
            == Some(expected.name.as_str())
        && body
            .pointer("/metadata/namespace")
            .and_then(serde_json::Value::as_str)
            == expected.namespace.as_deref()
        && body
            .pointer("/metadata/uid")
            .and_then(serde_json::Value::as_str)
            == Some(expected.uid.as_str())
        && labels
            .get("kapsel.dev/cleanup-owner")
            .and_then(serde_json::Value::as_str)
            == Some(expected.owner_label.as_str())
        && labels
            .get("kapsel.dev/sandbox-owner")
            .and_then(serde_json::Value::as_str)
            == Some(expected.owner_label.as_str())
        && labels
            .get("kapsel.dev/policy-revision")
            .and_then(serde_json::Value::as_str)
            == Some(crate::kubernetes_policy::REVISION)
        && body
            .pointer("/metadata/finalizers")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty);
    exact.then_some(()).ok_or(ServiceError::OwnershipMismatch)
}

fn ordered_cleanup_objects(
    objects: &[CleanupOwnedObject],
) -> Result<Vec<&CleanupOwnedObject>, ServiceError> {
    let mut ordered = objects.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        cleanup_rank(&left.kind, &left.name)
            .cmp(&cleanup_rank(&right.kind, &right.name))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.uid.cmp(&right.uid))
    });
    if ordered
        .iter()
        .any(|object| cleanup_rank(&object.kind, &object.name) == u8::MAX)
    {
        return Err(ServiceError::OwnershipMismatch);
    }
    Ok(ordered)
}

fn cleanup_rank(kind: &str, name: &str) -> u8 {
    match (kind, name) {
        ("Deployment", "sandbox-target") => 0,
        ("ReplicaSet", _) => 1,
        ("Pod", _) => 2,
        ("NetworkPolicy", "default-deny") => 3,
        ("ServiceAccount", "sandbox-target") => 4,
        ("ResourceQuota", "sandbox-quota") => 5,
        ("LimitRange", "sandbox-limits") => 6,
        ("RoleBinding", "sandbox-runner") => 7,
        ("Role", "sandbox-runner") => 8,
        ("RoleBinding", "sandbox-cleanup") => 9,
        ("Role", "sandbox-cleanup") => 10,
        ("Namespace", _) => 11,
        _ => u8::MAX,
    }
}

fn cleanup_propagation(kind: &str) -> CleanupPropagation {
    match kind {
        "Deployment" | "ReplicaSet" => CleanupPropagation::Orphan,
        "Namespace" => CleanupPropagation::Foreground,
        _ => CleanupPropagation::Background,
    }
}

impl Service {
    fn cleanup_candidate(&self) -> Result<Option<CleanupCandidate>, ServiceError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM cleanup_records WHERE active = 1 AND eligible = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if count > 1 {
            return Err(ServiceError::Unavailable);
        }
        connection
            .query_row(
                concat!(
                    "SELECT cleanup_records.run_id, cleanup_records.cleanup_identity, ",
                    "cleanup_records.namespace_uid, cleanup_records.state, ",
                    "cleanup_records.started_at, cleanup_records.escalated FROM cleanup_records ",
                    "JOIN runs ON runs.run_id = cleanup_records.run_id ",
                    "WHERE cleanup_records.active = 1 AND cleanup_records.eligible = 1 ",
                    "AND cleanup_records.resource_state = 'owned' ",
                    "AND runs.provisioning_closed = 1 AND runs.runner_revoked = 1 ",
                    "AND runs.runner_process_absent = 1 AND runs.journal_handoff = 1 ",
                    "AND runs.runner_state_retired = 1 ",
                    "ORDER BY runs.admission_order ",
                    "LIMIT 1"
                ),
                [],
                |row| {
                    let state = row.get::<_, String>(3)?;
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        CleanupState::parse(&state).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)
    }

    fn cleanup_owned_objects(
        &self,
        run_id: &str,
        cleanup_identity: &str,
    ) -> Result<Vec<CleanupOwnedObject>, ServiceError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(concat!(
                "SELECT identity, uid, owner_label FROM provisioned_object_owners ",
                "WHERE run_id = ?1 ORDER BY uid"
            ))
            .map_err(storage_error)?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage_error)?;
        let mut objects = Vec::new();
        for row in rows {
            let (identity, uid, owner_label) = row.map_err(storage_error)?;
            if owner_label != cleanup_identity {
                return Err(ServiceError::OwnershipMismatch);
            }
            let (kind, namespace, name) = object_identity_parts(&identity)?;
            objects.push(CleanupOwnedObject {
                kind,
                namespace,
                name,
                uid,
                owner_label,
            });
        }
        if objects.is_empty()
            || i64::try_from(objects.len()).ok() > Some(PROVISIONED_OBJECT_OWNERS_MAX)
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(objects)
    }

    fn mark_cleanup_escalated(
        &self,
        run_id: &str,
        cleanup_identity: &str,
        now_unix_s: i64,
    ) -> Result<(), ServiceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                concat!(
                    "UPDATE cleanup_records SET escalated = 1 WHERE run_id = ?1 ",
                    "AND cleanup_identity = ?2 AND active = 1 AND eligible = 1 ",
                    "AND state = 'failed' AND escalated = 0 AND started_at IS NOT NULL ",
                    "AND ?3 - started_at >= ?4"
                ),
                params![
                    run_id,
                    cleanup_identity,
                    now_unix_s,
                    CLEANUP_ESCALATION_SECONDS
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        transaction.commit().map_err(storage_error)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        thread,
    };

    use http::{Request, Response, StatusCode};
    use kube::client::Body;
    use tower_test::mock;

    use super::*;

    #[allow(
        clippy::needless_pass_by_value,
        reason = "test responses consume one temporary JSON body"
    )]
    fn response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    enum ResponseFraming {
        ContentLength,
        Chunked,
        CloseDelimited,
        Trickle,
    }

    fn response_server(
        body_bytes: usize,
        framing: ResponseFraming,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let prefix = br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"bounded"}}"#;
            let mut body = prefix.to_vec();
            body.resize(body_bytes, b' ');
            match framing {
                ResponseFraming::ContentLength => {
                    write!(
                        stream,
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "content-length: {}\r\nconnection: close\r\n\r\n"
                        ),
                        body.len()
                    )
                    .unwrap();
                    let _ = stream.write_all(&body);
                },
                ResponseFraming::Chunked => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    write!(stream, "{:x}\r\n", body.len()).unwrap();
                    let _ = stream.write_all(&body);
                    let _ = stream.write_all(b"\r\n0\r\n\r\n");
                },
                ResponseFraming::CloseDelimited => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    let _ = stream.write_all(&body);
                },
                ResponseFraming::Trickle => {
                    write!(
                        stream,
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "content-length: {}\r\nconnection: close\r\n\r\n"
                        ),
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body[..1]).unwrap();
                    thread::sleep(std::time::Duration::from_millis(250));
                    let _ = stream.write_all(&body[1..]);
                },
            }
        });
        (address, server)
    }

    async fn oversized_response_is_rejected(framing: ResponseFraming) {
        let (address, server) = response_server(KUBERNETES_RESPONSE_BYTES_MAX + 1, framing);
        let configuration = kube::Config::new(format!("http://{address}").parse().unwrap());
        let client = bounded_kubernetes_client(configuration).unwrap();
        assert!(cleanup_api(client, "Namespace", None)
            .unwrap()
            .get("bounded")
            .await
            .is_err());
        server.join().unwrap();
    }

    fn cleanup_service(name: &str) -> (std::path::PathBuf, Service, String) {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            std::env::temp_dir().join(format!("kapsel-cleanup-role-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        std::fs::create_dir(&receipts).unwrap();
        std::fs::set_permissions(&receipts, std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("sandbox.sqlite3");
        let service = Service::open(&database, &receipts, [7; 32], 1_800_000_000).unwrap();
        let admission = service
            .admit(
                "44444444444444444444444444444444",
                crate::Scenario::Healthy,
                1_800_000_000,
            )
            .unwrap();
        let lease = service.dispatch_next(1_800_000_001).unwrap();
        let specification = service
            .provisioning_specification(&lease, 1_800_000_001)
            .unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute(
                concat!(
                    "UPDATE runs SET provisioning_closed = 1, execution_state = 'service_failed', ",
                    "namespace_uid = 'namespace-uid', runner_revoked = 1, ",
                    "runner_process_absent = 1, journal_handoff = 1, runner_state_retiring = 1, ",
                    "runner_state_retired = 1 WHERE run_id = ?1"
                ),
                [&admission.run_id],
            )
            .unwrap();
        connection
            .execute(
                concat!(
                    "UPDATE cleanup_records SET eligible = 1, resource_state = 'owned', ",
                    "namespace_uid = 'namespace-uid' WHERE run_id = ?1"
                ),
                [&admission.run_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO provisioned_object_owners VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "namespace-uid",
                    admission.run_id,
                    format!("Namespace/sandbox-{}", admission.run_id),
                    specification.cleanup_identity
                ],
            )
            .unwrap();
        (root, service, admission.run_id)
    }

    fn work() -> CleanupWork {
        CleanupWork {
            run_id: "0123456789abcdef0123456789abcdef".into(),
            cleanup_identity: "cleanup-0123456789abcdef0123456789abcdef".into(),
            namespace_uid: "namespace-uid".into(),
            objects: vec![
                CleanupOwnedObject {
                    kind: "Pod".into(),
                    namespace: Some("sandbox-0123456789abcdef0123456789abcdef".into()),
                    name: "target-pod".into(),
                    uid: "pod-uid".into(),
                    owner_label: "cleanup-0123456789abcdef0123456789abcdef".into(),
                },
                CleanupOwnedObject {
                    kind: "Namespace".into(),
                    namespace: None,
                    name: "sandbox-0123456789abcdef0123456789abcdef".into(),
                    uid: "namespace-uid".into(),
                    owner_label: "cleanup-0123456789abcdef0123456789abcdef".into(),
                },
            ],
            escalated: false,
        }
    }

    #[tokio::test]
    async fn concrete_role_owns_failed_attempt_transition() {
        let (root, service, run_id) = cleanup_service("failed-attempt");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    concat!(
                        "HTTP/1.1 503 Service Unavailable\r\n",
                        "content-type: application/json\r\ncontent-length: 2\r\n",
                        "connection: close\r\n\r\n{}"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let configuration = kube::Config::new(format!("http://{address}").parse().unwrap());
        let role = KubernetesCleanupRole::new(service.clone(), configuration).unwrap();
        assert_eq!(
            role.run_once(1_800_000_002).await,
            Err(ServiceError::Unavailable)
        );
        assert_eq!(
            service
                .snapshot(&run_id, 1_800_000_002)
                .unwrap()
                .cleanup_state,
            CleanupState::Failed
        );
        server.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn response_cap_precedes_kube_deserialization_for_every_http_framing() {
        oversized_response_is_rejected(ResponseFraming::ContentLength).await;
        oversized_response_is_rejected(ResponseFraming::Chunked).await;
        oversized_response_is_rejected(ResponseFraming::CloseDelimited).await;
    }

    #[tokio::test]
    async fn trickled_response_exceeds_request_deadline() {
        let (address, server) = response_server(128, ResponseFraming::Trickle);
        let configuration = kube::Config::new(format!("http://{address}").parse().unwrap());
        let client = bounded_kubernetes_client(configuration).unwrap();
        let api = cleanup_api(client, "Namespace", None).unwrap();
        assert!(
            tokio::time::timeout(KUBERNETES_REQUEST_TIMEOUT, api.get("bounded"))
                .await
                .is_err()
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn request_and_attempt_deadlines_fail_closed() {
        let (service, _handle) = mock::pair::<Request<Body>, Response<Body>>();
        assert_eq!(
            issue_kubernetes_delete(
                kube::Client::new(service, "default"),
                &CleanupDeleteRequest {
                    kind: "Pod".into(),
                    namespace: Some("sandbox-run".into()),
                    name: "target-pod".into(),
                    uid_precondition: "pod-uid".into(),
                    propagation: CleanupPropagation::Background,
                },
            )
            .await,
            Err(ServiceError::Unavailable)
        );
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let progress = completed.clone();
        assert_eq!(
            cleanup_attempt_deadline(async move {
                for _ in 0..3 {
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                    progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(())
            })
            .await,
            Err(ServiceError::Unavailable)
        );
        assert!(completed.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    }

    #[tokio::test]
    async fn changed_opaque_plan_is_rejected_before_kubernetes_request() {
        let (root, service, run_id) = cleanup_service("changed-plan");
        let role = CleanupRole::new(service);
        let work = CleanupWork {
            run_id: run_id.clone(),
            cleanup_identity: format!("cleanup-{run_id}"),
            namespace_uid: "namespace-uid".into(),
            objects: Vec::new(),
            escalated: false,
        };
        let requests = vec![CleanupDeleteRequest {
            kind: "Pod".into(),
            namespace: Some("sandbox-run".into()),
            name: "target-pod".into(),
            uid_precondition: "pod-uid".into(),
            propagation: CleanupPropagation::Background,
        }];
        let digest = crate::sha256_hex(&serde_json::to_vec(&requests).unwrap());
        let mut plan = CleanupDeletePlan {
            run_id,
            cleanup_identity: work.cleanup_identity.clone(),
            cleanup_attempt: 1,
            plan_digest: digest,
            requests,
        };
        plan.requests[0].name = "changed-target".into();
        let (client, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        assert_eq!(
            role.execute_kubernetes_attempt_with_client(
                &work,
                &plan,
                kube::Client::new(client, "default"),
                1_800_000_002,
            )
            .await,
            Err(ServiceError::OwnershipMismatch)
        );
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_millis(20), handle.next_request(),)
                .await,
            Ok(None) | Err(_)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn concrete_delete_binds_uid_and_propagation() {
        let (service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let responder = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::DELETE);
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/sandbox-run/pods/target-pod"
            );
            let bytes = http_body_util::BodyExt::collect(request.into_body())
                .await
                .unwrap()
                .to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["preconditions"]["uid"], "pod-uid");
            assert_eq!(body["propagationPolicy"], "Background");
            send.send_response(response(
                StatusCode::OK,
                serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Success"
                }),
            ));
        });
        issue_kubernetes_delete(
            kube::Client::new(service, "default"),
            &CleanupDeleteRequest {
                kind: "Pod".into(),
                namespace: Some("sandbox-run".into()),
                name: "target-pod".into(),
                uid_precondition: "pod-uid".into(),
                propagation: CleanupPropagation::Background,
            },
        )
        .await
        .unwrap();
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn namespace_absence_short_circuits_namespaced_observation() {
        let (service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let responder = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/sandbox-0123456789abcdef0123456789abcdef"
            );
            send.send_response(response(
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "NotFound", "code": 404
                }),
            ));
        });
        let observation =
            observe_kubernetes_cleanup(kube::Client::new(service, "default"), &work())
                .await
                .unwrap();
        assert!(observation
            .rows
            .iter()
            .all(|row| row.response == CleanupApiObservation::Absent));
        assert!(observation.owned_orphans.is_empty());
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn present_namespace_scans_only_frozen_cleanup_rbac_kinds() {
        let (service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let responder = tokio::spawn(async move {
            let mut paths = Vec::new();
            for index in 0..10 {
                let (request, send) = handle.next_request().await.unwrap();
                paths.push(request.uri().path().to_owned());
                if index == 0 {
                    send.send_response(response(
                        StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "Namespace",
                            "metadata": {
                                "name": "sandbox-0123456789abcdef0123456789abcdef",
                                "uid": "namespace-uid"
                            }
                        }),
                    ));
                } else {
                    send.send_response(response(
                        StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "List",
                            "metadata": {"resourceVersion": "1"}, "items": []
                        }),
                    ));
                }
            }
            assert!(paths.iter().any(|path| path.ends_with("/pods")));
            assert!(paths.iter().any(|path| path.ends_with("/replicasets")));
            assert!(paths.iter().any(|path| path.ends_with("/networkpolicies")));
            assert!(!paths.iter().any(|path| path.ends_with("/configmaps")));
            assert!(!paths.iter().any(|path| path.ends_with("/secrets")));
            assert!(!paths.iter().any(|path| path.ends_with("/jobs")));
        });
        let mut namespace_only = work();
        namespace_only
            .objects
            .retain(|object| object.kind == "Namespace");
        let observation =
            observe_kubernetes_cleanup(kube::Client::new(service, "default"), &namespace_only)
                .await
                .unwrap();
        assert_eq!(observation.rows.len(), 1);
        assert!(matches!(
            observation.rows[0].response,
            CleanupApiObservation::Present(_)
        ));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn concrete_observer_rejects_oversized_and_over_count_lists() {
        let namespace_body = serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {
                "name": "sandbox-0123456789abcdef0123456789abcdef",
                "uid": "namespace-uid"
            }
        });
        let cases = [
            serde_json::json!({
                "apiVersion": "v1", "kind": "List",
                "metadata": {"resourceVersion": "1"},
                "items": [
                    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "a"}},
                    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "b"}},
                    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "c"}}
                ]
            }),
            serde_json::json!({
                "apiVersion": "v1", "kind": "List",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": "a"}, "payload": "x".repeat(2 * 1024 * 1024)
                }]
            }),
        ];
        for list_body in cases {
            let (service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
            let namespace_body = namespace_body.clone();
            let responder = tokio::spawn(async move {
                let (_, namespace_send) = handle.next_request().await.unwrap();
                namespace_send.send_response(response(StatusCode::OK, namespace_body));
                let (request, list_send) = handle.next_request().await.unwrap();
                assert!(request.uri().path().ends_with("/serviceaccounts"));
                list_send.send_response(response(StatusCode::OK, list_body));
            });
            let mut namespace_only = work();
            namespace_only
                .objects
                .retain(|object| object.kind == "Namespace");
            assert_eq!(
                observe_kubernetes_cleanup(kube::Client::new(service, "default"), &namespace_only,)
                    .await,
                Err(ServiceError::OwnershipMismatch)
            );
            responder.await.unwrap();
        }
    }

    #[test]
    fn response_and_closed_list_bounds_fail_closed() {
        let resource = cleanup_api_resource("Pod").unwrap();
        let oversized = kube::core::DynamicObject::new("pod", &resource)
            .data(serde_json::json!({"payload": "x".repeat(2 * 1024 * 1024)}));
        assert_eq!(
            bounded_kubernetes_value(oversized),
            Err(ServiceError::Unavailable)
        );
        assert_eq!(cleanup_list_max("Pod"), 1);
        assert_eq!(cleanup_list_max("ReplicaSet"), 2);
        assert_eq!(cleanup_list_max("ConfigMap"), 0);
    }
}
