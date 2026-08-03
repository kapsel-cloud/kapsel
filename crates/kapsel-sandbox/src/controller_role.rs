//! Concrete serialized controller role for the fixed native runner boundary.
//!
//! This role is the sole production composition of scheduling, current handoff assignment, fixed
//! input staging, and runner-generation supervision. It is not a generic process interface.

#![allow(
    clippy::similar_names,
    reason = "paired UID/GID bindings make exact numeric identity checks auditable"
)]

use std::{fmt, path::PathBuf, sync::Arc};

use ed25519_dalek::SigningKey;
use kapsel::{provision_exact_grant, ExactAuthorization, GrantProvisioning};
use kube::{config::KubeConfigOptions, Config};

use crate::{
    fixed_staging::{FixedStagingError, FixedStagingReader},
    local_roles::KubernetesCleanupRole,
    runner_host::{RunnerHost, RunnerHostError},
    DispatchLease, RetentionRole, SchedulerRole, SchedulerStep, Service, ServiceError,
};

/// Fixed deployment configuration for the serialized controller role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerConfiguration {
    generation_directory: PathBuf,
    runner_uid: u32,
    runner_gid: u32,
}

impl ControllerConfiguration {
    /// Names the deployment-owned runner generation root and numeric identity.
    ///
    /// The runner executable is deliberately not configurable. The role binds the current
    /// `kapsel-sandbox` program image and opens the crate-private authority reader itself.
    #[must_use]
    pub fn new(generation_directory: PathBuf, runner_uid: u32, runner_gid: u32) -> Self {
        Self {
            generation_directory,
            runner_uid,
            runner_gid,
        }
    }
}

/// Bounded controller-role failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    /// Durable scheduling or current-assignment validation failed.
    Service(ServiceError),
    /// Fixed host inputs, roots, executable, or durable generation state failed closed.
    Boundary,
    /// Runner launch, fencing, or wait failed.
    Process,
    /// No current reservation or runner generation was available for the requested role step.
    Inactive,
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Service(_) => "serialized controller service transition failed",
            Self::Boundary => "serialized controller boundary is invalid",
            Self::Process => "serialized controller runner operation failed",
            Self::Inactive => "serialized controller has no current runner",
        })
    }
}

impl std::error::Error for ControllerError {}

impl From<ServiceError> for ControllerError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

fn controller_staging_error(error: FixedStagingError) -> ControllerError {
    match error {
        FixedStagingError::Unavailable => ControllerError::Service(ServiceError::Unavailable),
        FixedStagingError::Boundary | FixedStagingError::RotationCeiling => {
            ControllerError::Boundary
        },
    }
}

/// Non-secret identity of the one runner generation supervised by the controller role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerRun {
    run_id: String,
    operation_id: String,
    generation: u64,
}

impl ControllerRun {
    /// Returns the durable public run identity.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the fixed KAP-0038 operation identity for the same run.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the monotonic host generation number.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Result of waiting for the one supervised runner generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerWait {
    run: ControllerRun,
    success: bool,
}

impl ControllerWait {
    /// Returns the exact run and operation generation that exited.
    #[must_use]
    pub fn run(&self) -> &ControllerRun {
        &self.run
    }

    /// Reports only OS process success; it does not classify a receiver result.
    #[must_use]
    pub fn success(&self) -> bool {
        self.success
    }
}

struct PreparedRunnerInputs {
    assignment: crate::HandoffAssignment,
    files: Vec<(&'static str, Vec<u8>)>,
}

/// One concrete local scheduler/controller owning at most one runner generation.
pub struct ControllerRole {
    service: Service,
    scheduler: SchedulerRole,
    configuration: ControllerConfiguration,
    staging: Arc<FixedStagingReader>,
    host: Option<RunnerHost>,
    scheduled: Option<DispatchLease>,
    active: Option<ControllerRun>,
}

/// Fixed authority-bound service transitions that do not launch a runner.
pub struct AuthorityController {
    service: Service,
    staging: Arc<FixedStagingReader>,
}

impl AuthorityController {
    /// Uses the reader already bound into the service; no second authority root can be supplied.
    #[must_use]
    pub fn new(service: Service) -> Self {
        let staging = service.authority_reader();
        Self { service, staging }
    }

    /// Validates the complete current generation before atomically dispatching one queued run.
    ///
    /// # Errors
    ///
    /// Returns before mutation when current authority or durable scheduling fails closed.
    pub fn dispatch_next(&self, now_unix_s: i64) -> Result<DispatchLease, ControllerError> {
        let authority = self
            .staging
            .current_identity()
            .map_err(controller_staging_error)?;
        self.service
            .dispatch_next(now_unix_s, &authority)
            .map_err(ControllerError::Service)
    }

    /// Returns the unchanged staged trust document for one retained receipt's durable generation.
    ///
    /// This channel remains separate from receipt retrieval; the receipt never appoints trust.
    ///
    /// # Errors
    ///
    /// Returns unavailable unless the retained run has a receipt and its exact pinned trust remains
    /// complete and valid.
    pub fn retained_receipt_trust(&self, run_id: &str) -> Result<Vec<u8>, ControllerError> {
        self.service
            .retained_public_trust(run_id)
            .map_err(ControllerError::Service)
    }
}

/// Fixed cleanup composition that selects only the run-pinned staged Kubernetes family.
pub struct CleanupController {
    service: Service,
    staging: Arc<FixedStagingReader>,
}

impl CleanupController {
    /// Uses the reader already bound into the service; no endpoint or credential can be supplied.
    #[must_use]
    pub fn new(service: Service) -> Self {
        let staging = service.authority_reader();
        Self { service, staging }
    }

    /// Runs at most one cleanup attempt after validating the exact durable generation.
    ///
    /// # Errors
    ///
    /// Returns before cleanup mutation or API use when the pin or staged family is unavailable.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation may leave a durably started cleanup attempt before or during Kubernetes I/O.
    /// The next invocation reselects the same authority-bound work and converges through the
    /// existing cleanup retry state; cancellation never creates a receiver result.
    pub async fn run_once(&self, now_unix_s: i64) -> Result<bool, ControllerError> {
        let Some(identity) = self.service.sole_cleanup_authority_identity()? else {
            return Ok(false);
        };
        let material = self
            .staging
            .cleanup_kubernetes(&identity)
            .map_err(controller_staging_error)?;
        let kubeconfig_text = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "cleanup",
            "clusters": [{"name": "cleanup", "cluster": {
                "server": material.api_server,
                "certificate-authority-data": crate::encode_base64(&material.ca_bytes),
            }}],
            "contexts": [{"name": "cleanup", "context": {
                "cluster": "cleanup", "user": "cleanup",
            }}],
            "users": [{"name": "cleanup", "user": {"token": material.token}}],
        })
        .to_string();
        let kubeconfig = kube::config::Kubeconfig::from_yaml(&kubeconfig_text)
            .map_err(|_| ControllerError::Boundary)?;
        let mut configuration =
            Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                .await
                .map_err(|_| ControllerError::Boundary)?;
        configuration.proxy_url = None;
        let role = KubernetesCleanupRole::new(self.service.clone(), configuration, identity)?;
        role.run_once(now_unix_s)
            .await
            .map_err(ControllerError::Service)
    }
}

/// Periodic retention composition backed by the same fixed authority root.
pub struct RetentionController {
    service: Service,
    role: RetentionRole,
    staging: Arc<FixedStagingReader>,
}

impl RetentionController {
    /// Uses the reader already bound into the service; no second authority root can be supplied.
    #[must_use]
    pub fn new(service: Service) -> Self {
        let staging = service.authority_reader();
        Self {
            service: service.clone(),
            role: RetentionRole::new(service),
            staging,
        }
    }

    /// Reads the current complete generation and performs one authority-bound retention sweep.
    ///
    /// # Errors
    ///
    /// Returns before mutation when current authority is missing or invalid.
    pub fn run_once(&self, now_unix_s: i64) -> Result<(), ControllerError> {
        self.staging
            .tombstone_keyring()
            .map_err(controller_staging_error)?;
        self.role.run_once(now_unix_s)?;
        self.service.collect_unused_authority()?;
        Ok(())
    }
}

impl ControllerRole {
    /// Opens the concrete role and fixed authority reader without touching the runner boundary.
    ///
    /// [`Self::run_once`] always validates durable active authority before recovery and validates
    /// current authority before fresh dispatch.
    ///
    #[must_use]
    pub fn new(service: Service, configuration: ControllerConfiguration) -> Self {
        let staging = service.authority_reader();
        let scheduler = SchedulerRole::new(service.clone());
        Self {
            service,
            scheduler,
            configuration,
            staging,
            host: None,
            scheduled: None,
            active: None,
        }
    }

    /// Recovers the sole active reservation before considering one FIFO dispatch.
    ///
    /// The returned lease remains the existing concrete scheduler result. The role retains the
    /// same lease internally so only the exact current assignment can be staged and launched.
    ///
    /// # Errors
    ///
    /// Returns a bounded service failure when durable scheduling cannot be read or advanced.
    fn schedule_once(&mut self, now_unix_s: i64) -> Result<SchedulerStep, ControllerError> {
        let current_authority =
            if let Some(pinned) = self.service.sole_active_authority_identity()? {
                self.staging
                    .validate_identity(&pinned)
                    .map_err(controller_staging_error)?;
                None
            } else {
                Some(
                    self.staging
                        .current_identity()
                        .map_err(controller_staging_error)?,
                )
            };
        let step = self
            .scheduler
            .run_once(now_unix_s, current_authority.as_ref())?;
        self.scheduled = match &step {
            SchedulerStep::Active(lease)
            | SchedulerStep::Recovered(lease)
            | SchedulerStep::Dispatched(lease) => Some(lease.clone()),
            SchedulerStep::Waiting => None,
        };
        Ok(step)
    }

    fn runner_inputs(
        &self,
        lease: &DispatchLease,
        now_unix_s: i64,
    ) -> Result<PreparedRunnerInputs, ControllerError> {
        let authorization = self
            .staging
            .authorization(&lease.authority)
            .map_err(controller_staging_error)?;
        let receipt = self
            .staging
            .receipt(&lease.authority)
            .map_err(controller_staging_error)?;
        let kubernetes = self
            .staging
            .runner_kubernetes(&lease.authority)
            .map_err(controller_staging_error)?;
        let handoff = self
            .staging
            .handoff(&lease.authority)
            .map_err(controller_staging_error)?;
        let request = self.service.server_owned_request(&lease.run_id)?;
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &ExactAuthorization {
                authorization_id: format!("auth-{}", lease.run_id),
                operation_id: request.operation_id.clone(),
                namespace: request.namespace.clone(),
                deployment: request.deployment.clone(),
                container: request.container.clone(),
                immutable_image_digest: request.immutable_image_digest.clone(),
            },
            signing_seed: &authorization.signing_seed,
            signing_key_id: &authorization.signing_key_id,
        })
        .map_err(|_| ControllerError::Boundary)?;
        let authorization_public_key =
            SigningKey::from_bytes(&authorization.signing_seed).verifying_key();
        let trust = serde_json::to_vec(&serde_json::json!({
            "key_id": authorization.signing_key_id,
            "public_key_hex": lower_hex(&authorization_public_key.to_bytes()),
        }))
        .map_err(|_| ControllerError::Boundary)?;
        let assignment = self
            .service
            .handoff_assignment(lease, handoff.endpoint, now_unix_s)?;
        let request_document = serde_json::to_vec(&serde_json::json!({
            "operation_id": &request.operation_id,
            "namespace": &request.namespace,
            "deployment": &request.deployment,
            "container": &request.container,
            "immutable_image_digest": &request.immutable_image_digest,
        }))
        .map_err(|_| ControllerError::Boundary)?;
        let inputs = vec![
            ("request.json", request_document),
            ("signed-authorization-grant.bin", grant),
            ("authorization-trust.json", trust),
            ("kubernetes-api-server", kubernetes.api_server.into_bytes()),
            ("kubernetes-ca.pem", kubernetes.ca_bytes),
            ("kubernetes-namespace", request.namespace.into_bytes()),
            ("kubernetes-token", kubernetes.token.into_bytes()),
            ("receipt-signing-seed", receipt.signing_seed.to_vec()),
            (
                "receipt-signing-key-id",
                receipt.signing_key_id.into_bytes(),
            ),
            (
                "handoff-endpoint",
                assignment.endpoint().to_string().into_bytes(),
            ),
            (
                "handoff-lease-id",
                assignment.lease_id().as_bytes().to_vec(),
            ),
            ("handoff-credential", assignment.credential().to_vec()),
        ];
        Ok(PreparedRunnerInputs {
            assignment,
            files: inputs,
        })
    }

    /// Obtains the exact current assignment from `Service`, stages all twelve fixed runner inputs,
    /// and launches or replaces the same run and operation behind the crate-private host.
    ///
    /// # Errors
    ///
    /// Returns a service, boundary, process, or inactive-role failure before unsafe launch.
    fn launch_scheduled(&mut self, now_unix_s: i64) -> Result<&ControllerRun, ControllerError> {
        let lease = self
            .scheduled
            .as_ref()
            .ok_or(ControllerError::Inactive)?
            .clone();
        // Fresh dispatch remains blocked until Slice 3 policy verification closes provisioning.
        // Already-invoked same-run recovery remains eligible after its ordinary deadline.
        self.service.validate_runner_launch(&lease, now_unix_s)?;
        let prepared = self.runner_inputs(&lease, now_unix_s)?;
        let published = self
            .staging
            .publish_runner_inputs(&lease.run_id, lease.epoch(), &prepared.files)
            .map_err(controller_staging_error)?;
        self.open_host()?;
        let retained_identity = self
            .host
            .as_ref()
            .and_then(crate::runner_host::RunnerHost::retained_identity);
        if retained_identity.is_some_and(|(run_id, operation_id)| {
            run_id != lease.run_id || operation_id != prepared.assignment.operation_id
        }) {
            return Err(ControllerError::Boundary);
        }
        let host = self.host.as_mut().ok_or(ControllerError::Boundary)?;
        let generation = if host.active().is_some() {
            host.replace(&lease.run_id, &prepared.assignment, &published)?
                .generation()
        } else {
            host.launch(&lease.run_id, &prepared.assignment, &published)?
                .generation()
        };
        let run = ControllerRun {
            run_id: lease.run_id.clone(),
            operation_id: format!("sandbox-{}", lease.run_id),
            generation,
        };
        if self.active.as_ref().is_some_and(|active| {
            active.run_id != run.run_id || active.operation_id != run.operation_id
        }) {
            return Err(ControllerError::Boundary);
        }
        self.active = Some(run);
        self.active.as_ref().ok_or(ControllerError::Process)
    }

    /// Performs one production scheduling and launch/replacement step.
    ///
    /// # Errors
    ///
    /// Returns a service, boundary, process, or inactive-role failure for the concrete step.
    pub fn run_once(&mut self, now_unix_s: i64) -> Result<Option<&ControllerRun>, ControllerError> {
        if let Some(run_id) = self.service.sole_active_run()? {
            if self.converge_runner_retirement(&run_id)? {
                self.scheduled = None;
                self.active = None;
                return Ok(None);
            }
        }
        match self.schedule_once(now_unix_s)? {
            SchedulerStep::Waiting => Ok(None),
            SchedulerStep::Active(lease) if self.active.is_none() => {
                // Opening the durable boundary fences any recorded generation before this role
                // waits for a fresh recovery lease. The still-active scheduler lease is never used
                // to launch a replacement with stale raw authority.
                self.open_host()?;
                self.converge_runner_retirement(&lease.run_id)?;
                Ok(None)
            },
            SchedulerStep::Active(_) => Ok(self.active.as_ref()),
            SchedulerStep::Recovered(lease) | SchedulerStep::Dispatched(lease) => {
                if self.converge_runner_retirement(&lease.run_id)? {
                    Ok(None)
                } else {
                    self.launch_scheduled(now_unix_s).map(Some)
                }
            },
        }
    }

    fn converge_runner_retirement(&mut self, run_id: &str) -> Result<bool, ControllerError> {
        let (retiring, retired) = self.service.runner_retirement_state(run_id)?;
        if retired {
            self.service.converge_retired_dispatch(run_id)?;
            return Ok(true);
        }
        if !retiring {
            return Ok(false);
        }
        self.open_host()?;
        let host = self.host.as_mut().ok_or(ControllerError::Inactive)?;
        match host.retained_identity() {
            Some((retained_run_id, _)) if retained_run_id == run_id => host.retire(run_id)?,
            Some(_) => return Err(ControllerError::Boundary),
            None => {},
        }
        self.service.commit_runner_state_retired(run_id)?;
        Ok(true)
    }

    fn open_host(&mut self) -> Result<(), ControllerError> {
        if self.host.is_none() {
            self.host = Some(RunnerHost::open(
                fixed_current_executable()?,
                &self.configuration.generation_directory,
                self.configuration.runner_uid,
                self.configuration.runner_gid,
            )?);
        }
        Ok(())
    }

    /// Waits for the one active generation and retains its sole journal for recovery.
    ///
    /// # Errors
    ///
    /// Returns an inactive, boundary, or process failure unless the generation is reaped.
    pub fn wait(&mut self) -> Result<ControllerWait, ControllerError> {
        let run = self.active.take().ok_or(ControllerError::Inactive)?;
        let status = self
            .host
            .as_mut()
            .ok_or(ControllerError::Inactive)?
            .wait()?;
        match self.service.begin_runner_retirement(&run.run_id) {
            Ok(()) => {
                self.host
                    .as_mut()
                    .ok_or(ControllerError::Inactive)?
                    .retire(&run.run_id)?;
                self.service.commit_runner_state_retired(&run.run_id)?;
            },
            Err(ServiceError::InvalidTransition) => {},
            Err(error) => return Err(error.into()),
        }
        Ok(ControllerWait {
            run,
            success: status.success(),
        })
    }
}

impl From<RunnerHostError> for ControllerError {
    fn from(error: RunnerHostError) -> Self {
        match error {
            RunnerHostError::Process => Self::Process,
            RunnerHostError::Boundary
            | RunnerHostError::Identity
            | RunnerHostError::ActiveGeneration
            | RunnerHostError::StaleAuthority => Self::Boundary,
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn fixed_current_executable() -> Result<PathBuf, ControllerError> {
    let current = std::env::current_exe().map_err(|_| ControllerError::Boundary)?;
    if current.file_name().and_then(|name| name.to_str()) == Some("kapsel-sandbox") {
        return Ok(current);
    }
    let parent = current.parent().ok_or(ControllerError::Boundary)?;
    if parent.file_name().and_then(|name| name.to_str()) == Some("deps") {
        let candidate = parent
            .parent()
            .ok_or(ControllerError::Boundary)?
            .join("kapsel-sandbox");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(ControllerError::Boundary)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        sync::mpsc,
        thread,
    };

    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig, ServerConnection, StreamOwned,
    };

    use super::*;

    fn cleanup_failure_server(
        listener: TcpListener,
    ) -> (mpsc::Receiver<bool>, thread::JoinHandle<()>) {
        const FAILURE_RESPONSE: &[u8] = concat!(
            "HTTP/1.1 500 Internal Server Error\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n\r\n{}"
        )
        .as_bytes();
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let configuration = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("../tests/fixtures/localhost-cert.der").to_vec(),
                    )],
                    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                        include_bytes!("../tests/fixtures/localhost-key.der").to_vec(),
                    )),
                )
                .unwrap();
            let connection = ServerConnection::new(Arc::new(configuration)).unwrap();
            let (stream, _) = listener.accept().unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let mut request = [0_u8; 8192];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            sender
                .send(request.contains("authorization: Bearer cleanup-token\r\n"))
                .unwrap();
            stream.write_all(FAILURE_RESPONSE).unwrap();
            stream.flush().unwrap();
        });
        (receiver, server)
    }

    #[tokio::test]
    async fn cleanup_controller_uses_the_run_pinned_staged_tls_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("https://{}", listener.local_addr().unwrap());
        let (root, service, run_id) =
            crate::test_authority::cleanup_service("staged-composition", Some(&endpoint));
        crate::test_authority::rotate(&root, [8; 32]);
        let (authorization, server) = cleanup_failure_server(listener);
        let controller = CleanupController::new(service.clone());
        assert!(controller.run_once(1_800_000_002).await.is_err());
        assert!(authorization.recv().unwrap());
        server.join().unwrap();
        assert_eq!(
            service
                .snapshot(&run_id, 1_800_000_002)
                .unwrap()
                .cleanup_state,
            crate::CleanupState::Failed
        );
        crate::test_authority::remove_root(&root);
    }

    #[tokio::test]
    async fn missing_pinned_cleanup_authority_holds_before_cleanup_mutation() {
        let (root, service, run_id) = crate::test_authority::cleanup_service(
            "missing-staged-composition",
            Some("https://localhost:9"),
        );
        crate::test_authority::rotate(&root, [8; 32]);
        let database = root.join("sandbox.sqlite3");
        let facts = || {
            rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    concat!(
                        "SELECT runs.execution_state, runs.cleanup_state, ",
                        "(SELECT COUNT(*) FROM events WHERE events.run_id = runs.run_id) ",
                        "FROM runs WHERE run_id = ?1"
                    ),
                    [&run_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap()
        };
        let before = facts();
        let old_generation =
            root.join("fixed-authority/generations/generation-00000000000000000001");
        fs::set_permissions(&old_generation, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&old_generation).unwrap();
        let controller = CleanupController::new(service);
        assert!(controller.run_once(1_800_000_002).await.is_err());
        assert_eq!(facts(), before);
        crate::test_authority::remove_root(&root);
    }
}
