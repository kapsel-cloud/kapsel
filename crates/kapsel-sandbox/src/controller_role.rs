//! Concrete serialized controller role for the fixed native runner boundary.
//!
//! This role is the sole production composition of scheduling, current handoff assignment, fixed
//! input staging, and runner-generation supervision. It is not a generic process interface.

#![allow(
    clippy::similar_names,
    reason = "paired UID/GID bindings make exact numeric identity checks auditable"
)]

use std::{
    fmt, fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::fs::{openat, Mode, OFlags, CWD};

use crate::{
    runner_host::{RunnerHost, RunnerHostError},
    DispatchLease, SchedulerRole, SchedulerStep, Service, ServiceError,
};

/// Fixed deployment configuration for the serialized controller role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerConfiguration {
    input_directory: PathBuf,
    generation_directory: PathBuf,
    runner_uid: u32,
    runner_gid: u32,
    handoff_endpoint: SocketAddr,
}

impl ControllerConfiguration {
    /// Names the deployment-owned runner roots, numeric identity, and private loopback handoff.
    ///
    /// The runner executable is deliberately not configurable. The role binds the current
    /// `kapsel-sandbox` program image.
    #[must_use]
    pub fn new(
        input_directory: PathBuf,
        generation_directory: PathBuf,
        runner_uid: u32,
        runner_gid: u32,
        handoff_endpoint: SocketAddr,
    ) -> Self {
        Self {
            input_directory,
            generation_directory,
            runner_uid,
            runner_gid,
            handoff_endpoint,
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

/// One concrete local scheduler/controller owning at most one runner generation.
pub struct ControllerRole {
    service: Service,
    scheduler: SchedulerRole,
    configuration: ControllerConfiguration,
    host: Option<RunnerHost>,
    scheduled: Option<DispatchLease>,
    active: Option<ControllerRun>,
}

impl ControllerRole {
    /// Opens the concrete role without touching the runner boundary.
    ///
    /// [`Self::run_once`] always recovers durable active capacity before it opens or fences the
    /// durable runner generation.
    #[must_use]
    pub fn new(service: Service, configuration: ControllerConfiguration) -> Self {
        let scheduler = SchedulerRole::new(service.clone());
        Self {
            service,
            scheduler,
            configuration,
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
        let step = self.scheduler.run_once(now_unix_s)?;
        self.scheduled = match &step {
            SchedulerStep::Active(lease)
            | SchedulerStep::Recovered(lease)
            | SchedulerStep::Dispatched(lease) => Some(lease.clone()),
            SchedulerStep::Waiting => None,
        };
        Ok(step)
    }

    /// Obtains the exact current assignment from `Service`, stages its three fixed handoff inputs,
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
        // Slice 2 never provisions a target. A freshly dispatched run therefore stops here until
        // the separately gated provisioning role has durably verified the complete target policy.
        // Already-invoked recovery remains eligible after its ordinary execution deadline.
        self.service.validate_runner_launch(&lease, now_unix_s)?;
        let assignment = self.service.handoff_assignment(
            &lease,
            self.configuration.handoff_endpoint,
            now_unix_s,
        )?;
        stage_handoff_inputs(&self.configuration.input_directory, &assignment)?;
        self.open_host()?;
        let host = self.host.as_mut().ok_or(ControllerError::Boundary)?;
        let generation = if host.active().is_some() {
            host.replace(&lease.run_id, &assignment)?.generation()
        } else {
            host.launch(&lease.run_id, &assignment)?.generation()
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
        match self.schedule_once(now_unix_s)? {
            SchedulerStep::Waiting => Ok(None),
            SchedulerStep::Active(_) if self.active.is_none() => {
                // Opening the durable boundary fences any recorded generation before this role
                // waits for a fresh recovery lease. The still-active scheduler lease is never used
                // to launch a replacement with stale raw authority.
                self.open_host()?;
                Ok(None)
            },
            SchedulerStep::Active(_) => Ok(self.active.as_ref()),
            SchedulerStep::Recovered(_) | SchedulerStep::Dispatched(_) => {
                self.launch_scheduled(now_unix_s).map(Some)
            },
        }
    }

    fn open_host(&mut self) -> Result<(), ControllerError> {
        if self.host.is_none() {
            self.host = Some(RunnerHost::open(
                fixed_current_executable()?,
                &self.configuration.input_directory,
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

fn stage_handoff_inputs(
    input_directory: &Path,
    assignment: &crate::HandoffAssignment,
) -> Result<(), ControllerError> {
    if !input_directory.is_absolute() || !assignment.endpoint().ip().is_loopback() {
        return Err(ControllerError::Boundary);
    }
    let root = fs::File::from(
        openat(
            CWD,
            input_directory,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(|_| ControllerError::Boundary)?,
    );
    let metadata = root.metadata().map_err(|_| ControllerError::Boundary)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ControllerError::Boundary);
    }
    for (name, bytes) in [
        (
            "handoff-endpoint",
            assignment.endpoint().to_string().into_bytes(),
        ),
        (
            "handoff-lease-id",
            assignment.lease_id().as_bytes().to_vec(),
        ),
        ("handoff-credential", assignment.credential().to_vec()),
    ] {
        let temporary = format!(".{name}.controller-stage");
        let _ = rustix::fs::unlinkat(&root, &temporary, rustix::fs::AtFlags::empty());
        let mut output = fs::File::from(
            openat(
                &root,
                &temporary,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o400),
            )
            .map_err(|_| ControllerError::Boundary)?,
        );
        output
            .write_all(&bytes)
            .map_err(|_| ControllerError::Boundary)?;
        output.sync_all().map_err(|_| ControllerError::Boundary)?;
        rustix::fs::renameat(&root, &temporary, &root, name)
            .map_err(|_| ControllerError::Boundary)?;
    }
    root.sync_all().map_err(|_| ControllerError::Boundary)
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
