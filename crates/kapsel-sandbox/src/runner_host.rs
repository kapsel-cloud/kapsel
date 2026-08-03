//! Controller-owned native runner host boundary.
//!
//! This is one fixed launcher for one sandbox runner generation. It is not a generic process,
//! secret, storage, or provider interface.

#![allow(
    clippy::similar_names,
    reason = "paired UID/GID bindings make exact numeric identity checks auditable"
)]

use std::{
    fmt, fs,
    io::{IoSlice, Write as _},
    mem::MaybeUninit,
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixDatagram,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

use rustix::fs::{mkdirat, openat, Mode, OFlags, CWD};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::{
    fixed_staging::PublishedRunnerInputs,
    runner_process::{credential_verifier, descriptor_identity, Bootstrap, INPUT_NAMES},
    HandoffAssignment,
};

/// Fixed native runner-host failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunnerHostError {
    /// A trusted root, fixed input, owner, mode, inode, or generation was invalid.
    Boundary,
    /// The requested numeric runner identity was not distinct or could not be installed.
    Identity,
    /// A current generation must be fenced before an ordinary launch.
    ActiveGeneration,
    /// Replacement did not carry a newly rotated lease and credential.
    StaleAuthority,
    /// The runner process could not be started, signaled, or waited.
    Process,
}

impl fmt::Display for RunnerHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Boundary => "runner host boundary is invalid",
            Self::Identity => "runner host identity is invalid",
            Self::ActiveGeneration => "runner generation is already active",
            Self::StaleAuthority => "runner replacement authority is stale",
            Self::Process => "runner host process operation failed",
        })
    }
}

impl std::error::Error for RunnerHostError {}

const GENERATION_RECORD_NAME: &str = "runner-generation.json";
const GENERATION_RECORD_TEMPORARY_NAME: &str = ".runner-generation.tmp";
const GENERATION_RECORD_BYTES_MAX: usize = 8 * 1024;
const MAX_GENERATION_ROOT_ENTRIES: usize = 4;
const RUNNER_READY: &[u8] = b"KAPSEL-SANDBOX-RUNNER-READY-V1\0";
const RUNNER_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const RUNNER_RELEASE: &[u8] = b"KAPSEL-SANDBOX-RUNNER-RELEASE-V1\0";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableGenerationRecord {
    version: u8,
    run_id: String,
    operation_id: String,
    generation: u64,
    runner_uid: u32,
    runner_gid: u32,
    process_id: Option<u32>,
    start_identity: Option<String>,
    lease_id: String,
    credential_verifier: String,
    generation_device: u64,
    generation_inode: u64,
    run_device: u64,
    run_inode: u64,
    journal_device: Option<u64>,
    journal_inode: Option<u64>,
    cgroup_path: Option<String>,
    cgroup_device: Option<u64>,
    cgroup_inode: Option<u64>,
    phase: String,
}

/// Controller record for the one running process and authority generation.
pub(crate) struct RunnerGeneration {
    child: Child,
    generation: u64,
    lease_id: String,
    credential_verifier: String,
    directory_descriptor: fs::File,
    #[cfg(target_os = "linux")]
    cgroup_name: String,
}

impl RunnerGeneration {
    /// Returns the monotonic fresh generation number.
    #[must_use]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for RunnerGeneration {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
struct CgroupBoundary {
    directory: fs::File,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
static CGROUP_BOUNDARY_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(target_os = "linux")]
impl CgroupBoundary {
    fn open(identity: u64) -> Result<Self, RunnerHostError> {
        let root = fs::File::from(
            openat(CWD, "/sys/fs/cgroup", directory_flags(), Mode::empty())
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        let nonce = CGROUP_BOUNDARY_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!(
            "kapsel-sandbox-controller-{}-{identity}-{nonce}",
            std::process::id()
        );
        mkdirat(&root, &name, Mode::from_raw_mode(0o700)).map_err(|_| RunnerHostError::Boundary)?;
        let directory = fs::File::from(
            openat(&root, &name, directory_flags(), Mode::empty())
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        Ok(Self {
            directory,
            path: Path::new("/sys/fs/cgroup").join(name),
        })
    }

    fn generation_name(generation: u64) -> String {
        format!("generation-{generation:020}")
    }

    fn planned_path(&self, generation: u64) -> PathBuf {
        self.path.join(Self::generation_name(generation))
    }

    fn prepare(&self, generation: u64) -> Result<String, RunnerHostError> {
        let name = Self::generation_name(generation);
        mkdirat(&self.directory, &name, Mode::from_raw_mode(0o700))
            .map_err(|_| RunnerHostError::Boundary)?;
        Ok(name)
    }

    fn identity(&self, generation: &str) -> Result<(u64, u64), RunnerHostError> {
        let directory = fs::File::from(
            openat(
                &self.directory,
                generation,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|_| RunnerHostError::Boundary)?,
        );
        let metadata = directory
            .metadata()
            .map_err(|_| RunnerHostError::Boundary)?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn write(&self, generation: &str, file: &str, bytes: &[u8]) -> Result<(), RunnerHostError> {
        let generation = fs::File::from(
            openat(
                &self.directory,
                generation,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|_| RunnerHostError::Boundary)?,
        );
        let descriptor = openat(
            &generation,
            file,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| RunnerHostError::Boundary)?;
        let mut output = fs::File::from(descriptor);
        output
            .write_all(bytes)
            .map_err(|_| RunnerHostError::Process)
    }

    fn attach(&self, generation: &str, process_id: u32) -> Result<(), RunnerHostError> {
        self.write(
            generation,
            "cgroup.procs",
            process_id.to_string().as_bytes(),
        )
    }

    fn fence(&self, generation: &str) -> Result<(), RunnerHostError> {
        let directory = self.path.join(generation);
        let events = directory.join("cgroup.events");
        let initial = fs::read_to_string(&events).map_err(|_| RunnerHostError::Process)?;
        if !initial.lines().any(|line| line == "populated 0")
            && self.write(generation, "cgroup.kill", b"1").is_err()
            && !fs::read_to_string(&events)
                .is_ok_and(|value| value.lines().any(|line| line == "populated 0"))
        {
            return Err(RunnerHostError::Process);
        }
        for _ in 0..30_000 {
            let value = fs::read_to_string(&events).map_err(|_| RunnerHostError::Process)?;
            if value.lines().any(|line| line == "populated 0") {
                for _ in 0..30_000 {
                    match fs::remove_dir(&directory) {
                        Ok(()) => return Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                    }
                }
                return Err(RunnerHostError::Process);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err(RunnerHostError::Process)
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupBoundary {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

/// One controller-owned host for at most one native runner generation.
pub(crate) struct RunnerHost {
    executable: PathBuf,
    generation_root_path: PathBuf,
    generation_root: fs::File,
    controller_uid: u32,
    controller_gid: u32,
    runner_uid: u32,
    runner_gid: u32,
    next_generation: u64,
    active: Option<RunnerGeneration>,
    recovery_directory: Option<fs::File>,
    durable_record: Option<DurableGenerationRecord>,
    #[cfg(target_os = "linux")]
    cgroup: Option<CgroupBoundary>,
}

impl RunnerHost {
    /// Opens and pins the generation root before any per-run input is accepted.
    ///
    /// On Linux, the runner UID and GID must both differ from the controller's effective numeric
    /// identity. The caller must have authority to chown the fresh generation and drop the child
    /// to that identity. Other Unix hosts are deterministic contract-test platforms only.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerHostError`] unless the executable is absolute and the generation root is an
    /// exact owner-private, non-symlink directory under the controller identity.
    pub(crate) fn open(
        executable: impl AsRef<Path>,
        generation_root: impl AsRef<Path>,
        runner_uid: u32,
        runner_gid: u32,
    ) -> Result<Self, RunnerHostError> {
        let executable = executable.as_ref();
        let generation_root_path = generation_root.as_ref();
        if !executable.is_absolute() || !generation_root_path.is_absolute() {
            return Err(RunnerHostError::Boundary);
        }
        let controller_uid = rustix::process::geteuid().as_raw();
        let controller_gid = rustix::process::getegid().as_raw();
        #[cfg(target_os = "linux")]
        if runner_uid == controller_uid || runner_gid == controller_gid {
            return Err(RunnerHostError::Identity);
        }
        #[cfg(not(target_os = "linux"))]
        if (runner_uid != controller_uid || runner_gid != controller_gid) && controller_uid != 0 {
            return Err(RunnerHostError::Identity);
        }
        let generation_root =
            open_private_root(generation_root_path, controller_uid, controller_gid)?;
        let mut host = Self {
            executable: executable.to_owned(),
            generation_root_path: generation_root_path.to_owned(),
            generation_root,
            controller_uid,
            controller_gid,
            runner_uid,
            runner_gid,
            next_generation: 1,
            active: None,
            recovery_directory: None,
            durable_record: None,
            #[cfg(target_os = "linux")]
            cgroup: None,
        };
        host.recover_durable_generation()?;
        Ok(host)
    }

    /// Launches one fresh generation after validating all fixed input descriptors.
    ///
    /// # Errors
    ///
    /// Returns a boundary, identity, active-generation, stale-authority, or process failure before
    /// the child can enter `Application` lifecycle work.
    pub(crate) fn launch(
        &mut self,
        run_id: &str,
        assignment: &HandoffAssignment,
        published_inputs: &PublishedRunnerInputs,
    ) -> Result<&RunnerGeneration, RunnerHostError> {
        if self.active.is_some() {
            return Err(RunnerHostError::ActiveGeneration);
        }
        self.validate_recovery_identity(run_id, &assignment.operation_id)?;
        let input_files = self.open_inputs(published_inputs, assignment)?;
        let recovery = self
            .recovery_directory
            .as_ref()
            .map(fs::File::try_clone)
            .transpose()
            .map_err(|_| RunnerHostError::Boundary)?;
        self.launch_fresh_from(run_id, assignment, recovery.as_ref(), &input_files)
    }

    /// Replaces the current runner only after a different lease and credential are already staged.
    ///
    /// The controller rotates the durable KAP-0055 lease/verifier before calling this method. This
    /// method then proves the staged assignment differs, kills and waits for the old process,
    /// closes its inherited descriptors, and only then creates the next fresh generation.
    ///
    /// # Errors
    ///
    /// Returns stale authority, boundary, identity, or process failure. A failure never leaves a
    /// newly launched generation alongside the old one.
    pub(crate) fn replace(
        &mut self,
        run_id: &str,
        assignment: &HandoffAssignment,
        published_inputs: &PublishedRunnerInputs,
    ) -> Result<&RunnerGeneration, RunnerHostError> {
        self.validate_recovery_identity(run_id, &assignment.operation_id)?;
        let new_verifier = credential_verifier(
            run_id,
            &format!("sandbox-{run_id}"),
            assignment.lease_id(),
            &assignment.credential(),
        );
        let active = self
            .active
            .as_ref()
            .ok_or(RunnerHostError::ActiveGeneration)?;
        if active.lease_id == assignment.lease_id() || active.credential_verifier == new_verifier {
            return Err(RunnerHostError::StaleAuthority);
        }
        let input_files = self.open_inputs(published_inputs, assignment)?;
        self.terminate()?;
        let recovery = self
            .recovery_directory
            .as_ref()
            .map(fs::File::try_clone)
            .transpose()
            .map_err(|_| RunnerHostError::Boundary)?;
        self.launch_fresh_from(run_id, assignment, recovery.as_ref(), &input_files)
    }

    fn validate_recovery_identity(
        &self,
        run_id: &str,
        operation_id: &str,
    ) -> Result<(), RunnerHostError> {
        match (&self.durable_record, &self.recovery_directory) {
            (None, None) => Ok(()),
            (Some(record), Some(_))
                if record.run_id == run_id && record.operation_id == operation_id =>
            {
                Ok(())
            },
            (Some(_), Some(_)) => Err(RunnerHostError::StaleAuthority),
            _ => Err(RunnerHostError::Boundary),
        }
    }

    /// Returns the run identity whose fenced journal is retained for same-run recovery.
    pub(crate) fn retained_identity(&self) -> Option<(&str, &str)> {
        self.durable_record
            .as_ref()
            .map(|record| (record.run_id.as_str(), record.operation_id.as_str()))
    }

    /// Irreversibly removes one completed run's fenced journal before another run can launch.
    ///
    /// # Errors
    ///
    /// Returns a boundary, stale-authority, or active-generation failure unless the exact retained
    /// run is fenced and its generation can be removed durably.
    pub(crate) fn retire(&mut self, run_id: &str) -> Result<(), RunnerHostError> {
        if self.active.is_some() {
            return Err(RunnerHostError::ActiveGeneration);
        }
        let mut record = self
            .durable_record
            .clone()
            .ok_or(RunnerHostError::Boundary)?;
        if record.run_id != run_id || record.phase != "fenced" || self.recovery_directory.is_none()
        {
            return Err(RunnerHostError::StaleAuthority);
        }
        record.phase = String::from("retiring");
        self.persist_record(&record)?;
        self.durable_record = Some(record.clone());
        self.recovery_directory = None;
        self.complete_retirement(&record)
    }

    fn complete_retirement(
        &mut self,
        record: &DurableGenerationRecord,
    ) -> Result<(), RunnerHostError> {
        let entries = bounded_generation_root_entries(&self.generation_root)?;
        for entry in entries {
            if entry == GENERATION_RECORD_NAME {
                continue;
            }
            if entry == GENERATION_RECORD_TEMPORARY_NAME {
                rustix::fs::unlinkat(&self.generation_root, &entry, rustix::fs::AtFlags::empty())
                    .map_err(|_| RunnerHostError::Boundary)?;
                continue;
            }
            let generation = entry
                .strip_prefix("generation-")
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value != 0 && entry == format!("generation-{value:020}"))
                .ok_or(RunnerHostError::Boundary)?;
            if generation > record.generation {
                return Err(RunnerHostError::Boundary);
            }
            let directory = fs::File::from(
                openat(
                    &self.generation_root,
                    &entry,
                    directory_flags(),
                    Mode::empty(),
                )
                .map_err(|_| RunnerHostError::Boundary)?,
            );
            validate_directory(&directory, self.runner_uid, self.runner_gid)?;
            let metadata = directory
                .metadata()
                .map_err(|_| RunnerHostError::Boundary)?;
            if generation == record.generation {
                if metadata.dev() != record.generation_device
                    || metadata.ino() != record.generation_inode
                {
                    return Err(RunnerHostError::Boundary);
                }
            } else if !directory_is_empty(&self.generation_root_path.join(&entry))? {
                return Err(RunnerHostError::Boundary);
            }
            drop(directory);
            fs::remove_dir_all(self.generation_root_path.join(&entry))
                .map_err(|_| RunnerHostError::Boundary)?;
        }
        self.generation_root
            .sync_all()
            .map_err(|_| RunnerHostError::Boundary)?;
        rustix::fs::unlinkat(
            &self.generation_root,
            GENERATION_RECORD_NAME,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| RunnerHostError::Boundary)?;
        self.generation_root
            .sync_all()
            .map_err(|_| RunnerHostError::Boundary)?;
        self.durable_record = None;
        self.recovery_directory = None;
        Ok(())
    }

    /// Kills and waits for the current process before dropping its generation record.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerHostError::Process`] if signaling or waiting fails.
    pub(crate) fn terminate(&mut self) -> Result<(), RunnerHostError> {
        let Some(mut active) = self.active.take() else {
            return Ok(());
        };
        if active
            .child
            .try_wait()
            .map_err(|_| RunnerHostError::Process)?
            .is_none()
        {
            active.child.kill().map_err(|_| RunnerHostError::Process)?;
        }
        active.child.wait().map_err(|_| RunnerHostError::Process)?;
        #[cfg(target_os = "linux")]
        self.cgroup
            .as_ref()
            .ok_or(RunnerHostError::Boundary)?
            .fence(&active.cgroup_name)?;
        self.retain_recovery_record(&active)?;
        Ok(())
    }

    /// Waits for normal process completion and returns its exit status.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerHostError::ActiveGeneration`] when no process is active or
    /// [`RunnerHostError::Process`] when waiting fails.
    pub(crate) fn wait(&mut self) -> Result<ExitStatus, RunnerHostError> {
        let mut active = self
            .active
            .take()
            .ok_or(RunnerHostError::ActiveGeneration)?;
        let status = active.child.wait().map_err(|_| RunnerHostError::Process)?;
        #[cfg(target_os = "linux")]
        self.cgroup
            .as_ref()
            .ok_or(RunnerHostError::Boundary)?
            .fence(&active.cgroup_name)?;
        self.retain_recovery_record(&active)?;
        Ok(status)
    }

    /// Returns the current controller record, if any.
    #[must_use]
    pub(crate) fn active(&self) -> Option<&RunnerGeneration> {
        self.active.as_ref()
    }

    fn retain_recovery_record(
        &mut self,
        generation: &RunnerGeneration,
    ) -> Result<(), RunnerHostError> {
        self.recovery_directory = Some(
            generation
                .directory_descriptor
                .try_clone()
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        let mut record = self
            .durable_record
            .clone()
            .ok_or(RunnerHostError::Boundary)?;
        match openat(
            &generation.directory_descriptor,
            "run/gateway.sqlite3",
            read_flags(),
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                let metadata = fs::File::from(descriptor)
                    .metadata()
                    .map_err(|_| RunnerHostError::Boundary)?;
                if !metadata.is_file() {
                    return Err(RunnerHostError::Boundary);
                }
                record.journal_device = Some(metadata.dev());
                record.journal_inode = Some(metadata.ino());
            },
            Err(rustix::io::Errno::NOENT) => {},
            Err(_) => return Err(RunnerHostError::Boundary),
        }
        record.phase = String::from("fenced");
        clear_cgroup_record(&mut record);
        self.persist_record(&record)?;
        self.durable_record = Some(record);
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "durable reopen validation is intentionally one fail-closed audit sequence"
    )]
    fn recover_durable_generation(&mut self) -> Result<(), RunnerHostError> {
        let mut entries = bounded_generation_root_entries(&self.generation_root)?;
        let has_temporary = entries
            .iter()
            .any(|name| name == GENERATION_RECORD_TEMPORARY_NAME);
        let has_canonical = entries.iter().any(|name| name == GENERATION_RECORD_NAME);
        if has_temporary && !has_canonical {
            #[allow(
                clippy::single_match_else,
                reason = "complete and partial atomic-record recovery remain visibly paired"
            )]
            match self.read_record(GENERATION_RECORD_TEMPORARY_NAME) {
                Ok(record) => {
                    self.validate_record_identity(&record)?;
                    rustix::fs::renameat(
                        &self.generation_root,
                        GENERATION_RECORD_TEMPORARY_NAME,
                        &self.generation_root,
                        GENERATION_RECORD_NAME,
                    )
                    .map_err(|_| RunnerHostError::Boundary)?;
                    self.generation_root
                        .sync_all()
                        .map_err(|_| RunnerHostError::Boundary)?;
                    entries.retain(|name| name != GENERATION_RECORD_TEMPORARY_NAME);
                    entries.push(String::from(GENERATION_RECORD_NAME));
                },
                Err(_) => {
                    if entries.iter().any(|name| name.starts_with("generation-")) {
                        return Err(RunnerHostError::Boundary);
                    }
                    rustix::fs::unlinkat(
                        &self.generation_root,
                        GENERATION_RECORD_TEMPORARY_NAME,
                        rustix::fs::AtFlags::empty(),
                    )
                    .map_err(|_| RunnerHostError::Boundary)?;
                    self.generation_root
                        .sync_all()
                        .map_err(|_| RunnerHostError::Boundary)?;
                    entries.retain(|name| name != GENERATION_RECORD_TEMPORARY_NAME);
                },
            }
        } else if has_temporary {
            rustix::fs::unlinkat(
                &self.generation_root,
                GENERATION_RECORD_TEMPORARY_NAME,
                rustix::fs::AtFlags::empty(),
            )
            .map_err(|_| RunnerHostError::Boundary)?;
            self.generation_root
                .sync_all()
                .map_err(|_| RunnerHostError::Boundary)?;
            entries.retain(|name| name != GENERATION_RECORD_TEMPORARY_NAME);
        }
        if entries.is_empty() {
            return Ok(());
        }
        if !entries.iter().any(|name| name == GENERATION_RECORD_NAME) {
            return Err(RunnerHostError::Boundary);
        }
        #[allow(
            unused_mut,
            reason = "Linux durable reopen clears the fenced cgroup binding"
        )]
        let mut record = self.read_record(GENERATION_RECORD_NAME)?;
        self.validate_record_identity(&record)?;
        if record.phase == "retiring" {
            self.complete_retirement(&record)?;
            self.next_generation = record.generation;
            return Ok(());
        }
        if record.phase == "allocating" {
            self.recover_allocating_generation(&record, &entries)?;
            self.next_generation = record.generation;
            return Ok(());
        }
        if matches!(record.phase.as_str(), "preparing" | "preparing_fencing") {
            self.recover_preparing_generation(&record, &entries)?;
            self.next_generation = record.generation;
            return Ok(());
        }
        let recorded_generation = record.generation;
        let recorded_name = format!("generation-{recorded_generation:020}");
        let adjacent_generation = recorded_generation
            .checked_add(1)
            .ok_or(RunnerHostError::Boundary)?;
        let adjacent_name = format!("generation-{adjacent_generation:020}");
        let mut generation_entries = entries
            .iter()
            .filter(|entry| entry.as_str() != GENERATION_RECORD_NAME)
            .map(|entry| {
                let number = entry
                    .strip_prefix("generation-")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|number| *number != 0)
                    .ok_or(RunnerHostError::Boundary)?;
                if entry != &format!("generation-{number:020}") {
                    return Err(RunnerHostError::Boundary);
                }
                Ok((number, entry.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        generation_entries.sort_unstable_by_key(|(number, _)| *number);
        if !generation_entries
            .iter()
            .any(|(number, _)| *number == recorded_generation)
            || generation_entries
                .iter()
                .any(|(number, _)| *number > adjacent_generation)
        {
            return Err(RunnerHostError::Boundary);
        }
        let mut removed_any_obsolete_generation = false;
        for (_, entry) in generation_entries
            .iter()
            .filter(|(number, _)| *number < recorded_generation)
        {
            let old = fs::File::from(
                openat(
                    &self.generation_root,
                    entry,
                    directory_flags(),
                    Mode::empty(),
                )
                .map_err(|_| RunnerHostError::Boundary)?,
            );
            validate_directory(&old, self.runner_uid, self.runner_gid)?;
            if open_optional_run(&old)?.is_some() || !directory_descriptor_is_empty(&old)? {
                return Err(RunnerHostError::Boundary);
            }
            drop(old);
            rustix::fs::unlinkat(&self.generation_root, entry, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|_| RunnerHostError::Boundary)?;
            removed_any_obsolete_generation = true;
        }
        if removed_any_obsolete_generation {
            self.generation_root
                .sync_all()
                .map_err(|_| RunnerHostError::Boundary)?;
        }
        let recorded = fs::File::from(
            openat(
                &self.generation_root,
                &recorded_name,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|_| RunnerHostError::Boundary)?,
        );
        validate_directory(&recorded, self.runner_uid, self.runner_gid)?;
        let recorded_metadata = recorded.metadata().map_err(|_| RunnerHostError::Boundary)?;
        if recorded_metadata.dev() != record.generation_device
            || recorded_metadata.ino() != record.generation_inode
        {
            return Err(RunnerHostError::Boundary);
        }
        let recorded_run = open_optional_run(&recorded)?;
        let recorded_entry_count =
            directory_entry_count(&self.generation_root_path.join(&recorded_name))?;
        let adjacent = if generation_entries
            .iter()
            .any(|(number, _)| *number == adjacent_generation)
        {
            let adjacent = fs::File::from(
                openat(
                    &self.generation_root,
                    &adjacent_name,
                    directory_flags(),
                    Mode::empty(),
                )
                .map_err(|_| RunnerHostError::Boundary)?,
            );
            validate_directory(&adjacent, self.runner_uid, self.runner_gid)?;
            Some(adjacent)
        } else {
            None
        };
        let (generation, run, moved_generation) = match (recorded_run, adjacent) {
            (Some(run), None) if recorded_entry_count == 1 => (recorded, run, None),
            (Some(run), Some(adjacent))
                if record.phase == "fenced"
                    && recorded_entry_count == 1
                    && directory_is_empty(&self.generation_root_path.join(&adjacent_name))? =>
            {
                drop(adjacent);
                rustix::fs::unlinkat(
                    &self.generation_root,
                    &adjacent_name,
                    rustix::fs::AtFlags::REMOVEDIR,
                )
                .map_err(|_| RunnerHostError::Boundary)?;
                self.generation_root
                    .sync_all()
                    .map_err(|_| RunnerHostError::Boundary)?;
                (recorded, run, None)
            },
            (None, Some(adjacent)) if record.phase == "fenced" && recorded_entry_count == 0 => {
                let run = open_optional_run(&adjacent)?.ok_or(RunnerHostError::Boundary)?;
                if directory_entry_count(&self.generation_root_path.join(&adjacent_name))? != 1 {
                    return Err(RunnerHostError::Boundary);
                }
                let metadata = adjacent.metadata().map_err(|_| RunnerHostError::Boundary)?;
                (adjacent, run, Some((metadata.dev(), metadata.ino())))
            },
            _ => return Err(RunnerHostError::Boundary),
        };
        validate_directory(&run, self.runner_uid, self.runner_gid)?;
        let run_metadata = run.metadata().map_err(|_| RunnerHostError::Boundary)?;
        if run_metadata.dev() != record.run_device || run_metadata.ino() != record.run_inode {
            return Err(RunnerHostError::Boundary);
        }
        match (record.journal_device, record.journal_inode) {
            (Some(device), Some(inode)) => {
                let journal = fs::File::from(
                    openat(&run, "gateway.sqlite3", read_flags(), Mode::empty())
                        .map_err(|_| RunnerHostError::Boundary)?,
                );
                let metadata = journal.metadata().map_err(|_| RunnerHostError::Boundary)?;
                if !metadata.is_file() || metadata.dev() != device || metadata.ino() != inode {
                    return Err(RunnerHostError::Boundary);
                }
            },
            (None, None) => {},
            _ => return Err(RunnerHostError::Boundary),
        }
        if let Some((device, inode)) = moved_generation {
            record.generation = adjacent_generation;
            record.generation_device = device;
            record.generation_inode = inode;
            self.persist_record(&record)?;
        }
        #[cfg(target_os = "linux")]
        if let (Some(path), Some(device), Some(inode)) = (
            record.cgroup_path.as_deref(),
            record.cgroup_device,
            record.cgroup_inode,
        ) {
            let process_id = record.process_id.ok_or(RunnerHostError::Boundary)?;
            let start_identity = record
                .start_identity
                .as_deref()
                .ok_or(RunnerHostError::Boundary)?;
            let observed = process_start_identity(process_id).ok();
            let reused = observed
                .as_ref()
                .is_some_and(|identity| identity != start_identity);
            if record.phase != "fencing" {
                record.phase = String::from("fencing");
                self.persist_record(&record)?;
            }
            fence_cgroup_path(Path::new(path), record.generation, device, inode, true)?;
            if process_start_identity(process_id).is_ok_and(|identity| identity == start_identity) {
                return Err(RunnerHostError::Process);
            }
            if reused {
                return Err(RunnerHostError::Boundary);
            }
            record.phase = String::from("fenced");
            clear_cgroup_record(&mut record);
            self.persist_record(&record)?;
        }
        self.next_generation = record
            .generation
            .checked_add(1)
            .ok_or(RunnerHostError::Boundary)?;
        self.recovery_directory = Some(generation);
        self.durable_record = Some(record);
        Ok(())
    }

    fn read_record(&self, name: &str) -> Result<DurableGenerationRecord, RunnerHostError> {
        let mut record_file = fs::File::from(
            openat(&self.generation_root, name, read_flags(), Mode::empty())
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        let metadata = record_file
            .metadata()
            .map_err(|_| RunnerHostError::Boundary)?;
        if !metadata.is_file()
            || metadata.uid() != self.controller_uid
            || metadata.gid() != self.controller_gid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(RunnerHostError::Boundary);
        }
        let bytes = read_exact(&mut record_file, GENERATION_RECORD_BYTES_MAX)?;
        serde_json::from_slice(&bytes).map_err(|_| RunnerHostError::Boundary)
    }

    fn validate_record_identity(
        &self,
        record: &DurableGenerationRecord,
    ) -> Result<(), RunnerHostError> {
        if record.version != 1
            || record.generation == 0
            || record.runner_uid != self.runner_uid
            || record.runner_gid != self.runner_gid
            || record.operation_id != format!("sandbox-{}", record.run_id)
        {
            return Err(RunnerHostError::Boundary);
        }
        match (record.process_id, record.start_identity.as_deref()) {
            (Some(process_id), Some(start_identity)) => {
                let (recorded_process, _) = process_start_identity_from_record(start_identity)?;
                if recorded_process != process_id {
                    return Err(RunnerHostError::Boundary);
                }
            },
            (None, None) => {},
            _ => return Err(RunnerHostError::Boundary),
        }
        validate_durable_phase(record)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "pre-allocation cleanup is one fail-closed descriptor-relative sequence"
    )]
    fn recover_allocating_generation(
        &self,
        record: &DurableGenerationRecord,
        entries: &[String],
    ) -> Result<(), RunnerHostError> {
        let generation_name = format!("generation-{:020}", record.generation);
        if !entries.iter().any(|name| name == GENERATION_RECORD_NAME)
            || entries
                .iter()
                .any(|name| name != GENERATION_RECORD_NAME && name != &generation_name)
        {
            return Err(RunnerHostError::Boundary);
        }
        let generation = match openat(
            &self.generation_root,
            &generation_name,
            directory_flags(),
            Mode::empty(),
        ) {
            Ok(descriptor) => Some(fs::File::from(descriptor)),
            Err(rustix::io::Errno::NOENT) => None,
            Err(_) => return Err(RunnerHostError::Boundary),
        };
        let mut run = None;
        let mut outbox = None;
        if let Some(state) = generation.as_ref() {
            validate_allocating_directory(
                state,
                self.controller_uid,
                self.controller_gid,
                self.runner_uid,
                self.runner_gid,
            )?;
            let names = directory_names(state)?;
            if names == [String::from("run")] {
                let directory = fs::File::from(
                    openat(state, "run", directory_flags(), Mode::empty())
                        .map_err(|_| RunnerHostError::Boundary)?,
                );
                validate_allocating_directory(
                    &directory,
                    self.controller_uid,
                    self.controller_gid,
                    self.runner_uid,
                    self.runner_gid,
                )?;
                let names = directory_names(&directory)?;
                if names == [String::from("receipt-outbox")] {
                    let directory_outbox = fs::File::from(
                        openat(
                            &directory,
                            "receipt-outbox",
                            directory_flags(),
                            Mode::empty(),
                        )
                        .map_err(|_| RunnerHostError::Boundary)?,
                    );
                    validate_allocating_directory(
                        &directory_outbox,
                        self.controller_uid,
                        self.controller_gid,
                        self.runner_uid,
                        self.runner_gid,
                    )?;
                    if !directory_names(&directory_outbox)?.is_empty() {
                        return Err(RunnerHostError::Boundary);
                    }
                    outbox = Some(directory_outbox);
                } else if !names.is_empty() {
                    return Err(RunnerHostError::Boundary);
                }
                run = Some(directory);
            } else if !names.is_empty() {
                return Err(RunnerHostError::Boundary);
            }
        }

        #[cfg(target_os = "linux")]
        remove_empty_allocating_cgroup(
            Path::new(
                record
                    .cgroup_path
                    .as_deref()
                    .ok_or(RunnerHostError::Boundary)?,
            ),
            record.generation,
        )?;

        drop(outbox);
        if let Some(directory) = run {
            match rustix::fs::unlinkat(&directory, "receipt-outbox", rustix::fs::AtFlags::REMOVEDIR)
            {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {},
                Err(_) => return Err(RunnerHostError::Boundary),
            }
            directory
                .sync_all()
                .map_err(|_| RunnerHostError::Boundary)?;
            drop(directory);
        }
        if let Some(state) = generation {
            match rustix::fs::unlinkat(&state, "run", rustix::fs::AtFlags::REMOVEDIR) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {},
                Err(_) => return Err(RunnerHostError::Boundary),
            }
            state.sync_all().map_err(|_| RunnerHostError::Boundary)?;
            drop(state);
            rustix::fs::unlinkat(
                &self.generation_root,
                &generation_name,
                rustix::fs::AtFlags::REMOVEDIR,
            )
            .map_err(|_| RunnerHostError::Boundary)?;
        }
        rustix::fs::unlinkat(
            &self.generation_root,
            GENERATION_RECORD_NAME,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| RunnerHostError::Boundary)?;
        self.generation_root
            .sync_all()
            .map_err(|_| RunnerHostError::Boundary)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "pre-authority cleanup is one fail-closed descriptor-relative audit sequence"
    )]
    fn recover_preparing_generation(
        &self,
        record: &DurableGenerationRecord,
        entries: &[String],
    ) -> Result<(), RunnerHostError> {
        #[allow(
            unused_mut,
            reason = "Linux persists the pre-fence preparing transition"
        )]
        let mut record = record.clone();
        let generation_name = format!("generation-{:020}", record.generation);
        if !entries.iter().any(|name| name == GENERATION_RECORD_NAME)
            || entries
                .iter()
                .any(|name| name != GENERATION_RECORD_NAME && name != &generation_name)
        {
            return Err(RunnerHostError::Boundary);
        }
        let generation = match openat(
            &self.generation_root,
            &generation_name,
            directory_flags(),
            Mode::empty(),
        ) {
            Ok(descriptor) => Some(fs::File::from(descriptor)),
            Err(rustix::io::Errno::NOENT) => None,
            Err(_) => return Err(RunnerHostError::Boundary),
        };
        let mut run = None;
        let mut outbox = None;
        if let Some(state) = generation.as_ref() {
            validate_directory(state, self.runner_uid, self.runner_gid)?;
            let metadata = state.metadata().map_err(|_| RunnerHostError::Boundary)?;
            if metadata.dev() != record.generation_device
                || metadata.ino() != record.generation_inode
            {
                return Err(RunnerHostError::Boundary);
            }
            let names = directory_names(state)?;
            if names == [String::from("run")] {
                let directory = fs::File::from(
                    openat(state, "run", directory_flags(), Mode::empty())
                        .map_err(|_| RunnerHostError::Boundary)?,
                );
                validate_directory(&directory, self.runner_uid, self.runner_gid)?;
                let metadata = directory
                    .metadata()
                    .map_err(|_| RunnerHostError::Boundary)?;
                if metadata.dev() != record.run_device || metadata.ino() != record.run_inode {
                    return Err(RunnerHostError::Boundary);
                }
                let names = directory_names(&directory)?;
                if names == [String::from("receipt-outbox")] {
                    let directory_outbox = fs::File::from(
                        openat(
                            &directory,
                            "receipt-outbox",
                            directory_flags(),
                            Mode::empty(),
                        )
                        .map_err(|_| RunnerHostError::Boundary)?,
                    );
                    validate_directory(&directory_outbox, self.runner_uid, self.runner_gid)?;
                    if !directory_names(&directory_outbox)?.is_empty() {
                        return Err(RunnerHostError::Boundary);
                    }
                    outbox = Some(directory_outbox);
                } else if !names.is_empty() {
                    return Err(RunnerHostError::Boundary);
                }
                run = Some(directory);
            } else if !names.is_empty() {
                return Err(RunnerHostError::Boundary);
            }
        }

        #[cfg(target_os = "linux")]
        {
            if record.phase != "preparing_fencing" {
                record.phase = String::from("preparing_fencing");
                self.persist_record(&record)?;
            }
            fence_cgroup_path(
                Path::new(
                    record
                        .cgroup_path
                        .as_deref()
                        .ok_or(RunnerHostError::Boundary)?,
                ),
                record.generation,
                record.cgroup_device.ok_or(RunnerHostError::Boundary)?,
                record.cgroup_inode.ok_or(RunnerHostError::Boundary)?,
                true,
            )?;
        }

        drop(outbox);
        if let Some(directory) = run {
            match rustix::fs::unlinkat(&directory, "receipt-outbox", rustix::fs::AtFlags::REMOVEDIR)
            {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {},
                Err(_) => return Err(RunnerHostError::Boundary),
            }
            directory
                .sync_all()
                .map_err(|_| RunnerHostError::Boundary)?;
            drop(directory);
        }
        if let Some(state) = generation {
            match rustix::fs::unlinkat(&state, "run", rustix::fs::AtFlags::REMOVEDIR) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {},
                Err(_) => return Err(RunnerHostError::Boundary),
            }
            state.sync_all().map_err(|_| RunnerHostError::Boundary)?;
            drop(state);
            rustix::fs::unlinkat(
                &self.generation_root,
                &generation_name,
                rustix::fs::AtFlags::REMOVEDIR,
            )
            .map_err(|_| RunnerHostError::Boundary)?;
        }
        rustix::fs::unlinkat(
            &self.generation_root,
            GENERATION_RECORD_NAME,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| RunnerHostError::Boundary)?;
        self.generation_root
            .sync_all()
            .map_err(|_| RunnerHostError::Boundary)
    }

    fn persist_record(&self, record: &DurableGenerationRecord) -> Result<(), RunnerHostError> {
        let bytes = serde_json::to_vec(record).map_err(|_| RunnerHostError::Boundary)?;
        if bytes.is_empty() || bytes.len() > GENERATION_RECORD_BYTES_MAX {
            return Err(RunnerHostError::Boundary);
        }
        let _ = rustix::fs::unlinkat(
            &self.generation_root,
            GENERATION_RECORD_TEMPORARY_NAME,
            rustix::fs::AtFlags::empty(),
        );
        let mut output = fs::File::from(
            openat(
                &self.generation_root,
                GENERATION_RECORD_TEMPORARY_NAME,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| RunnerHostError::Boundary)?,
        );
        output
            .write_all(&bytes)
            .map_err(|_| RunnerHostError::Boundary)?;
        output.sync_all().map_err(|_| RunnerHostError::Boundary)?;
        rustix::fs::renameat(
            &self.generation_root,
            GENERATION_RECORD_TEMPORARY_NAME,
            &self.generation_root,
            GENERATION_RECORD_NAME,
        )
        .map_err(|_| RunnerHostError::Boundary)?;
        self.generation_root
            .sync_all()
            .map_err(|_| RunnerHostError::Boundary)
    }

    #[cfg(target_os = "linux")]
    fn ensure_cgroup(&mut self) -> Result<&CgroupBoundary, RunnerHostError> {
        if self.cgroup.is_none() {
            let identity = self
                .generation_root
                .metadata()
                .map_err(|_| RunnerHostError::Boundary)?
                .ino();
            self.cgroup = Some(CgroupBoundary::open(identity)?);
        }
        self.cgroup.as_ref().ok_or(RunnerHostError::Boundary)
    }

    #[cfg(target_os = "linux")]
    fn prepare_cgroup(&mut self, generation: u64) -> Result<String, RunnerHostError> {
        self.ensure_cgroup()?.prepare(generation)
    }

    #[cfg(target_os = "linux")]
    fn attach_cgroup(&self, generation: &str, process_id: u32) -> Result<(), RunnerHostError> {
        self.cgroup
            .as_ref()
            .ok_or(RunnerHostError::Boundary)?
            .attach(generation, process_id)
    }

    fn fail_attached_launch(
        &mut self,
        child: &mut Child,
        cgroup_name: &str,
        state: &fs::File,
        record: &DurableGenerationRecord,
        failure: RunnerHostError,
    ) -> RunnerHostError {
        #[cfg(not(target_os = "linux"))]
        let _ = cgroup_name;

        let mut cleanup_failed = false;
        let mut retained = record.clone();
        if self.persist_record(&retained).is_err() {
            cleanup_failed = true;
        }
        self.durable_record = Some(retained.clone());
        match state.try_clone() {
            Ok(directory) => self.recovery_directory = Some(directory),
            Err(_) => cleanup_failed = true,
        }

        let _ = child.kill();
        if child.wait().is_err() {
            cleanup_failed = true;
        }

        #[cfg(target_os = "linux")]
        {
            let fenced = self
                .cgroup
                .as_ref()
                .ok_or(RunnerHostError::Boundary)
                .and_then(|boundary| boundary.fence(cgroup_name));
            if fenced.is_err() {
                let _ = self.persist_record(&retained);
                return RunnerHostError::Process;
            }
        }

        retained.phase = String::from("fenced");
        clear_cgroup_record(&mut retained);
        if self.persist_record(&retained).is_err() {
            cleanup_failed = true;
        }
        self.durable_record = Some(retained);
        if cleanup_failed {
            RunnerHostError::Process
        } else {
            failure
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "generation construction is intentionally one fail-closed audit sequence"
    )]
    fn launch_fresh_from(
        &mut self,
        run_id: &str,
        assignment: &HandoffAssignment,
        previous_directory: Option<&fs::File>,
        input_files: &[fs::File],
    ) -> Result<&RunnerGeneration, RunnerHostError> {
        if assignment.operation_id != format!("sandbox-{run_id}") || assignment.run_id != run_id {
            return Err(RunnerHostError::StaleAuthority);
        }
        validate_hex_identity(run_id)?;
        self.require_trusted_roots()?;
        let input_identities = input_files
            .iter()
            .map(|file| {
                file.metadata()
                    .map(|metadata| descriptor_identity(&metadata))
                    .map_err(|_| RunnerHostError::Boundary)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let executable =
            open_executable(&self.executable, self.controller_uid, self.controller_gid)?;
        let helper_path = Path::new(env!("KAPSEL_SANDBOX_RUNNER_PRE_EXEC"));
        let helper = open_executable(helper_path, self.controller_uid, self.controller_gid)?;
        #[cfg(target_os = "linux")]
        let helper_execution_path = executable_descriptor_path(&helper);
        #[cfg(not(target_os = "linux"))]
        let helper_execution_path = helper_path.to_path_buf();
        #[cfg(not(target_os = "linux"))]
        let _checked_helper = &helper;
        let generation = self.next_generation;
        let credential_verifier = credential_verifier(
            run_id,
            &assignment.operation_id,
            assignment.lease_id(),
            &assignment.credential(),
        );
        let runner_uid = self.runner_uid;
        let runner_gid = self.runner_gid;
        let is_first_allocation = previous_directory.is_none() && self.durable_record.is_none();
        if previous_directory.is_none() != self.durable_record.is_none() {
            return Err(RunnerHostError::Boundary);
        }
        if is_first_allocation {
            #[cfg(target_os = "linux")]
            let planned_cgroup_path = Some(
                self.ensure_cgroup()?
                    .planned_path(generation)
                    .display()
                    .to_string(),
            );
            #[cfg(not(target_os = "linux"))]
            let planned_cgroup_path = None;
            let allocating_record = DurableGenerationRecord {
                version: 1,
                run_id: run_id.to_owned(),
                operation_id: assignment.operation_id.clone(),
                generation,
                runner_uid,
                runner_gid,
                process_id: None,
                start_identity: None,
                lease_id: assignment.lease_id().to_owned(),
                credential_verifier: credential_verifier.clone(),
                generation_device: 0,
                generation_inode: 0,
                run_device: 0,
                run_inode: 0,
                journal_device: None,
                journal_inode: None,
                cgroup_path: planned_cgroup_path,
                cgroup_device: None,
                cgroup_inode: None,
                phase: String::from("allocating"),
            };
            self.persist_record(&allocating_record)?;
            self.durable_record = Some(allocating_record);
        }

        let (_directory, state) = self.create_generation(generation, previous_directory)?;
        self.recovery_directory = Some(state.try_clone().map_err(|_| RunnerHostError::Boundary)?);
        let state_metadata = state.metadata().map_err(|_| RunnerHostError::Boundary)?;
        let state_identity = descriptor_identity(&state_metadata);
        let run = fs::File::from(
            openat(&state, "run", directory_flags(), Mode::empty())
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        let run_metadata = run.metadata().map_err(|_| RunnerHostError::Boundary)?;
        #[cfg(target_os = "linux")]
        let cgroup_name = self.prepare_cgroup(generation)?;
        #[cfg(not(target_os = "linux"))]
        let cgroup_name = String::new();
        #[cfg(target_os = "linux")]
        let (cgroup_path, cgroup_device, cgroup_inode) = {
            let boundary = self.cgroup.as_ref().ok_or(RunnerHostError::Boundary)?;
            let (device, inode) = boundary.identity(&cgroup_name)?;
            (
                Some(boundary.path.join(&cgroup_name).display().to_string()),
                Some(device),
                Some(inode),
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (cgroup_path, cgroup_device, cgroup_inode) = (None, None, None);
        let mut durable_record = DurableGenerationRecord {
            version: 1,
            run_id: run_id.to_owned(),
            operation_id: assignment.operation_id.clone(),
            generation,
            runner_uid,
            runner_gid,
            process_id: None,
            start_identity: None,
            lease_id: assignment.lease_id().to_owned(),
            credential_verifier: credential_verifier.clone(),
            generation_device: state_metadata.dev(),
            generation_inode: state_metadata.ino(),
            run_device: run_metadata.dev(),
            run_inode: run_metadata.ino(),
            journal_device: None,
            journal_inode: None,
            cgroup_path,
            cgroup_device,
            cgroup_inode,
            phase: String::from("preparing"),
        };
        self.persist_record(&durable_record)?;
        self.durable_record = Some(durable_record.clone());

        let (bootstrap_writer, bootstrap_reader) =
            UnixDatagram::pair().map_err(|_| RunnerHostError::Process)?;
        let mut command = Command::new(&helper_execution_path);
        command
            .env_clear()
            .process_group(0)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(bootstrap_reader)))
            .stdout(Stdio::from(
                state.try_clone().map_err(|_| RunnerHostError::Process)?,
            ))
            .stderr(Stdio::from(executable));
        let mut child = command.spawn().map_err(|_| RunnerHostError::Identity)?;
        let process_id = child.id();
        let start_identity = match wait_for_process_start_identity(&mut child) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            },
        };
        durable_record.process_id = Some(process_id);
        durable_record.start_identity = Some(start_identity);
        durable_record.phase = String::from("spawned");
        #[cfg(target_os = "linux")]
        if self.attach_cgroup(&cgroup_name, process_id).is_err() {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Process,
            ));
        }
        if let Err(error) = self.persist_record(&durable_record) {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                error,
            ));
        }
        self.durable_record = Some(durable_record.clone());
        let bootstrap = Bootstrap {
            version: 1,
            run_id: run_id.to_owned(),
            operation_id: assignment.operation_id.clone(),
            lease_id: assignment.lease_id().to_owned(),
            generation,
            process_id,
            controller_uid: self.controller_uid,
            controller_gid: self.controller_gid,
            runner_uid,
            runner_gid,
            credential_verifier: credential_verifier.clone(),
            inputs: input_identities,
            state: state_identity,
        };
        let Ok(bytes) = serde_json::to_vec(&bootstrap) else {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Boundary,
            ));
        };
        let descriptors = input_files.iter().map(AsFd::as_fd).collect::<Vec<_>>();
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(INPUT_NAMES.len()))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut control_space);
        if !control.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors))
            || rustix::net::sendmsg(
                &bootstrap_writer,
                &[IoSlice::new(&bytes)],
                &mut control,
                rustix::net::SendFlags::empty(),
            )
            .is_err()
        {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Process,
            ));
        }
        if bootstrap_writer
            .set_read_timeout(Some(RUNNER_READY_TIMEOUT))
            .is_err()
        {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Process,
            ));
        }
        let mut ready = [0_u8; RUNNER_READY.len()];
        if bootstrap_writer.recv(&mut ready).ok() != Some(RUNNER_READY.len())
            || ready != RUNNER_READY
        {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Process,
            ));
        }
        let journal = match openat(&run, "gateway.sqlite3", read_flags(), Mode::empty()) {
            Ok(descriptor) => fs::File::from(descriptor),
            Err(_) => {
                return Err(self.fail_attached_launch(
                    &mut child,
                    &cgroup_name,
                    &state,
                    &durable_record,
                    RunnerHostError::Boundary,
                ));
            },
        };
        let Ok(journal_metadata) = journal.metadata() else {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Boundary,
            ));
        };
        if !journal_metadata.is_file() {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Boundary,
            ));
        }
        durable_record.journal_device = Some(journal_metadata.dev());
        durable_record.journal_inode = Some(journal_metadata.ino());
        durable_record.phase = String::from("ready");
        if let Err(error) = self.persist_record(&durable_record) {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                error,
            ));
        }
        self.durable_record = Some(durable_record.clone());
        if bootstrap_writer.send(RUNNER_RELEASE).ok() != Some(RUNNER_RELEASE.len()) {
            return Err(self.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &durable_record,
                RunnerHostError::Process,
            ));
        }
        drop(bootstrap_writer);
        self.next_generation = match generation.checked_add(1) {
            Some(next) => next,
            None => {
                return Err(self.fail_attached_launch(
                    &mut child,
                    &cgroup_name,
                    &state,
                    &durable_record,
                    RunnerHostError::Boundary,
                ));
            },
        };
        self.active = Some(RunnerGeneration {
            child,
            generation,
            lease_id: assignment.lease_id().to_owned(),
            credential_verifier,
            directory_descriptor: state,
            #[cfg(target_os = "linux")]
            cgroup_name,
        });
        let Some(active) = self.active.as_ref() else {
            unreachable!("the runner generation was installed immediately above")
        };
        Ok(active)
    }

    fn require_trusted_roots(&self) -> Result<(), RunnerHostError> {
        require_same_root(
            &self.generation_root_path,
            &self.generation_root,
            self.controller_uid,
            self.controller_gid,
        )
    }

    fn open_inputs(
        &self,
        published: &PublishedRunnerInputs,
        assignment: &HandoffAssignment,
    ) -> Result<Vec<fs::File>, RunnerHostError> {
        let root = published.directory();
        validate_directory(root, self.controller_uid, self.controller_gid)?;
        let mut names = INPUT_NAMES
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        names.sort_unstable();
        if directory_names(root)? != names {
            return Err(RunnerHostError::Boundary);
        }
        let mut files = Vec::with_capacity(INPUT_NAMES.len());
        for name in INPUT_NAMES {
            let file = open_fixed_file(root, name, self.controller_uid, self.controller_gid)?;
            let metadata = file.metadata().map_err(|_| RunnerHostError::Boundary)?;
            let reopened = open_fixed_file(root, name, self.controller_uid, self.controller_gid)?;
            let reopened_metadata = reopened.metadata().map_err(|_| RunnerHostError::Boundary)?;
            if reopened_metadata.dev() != metadata.dev()
                || reopened_metadata.ino() != metadata.ino()
            {
                return Err(RunnerHostError::Boundary);
            }
            files.push(file);
        }
        let endpoint = read_exact(&mut files[9], 64)?;
        let lease = read_exact(&mut files[10], 32)?;
        let credential: [u8; 32] = read_exact(&mut files[11], 32)?
            .try_into()
            .map_err(|_| RunnerHostError::StaleAuthority)?;
        if !assignment.endpoint().ip().is_loopback()
            || endpoint != assignment.endpoint().to_string().as_bytes()
            || lease != assignment.lease_id().as_bytes()
            || credential != assignment.credential()
        {
            return Err(RunnerHostError::StaleAuthority);
        }
        for file in &mut files {
            use std::io::Seek;
            file.rewind().map_err(|_| RunnerHostError::Boundary)?;
        }
        self.require_trusted_roots()?;
        Ok(files)
    }

    fn create_generation(
        &self,
        generation: u64,
        previous_directory: Option<&fs::File>,
    ) -> Result<(PathBuf, fs::File), RunnerHostError> {
        let name = format!("generation-{generation:020}");
        mkdirat(&self.generation_root, &name, Mode::from_raw_mode(0o700))
            .map_err(|_| RunnerHostError::Boundary)?;
        let state = fs::File::from(
            openat(
                &self.generation_root,
                &name,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|_| RunnerHostError::Boundary)?,
        );
        set_directory_identity(&state, self.runner_uid, self.runner_gid)?;
        let directory = self.generation_root_path.join(name);
        if let Some(previous) = previous_directory {
            validate_directory(previous, self.runner_uid, self.runner_gid)?;
            rustix::fs::renameat(previous, "run", &state, "run")
                .map_err(|_| RunnerHostError::Boundary)?;
            previous.sync_all().map_err(|_| RunnerHostError::Boundary)?;
            state.sync_all().map_err(|_| RunnerHostError::Boundary)?;
        } else {
            mkdirat(&state, "run", Mode::from_raw_mode(0o700))
                .map_err(|_| RunnerHostError::Boundary)?;
            let run = fs::File::from(
                openat(&state, "run", directory_flags(), Mode::empty())
                    .map_err(|_| RunnerHostError::Boundary)?,
            );
            set_directory_identity(&run, self.runner_uid, self.runner_gid)?;
            mkdirat(&run, "receipt-outbox", Mode::from_raw_mode(0o700))
                .map_err(|_| RunnerHostError::Boundary)?;
            let outbox = fs::File::from(
                openat(&run, "receipt-outbox", directory_flags(), Mode::empty())
                    .map_err(|_| RunnerHostError::Boundary)?,
            );
            set_directory_identity(&outbox, self.runner_uid, self.runner_gid)?;
        }
        let reopened = fs::File::from(
            openat(CWD, &directory, directory_flags(), Mode::empty())
                .map_err(|_| RunnerHostError::Boundary)?,
        );
        let expected = state.metadata().map_err(|_| RunnerHostError::Boundary)?;
        let found = reopened.metadata().map_err(|_| RunnerHostError::Boundary)?;
        if expected.dev() != found.dev() || expected.ino() != found.ino() {
            return Err(RunnerHostError::Boundary);
        }
        Ok((directory, state))
    }
}

impl Drop for RunnerHost {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn open_private_root(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<fs::File, RunnerHostError> {
    let directory = fs::File::from(
        openat(CWD, path, directory_flags(), Mode::empty())
            .map_err(|_| RunnerHostError::Boundary)?,
    );
    validate_directory(&directory, owner_uid, owner_gid)?;
    Ok(directory)
}

fn require_same_root(
    path: &Path,
    trusted: &fs::File,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RunnerHostError> {
    let reopened = open_private_root(path, owner_uid, owner_gid)?;
    let expected = trusted.metadata().map_err(|_| RunnerHostError::Boundary)?;
    let found = reopened.metadata().map_err(|_| RunnerHostError::Boundary)?;
    if expected.dev() == found.dev() && expected.ino() == found.ino() {
        Ok(())
    } else {
        Err(RunnerHostError::Boundary)
    }
}

fn validate_allocating_directory(
    directory: &fs::File,
    controller_uid: u32,
    controller_gid: u32,
    runner_uid: u32,
    runner_gid: u32,
) -> Result<(), RunnerHostError> {
    let metadata = directory
        .metadata()
        .map_err(|_| RunnerHostError::Boundary)?;
    let owner_is_expected = (metadata.uid() == controller_uid && metadata.gid() == controller_gid)
        || (metadata.uid() == runner_uid && metadata.gid() == runner_gid);
    if metadata.is_dir() && owner_is_expected && metadata.permissions().mode() & 0o777 == 0o700 {
        Ok(())
    } else {
        Err(RunnerHostError::Boundary)
    }
}

fn validate_directory(
    directory: &fs::File,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), RunnerHostError> {
    let metadata = directory
        .metadata()
        .map_err(|_| RunnerHostError::Boundary)?;
    if metadata.is_dir()
        && metadata.uid() == owner_uid
        && metadata.gid() == owner_gid
        && metadata.permissions().mode() & 0o777 == 0o700
    {
        Ok(())
    } else {
        Err(RunnerHostError::Boundary)
    }
}

fn open_optional_run(generation: &fs::File) -> Result<Option<fs::File>, RunnerHostError> {
    match openat(generation, "run", directory_flags(), Mode::empty()) {
        Ok(descriptor) => Ok(Some(fs::File::from(descriptor))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(RunnerHostError::Boundary),
    }
}

fn directory_names(directory: &fs::File) -> Result<Vec<String>, RunnerHostError> {
    let mut names = rustix::fs::Dir::read_from(directory)
        .map_err(|_| RunnerHostError::Boundary)?
        .filter_map(|entry| match entry {
            Ok(entry)
                if entry.file_name().to_bytes() == b"."
                    || entry.file_name().to_bytes() == b".." =>
            {
                None
            },
            result => Some(result),
        })
        .map(|entry| {
            entry
                .map_err(|_| RunnerHostError::Boundary)?
                .file_name()
                .to_str()
                .map(str::to_owned)
                .map_err(|_| RunnerHostError::Boundary)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    Ok(names)
}

fn bounded_generation_root_entries(
    generation_root: &fs::File,
) -> Result<Vec<String>, RunnerHostError> {
    let mut entries = Vec::new();
    for entry in
        rustix::fs::Dir::read_from(generation_root).map_err(|_| RunnerHostError::Boundary)?
    {
        let entry = entry.map_err(|_| RunnerHostError::Boundary)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if entries.len() == MAX_GENERATION_ROOT_ENTRIES {
            return Err(RunnerHostError::Boundary);
        }
        entries.push(
            name.to_str()
                .map(str::to_owned)
                .map_err(|_| RunnerHostError::Boundary)?,
        );
    }
    entries.sort_unstable();
    Ok(entries)
}

fn directory_descriptor_is_empty(directory: &fs::File) -> Result<bool, RunnerHostError> {
    for entry in rustix::fs::Dir::read_from(directory).map_err(|_| RunnerHostError::Boundary)? {
        let entry = entry.map_err(|_| RunnerHostError::Boundary)?;
        let name = entry.file_name();
        if !matches!(name.to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

fn directory_entry_count(path: &Path) -> Result<usize, RunnerHostError> {
    fs::read_dir(path)
        .map_err(|_| RunnerHostError::Boundary)?
        .try_fold(0_usize, |count, entry| {
            entry
                .map(|_| count.saturating_add(1))
                .map_err(|_| RunnerHostError::Boundary)
        })
}

fn directory_is_empty(path: &Path) -> Result<bool, RunnerHostError> {
    directory_entry_count(path).map(|count| count == 0)
}

fn open_fixed_file(
    root: &fs::File,
    name: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<fs::File, RunnerHostError> {
    let file = fs::File::from(
        openat(root, name, read_flags(), Mode::empty()).map_err(|_| RunnerHostError::Boundary)?,
    );
    let metadata = file.metadata().map_err(|_| RunnerHostError::Boundary)?;
    if metadata.is_file()
        && metadata.uid() == owner_uid
        && metadata.gid() == owner_gid
        && metadata.permissions().mode() & 0o777 == 0o400
        && metadata.len() > 0
    {
        Ok(file)
    } else {
        Err(RunnerHostError::Boundary)
    }
}

#[cfg(target_os = "linux")]
fn executable_descriptor_path(executable: &fs::File) -> PathBuf {
    Path::new("/proc/self/fd").join(executable.as_raw_fd().to_string())
}

fn open_executable(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<fs::File, RunnerHostError> {
    use std::io::{Read as _, Seek as _};

    if !path.is_absolute() {
        return Err(RunnerHostError::Boundary);
    }
    let descriptor =
        openat(CWD, path, read_flags(), Mode::empty()).map_err(|_| RunnerHostError::Boundary)?;
    let mut file = fs::File::from(descriptor);
    #[cfg(target_os = "linux")]
    reject_file_capabilities(&file)?;
    let metadata = file.metadata().map_err(|_| RunnerHostError::Boundary)?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.permissions().mode() & 0o777 != 0o755
        || metadata.len() == 0
        || metadata.len() > 128 * 1024 * 1024
    {
        return Err(RunnerHostError::Boundary);
    }
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| RunnerHostError::Boundary)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let _bound_digest = digest.finalize();
    file.rewind().map_err(|_| RunnerHostError::Boundary)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn reject_file_capabilities(file: &fs::File) -> Result<(), RunnerHostError> {
    let mut value = Vec::<u8>::with_capacity(64);
    match rustix::fs::fgetxattr(file, "security.capability", &mut value) {
        Err(rustix::io::Errno::NODATA) => Ok(()),
        Ok(_) | Err(_) => Err(RunnerHostError::Boundary),
    }
}

fn set_directory_identity(directory: &fs::File, uid: u32, gid: u32) -> Result<(), RunnerHostError> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(RunnerHostError::Identity);
    }
    rustix::fs::fchown(
        directory,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .map_err(|_| RunnerHostError::Identity)?;
    rustix::fs::fchmod(directory, Mode::from_raw_mode(0o700))
        .map_err(|_| RunnerHostError::Identity)?;
    validate_directory(directory, uid, gid)
}

fn read_exact(file: &mut fs::File, maximum: usize) -> Result<Vec<u8>, RunnerHostError> {
    let bytes = read_input(file)?;
    if bytes.len() > maximum {
        Err(RunnerHostError::Boundary)
    } else {
        Ok(bytes)
    }
}

fn read_input(file: &mut fs::File) -> Result<Vec<u8>, RunnerHostError> {
    use std::io::Read;
    const INPUT_BYTES_MAX: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(4096);
    file.take(INPUT_BYTES_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerHostError::Boundary)?;
    if bytes.is_empty() || bytes.len() > INPUT_BYTES_MAX {
        Err(RunnerHostError::Boundary)
    } else {
        Ok(bytes)
    }
}

fn validate_hex_identity(value: &str) -> Result<(), RunnerHostError> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RunnerHostError::StaleAuthority)
    }
}

fn process_start_identity_from_record(value: &str) -> Result<(u32, u64), RunnerHostError> {
    let (process, start) = value.split_once(':').ok_or(RunnerHostError::Boundary)?;
    let process = process.parse().map_err(|_| RunnerHostError::Boundary)?;
    let start = start.parse().map_err(|_| RunnerHostError::Boundary)?;
    if process == 0 || start == 0 {
        return Err(RunnerHostError::Boundary);
    }
    Ok((process, start))
}

fn validate_durable_phase(record: &DurableGenerationRecord) -> Result<(), RunnerHostError> {
    if !matches!(
        record.phase.as_str(),
        "allocating"
            | "preparing"
            | "preparing_fencing"
            | "spawned"
            | "ready"
            | "fencing"
            | "fenced"
            | "retiring"
    ) {
        return Err(RunnerHostError::Boundary);
    }
    let has_process = record.process_id.is_some() && record.start_identity.is_some();
    let pre_process = matches!(
        record.phase.as_str(),
        "allocating" | "preparing" | "preparing_fencing"
    );
    if (pre_process
        && (has_process || record.journal_device.is_some() || record.journal_inode.is_some()))
        || (!pre_process && !has_process)
        || (record.phase == "allocating"
            && (record.generation_device != 0
                || record.generation_inode != 0
                || record.run_device != 0
                || record.run_inode != 0))
        || (record.phase != "allocating"
            && (record.generation_device == 0
                || record.generation_inode == 0
                || record.run_device == 0
                || record.run_inode == 0))
    {
        return Err(RunnerHostError::Boundary);
    }
    #[cfg(target_os = "linux")]
    {
        let cgroup_fields = (
            record.cgroup_path.is_some(),
            record.cgroup_device.is_some(),
            record.cgroup_inode.is_some(),
        );
        if (record.phase == "allocating" && cgroup_fields != (true, false, false))
            || (matches!(record.phase.as_str(), "fenced" | "retiring")
                && cgroup_fields != (false, false, false))
            || (!matches!(record.phase.as_str(), "allocating" | "fenced" | "retiring")
                && cgroup_fields != (true, true, true))
        {
            return Err(RunnerHostError::Boundary);
        }
    }
    #[cfg(not(target_os = "linux"))]
    if record.cgroup_path.is_some()
        || record.cgroup_device.is_some()
        || record.cgroup_inode.is_some()
    {
        return Err(RunnerHostError::Boundary);
    }
    Ok(())
}

fn clear_cgroup_record(record: &mut DurableGenerationRecord) {
    record.cgroup_path = None;
    record.cgroup_device = None;
    record.cgroup_inode = None;
}

#[cfg(target_os = "linux")]
fn remove_empty_allocating_cgroup(path: &Path, generation: u64) -> Result<(), RunnerHostError> {
    let root_path = Path::new("/sys/fs/cgroup");
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| RunnerHostError::Boundary)?;
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str().ok_or(RunnerHostError::Boundary),
            _ => Err(RunnerHostError::Boundary),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_leaf = format!("generation-{generation:020}");
    if components.len() != 2
        || !components[0].starts_with("kapsel-sandbox-controller-")
        || components[1] != expected_leaf
    {
        return Err(RunnerHostError::Boundary);
    }
    let root = fs::File::from(
        openat(CWD, root_path, directory_flags(), Mode::empty())
            .map_err(|_| RunnerHostError::Boundary)?,
    );
    let parent = match openat(&root, components[0], directory_flags(), Mode::empty()) {
        Ok(descriptor) => fs::File::from(descriptor),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => return Err(RunnerHostError::Boundary),
    };
    let directory = match openat(&parent, components[1], directory_flags(), Mode::empty()) {
        Ok(descriptor) => fs::File::from(descriptor),
        Err(rustix::io::Errno::NOENT) => {
            drop(parent);
            rustix::fs::unlinkat(&root, components[0], rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|_| RunnerHostError::Boundary)?;
            return Ok(());
        },
        Err(_) => return Err(RunnerHostError::Boundary),
    };
    if !read_cgroup_events(&directory)?
        .lines()
        .any(|line| line == "populated 0")
    {
        return Err(RunnerHostError::Boundary);
    }
    drop(directory);
    rustix::fs::unlinkat(&parent, components[1], rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|_| RunnerHostError::Boundary)?;
    drop(parent);
    rustix::fs::unlinkat(&root, components[0], rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|_| RunnerHostError::Boundary)
}

#[cfg(target_os = "linux")]
fn read_cgroup_events(directory: &fs::File) -> Result<String, RunnerHostError> {
    use std::io::Read as _;

    let mut events = fs::File::from(
        openat(directory, "cgroup.events", read_flags(), Mode::empty())
            .map_err(|_| RunnerHostError::Process)?,
    );
    let mut value = String::new();
    events
        .read_to_string(&mut value)
        .map_err(|_| RunnerHostError::Process)?;
    Ok(value)
}

#[cfg(target_os = "linux")]
fn fence_cgroup_path(
    path: &Path,
    generation: u64,
    expected_device: u64,
    expected_inode: u64,
    allow_missing: bool,
) -> Result<(), RunnerHostError> {
    let root_path = Path::new("/sys/fs/cgroup");
    let relative = path
        .strip_prefix(root_path)
        .map_err(|_| RunnerHostError::Boundary)?;
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str().ok_or(RunnerHostError::Boundary),
            _ => Err(RunnerHostError::Boundary),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_leaf = format!("generation-{generation:020}");
    if components.len() != 2
        || !components[0].starts_with("kapsel-sandbox-controller-")
        || components[1] != expected_leaf
    {
        return Err(RunnerHostError::Boundary);
    }
    let root = fs::File::from(
        openat(CWD, root_path, directory_flags(), Mode::empty())
            .map_err(|_| RunnerHostError::Boundary)?,
    );
    let parent = match openat(&root, components[0], directory_flags(), Mode::empty()) {
        Ok(descriptor) => fs::File::from(descriptor),
        Err(rustix::io::Errno::NOENT) if allow_missing => return Ok(()),
        Err(_) => return Err(RunnerHostError::Boundary),
    };
    let directory = match openat(&parent, components[1], directory_flags(), Mode::empty()) {
        Ok(descriptor) => fs::File::from(descriptor),
        Err(rustix::io::Errno::NOENT) if allow_missing => return Ok(()),
        Err(_) => return Err(RunnerHostError::Boundary),
    };
    let metadata = directory
        .metadata()
        .map_err(|_| RunnerHostError::Boundary)?;
    if !metadata.is_dir() || metadata.dev() != expected_device || metadata.ino() != expected_inode {
        return Err(RunnerHostError::Boundary);
    }
    let initial = read_cgroup_events(&directory)?;
    if !initial.lines().any(|line| line == "populated 0") {
        let mut kill = fs::File::from(
            openat(
                &directory,
                "cgroup.kill",
                OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| RunnerHostError::Process)?,
        );
        kill.write_all(b"1").map_err(|_| RunnerHostError::Process)?;
    }
    for _ in 0..10_000 {
        if read_cgroup_events(&directory)?
            .lines()
            .any(|line| line == "populated 0")
        {
            drop(directory);
            rustix::fs::unlinkat(&parent, components[1], rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|_| RunnerHostError::Process)?;
            drop(parent);
            for _ in 0..10_000 {
                match rustix::fs::unlinkat(&root, components[0], rustix::fs::AtFlags::REMOVEDIR) {
                    Ok(()) => return Ok(()),
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
            return Err(RunnerHostError::Process);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(RunnerHostError::Process)
}

#[cfg(target_os = "linux")]
fn wait_for_process_start_identity(child: &mut Child) -> Result<String, RunnerHostError> {
    for _ in 0..1_000 {
        if let Ok(identity) = process_start_identity(child.id()) {
            return Ok(identity);
        }
        if child
            .try_wait()
            .map_err(|_| RunnerHostError::Process)?
            .is_some()
        {
            return Err(RunnerHostError::Process);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(RunnerHostError::Process)
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::needless_pass_by_ref_mut,
    reason = "the call site is shared with the fallible Linux child-state probe"
)]
fn wait_for_process_start_identity(child: &mut Child) -> Result<String, RunnerHostError> {
    process_start_identity(child.id())
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the mandatory Linux process-start identity read is fallible"
)]
fn process_start_identity(process_id: u32) -> Result<String, RunnerHostError> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{process_id}/stat"))
            .map_err(|_| RunnerHostError::Process)?;
        let end = stat.rfind(") ").ok_or(RunnerHostError::Process)?;
        let start = stat[end + 2..]
            .split_ascii_whitespace()
            .nth(19)
            .ok_or(RunnerHostError::Process)?;
        Ok(format!("{process_id}:{start}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(format!("{process_id}:1"))
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn fixed_inputs(path: &Path, lease: &str, credential: [u8; 32]) {
        private_directory(path);
        for name in INPUT_NAMES {
            let bytes: &[u8] = match name {
                "handoff-endpoint" => b"127.0.0.1:1",
                "handoff-lease-id" => lease.as_bytes(),
                "handoff-credential" => &credential,
                _ => b"fixed",
            };
            fs::write(path.join(name), bytes).unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o400)).unwrap();
        }
    }

    fn durable_record_layout(
        generations: &Path,
        runner_uid: u32,
        runner_gid: u32,
        generation_number: u64,
        with_journal: bool,
    ) -> DurableGenerationRecord {
        let generation_path = generations.join(format!("generation-{generation_number:020}"));
        private_directory(&generation_path);
        let generation = open_private_root(
            &generation_path,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
        .unwrap();
        set_directory_identity(&generation, runner_uid, runner_gid).unwrap();
        fs::create_dir(generation_path.join("run")).unwrap();
        fs::set_permissions(
            generation_path.join("run"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let run =
            fs::File::from(openat(&generation, "run", directory_flags(), Mode::empty()).unwrap());
        set_directory_identity(&run, runner_uid, runner_gid).unwrap();
        fs::create_dir(generation_path.join("run/receipt-outbox")).unwrap();
        fs::set_permissions(
            generation_path.join("run/receipt-outbox"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let outbox = fs::File::from(
            openat(&run, "receipt-outbox", directory_flags(), Mode::empty()).unwrap(),
        );
        set_directory_identity(&outbox, runner_uid, runner_gid).unwrap();
        let journal_identity = if with_journal {
            fs::write(generation_path.join("run/gateway.sqlite3"), b"journal").unwrap();
            fs::set_permissions(
                generation_path.join("run/gateway.sqlite3"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let journal = fs::File::from(
                openat(&run, "gateway.sqlite3", read_flags(), Mode::empty()).unwrap(),
            );
            rustix::fs::fchown(
                &journal,
                Some(rustix::process::Uid::from_raw(runner_uid)),
                Some(rustix::process::Gid::from_raw(runner_gid)),
            )
            .unwrap();
            let metadata = journal.metadata().unwrap();
            Some((metadata.dev(), metadata.ino()))
        } else {
            None
        };
        let generation_metadata = generation.metadata().unwrap();
        let run_metadata = run.metadata().unwrap();
        DurableGenerationRecord {
            version: 1,
            run_id: "fedcba9876543210fedcba9876543210".into(),
            operation_id: "sandbox-fedcba9876543210fedcba9876543210".into(),
            generation: generation_number,
            runner_uid,
            runner_gid,
            process_id: Some(std::process::id()),
            start_identity: Some(format!("{}:1", std::process::id())),
            lease_id: "0123456789abcdef0123456789abcdef".into(),
            credential_verifier: "a".repeat(64),
            generation_device: generation_metadata.dev(),
            generation_inode: generation_metadata.ino(),
            run_device: run_metadata.dev(),
            run_inode: run_metadata.ino(),
            journal_device: journal_identity.map(|identity| identity.0),
            journal_inode: journal_identity.map(|identity| identity.1),
            cgroup_path: None,
            cgroup_device: None,
            cgroup_inode: None,
            phase: "fenced".into(),
        }
    }

    fn empty_generation_layout(
        generations: &Path,
        runner_uid: u32,
        runner_gid: u32,
        generation_number: u64,
    ) {
        let path = generations.join(format!("generation-{generation_number:020}"));
        private_directory(&path);
        let directory =
            fs::File::from(openat(CWD, &path, directory_flags(), Mode::empty()).unwrap());
        set_directory_identity(&directory, runner_uid, runner_gid).unwrap();
    }

    fn write_durable_record(generations: &Path, record: &DurableGenerationRecord) {
        write_record_named(generations, GENERATION_RECORD_NAME, record);
    }

    fn write_record_named(generations: &Path, name: &str, record: &DurableGenerationRecord) {
        fs::write(generations.join(name), serde_json::to_vec(record).unwrap()).unwrap();
        fs::set_permissions(generations.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn allocating_record_layout(runner_uid: u32, runner_gid: u32) -> DurableGenerationRecord {
        DurableGenerationRecord {
            version: 1,
            run_id: "fedcba9876543210fedcba9876543210".into(),
            operation_id: "sandbox-fedcba9876543210fedcba9876543210".into(),
            generation: 1,
            runner_uid,
            runner_gid,
            process_id: None,
            start_identity: None,
            lease_id: "0123456789abcdef0123456789abcdef".into(),
            credential_verifier: "a".repeat(64),
            generation_device: 0,
            generation_inode: 0,
            run_device: 0,
            run_inode: 0,
            journal_device: None,
            journal_inode: None,
            cgroup_path: None,
            cgroup_device: None,
            cgroup_inode: None,
            phase: "allocating".into(),
        }
    }

    #[cfg(target_os = "linux")]
    fn bind_allocating_cgroup(record: &mut DurableGenerationRecord) -> CgroupBoundary {
        let boundary = CgroupBoundary::open(record.generation).unwrap();
        record.cgroup_path = Some(
            boundary
                .planned_path(record.generation)
                .display()
                .to_string(),
        );
        boundary
    }

    fn preparing_record_layout(
        generations: &Path,
        runner_uid: u32,
        runner_gid: u32,
    ) -> DurableGenerationRecord {
        let mut record = durable_record_layout(generations, runner_uid, runner_gid, 1, false);
        record.process_id = None;
        record.start_identity = None;
        record.phase = String::from("preparing");
        record
    }

    #[cfg(target_os = "linux")]
    fn bind_preparing_cgroup(record: &mut DurableGenerationRecord) -> CgroupBoundary {
        let boundary = CgroupBoundary::open(record.generation).unwrap();
        let name = boundary.prepare(record.generation).unwrap();
        let (device, inode) = boundary.identity(&name).unwrap();
        record.cgroup_path = Some(boundary.path.join(name).display().to_string());
        record.cgroup_device = Some(device);
        record.cgroup_inode = Some(inode);
        boundary
    }

    fn runner_identity() -> (u32, u32) {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        #[cfg(target_os = "linux")]
        return (
            uid.checked_add(1).unwrap_or_else(|| uid.saturating_sub(1)),
            gid.checked_add(1).unwrap_or_else(|| gid.saturating_sub(1)),
        );
        #[cfg(not(target_os = "linux"))]
        (uid, gid)
    }

    fn allocation_state_fixture(suffix: &str) -> (PathBuf, PathBuf, u32, u32) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-allocation-{suffix}-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        private_directory(&root);
        let generations = root.join("generations");
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        (root, generations, runner_uid, runner_gid)
    }

    #[test]
    fn generation_root_enumeration_stops_at_four_entries() {
        let (root, generations, _, _) = allocation_state_fixture("root-entry-bound");
        for name in [
            GENERATION_RECORD_NAME,
            GENERATION_RECORD_TEMPORARY_NAME,
            "generation-00000000000000000001",
            "generation-00000000000000000002",
        ] {
            fs::write(generations.join(name), b"bounded").unwrap();
        }
        let generation_root =
            fs::File::from(openat(CWD, &generations, directory_flags(), Mode::empty()).unwrap());
        assert_eq!(
            bounded_generation_root_entries(&generation_root)
                .unwrap()
                .len(),
            4
        );
        fs::write(generations.join("five"), b"excess").unwrap();
        assert_eq!(
            bounded_generation_root_entries(&generation_root),
            Err(RunnerHostError::Boundary)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn allocating_reopen_without_generation_retries_same_generation_repeatedly() {
        let (root, generations, runner_uid, runner_gid) = allocation_state_fixture("no-generation");
        #[allow(unused_mut)]
        let mut record = allocating_record_layout(runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let _boundary = bind_allocating_cgroup(&mut record);
        write_durable_record(&generations, &record);

        let first = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(first.next_generation, 1);
        assert!(directory_is_empty(&generations).unwrap());
        drop(first);
        let second = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(second.next_generation, 1);
        assert!(directory_is_empty(&generations).unwrap());
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    fn partial_allocation_generation(
        generations: &Path,
        runner_uid: u32,
        runner_gid: u32,
        with_outbox: bool,
    ) {
        let generation_path = generations.join("generation-00000000000000000001");
        private_directory(&generation_path);
        let generation = fs::File::from(
            openat(CWD, &generation_path, directory_flags(), Mode::empty()).unwrap(),
        );
        set_directory_identity(&generation, runner_uid, runner_gid).unwrap();
        private_directory(&generation_path.join("run"));
        let run =
            fs::File::from(openat(&generation, "run", directory_flags(), Mode::empty()).unwrap());
        set_directory_identity(&run, runner_uid, runner_gid).unwrap();
        if with_outbox {
            private_directory(&generation_path.join("run/receipt-outbox"));
            let outbox = fs::File::from(
                openat(&run, "receipt-outbox", directory_flags(), Mode::empty()).unwrap(),
            );
            set_directory_identity(&outbox, runner_uid, runner_gid).unwrap();
        }
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn allocating_reopen_removes_partial_generation_and_rejects_any_content() {
        let (root, generations, runner_uid, runner_gid) =
            allocation_state_fixture("partial-generation");
        #[allow(unused_mut)]
        let mut record = allocating_record_layout(runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let _boundary = bind_allocating_cgroup(&mut record);
        partial_allocation_generation(&generations, runner_uid, runner_gid, true);
        write_durable_record(&generations, &record);

        let first = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(first.next_generation, 1);
        assert!(directory_is_empty(&generations).unwrap());
        drop(first);
        let second = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(second.next_generation, 1);
        drop(second);
        fs::remove_dir_all(root).unwrap();

        for (suffix, entry) in [
            ("journal", "run/gateway.sqlite3"),
            ("outbox-content", "run/receipt-outbox/receipt"),
            ("other", "unexpected"),
        ] {
            let (root, generations, runner_uid, runner_gid) = allocation_state_fixture(suffix);
            #[allow(unused_mut)]
            let mut record = allocating_record_layout(runner_uid, runner_gid);
            #[cfg(target_os = "linux")]
            let boundary = bind_allocating_cgroup(&mut record);
            let generation_path = generations.join("generation-00000000000000000001");
            if entry == "unexpected" {
                private_directory(&generation_path);
                let generation = fs::File::from(
                    openat(CWD, &generation_path, directory_flags(), Mode::empty()).unwrap(),
                );
                set_directory_identity(&generation, runner_uid, runner_gid).unwrap();
            } else {
                partial_allocation_generation(
                    &generations,
                    runner_uid,
                    runner_gid,
                    entry.contains("receipt-outbox"),
                );
            }
            fs::write(generation_path.join(entry), b"forbidden").unwrap();
            write_durable_record(&generations, &record);
            assert!(matches!(
                RunnerHost::open(
                    std::env::current_exe().unwrap(),
                    &generations,
                    runner_uid,
                    runner_gid,
                ),
                Err(RunnerHostError::Boundary)
            ));
            #[cfg(target_os = "linux")]
            drop(boundary);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn allocating_record_rejects_process_journal_and_allocated_identities() {
        let (runner_uid, runner_gid) = runner_identity();
        let mut record = allocating_record_layout(runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let _boundary = bind_allocating_cgroup(&mut record);
        record.process_id = Some(std::process::id());
        record.start_identity = Some(format!("{}:1", std::process::id()));
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));
        record.process_id = None;
        record.start_identity = None;
        record.journal_device = Some(1);
        record.journal_inode = Some(2);
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));
        record.journal_device = None;
        record.journal_inode = None;
        record.generation_inode = 1;
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocating_reopen_removes_empty_cgroup_and_rejects_populated_cgroup() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let (root, generations, runner_uid, runner_gid) = allocation_state_fixture("empty-cgroup");
        let mut record = allocating_record_layout(runner_uid, runner_gid);
        let boundary = bind_allocating_cgroup(&mut record);
        partial_allocation_generation(&generations, runner_uid, runner_gid, true);
        let name = boundary.prepare(record.generation).unwrap();
        write_durable_record(&generations, &record);
        let first = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(first.next_generation, 1);
        assert!(!boundary.path.join(&name).exists());
        drop(first);
        let second = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(second.next_generation, 1);
        drop(second);
        drop(boundary);
        fs::remove_dir_all(root).unwrap();

        let (root, generations, runner_uid, runner_gid) =
            allocation_state_fixture("populated-cgroup");
        let mut record = allocating_record_layout(runner_uid, runner_gid);
        let boundary = bind_allocating_cgroup(&mut record);
        let name = boundary.prepare(record.generation).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .spawn()
            .unwrap();
        boundary.attach(&name, child.id()).unwrap();
        write_durable_record(&generations, &record);
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
        boundary.fence(&name).unwrap();
        drop(boundary);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn published_input_descriptor_ignores_later_path_substitution() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-parent-substitution-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        let lease = "0123456789abcdef0123456789abcdef";
        let credential = [7; 32];
        fixed_inputs(&inputs, lease, credential);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        let published = PublishedRunnerInputs::open_for_test(&inputs).unwrap();
        fs::rename(&inputs, root.join("replaced-inputs")).unwrap();
        fixed_inputs(&inputs, "ffffffffffffffffffffffffffffffff", [9; 32]);
        let run_id = "fedcba9876543210fedcba9876543210";
        let assignment = HandoffAssignment {
            run_id: run_id.into(),
            operation_id: format!("sandbox-{run_id}"),
            lease_id: lease.into(),
            credential,
            endpoint: "127.0.0.1:1".parse().unwrap(),
        };
        let mut opened = host.open_inputs(&published, &assignment).unwrap();
        assert_eq!(
            read_input(&mut opened.remove(10)).unwrap(),
            lease.as_bytes()
        );
        assert!(fs::read_dir(&generations).unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn durable_reopen_derives_monotonic_generation_and_rejects_journal_ambiguity() {
        let make = |suffix: &str| {
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-host-record-{suffix}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let generations = root.join("generations");
            private_directory(&generations);
            (root, generations)
        };
        let (runner_uid, runner_gid) = runner_identity();

        let (root, generations) = make("accepted");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        let obsolete_path = generations.join("generation-00000000000000000006");
        private_directory(&obsolete_path);
        let obsolete =
            fs::File::from(openat(CWD, &obsolete_path, directory_flags(), Mode::empty()).unwrap());
        set_directory_identity(&obsolete, runner_uid, runner_gid).unwrap();
        drop(obsolete);
        write_durable_record(&generations, &record);
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 8);
        assert!(host.recovery_directory.is_some());
        assert!(!obsolete_path.exists());
        assert!(generations
            .join("generation-00000000000000000007/run/gateway.sqlite3")
            .is_file());
        drop(host);
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("missing");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        write_durable_record(&generations, &record);
        fs::remove_file(generations.join("generation-00000000000000000007/run/gateway.sqlite3"))
            .unwrap();
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("duplicate");
        durable_record_layout(&generations, runner_uid, runner_gid, 6, true);
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        write_durable_record(&generations, &record);
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        assert!(generations
            .join("generation-00000000000000000006/run/gateway.sqlite3")
            .is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn interrupted_record_temporary_is_removed_with_and_without_canonical_record() {
        let make = |suffix: &str| {
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-host-record-temporary-{suffix}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let generations = root.join("generations");
            private_directory(&generations);
            (root, generations)
        };
        let (runner_uid, runner_gid) = runner_identity();

        let (root, generations) = make("without-canonical");
        fs::write(
            generations.join(GENERATION_RECORD_TEMPORARY_NAME),
            b"partial",
        )
        .unwrap();
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 1);
        assert!(!generations.join(GENERATION_RECORD_TEMPORARY_NAME).exists());
        drop(host);
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("with-canonical");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        write_durable_record(&generations, &record);
        fs::write(
            generations.join(GENERATION_RECORD_TEMPORARY_NAME),
            b"partial",
        )
        .unwrap();
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 8);
        assert!(!generations.join(GENERATION_RECORD_TEMPORARY_NAME).exists());
        drop(host);
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("other-entry");
        fs::write(
            generations.join(GENERATION_RECORD_TEMPORARY_NAME),
            b"partial",
        )
        .unwrap();
        fs::write(generations.join(".runner-generation.tmp.other"), b"invalid").unwrap();
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        assert!(!generations.join(GENERATION_RECORD_TEMPORARY_NAME).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn complete_temporary_preparing_record_is_promoted_and_generation_is_cleaned() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-complete-temporary-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        #[allow(unused_mut)]
        let mut record = preparing_record_layout(&generations, runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let _boundary = bind_preparing_cgroup(&mut record);
        write_record_named(&generations, GENERATION_RECORD_TEMPORARY_NAME, &record);

        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 1);
        assert!(directory_is_empty(&generations).unwrap());
        drop(host);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn partial_temporary_record_with_generation_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-partial-temporary-generation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        #[allow(unused_mut)]
        let mut record = preparing_record_layout(&generations, runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let boundary = bind_preparing_cgroup(&mut record);
        let _ = &record;
        fs::write(
            generations.join(GENERATION_RECORD_TEMPORARY_NAME),
            b"partial",
        )
        .unwrap();
        fs::set_permissions(
            generations.join(GENERATION_RECORD_TEMPORARY_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        assert!(generations.join(GENERATION_RECORD_TEMPORARY_NAME).is_file());
        assert!(generations.join("generation-00000000000000000001").is_dir());
        #[cfg(target_os = "linux")]
        boundary.fence("generation-00000000000000000001").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn preparing_cleanup_crash_after_cgroup_fence_reopens_and_retries_same_generation() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-preparing-retry-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        #[allow(unused_mut)]
        let mut record = preparing_record_layout(&generations, runner_uid, runner_gid);
        #[cfg(target_os = "linux")]
        let boundary = bind_preparing_cgroup(&mut record);
        record.phase = String::from("preparing_fencing");
        write_durable_record(&generations, &record);
        #[cfg(target_os = "linux")]
        boundary.fence("generation-00000000000000000001").unwrap();

        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 1);
        assert!(directory_is_empty(&generations).unwrap());
        let (_, retry) = host.create_generation(1, None).unwrap();
        assert!(openat(&retry, "run", directory_flags(), Mode::empty()).is_ok());
        drop(retry);
        drop(host);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn durable_record_rejects_unknown_and_fenced_cgroup_phase_combinations() {
        let (runner_uid, runner_gid) = runner_identity();
        for (suffix, phase, path, device, inode) in [
            ("unknown", "unknown", None, None, None),
            ("fenced-path", "fenced", Some("/invalid"), None, None),
            ("fenced-identity", "fenced", None, Some(1), Some(2)),
        ] {
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-host-record-phase-{suffix}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let inputs = root.join("inputs");
            let generations = root.join("generations");
            fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
            private_directory(&generations);
            let mut record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
            record.phase = phase.into();
            record.cgroup_path = path.map(str::to_owned);
            record.cgroup_device = device;
            record.cgroup_inode = inode;
            write_durable_record(&generations, &record);
            assert!(matches!(
                RunnerHost::open(
                    std::env::current_exe().unwrap(),
                    &generations,
                    runner_uid,
                    runner_gid,
                ),
                Err(RunnerHostError::Boundary)
            ));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test crosses both repeatable atomic migration crash sides"
    )]
    fn durable_reopen_converges_on_both_atomic_generation_migration_crash_sides() {
        let make = |suffix: &str| {
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-host-migration-{suffix}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let generations = root.join("generations");
            private_directory(&generations);
            (root, generations)
        };
        let (runner_uid, runner_gid) = runner_identity();

        let (root, generations) = make("before-rename");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        empty_generation_layout(&generations, runner_uid, runner_gid, 8);
        write_durable_record(&generations, &record);
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 8);
        assert_eq!(host.durable_record.as_ref().unwrap().generation, 7);
        assert!(generations
            .join("generation-00000000000000000007/run")
            .is_dir());
        assert!(!generations.join("generation-00000000000000000008").exists());
        drop(host);
        empty_generation_layout(&generations, runner_uid, runner_gid, 8);
        let reopened = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(reopened.next_generation, 8);
        assert!(!generations.join("generation-00000000000000000008").exists());
        drop(reopened);
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("after-rename");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        empty_generation_layout(&generations, runner_uid, runner_gid, 8);
        fs::rename(
            generations.join("generation-00000000000000000007/run"),
            generations.join("generation-00000000000000000008/run"),
        )
        .unwrap();
        write_durable_record(&generations, &record);
        let host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(host.next_generation, 9);
        let repaired: DurableGenerationRecord =
            serde_json::from_slice(&fs::read(generations.join(GENERATION_RECORD_NAME)).unwrap())
                .unwrap();
        assert_eq!(repaired.generation, 8);
        assert_eq!(repaired.run_device, record.run_device);
        assert_eq!(repaired.run_inode, record.run_inode);
        let moved = fs::metadata(generations.join("generation-00000000000000000008")).unwrap();
        assert_eq!(repaired.generation_device, moved.dev());
        assert_eq!(repaired.generation_inode, moved.ino());
        drop(host);

        empty_generation_layout(&generations, runner_uid, runner_gid, 9);
        let before_rename_again = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(before_rename_again.next_generation, 9);
        assert!(!generations.join("generation-00000000000000000009").exists());
        drop(before_rename_again);

        empty_generation_layout(&generations, runner_uid, runner_gid, 9);
        fs::rename(
            generations.join("generation-00000000000000000008/run"),
            generations.join("generation-00000000000000000009/run"),
        )
        .unwrap();
        let after_rename_again = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(after_rename_again.next_generation, 10);
        assert_eq!(
            after_rename_again
                .durable_record
                .as_ref()
                .unwrap()
                .generation,
            9
        );
        drop(after_rename_again);
        fs::remove_dir_all(root).unwrap();

        let (root, generations) = make("ambiguous");
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        empty_generation_layout(&generations, runner_uid, runner_gid, 8);
        fs::write(
            generations.join("generation-00000000000000000008/unexpected"),
            b"ambiguous",
        )
        .unwrap();
        write_durable_record(&generations, &record);
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_cgroup_record_requires_complete_exact_generation_identity() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-cgroup-record-validation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let generations = root.join("generations");
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let mut record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        record.phase = "spawned".into();
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));
        record.cgroup_path = Some("/sys/fs/cgroup/invalid/generation-00000000000000000007".into());
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));
        record.cgroup_path = None;
        record.cgroup_device = Some(1);
        record.cgroup_inode = Some(2);
        assert!(matches!(
            validate_durable_phase(&record),
            Err(RunnerHostError::Boundary)
        ));

        let expected = CgroupBoundary::open(7).unwrap();
        let expected_name = expected.prepare(7).unwrap();
        let (expected_device, expected_inode) = expected.identity(&expected_name).unwrap();
        let expected_path = expected.path.join(&expected_name);
        assert!(matches!(
            fence_cgroup_path(&expected_path, 8, expected_device, expected_inode, false),
            Err(RunnerHostError::Boundary)
        ));
        assert!(expected_path.exists());

        let substitute = CgroupBoundary::open(7).unwrap();
        let substitute_name = substitute.prepare(7).unwrap();
        let substitute_path = substitute.path.join(&substitute_name);
        assert!(substitute_path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("kapsel-sandbox-controller-"));
        assert!(matches!(
            fence_cgroup_path(&substitute_path, 7, expected_device, expected_inode, false,),
            Err(RunnerHostError::Boundary)
        ));
        assert!(expected_path.exists());
        assert!(substitute_path.exists());
        expected.fence(&expected_name).unwrap();
        substitute.fence(&substitute_name).unwrap();
        drop(expected);
        drop(substitute);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_fencing_crash_after_cgroup_removal_survives_double_reopen() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-double-reopen-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let mut record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        let boundary = CgroupBoundary::open(7).unwrap();
        let cgroup_name = boundary.prepare(7).unwrap();
        let mut exited = Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .spawn()
            .unwrap();
        record.process_id = Some(exited.id());
        record.start_identity = Some(process_start_identity(exited.id()).unwrap());
        exited.kill().unwrap();
        exited.wait().unwrap();
        record.phase = "fencing".into();
        record.cgroup_path = Some(boundary.path.join(&cgroup_name).display().to_string());
        let (device, inode) = boundary.identity(&cgroup_name).unwrap();
        record.cgroup_device = Some(device);
        record.cgroup_inode = Some(inode);
        write_durable_record(&generations, &record);
        boundary.fence(&cgroup_name).unwrap();
        drop(boundary);

        let first = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        let persisted: DurableGenerationRecord =
            serde_json::from_slice(&fs::read(generations.join(GENERATION_RECORD_NAME)).unwrap())
                .unwrap();
        assert_eq!(persisted.phase, "fenced");
        assert_eq!(persisted.cgroup_path, None);
        assert_eq!(persisted.cgroup_device, None);
        assert_eq!(persisted.cgroup_inode, None);
        drop(first);

        let second = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(second.next_generation, 8);
        assert!(second.recovery_directory.is_some());
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test owns one complete descendant launch and cgroup-fencing seam"
    )]
    fn post_attach_bootstrap_failure_fences_forked_descendant_and_empty_cgroup() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-attached-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        write_durable_record(&generations, &record);
        let mut host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        let cgroup_name = host.prepare_cgroup(8).unwrap();
        let release = root.join("release-descendant");
        let descendant_file = root.join("descendant-pid");
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                concat!(
                    "while [ ! -f \"$1\" ]; do sleep 0.01; done; ",
                    "sleep 1000 & pid=$!; printf '%s\\n' \"$pid\" > \"$2.tmp\"; ",
                    "mv \"$2.tmp\" \"$2\"; wait"
                ),
                "sh",
                release.to_str().unwrap(),
                descendant_file.to_str().unwrap(),
            ])
            .spawn()
            .unwrap();
        host.attach_cgroup(&cgroup_name, child.id()).unwrap();
        fs::write(&release, b"release").unwrap();
        for _ in 0..10_000 {
            if descendant_file.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let descendant: u32 = fs::read_to_string(&descendant_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(Path::new(&format!("/proc/{descendant}")).exists());

        let mut spawned = record;
        spawned.process_id = Some(child.id());
        spawned.start_identity = Some(process_start_identity(child.id()).unwrap());
        spawned.phase = String::from("spawned");
        let boundary = host.cgroup.as_ref().unwrap();
        let cgroup_path = boundary.path.join(&cgroup_name);
        spawned.cgroup_path = Some(cgroup_path.display().to_string());
        let (device, inode) = boundary.identity(&cgroup_name).unwrap();
        spawned.cgroup_device = Some(device);
        spawned.cgroup_inode = Some(inode);
        host.persist_record(&spawned).unwrap();
        let state = host
            .recovery_directory
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap();
        assert_eq!(
            host.fail_attached_launch(
                &mut child,
                &cgroup_name,
                &state,
                &spawned,
                RunnerHostError::Boundary,
            ),
            RunnerHostError::Boundary
        );
        for _ in 0..10_000 {
            if !Path::new(&format!("/proc/{descendant}")).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(!Path::new(&format!("/proc/{descendant}")).exists());
        assert!(
            !cgroup_path.exists(),
            "the cgroup is removed only after cgroup.events reports populated 0"
        );
        let retained: DurableGenerationRecord =
            serde_json::from_slice(&fs::read(generations.join(GENERATION_RECORD_NAME)).unwrap())
                .unwrap();
        assert_eq!(retained.phase, "fenced");
        assert_eq!(retained.cgroup_path, None);
        assert_eq!(retained.cgroup_device, None);
        assert_eq!(retained.cgroup_inode, None);
        drop(host);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_durable_generation_record_is_rejected_on_reopen() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-malformed-record-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
        private_directory(&generations);
        fs::write(generations.join(GENERATION_RECORD_NAME), b"not-json").unwrap();
        fs::set_permissions(
            generations.join(GENERATION_RECORD_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let (runner_uid, runner_gid) = runner_identity();
        assert!(matches!(
            RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            ),
            Err(RunnerHostError::Boundary)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn retained_journal_rejects_cross_run_launch_until_explicit_retirement() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-cross-run-retirement-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        let lease = "0123456789abcdef0123456789abcdef";
        let credential = [7; 32];
        fixed_inputs(&inputs, lease, credential);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
        write_durable_record(&generations, &record);
        let mut host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        assert_eq!(
            host.retained_identity(),
            Some((record.run_id.as_str(), record.operation_id.as_str()))
        );
        let next_run = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let assignment = HandoffAssignment {
            run_id: next_run.into(),
            operation_id: format!("sandbox-{next_run}"),
            lease_id: lease.into(),
            credential,
            endpoint: "127.0.0.1:1".parse().unwrap(),
        };
        assert!(matches!(
            host.launch(
                next_run,
                &assignment,
                &PublishedRunnerInputs::open_for_test(&inputs).unwrap(),
            ),
            Err(RunnerHostError::StaleAuthority)
        ));
        assert!(generations.join(GENERATION_RECORD_NAME).is_file());
        assert!(generations
            .join("generation-00000000000000000007/run/gateway.sqlite3")
            .is_file());
        host.retire(&record.run_id).unwrap();
        assert_eq!(host.retained_identity(), None);
        assert!(fs::read_dir(&generations).unwrap().next().is_none());
        let (fresh_generation, _) = host.create_generation(8, None).unwrap();
        assert!(!fresh_generation.join("run/gateway.sqlite3").exists());
        assert!(fs::read_dir(fresh_generation.join("run/receipt-outbox"))
            .unwrap()
            .next()
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg_attr(
        target_os = "linux",
        ignore = "requires the privileged private-cgroup Linux lane"
    )]
    #[test]
    fn retiring_record_converges_before_and_after_generation_removal() {
        for generation_removed in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-host-retiring-reopen-{}-{generation_removed}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let inputs = root.join("inputs");
            let generations = root.join("generations");
            fixed_inputs(&inputs, "0123456789abcdef0123456789abcdef", [7; 32]);
            private_directory(&generations);
            let (runner_uid, runner_gid) = runner_identity();
            let mut record = durable_record_layout(&generations, runner_uid, runner_gid, 7, true);
            record.phase = String::from("retiring");
            write_durable_record(&generations, &record);
            if generation_removed {
                fs::remove_dir_all(generations.join("generation-00000000000000000007")).unwrap();
            }
            let host = RunnerHost::open(
                std::env::current_exe().unwrap(),
                &generations,
                runner_uid,
                runner_gid,
            )
            .unwrap();
            assert_eq!(host.retained_identity(), None);
            assert!(fs::read_dir(&generations).unwrap().next().is_none());
            drop(host);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn endpoint_mismatch_and_non_loopback_are_rejected_before_generation() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-endpoint-rejection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        let lease = "0123456789abcdef0123456789abcdef";
        let credential = [7; 32];
        fixed_inputs(&inputs, lease, credential);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let mut host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        let run_id = "fedcba9876543210fedcba9876543210";
        for endpoint in ["127.0.0.1:2", "192.0.2.1:1"] {
            let assignment = HandoffAssignment {
                run_id: run_id.into(),
                operation_id: format!("sandbox-{run_id}"),
                lease_id: lease.into(),
                credential,
                endpoint: endpoint.parse().unwrap(),
            };
            assert!(matches!(
                host.launch(
                    run_id,
                    &assignment,
                    &PublishedRunnerInputs::open_for_test(&inputs).unwrap(),
                ),
                Err(RunnerHostError::StaleAuthority)
            ));
            assert!(fs::read_dir(&generations).unwrap().next().is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_executable_descriptor_survives_path_substitution_and_is_cloexec() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-pinned-executable-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let path = root.join("helper");
        fs::write(&path, b"original helper bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut descriptor = open_executable(
            &path,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
        .unwrap();
        assert!(rustix::io::fcntl_getfd(&descriptor)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        fs::rename(&path, root.join("original-helper")).unwrap();
        fs::write(&path, b"substituted helper bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            read_input(&mut descriptor).unwrap(),
            b"original helper bytes"
        );
        assert_eq!(
            fs::read(executable_descriptor_path(&descriptor)).unwrap(),
            b"original helper bytes"
        );
        assert_eq!(fs::read(path).unwrap(), b"substituted helper bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_and_runner_file_capabilities_are_rejected_before_launch() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-file-capability-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let owner_uid = rustix::process::geteuid().as_raw();
        let owner_gid = rustix::process::getegid().as_raw();
        // Linux VFS capability revision 2 with CAP_CHOWN in the permitted/effective set.
        let capability = [
            1_u8, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for name in ["helper", "runner"] {
            let path = root.join(name);
            fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let file = fs::File::open(&path).unwrap();
            rustix::fs::fsetxattr(
                &file,
                "security.capability",
                &capability,
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            assert!(matches!(
                open_executable(&path, owner_uid, owner_gid),
                Err(RunnerHostError::Boundary)
            ));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn substituted_executable_is_rejected_without_stranding_a_generation() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-executable-rejection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        let executable = root.join("kapsel-sandbox");
        let lease = "0123456789abcdef0123456789abcdef";
        let credential = [7; 32];
        fixed_inputs(&inputs, lease, credential);
        private_directory(&generations);
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let (runner_uid, runner_gid) = runner_identity();
        let mut host = RunnerHost::open(&executable, &generations, runner_uid, runner_gid).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o777)).unwrap();
        let run_id = "fedcba9876543210fedcba9876543210";
        let assignment = HandoffAssignment {
            run_id: run_id.into(),
            operation_id: format!("sandbox-{run_id}"),
            lease_id: lease.into(),
            credential,
            endpoint: "127.0.0.1:1".parse().unwrap(),
        };
        assert!(matches!(
            host.launch(
                run_id,
                &assignment,
                &PublishedRunnerInputs::open_for_test(&inputs).unwrap(),
            ),
            Err(RunnerHostError::Boundary)
        ));
        assert!(fs::read_dir(&generations).unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn permissive_input_and_stale_lease_are_rejected_before_generation() {
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-host-input-rejection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let inputs = root.join("inputs");
        let generations = root.join("generations");
        let lease = "0123456789abcdef0123456789abcdef";
        fixed_inputs(&inputs, lease, [7; 32]);
        private_directory(&generations);
        let (runner_uid, runner_gid) = runner_identity();
        let mut host = RunnerHost::open(
            std::env::current_exe().unwrap(),
            &generations,
            runner_uid,
            runner_gid,
        )
        .unwrap();
        fs::set_permissions(
            inputs.join("request.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let run_id = "fedcba9876543210fedcba9876543210";
        let assignment = HandoffAssignment {
            run_id: run_id.into(),
            operation_id: format!("sandbox-{run_id}"),
            lease_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            credential: [8; 32],
            endpoint: "127.0.0.1:1".parse().unwrap(),
        };
        assert!(matches!(
            host.launch(
                run_id,
                &assignment,
                &PublishedRunnerInputs::open_for_test(&inputs).unwrap(),
            ),
            Err(RunnerHostError::Boundary)
        ));
        fs::set_permissions(
            inputs.join("request.json"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        assert!(matches!(
            host.launch(
                run_id,
                &assignment,
                &PublishedRunnerInputs::open_for_test(&inputs).unwrap(),
            ),
            Err(RunnerHostError::StaleAuthority)
        ));
        assert!(fs::read_dir(&generations).unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
