//! Fixed state-root publication, readiness validation, and process-lifetime fencing.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::fs::{flock, open, openat, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    service_schema, AuthorityConfiguration, PinnedServiceState, Service, ServiceError,
    StoppedBackupService,
};

const PARENT_LOCK: &str = ".kapsel-sandbox-restore.lock";
const STATE_LOCK: &str = ".backup.lock";
const DATABASE: &str = "sandbox.sqlite3";
const RECEIPTS: &str = "receipts";
const RUNNER: &str = "runner";
const DEPLOYMENT: &str = "deployment.json";
const READY: &str = "restore.ready";
const INCOMPLETE: &str = "restore.incomplete";
const JSON_MAX: u64 = 16 * 1024;
const STAGING_ID: u32 = 65_531;

#[derive(Clone, Copy, Debug)]
pub(crate) enum DeploymentProfile {
    Production,
    #[cfg(any(test, feature = "state-root-test-harness"))]
    Test,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RoleIdentities {
    pub(crate) controller_uid: u32,
    pub(crate) controller_gid: u32,
    pub(crate) staging_uid: u32,
    pub(crate) staging_gid: u32,
    pub(crate) runner_uid: u32,
    pub(crate) runner_gid: u32,
}

impl RoleIdentities {
    #[allow(
        clippy::similar_names,
        reason = "fixed controller and staging UID/GID pairs remain deliberately explicit"
    )]
    pub(crate) fn validate_authority(
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
    ) -> Result<Self, ()> {
        let expected = Self::production();
        if controller_uid != expected.controller_uid
            || controller_gid != expected.controller_gid
            || staging_uid != expected.staging_uid
            || staging_gid != expected.staging_gid
        {
            return Err(());
        }
        Ok(expected)
    }

    #[allow(
        clippy::similar_names,
        reason = "the fixed runner UID/GID pair remains deliberately explicit"
    )]
    pub(crate) fn validate_runner(self, runner_uid: u32, runner_gid: u32) -> Result<Self, ()> {
        if runner_uid == self.runner_uid && runner_gid == self.runner_gid {
            Ok(self)
        } else {
            Err(())
        }
    }

    pub(crate) fn controller() -> Self {
        Self::production()
    }

    #[cfg(any(test, feature = "state-root-test-harness"))]
    #[allow(
        clippy::similar_names,
        reason = "the private test controller keeps its exact UID/GID pair visible"
    )]
    pub(crate) fn test_controller() -> Self {
        let controller_uid = rustix::process::geteuid().as_raw();
        let controller_gid = rustix::process::getegid().as_raw();
        Self {
            controller_uid,
            controller_gid,
            staging_uid: STAGING_ID,
            staging_gid: STAGING_ID,
            runner_uid: controller_uid,
            runner_gid: controller_gid,
        }
    }

    fn production() -> Self {
        Self {
            controller_uid: 65_530,
            controller_gid: 65_530,
            staging_uid: 65_531,
            staging_gid: 65_531,
            runner_uid: 65_532,
            runner_gid: 65_532,
        }
    }

    #[cfg(any(test, feature = "state-root-test-harness"))]
    #[allow(
        clippy::similar_names,
        reason = "the private test profile keeps exact UID/GID role pairs visible"
    )]
    pub(crate) fn validate_test_authority(
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
    ) -> Result<Self, ()> {
        let expected_controller_uid = rustix::process::geteuid().as_raw();
        let expected_controller_gid = rustix::process::getegid().as_raw();
        if controller_uid != expected_controller_uid || controller_gid != expected_controller_gid {
            return Err(());
        }
        Ok(Self {
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
            runner_uid: controller_uid,
            runner_gid: controller_gid,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

impl ObjectIdentity {
    fn of(file: &File) -> Result<Self, ()> {
        let metadata = file.metadata().map_err(|_| ())?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct StateGuard {
    root: PathBuf,
    root_name: std::ffi::OsString,
    parent_directory: File,
    state_directory: File,
    database_file: File,
    receipts_directory: File,
    runner_directory: File,
    _parent_lock: File,
    _state_lock: File,
}

impl StateGuard {
    pub(crate) fn open(
        root: &Path,
        identities: RoleIdentities,
        profile: DeploymentProfile,
    ) -> Result<Self, ()> {
        require_absolute(root)?;
        let parent_path = root.parent().ok_or(())?;
        let root_name = root.file_name().ok_or(())?.to_owned();
        let parent_directory = open_fixed_directory_path(
            parent_path,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        let parent_lock = open_fixed_file_at(
            &parent_directory,
            PARENT_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&parent_lock, FlockOperation::NonBlockingLockShared).map_err(|_| ())?;
        validate_parent_inventory_at(&parent_directory, &root_name)?;
        let state_directory = open_fixed_directory_at(
            &parent_directory,
            &root_name,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        let state_lock = open_fixed_file_at(
            &state_directory,
            STATE_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&state_lock, FlockOperation::NonBlockingLockShared).map_err(|_| ())?;
        let (database_file, receipts_directory, runner_directory) =
            validate_inventory_at(&state_directory, identities)?;
        validate_deployment_at(
            &state_directory,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
        validate_ready_at(
            &state_directory,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
        let guard = Self {
            root: root.to_owned(),
            root_name,
            parent_directory,
            state_directory,
            database_file,
            receipts_directory,
            runner_directory,
            _parent_lock: parent_lock,
            _state_lock: state_lock,
        };
        guard.verify()?;
        Ok(guard)
    }

    pub(crate) fn verify(&self) -> Result<(), ()> {
        let state = openat(
            &self.parent_directory,
            &self.root_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ())?;
        require_same(&state, &self.state_directory)?;
        let database = openat(
            &state,
            DATABASE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ())?;
        if ObjectIdentity::of(&database)? != ObjectIdentity::of(&self.database_file)? {
            return Err(());
        }
        let receipts = openat(
            &state,
            RECEIPTS,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ())?;
        if ObjectIdentity::of(&receipts)? != ObjectIdentity::of(&self.receipts_directory)? {
            return Err(());
        }
        let runner = openat(
            &state,
            RUNNER,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ())?;
        if ObjectIdentity::of(&runner)? != ObjectIdentity::of(&self.runner_directory)? {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn open_service(
        &self,
        authority: &AuthorityConfiguration,
        now_unix_s: i64,
    ) -> Result<Service, ServiceError> {
        self.verify().map_err(|()| ServiceError::Unavailable)?;
        Service::open_internal(
            &self.root.join(DATABASE),
            &self.root.join(RECEIPTS),
            authority,
            now_unix_s,
            Some(PinnedServiceState {
                state_directory: self
                    .state_directory
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
                database: self
                    .database_file
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
                receipts: self
                    .receipts_directory
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
            }),
        )
    }

    pub(crate) fn set_global_stop(&self, stopped: bool) -> Result<(), ServiceError> {
        self.verify().map_err(|()| ServiceError::Unavailable)?;
        let pinned = PinnedServiceState {
            state_directory: self
                .state_directory
                .try_clone()
                .map_err(|_| ServiceError::Unavailable)?,
            database: self
                .database_file
                .try_clone()
                .map_err(|_| ServiceError::Unavailable)?,
            receipts: self
                .receipts_directory
                .try_clone()
                .map_err(|_| ServiceError::Unavailable)?,
        };
        crate::set_global_stop_internal(
            &self.root.join(DATABASE),
            stopped,
            Some((&self.root.join(RECEIPTS), &pinned)),
        )
    }

    pub(crate) fn runner(&self) -> Result<PathBuf, ()> {
        self.verify()?;
        Ok(self.root.join(RUNNER))
    }
}

#[allow(
    dead_code,
    reason = "the capture-only guard is the accepted foundation for the private backup module"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeploymentIdentity {
    pub(crate) compatibility_sha256: String,
    pub(crate) package_version: String,
    pub(crate) target: String,
    pub(crate) service_schema_sha256: String,
    pub(crate) gateway_schema_sha256: String,
    pub(crate) staging_schema: String,
    pub(crate) policy: String,
    pub(crate) pre_exec_source_sha256: String,
    pub(crate) pre_exec_compiler: String,
    pub(crate) pre_exec_helper_sha256: String,
    pub(crate) runner_sha256: String,
}

#[allow(
    dead_code,
    reason = "the capture-only guard is the accepted foundation for the private backup module"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeploymentSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: DeploymentIdentity,
}

#[allow(
    dead_code,
    reason = "the clean generation tracer consumes the pinned source unit"
)]
pub(crate) struct BackupSourceDescriptors {
    pub(crate) database: File,
    pub(crate) receipts: File,
    pub(crate) runner: File,
    pub(crate) deployment: File,
    pub(crate) deployment_snapshot: DeploymentSnapshot,
}

#[allow(
    dead_code,
    reason = "the capture-only guard is the accepted foundation for the private backup module"
)]
#[derive(Debug)]
pub(crate) struct BackupStateGuard {
    root: PathBuf,
    root_name: std::ffi::OsString,
    parent_directory: File,
    state_directory: File,
    database_file: File,
    receipts_directory: File,
    runner_directory: File,
    deployment_file: File,
    ready_file: File,
    deployment: DeploymentSnapshot,
    identities: RoleIdentities,
    profile: DeploymentProfile,
    parent_lock: File,
    state_lock: File,
}

#[allow(
    dead_code,
    reason = "the capture-only guard is the accepted foundation for the private backup module"
)]
impl BackupStateGuard {
    pub(crate) fn open_clean(
        root: &Path,
        identities: RoleIdentities,
        profile: DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_capture(root, identities, profile)?;
        Service::preflight_clean_backup_source(&guard.root.join(DATABASE)).map_err(|_| ())?;
        guard.verify()?;
        Ok(guard)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one closed lock, inventory, descriptor, and read-only source audit stays ordered"
    )]
    pub(crate) fn open_capture(
        root: &Path,
        identities: RoleIdentities,
        profile: DeploymentProfile,
    ) -> Result<Self, ()> {
        require_absolute(root)?;
        let parent_path = root.parent().ok_or(())?;
        let root_name = root.file_name().ok_or(())?.to_owned();
        let parent_directory = open_fixed_directory_path(
            parent_path,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        let parent_lock = open_fixed_file_at(
            &parent_directory,
            PARENT_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&parent_lock, FlockOperation::NonBlockingLockShared).map_err(|_| ())?;
        validate_parent_inventory_at(&parent_directory, &root_name)?;
        let state_directory = open_fixed_directory_at(
            &parent_directory,
            &root_name,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        let state_lock = open_fixed_file_at(
            &state_directory,
            STATE_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&state_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
        let actual = directory_names(&state_directory, 7)?;
        let expected = [DATABASE, RECEIPTS, RUNNER, DEPLOYMENT, STATE_LOCK, READY]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(());
        }
        let database_file = open_fixed_file_at(
            &state_directory,
            DATABASE,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            false,
        )?;
        let receipts_directory = open_fixed_directory_at(
            &state_directory,
            RECEIPTS,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        if !directory_names(&receipts_directory, 1)?.is_empty() {
            return Err(());
        }
        let runner_directory = open_fixed_directory_at(
            &state_directory,
            RUNNER,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        if !directory_names(&runner_directory, 1)?.is_empty() {
            return Err(());
        }
        let (deployment_file, deployment) = open_deployment_snapshot_at(
            &state_directory,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
        let ready_file = open_ready_at(
            &state_directory,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
        Service::preflight_stopped_backup_source(&root.join(DATABASE)).map_err(|_| ())?;
        let guard = Self {
            root: root.to_owned(),
            root_name,
            parent_directory,
            state_directory,
            database_file,
            receipts_directory,
            runner_directory,
            deployment_file,
            ready_file,
            deployment,
            identities,
            profile,
            parent_lock,
            state_lock,
        };
        guard.verify()?;
        Ok(guard)
    }

    pub(crate) fn verify(&self) -> Result<(), ()> {
        validate_parent_inventory_at(&self.parent_directory, &self.root_name)?;
        let parent_lock = open_fixed_file_at(
            &self.parent_directory,
            PARENT_LOCK,
            self.identities.controller_uid,
            self.identities.controller_gid,
            0o600,
            true,
        )?;
        require_same(&parent_lock, &self.parent_lock)?;
        let state = open_fixed_directory_at(
            &self.parent_directory,
            &self.root_name,
            self.identities.controller_uid,
            self.identities.controller_gid,
            0o700,
        )?;
        require_same(&state, &self.state_directory)?;
        for (name, pinned, mode, writable) in [
            (DATABASE, &self.database_file, 0o600, false),
            (DEPLOYMENT, &self.deployment_file, 0o400, false),
            (READY, &self.ready_file, 0o600, false),
            (STATE_LOCK, &self.state_lock, 0o600, true),
        ] {
            let reopened = open_fixed_file_at(
                &state,
                name,
                self.identities.controller_uid,
                self.identities.controller_gid,
                mode,
                writable,
            )?;
            require_same(&reopened, pinned)?;
        }
        for (name, pinned) in [
            (RECEIPTS, &self.receipts_directory),
            (RUNNER, &self.runner_directory),
        ] {
            let reopened = open_fixed_directory_at(
                &state,
                name,
                self.identities.controller_uid,
                self.identities.controller_gid,
                0o700,
            )?;
            require_same(&reopened, pinned)?;
            if !directory_names(&reopened, 1)?.is_empty() {
                return Err(());
            }
        }
        let actual = directory_names(&state, 7)?;
        let expected = [DATABASE, RECEIPTS, RUNNER, DEPLOYMENT, STATE_LOCK, READY]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(());
        }
        let deployment = deployment_snapshot_from_file(&self.deployment_file, self.profile)?;
        if deployment != self.deployment {
            return Err(());
        }
        validate_ready_file(&self.ready_file, self.profile)?;
        Service::preflight_stopped_backup_source(&self.root.join(DATABASE)).map_err(|_| ())
    }

    pub(crate) fn deployment_snapshot(&self) -> Result<DeploymentSnapshot, ()> {
        self.verify()?;
        Ok(self.deployment.clone())
    }

    pub(crate) fn backup_source_descriptors(&self) -> Result<BackupSourceDescriptors, ()> {
        self.verify()?;
        let source = BackupSourceDescriptors {
            database: self.database_file.try_clone().map_err(|_| ())?,
            receipts: self.receipts_directory.try_clone().map_err(|_| ())?,
            runner: self.runner_directory.try_clone().map_err(|_| ())?,
            deployment: self.deployment_file.try_clone().map_err(|_| ())?,
            deployment_snapshot: self.deployment.clone(),
        };
        require_same(&source.database, &self.database_file)?;
        require_same(&source.receipts, &self.receipts_directory)?;
        require_same(&source.runner, &self.runner_directory)?;
        require_same(&source.deployment, &self.deployment_file)?;
        self.verify()?;
        Ok(source)
    }

    pub(crate) fn open_stopped_service<'guard>(
        &'guard self,
        authority: &AuthorityConfiguration,
    ) -> Result<StoppedBackupService<'guard>, ServiceError> {
        self.verify().map_err(|()| ServiceError::Unavailable)?;
        StoppedBackupService::open_internal(
            &self.root.join(DATABASE),
            &self.root.join(RECEIPTS),
            authority,
            Some(PinnedServiceState {
                state_directory: self
                    .state_directory
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
                database: self
                    .database_file
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
                receipts: self
                    .receipts_directory
                    .try_clone()
                    .map_err(|_| ServiceError::Unavailable)?,
            }),
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InitializationKind {
    Fresh,
    Migration,
}

#[derive(Clone, Copy)]
enum ExistingMigrationMarkers {
    None,
    Deployment,
    Ready,
}

pub(crate) struct StateInitializer {
    destination: PathBuf,
    working_path: PathBuf,
    root_name: std::ffi::OsString,
    working_name: std::ffi::OsString,
    parent_directory: File,
    working_directory: File,
    kind: InitializationKind,
    identities: RoleIdentities,
    profile: DeploymentProfile,
    published: bool,
    existing_markers: ExistingMigrationMarkers,
    remove_state_lock_on_drop: bool,
    _parent_lock: File,
    _state_lock: File,
}

impl StateInitializer {
    #[allow(
        clippy::too_many_lines,
        reason = "one closed audit sequence separates exact migration from atomic fresh init"
    )]
    pub(crate) fn begin(
        root: &Path,
        identities: RoleIdentities,
        authority: &AuthorityConfiguration,
        profile: DeploymentProfile,
    ) -> Result<Self, ()> {
        require_absolute(root)?;
        let parent_path = root.parent().ok_or(())?;
        let root_name = root.file_name().ok_or(())?.to_owned();
        let parent_directory = open_fixed_directory_path(
            parent_path,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        let parent_lock = open_fixed_file_at(
            &parent_directory,
            PARENT_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&parent_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
        let parent_names = directory_names(&parent_directory, 3)?;
        if parent_names.contains(&root_name) {
            let expected = [std::ffi::OsString::from(PARENT_LOCK), root_name.clone()]
                .into_iter()
                .collect::<BTreeSet<_>>();
            if parent_names != expected {
                return Err(());
            }
            let working_directory = open_fixed_directory_at(
                &parent_directory,
                &root_name,
                identities.controller_uid,
                identities.controller_gid,
                0o700,
            )?;
            let state_lock_exists =
                validate_pre_slice_inventory(&working_directory, identities, profile)?;
            preflight_migration_database(&root.join(DATABASE), &working_directory)?;
            Service::preflight_stopped_state_root_migration(&root.join(DATABASE), authority)
                .map_err(|_| ())?;
            if !state_lock_exists {
                create_file_at(
                    &working_directory,
                    STATE_LOCK,
                    identities.controller_uid,
                    identities.controller_gid,
                    0o600,
                )?;
            }
            let state_lock = open_fixed_file_at(
                &working_directory,
                STATE_LOCK,
                identities.controller_uid,
                identities.controller_gid,
                0o600,
                true,
            )?;
            flock(&state_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
            Service::migrate_stopped_state_root(&root.join(DATABASE)).map_err(|_| ())?;
            let migrated_names = directory_names(&working_directory, 7)?;
            let existing_markers = if migrated_names.contains(std::ffi::OsStr::new(READY)) {
                ExistingMigrationMarkers::Ready
            } else if migrated_names.contains(std::ffi::OsStr::new(DEPLOYMENT)) {
                ExistingMigrationMarkers::Deployment
            } else {
                ExistingMigrationMarkers::None
            };
            return Ok(Self {
                destination: root.to_owned(),
                working_path: root.to_owned(),
                root_name: root_name.clone(),
                working_name: root_name,
                parent_directory,
                working_directory,
                kind: InitializationKind::Migration,
                identities,
                profile,
                published: false,
                existing_markers,
                remove_state_lock_on_drop: !state_lock_exists,
                _parent_lock: parent_lock,
                _state_lock: state_lock,
            });
        }
        let temporary_name =
            std::ffi::OsString::from(format!(".{}.initializing", root_name.to_str().ok_or(())?));
        let allowed = [
            std::ffi::OsString::from(PARENT_LOCK),
            temporary_name.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if parent_names != std::iter::once(std::ffi::OsString::from(PARENT_LOCK)).collect()
            && parent_names != allowed
        {
            return Err(());
        }
        if parent_names.contains(&temporary_name) {
            remove_recoverable_tree(&parent_directory, &temporary_name, identities)?;
            parent_directory.sync_all().map_err(|_| ())?;
        }
        rustix::fs::mkdirat(
            &parent_directory,
            &temporary_name,
            Mode::from_raw_mode(0o700),
        )
        .map_err(|_| ())?;
        let working_directory = open_fixed_directory_at(
            &parent_directory,
            &temporary_name,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        create_directory_at(
            &working_directory,
            RECEIPTS,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        create_directory_at(
            &working_directory,
            RUNNER,
            identities.controller_uid,
            identities.controller_gid,
            0o700,
        )?;
        create_file_at(
            &working_directory,
            STATE_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
        )?;
        let state_lock = open_fixed_file_at(
            &working_directory,
            STATE_LOCK,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            true,
        )?;
        flock(&state_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
        working_directory.sync_all().map_err(|_| ())?;
        let working_path = parent_path.join(&temporary_name);
        Ok(Self {
            destination: root.to_owned(),
            working_path,
            root_name,
            working_name: temporary_name,
            parent_directory,
            working_directory,
            kind: InitializationKind::Fresh,
            identities,
            profile,
            published: false,
            existing_markers: ExistingMigrationMarkers::None,
            remove_state_lock_on_drop: false,
            _parent_lock: parent_lock,
            _state_lock: state_lock,
        })
    }

    pub(crate) fn is_migration(&self) -> bool {
        self.kind == InitializationKind::Migration
    }

    pub(crate) fn verify(&self) -> Result<(), ()> {
        let reopened = openat(
            &self.parent_directory,
            &self.working_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| ())?;
        require_same(&reopened, &self.working_directory)
    }

    pub(crate) fn database(&self) -> Result<PathBuf, ()> {
        self.verify()?;
        Ok(self.working_path.join(DATABASE))
    }
    pub(crate) fn receipts(&self) -> Result<PathBuf, ()> {
        self.verify()?;
        Ok(self.working_path.join(RECEIPTS))
    }

    pub(crate) fn publish(mut self, completed_at: i64) -> Result<(), ()> {
        if completed_at <= 0 {
            return Err(());
        }
        self.verify()?;
        let deployment = deployment_record(self.profile)?;
        if self.kind == InitializationKind::Migration
            && directory_names(&self.working_directory, 7)?
                .contains(std::ffi::OsStr::new(DEPLOYMENT))
        {
            validate_deployment_at(
                &self.working_directory,
                self.identities.controller_uid,
                self.identities.controller_gid,
                self.profile,
            )?;
        } else {
            write_canonical_at(
                &self.working_directory,
                DEPLOYMENT,
                &deployment,
                self.identities.controller_uid,
                self.identities.controller_gid,
                0o400,
            )?;
        }
        let ready = ReadyRecord {
            schema: "kapsel.sandbox.restore-ready.v1".into(),
            source: "initialized".into(),
            generation: None,
            manifest_sha256: None,
            compatibility_sha256: deployment.compatibility_sha256,
            completed_at,
        };
        if self.kind == InitializationKind::Migration
            && directory_names(&self.working_directory, 7)?.contains(std::ffi::OsStr::new(READY))
        {
            validate_ready_at(
                &self.working_directory,
                self.identities.controller_uid,
                self.identities.controller_gid,
                self.profile,
            )?;
        } else {
            write_canonical_at(
                &self.working_directory,
                READY,
                &ready,
                self.identities.controller_uid,
                self.identities.controller_gid,
                0o600,
            )?;
        }
        sync_tree(&self.working_directory, 0)?;
        if self.kind == InitializationKind::Fresh {
            rustix::fs::renameat(
                &self.parent_directory,
                &self.working_name,
                &self.parent_directory,
                &self.root_name,
            )
            .map_err(|_| ())?;
        }
        self.parent_directory.sync_all().map_err(|_| ())?;
        self.published = true;
        let _ = &self.destination;
        Ok(())
    }
}

impl Drop for StateInitializer {
    fn drop(&mut self) {
        if self.published || self.kind != InitializationKind::Migration {
            return;
        }
        if !matches!(self.existing_markers, ExistingMigrationMarkers::Ready) {
            let _ =
                rustix::fs::unlinkat(&self.working_directory, READY, rustix::fs::AtFlags::empty());
        }
        if matches!(self.existing_markers, ExistingMigrationMarkers::None) {
            let _ = rustix::fs::unlinkat(
                &self.working_directory,
                DEPLOYMENT,
                rustix::fs::AtFlags::empty(),
            );
        }
        if self.remove_state_lock_on_drop {
            let _ = rustix::fs::unlinkat(
                &self.working_directory,
                STATE_LOCK,
                rustix::fs::AtFlags::empty(),
            );
        }
        let _ = self.working_directory.sync_all();
        let _ = self.parent_directory.sync_all();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentRecord {
    schema: String,
    compatibility_sha256: String,
    package_version: String,
    target: String,
    service_schema_sha256: String,
    gateway_schema_sha256: String,
    staging_schema: String,
    policy: String,
    pre_exec_source_sha256: String,
    pre_exec_compiler: String,
    pre_exec_helper_sha256: String,
    runner_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadyRecord {
    schema: String,
    source: String,
    generation: Option<u64>,
    manifest_sha256: Option<String>,
    compatibility_sha256: String,
    completed_at: i64,
}

fn deployment_record(profile: DeploymentProfile) -> Result<DeploymentRecord, ()> {
    let service = service_schema::digest();
    let gateway = kapsel::sandbox_gateway_schema_digest();
    let service_hex = hex(&service);
    let gateway_hex = hex(&gateway);
    let target = target_identity(profile)?;
    let compatibility = compatibility_digest(&service_hex, &gateway_hex, target)?;
    let helper = open_identity_file(Path::new(env!("KAPSEL_SANDBOX_RUNNER_PRE_EXEC")), true)?;
    let runner = open_runner_identity()?;
    Ok(DeploymentRecord {
        schema: "kapsel.sandbox.deployment.v1".into(),
        compatibility_sha256: hex(&compatibility),
        package_version: env!("CARGO_PKG_VERSION").into(),
        target: target.into(),
        service_schema_sha256: service_hex,
        gateway_schema_sha256: gateway_hex,
        staging_schema: "v1".into(),
        policy: "sandbox-policy-v3".into(),
        pre_exec_source_sha256: hex(&Sha256::digest(include_bytes!("runner_pre_exec.c"))),
        pre_exec_compiler: env!("KAPSEL_SANDBOX_PRE_EXEC_COMPILER").into(),
        pre_exec_helper_sha256: digest_file(helper)?,
        runner_sha256: digest_file(runner)?,
    })
}

fn compatibility_digest(service: &str, gateway: &str, target: &str) -> Result<[u8; 32], ()> {
    let mut digest = Sha256::new();
    digest.update(b"KAPSEL-SANDBOX-BACKUP-COMPATIBILITY-V1\0");
    for value in [
        env!("CARGO_PKG_VERSION"),
        target,
        service,
        gateway,
        "v1",
        "sandbox-policy-v3",
    ] {
        digest.update(u64::try_from(value.len()).map_err(|_| ())?.to_be_bytes());
        digest.update(value.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn preflight_migration_database(database: &Path, state: &File) -> Result<(), ()> {
    let database = std::fs::canonicalize(database).map_err(|_| ())?;
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| ())?;
    let safe: i64 = connection
        .query_row(
            concat!(
                "SELECT stopped = 1 ",
                "AND NOT EXISTS(SELECT 1 FROM runs WHERE active = 1) ",
                "AND NOT EXISTS(SELECT 1 FROM receipt_publications) ",
                "AND NOT EXISTS(SELECT 1 FROM cleanup_records WHERE active = 1) ",
                "AND NOT EXISTS(SELECT 1 FROM authority_collection) ",
                "FROM service_state WHERE singleton = 1"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    if safe != 1 {
        return Err(());
    }
    for table in ["backup_generations", "backup_authority_references"] {
        let exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| ())?;
        if exists == 1 {
            let empty: i64 = connection
                .query_row(&format!("SELECT COUNT(*) = 0 FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(|_| ())?;
            if empty != 1 {
                return Err(());
            }
        }
    }
    let mut statement = connection
        .prepare("SELECT object_name FROM receipts ORDER BY object_name")
        .map_err(|_| ())?;
    let referenced = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| ())?
        .map(|row| row.map(std::ffi::OsString::from).map_err(|_| ()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let receipts = openat(
        state,
        RECEIPTS,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ())?;
    if directory_names(&receipts, 4_096)? != referenced {
        return Err(());
    }
    Ok(())
}

fn validate_pre_slice_inventory(
    root: &File,
    identities: RoleIdentities,
    profile: DeploymentProfile,
) -> Result<bool, ()> {
    let actual = directory_names(root, 7)?;
    let required = [DATABASE, RECEIPTS, RUNNER]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    let mut allowed = required.clone();
    allowed.insert("sandbox.sqlite3-journal".into());
    allowed.insert(STATE_LOCK.into());
    allowed.insert(DEPLOYMENT.into());
    allowed.insert(READY.into());
    if !required.is_subset(&actual)
        || !actual.is_subset(&allowed)
        || (actual.contains(std::ffi::OsStr::new(READY))
            && !actual.contains(std::ffi::OsStr::new(DEPLOYMENT)))
    {
        return Err(());
    }
    open_fixed_file_at(
        root,
        DATABASE,
        identities.controller_uid,
        identities.controller_gid,
        0o600,
        false,
    )?;
    if actual.contains(std::ffi::OsStr::new("sandbox.sqlite3-journal")) {
        open_fixed_file_at(
            root,
            "sandbox.sqlite3-journal",
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            false,
        )?;
    }
    if actual.contains(std::ffi::OsStr::new(DEPLOYMENT)) {
        validate_deployment_at(
            root,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
    }
    if actual.contains(std::ffi::OsStr::new(READY)) {
        validate_ready_at(
            root,
            identities.controller_uid,
            identities.controller_gid,
            profile,
        )?;
    }
    let receipts = open_fixed_directory_at(
        root,
        RECEIPTS,
        identities.controller_uid,
        identities.controller_gid,
        0o700,
    )?;
    validate_receipts(&receipts, identities)?;
    let runner = open_fixed_directory_at(
        root,
        RUNNER,
        identities.controller_uid,
        identities.controller_gid,
        0o700,
    )?;
    if !directory_names(&runner, 1)?.is_empty() {
        return Err(());
    }
    Ok(actual.contains(std::ffi::OsStr::new(STATE_LOCK)))
}

fn create_directory_at(
    parent: &File,
    name: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<File, ()> {
    rustix::fs::mkdirat(
        parent,
        name,
        Mode::from_raw_mode(u16::try_from(mode).map_err(|_| ())?),
    )
    .map_err(|_| ())?;
    open_fixed_directory_at(parent, name, uid, gid, mode)
}

fn create_file_at(parent: &File, name: &str, uid: u32, gid: u32, mode: u32) -> Result<File, ()> {
    let file = File::from(
        openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(u16::try_from(mode).map_err(|_| ())?),
        )
        .map_err(|_| ())?,
    );
    file.sync_all().map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        return Err(());
    }
    Ok(file)
}

fn write_canonical_at(
    parent: &File,
    name: &str,
    value: &impl Serialize,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(u16::try_from(mode).map_err(|_| ())?),
        )
        .map_err(|_| ())?,
    );
    file.write_all(&bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        return Err(());
    }
    Ok(())
}

fn remove_recoverable_tree(
    parent: &File,
    name: &std::ffi::OsStr,
    identities: RoleIdentities,
) -> Result<(), ()> {
    let directory = open_fixed_directory_at(
        parent,
        name,
        identities.controller_uid,
        identities.controller_gid,
        0o700,
    )?;
    let mut count = 0;
    remove_tree_contents(&directory, identities, 0, &mut count)?;
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR).map_err(|_| ())
}

fn remove_tree_contents(
    directory: &File,
    identities: RoleIdentities,
    depth: u8,
    count: &mut usize,
) -> Result<(), ()> {
    if depth > 8 {
        return Err(());
    }
    for name in directory_names(directory, 4_112)? {
        *count = count.checked_add(1).ok_or(())?;
        if *count > 4_112 {
            return Err(());
        }
        match openat(
            directory,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                let child = File::from(descriptor);
                validate_directory_file(
                    &child,
                    identities.controller_uid,
                    identities.controller_gid,
                    0o700,
                )?;
                remove_tree_contents(&child, identities, depth + 1, count)?;
                rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::REMOVEDIR)
                    .map_err(|_| ())?;
            },
            Err(rustix::io::Errno::NOTDIR) => {
                let child = File::from(
                    openat(
                        directory,
                        &name,
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|_| ())?,
                );
                let metadata = child.metadata().map_err(|_| ())?;
                if !metadata.is_file()
                    || metadata.uid() != identities.controller_uid
                    || metadata.gid() != identities.controller_gid
                    || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
                    || metadata.nlink() != 1
                {
                    return Err(());
                }
                rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty())
                    .map_err(|_| ())?;
            },
            Err(_) => return Err(()),
        }
    }
    directory.sync_all().map_err(|_| ())
}

fn sync_tree(directory: &File, depth: u8) -> Result<(), ()> {
    if depth > 8 {
        return Err(());
    }
    for name in directory_names(directory, 4_112)? {
        match openat(
            directory,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => sync_tree(&File::from(descriptor), depth + 1)?,
            Err(rustix::io::Errno::NOTDIR) => {
                File::from(
                    openat(
                        directory,
                        &name,
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|_| ())?,
                )
                .sync_all()
                .map_err(|_| ())?;
            },
            Err(_) => return Err(()),
        }
    }
    directory.sync_all().map_err(|_| ())
}

fn directory_names(directory: &File, maximum: usize) -> Result<BTreeSet<std::ffi::OsString>, ()> {
    let mut reopened = directory.try_clone().map_err(|_| ())?;
    reopened.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut names = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(&reopened).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if names.len() == maximum {
            return Err(());
        }
        names.insert(std::ffi::OsString::from(name.to_str().map_err(|_| ())?));
    }
    Ok(names)
}

fn validate_parent_inventory_at(parent: &File, root_name: &std::ffi::OsStr) -> Result<(), ()> {
    let actual = directory_names(parent, 2)?;
    let expected = [PARENT_LOCK.as_ref(), root_name]
        .into_iter()
        .map(std::ffi::OsStr::to_owned)
        .collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_inventory_at(
    root: &File,
    identities: RoleIdentities,
) -> Result<(File, File, File), ()> {
    let actual = directory_names(root, 7)?;
    let required = [DATABASE, RECEIPTS, RUNNER, DEPLOYMENT, STATE_LOCK, READY]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    let mut allowed = required.clone();
    allowed.insert("sandbox.sqlite3-journal".into());
    if !required.is_subset(&actual)
        || !actual.is_subset(&allowed)
        || actual.contains(std::ffi::OsStr::new(INCOMPLETE))
    {
        return Err(());
    }
    let database = open_fixed_file_at(
        root,
        DATABASE,
        identities.controller_uid,
        identities.controller_gid,
        0o600,
        false,
    )?;
    open_fixed_file_at(
        root,
        DEPLOYMENT,
        identities.controller_uid,
        identities.controller_gid,
        0o400,
        false,
    )?;
    open_fixed_file_at(
        root,
        READY,
        identities.controller_uid,
        identities.controller_gid,
        0o600,
        false,
    )?;
    if actual.contains(std::ffi::OsStr::new("sandbox.sqlite3-journal")) {
        open_fixed_file_at(
            root,
            "sandbox.sqlite3-journal",
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            false,
        )?;
    }
    let receipts = open_fixed_directory_at(
        root,
        RECEIPTS,
        identities.controller_uid,
        identities.controller_gid,
        0o700,
    )?;
    validate_receipts(&receipts, identities)?;
    let runner = open_fixed_directory_at(
        root,
        RUNNER,
        identities.controller_uid,
        identities.controller_gid,
        0o700,
    )?;
    crate::runner_host::validate_state_root_inventory(
        &runner,
        identities.controller_uid,
        identities.controller_gid,
        identities.runner_uid,
        identities.runner_gid,
    )
    .map_err(|_| ())?;
    let mut runner_entries = 0;
    let mut runner_bytes = 0;
    validate_runner_tree(
        &runner,
        identities,
        0,
        &mut runner_entries,
        &mut runner_bytes,
    )?;
    Ok((database, receipts, runner))
}

fn validate_receipts(directory: &File, identities: RoleIdentities) -> Result<(), ()> {
    let names = directory_names(directory, 4_096)?;
    let mut total = 0_u64;
    for name in names {
        let name = name.to_str().ok_or(())?;
        if !valid_receipt_name(name) {
            return Err(());
        }
        let file = open_fixed_file_at(
            directory,
            name,
            identities.controller_uid,
            identities.controller_gid,
            0o600,
            false,
        )?;
        let length = file.metadata().map_err(|_| ())?.len();
        if length > 16 * 1024 {
            return Err(());
        }
        let bytes = read_descriptor_bounded(&file, 16 * 1024)?;
        if hex(&Sha256::digest(&bytes)) != receipt_digest(name).ok_or(())? {
            return Err(());
        }
        total = total.checked_add(length).ok_or(())?;
        if total > 64 * 1024 * 1024 {
            return Err(());
        }
    }
    Ok(())
}

fn receipt_digest(name: &str) -> Option<&str> {
    let body = if let Some((body, suffix)) = name
        .strip_prefix(".sandbox-")
        .and_then(|value| value.split_once(".receipt.pending-"))
    {
        if suffix.len() != 16 || !suffix.bytes().all(lower_hex) {
            return None;
        }
        body
    } else {
        name.strip_prefix("sandbox-")
            .and_then(|value| value.strip_suffix(".receipt"))?
    };
    let (run_id, digest) = body.split_once('-')?;
    (run_id.len() == 32
        && digest.len() == 64
        && run_id.bytes().all(lower_hex)
        && digest.bytes().all(lower_hex))
    .then_some(digest)
}

fn valid_receipt_name(name: &str) -> bool {
    receipt_digest(name).is_some()
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn validate_runner_tree(
    directory: &File,
    identities: RoleIdentities,
    depth: u8,
    count: &mut usize,
    bytes: &mut u64,
) -> Result<(), ()> {
    if depth > 8 {
        return Err(());
    }
    for name in directory_names(directory, if depth == 0 { 4 } else { 4_096 })? {
        *count = count.checked_add(1).ok_or(())?;
        if *count > 4_096 {
            return Err(());
        }
        let name = name.to_str().ok_or(())?;
        if !valid_runner_tree_name(depth, name) {
            return Err(());
        }
        match openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                let child = File::from(descriptor);
                validate_runner_owner(&child, identities, true)?;
                validate_runner_tree(&child, identities, depth + 1, count, bytes)?;
            },
            Err(rustix::io::Errno::NOTDIR) => {
                let child = File::from(
                    openat(
                        directory,
                        name,
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|_| ())?,
                );
                validate_runner_owner(&child, identities, false)?;
                let metadata = child.metadata().map_err(|_| ())?;
                *bytes = bytes.checked_add(metadata.len()).ok_or(())?;
                if *bytes > 64 * 1024 * 1024 {
                    return Err(());
                }
            },
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

fn valid_runner_tree_name(depth: u8, name: &str) -> bool {
    match depth {
        0 => {
            name == "runner-generation.json"
                || name == ".runner-generation.tmp"
                || name.strip_prefix("generation-").is_some_and(|generation| {
                    generation.len() == 20
                        && generation.bytes().all(|byte| byte.is_ascii_digit())
                        && generation != "00000000000000000000"
                })
        },
        1 => name == "run",
        2 => matches!(
            name,
            "gateway.sqlite3"
                | "gateway.sqlite3-journal"
                | "gateway.sqlite3.kap0038-worker.lock"
                | "receipt-outbox"
        ),
        3 => name == "receipt",
        _ => false,
    }
}

fn read_descriptor_bounded(file: &File, maximum: u64) -> Result<Vec<u8>, ()> {
    let mut file = file.try_clone().map_err(|_| ())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if u64::try_from(bytes.len()).map_err(|_| ())? > maximum {
        return Err(());
    }
    Ok(bytes)
}

fn validate_runner_owner(
    file: &File,
    identities: RoleIdentities,
    directory: bool,
) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    let valid_owner = (metadata.uid() == identities.controller_uid
        && metadata.gid() == identities.controller_gid)
        || (metadata.uid() == identities.runner_uid && metadata.gid() == identities.runner_gid);
    let mode = metadata.mode() & 0o7777;
    let valid_mode = if directory {
        metadata.is_dir() && matches!(mode, 0o500 | 0o700)
    } else {
        metadata.is_file() && metadata.nlink() == 1 && matches!(mode, 0o400 | 0o600)
    };
    if valid_owner && valid_mode {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_deployment_at(
    root: &File,
    uid: u32,
    gid: u32,
    profile: DeploymentProfile,
) -> Result<(), ()> {
    open_deployment_snapshot_at(root, uid, gid, profile).map(|_| ())
}

fn open_deployment_snapshot_at(
    root: &File,
    uid: u32,
    gid: u32,
    profile: DeploymentProfile,
) -> Result<(File, DeploymentSnapshot), ()> {
    let file = open_fixed_file_at(root, DEPLOYMENT, uid, gid, 0o400, false)?;
    let snapshot = deployment_snapshot_from_file(&file, profile)?;
    Ok((file, snapshot))
}

fn deployment_snapshot_from_file(
    file: &File,
    profile: DeploymentProfile,
) -> Result<DeploymentSnapshot, ()> {
    let bytes = read_descriptor_bounded(file, JSON_MAX)?;
    let stored: DeploymentRecord = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let expected = deployment_record(profile)?;
    if serde_json::to_vec(&stored).map_err(|_| ())? != bytes
        || serde_json::to_vec(&expected).map_err(|_| ())? != bytes
    {
        return Err(());
    }
    Ok(DeploymentSnapshot {
        bytes,
        identity: DeploymentIdentity {
            compatibility_sha256: stored.compatibility_sha256,
            package_version: stored.package_version,
            target: stored.target,
            service_schema_sha256: stored.service_schema_sha256,
            gateway_schema_sha256: stored.gateway_schema_sha256,
            staging_schema: stored.staging_schema,
            policy: stored.policy,
            pre_exec_source_sha256: stored.pre_exec_source_sha256,
            pre_exec_compiler: stored.pre_exec_compiler,
            pre_exec_helper_sha256: stored.pre_exec_helper_sha256,
            runner_sha256: stored.runner_sha256,
        },
    })
}

fn validate_ready_at(
    root: &File,
    uid: u32,
    gid: u32,
    profile: DeploymentProfile,
) -> Result<(), ()> {
    open_ready_at(root, uid, gid, profile).map(|_| ())
}

fn open_ready_at(root: &File, uid: u32, gid: u32, profile: DeploymentProfile) -> Result<File, ()> {
    let file = open_fixed_file_at(root, READY, uid, gid, 0o600, false)?;
    validate_ready_file(&file, profile)?;
    Ok(file)
}

fn validate_ready_file(file: &File, profile: DeploymentProfile) -> Result<(), ()> {
    let bytes = read_descriptor_bounded(file, 1024)?;
    let stored: ReadyRecord = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if serde_json::to_vec(&stored).map_err(|_| ())? != bytes
        || stored.schema != "kapsel.sandbox.restore-ready.v1"
        || stored.compatibility_sha256 != deployment_record(profile)?.compatibility_sha256
        || stored.completed_at <= 0
    {
        return Err(());
    }
    match stored.source.as_str() {
        "initialized" if stored.generation.is_none() && stored.manifest_sha256.is_none() => Ok(()),
        "restored"
            if stored.generation.is_some_and(|generation| generation > 0)
                && stored.manifest_sha256.as_deref().is_some_and(valid_digest) =>
        {
            Ok(())
        },
        _ => Err(()),
    }
}

fn open_fixed_directory_path(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<File, ()> {
    let directory = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory_file(&directory, uid, gid, mode)?;
    Ok(directory)
}

fn open_fixed_directory_at(
    parent: &File,
    name: impl rustix::path::Arg,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<File, ()> {
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory_file(&directory, uid, gid, mode)?;
    Ok(directory)
}

fn validate_directory_file(file: &File, uid: u32, gid: u32, mode: u32) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == mode
    {
        Ok(())
    } else {
        Err(())
    }
}

fn open_fixed_file_at(
    directory: &File,
    name: impl rustix::path::Arg,
    uid: u32,
    gid: u32,
    mode: u32,
    writable: bool,
) -> Result<File, ()> {
    let flags = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    } | OFlags::CLOEXEC
        | OFlags::NOFOLLOW;
    let file = File::from(openat(directory, name, flags, Mode::empty()).map_err(|_| ())?);
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        return Err(());
    }
    Ok(file)
}

fn require_same(left: &File, right: &File) -> Result<(), ()> {
    if ObjectIdentity::of(left)? == ObjectIdentity::of(right)? {
        Ok(())
    } else {
        Err(())
    }
}

fn require_absolute(path: &Path) -> Result<(), ()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(())
    }
}
fn target_identity(profile: DeploymentProfile) -> Result<&'static str, ()> {
    match profile {
        DeploymentProfile::Production if cfg!(all(target_arch = "x86_64", target_os = "linux")) => {
            Ok("x86_64-linux")
        },
        DeploymentProfile::Production => Err(()),
        #[cfg(any(test, feature = "state-root-test-harness"))]
        DeploymentProfile::Test => Ok("test-architecture"),
    }
}

fn open_identity_file(path: &Path, no_follow: bool) -> Result<File, ()> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC;
    if no_follow {
        flags |= OFlags::NOFOLLOW;
    }
    let file = File::from(open(path, flags, Mode::empty()).map_err(|_| ())?);
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o6000 != 0 {
        return Err(());
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_runner_identity() -> Result<File, ()> {
    open_identity_file(Path::new("/proc/self/exe"), false)
}

#[cfg(not(target_os = "linux"))]
fn open_runner_identity() -> Result<File, ()> {
    open_identity_file(&std::env::current_exe().map_err(|_| ())?, true)
}

fn digest_file(mut file: File) -> Result<String, ()> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    };

    use super::*;

    fn fixture(name: &str) -> (PathBuf, RoleIdentities) {
        let parent = std::env::temp_dir().join(format!(
            "kapsel-state-root-unit-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = parent.join(PARENT_LOCK);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock)
            .unwrap();
        (parent, RoleIdentities::test_controller())
    }

    fn initialized(name: &str) -> (PathBuf, RoleIdentities) {
        let (parent, identities) = fixture(name);
        let root = parent.join("state");
        let authority = AuthorityConfiguration::new(
            parent.join("unopened-authority"),
            identities.controller_uid,
            identities.controller_gid,
            identities.staging_uid,
            identities.staging_gid,
        );
        let initializer =
            StateInitializer::begin(&root, identities, &authority, DeploymentProfile::Test)
                .unwrap();
        let database = initializer.database().unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)
            .unwrap();
        initializer.publish(1_774_051_200).unwrap();
        let connection = rusqlite::Connection::open(root.join(DATABASE)).unwrap();
        for ddl in service_schema::TABLES_BY_NAME {
            connection.execute_batch(ddl).unwrap();
        }
        connection
            .execute(
                concat!(
                    "INSERT INTO service_state (singleton, stopped, ",
                    "boundary_uid_digest) VALUES (1, 1, '')"
                ),
                [],
            )
            .unwrap();
        drop(connection);
        (root, identities)
    }

    #[test]
    fn production_role_identity_is_closed() {
        let identities = RoleIdentities::production();
        assert_eq!(
            (
                identities.controller_uid,
                identities.controller_gid,
                identities.staging_uid,
                identities.staging_gid,
                identities.runner_uid,
                identities.runner_gid,
            ),
            (65_530, 65_530, 65_531, 65_531, 65_532, 65_532)
        );
    }

    #[test]
    fn state_root_rejects_untyped_runner_generation_record() {
        let (root, identities) = initialized("runner-record");
        let record = root.join("runner/runner-generation.json");
        fs::write(&record, b"{}").unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(StateGuard::open(&root, identities, DeploymentProfile::Test).is_err());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_is_exclusive_and_pins_deployment() {
        let (root, identities) = initialized("clean-backup-snapshot");
        Service::preflight_clean_backup_source(&root.join(DATABASE)).unwrap();
        let ordinary = StateGuard::open(&root, identities, DeploymentProfile::Test).unwrap();
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        drop(ordinary);

        let backup =
            BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).unwrap();
        assert!(StateGuard::open(&root, identities, DeploymentProfile::Test).is_err());
        let deployment = backup.deployment_snapshot().unwrap();
        assert_eq!(deployment.bytes, fs::read(root.join(DEPLOYMENT)).unwrap());
        assert_eq!(deployment.identity.target, "test-architecture");
        assert!(valid_digest(&deployment.identity.compatibility_sha256));

        let original = root.join("original-deployment.json");
        fs::rename(root.join(DEPLOYMENT), &original).unwrap();
        fs::copy(&original, root.join(DEPLOYMENT)).unwrap();
        fs::set_permissions(root.join(DEPLOYMENT), fs::Permissions::from_mode(0o400)).unwrap();
        assert!(backup.verify().is_err());
        drop(backup);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_rejects_unsupported_files_without_mutation() {
        let (root, identities) = initialized("clean-backup-preflight");
        let database = root.join(DATABASE);
        let original_database = fs::read(&database).unwrap();

        let journal = root.join("sandbox.sqlite3-journal");
        fs::write(&journal, b"unsupported journal").unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        assert_eq!(fs::read(&database).unwrap(), original_database);
        fs::remove_file(journal).unwrap();

        let receipt_bytes = b"unsupported receipt";
        let receipt_digest = hex(&Sha256::digest(receipt_bytes));
        let receipt = root.join(RECEIPTS).join(format!(
            "sandbox-{}-{receipt_digest}.receipt",
            "a".repeat(32)
        ));
        fs::write(&receipt, receipt_bytes).unwrap();
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        assert_eq!(fs::read(&database).unwrap(), original_database);
        fs::remove_file(receipt).unwrap();

        let runner_record = root.join(RUNNER).join("runner-generation.json");
        fs::write(&runner_record, b"{}").unwrap();
        fs::set_permissions(&runner_record, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        assert_eq!(fs::read(&database).unwrap(), original_database);
        fs::remove_file(runner_record).unwrap();
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_rejects_unsupported_service_state() {
        let (root, identities) = initialized("clean-backup-service-state");
        let database = root.join(DATABASE);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("UPDATE service_state SET stopped = 0", [])
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT stopped FROM service_state", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        connection
            .execute(
                "UPDATE service_state SET stopped = 1, boundary_uid_digest = 'owned'",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("UPDATE service_state SET boundary_uid_digest = ''", [])
            .unwrap();
        connection
            .execute(
                concat!(
                    "INSERT INTO runs (run_id, idempotency_key, scenario, operation_id, ",
                    "admitted_at, expires_at, execution_state, receipt_available, cleanup_state, ",
                    "last_sequence, active, deadline_emitted, application_invoked, ",
                    "public_retained, policy_revision, policy_inventory, ",
                    "policy_inventory_digest, cleanup_identity, deadline_seconds, deadline_at, ",
                    "policy_verified, cleanup_resource_state, lease_id, lease_epoch, ",
                    "lease_expires_at, handoff_credential_verifier) VALUES ",
                    "('run', 'key', 'healthy', 'operation', 1, 2, 'queued', 0, 'pending', ",
                    "1, 0, 0, 0, 1, 'policy', 'inventory', 'digest', 'cleanup', 180, NULL, ",
                    "0, 'unverified', '', 0, 0, X'')"
                ),
                [],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute("DELETE FROM runs", []).unwrap();
        connection
            .execute(
                "INSERT INTO receipt_publications VALUES ('run', 'digest', 'object', 1)",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("DELETE FROM receipt_publications", [])
            .unwrap();
        drop(connection);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_rejects_unsupported_backup_owners() {
        let (root, identities) = initialized("clean-backup-owners");
        let database = root.join(DATABASE);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute(
                "INSERT INTO cleanup_records VALUES ('run', 'cleanup', NULL, 'unverified', \
                 'pending', 1, 0, NULL, 0)",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("DELETE FROM cleanup_records", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_collection VALUES (1, 1, ?1)",
                ["a".repeat(64)],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM authority_collection", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            1
        );
        connection
            .execute("DELETE FROM authority_collection", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO backup_generations VALUES ('pending', 1, NULL, 'pending', 1)",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);

        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_rejects_extra_schema_objects() {
        let (root, identities) = initialized("clean-backup-schema");
        let database = root.join(DATABASE);
        let connection = rusqlite::Connection::open(database).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER unexpected_backup_trigger AFTER INSERT ON backup_generations \
                 BEGIN UPDATE service_state SET stopped = 0 WHERE singleton = 1; END;",
            )
            .unwrap();
        drop(connection);

        assert!(BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).is_err());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn clean_backup_snapshot_rejects_pinned_component_substitution() {
        let (root, identities) = initialized("clean-backup-components");
        let backup =
            BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).unwrap();

        for (name, mode) in [(DATABASE, 0o600), (READY, 0o600)] {
            let original = root.join(format!("original-{name}"));
            fs::rename(root.join(name), &original).unwrap();
            fs::copy(&original, root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(mode)).unwrap();
            assert!(backup.verify().is_err());
            fs::remove_file(root.join(name)).unwrap();
            fs::rename(original, root.join(name)).unwrap();
            assert!(backup.verify().is_ok());
        }
        for name in [RECEIPTS, RUNNER] {
            let original = root.join(format!("original-{name}"));
            fs::rename(root.join(name), &original).unwrap();
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(backup.verify().is_err());
            fs::remove_dir(root.join(name)).unwrap();
            fs::rename(original, root.join(name)).unwrap();
            assert!(backup.verify().is_ok());
        }

        let competing_parent_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.parent().unwrap().join(PARENT_LOCK))
            .unwrap();
        assert!(flock(
            &competing_parent_lock,
            FlockOperation::NonBlockingLockExclusive
        )
        .is_err());

        let moved = root.with_file_name("moved-clean-backup-components");
        fs::rename(&root, &moved).unwrap();
        symlink(&moved, &root).unwrap();
        assert!(backup.verify().is_err());
        fs::remove_file(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        assert!(backup.verify().is_ok());
        drop(backup);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    fn set_stopped(root: &Path, stopped: bool) {
        let connection = rusqlite::Connection::open(root.join(DATABASE)).unwrap();
        connection
            .execute(
                "UPDATE service_state SET stopped = ?1",
                [i64::from(stopped)],
            )
            .unwrap();
    }

    #[test]
    fn pinned_stopped_backup_service_reopens_pending_and_crosses_closed_states() {
        let (root, identities) = initialized("stopped-backup-reopen");
        let authority_parent = std::env::temp_dir().join(format!(
            "kapsel-state-root-authority-{}-stopped-backup-reopen",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&authority_parent);
        fs::create_dir(&authority_parent).unwrap();
        fs::set_permissions(&authority_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = crate::test_authority::configuration(&authority_parent, [7; 32]);

        let guard =
            BackupStateGuard::open_clean(&root, identities, DeploymentProfile::Test).unwrap();
        let service = guard.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        drop(guard);

        let guard =
            BackupStateGuard::open_capture(&root, identities, DeploymentProfile::Test).unwrap();
        let service = guard.open_stopped_service(&authority).unwrap();
        assert_eq!(service.resume_pending().unwrap(), pending);
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Pending(pending)
        );
        assert!(StateGuard::open(&root, identities, DeploymentProfile::Test).is_err());
        set_stopped(&root, false);
        assert!(service.finish_publication(1, &"a".repeat(64)).is_err());
        set_stopped(&root, true);
        service.finish_publication(1, &"a".repeat(64)).unwrap();
        let current_one = crate::PublishedBackup {
            generation: 1,
            captured_at: 1_774_051_201,
            manifest_digest: "a".repeat(64),
            authorities: Vec::new(),
        };
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Current(current_one.clone())
        );
        let second = service.begin_publication(2, 1_774_051_202).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Replacing {
                current: current_one.clone(),
                pending: second.clone(),
            }
        );
        drop(service);
        drop(guard);

        let guard =
            BackupStateGuard::open_capture(&root, identities, DeploymentProfile::Test).unwrap();
        let service = guard.open_stopped_service(&authority).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Replacing {
                current: current_one.clone(),
                pending: second,
            }
        );
        set_stopped(&root, false);
        assert!(service.finish_publication(2, &"b".repeat(64)).is_err());
        set_stopped(&root, true);
        service.finish_publication(2, &"b".repeat(64)).unwrap();
        let current_two = crate::PublishedBackup {
            generation: 2,
            captured_at: 1_774_051_202,
            manifest_digest: "b".repeat(64),
            authorities: Vec::new(),
        };
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Deleting {
                current: current_two.clone(),
                deleting: current_one.clone(),
            }
        );
        drop(service);
        drop(guard);

        let guard =
            BackupStateGuard::open_capture(&root, identities, DeploymentProfile::Test).unwrap();
        let service = guard.open_stopped_service(&authority).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Deleting {
                current: current_two.clone(),
                deleting: current_one,
            }
        );
        set_stopped(&root, false);
        assert!(service.finish_deletion(1).is_err());
        set_stopped(&root, true);
        service.finish_deletion(1).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            crate::BackupPublicationState::Current(current_two)
        );
        drop(service);
        drop(guard);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
        crate::test_authority::remove_root(&authority_parent);
    }

    #[test]
    fn pinned_state_rejects_root_and_database_path_substitution() {
        let (root, identities) = initialized("substitution");
        let guard = StateGuard::open(&root, identities, DeploymentProfile::Test).unwrap();
        let moved = root.with_file_name("moved-state");
        fs::rename(&root, &moved).unwrap();
        symlink(&moved, &root).unwrap();
        assert!(guard.verify().is_err());
        fs::remove_file(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        let database = root.join(DATABASE);
        let original = root.join("original.sqlite3");
        fs::rename(&database, &original).unwrap();
        fs::copy(&original, &database).unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(guard.verify().is_err());
        drop(guard);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }
}
