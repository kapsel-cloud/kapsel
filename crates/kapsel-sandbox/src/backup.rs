//! Descriptor-pinned backup-root inventory and complete clean-generation validation.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use rustix::fs::{fchmod, flock, mkdirat, open, openat, renameat, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    state_root::{BackupStateGuard, DeploymentSnapshot},
    AuthorityConfiguration, BackupPublication, BackupPublicationState, ExpiryTransactionBarrier,
    Service,
};

const BACKUP_ID: u32 = 65_529;
const LOCK: &str = ".backup.lock";
const PARENT_RESTORE_LOCK: &str = ".kapsel-sandbox-restore.lock";
const RESTORE_TEMPORARY: &str = ".kapsel-sandbox-restore.tmp";
const RESTORE_INCOMPLETE: &str = "restore.incomplete";
const RESTORE_READY: &str = "restore.ready";
const RESTORE_STATE_TEMPORARY: &str = "restore.state.tmp";
const GENERATIONS: &str = "generations";
const DEPLOYMENT: &str = "deployment.json";
const MANIFEST: &str = "manifest.json";
const CURRENT: &str = "current";
const CURRENT_TMP: &str = ".current.tmp";
const GENERATION_TMP: &str = ".generation-00000000000000000001.tmp";
const GENERATION_ONE: &str = "backup-00000000000000000001";
const DATABASE: &str = "sandbox.sqlite3";
const DATABASE_MAX: u64 = 64 * 1024 * 1024;
const JSON_MAX: u64 = 256 * 1024;
const GENERATION_MAX: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(file: &File) -> Result<Self, ()> {
        let metadata = file.metadata().map_err(|_| ())?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BackupIdentity {
    uid: u32,
    gid: u32,
}

impl BackupIdentity {
    #[allow(
        dead_code,
        reason = "the shipped backup command follows this foundation"
    )]
    pub(crate) fn production(uid: u32, gid: u32) -> Result<Self, ()> {
        if uid == BACKUP_ID && gid == BACKUP_ID {
            Ok(Self { uid, gid })
        } else {
            Err(())
        }
    }

    #[cfg(test)]
    fn current_process() -> Self {
        Self {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }
}

/// Pins one backup root and holds its exclusive lock after the borrowed state guard's locks.
#[allow(
    dead_code,
    reason = "the generation publisher follows this accepted foundation"
)]
pub(crate) struct BackupRootGuard<'state> {
    state: &'state BackupStateGuard,
    name: OsString,
    identity: BackupIdentity,
    parent: File,
    root: File,
    lock: File,
    generations: File,
}

#[allow(
    dead_code,
    reason = "the generation publisher follows this accepted foundation"
)]
impl<'state> BackupRootGuard<'state> {
    /// Opens only the exact initial root. The lock is acquired before either inventory is read.
    pub(crate) fn open_initial(
        state: &'state BackupStateGuard,
        path: &Path,
        identity: BackupIdentity,
    ) -> Result<Self, ()> {
        state.verify()?;
        if !path.is_absolute() {
            return Err(());
        }
        let parent_path = path.parent().ok_or(())?;
        let name = path.file_name().ok_or(())?.to_owned();
        let parent = directory_path(parent_path, identity.uid, identity.gid, 0o700)?;
        let root = directory_at(&parent, &name, identity.uid, identity.gid, 0o700)?;
        let lock = file_at(&root, LOCK, identity.uid, identity.gid, 0o600, true, 0)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;

        let expected = [OsString::from(LOCK), OsString::from(GENERATIONS)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut selected = expected.clone();
        selected.insert(OsString::from(CURRENT));
        let mut publishing = expected.clone();
        publishing.insert(OsString::from(CURRENT_TMP));
        let root_names = names(&root, 4)?;
        if root_names != expected && root_names != selected && root_names != publishing {
            return Err(());
        }
        let generations = directory_at(&root, GENERATIONS, identity.uid, identity.gid, 0o700)?;
        let generation_names = names(&generations, 2)?;
        let empty = BTreeSet::new();
        let temporary = std::iter::once(OsString::from(GENERATION_TMP)).collect();
        let complete = std::iter::once(OsString::from(GENERATION_ONE)).collect();
        if generation_names != empty
            && generation_names != temporary
            && generation_names != complete
        {
            return Err(());
        }
        if generation_names.contains(std::ffi::OsStr::new(GENERATION_TMP)) {
            let temporary = directory_at_modes(
                &generations,
                GENERATION_TMP,
                identity.uid,
                identity.gid,
                &[0o700, 0o500],
            )?;
            let _ = names(&temporary, 7)?;
        }
        let guard = Self {
            state,
            name,
            identity,
            parent,
            root,
            lock,
            generations,
        };
        guard.verify_pins()?;
        Ok(guard)
    }

    fn verify_pins(&self) -> Result<(), ()> {
        self.state.verify()?;
        validate_directory(&self.parent, self.identity.uid, self.identity.gid, 0o700)?;
        let root = directory_at(
            &self.parent,
            &self.name,
            self.identity.uid,
            self.identity.gid,
            0o700,
        )?;
        same(&root, &self.root)?;
        let lock = file_at(
            &root,
            LOCK,
            self.identity.uid,
            self.identity.gid,
            0o600,
            true,
            0,
        )?;
        same(&lock, &self.lock)?;
        let generations = directory_at(
            &root,
            GENERATIONS,
            self.identity.uid,
            self.identity.gid,
            0o700,
        )?;
        same(&generations, &self.generations)?;
        Ok(())
    }

    fn verify_root_inventory(&self, selected: bool) -> Result<(), ()> {
        self.verify_pins()?;
        let mut expected = [OsString::from(LOCK), OsString::from(GENERATIONS)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if selected {
            expected.insert(OsString::from(CURRENT));
        }
        (names(&self.root, 4)? == expected).then_some(()).ok_or(())
    }

    fn verify_publishing_root_inventory(&self) -> Result<(), ()> {
        self.verify_pins()?;
        let expected = [LOCK, GENERATIONS, CURRENT_TMP]
            .into_iter()
            .map(OsString::from)
            .collect::<BTreeSet<_>>();
        (names(&self.root, 4)? == expected).then_some(()).ok_or(())
    }

    /// Reopens and validates the sole complete clean generation without publishing `current`.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed generation inventory and retained descriptor set stay visibly ordered"
    )]
    pub(crate) fn validate_clean_generation(
        &self,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        self.validate_generation(false)
    }

    pub(crate) fn validate_selected_clean_generation(
        &self,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        let current_file = file_at(
            &self.root,
            CURRENT,
            self.identity.uid,
            self.identity.gid,
            0o400,
            false,
            1024,
        )?;
        let current_bytes = read_bounded(&current_file, 1024)?;
        let current: CurrentRecord = serde_json::from_slice(&current_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&current).map_err(|_| ())? != current_bytes
            || current.schema != "kapsel.sandbox.backup.current.v1"
            || current.generation != 1
            || !valid_digest(&current.manifest_sha256)
        {
            return Err(());
        }
        let mut generation = self.validate_generation(true)?;
        if generation.manifest_sha256 != current.manifest_sha256 {
            return Err(());
        }
        generation.selected = true;
        generation.current_descriptor = Some(current_file);
        Ok(generation)
    }

    fn validate_generation(
        &self,
        selected: bool,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        self.validate_generation_named(GENERATION_ONE, selected, false)
    }

    fn validate_sealed_temporary(&self) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        self.validate_generation_named(GENERATION_TMP, false, false)
    }

    fn validate_generation_during_current_publication(
        &self,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        self.validate_generation_named(GENERATION_ONE, false, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed generation inventory and retained descriptor set stay visibly ordered"
    )]
    fn validate_generation_named(
        &self,
        generation_name: &str,
        selected: bool,
        current_temporary: bool,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        if current_temporary {
            self.verify_publishing_root_inventory()?;
        } else {
            self.verify_root_inventory(selected)?;
        }
        if names(&self.generations, 2)?
            != std::iter::once(OsString::from(generation_name)).collect()
        {
            return Err(());
        }
        let generation_number = if generation_name == GENERATION_TMP {
            1
        } else {
            generation_number(generation_name)?
        };
        if generation_number != 1 {
            return Err(());
        }
        let generation = directory_at(
            &self.generations,
            generation_name,
            self.identity.uid,
            self.identity.gid,
            0o500,
        )?;
        let expected = [
            DEPLOYMENT, MANIFEST, "receipts", "runner", "service", "trust",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if names(&generation, 7)? != expected {
            return Err(());
        }
        let service = directory_at(
            &generation,
            "service",
            self.identity.uid,
            self.identity.gid,
            0o500,
        )?;
        let receipts = directory_at(
            &generation,
            "receipts",
            self.identity.uid,
            self.identity.gid,
            0o500,
        )?;
        let runner = directory_at(
            &generation,
            "runner",
            self.identity.uid,
            self.identity.gid,
            0o500,
        )?;
        let trust = directory_at(
            &generation,
            "trust",
            self.identity.uid,
            self.identity.gid,
            0o500,
        )?;
        if names(&service, 2)? != std::iter::once(OsString::from(DATABASE)).collect()
            || !names(&receipts, 1)?.is_empty()
            || !names(&runner, 1)?.is_empty()
            || !names(&trust, 1)?.is_empty()
        {
            return Err(());
        }
        let database = file_at(
            &service,
            DATABASE,
            self.identity.uid,
            self.identity.gid,
            0o400,
            false,
            DATABASE_MAX,
        )?;
        let deployment = file_at(
            &generation,
            DEPLOYMENT,
            self.identity.uid,
            self.identity.gid,
            0o400,
            false,
            16 * 1024,
        )?;
        let manifest_file = file_at(
            &generation,
            MANIFEST,
            self.identity.uid,
            self.identity.gid,
            0o400,
            false,
            JSON_MAX,
        )?;
        let source_deployment = self.state.deployment_snapshot()?;
        if read_bounded(&deployment, 16 * 1024)? != source_deployment.bytes {
            return Err(());
        }
        let manifest_bytes = read_bounded(&manifest_file, JSON_MAX)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&manifest).map_err(|_| ())? != manifest_bytes {
            return Err(());
        }
        validate_manifest(
            &manifest,
            generation_number,
            &source_deployment,
            &deployment,
            &database,
        )?;
        let total = deployment
            .metadata()
            .map_err(|_| ())?
            .len()
            .checked_add(database.metadata().map_err(|_| ())?.len())
            .and_then(|value| value.checked_add(manifest_file.metadata().ok()?.len()))
            .ok_or(())?;
        if total > GENERATION_MAX {
            return Err(());
        }
        revalidate_generation(
            self,
            generation_name,
            &generation,
            &service,
            &receipts,
            &runner,
            &trust,
            &database,
            &deployment,
            &manifest_file,
            selected,
            current_temporary,
        )?;
        Ok(ValidatedCleanGeneration {
            generation: generation_number,
            captured_at: manifest.captured_at,
            manifest_sha256: digest_bytes(&manifest_bytes),
            compatibility_sha256: manifest.compatibility_sha256,
            name: generation_name.to_owned(),
            guard: self,
            generation_descriptor: generation,
            service_descriptor: service,
            receipts_descriptor: receipts,
            runner_descriptor: runner,
            trust_descriptor: trust,
            database_descriptor: database,
            deployment_descriptor: deployment,
            manifest_descriptor: manifest_file,
            selected,
            current_descriptor: None,
        })
    }

    fn publish_initial_current(&self) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        let unselected = self.validate_clean_generation()?;
        let current = CurrentRecord {
            schema: "kapsel.sandbox.backup.current.v1".to_owned(),
            generation: 1,
            manifest_sha256: unselected.manifest_sha256.clone(),
        };
        drop(unselected);
        let current_file = write_new_file(
            &self.root,
            CURRENT_TMP,
            &serde_json::to_vec(&current).map_err(|_| ())?,
            self.identity,
            1024,
        )?;
        fchmod(&current_file, Mode::from_raw_mode(0o400)).map_err(|_| ())?;
        validate_file(&current_file, self.identity, 0o400, 1024)?;
        current_file.sync_all().map_err(|_| ())?;
        renameat(&self.root, CURRENT_TMP, &self.root, CURRENT).map_err(|_| ())?;
        self.root.sync_all().map_err(|_| ())?;
        self.validate_selected_clean_generation()
    }

    fn finish_initial_p2<'guard, F>(
        &'guard self,
        authority: &AuthorityConfiguration,
        pending: &crate::BackupPublication,
        selected: ValidatedCleanGeneration<'guard, 'state>,
        before_p2: F,
    ) -> Result<ValidatedCleanGeneration<'guard, 'state>, ()>
    where
        F: FnOnce() -> Result<bool, ()>,
    {
        if selected.generation != pending.generation || selected.captured_at != pending.captured_at
        {
            return Err(());
        }
        let _ = before_p2()?;
        selected.verify()?;
        let service = self.state.open_stopped_service(authority).map_err(|_| ())?;
        if service.resume_pending().map_err(|_| ())? != *pending
            || service
                .finish_publication(1, &selected.manifest_sha256)
                .map_err(|_| ())?
                .is_some()
        {
            return Err(());
        }
        match service.publication_state().map_err(|_| ())? {
            BackupPublicationState::Current(current)
                if current.generation == 1
                    && current.captured_at == pending.captured_at
                    && current.manifest_digest == selected.manifest_sha256
                    && current.authorities.is_empty() => {},
            _ => return Err(()),
        }
        drop(service);
        Ok(selected)
    }

    pub(crate) fn capture_initial_clean(
        &self,
        authority: &AuthorityConfiguration,
        captured_at: i64,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()> {
        self.capture_initial_clean_with_barrier(authority, captured_at, || Ok(false))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the initial P1-filesystem-P2 durability order remains explicit"
    )]
    fn capture_initial_clean_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        captured_at: i64,
        before_p2: F,
    ) -> Result<ValidatedCleanGeneration<'_, 'state>, ()>
    where
        F: FnOnce() -> Result<bool, ()>,
    {
        self.verify_pins()?;
        let root_names = names(&self.root, 4)?;
        let initial_root = [OsString::from(LOCK), OsString::from(GENERATIONS)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut selected_root = initial_root.clone();
        selected_root.insert(OsString::from(CURRENT));
        let mut publishing_root = initial_root.clone();
        publishing_root.insert(OsString::from(CURRENT_TMP));
        if root_names != initial_root
            && root_names != selected_root
            && root_names != publishing_root
        {
            return Err(());
        }
        let generation_names = names(&self.generations, 2)?;
        let service = self.state.open_stopped_service(authority).map_err(|_| ())?;
        let publication_state = service.publication_state().map_err(|_| ())?;
        if let BackupPublicationState::Current(current) = publication_state {
            drop(service);
            if root_names != selected_root
                || current.generation != 1
                || current.captured_at <= 0
                || !current.authorities.is_empty()
            {
                return Err(());
            }
            let selected = self.validate_selected_clean_generation()?;
            let generation_matches = selected.generation == current.generation;
            let capture_matches = selected.captured_at == current.captured_at;
            let digest_matches = selected.manifest_sha256 == current.manifest_digest;
            if !generation_matches || !capture_matches || !digest_matches {
                return Err(());
            }
            return Ok(selected);
        }
        let pending = match publication_state {
            BackupPublicationState::Empty => {
                if captured_at <= 0 || root_names != initial_root || !generation_names.is_empty() {
                    return Err(());
                }
                service.begin_publication(1, captured_at).map_err(|_| ())?
            },
            BackupPublicationState::Pending(pending) => {
                let resumed = service.resume_pending().map_err(|_| ())?;
                (resumed == pending).then_some(resumed).ok_or(())?
            },
            _ => return Err(()),
        };
        if pending.generation != 1
            || pending.captured_at <= 0
            || pending.predecessor.is_some()
            || !pending.authorities.is_empty()
        {
            return Err(());
        }
        drop(service);
        let captured_at = pending.captured_at;

        if root_names == selected_root {
            let selected = self.validate_selected_clean_generation()?;
            self.root.sync_all().map_err(|_| ())?;
            return self.finish_initial_p2(authority, &pending, selected, before_p2);
        }
        if root_names == publishing_root {
            let generation = self.validate_generation_during_current_publication()?;
            let current_file = file_at_modes(
                &self.root,
                CURRENT_TMP,
                self.identity,
                &[0o600, 0o400],
                1024,
            )?;
            let expected_current = CurrentRecord {
                schema: "kapsel.sandbox.backup.current.v1".to_owned(),
                generation: generation.generation,
                manifest_sha256: generation.manifest_sha256.clone(),
            };
            let expected_bytes = serde_json::to_vec(&expected_current).map_err(|_| ())?;
            let current_bytes = read_bounded(&current_file, 1024)?;
            let current_mode = current_file.metadata().map_err(|_| ())?.mode() & 0o7777;
            if generation.captured_at != pending.captured_at {
                return Err(());
            }
            if current_bytes != expected_bytes {
                if current_mode != 0o600
                    || current_bytes.len() >= expected_bytes.len()
                    || !expected_bytes.starts_with(&current_bytes)
                {
                    return Err(());
                }
                drop(generation);
                drop(current_file);
                rustix::fs::unlinkat(&self.root, CURRENT_TMP, rustix::fs::AtFlags::empty())
                    .map_err(|_| ())?;
                self.root.sync_all().map_err(|_| ())?;
                self.generations.sync_all().map_err(|_| ())?;
                let selected = self.publish_initial_current()?;
                return self.finish_initial_p2(authority, &pending, selected, before_p2);
            }
            drop(generation);
            self.generations.sync_all().map_err(|_| ())?;
            fchmod(&current_file, Mode::from_raw_mode(0o400)).map_err(|_| ())?;
            validate_file(&current_file, self.identity, 0o400, 1024)?;
            current_file.sync_all().map_err(|_| ())?;
            renameat(&self.root, CURRENT_TMP, &self.root, CURRENT).map_err(|_| ())?;
            self.root.sync_all().map_err(|_| ())?;
            let selected = self.validate_selected_clean_generation()?;
            return self.finish_initial_p2(authority, &pending, selected, before_p2);
        }
        if generation_names == std::iter::once(OsString::from(GENERATION_ONE)).collect() {
            let complete = self.validate_clean_generation()?;
            if complete.captured_at != pending.captured_at {
                return Err(());
            }
            drop(complete);
            self.generations.sync_all().map_err(|_| ())?;
            let selected = self.publish_initial_current()?;
            return self.finish_initial_p2(authority, &pending, selected, before_p2);
        }
        if generation_names == std::iter::once(OsString::from(GENERATION_TMP)).collect() {
            let temporary = directory_at_modes(
                &self.generations,
                GENERATION_TMP,
                self.identity.uid,
                self.identity.gid,
                &[0o700, 0o500],
            )?;
            if temporary.metadata().map_err(|_| ())?.mode() & 0o7777 == 0o500 {
                let validated = self.validate_sealed_temporary()?;
                if validated.captured_at != pending.captured_at {
                    return Err(());
                }
                drop(validated);
                renameat(
                    &self.generations,
                    GENERATION_TMP,
                    &self.generations,
                    GENERATION_ONE,
                )
                .map_err(|_| ())?;
                self.generations.sync_all().map_err(|_| ())?;
                let selected = self.publish_initial_current()?;
                return self.finish_initial_p2(authority, &pending, selected, before_p2);
            }
        }

        let source = self.state.backup_source_descriptors()?;
        if !names(&source.receipts, 1)?.is_empty() || !names(&source.runner, 1)?.is_empty() {
            return Err(());
        }
        let generation_names = names(&self.generations, 2)?;
        if generation_names == std::iter::once(OsString::from(GENERATION_TMP)).collect() {
            remove_incomplete_initial_temporary(&self.generations, self.identity)?;
        } else if !generation_names.is_empty() {
            return Err(());
        }
        let temporary = create_directory(&self.generations, GENERATION_TMP, self.identity)?;
        let service_directory = create_directory(&temporary, "service", self.identity)?;
        let receipts = create_directory(&temporary, "receipts", self.identity)?;
        let runner = create_directory(&temporary, "runner", self.identity)?;
        let trust = create_directory(&temporary, "trust", self.identity)?;
        let database = copy_file(
            &source.database,
            &service_directory,
            DATABASE,
            self.identity,
            DATABASE_MAX,
        )?;
        let deployment = copy_file(
            &source.deployment,
            &temporary,
            DEPLOYMENT,
            self.identity,
            16 * 1024,
        )?;
        if read_bounded(&deployment, 16 * 1024)? != source.deployment_snapshot.bytes {
            return Err(());
        }
        let manifest = Manifest {
            schema: "kapsel.sandbox.backup.v1".to_owned(),
            generation: 1,
            predecessor: None,
            captured_at,
            stopped: true,
            compatibility_sha256: source.deployment_snapshot.identity.compatibility_sha256,
            authorities: Vec::new(),
            trust: Vec::new(),
            files: vec![
                record(DEPLOYMENT, &deployment, 16 * 1024)?,
                record("service/sandbox.sqlite3", &database, DATABASE_MAX)?,
            ],
        };
        let manifest_file = write_new_file(
            &temporary,
            MANIFEST,
            &serde_json::to_vec(&manifest).map_err(|_| ())?,
            self.identity,
            JSON_MAX,
        )?;
        for file in [&database, &deployment, &manifest_file] {
            fchmod(file, Mode::from_raw_mode(0o400)).map_err(|_| ())?;
            validate_file(file, self.identity, 0o400, GENERATION_MAX)?;
            file.sync_all().map_err(|_| ())?;
        }
        for directory in [&service_directory, &receipts, &runner, &trust] {
            directory.sync_all().map_err(|_| ())?;
            fchmod(directory, Mode::from_raw_mode(0o500)).map_err(|_| ())?;
            validate_directory(directory, self.identity.uid, self.identity.gid, 0o500)?;
            directory.sync_all().map_err(|_| ())?;
        }
        temporary.sync_all().map_err(|_| ())?;
        fchmod(&temporary, Mode::from_raw_mode(0o500)).map_err(|_| ())?;
        validate_directory(&temporary, self.identity.uid, self.identity.gid, 0o500)?;
        temporary.sync_all().map_err(|_| ())?;
        renameat(
            &self.generations,
            GENERATION_TMP,
            &self.generations,
            GENERATION_ONE,
        )
        .map_err(|_| ())?;
        self.generations.sync_all().map_err(|_| ())?;
        let selected = self.publish_initial_current()?;
        self.finish_initial_p2(authority, &pending, selected, before_p2)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreIncomplete {
    schema: String,
    generation: u64,
    manifest_sha256: String,
    compatibility_sha256: String,
    started_at: i64,
    step: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreReady {
    schema: String,
    source: String,
    generation: Option<u64>,
    manifest_sha256: Option<String>,
    compatibility_sha256: String,
    completed_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreInstallComponent {
    Database,
    Deployment,
    Receipts,
    Runner,
    StateLock,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::enum_variant_names,
    reason = "installation barriers name the durable side reached before simulated process loss"
)]
enum RestoreInstallBarrier {
    AfterTemporaryCreate,
    AfterTemporaryOwnership,
    AfterTemporaryInodeSync,
    AfterTemporaryParentSync,
    AfterComponentCreate(RestoreInstallComponent),
    AfterComponentNamespaceSync(RestoreInstallComponent),
    AfterComponentPartialWrite(RestoreInstallComponent),
    AfterComponentWrite(RestoreInstallComponent),
    AfterComponentContentSync(RestoreInstallComponent),
    AfterComponentOwnership(RestoreInstallComponent),
    AfterComponentMode(RestoreInstallComponent),
    AfterComponentFinalSync(RestoreInstallComponent),
    AfterComponentUnlink(RestoreInstallComponent),
    AfterComponentRemovalSync(RestoreInstallComponent),
    AfterTreeSync,
    AfterTemporaryUnlink,
    AfterCleanupParentSync,
    BeforeRenameRace,
    AfterRename,
    AfterParentSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::enum_variant_names,
    reason = "fault barriers name the durable side reached before simulated process loss"
)]
enum RestoreStopBarrier {
    BeforePublication,
    AfterPublication,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreExpiryBarrier {
    BeforeExpiryCommit,
    AfterExpiryCommit,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreReceiptBarrier {
    BeforeConvergence,
    AfterConvergence,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreRunnerBarrier {
    BeforeReconstruction,
    AfterReconstruction,
    BeforeReconciliation,
    AfterReconciliation,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreLeaseBarrier {
    BeforePublicationFixedPoint,
    AfterPublicationFixedPoint,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreCleanupBarrier {
    BeforeCleanupFixedPoint,
    AfterCleanupFixedPoint,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreValidationBarrier {
    BeforeValidationFixedPoint,
    AfterValidationFixedPoint,
    AfterTemporarySync,
    AfterRename,
    AfterStateRootSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::enum_variant_names,
    reason = "fault barriers name the durable side reached before simulated process loss"
)]
enum RestoreReadinessBarrier {
    AfterTemporarySync,
    AfterReadyRename,
    AfterPairSync,
    AfterIncompleteUnlink,
    AfterFinalStateSync,
    AfterParentSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanStepPublicationBarrier {
    TemporarySynced,
    Renamed,
    StateRootSynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreTransition {
    InstalledToStopped,
    StoppedToExpired,
    ExpiredToReceipts,
    ReceiptsToRunner,
    RunnerToLease,
    LeaseToCleanup,
    CleanupToValidated,
}

fn map_stop_publication_barrier(phase: CleanStepPublicationBarrier) -> RestoreStopBarrier {
    match phase {
        CleanStepPublicationBarrier::TemporarySynced => RestoreStopBarrier::AfterTemporarySync,
        CleanStepPublicationBarrier::Renamed => RestoreStopBarrier::AfterRename,
        CleanStepPublicationBarrier::StateRootSynced => RestoreStopBarrier::AfterStateRootSync,
    }
}

fn map_expiry_publication_barrier(phase: CleanStepPublicationBarrier) -> RestoreExpiryBarrier {
    match phase {
        CleanStepPublicationBarrier::TemporarySynced => RestoreExpiryBarrier::AfterTemporarySync,
        CleanStepPublicationBarrier::Renamed => RestoreExpiryBarrier::AfterRename,
        CleanStepPublicationBarrier::StateRootSynced => RestoreExpiryBarrier::AfterStateRootSync,
    }
}

impl RestoreTransition {
    fn steps(self) -> (&'static str, &'static str) {
        match self {
            Self::InstalledToStopped => ("installed", "stopped"),
            Self::StoppedToExpired => ("stopped", "expired"),
            Self::ExpiredToReceipts => ("expired", "receipts"),
            Self::ReceiptsToRunner => ("receipts", "runner"),
            Self::RunnerToLease => ("runner", "lease"),
            Self::LeaseToCleanup => ("lease", "cleanup"),
            Self::CleanupToValidated => ("cleanup", "validated"),
        }
    }
}

#[allow(
    dead_code,
    reason = "opened destination descriptors remain pinned through the stopped transition"
)]
struct RestoredCleanPrefix {
    root: File,
    database: File,
    deployment: File,
    receipts: File,
    runner: File,
    state_lock: File,
    incomplete: File,
    temporary: Option<File>,
    record: RestoreIncomplete,
    current_publication: bool,
}

struct RestoreInstallationComplete {
    root: File,
    database: File,
    deployment: File,
    receipts: File,
    runner: File,
    state_lock: File,
    incomplete_file: File,
    record: RestoreIncomplete,
}

struct RestoreInstallationPrefix {
    root: File,
    components: Vec<RestoreInstallComponent>,
    pinned_components: Vec<(RestoreInstallComponent, File)>,
    complete: Option<RestoreInstallationComplete>,
}

struct RestoredReadinessPrefix {
    root: File,
    incomplete: Option<File>,
    ready: Option<File>,
    temporary: Option<File>,
    incomplete_record: Option<RestoreIncomplete>,
    ready_record: Option<RestoreReady>,
}

/// Pins one selected clean backup after exclusively fencing an absent destination.
#[allow(
    dead_code,
    reason = "the shipped restore command will compose this private filesystem phase"
)]
struct RestoreGuard {
    destination_path: PathBuf,
    destination_name: OsString,
    controller: BackupIdentity,
    destination_parent: File,
    destination_lock: File,
    destination_state: Option<File>,
    destination_state_lock: Option<File>,
    backup_name: OsString,
    backup_identity: BackupIdentity,
    backup_parent: File,
    backup_root: File,
    backup_lock: File,
    generations: File,
    generation: File,
    service: File,
    receipts: File,
    runner: File,
    trust: File,
    database: File,
    database_path: PathBuf,
    deployment: File,
    manifest_file: File,
    current_file: File,
    manifest: Manifest,
    manifest_sha256: String,
    profile: crate::state_root::DeploymentProfile,
}

#[allow(
    dead_code,
    clippy::too_many_lines,
    reason = "the restore tracer keeps its ordered filesystem proof explicit"
)]
impl RestoreGuard {
    fn open_selected_clean(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            false,
            false,
        )
    }

    fn open_selected_clean_prefix(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
        installed: bool,
        temporary: bool,
    ) -> Result<Self, ()> {
        if !destination.is_absolute() || !backup_path.is_absolute() {
            return Err(());
        }
        let destination_parent_path = destination.parent().ok_or(())?;
        let destination_name = destination.file_name().ok_or(())?.to_owned();
        if destination_name == PARENT_RESTORE_LOCK || destination_name == RESTORE_TEMPORARY {
            return Err(());
        }
        let destination_parent = directory_path(
            destination_parent_path,
            controller.uid,
            controller.gid,
            0o700,
        )?;
        let destination_lock = file_at(
            &destination_parent,
            PARENT_RESTORE_LOCK,
            controller.uid,
            controller.gid,
            0o600,
            true,
            0,
        )?;
        flock(&destination_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
        let mut expected_parent =
            std::iter::once(OsString::from(PARENT_RESTORE_LOCK)).collect::<BTreeSet<_>>();
        if installed {
            expected_parent.insert(destination_name.clone());
        }
        if temporary {
            expected_parent.insert(OsString::from(RESTORE_TEMPORARY));
        }
        if names(&destination_parent, 3)? != expected_parent {
            return Err(());
        }
        let (destination_state, destination_state_lock) = if installed {
            let state = directory_at(
                &destination_parent,
                &destination_name,
                controller.uid,
                controller.gid,
                0o700,
            )?;
            let state_lock = file_at(&state, LOCK, controller.uid, controller.gid, 0o600, true, 0)?;
            flock(&state_lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
            (Some(state), Some(state_lock))
        } else {
            (None, None)
        };

        let backup_parent_path = backup_path.parent().ok_or(())?;
        let backup_name = backup_path.file_name().ok_or(())?.to_owned();
        let backup_parent = directory_path(
            backup_parent_path,
            backup_identity.uid,
            backup_identity.gid,
            0o700,
        )?;
        let backup_root = directory_at(
            &backup_parent,
            &backup_name,
            backup_identity.uid,
            backup_identity.gid,
            0o700,
        )?;
        let backup_lock = file_at(
            &backup_root,
            LOCK,
            backup_identity.uid,
            backup_identity.gid,
            0o600,
            true,
            0,
        )?;
        flock(&backup_lock, FlockOperation::NonBlockingLockShared).map_err(|_| ())?;
        let expected_backup = [LOCK, GENERATIONS, CURRENT]
            .into_iter()
            .map(OsString::from)
            .collect();
        if names(&backup_root, 4)? != expected_backup {
            return Err(());
        }
        let generations = directory_at(
            &backup_root,
            GENERATIONS,
            backup_identity.uid,
            backup_identity.gid,
            0o700,
        )?;
        if names(&generations, 2)? != std::iter::once(OsString::from(GENERATION_ONE)).collect() {
            return Err(());
        }
        let generation = directory_at(
            &generations,
            GENERATION_ONE,
            backup_identity.uid,
            backup_identity.gid,
            0o500,
        )?;
        let expected_generation = [
            DEPLOYMENT, MANIFEST, "receipts", "runner", "service", "trust",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if names(&generation, 7)? != expected_generation {
            return Err(());
        }
        let service = directory_at(
            &generation,
            "service",
            backup_identity.uid,
            backup_identity.gid,
            0o500,
        )?;
        let receipts = directory_at(
            &generation,
            "receipts",
            backup_identity.uid,
            backup_identity.gid,
            0o500,
        )?;
        let runner = directory_at(
            &generation,
            "runner",
            backup_identity.uid,
            backup_identity.gid,
            0o500,
        )?;
        let trust = directory_at(
            &generation,
            "trust",
            backup_identity.uid,
            backup_identity.gid,
            0o500,
        )?;
        if names(&service, 2)? != std::iter::once(OsString::from(DATABASE)).collect()
            || !names(&receipts, 1)?.is_empty()
            || !names(&runner, 1)?.is_empty()
            || !names(&trust, 1)?.is_empty()
        {
            return Err(());
        }
        let database = file_at(
            &service,
            DATABASE,
            backup_identity.uid,
            backup_identity.gid,
            0o400,
            false,
            DATABASE_MAX,
        )?;
        let deployment = file_at(
            &generation,
            DEPLOYMENT,
            backup_identity.uid,
            backup_identity.gid,
            0o400,
            false,
            16 * 1024,
        )?;
        let manifest_file = file_at(
            &generation,
            MANIFEST,
            backup_identity.uid,
            backup_identity.gid,
            0o400,
            false,
            JSON_MAX,
        )?;
        let current_file = file_at(
            &backup_root,
            CURRENT,
            backup_identity.uid,
            backup_identity.gid,
            0o400,
            false,
            1024,
        )?;
        let manifest_bytes = read_bounded(&manifest_file, JSON_MAX)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&manifest).map_err(|_| ())? != manifest_bytes {
            return Err(());
        }
        let deployment_snapshot =
            crate::state_root::deployment_snapshot_from_file(&deployment, profile)?;
        validate_manifest(&manifest, 1, &deployment_snapshot, &deployment, &database)?;
        Service::preflight_clean_restore_source(
            &backup_path
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join("service")
                .join(DATABASE),
            manifest.generation,
            manifest.captured_at,
        )
        .map_err(|_| ())?;
        let manifest_sha256 = digest_bytes(&manifest_bytes);
        let current_bytes = read_bounded(&current_file, 1024)?;
        let current: CurrentRecord = serde_json::from_slice(&current_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&current).map_err(|_| ())? != current_bytes
            || current.schema != "kapsel.sandbox.backup.current.v1"
            || current.generation != 1
            || current.manifest_sha256 != manifest_sha256
        {
            return Err(());
        }
        let guard = Self {
            destination_path: destination.to_owned(),
            destination_name,
            controller,
            destination_parent,
            destination_lock,
            destination_state,
            destination_state_lock,
            backup_name,
            backup_identity,
            backup_parent,
            backup_root,
            backup_lock,
            generations,
            generation,
            service,
            receipts,
            runner,
            trust,
            database,
            database_path: backup_path
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join("service")
                .join(DATABASE),
            deployment,
            manifest_file,
            current_file,
            manifest,
            manifest_sha256,
            profile,
        };
        guard.verify(installed, temporary)?;
        Ok(guard)
    }

    fn verify(&self, installed: bool, temporary: bool) -> Result<(), ()> {
        let mut expected_parent =
            std::iter::once(OsString::from(PARENT_RESTORE_LOCK)).collect::<BTreeSet<_>>();
        if installed {
            expected_parent.insert(self.destination_name.clone());
        }
        if temporary {
            expected_parent.insert(OsString::from(RESTORE_TEMPORARY));
        }
        if names(&self.destination_parent, 3)? != expected_parent {
            return Err(());
        }
        let expected_backup = [LOCK, GENERATIONS, CURRENT]
            .into_iter()
            .map(OsString::from)
            .collect();
        if names(&self.backup_root, 4)? != expected_backup
            || names(&self.generations, 2)?
                != std::iter::once(OsString::from(GENERATION_ONE)).collect()
        {
            return Err(());
        }
        let expected_generation = [
            DEPLOYMENT, MANIFEST, "receipts", "runner", "service", "trust",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if names(&self.generation, 7)? != expected_generation
            || names(&self.service, 2)? != std::iter::once(OsString::from(DATABASE)).collect()
            || !names(&self.receipts, 1)?.is_empty()
            || !names(&self.runner, 1)?.is_empty()
            || !names(&self.trust, 1)?.is_empty()
        {
            return Err(());
        }
        let destination_lock = file_at(
            &self.destination_parent,
            PARENT_RESTORE_LOCK,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            0,
        )?;
        same(&destination_lock, &self.destination_lock)?;
        match (
            installed,
            self.destination_state.as_ref(),
            self.destination_state_lock.as_ref(),
        ) {
            (true, Some(pinned_state), Some(pinned_lock)) => {
                let state = directory_at(
                    &self.destination_parent,
                    &self.destination_name,
                    self.controller.uid,
                    self.controller.gid,
                    0o700,
                )?;
                same(&state, pinned_state)?;
                let state_lock = file_at(
                    &state,
                    LOCK,
                    self.controller.uid,
                    self.controller.gid,
                    0o600,
                    true,
                    0,
                )?;
                same(&state_lock, pinned_lock)?;
            },
            (true | false, None, None) => {},
            _ => return Err(()),
        }
        let backup_root = directory_at(
            &self.backup_parent,
            &self.backup_name,
            self.backup_identity.uid,
            self.backup_identity.gid,
            0o700,
        )?;
        same(&backup_root, &self.backup_root)?;
        let backup_lock = file_at(
            &backup_root,
            LOCK,
            self.backup_identity.uid,
            self.backup_identity.gid,
            0o600,
            true,
            0,
        )?;
        same(&backup_lock, &self.backup_lock)?;
        let generations = directory_at(
            &backup_root,
            GENERATIONS,
            self.backup_identity.uid,
            self.backup_identity.gid,
            0o700,
        )?;
        same(&generations, &self.generations)?;
        let generation = directory_at(
            &generations,
            GENERATION_ONE,
            self.backup_identity.uid,
            self.backup_identity.gid,
            0o500,
        )?;
        same(&generation, &self.generation)?;
        for (name, reopened, pinned) in [
            ("service", &generation, &self.service),
            ("receipts", &generation, &self.receipts),
            ("runner", &generation, &self.runner),
            ("trust", &generation, &self.trust),
        ] {
            let directory = directory_at(
                reopened,
                name,
                self.backup_identity.uid,
                self.backup_identity.gid,
                0o500,
            )?;
            same(&directory, pinned)?;
        }
        for (parent, name, pinned, maximum) in [
            (&self.service, DATABASE, &self.database, DATABASE_MAX),
            (&self.generation, DEPLOYMENT, &self.deployment, 16 * 1024),
            (&self.generation, MANIFEST, &self.manifest_file, JSON_MAX),
            (&self.backup_root, CURRENT, &self.current_file, 1024),
        ] {
            let file = file_at(
                parent,
                name,
                self.backup_identity.uid,
                self.backup_identity.gid,
                0o400,
                false,
                maximum,
            )?;
            same(&file, pinned)?;
        }
        let manifest_bytes = read_bounded(&self.manifest_file, JSON_MAX)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|_| ())?;
        if digest_bytes(&manifest_bytes) != self.manifest_sha256
            || serde_json::to_vec(&manifest).map_err(|_| ())? != manifest_bytes
        {
            return Err(());
        }
        let deployment =
            crate::state_root::deployment_snapshot_from_file(&self.deployment, self.profile)?;
        validate_manifest(&manifest, 1, &deployment, &self.deployment, &self.database)?;
        Service::preflight_clean_restore_source(
            &self.database_path,
            manifest.generation,
            manifest.captured_at,
        )
        .map_err(|_| ())?;
        let current_bytes = read_bounded(&self.current_file, 1024)?;
        let current: CurrentRecord = serde_json::from_slice(&current_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&current).map_err(|_| ())? != current_bytes
            || current.schema != "kapsel.sandbox.backup.current.v1"
            || current.generation != 1
            || current.manifest_sha256 != self.manifest_sha256
        {
            return Err(());
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the closed installed-prefix inventory stays explicit before publication"
    )]
    fn verify_restore_temporary(
        &self,
        temporary: &File,
        database: &File,
        deployment: &File,
        receipts: &File,
        runner: &File,
        state_lock: &File,
        incomplete_file: &File,
        incomplete: &RestoreIncomplete,
    ) -> Result<(), ()> {
        self.verify_installation_tree(
            OsStr::new(RESTORE_TEMPORARY),
            temporary,
            database,
            deployment,
            receipts,
            runner,
            state_lock,
            incomplete_file,
            incomplete,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "published installation validation keeps every pinned component explicit"
    )]
    fn verify_installation_tree(
        &self,
        name: &OsStr,
        root: &File,
        database: &File,
        deployment: &File,
        receipts: &File,
        runner: &File,
        state_lock: &File,
        incomplete_file: &File,
        incomplete: &RestoreIncomplete,
    ) -> Result<(), ()> {
        let reopened_root = directory_at(
            &self.destination_parent,
            name,
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        same(&reopened_root, root)?;
        let expected = [
            DATABASE,
            DEPLOYMENT,
            LOCK,
            RESTORE_INCOMPLETE,
            "receipts",
            "runner",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if names(root, 7)? != expected {
            return Err(());
        }
        validate_directory(root, self.controller.uid, self.controller.gid, 0o700)?;
        validate_directory(receipts, self.controller.uid, self.controller.gid, 0o700)?;
        validate_directory(runner, self.controller.uid, self.controller.gid, 0o700)?;
        if !names(receipts, 1)?.is_empty() || !names(runner, 1)?.is_empty() {
            return Err(());
        }
        validate_file(database, self.controller, 0o600, DATABASE_MAX)?;
        validate_file(deployment, self.controller, 0o400, 16 * 1024)?;
        validate_file(state_lock, self.controller, 0o600, 0)?;
        validate_file(incomplete_file, self.controller, 0o600, 1024)?;
        for (child_name, pinned) in [("receipts", receipts), ("runner", runner)] {
            let reopened = directory_at(
                root,
                child_name,
                self.controller.uid,
                self.controller.gid,
                0o700,
            )?;
            same(&reopened, pinned)?;
        }
        for (child_name, pinned, mode, maximum) in [
            (DATABASE, database, 0o600, DATABASE_MAX),
            (DEPLOYMENT, deployment, 0o400, 16 * 1024),
            (LOCK, state_lock, 0o600, 0),
            (RESTORE_INCOMPLETE, incomplete_file, 0o600, 1024),
        ] {
            let reopened = file_at(
                root,
                child_name,
                self.controller.uid,
                self.controller.gid,
                mode,
                false,
                maximum,
            )?;
            same(&reopened, pinned)?;
        }
        if read_bounded(database, DATABASE_MAX)? != read_bounded(&self.database, DATABASE_MAX)?
            || read_bounded(deployment, 16 * 1024)? != read_bounded(&self.deployment, 16 * 1024)?
        {
            return Err(());
        }
        let incomplete_bytes = read_bounded(incomplete_file, 1024)?;
        if serde_json::to_vec(incomplete).map_err(|_| ())? != incomplete_bytes {
            return Err(());
        }
        Ok(())
    }

    fn verify_published_clean_prefix(&self, prefix: &RestoredCleanPrefix) -> Result<(), ()> {
        self.verify_installation_tree(
            &self.destination_name,
            &prefix.root,
            &prefix.database,
            &prefix.deployment,
            &prefix.receipts,
            &prefix.runner,
            &prefix.state_lock,
            &prefix.incomplete,
            &prefix.record,
        )
    }

    fn open_installation_prefix(&self) -> Result<RestoreInstallationPrefix, ()> {
        self.verify(false, true)?;
        let root = File::from(
            openat(
                &self.destination_parent,
                RESTORE_TEMPORARY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| ())?,
        );
        let ordered = [
            (DATABASE, RestoreInstallComponent::Database),
            (DEPLOYMENT, RestoreInstallComponent::Deployment),
            ("receipts", RestoreInstallComponent::Receipts),
            ("runner", RestoreInstallComponent::Runner),
            (LOCK, RestoreInstallComponent::StateLock),
            (RESTORE_INCOMPLETE, RestoreInstallComponent::Incomplete),
        ];
        let root_names = names(&root, 7)?;
        let count = (0..=ordered.len())
            .find(|count| {
                ordered[..*count]
                    .iter()
                    .map(|(name, _)| OsString::from(name))
                    .collect::<BTreeSet<_>>()
                    == root_names
            })
            .ok_or(())?;
        let root_metadata = root.metadata().map_err(|_| ())?;
        let root_owner = BackupIdentity {
            uid: root_metadata.uid(),
            gid: root_metadata.gid(),
        };
        if !reachable_installation_root_state(
            root_owner,
            root_metadata.mode() & 0o7777,
            count == 0,
            self.backup_identity,
            self.controller,
        ) {
            return Err(());
        }

        let database_bytes = read_bounded(&self.database, DATABASE_MAX)?;
        let deployment_bytes = read_bounded(&self.deployment, 16 * 1024)?;
        let mut database = None;
        let mut deployment = None;
        let mut receipts = None;
        let mut runner = None;
        let mut state_lock = None;
        let mut incomplete_file = None;
        let mut incomplete_record = None;
        let mut pinned_components = Vec::with_capacity(count);
        let mut all_final = true;

        for (index, (_, component)) in ordered[..count].iter().enumerate() {
            let current = index + 1 == count;
            let final_state = match component {
                RestoreInstallComponent::Database => {
                    let file = open_installation_file(&root, DATABASE, DATABASE_MAX)?;
                    let bytes = read_bounded(&file, DATABASE_MAX)?;
                    if !database_bytes.starts_with(&bytes) {
                        return Err(());
                    }
                    let final_state = validate_installation_file_state(
                        &file,
                        self.backup_identity,
                        self.controller,
                        0o600,
                        bytes.len() == database_bytes.len(),
                    )?;
                    pinned_components.push((*component, file.try_clone().map_err(|_| ())?));
                    database = Some(file);
                    final_state
                },
                RestoreInstallComponent::Deployment => {
                    let file = open_installation_file(&root, DEPLOYMENT, 16 * 1024)?;
                    let bytes = read_bounded(&file, 16 * 1024)?;
                    if !deployment_bytes.starts_with(&bytes) {
                        return Err(());
                    }
                    let final_state = validate_installation_file_state(
                        &file,
                        self.backup_identity,
                        self.controller,
                        0o400,
                        bytes.len() == deployment_bytes.len(),
                    )?;
                    pinned_components.push((*component, file.try_clone().map_err(|_| ())?));
                    deployment = Some(file);
                    final_state
                },
                RestoreInstallComponent::Receipts | RestoreInstallComponent::Runner => {
                    let name = if *component == RestoreInstallComponent::Receipts {
                        "receipts"
                    } else {
                        "runner"
                    };
                    let directory = open_installation_directory(&root, name)?;
                    if !names(&directory, 1)?.is_empty() {
                        return Err(());
                    }
                    let final_state = validate_installation_directory_state(
                        &directory,
                        self.backup_identity,
                        self.controller,
                    )?;
                    pinned_components.push((*component, directory.try_clone().map_err(|_| ())?));
                    if *component == RestoreInstallComponent::Receipts {
                        receipts = Some(directory);
                    } else {
                        runner = Some(directory);
                    }
                    final_state
                },
                RestoreInstallComponent::StateLock => {
                    let file = open_installation_file(&root, LOCK, 0)?;
                    let final_state = validate_installation_file_state(
                        &file,
                        self.backup_identity,
                        self.controller,
                        0o600,
                        true,
                    )?;
                    pinned_components.push((*component, file.try_clone().map_err(|_| ())?));
                    state_lock = Some(file);
                    final_state
                },
                RestoreInstallComponent::Incomplete => {
                    let file = open_installation_file(&root, RESTORE_INCOMPLETE, 1024)?;
                    let bytes = read_bounded(&file, 1024)?;
                    let record = canonical_installed_record(
                        &bytes,
                        self.manifest.generation,
                        &self.manifest_sha256,
                        &self.manifest.compatibility_sha256,
                        self.manifest.captured_at,
                    );
                    if record.is_none()
                        && !valid_installed_record_prefix(
                            &bytes,
                            self.manifest.generation,
                            &self.manifest_sha256,
                            &self.manifest.compatibility_sha256,
                            self.manifest.captured_at,
                        )
                    {
                        return Err(());
                    }
                    let final_state = validate_installation_file_state(
                        &file,
                        self.backup_identity,
                        self.controller,
                        0o600,
                        record.is_some(),
                    )?;
                    pinned_components.push((*component, file.try_clone().map_err(|_| ())?));
                    incomplete_record = record;
                    incomplete_file = Some(file);
                    final_state
                },
            };
            if !current && !final_state {
                return Err(());
            }
            all_final &= final_state;
        }

        let components = ordered[..count]
            .iter()
            .map(|(_, component)| *component)
            .collect::<Vec<_>>();
        let complete = if count == ordered.len() && all_final {
            Some(RestoreInstallationComplete {
                root: root.try_clone().map_err(|_| ())?,
                database: database.ok_or(())?,
                deployment: deployment.ok_or(())?,
                receipts: receipts.ok_or(())?,
                runner: runner.ok_or(())?,
                state_lock: state_lock.ok_or(())?,
                incomplete_file: incomplete_file.ok_or(())?,
                record: incomplete_record.ok_or(())?,
            })
        } else {
            None
        };
        Ok(RestoreInstallationPrefix {
            root,
            components,
            pinned_components,
            complete,
        })
    }

    fn install_incomplete(&self, started_at: i64) -> Result<(), ()> {
        self.install_incomplete_with_barrier(started_at, |_| Ok(()))
    }

    fn install_incomplete_with_barrier<F>(&self, started_at: i64, mut barrier: F) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        self.construct_installation(started_at, &mut barrier)
    }

    fn construct_installation<F>(&self, started_at: i64, barrier: &mut F) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        if started_at < self.manifest.captured_at {
            return Err(());
        }
        self.verify(false, false)?;
        let database_bytes = read_bounded(&self.database, DATABASE_MAX)?;
        let deployment_bytes = read_bounded(&self.deployment, 16 * 1024)?;
        let incomplete = RestoreIncomplete {
            schema: "kapsel.sandbox.restore-incomplete.v1".to_owned(),
            generation: self.manifest.generation,
            manifest_sha256: self.manifest_sha256.clone(),
            compatibility_sha256: self.manifest.compatibility_sha256.clone(),
            started_at,
            step: "installed".to_owned(),
        };
        let incomplete_bytes = serde_json::to_vec(&incomplete).map_err(|_| ())?;
        let temporary = create_restore_installation_root(
            &self.destination_parent,
            self.backup_identity,
            self.controller,
            barrier,
        )?;
        let database = install_restore_file(
            &temporary,
            DATABASE,
            &database_bytes,
            self.backup_identity,
            self.controller,
            0o600,
            DATABASE_MAX,
            RestoreInstallComponent::Database,
            barrier,
        )?;
        let deployment = install_restore_file(
            &temporary,
            DEPLOYMENT,
            &deployment_bytes,
            self.backup_identity,
            self.controller,
            0o400,
            16 * 1024,
            RestoreInstallComponent::Deployment,
            barrier,
        )?;
        let receipts = install_restore_directory(
            &temporary,
            "receipts",
            self.backup_identity,
            self.controller,
            RestoreInstallComponent::Receipts,
            barrier,
        )?;
        let runner = install_restore_directory(
            &temporary,
            "runner",
            self.backup_identity,
            self.controller,
            RestoreInstallComponent::Runner,
            barrier,
        )?;
        let state_lock = install_restore_file(
            &temporary,
            LOCK,
            b"",
            self.backup_identity,
            self.controller,
            0o600,
            0,
            RestoreInstallComponent::StateLock,
            barrier,
        )?;
        let incomplete_file = install_restore_file(
            &temporary,
            RESTORE_INCOMPLETE,
            &incomplete_bytes,
            self.backup_identity,
            self.controller,
            0o600,
            1024,
            RestoreInstallComponent::Incomplete,
            barrier,
        )?;
        self.verify_restore_temporary(
            &temporary,
            &database,
            &deployment,
            &receipts,
            &runner,
            &state_lock,
            &incomplete_file,
            &incomplete,
        )?;
        self.verify(false, true)?;
        temporary.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterTreeSync)?;
        self.verify_restore_temporary(
            &temporary,
            &database,
            &deployment,
            &receipts,
            &runner,
            &state_lock,
            &incomplete_file,
            &incomplete,
        )?;
        self.verify(false, true)?;
        // Production performs no work in this interval; the private seam models a destination name
        // racing final validation so NOREPLACE itself remains covered.
        barrier(RestoreInstallBarrier::BeforeRenameRace)?;
        rustix::fs::renameat_with(
            &self.destination_parent,
            RESTORE_TEMPORARY,
            &self.destination_parent,
            &self.destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterRename)?;
        self.verify_installation_tree(
            &self.destination_name,
            &temporary,
            &database,
            &deployment,
            &receipts,
            &runner,
            &state_lock,
            &incomplete_file,
            &incomplete,
        )?;
        self.verify(true, false)?;
        self.destination_parent.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterParentSync)?;
        self.verify_installation_tree(
            &self.destination_name,
            &temporary,
            &database,
            &deployment,
            &receipts,
            &runner,
            &state_lock,
            &incomplete_file,
            &incomplete,
        )?;
        self.verify(true, false)
    }

    fn reopen_temporary_installation(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            false,
            true,
        )?;
        guard.open_installation_prefix()?;
        Ok(guard)
    }

    fn resume_temporary_installation_with_barrier<F>(
        &self,
        replacement_started_at: i64,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        let prefix = self.open_installation_prefix()?;
        if let Some(complete) = prefix.complete.as_ref() {
            return self.publish_complete_installation(complete, &mut barrier);
        }
        self.remove_installation_prefix(&prefix, &mut barrier)?;
        self.verify(false, false)?;
        self.construct_installation(replacement_started_at, &mut barrier)
    }

    fn remove_installation_prefix<F>(
        &self,
        prefix: &RestoreInstallationPrefix,
        barrier: &mut F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        let mut remaining = prefix.components.clone();
        while let Some(component) = remaining.last().copied() {
            self.verify(false, true)?;
            let reopened_root =
                open_installation_directory(&self.destination_parent, RESTORE_TEMPORARY)?;
            same(&reopened_root, &prefix.root)?;
            let expected_names = remaining
                .iter()
                .map(|component| {
                    OsString::from(match component {
                        RestoreInstallComponent::Database => DATABASE,
                        RestoreInstallComponent::Deployment => DEPLOYMENT,
                        RestoreInstallComponent::Receipts => "receipts",
                        RestoreInstallComponent::Runner => "runner",
                        RestoreInstallComponent::StateLock => LOCK,
                        RestoreInstallComponent::Incomplete => RESTORE_INCOMPLETE,
                    })
                })
                .collect::<BTreeSet<_>>();
            if names(&prefix.root, 7)? != expected_names {
                return Err(());
            }
            let (name, flags) = match component {
                RestoreInstallComponent::Database => (DATABASE, rustix::fs::AtFlags::empty()),
                RestoreInstallComponent::Deployment => (DEPLOYMENT, rustix::fs::AtFlags::empty()),
                RestoreInstallComponent::Receipts => ("receipts", rustix::fs::AtFlags::REMOVEDIR),
                RestoreInstallComponent::Runner => ("runner", rustix::fs::AtFlags::REMOVEDIR),
                RestoreInstallComponent::StateLock => (LOCK, rustix::fs::AtFlags::empty()),
                RestoreInstallComponent::Incomplete => {
                    (RESTORE_INCOMPLETE, rustix::fs::AtFlags::empty())
                },
            };
            let pinned = prefix
                .pinned_components
                .iter()
                .find_map(|(pinned_component, file)| {
                    (*pinned_component == component).then_some(file)
                })
                .ok_or(())?;
            let reopened = if flags.contains(rustix::fs::AtFlags::REMOVEDIR) {
                open_installation_directory(&prefix.root, name)?
            } else {
                open_installation_file(
                    &prefix.root,
                    name,
                    match component {
                        RestoreInstallComponent::Database => DATABASE_MAX,
                        RestoreInstallComponent::Deployment => 16 * 1024,
                        RestoreInstallComponent::StateLock => 0,
                        RestoreInstallComponent::Incomplete => 1024,
                        RestoreInstallComponent::Receipts | RestoreInstallComponent::Runner => {
                            return Err(());
                        },
                    },
                )?
            };
            same(&reopened, pinned)?;
            rustix::fs::unlinkat(&prefix.root, name, flags).map_err(|_| ())?;
            // The exclusive parent fence excludes conforming peers. Regular-file unlink is also
            // visible on the pinned descriptor; directory link counts are intentionally not
            // identity, so the exact post-unlink namespace inventory below is their evidence.
            let removed_metadata = pinned.metadata().map_err(|_| ())?;
            if removed_metadata.is_file() && removed_metadata.nlink() != 0 {
                return Err(());
            }
            remaining.pop();
            let remaining_names = remaining
                .iter()
                .map(|component| {
                    OsString::from(match component {
                        RestoreInstallComponent::Database => DATABASE,
                        RestoreInstallComponent::Deployment => DEPLOYMENT,
                        RestoreInstallComponent::Receipts => "receipts",
                        RestoreInstallComponent::Runner => "runner",
                        RestoreInstallComponent::StateLock => LOCK,
                        RestoreInstallComponent::Incomplete => RESTORE_INCOMPLETE,
                    })
                })
                .collect::<BTreeSet<_>>();
            if names(&prefix.root, 7)? != remaining_names {
                return Err(());
            }
            barrier(RestoreInstallBarrier::AfterComponentUnlink(component))?;
            prefix.root.sync_all().map_err(|_| ())?;
            barrier(RestoreInstallBarrier::AfterComponentRemovalSync(component))?;
        }
        self.verify(false, true)?;
        let reopened_root =
            open_installation_directory(&self.destination_parent, RESTORE_TEMPORARY)?;
        same(&reopened_root, &prefix.root)?;
        if !names(&prefix.root, 1)?.is_empty() {
            return Err(());
        }
        rustix::fs::unlinkat(
            &self.destination_parent,
            RESTORE_TEMPORARY,
            rustix::fs::AtFlags::REMOVEDIR,
        )
        .map_err(|_| ())?;
        if names(&self.destination_parent, 2)?
            != std::iter::once(OsString::from(PARENT_RESTORE_LOCK)).collect()
        {
            return Err(());
        }
        barrier(RestoreInstallBarrier::AfterTemporaryUnlink)?;
        self.destination_parent.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterCleanupParentSync)
    }

    fn publish_complete_installation<F>(
        &self,
        complete: &RestoreInstallationComplete,
        barrier: &mut F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        self.verify_restore_temporary(
            &complete.root,
            &complete.database,
            &complete.deployment,
            &complete.receipts,
            &complete.runner,
            &complete.state_lock,
            &complete.incomplete_file,
            &complete.record,
        )?;
        for file in [
            &complete.database,
            &complete.deployment,
            &complete.state_lock,
            &complete.incomplete_file,
        ] {
            file.sync_all().map_err(|_| ())?;
        }
        for directory in [&complete.receipts, &complete.runner] {
            directory.sync_all().map_err(|_| ())?;
        }
        complete.root.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterTreeSync)?;
        self.verify_restore_temporary(
            &complete.root,
            &complete.database,
            &complete.deployment,
            &complete.receipts,
            &complete.runner,
            &complete.state_lock,
            &complete.incomplete_file,
            &complete.record,
        )?;
        self.verify(false, true)?;
        // Production performs no work in this interval; the private seam models a destination name
        // racing final validation so NOREPLACE itself remains covered.
        barrier(RestoreInstallBarrier::BeforeRenameRace)?;
        rustix::fs::renameat_with(
            &self.destination_parent,
            RESTORE_TEMPORARY,
            &self.destination_parent,
            &self.destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterRename)?;
        self.verify_installation_tree(
            &self.destination_name,
            &complete.root,
            &complete.database,
            &complete.deployment,
            &complete.receipts,
            &complete.runner,
            &complete.state_lock,
            &complete.incomplete_file,
            &complete.record,
        )?;
        self.verify(true, false)?;
        self.destination_parent.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterParentSync)?;
        self.verify_installation_tree(
            &self.destination_name,
            &complete.root,
            &complete.database,
            &complete.deployment,
            &complete.receipts,
            &complete.runner,
            &complete.state_lock,
            &complete.incomplete_file,
            &complete.record,
        )?;
        self.verify(true, false)
    }

    fn retry_installed_installation_with_barrier<F>(&self, mut barrier: F) -> Result<(), ()>
    where
        F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
    {
        let prefix = self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
        if prefix.record.step != "installed" {
            return Err(());
        }
        for file in [
            &prefix.database,
            &prefix.deployment,
            &prefix.state_lock,
            &prefix.incomplete,
        ] {
            file.sync_all().map_err(|_| ())?;
        }
        for directory in [&prefix.receipts, &prefix.runner] {
            directory.sync_all().map_err(|_| ())?;
        }
        prefix.root.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterTreeSync)?;
        self.verify_published_clean_prefix(&prefix)?;
        self.verify(true, false)?;
        self.destination_parent.sync_all().map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterParentSync)?;
        self.verify_published_clean_prefix(&prefix)?;
        self.verify(true, false)
    }

    fn reopen_installed_to_stopped(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
        if !matches!(prefix.record.step.as_str(), "installed" | "stopped") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_stopped_to_expired(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
        if !matches!(prefix.record.step.as_str(), "stopped" | "expired") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_expired_to_receipts(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
        if !matches!(prefix.record.step.as_str(), "expired" | "receipts") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_receipts_to_runner(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
        if !matches!(prefix.record.step.as_str(), "receipts" | "runner") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_runner_to_lease(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        if !matches!(prefix.record.step.as_str(), "runner" | "lease") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_lease_to_cleanup(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::LeaseToCleanup)?;
        if !matches!(prefix.record.step.as_str(), "lease" | "cleanup") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_cleanup_to_validated(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::CleanupToValidated)?;
        if !matches!(prefix.record.step.as_str(), "cleanup" | "validated") {
            return Err(());
        }
        Ok(guard)
    }

    fn reopen_validated_to_ready(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
    ) -> Result<Self, ()> {
        let guard = Self::open_selected_clean_prefix(
            destination,
            backup_path,
            controller,
            backup_identity,
            profile,
            true,
            false,
        )?;
        guard.open_restored_readiness_prefix()?;
        Ok(guard)
    }

    fn expected_ready(&self, completed_at: i64) -> RestoreReady {
        RestoreReady {
            schema: "kapsel.sandbox.restore-ready.v1".to_owned(),
            source: "restored".to_owned(),
            generation: Some(self.manifest.generation),
            manifest_sha256: Some(self.manifest_sha256.clone()),
            compatibility_sha256: self.manifest.compatibility_sha256.clone(),
            completed_at,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the three accepted readiness inventories are validated as one closed prefix"
    )]
    fn open_restored_readiness_prefix(&self) -> Result<RestoredReadinessPrefix, ()> {
        self.verify(true, false)?;
        let root = directory_at(
            &self.destination_parent,
            &self.destination_name,
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        same(&root, self.destination_state.as_ref().ok_or(())?)?;
        let actual = names(&root, 8)?;
        let base = [DATABASE, DEPLOYMENT, LOCK, "receipts", "runner"]
            .into_iter()
            .map(OsString::from)
            .collect::<BTreeSet<_>>();
        let has_incomplete = actual.contains(std::ffi::OsStr::new(RESTORE_INCOMPLETE));
        let has_ready = actual.contains(std::ffi::OsStr::new(RESTORE_READY));
        let has_temporary = actual.contains(std::ffi::OsStr::new(RESTORE_STATE_TEMPORARY));
        let mut expected = base;
        match (has_incomplete, has_ready, has_temporary) {
            (true, false, temporary) => {
                expected.insert(OsString::from(RESTORE_INCOMPLETE));
                if temporary {
                    expected.insert(OsString::from(RESTORE_STATE_TEMPORARY));
                }
            },
            (true, true, false) => {
                expected.insert(OsString::from(RESTORE_INCOMPLETE));
                expected.insert(OsString::from(RESTORE_READY));
            },
            (false, true, false) => {
                expected.insert(OsString::from(RESTORE_READY));
            },
            _ => return Err(()),
        }
        if actual != expected {
            return Err(());
        }
        file_at(
            &root,
            DATABASE,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            DATABASE_MAX,
        )?;
        let deployment = file_at(
            &root,
            DEPLOYMENT,
            self.controller.uid,
            self.controller.gid,
            0o400,
            false,
            16 * 1024,
        )?;
        let state_lock = file_at(
            &root,
            LOCK,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            0,
        )?;
        same(&state_lock, self.destination_state_lock.as_ref().ok_or(())?)?;
        let receipts = directory_at(
            &root,
            "receipts",
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        let runner = directory_at(
            &root,
            "runner",
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        if !names(&receipts, 1)?.is_empty()
            || !names(&runner, 1)?.is_empty()
            || read_bounded(&deployment, 16 * 1024)? != read_bounded(&self.deployment, 16 * 1024)?
            || !Service::preflight_clean_restored_source(
                &self.destination_path.join(DATABASE),
                self.manifest.generation,
                self.manifest.captured_at,
                Some(&self.manifest_sha256),
            )
            .map_err(|_| ())?
        {
            return Err(());
        }
        let (incomplete, incomplete_record) = if has_incomplete {
            let file = file_at(
                &root,
                RESTORE_INCOMPLETE,
                self.controller.uid,
                self.controller.gid,
                0o600,
                true,
                1024,
            )?;
            let bytes = read_bounded(&file, 1024)?;
            let record: RestoreIncomplete = serde_json::from_slice(&bytes).map_err(|_| ())?;
            if serde_json::to_vec(&record).map_err(|_| ())? != bytes
                || record.schema != "kapsel.sandbox.restore-incomplete.v1"
                || record.generation != self.manifest.generation
                || record.manifest_sha256 != self.manifest_sha256
                || record.compatibility_sha256 != self.manifest.compatibility_sha256
                || record.started_at < self.manifest.captured_at
                || record.step != "validated"
            {
                return Err(());
            }
            (Some(file), Some(record))
        } else {
            (None, None)
        };
        let (ready, ready_record) = if has_ready {
            let file = file_at(
                &root,
                RESTORE_READY,
                self.controller.uid,
                self.controller.gid,
                0o600,
                true,
                1024,
            )?;
            let bytes = read_bounded(&file, 1024)?;
            let record: RestoreReady = serde_json::from_slice(&bytes).map_err(|_| ())?;
            if serde_json::to_vec(&record).map_err(|_| ())? != bytes
                || record.schema != "kapsel.sandbox.restore-ready.v1"
                || record.source != "restored"
                || record.generation != Some(self.manifest.generation)
                || record.manifest_sha256.as_deref() != Some(self.manifest_sha256.as_str())
                || record.compatibility_sha256 != self.manifest.compatibility_sha256
                || record.completed_at < self.manifest.captured_at
                || incomplete_record
                    .as_ref()
                    .is_some_and(|old| record.completed_at != old.started_at)
            {
                return Err(());
            }
            (Some(file), Some(record))
        } else {
            (None, None)
        };
        let temporary = if has_temporary {
            let file = file_at(
                &root,
                RESTORE_STATE_TEMPORARY,
                self.controller.uid,
                self.controller.gid,
                0o600,
                true,
                1024,
            )?;
            let completed_at = incomplete_record.as_ref().ok_or(())?.started_at;
            let expected_bytes =
                serde_json::to_vec(&self.expected_ready(completed_at)).map_err(|_| ())?;
            let bytes = read_bounded(&file, 1024)?;
            if bytes.len() > expected_bytes.len() || !expected_bytes.starts_with(&bytes) {
                return Err(());
            }
            Some(file)
        } else {
            None
        };
        Ok(RestoredReadinessPrefix {
            root,
            incomplete,
            ready,
            temporary,
            incomplete_record,
            ready_record,
        })
    }

    fn open_restored_clean_prefix(
        &self,
        transition: RestoreTransition,
    ) -> Result<RestoredCleanPrefix, ()> {
        self.verify(true, false)?;
        let root = directory_at(
            &self.destination_parent,
            &self.destination_name,
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        same(&root, self.destination_state.as_ref().ok_or(())?)?;
        let base_names = [
            DATABASE,
            DEPLOYMENT,
            LOCK,
            RESTORE_INCOMPLETE,
            "receipts",
            "runner",
        ];
        let mut expected = base_names
            .into_iter()
            .map(OsString::from)
            .collect::<BTreeSet<_>>();
        let actual = names(&root, 8)?;
        let has_temporary = actual.contains(std::ffi::OsStr::new(RESTORE_STATE_TEMPORARY));
        if has_temporary {
            expected.insert(OsString::from(RESTORE_STATE_TEMPORARY));
        }
        if actual != expected {
            return Err(());
        }
        let database = file_at(
            &root,
            DATABASE,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            DATABASE_MAX,
        )?;
        let deployment = file_at(
            &root,
            DEPLOYMENT,
            self.controller.uid,
            self.controller.gid,
            0o400,
            false,
            16 * 1024,
        )?;
        let state_lock = file_at(
            &root,
            LOCK,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            0,
        )?;
        same(&state_lock, self.destination_state_lock.as_ref().ok_or(())?)?;
        let incomplete = file_at(
            &root,
            RESTORE_INCOMPLETE,
            self.controller.uid,
            self.controller.gid,
            0o600,
            true,
            1024,
        )?;
        let receipts = directory_at(
            &root,
            "receipts",
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        let runner = directory_at(
            &root,
            "runner",
            self.controller.uid,
            self.controller.gid,
            0o700,
        )?;
        if !names(&receipts, 1)?.is_empty()
            || !names(&runner, 1)?.is_empty()
            || read_bounded(&deployment, 16 * 1024)? != read_bounded(&self.deployment, 16 * 1024)?
        {
            return Err(());
        }
        let record_bytes = read_bounded(&incomplete, 1024)?;
        let record: RestoreIncomplete = serde_json::from_slice(&record_bytes).map_err(|_| ())?;
        if serde_json::to_vec(&record).map_err(|_| ())? != record_bytes
            || record.schema != "kapsel.sandbox.restore-incomplete.v1"
            || record.generation != self.manifest.generation
            || record.manifest_sha256 != self.manifest_sha256
            || record.compatibility_sha256 != self.manifest.compatibility_sha256
            || record.started_at < self.manifest.captured_at
        {
            return Err(());
        }
        let (current_step, next_step) = transition.steps();
        if record.step != current_step && record.step != next_step {
            return Err(());
        }
        let current_publication = Service::preflight_clean_restored_source(
            &self.destination_path.join(DATABASE),
            self.manifest.generation,
            self.manifest.captured_at,
            Some(&self.manifest_sha256),
        )
        .map_err(|_| ())?;
        if record.step == next_step && (!current_publication || has_temporary) {
            return Err(());
        }
        if current_step == "stopped" && !current_publication {
            return Err(());
        }
        let expected_next = RestoreIncomplete {
            step: next_step.to_owned(),
            ..record.clone()
        };
        let expected_next_bytes = serde_json::to_vec(&expected_next).map_err(|_| ())?;
        let temporary = if has_temporary {
            if record.step != current_step || !current_publication {
                return Err(());
            }
            let file = file_at(
                &root,
                RESTORE_STATE_TEMPORARY,
                self.controller.uid,
                self.controller.gid,
                0o600,
                true,
                1024,
            )?;
            let bytes = read_bounded(&file, 1024)?;
            if bytes.len() > expected_next_bytes.len() || !expected_next_bytes.starts_with(&bytes) {
                return Err(());
            }
            Some(file)
        } else {
            None
        };
        Ok(RestoredCleanPrefix {
            root,
            database,
            deployment,
            receipts,
            runner,
            state_lock,
            incomplete,
            temporary,
            record,
            current_publication,
        })
    }

    fn publish_clean_restore_step<Barrier>(
        &self,
        mut prefix: RestoredCleanPrefix,
        transition: RestoreTransition,
        next_bytes: &[u8],
        mut barrier: Barrier,
    ) -> Result<RestoredCleanPrefix, ()>
    where
        Barrier: FnMut(CleanStepPublicationBarrier) -> Result<(), ()>,
    {
        let (_, next_step) = transition.steps();
        if prefix.record.step == next_step {
            let pinned_incomplete = prefix.incomplete.try_clone().map_err(|_| ())?;
            prefix.root.sync_all().map_err(|_| ())?;
            let synced = self.open_restored_clean_prefix(transition)?;
            same(&synced.incomplete, &pinned_incomplete)?;
            barrier(CleanStepPublicationBarrier::StateRootSynced)?;
            return Ok(synced);
        }

        let mut pinned_temporary = prefix
            .temporary
            .as_ref()
            .map(File::try_clone)
            .transpose()
            .map_err(|_| ())?;
        if let Some(temporary) = prefix.temporary.take() {
            let pinned = pinned_temporary.as_ref().ok_or(())?;
            same(&temporary, pinned)?;
            if read_bounded(pinned, 1024)? != next_bytes {
                let cleanup = self.open_restored_clean_prefix(transition)?;
                same(cleanup.temporary.as_ref().ok_or(())?, pinned)?;
                rustix::fs::unlinkat(
                    &cleanup.root,
                    RESTORE_STATE_TEMPORARY,
                    rustix::fs::AtFlags::empty(),
                )
                .map_err(|_| ())?;
                if pinned.metadata().map_err(|_| ())?.nlink() != 0 {
                    return Err(());
                }
                cleanup.root.sync_all().map_err(|_| ())?;
                pinned_temporary = None;
            }
        }
        if pinned_temporary.is_none() {
            pinned_temporary = Some(write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                next_bytes,
                self.controller,
                1024,
            )?);
            barrier(CleanStepPublicationBarrier::TemporarySynced)?;
        }
        let pinned_temporary = pinned_temporary.as_ref().ok_or(())?;
        if read_bounded(pinned_temporary, 1024)? != next_bytes {
            return Err(());
        }

        let publication = self.open_restored_clean_prefix(transition)?;
        let named_temporary = publication.temporary.as_ref().ok_or(())?;
        same(named_temporary, pinned_temporary)?;
        if read_bounded(named_temporary, 1024)? != next_bytes {
            return Err(());
        }
        renameat(
            &publication.root,
            RESTORE_STATE_TEMPORARY,
            &publication.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(CleanStepPublicationBarrier::Renamed)?;

        let renamed = self.open_restored_clean_prefix(transition)?;
        same(&renamed.incomplete, pinned_temporary)?;
        renamed.root.sync_all().map_err(|_| ())?;
        let synced = self.open_restored_clean_prefix(transition)?;
        same(&synced.incomplete, pinned_temporary)?;
        barrier(CleanStepPublicationBarrier::StateRootSynced)?;
        Ok(synced)
    }

    fn advance_installed_to_stopped_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreStopBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
        if prefix.record.step == "stopped" {
            let stopped_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::InstalledToStopped,
                &stopped_bytes,
                |phase| barrier(map_stop_publication_barrier(phase)),
            )?;
            return Ok(());
        }
        if !prefix.current_publication {
            barrier(RestoreStopBarrier::BeforePublication)?;
            let selected = BackupPublication {
                generation: self.manifest.generation,
                captured_at: self.manifest.captured_at,
                authorities: Vec::new(),
                predecessor: None,
            };
            let service = crate::StoppedBackupService::open_restored(
                &self.destination_path.join(DATABASE),
                &self.destination_path.join("receipts"),
                authority,
            )
            .map_err(|_| ())?;
            service
                .restore_publication(&selected, &self.manifest_sha256)
                .map_err(|_| ())?;
            drop(service);
            barrier(RestoreStopBarrier::AfterPublication)?;
            prefix = self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
            if !prefix.current_publication || prefix.record.step != "installed" {
                return Err(());
            }
        }
        let stopped = RestoreIncomplete {
            step: "stopped".to_owned(),
            ..prefix.record.clone()
        };
        let stopped_bytes = serde_json::to_vec(&stopped).map_err(|_| ())?;
        let stopped_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::InstalledToStopped,
            &stopped_bytes,
            |phase| barrier(map_stop_publication_barrier(phase)),
        )?;
        if stopped_prefix.record.step != "stopped" || !stopped_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_stopped_to_expired_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreExpiryBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
        if prefix.record.step == "expired" {
            let expired_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::StoppedToExpired,
                &expired_bytes,
                |phase| barrier(map_expiry_publication_barrier(phase)),
            )?;
            return Ok(());
        }
        let service = crate::StoppedBackupService::open_restored(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service
            .apply_restore_expiry_with_barrier(prefix.record.started_at, |phase| {
                let phase = match phase {
                    ExpiryTransactionBarrier::BeforeCommit => {
                        RestoreExpiryBarrier::BeforeExpiryCommit
                    },
                    ExpiryTransactionBarrier::AfterCommit => {
                        RestoreExpiryBarrier::AfterExpiryCommit
                    },
                };
                barrier(phase).map_err(|()| crate::ServiceError::Unavailable)
            })
            .map_err(|_| ())?;
        drop(service);
        prefix = self.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
        if prefix.record.step != "stopped" || !prefix.current_publication {
            return Err(());
        }
        let expired = RestoreIncomplete {
            step: "expired".to_owned(),
            ..prefix.record.clone()
        };
        let expired_bytes = serde_json::to_vec(&expired).map_err(|_| ())?;
        let expired_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::StoppedToExpired,
            &expired_bytes,
            |phase| barrier(map_expiry_publication_barrier(phase)),
        )?;
        if expired_prefix.record.step != "expired" || !expired_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_expired_to_receipts_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreReceiptBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
        if prefix.record.step == "receipts" {
            let receipts_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::ExpiredToReceipts,
                &receipts_bytes,
                |phase| {
                    barrier(match phase {
                        CleanStepPublicationBarrier::TemporarySynced => {
                            RestoreReceiptBarrier::AfterTemporarySync
                        },
                        CleanStepPublicationBarrier::Renamed => RestoreReceiptBarrier::AfterRename,
                        CleanStepPublicationBarrier::StateRootSynced => {
                            RestoreReceiptBarrier::AfterStateRootSync
                        },
                    })
                },
            )?;
            return Ok(());
        }
        barrier(RestoreReceiptBarrier::BeforeConvergence)?;
        let service = crate::StoppedBackupService::open_restored(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service.converge_clean_restore_receipts().map_err(|_| ())?;
        drop(service);
        barrier(RestoreReceiptBarrier::AfterConvergence)?;
        prefix = self.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
        if prefix.record.step != "expired" || !prefix.current_publication {
            return Err(());
        }
        let receipts = RestoreIncomplete {
            step: "receipts".to_owned(),
            ..prefix.record.clone()
        };
        let receipts_bytes = serde_json::to_vec(&receipts).map_err(|_| ())?;
        let receipts_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::ExpiredToReceipts,
            &receipts_bytes,
            |phase| {
                barrier(match phase {
                    CleanStepPublicationBarrier::TemporarySynced => {
                        RestoreReceiptBarrier::AfterTemporarySync
                    },
                    CleanStepPublicationBarrier::Renamed => RestoreReceiptBarrier::AfterRename,
                    CleanStepPublicationBarrier::StateRootSynced => {
                        RestoreReceiptBarrier::AfterStateRootSync
                    },
                })
            },
        )?;
        if receipts_prefix.record.step != "receipts" || !receipts_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_receipts_to_runner_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreRunnerBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
        if prefix.record.step == "runner" {
            let runner_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::ReceiptsToRunner,
                &runner_bytes,
                |phase| {
                    barrier(match phase {
                        CleanStepPublicationBarrier::TemporarySynced => {
                            RestoreRunnerBarrier::AfterTemporarySync
                        },
                        CleanStepPublicationBarrier::Renamed => RestoreRunnerBarrier::AfterRename,
                        CleanStepPublicationBarrier::StateRootSynced => {
                            RestoreRunnerBarrier::AfterStateRootSync
                        },
                    })
                },
            )?;
            return Ok(());
        }
        let identities = match self.profile {
            crate::state_root::DeploymentProfile::Production => {
                crate::state_root::RoleIdentities::controller()
            },
            #[cfg(any(test, feature = "state-root-test-harness"))]
            crate::state_root::DeploymentProfile::Test => {
                crate::state_root::RoleIdentities::test_controller()
            },
        };
        barrier(RestoreRunnerBarrier::BeforeReconstruction)?;
        let service = crate::StoppedBackupService::open_restored(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service
            .reconstruct_clean_restore_runner(&prefix.runner, identities)
            .map_err(|_| ())?;
        barrier(RestoreRunnerBarrier::AfterReconstruction)?;
        barrier(RestoreRunnerBarrier::BeforeReconciliation)?;
        service
            .reconcile_clean_restore_operation()
            .map_err(|_| ())?;
        drop(service);
        barrier(RestoreRunnerBarrier::AfterReconciliation)?;
        prefix = self.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
        if prefix.record.step != "receipts" || !prefix.current_publication {
            return Err(());
        }
        let runner = RestoreIncomplete {
            step: "runner".to_owned(),
            ..prefix.record.clone()
        };
        let runner_bytes = serde_json::to_vec(&runner).map_err(|_| ())?;
        let runner_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::ReceiptsToRunner,
            &runner_bytes,
            |phase| {
                barrier(match phase {
                    CleanStepPublicationBarrier::TemporarySynced => {
                        RestoreRunnerBarrier::AfterTemporarySync
                    },
                    CleanStepPublicationBarrier::Renamed => RestoreRunnerBarrier::AfterRename,
                    CleanStepPublicationBarrier::StateRootSynced => {
                        RestoreRunnerBarrier::AfterStateRootSync
                    },
                })
            },
        )?;
        if runner_prefix.record.step != "runner" || !runner_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_runner_to_lease_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreLeaseBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        if prefix.record.step == "lease" {
            let lease_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::RunnerToLease,
                &lease_bytes,
                |phase| {
                    barrier(match phase {
                        CleanStepPublicationBarrier::TemporarySynced => {
                            RestoreLeaseBarrier::AfterTemporarySync
                        },
                        CleanStepPublicationBarrier::Renamed => RestoreLeaseBarrier::AfterRename,
                        CleanStepPublicationBarrier::StateRootSynced => {
                            RestoreLeaseBarrier::AfterStateRootSync
                        },
                    })
                },
            )?;
            return Ok(());
        }
        barrier(RestoreLeaseBarrier::BeforePublicationFixedPoint)?;
        let service = crate::StoppedBackupService::open_restored_lease_fixed_point(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service
            .converge_clean_restore_lease_publication()
            .map_err(|_| ())?;
        drop(service);
        barrier(RestoreLeaseBarrier::AfterPublicationFixedPoint)?;
        prefix = self.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        if prefix.record.step != "runner" || !prefix.current_publication {
            return Err(());
        }
        let lease = RestoreIncomplete {
            step: "lease".to_owned(),
            ..prefix.record.clone()
        };
        let lease_bytes = serde_json::to_vec(&lease).map_err(|_| ())?;
        let lease_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::RunnerToLease,
            &lease_bytes,
            |phase| {
                barrier(match phase {
                    CleanStepPublicationBarrier::TemporarySynced => {
                        RestoreLeaseBarrier::AfterTemporarySync
                    },
                    CleanStepPublicationBarrier::Renamed => RestoreLeaseBarrier::AfterRename,
                    CleanStepPublicationBarrier::StateRootSynced => {
                        RestoreLeaseBarrier::AfterStateRootSync
                    },
                })
            },
        )?;
        if lease_prefix.record.step != "lease" || !lease_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_lease_to_cleanup_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreCleanupBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::LeaseToCleanup)?;
        if prefix.record.step == "cleanup" {
            let cleanup_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::LeaseToCleanup,
                &cleanup_bytes,
                |phase| {
                    barrier(match phase {
                        CleanStepPublicationBarrier::TemporarySynced => {
                            RestoreCleanupBarrier::AfterTemporarySync
                        },
                        CleanStepPublicationBarrier::Renamed => RestoreCleanupBarrier::AfterRename,
                        CleanStepPublicationBarrier::StateRootSynced => {
                            RestoreCleanupBarrier::AfterStateRootSync
                        },
                    })
                },
            )?;
            return Ok(());
        }
        barrier(RestoreCleanupBarrier::BeforeCleanupFixedPoint)?;
        let service = crate::StoppedBackupService::open_restored_cleanup_fixed_point(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service.converge_clean_restore_cleanup().map_err(|_| ())?;
        drop(service);
        barrier(RestoreCleanupBarrier::AfterCleanupFixedPoint)?;
        prefix = self.open_restored_clean_prefix(RestoreTransition::LeaseToCleanup)?;
        if prefix.record.step != "lease" || !prefix.current_publication {
            return Err(());
        }
        let cleanup = RestoreIncomplete {
            step: "cleanup".to_owned(),
            ..prefix.record.clone()
        };
        let cleanup_bytes = serde_json::to_vec(&cleanup).map_err(|_| ())?;
        let cleanup_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::LeaseToCleanup,
            &cleanup_bytes,
            |phase| {
                barrier(match phase {
                    CleanStepPublicationBarrier::TemporarySynced => {
                        RestoreCleanupBarrier::AfterTemporarySync
                    },
                    CleanStepPublicationBarrier::Renamed => RestoreCleanupBarrier::AfterRename,
                    CleanStepPublicationBarrier::StateRootSynced => {
                        RestoreCleanupBarrier::AfterStateRootSync
                    },
                })
            },
        )?;
        if cleanup_prefix.record.step != "cleanup" || !cleanup_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_cleanup_to_validated_with_barrier<F>(
        &self,
        authority: &AuthorityConfiguration,
        mut barrier: F,
    ) -> Result<(), ()>
    where
        F: FnMut(RestoreValidationBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_clean_prefix(RestoreTransition::CleanupToValidated)?;
        if prefix.record.step == "validated" {
            let validated_bytes = serde_json::to_vec(&prefix.record).map_err(|_| ())?;
            self.publish_clean_restore_step(
                prefix,
                RestoreTransition::CleanupToValidated,
                &validated_bytes,
                |phase| {
                    barrier(match phase {
                        CleanStepPublicationBarrier::TemporarySynced => {
                            RestoreValidationBarrier::AfterTemporarySync
                        },
                        CleanStepPublicationBarrier::Renamed => {
                            RestoreValidationBarrier::AfterRename
                        },
                        CleanStepPublicationBarrier::StateRootSynced => {
                            RestoreValidationBarrier::AfterStateRootSync
                        },
                    })
                },
            )?;
            return Ok(());
        }
        let identities = match self.profile {
            crate::state_root::DeploymentProfile::Production => {
                crate::state_root::RoleIdentities::controller()
            },
            #[cfg(any(test, feature = "state-root-test-harness"))]
            crate::state_root::DeploymentProfile::Test => {
                crate::state_root::RoleIdentities::test_controller()
            },
        };
        barrier(RestoreValidationBarrier::BeforeValidationFixedPoint)?;
        let service = crate::StoppedBackupService::open_restored_validation_fixed_point(
            &self.destination_path.join(DATABASE),
            &self.destination_path.join("receipts"),
            authority,
        )
        .map_err(|_| ())?;
        service
            .validate_clean_restore_uniqueness_and_references(&prefix.runner, identities)
            .map_err(|_| ())?;
        drop(service);
        barrier(RestoreValidationBarrier::AfterValidationFixedPoint)?;
        prefix = self.open_restored_clean_prefix(RestoreTransition::CleanupToValidated)?;
        if prefix.record.step != "cleanup" || !prefix.current_publication {
            return Err(());
        }
        let validated = RestoreIncomplete {
            step: "validated".to_owned(),
            ..prefix.record.clone()
        };
        let validated_bytes = serde_json::to_vec(&validated).map_err(|_| ())?;
        let validated_prefix = self.publish_clean_restore_step(
            prefix,
            RestoreTransition::CleanupToValidated,
            &validated_bytes,
            |phase| {
                barrier(match phase {
                    CleanStepPublicationBarrier::TemporarySynced => {
                        RestoreValidationBarrier::AfterTemporarySync
                    },
                    CleanStepPublicationBarrier::Renamed => RestoreValidationBarrier::AfterRename,
                    CleanStepPublicationBarrier::StateRootSynced => {
                        RestoreValidationBarrier::AfterStateRootSync
                    },
                })
            },
        )?;
        if validated_prefix.record.step != "validated" || !validated_prefix.current_publication {
            return Err(());
        }
        Ok(())
    }

    fn advance_validated_to_ready_with_barrier<F>(&self, mut barrier: F) -> Result<(), ()>
    where
        F: FnMut(RestoreReadinessBarrier) -> Result<(), ()>,
    {
        let mut prefix = self.open_restored_readiness_prefix()?;
        let ready_bytes = if let Some(incomplete) = prefix.incomplete_record.as_ref() {
            serde_json::to_vec(&self.expected_ready(incomplete.started_at)).map_err(|_| ())?
        } else {
            serde_json::to_vec(prefix.ready_record.as_ref().ok_or(())?).map_err(|_| ())?
        };
        let pinned_incomplete = prefix
            .incomplete
            .as_ref()
            .map(File::try_clone)
            .transpose()
            .map_err(|_| ())?;
        let mut pinned_ready = prefix
            .ready
            .as_ref()
            .map(File::try_clone)
            .transpose()
            .map_err(|_| ())?;
        if let Some(ready) = prefix.ready.as_ref() {
            if read_bounded(ready, 1024)? != ready_bytes {
                return Err(());
            }
        }
        if prefix.ready.is_none() {
            let mut pinned_temporary = None;
            if let Some(temporary) = prefix.temporary.take() {
                let bytes = read_bounded(&temporary, 1024)?;
                if bytes == ready_bytes {
                    pinned_temporary = Some(temporary);
                } else {
                    let reopened = file_at(
                        &prefix.root,
                        RESTORE_STATE_TEMPORARY,
                        self.controller.uid,
                        self.controller.gid,
                        0o600,
                        true,
                        1024,
                    )?;
                    same(&reopened, &temporary)?;
                    drop(reopened);
                    drop(temporary);
                    rustix::fs::unlinkat(
                        &prefix.root,
                        RESTORE_STATE_TEMPORARY,
                        rustix::fs::AtFlags::empty(),
                    )
                    .map_err(|_| ())?;
                    prefix.root.sync_all().map_err(|_| ())?;
                }
            }
            if !names(&prefix.root, 8)?.contains(std::ffi::OsStr::new(RESTORE_STATE_TEMPORARY)) {
                pinned_temporary = Some(write_restored_file(
                    &prefix.root,
                    RESTORE_STATE_TEMPORARY,
                    &ready_bytes,
                    self.controller,
                    1024,
                )?);
                barrier(RestoreReadinessBarrier::AfterTemporarySync)?;
            }
            prefix = self.open_restored_readiness_prefix()?;
            let temporary = prefix.temporary.as_ref().ok_or(())?;
            let pinned_temporary = pinned_temporary.as_ref().ok_or(())?;
            same(temporary, pinned_temporary)?;
            if read_bounded(temporary, 1024)? != ready_bytes {
                return Err(());
            }
            match (&prefix.incomplete, &pinned_incomplete) {
                (Some(reopened), Some(pinned)) => same(reopened, pinned)?,
                _ => return Err(()),
            }
            pinned_ready = Some(pinned_temporary.try_clone().map_err(|_| ())?);
            renameat(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &prefix.root,
                RESTORE_READY,
            )
            .map_err(|_| ())?;
            barrier(RestoreReadinessBarrier::AfterReadyRename)?;
            prefix = self.open_restored_readiness_prefix()?;
        }
        let verify_publication = |prefix: &RestoredReadinessPrefix| -> Result<(), ()> {
            let ready = prefix.ready.as_ref().ok_or(())?;
            same(ready, pinned_ready.as_ref().ok_or(())?)?;
            if read_bounded(ready, 1024)? != ready_bytes {
                return Err(());
            }
            match (&prefix.incomplete, &pinned_incomplete) {
                (Some(reopened), Some(pinned)) => same(reopened, pinned),
                (None, None | Some(_)) => Ok(()),
                _ => Err(()),
            }
        };
        verify_publication(&prefix)?;
        if prefix.incomplete.is_some() {
            if prefix.temporary.is_some()
                || prefix.incomplete_record.is_none()
                || prefix.ready_record.is_none()
            {
                return Err(());
            }
            prefix.root.sync_all().map_err(|_| ())?;
            barrier(RestoreReadinessBarrier::AfterPairSync)?;
            prefix = self.open_restored_readiness_prefix()?;
            verify_publication(&prefix)?;
            if prefix.incomplete.is_none() {
                return Err(());
            }
            rustix::fs::unlinkat(
                &prefix.root,
                RESTORE_INCOMPLETE,
                rustix::fs::AtFlags::empty(),
            )
            .map_err(|_| ())?;
            barrier(RestoreReadinessBarrier::AfterIncompleteUnlink)?;
        }
        prefix = self.open_restored_readiness_prefix()?;
        verify_publication(&prefix)?;
        if prefix.incomplete.is_some()
            || prefix.temporary.is_some()
            || prefix.ready_record.is_none()
        {
            return Err(());
        }
        prefix.root.sync_all().map_err(|_| ())?;
        barrier(RestoreReadinessBarrier::AfterFinalStateSync)?;
        prefix = self.open_restored_readiness_prefix()?;
        verify_publication(&prefix)?;
        self.destination_parent.sync_all().map_err(|_| ())?;
        barrier(RestoreReadinessBarrier::AfterParentSync)?;
        prefix = self.open_restored_readiness_prefix()?;
        verify_publication(&prefix)?;
        Ok(())
    }
}

#[allow(
    dead_code,
    reason = "the generation publisher consumes this validated identity and pinned unit"
)]
pub(crate) struct ValidatedCleanGeneration<'guard, 'state> {
    pub(crate) generation: u64,
    pub(crate) captured_at: i64,
    pub(crate) manifest_sha256: String,
    pub(crate) compatibility_sha256: String,
    name: String,
    guard: &'guard BackupRootGuard<'state>,
    generation_descriptor: File,
    service_descriptor: File,
    receipts_descriptor: File,
    runner_descriptor: File,
    trust_descriptor: File,
    database_descriptor: File,
    deployment_descriptor: File,
    manifest_descriptor: File,
    selected: bool,
    current_descriptor: Option<File>,
}

#[allow(
    dead_code,
    reason = "the generation publisher rechecks immediately before its transition"
)]
impl ValidatedCleanGeneration<'_, '_> {
    pub(crate) fn verify(&self) -> Result<(), ()> {
        let reopened = if self.selected {
            self.guard.validate_selected_clean_generation()?
        } else {
            self.guard.validate_clean_generation()?
        };
        if reopened.generation != self.generation
            || reopened.captured_at != self.captured_at
            || reopened.manifest_sha256 != self.manifest_sha256
            || reopened.compatibility_sha256 != self.compatibility_sha256
            || reopened.name != self.name
        {
            return Err(());
        }
        for (left, right) in [
            (&reopened.generation_descriptor, &self.generation_descriptor),
            (&reopened.service_descriptor, &self.service_descriptor),
            (&reopened.receipts_descriptor, &self.receipts_descriptor),
            (&reopened.runner_descriptor, &self.runner_descriptor),
            (&reopened.trust_descriptor, &self.trust_descriptor),
            (&reopened.database_descriptor, &self.database_descriptor),
            (&reopened.deployment_descriptor, &self.deployment_descriptor),
            (&reopened.manifest_descriptor, &self.manifest_descriptor),
        ] {
            same(left, right)?;
        }
        match (&reopened.current_descriptor, &self.current_descriptor) {
            (Some(left), Some(right)) => same(left, right),
            (None, None) => Ok(()),
            _ => Err(()),
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the closed generation inventory is deliberately explicit"
)]
fn revalidate_generation(
    guard: &BackupRootGuard<'_>,
    name: &str,
    generation: &File,
    service: &File,
    receipts: &File,
    runner: &File,
    trust: &File,
    database: &File,
    deployment: &File,
    manifest: &File,
    selected: bool,
    current_temporary: bool,
) -> Result<(), ()> {
    if current_temporary {
        guard.verify_publishing_root_inventory()?;
    } else {
        guard.verify_root_inventory(selected)?;
    }
    let identity = guard.identity;
    let reopened_generation =
        directory_at(&guard.generations, name, identity.uid, identity.gid, 0o500)?;
    same(&reopened_generation, generation)?;
    for (child_name, pinned) in [
        ("service", service),
        ("receipts", receipts),
        ("runner", runner),
        ("trust", trust),
    ] {
        let reopened = directory_at(
            &reopened_generation,
            child_name,
            identity.uid,
            identity.gid,
            0o500,
        )?;
        same(&reopened, pinned)?;
    }
    let reopened_database = file_at(
        service,
        DATABASE,
        identity.uid,
        identity.gid,
        0o400,
        false,
        DATABASE_MAX,
    )?;
    same(&reopened_database, database)?;
    for (file_name, pinned, maximum) in [
        (DEPLOYMENT, deployment, 16 * 1024),
        (MANIFEST, manifest, JSON_MAX),
    ] {
        let reopened = file_at(
            &reopened_generation,
            file_name,
            identity.uid,
            identity.gid,
            0o400,
            false,
            maximum,
        )?;
        same(&reopened, pinned)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CurrentRecord {
    schema: String,
    generation: u64,
    manifest_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    generation: u64,
    predecessor: Option<Predecessor>,
    captured_at: i64,
    stopped: bool,
    compatibility_sha256: String,
    authorities: Vec<Authority>,
    trust: Vec<Trust>,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Predecessor {
    generation: u64,
    manifest_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    generation: u64,
    manifest_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    generation: u64,
    key_id: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    kind: String,
    bytes: u64,
    sha256: String,
}

fn validate_manifest(
    manifest: &Manifest,
    generation: u64,
    deployment_snapshot: &DeploymentSnapshot,
    deployment: &File,
    database: &File,
) -> Result<(), ()> {
    if manifest.schema != "kapsel.sandbox.backup.v1"
        || manifest.generation != generation
        || manifest.predecessor.is_some()
        || manifest.captured_at <= 0
        || !manifest.stopped
        || manifest.compatibility_sha256 != deployment_snapshot.identity.compatibility_sha256
        || !manifest.authorities.is_empty()
        || !manifest.trust.is_empty()
    {
        return Err(());
    }
    let expected = [
        record(DEPLOYMENT, deployment, 16 * 1024)?,
        record("service/sandbox.sqlite3", database, DATABASE_MAX)?,
    ];
    if manifest.files.len() != expected.len() {
        return Err(());
    }
    for (actual, expected) in manifest.files.iter().zip(expected) {
        if actual.path != expected.path
            || actual.kind != "file"
            || actual.bytes != expected.bytes
            || actual.sha256 != expected.sha256
            || !valid_relative_path(&actual.path)
        {
            return Err(());
        }
    }
    Ok(())
}

fn record(path: &str, file: &File, maximum: u64) -> Result<ManifestFile, ()> {
    let length = file.metadata().map_err(|_| ())?.len();
    if length > maximum {
        return Err(());
    }
    Ok(ManifestFile {
        path: path.to_owned(),
        kind: "file".to_owned(),
        bytes: length,
        sha256: digest_file(file, maximum)?,
    })
}

fn valid_relative_path(path: &str) -> bool {
    path.len() <= 512
        && path.split('/').all(|component| {
            !component.is_empty()
                && component.len() <= 128
                && component
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn generation_number(name: &str) -> Result<u64, ()> {
    let digits = name.strip_prefix("backup-").ok_or(())?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let value = digits.parse::<u64>().map_err(|_| ())?;
    (value > 0).then_some(value).ok_or(())
}

fn remove_incomplete_initial_temporary(
    generations: &File,
    identity: BackupIdentity,
) -> Result<(), ()> {
    let temporary = directory_at(
        generations,
        GENERATION_TMP,
        identity.uid,
        identity.gid,
        0o700,
    )?;
    let allowed = [
        "service", "receipts", "runner", "trust", DEPLOYMENT, MANIFEST,
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<BTreeSet<_>>();
    let root_names = names(&temporary, 7)?;
    if !root_names.is_subset(&allowed) {
        return Err(());
    }
    for (directory_name, allowed_file) in [
        ("service", Some((DATABASE, DATABASE_MAX))),
        ("receipts", None),
        ("runner", None),
        ("trust", None),
    ] {
        if !root_names.contains(std::ffi::OsStr::new(directory_name)) {
            continue;
        }
        let directory = directory_at_modes(
            &temporary,
            directory_name,
            identity.uid,
            identity.gid,
            &[0o700, 0o500],
        )?;
        let child_names = names(&directory, 2)?;
        match allowed_file {
            Some((file_name, maximum)) => {
                let allowed_child = std::iter::once(OsString::from(file_name)).collect();
                if !child_names.is_subset(&allowed_child) {
                    return Err(());
                }
                if child_names.contains(std::ffi::OsStr::new(file_name)) {
                    file_at_modes(&directory, file_name, identity, &[0o600, 0o400], maximum)?;
                }
            },
            None if !child_names.is_empty() => return Err(()),
            None => {},
        }
    }
    for (file_name, maximum) in [(DEPLOYMENT, 16 * 1024), (MANIFEST, JSON_MAX)] {
        if root_names.contains(std::ffi::OsStr::new(file_name)) {
            file_at_modes(&temporary, file_name, identity, &[0o600, 0o400], maximum)?;
        }
    }
    for directory_name in ["service", "receipts", "runner", "trust"] {
        if !root_names.contains(std::ffi::OsStr::new(directory_name)) {
            continue;
        }
        let directory = directory_at_modes(
            &temporary,
            directory_name,
            identity.uid,
            identity.gid,
            &[0o700, 0o500],
        )?;
        fchmod(&directory, Mode::from_raw_mode(0o700)).map_err(|_| ())?;
        for child in names(&directory, 2)? {
            rustix::fs::unlinkat(&directory, &child, rustix::fs::AtFlags::empty())
                .map_err(|_| ())?;
        }
        directory.sync_all().map_err(|_| ())?;
        rustix::fs::unlinkat(&temporary, directory_name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| ())?;
    }
    for file_name in [DEPLOYMENT, MANIFEST] {
        if root_names.contains(std::ffi::OsStr::new(file_name)) {
            rustix::fs::unlinkat(&temporary, file_name, rustix::fs::AtFlags::empty())
                .map_err(|_| ())?;
        }
    }
    temporary.sync_all().map_err(|_| ())?;
    rustix::fs::unlinkat(generations, GENERATION_TMP, rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|_| ())?;
    generations.sync_all().map_err(|_| ())
}

fn create_directory(parent: &File, name: &str, identity: BackupIdentity) -> Result<File, ()> {
    mkdirat(parent, name, Mode::from_raw_mode(0o700)).map_err(|_| ())?;
    directory_at(parent, name, identity.uid, identity.gid, 0o700)
}

fn write_new_file(
    parent: &File,
    name: &str,
    bytes: &[u8],
    identity: BackupIdentity,
    maximum: u64,
) -> Result<File, ()> {
    if u64::try_from(bytes.len()).map_err(|_| ())? > maximum {
        return Err(());
    }
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ())?,
    );
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    validate_file(&file, identity, 0o600, maximum)?;
    Ok(file)
}

fn write_restored_file(
    parent: &File,
    name: &str,
    bytes: &[u8],
    controller: BackupIdentity,
    maximum: u64,
) -> Result<File, ()> {
    if u64::try_from(bytes.len()).map_err(|_| ())? > maximum {
        return Err(());
    }
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ())?,
    );
    file.write_all(bytes).map_err(|_| ())?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(controller.uid)),
        Some(rustix::process::Gid::from_raw(controller.gid)),
    )
    .map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    validate_file(&file, controller, 0o600, maximum)?;
    Ok(file)
}

fn create_restore_installation_root<F>(
    parent: &File,
    helper: BackupIdentity,
    controller: BackupIdentity,
    barrier: &mut F,
) -> Result<File, ()>
where
    F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
{
    mkdirat(parent, RESTORE_TEMPORARY, Mode::from_raw_mode(0o700)).map_err(|_| ())?;
    let root = File::from(
        openat(
            parent,
            RESTORE_TEMPORARY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory(&root, helper.uid, helper.gid, 0o700)?;
    barrier(RestoreInstallBarrier::AfterTemporaryCreate)?;
    rustix::fs::fchown(
        &root,
        Some(rustix::process::Uid::from_raw(controller.uid)),
        Some(rustix::process::Gid::from_raw(controller.gid)),
    )
    .map_err(|_| ())?;
    validate_directory(&root, controller.uid, controller.gid, 0o700)?;
    barrier(RestoreInstallBarrier::AfterTemporaryOwnership)?;
    root.sync_all().map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterTemporaryInodeSync)?;
    parent.sync_all().map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterTemporaryParentSync)?;
    Ok(root)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the installation file state machine keeps every durable side explicit"
)]
fn install_restore_file<F>(
    parent: &File,
    name: &str,
    bytes: &[u8],
    helper: BackupIdentity,
    controller: BackupIdentity,
    final_mode: u32,
    maximum: u64,
    component: RestoreInstallComponent,
    barrier: &mut F,
) -> Result<File, ()>
where
    F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
{
    if u64::try_from(bytes.len()).map_err(|_| ())? > maximum {
        return Err(());
    }
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ())?,
    );
    validate_file(&file, helper, 0o600, maximum)?;
    barrier(RestoreInstallBarrier::AfterComponentCreate(component))?;
    parent.sync_all().map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentNamespaceSync(
        component,
    ))?;
    let split = bytes.len() / 2;
    if split > 0 && split < bytes.len() {
        file.write_all(&bytes[..split]).map_err(|_| ())?;
        barrier(RestoreInstallBarrier::AfterComponentPartialWrite(component))?;
        file.write_all(&bytes[split..]).map_err(|_| ())?;
    } else {
        file.write_all(bytes).map_err(|_| ())?;
    }
    barrier(RestoreInstallBarrier::AfterComponentWrite(component))?;
    file.sync_all().map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentContentSync(component))?;
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(controller.uid)),
        Some(rustix::process::Gid::from_raw(controller.gid)),
    )
    .map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentOwnership(component))?;
    let raw_mode = rustix::fs::RawMode::try_from(final_mode).map_err(|_| ())?;
    fchmod(&file, Mode::from_raw_mode(raw_mode)).map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentMode(component))?;
    file.sync_all().map_err(|_| ())?;
    validate_file(&file, controller, final_mode, maximum)?;
    barrier(RestoreInstallBarrier::AfterComponentFinalSync(component))?;
    Ok(file)
}

fn install_restore_directory<F>(
    parent: &File,
    name: &str,
    helper: BackupIdentity,
    controller: BackupIdentity,
    component: RestoreInstallComponent,
    barrier: &mut F,
) -> Result<File, ()>
where
    F: FnMut(RestoreInstallBarrier) -> Result<(), ()>,
{
    mkdirat(parent, name, Mode::from_raw_mode(0o700)).map_err(|_| ())?;
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory(&directory, helper.uid, helper.gid, 0o700)?;
    barrier(RestoreInstallBarrier::AfterComponentCreate(component))?;
    parent.sync_all().map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentNamespaceSync(
        component,
    ))?;
    rustix::fs::fchown(
        &directory,
        Some(rustix::process::Uid::from_raw(controller.uid)),
        Some(rustix::process::Gid::from_raw(controller.gid)),
    )
    .map_err(|_| ())?;
    barrier(RestoreInstallBarrier::AfterComponentOwnership(component))?;
    directory.sync_all().map_err(|_| ())?;
    validate_directory(&directory, controller.uid, controller.gid, 0o700)?;
    barrier(RestoreInstallBarrier::AfterComponentFinalSync(component))?;
    Ok(directory)
}

fn same_backup_identity(left: BackupIdentity, right: BackupIdentity) -> bool {
    left.uid == right.uid && left.gid == right.gid
}

fn open_installation_file(parent: &File, name: &str, maximum: u64) -> Result<File, ()> {
    let file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= maximum {
        Ok(file)
    } else {
        Err(())
    }
}

fn open_installation_directory(parent: &File, name: &str) -> Result<File, ()> {
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    directory
        .metadata()
        .map_err(|_| ())?
        .is_dir()
        .then_some(directory)
        .ok_or(())
}

fn reachable_installation_root_state(
    identity: BackupIdentity,
    mode: u32,
    empty: bool,
    helper: BackupIdentity,
    controller: BackupIdentity,
) -> bool {
    mode == 0o700
        && (same_backup_identity(identity, controller)
            || empty && same_backup_identity(identity, helper))
}

fn classify_installation_file_state(
    identity: BackupIdentity,
    mode: u32,
    complete: bool,
    helper: BackupIdentity,
    controller: BackupIdentity,
    final_mode: u32,
) -> Option<bool> {
    let helper_state = same_backup_identity(identity, helper) && mode == 0o600;
    let controller_state = same_backup_identity(identity, controller)
        && complete
        && (mode == 0o600 || mode == final_mode);
    (helper_state || controller_state)
        .then_some(complete && same_backup_identity(identity, controller) && mode == final_mode)
}

fn classify_installation_directory_state(
    identity: BackupIdentity,
    mode: u32,
    helper: BackupIdentity,
    controller: BackupIdentity,
) -> Option<bool> {
    (mode == 0o700
        && (same_backup_identity(identity, helper) || same_backup_identity(identity, controller)))
    .then_some(same_backup_identity(identity, controller))
}

fn validate_installation_file_state(
    file: &File,
    helper: BackupIdentity,
    controller: BackupIdentity,
    final_mode: u32,
    complete: bool,
) -> Result<bool, ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    classify_installation_file_state(
        BackupIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        },
        metadata.mode() & 0o7777,
        complete,
        helper,
        controller,
        final_mode,
    )
    .ok_or(())
}

fn validate_installation_directory_state(
    directory: &File,
    helper: BackupIdentity,
    controller: BackupIdentity,
) -> Result<bool, ()> {
    let metadata = directory.metadata().map_err(|_| ())?;
    classify_installation_directory_state(
        BackupIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        },
        metadata.mode() & 0o7777,
        helper,
        controller,
    )
    .ok_or(())
}

fn canonical_installed_record(
    bytes: &[u8],
    generation: u64,
    manifest_sha256: &str,
    compatibility_sha256: &str,
    captured_at: i64,
) -> Option<RestoreIncomplete> {
    let record = serde_json::from_slice::<RestoreIncomplete>(bytes).ok()?;
    (serde_json::to_vec(&record).ok()? == bytes
        && record.schema == "kapsel.sandbox.restore-incomplete.v1"
        && record.generation == generation
        && record.manifest_sha256 == manifest_sha256
        && record.compatibility_sha256 == compatibility_sha256
        && record.started_at >= captured_at
        && record.step == "installed")
        .then_some(record)
}

fn valid_installed_record_prefix(
    bytes: &[u8],
    generation: u64,
    manifest_sha256: &str,
    compatibility_sha256: &str,
    captured_at: i64,
) -> bool {
    let sample = RestoreIncomplete {
        schema: "kapsel.sandbox.restore-incomplete.v1".to_owned(),
        generation,
        manifest_sha256: manifest_sha256.to_owned(),
        compatibility_sha256: compatibility_sha256.to_owned(),
        started_at: 0,
        step: "installed".to_owned(),
    };
    let Ok(sample) = serde_json::to_vec(&sample) else {
        return false;
    };
    let marker = b"\"started_at\":0";
    let Some(marker_at) = sample
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return false;
    };
    let mut header = sample[..marker_at].to_vec();
    header.extend_from_slice(b"\"started_at\":");
    if header.starts_with(bytes) {
        return true;
    }
    let Some(tail) = bytes.strip_prefix(header.as_slice()) else {
        return false;
    };
    let digits = tail
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect::<Vec<_>>();
    if digits.is_empty() || digits.len() > 19 || digits[0] == b'0' {
        return false;
    }
    let Ok(digits_text) = std::str::from_utf8(&digits) else {
        return false;
    };
    let Ok(value) = digits_text.parse::<u128>() else {
        return false;
    };
    let Ok(captured_at) = u128::try_from(captured_at) else {
        return false;
    };
    let suffix = b",\"step\":\"installed\"}";
    let remainder = &tail[digits.len()..];
    if !remainder.is_empty() {
        return suffix.starts_with(remainder) && value <= i64::MAX as u128 && value >= captured_at;
    }
    (digits.len()..=19).any(|total| {
        let power = 10_u128.pow(u32::try_from(total - digits.len()).unwrap_or(0));
        let minimum = value.saturating_mul(power);
        let maximum = value
            .saturating_add(1)
            .saturating_mul(power)
            .saturating_sub(1)
            .min(i64::MAX as u128);
        minimum <= i64::MAX as u128 && maximum >= captured_at
    })
}

fn copy_file(
    source: &File,
    destination: &File,
    name: &str,
    identity: BackupIdentity,
    maximum: u64,
) -> Result<File, ()> {
    let bytes = read_bounded(source, maximum)?;
    write_new_file(destination, name, &bytes, identity, maximum)
}

fn directory_path(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<File, ()> {
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory(&file, uid, gid, mode)?;
    Ok(file)
}

fn directory_at(
    parent: &File,
    name: impl rustix::path::Arg,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<File, ()> {
    let file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    validate_directory(&file, uid, gid, mode)?;
    Ok(file)
}

fn directory_at_modes(
    parent: &File,
    name: impl rustix::path::Arg,
    uid: u32,
    gid: u32,
    modes: &[u32],
) -> Result<File, ()> {
    let file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && modes.contains(&(metadata.mode() & 0o7777))
    {
        Ok(file)
    } else {
        Err(())
    }
}

fn validate_directory(file: &File, uid: u32, gid: u32, mode: u32) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    (metadata.is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == mode)
        .then_some(())
        .ok_or(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the pure metadata seam keeps every hostile metadata field explicit"
)]
fn valid_file_metadata_fields(
    is_file: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    identity: BackupIdentity,
    expected_mode: u32,
    maximum: u64,
) -> bool {
    is_file
        && uid == identity.uid
        && gid == identity.gid
        && mode == expected_mode
        && links == 1
        && length <= maximum
}

fn validate_file(file: &File, identity: BackupIdentity, mode: u32, maximum: u64) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    valid_file_metadata_fields(
        metadata.is_file(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
        metadata.nlink(),
        metadata.len(),
        identity,
        mode,
        maximum,
    )
    .then_some(())
    .ok_or(())
}

fn file_at_modes(
    parent: &File,
    name: impl rustix::path::Arg,
    identity: BackupIdentity,
    modes: &[u32],
    maximum: u64,
) -> Result<File, ()> {
    let file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_file()
        && metadata.uid() == identity.uid
        && metadata.gid() == identity.gid
        && modes.contains(&(metadata.mode() & 0o7777))
        && metadata.nlink() == 1
        && metadata.len() <= maximum
    {
        Ok(file)
    } else {
        Err(())
    }
}

fn file_at(
    parent: &File,
    name: impl rustix::path::Arg,
    uid: u32,
    gid: u32,
    mode: u32,
    writable: bool,
    maximum: u64,
) -> Result<File, ()> {
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let file = File::from(
        openat(
            parent,
            name,
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    let maximum = if maximum == 0 { u64::MAX } else { maximum };
    validate_file(&file, BackupIdentity { uid, gid }, mode, maximum)?;
    Ok(file)
}

fn same(left: &File, right: &File) -> Result<(), ()> {
    (Identity::of(left)? == Identity::of(right)?)
        .then_some(())
        .ok_or(())
}

fn names(directory: &File, maximum: usize) -> Result<BTreeSet<OsString>, ()> {
    let mut reopened = directory.try_clone().map_err(|_| ())?;
    reopened.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut result = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(&reopened).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if result.len() == maximum {
            return Err(());
        }
        result.insert(OsString::from(name.to_str().map_err(|_| ())?));
    }
    Ok(result)
}

fn read_bounded(file: &File, maximum: u64) -> Result<Vec<u8>, ()> {
    let mut file = file.try_clone().map_err(|_| ())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    (u64::try_from(bytes.len()).map_err(|_| ())? <= maximum)
        .then_some(bytes)
        .ok_or(())
}

fn digest_file(file: &File, maximum: u64) -> Result<String, ()> {
    let mut file = file.try_clone().map_err(|_| ())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| ())?)
            .ok_or(())?;
        if total > maximum {
            return Err(());
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex(&digest.finalize()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
    };

    use super::*;
    use crate::{
        service_schema,
        state_root::{DeploymentProfile, RoleIdentities, StateInitializer},
        AuthorityConfiguration,
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    static INSTALLATION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn initialized(name: &str) -> (PathBuf, BackupStateGuard) {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "kapsel-backup-unit-{}-{name}-{id}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        mode(&base, 0o700);
        let state_parent = base.join("state-parent");
        fs::create_dir(&state_parent).unwrap();
        mode(&state_parent, 0o700);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state_parent.join(".kapsel-sandbox-restore.lock"))
            .unwrap();
        let identities = RoleIdentities::test_controller();
        let state_root = state_parent.join("state");
        let authority = AuthorityConfiguration::new(
            state_parent.join("unopened-authority"),
            identities.controller_uid,
            identities.controller_gid,
            identities.staging_uid,
            identities.staging_gid,
        );
        let initializer =
            StateInitializer::begin(&state_root, identities, &authority, DeploymentProfile::Test)
                .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(initializer.database().unwrap())
            .unwrap();
        initializer.publish(1_774_051_200).unwrap();
        let connection = rusqlite::Connection::open(state_root.join(DATABASE)).unwrap();
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
        let state =
            BackupStateGuard::open_clean(&state_root, identities, DeploymentProfile::Test).unwrap();
        (base, state)
    }

    fn reopen_state(base: &Path) -> BackupStateGuard {
        BackupStateGuard::open_capture(
            &base.join("state-parent/state"),
            RoleIdentities::test_controller(),
            DeploymentProfile::Test,
        )
        .unwrap()
    }

    fn initial_root(base: &Path) -> PathBuf {
        let parent = base.join("backup-parent");
        fs::create_dir(&parent).unwrap();
        mode(&parent, 0o700);
        let root = parent.join("backup");
        fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(LOCK))
            .unwrap();
        fs::create_dir(root.join(GENERATIONS)).unwrap();
        mode(&root.join(GENERATIONS), 0o700);
        root
    }

    fn mode(path: &Path, value: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
    }

    fn install_generation(root: &Path, state: &BackupStateGuard) -> PathBuf {
        let generation = root.join(GENERATIONS).join("backup-00000000000000000001");
        fs::create_dir(&generation).unwrap();
        for name in ["service", "receipts", "runner", "trust"] {
            fs::create_dir(generation.join(name)).unwrap();
        }
        let deployment = state.deployment_snapshot().unwrap();
        fs::write(generation.join(DEPLOYMENT), &deployment.bytes).unwrap();
        let state_database = root
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("state-parent/state")
            .join(DATABASE);
        fs::copy(state_database, generation.join("service").join(DATABASE)).unwrap();
        let deployment_file = File::open(generation.join(DEPLOYMENT)).unwrap();
        let database_file = File::open(generation.join("service").join(DATABASE)).unwrap();
        let manifest = Manifest {
            schema: "kapsel.sandbox.backup.v1".to_owned(),
            generation: 1,
            predecessor: None,
            captured_at: 1_774_051_201,
            stopped: true,
            compatibility_sha256: deployment.identity.compatibility_sha256,
            authorities: Vec::new(),
            trust: Vec::new(),
            files: vec![
                record(DEPLOYMENT, &deployment_file, 16 * 1024).unwrap(),
                record("service/sandbox.sqlite3", &database_file, DATABASE_MAX).unwrap(),
            ],
        };
        fs::write(
            generation.join(MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        for path in [
            generation.join(DEPLOYMENT),
            generation.join(MANIFEST),
            generation.join("service").join(DATABASE),
        ] {
            mode(&path, 0o400);
        }
        for name in ["service", "receipts", "runner", "trust"] {
            mode(&generation.join(name), 0o500);
        }
        mode(&generation, 0o500);
        generation
    }

    fn cleanup(base: &Path) {
        let generations = base.join("backup-parent/backup/generations");
        if let Ok(entries) = fs::read_dir(&generations) {
            for entry in entries.flatten() {
                writable_tree(&entry.path());
            }
        }
        let _ = fs::remove_dir_all(base);
    }

    fn writable_tree(path: &Path) {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    writable_tree(&entry.path());
                }
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TreeInventoryEntry {
        path: PathBuf,
        kind: &'static str,
        uid: u32,
        gid: u32,
        mode: u32,
        links: u64,
        bytes: Vec<u8>,
    }

    fn tree_inventory(root: &Path) -> Vec<TreeInventoryEntry> {
        fn visit(root: &Path, path: &Path, inventory: &mut Vec<TreeInventoryEntry>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            let kind = if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else if metadata.file_type().is_symlink() {
                "symlink"
            } else {
                "special"
            };
            let bytes = if metadata.is_file() {
                fs::read(path).unwrap()
            } else if metadata.file_type().is_symlink() {
                fs::read_link(path)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec()
            } else {
                Vec::new()
            };
            inventory.push(TreeInventoryEntry {
                path: path.strip_prefix(root).unwrap().to_owned(),
                kind,
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
                links: metadata.nlink(),
                bytes,
            });
            if metadata.is_dir() {
                let mut children = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                children.sort();
                for child in children {
                    visit(root, &child, inventory);
                }
            }
        }

        let mut inventory = Vec::new();
        visit(root, root, &mut inventory);
        inventory
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MatrixBarrier {
        BeforeSemantic,
        AfterSemantic,
        AfterTemporarySync,
        AfterRename,
        AfterStateRootSync,
    }

    struct CleanTransitionFixture {
        base: PathBuf,
        backup_root: PathBuf,
        authority_root: PathBuf,
        authority: AuthorityConfiguration,
        destination: PathBuf,
        source_root: PathBuf,
        source_inventory: Vec<TreeInventoryEntry>,
        selected_inventory: Vec<TreeInventoryEntry>,
    }

    fn clean_transition_fixture(name: &str) -> CleanTransitionFixture {
        let (base, state) = initialized(name);
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);
        let source_root = base.join("state-parent/state");
        let source_inventory = tree_inventory(&source_root);
        let selected_inventory = tree_inventory(&backup_root);
        let restore_parent = base.join("matrix-restore-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        CleanTransitionFixture {
            base,
            backup_root,
            authority_root,
            authority,
            destination,
            source_root,
            source_inventory,
            selected_inventory,
        }
    }

    fn reopen_matrix_transition(
        fixture: &CleanTransitionFixture,
        transition: RestoreTransition,
    ) -> Result<RestoreGuard, ()> {
        let controller = BackupIdentity::current_process();
        let backup = BackupIdentity::current_process();
        match transition {
            RestoreTransition::InstalledToStopped => RestoreGuard::reopen_installed_to_stopped(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::StoppedToExpired => RestoreGuard::reopen_stopped_to_expired(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::ExpiredToReceipts => RestoreGuard::reopen_expired_to_receipts(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::ReceiptsToRunner => RestoreGuard::reopen_receipts_to_runner(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::RunnerToLease => RestoreGuard::reopen_runner_to_lease(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::LeaseToCleanup => RestoreGuard::reopen_lease_to_cleanup(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
            RestoreTransition::CleanupToValidated => RestoreGuard::reopen_cleanup_to_validated(
                &fixture.destination,
                &fixture.backup_root,
                controller,
                backup,
                DeploymentProfile::Test,
            ),
        }
    }

    fn stop_matrix_barrier(actual: MatrixBarrier, target: Option<MatrixBarrier>) -> Result<(), ()> {
        (target != Some(actual)).then_some(()).ok_or(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table dispatcher maps every existing transition barrier without a coordinator"
    )]
    fn advance_matrix_transition<Barrier>(
        restore: &RestoreGuard,
        transition: RestoreTransition,
        authority: &AuthorityConfiguration,
        mut matrix_barrier: Barrier,
    ) -> Result<(), ()>
    where
        Barrier: FnMut(MatrixBarrier) -> Result<(), ()>,
    {
        match transition {
            RestoreTransition::InstalledToStopped => restore
                .advance_installed_to_stopped_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreStopBarrier::BeforePublication => MatrixBarrier::BeforeSemantic,
                        RestoreStopBarrier::AfterPublication => MatrixBarrier::AfterSemantic,
                        RestoreStopBarrier::AfterTemporarySync => MatrixBarrier::AfterTemporarySync,
                        RestoreStopBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreStopBarrier::AfterStateRootSync => MatrixBarrier::AfterStateRootSync,
                    })
                }),
            RestoreTransition::StoppedToExpired => {
                restore.advance_stopped_to_expired_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreExpiryBarrier::BeforeExpiryCommit => MatrixBarrier::BeforeSemantic,
                        RestoreExpiryBarrier::AfterExpiryCommit => MatrixBarrier::AfterSemantic,
                        RestoreExpiryBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreExpiryBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreExpiryBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    })
                })
            },
            RestoreTransition::ExpiredToReceipts => restore
                .advance_expired_to_receipts_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreReceiptBarrier::BeforeConvergence => MatrixBarrier::BeforeSemantic,
                        RestoreReceiptBarrier::AfterConvergence => MatrixBarrier::AfterSemantic,
                        RestoreReceiptBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreReceiptBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreReceiptBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    })
                }),
            RestoreTransition::ReceiptsToRunner => {
                restore.advance_receipts_to_runner_with_barrier(authority, |phase| {
                    let phase = match phase {
                        RestoreRunnerBarrier::BeforeReconstruction => MatrixBarrier::BeforeSemantic,
                        RestoreRunnerBarrier::AfterReconstruction
                        | RestoreRunnerBarrier::BeforeReconciliation => return Ok(()),
                        RestoreRunnerBarrier::AfterReconciliation => MatrixBarrier::AfterSemantic,
                        RestoreRunnerBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreRunnerBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreRunnerBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    };
                    matrix_barrier(phase)
                })
            },
            RestoreTransition::RunnerToLease => {
                restore.advance_runner_to_lease_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreLeaseBarrier::BeforePublicationFixedPoint => {
                            MatrixBarrier::BeforeSemantic
                        },
                        RestoreLeaseBarrier::AfterPublicationFixedPoint => {
                            MatrixBarrier::AfterSemantic
                        },
                        RestoreLeaseBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreLeaseBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreLeaseBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    })
                })
            },
            RestoreTransition::LeaseToCleanup => {
                restore.advance_lease_to_cleanup_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreCleanupBarrier::BeforeCleanupFixedPoint => {
                            MatrixBarrier::BeforeSemantic
                        },
                        RestoreCleanupBarrier::AfterCleanupFixedPoint => {
                            MatrixBarrier::AfterSemantic
                        },
                        RestoreCleanupBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreCleanupBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreCleanupBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    })
                })
            },
            RestoreTransition::CleanupToValidated => restore
                .advance_cleanup_to_validated_with_barrier(authority, |phase| {
                    matrix_barrier(match phase {
                        RestoreValidationBarrier::BeforeValidationFixedPoint => {
                            MatrixBarrier::BeforeSemantic
                        },
                        RestoreValidationBarrier::AfterValidationFixedPoint => {
                            MatrixBarrier::AfterSemantic
                        },
                        RestoreValidationBarrier::AfterTemporarySync => {
                            MatrixBarrier::AfterTemporarySync
                        },
                        RestoreValidationBarrier::AfterRename => MatrixBarrier::AfterRename,
                        RestoreValidationBarrier::AfterStateRootSync => {
                            MatrixBarrier::AfterStateRootSync
                        },
                    })
                }),
        }
    }

    fn assert_clean_transition_invariants(fixture: &CleanTransitionFixture) {
        assert_eq!(
            tree_inventory(&fixture.source_root),
            fixture.source_inventory
        );
        assert_eq!(
            tree_inventory(&fixture.backup_root),
            fixture.selected_inventory
        );
        assert!(!fixture.destination.join("restore.ready").exists());
        assert!(!fixture.destination.join("sandbox.sqlite3-journal").exists());
        assert!(crate::state_root::StateGuard::open(
            &fixture.destination,
            RoleIdentities::test_controller(),
            DeploymentProfile::Test,
        )
        .is_err());
        assert!(fs::read_dir(fixture.destination.join("receipts"))
            .unwrap()
            .next()
            .is_none());
        assert!(fs::read_dir(fixture.destination.join("runner"))
            .unwrap()
            .next()
            .is_none());
        let connection = rusqlite::Connection::open(fixture.destination.join(DATABASE)).unwrap();
        for table in [
            "runs",
            "tombstones",
            "receipts",
            "receipt_publications",
            "cleanup_records",
            "application_reports",
            "provisioned_object_owners",
            "events",
            "authority_collection",
            "backup_authority_references",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "unexpected clean-matrix row in {table}");
        }
        let stopped: i64 = connection
            .query_row(
                "SELECT stopped FROM service_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 1);
        let backup_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(backup_rows, 1);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the shared matrix keeps all canonical transition prefix rows in one sequence"
    )]
    fn exercise_clean_transition_matrix_row() {
        let fixture = clean_transition_fixture("restore-cross-transition-matrix");
        let transitions = [
            RestoreTransition::InstalledToStopped,
            RestoreTransition::StoppedToExpired,
            RestoreTransition::ExpiredToReceipts,
            RestoreTransition::ReceiptsToRunner,
            RestoreTransition::RunnerToLease,
            RestoreTransition::LeaseToCleanup,
            RestoreTransition::CleanupToValidated,
        ];
        for transition in transitions {
            let (_, next_step) = transition.steps();
            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::BeforeSemantic)),
            )
            .is_err());
            drop(restore);
            assert!(!fixture.destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_clean_transition_invariants(&fixture);

            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::AfterSemantic)),
            )
            .is_err());
            drop(restore);
            assert!(!fixture.destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_clean_transition_invariants(&fixture);

            let temporary = fixture.destination.join(RESTORE_STATE_TEMPORARY);
            fs::write(&temporary, b"").unwrap();
            mode(&temporary, 0o600);
            assert!(reopen_matrix_transition(&fixture, transition).is_ok());
            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::AfterTemporarySync)),
            )
            .is_err());
            drop(restore);
            assert_clean_transition_invariants(&fixture);

            let complete = fs::read(&temporary).unwrap();
            assert!(!complete.is_empty());
            fs::write(&temporary, &complete[..complete.len() / 2]).unwrap();
            assert!(reopen_matrix_transition(&fixture, transition).is_ok());
            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::AfterTemporarySync)),
            )
            .is_err());
            drop(restore);
            assert_eq!(fs::read(&temporary).unwrap(), complete);
            assert_clean_transition_invariants(&fixture);

            assert!(reopen_matrix_transition(&fixture, transition).is_ok());
            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::AfterRename)),
            )
            .is_err());
            drop(restore);
            assert!(!temporary.exists());
            let new_bytes = fs::read(fixture.destination.join(RESTORE_INCOMPLETE)).unwrap();
            let new_record: RestoreIncomplete = serde_json::from_slice(&new_bytes).unwrap();
            assert_eq!(new_record.step, next_step);
            assert_clean_transition_invariants(&fixture);

            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            assert!(advance_matrix_transition(
                &restore,
                transition,
                &fixture.authority,
                |actual| stop_matrix_barrier(actual, Some(MatrixBarrier::AfterStateRootSync)),
            )
            .is_err());
            drop(restore);
            assert_eq!(
                fs::read(fixture.destination.join(RESTORE_INCOMPLETE)).unwrap(),
                new_bytes
            );
            assert_clean_transition_invariants(&fixture);

            for _ in 0..2 {
                let restore = reopen_matrix_transition(&fixture, transition).unwrap();
                advance_matrix_transition(&restore, transition, &fixture.authority, |_| Ok(()))
                    .unwrap();
                drop(restore);
                assert_eq!(
                    fs::read(fixture.destination.join(RESTORE_INCOMPLETE)).unwrap(),
                    new_bytes
                );
                assert_clean_transition_invariants(&fixture);
            }
        }
        crate::test_authority::remove_root(&fixture.authority_root);
        cleanup(&fixture.base);
    }

    fn exercise_clean_transition_temporary_substitution_table() {
        let fixture = clean_transition_fixture("restore-transition-temporary-substitution");
        let transitions = [
            RestoreTransition::InstalledToStopped,
            RestoreTransition::StoppedToExpired,
            RestoreTransition::ExpiredToReceipts,
            RestoreTransition::ReceiptsToRunner,
            RestoreTransition::RunnerToLease,
            RestoreTransition::LeaseToCleanup,
            RestoreTransition::CleanupToValidated,
        ];
        for (index, transition) in transitions.into_iter().enumerate() {
            let (current_step, next_step) = transition.steps();
            let incomplete = fixture.destination.join(RESTORE_INCOMPLETE);
            let temporary = fixture.destination.join(RESTORE_STATE_TEMPORARY);
            let before_bytes = fs::read(&incomplete).unwrap();
            let before: RestoreIncomplete = serde_json::from_slice(&before_bytes).unwrap();
            assert_eq!(before.step, current_step);

            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            let mut substituted = false;
            assert!(
                advance_matrix_transition(&restore, transition, &fixture.authority, |phase| {
                    if phase == MatrixBarrier::AfterTemporarySync {
                        let canonical_bytes = fs::read(&temporary).unwrap();
                        let replacement = fixture
                            .destination
                            .join(format!("restore-state-substitute-{index}"));
                        fs::write(&replacement, &canonical_bytes).unwrap();
                        mode(&replacement, 0o600);
                        fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&replacement)
                            .unwrap()
                            .sync_all()
                            .unwrap();
                        fs::rename(&replacement, &temporary).unwrap();
                        substituted = true;
                    }
                    Ok(())
                },)
                .is_err()
            );
            drop(restore);
            assert!(
                substituted,
                "substitution barrier was not reached for {transition:?}"
            );
            assert_eq!(fs::read(&incomplete).unwrap(), before_bytes);
            let unchanged: RestoreIncomplete =
                serde_json::from_slice(&fs::read(&incomplete).unwrap()).unwrap();
            assert_eq!(unchanged.step, current_step);
            assert!(temporary.exists());
            assert_clean_transition_invariants(&fixture);

            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            advance_matrix_transition(&restore, transition, &fixture.authority, |_| Ok(()))
                .unwrap();
            drop(restore);
            assert!(!temporary.exists());
            let advanced: RestoreIncomplete =
                serde_json::from_slice(&fs::read(&incomplete).unwrap()).unwrap();
            assert_eq!(advanced.step, next_step);
            assert_clean_transition_invariants(&fixture);
        }
        crate::test_authority::remove_root(&fixture.authority_root);
        cleanup(&fixture.base);
    }

    #[derive(Clone, Copy, Debug)]
    enum TransitionHostileFault {
        WrongStep,
        Nonprefix,
        ExtraEntry,
        WrongMode,
        WrongType,
        LinkCount,
        WrongOwnerGroup,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the hostile table keeps one representative validator fault per transition"
    )]
    fn exercise_clean_transition_hostile_table() {
        let fixture = clean_transition_fixture("restore-transition-hostile-table");
        let rows = [
            (
                RestoreTransition::InstalledToStopped,
                TransitionHostileFault::WrongStep,
            ),
            (
                RestoreTransition::StoppedToExpired,
                TransitionHostileFault::Nonprefix,
            ),
            (
                RestoreTransition::ExpiredToReceipts,
                TransitionHostileFault::ExtraEntry,
            ),
            (
                RestoreTransition::ReceiptsToRunner,
                TransitionHostileFault::WrongMode,
            ),
            (
                RestoreTransition::RunnerToLease,
                TransitionHostileFault::WrongType,
            ),
            (
                RestoreTransition::LeaseToCleanup,
                TransitionHostileFault::LinkCount,
            ),
            (
                RestoreTransition::CleanupToValidated,
                TransitionHostileFault::WrongOwnerGroup,
            ),
        ];
        let mut reached = Vec::new();
        for (index, (transition, fault)) in rows.into_iter().enumerate() {
            assert!(reopen_matrix_transition(&fixture, transition).is_ok());
            reached.push(transition);
            let record_path = fixture.destination.join(RESTORE_INCOMPLETE);
            let temporary = fixture.destination.join(RESTORE_STATE_TEMPORARY);
            let extra = fixture.destination.join("unexpected-transition-entry");
            let external = fixture.base.join(format!("transition-hardlink-{index}"));
            let record_bytes = fs::read(&record_path).unwrap();
            let mut actual_group_change = false;
            match fault {
                TransitionHostileFault::WrongStep => {
                    let mut record: RestoreIncomplete =
                        serde_json::from_slice(&record_bytes).unwrap();
                    record.step = "validated".to_owned();
                    fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
                },
                TransitionHostileFault::Nonprefix => {
                    fs::write(&temporary, b"not-a-prefix").unwrap();
                    mode(&temporary, 0o600);
                },
                TransitionHostileFault::ExtraEntry => {
                    fs::write(&extra, b"unexpected").unwrap();
                    mode(&extra, 0o600);
                },
                TransitionHostileFault::WrongMode => {
                    fs::write(&temporary, b"").unwrap();
                    mode(&temporary, 0o400);
                },
                TransitionHostileFault::WrongType => {
                    fs::create_dir(&temporary).unwrap();
                    mode(&temporary, 0o700);
                },
                TransitionHostileFault::LinkCount => {
                    fs::write(&temporary, b"").unwrap();
                    mode(&temporary, 0o600);
                    fs::hard_link(&temporary, &external).unwrap();
                },
                TransitionHostileFault::WrongOwnerGroup => {
                    let controller = BackupIdentity::current_process();
                    assert!(!valid_file_metadata_fields(
                        true,
                        controller.uid.saturating_add(1),
                        controller.gid,
                        0o600,
                        1,
                        0,
                        controller,
                        0o600,
                        1024,
                    ));
                    assert!(!valid_file_metadata_fields(
                        true,
                        controller.uid,
                        controller.gid.saturating_add(1),
                        0o600,
                        1,
                        0,
                        controller,
                        0o600,
                        1024,
                    ));
                    fs::write(&temporary, b"").unwrap();
                    mode(&temporary, 0o600);
                    let file = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&temporary)
                        .unwrap();
                    if let Some(group) = rustix::process::getgroups()
                        .unwrap()
                        .into_iter()
                        .find(|group| group.as_raw() != controller.gid)
                    {
                        rustix::fs::fchown(&file, None, Some(group)).unwrap();
                        actual_group_change = true;
                    }
                },
            }
            let hostile_inventory = tree_inventory(&fixture.destination);
            if actual_group_change || !matches!(fault, TransitionHostileFault::WrongOwnerGroup) {
                assert!(reopen_matrix_transition(&fixture, transition).is_err());
            } else {
                assert!(reopen_matrix_transition(&fixture, transition).is_ok());
            }
            assert_eq!(tree_inventory(&fixture.destination), hostile_inventory);
            match fault {
                TransitionHostileFault::WrongStep => fs::write(&record_path, record_bytes).unwrap(),
                TransitionHostileFault::ExtraEntry => fs::remove_file(&extra).unwrap(),
                TransitionHostileFault::WrongType => fs::remove_dir(&temporary).unwrap(),
                TransitionHostileFault::LinkCount => {
                    fs::remove_file(&external).unwrap();
                    fs::remove_file(&temporary).unwrap();
                },
                TransitionHostileFault::Nonprefix
                | TransitionHostileFault::WrongMode
                | TransitionHostileFault::WrongOwnerGroup => {
                    fs::remove_file(&temporary).unwrap();
                },
            }
            assert_clean_transition_invariants(&fixture);
            let restore = reopen_matrix_transition(&fixture, transition).unwrap();
            advance_matrix_transition(&restore, transition, &fixture.authority, |_| Ok(()))
                .unwrap();
            drop(restore);
            assert_clean_transition_invariants(&fixture);
        }
        assert_eq!(
            reached,
            rows.map(|(transition, _)| transition),
            "hostile table did not reach every canonical transition"
        );
        crate::test_authority::remove_root(&fixture.authority_root);
        cleanup(&fixture.base);
    }

    #[test]
    fn installation_owner_mode_classifier_closes_reachable_states() {
        let helper = BackupIdentity { uid: 11, gid: 12 };
        let controller = BackupIdentity { uid: 21, gid: 22 };
        let other = BackupIdentity { uid: 31, gid: 32 };
        for (identity, owner) in [
            (helper, "helper"),
            (controller, "controller"),
            (other, "other"),
        ] {
            for mode in [0o400, 0o600, 0o700, 0o4600] {
                for complete in [false, true] {
                    for final_mode in [0o400, 0o600] {
                        let expected = match (owner, mode, complete, final_mode) {
                            ("controller", 0o600, true, 0o600)
                            | ("controller", 0o400, true, 0o400) => Some(true),
                            ("helper", 0o600, _, _) | ("controller", 0o600, true, 0o400) => {
                                Some(false)
                            },
                            _ => None,
                        };
                        assert_eq!(
                            classify_installation_file_state(
                                identity, mode, complete, helper, controller, final_mode,
                            ),
                            expected,
                            "owner={owner} mode={mode:o} complete={complete} final={final_mode:o}"
                        );
                    }
                }
                let expected_directory = match (owner, mode) {
                    ("helper", 0o700) => Some(false),
                    ("controller", 0o700) => Some(true),
                    _ => None,
                };
                assert_eq!(
                    classify_installation_directory_state(identity, mode, helper, controller),
                    expected_directory,
                    "directory owner={owner} mode={mode:o}"
                );
                for empty in [false, true] {
                    let expected_root =
                        mode == 0o700 && (owner == "controller" || empty && owner == "helper");
                    assert_eq!(
                        reachable_installation_root_state(
                            identity, mode, empty, helper, controller,
                        ),
                        expected_root,
                        "root owner={owner} mode={mode:o} empty={empty}"
                    );
                }
            }
        }
    }

    #[test]
    fn installed_record_prefix_grammar_is_closed() {
        let manifest = "a".repeat(64);
        let compatibility = "b".repeat(64);
        let record = RestoreIncomplete {
            schema: "kapsel.sandbox.restore-incomplete.v1".to_owned(),
            generation: 1,
            manifest_sha256: manifest.clone(),
            compatibility_sha256: compatibility.clone(),
            started_at: 1_774_051_201,
            step: "installed".to_owned(),
        };
        let canonical = serde_json::to_vec(&record).unwrap();
        for end in 0..canonical.len() {
            assert!(valid_installed_record_prefix(
                &canonical[..end],
                1,
                &manifest,
                &compatibility,
                1_774_051_201,
            ));
        }
        assert!(canonical_installed_record(
            &canonical,
            1,
            &manifest,
            &compatibility,
            1_774_051_201,
        )
        .is_some());
        let time_at = canonical
            .windows(b"1774051201".len())
            .position(|window| window == b"1774051201")
            .unwrap();
        for invalid_time in [
            b"0".as_slice(),
            b"01774051201".as_slice(),
            b"1774051200,\"step\":\"installed\"}".as_slice(),
            b"9223372036854775808".as_slice(),
        ] {
            let mut invalid = canonical[..time_at].to_vec();
            invalid.extend_from_slice(invalid_time);
            assert!(!valid_installed_record_prefix(
                &invalid,
                1,
                &manifest,
                &compatibility,
                1_774_051_201,
            ));
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table keeps complete-temporary recovery publication sides explicit"
    )]
    fn exercise_complete_temporary_recovery_publication_matrix() {
        let (base, state) = initialized("restore-complete-temporary-recovery-matrix");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);
        let source_root = base.join("state-parent/state");
        let source_inventory = tree_inventory(&source_root);
        let selected_inventory = tree_inventory(&backup_root);
        let identities = RoleIdentities::test_controller();
        let rows = [
            (
                RestoreInstallBarrier::AfterComponentFinalSync(RestoreInstallComponent::Incomplete),
                RestoreInstallBarrier::AfterTreeSync,
            ),
            (
                RestoreInstallBarrier::AfterTreeSync,
                RestoreInstallBarrier::BeforeRenameRace,
            ),
            (
                RestoreInstallBarrier::AfterComponentFinalSync(RestoreInstallComponent::Incomplete),
                RestoreInstallBarrier::AfterRename,
            ),
            (
                RestoreInstallBarrier::AfterTreeSync,
                RestoreInstallBarrier::AfterParentSync,
            ),
        ];

        for (index, (construction_stop, recovery_stop)) in rows.into_iter().enumerate() {
            let restore_parent = base.join(format!("complete-recovery-parent-{index}"));
            fs::create_dir(&restore_parent).unwrap();
            mode(&restore_parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(restore_parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            let destination = restore_parent.join("state");
            let temporary = restore_parent.join(RESTORE_TEMPORARY);
            let ordinary_open_denied = || {
                assert!(crate::state_root::StateGuard::open(
                    &destination,
                    identities,
                    DeploymentProfile::Test,
                )
                .is_err());
            };

            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            let mut construction_reached = false;
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    if phase == construction_stop {
                        construction_reached = true;
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert!(
                construction_reached,
                "construction barrier {construction_stop:?} was not reached"
            );
            assert!(temporary.is_dir());
            assert!(!destination.exists());
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
            ordinary_open_denied();
            let frozen_bytes = fs::read(temporary.join(RESTORE_INCOMPLETE)).unwrap();
            let frozen: RestoreIncomplete = serde_json::from_slice(&frozen_bytes).unwrap();
            assert_eq!(serde_json::to_vec(&frozen).unwrap(), frozen_bytes);
            assert_eq!(frozen.step, "installed");
            assert_eq!(frozen.started_at, 1_774_051_201);

            let restore = RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            let mut recovery_reached = false;
            assert!(restore
                .resume_temporary_installation_with_barrier(1_774_051_202, |phase| {
                    if phase == recovery_stop {
                        recovery_reached = true;
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert!(
                recovery_reached,
                "recovery publisher barrier {recovery_stop:?} was not reached"
            );
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
            ordinary_open_denied();

            if matches!(
                recovery_stop,
                RestoreInstallBarrier::AfterTreeSync | RestoreInstallBarrier::BeforeRenameRace
            ) {
                assert!(temporary.is_dir());
                assert!(!destination.exists());
                let restore = RestoreGuard::reopen_temporary_installation(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore
                    .resume_temporary_installation_with_barrier(1_774_051_203, |_| Ok(()))
                    .unwrap();
            } else {
                assert!(!temporary.exists());
                assert!(destination.is_dir());
                let restore = RestoreGuard::reopen_installed_to_stopped(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore
                    .retry_installed_installation_with_barrier(|_| Ok(()))
                    .unwrap();
            }

            assert!(destination.is_dir());
            assert!(!temporary.exists());
            ordinary_open_denied();
            let installed_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
            assert_eq!(installed_bytes, frozen_bytes);
            let installed: RestoreIncomplete = serde_json::from_slice(&installed_bytes).unwrap();
            assert_eq!(installed.step, "installed");
            assert_eq!(installed.started_at, 1_774_051_201);
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
        }

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn clean_restore_complete_temporary_recovery_publication_matrix() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        exercise_complete_temporary_recovery_publication_matrix();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the installation matrix keeps every owner-frozen durable side explicit"
    )]
    fn clean_restore_installation_crash_restart_matrix() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let (base, state) = initialized("restore-installation-matrix");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);
        let source_root = base.join("state-parent/state");
        let source_inventory = tree_inventory(&source_root);
        let selected_inventory = tree_inventory(&backup_root);
        let identities = RoleIdentities::test_controller();

        let mut barriers = vec![
            RestoreInstallBarrier::AfterTemporaryCreate,
            RestoreInstallBarrier::AfterTemporaryOwnership,
            RestoreInstallBarrier::AfterTemporaryInodeSync,
            RestoreInstallBarrier::AfterTemporaryParentSync,
        ];
        for component in [
            RestoreInstallComponent::Database,
            RestoreInstallComponent::Deployment,
            RestoreInstallComponent::StateLock,
            RestoreInstallComponent::Incomplete,
        ] {
            barriers.extend([
                RestoreInstallBarrier::AfterComponentCreate(component),
                RestoreInstallBarrier::AfterComponentNamespaceSync(component),
            ]);
            if component != RestoreInstallComponent::StateLock {
                barriers.push(RestoreInstallBarrier::AfterComponentPartialWrite(component));
            }
            barriers.extend([
                RestoreInstallBarrier::AfterComponentWrite(component),
                RestoreInstallBarrier::AfterComponentContentSync(component),
                RestoreInstallBarrier::AfterComponentOwnership(component),
                RestoreInstallBarrier::AfterComponentMode(component),
                RestoreInstallBarrier::AfterComponentFinalSync(component),
            ]);
        }
        for component in [
            RestoreInstallComponent::Receipts,
            RestoreInstallComponent::Runner,
        ] {
            barriers.extend([
                RestoreInstallBarrier::AfterComponentCreate(component),
                RestoreInstallBarrier::AfterComponentNamespaceSync(component),
                RestoreInstallBarrier::AfterComponentOwnership(component),
                RestoreInstallBarrier::AfterComponentFinalSync(component),
            ]);
        }
        barriers.extend([
            RestoreInstallBarrier::AfterTreeSync,
            RestoreInstallBarrier::BeforeRenameRace,
            RestoreInstallBarrier::AfterRename,
            RestoreInstallBarrier::AfterParentSync,
        ]);

        for (index, stopped_at) in barriers.into_iter().enumerate() {
            let restore_parent = base.join(format!("restore-parent-{index}"));
            fs::create_dir(&restore_parent).unwrap();
            mode(&restore_parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(restore_parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            let destination = restore_parent.join("state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(
                restore
                    .install_incomplete_with_barrier(1_774_051_201, |phase| {
                        (phase != stopped_at).then_some(()).ok_or(())
                    })
                    .is_err(),
                "barrier {stopped_at:?} was not reached"
            );
            drop(restore);
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());

            if destination.exists() {
                assert!(!restore_parent.join(RESTORE_TEMPORARY).exists());
                let restore = RestoreGuard::reopen_installed_to_stopped(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                let retry_stop = match stopped_at {
                    RestoreInstallBarrier::AfterRename => {
                        Some(RestoreInstallBarrier::AfterTreeSync)
                    },
                    RestoreInstallBarrier::AfterParentSync => {
                        Some(RestoreInstallBarrier::AfterParentSync)
                    },
                    _ => None,
                };
                if let Some(retry_stop) = retry_stop {
                    assert!(restore
                        .retry_installed_installation_with_barrier(|phase| {
                            (phase != retry_stop).then_some(()).ok_or(())
                        })
                        .is_err());
                    drop(restore);
                    assert_eq!(tree_inventory(&source_root), source_inventory);
                    assert_eq!(tree_inventory(&backup_root), selected_inventory);
                    assert!(crate::state_root::StateGuard::open(
                        &destination,
                        identities,
                        DeploymentProfile::Test,
                    )
                    .is_err());
                    let restore = RestoreGuard::reopen_installed_to_stopped(
                        &destination,
                        &backup_root,
                        BackupIdentity::current_process(),
                        BackupIdentity::current_process(),
                        DeploymentProfile::Test,
                    )
                    .unwrap();
                    restore
                        .retry_installed_installation_with_barrier(|_| Ok(()))
                        .unwrap();
                } else {
                    restore
                        .retry_installed_installation_with_barrier(|_| Ok(()))
                        .unwrap();
                }
            } else {
                assert!(restore_parent.join(RESTORE_TEMPORARY).is_dir());
                let restore = RestoreGuard::reopen_temporary_installation(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore
                    .resume_temporary_installation_with_barrier(1_774_051_202, |_| Ok(()))
                    .unwrap();
            }

            assert!(destination.is_dir());
            assert!(!restore_parent.join(RESTORE_TEMPORARY).exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
            let bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
            let record: RestoreIncomplete = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&record).unwrap(), bytes);
            let complete_on_disk = matches!(
                stopped_at,
                RestoreInstallBarrier::AfterComponentWrite(RestoreInstallComponent::Incomplete)
                    | RestoreInstallBarrier::AfterComponentContentSync(
                        RestoreInstallComponent::Incomplete
                    )
                    | RestoreInstallBarrier::AfterComponentOwnership(
                        RestoreInstallComponent::Incomplete
                    )
                    | RestoreInstallBarrier::AfterComponentMode(
                        RestoreInstallComponent::Incomplete
                    )
                    | RestoreInstallBarrier::AfterComponentFinalSync(
                        RestoreInstallComponent::Incomplete
                    )
                    | RestoreInstallBarrier::AfterTreeSync
                    | RestoreInstallBarrier::BeforeRenameRace
                    | RestoreInstallBarrier::AfterRename
                    | RestoreInstallBarrier::AfterParentSync
            );
            assert_eq!(
                record.started_at,
                if complete_on_disk {
                    1_774_051_201
                } else {
                    1_774_051_202
                },
                "barrier {stopped_at:?} chose the wrong retry clock"
            );
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
        }

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the hostile installation inventory stays beside its no-deletion assertions"
    )]
    fn clean_restore_installation_rejects_malformed_prefix_without_deletion() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let (base, state) = initialized("restore-installation-malformed");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        for (index, malformed) in ["unexpected", "out-of-order", "nonprefix"]
            .into_iter()
            .enumerate()
        {
            let restore_parent = base.join(format!("malformed-parent-{index}"));
            fs::create_dir(&restore_parent).unwrap();
            mode(&restore_parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(restore_parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            let destination = restore_parent.join("state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            let construction_stop = if malformed == "nonprefix" {
                RestoreInstallBarrier::AfterComponentPartialWrite(RestoreInstallComponent::Database)
            } else {
                RestoreInstallBarrier::AfterTemporaryParentSync
            };
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    (phase != construction_stop).then_some(()).ok_or(())
                })
                .is_err());
            drop(restore);
            let temporary = restore_parent.join(RESTORE_TEMPORARY);
            if malformed == "unexpected" {
                fs::write(temporary.join("unexpected"), b"unexpected").unwrap();
            } else if malformed == "out-of-order" {
                fs::create_dir(temporary.join("receipts")).unwrap();
            } else {
                let database = temporary.join(DATABASE);
                let mut bytes = fs::read(&database).unwrap();
                bytes[0] ^= 1;
                fs::write(database, bytes).unwrap();
            }
            let before = fs::read_dir(&temporary)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>();
            assert!(RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .is_err());
            assert_eq!(
                fs::read_dir(&temporary)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<BTreeSet<_>>(),
                before
            );
            if malformed == "out-of-order" {
                fs::create_dir(&destination).unwrap();
                mode(&destination, 0o700);
                assert!(RestoreGuard::reopen_temporary_installation(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .is_err());
                assert!(temporary.exists());
                assert!(destination.exists());
            }
        }

        let restore_parent = base.join("substituted-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let temporary_database = restore_parent.join(RESTORE_TEMPORARY).join(DATABASE);
        let selected_database = fs::read(
            backup_root
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join("service")
                .join(DATABASE),
        )
        .unwrap();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .install_incomplete_with_barrier(1_774_051_201, |phase| {
                if phase
                    == RestoreInstallBarrier::AfterComponentFinalSync(
                        RestoreInstallComponent::Database,
                    )
                {
                    fs::remove_file(&temporary_database).unwrap();
                    fs::write(&temporary_database, &selected_database).unwrap();
                    fs::set_permissions(&temporary_database, fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                Ok(())
            })
            .is_err());
        assert_eq!(fs::read(&temporary_database).unwrap(), selected_database);
        assert!(!destination.exists());

        let race_parent = base.join("rename-race-parent");
        fs::create_dir(&race_parent).unwrap();
        mode(&race_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(race_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let race_destination = race_parent.join("state");
        let restore = RestoreGuard::open_selected_clean(
            &race_destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .install_incomplete_with_barrier(1_774_051_201, |phase| {
                if phase == RestoreInstallBarrier::BeforeRenameRace {
                    fs::create_dir(&race_destination).unwrap();
                    mode(&race_destination, 0o700);
                    fs::write(race_destination.join("sentinel"), b"racing destination").unwrap();
                }
                Ok(())
            })
            .is_err());
        assert_eq!(
            fs::read(race_destination.join("sentinel")).unwrap(),
            b"racing destination"
        );
        assert!(race_parent.join(RESTORE_TEMPORARY).is_dir());

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "hostile installation object kinds stay beside their no-deletion assertions"
    )]
    fn clean_restore_installation_rejects_hostile_objects_and_separate_init_prefix() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let (base, state) = initialized("restore-installation-hostile-objects");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let make_parent = |name: &str| {
            let parent = base.join(name);
            fs::create_dir(&parent).unwrap();
            mode(&parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            parent
        };

        for (index, hostile) in ["symlink", "hardlink", "directory", "socket", "special-bits"]
            .into_iter()
            .enumerate()
        {
            let parent = make_parent(&format!("hostile-component-{index}"));
            let destination = parent.join("state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            let stop = if matches!(hostile, "hardlink" | "special-bits") {
                RestoreInstallBarrier::AfterComponentFinalSync(RestoreInstallComponent::Database)
            } else {
                RestoreInstallBarrier::AfterTemporaryParentSync
            };
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    (phase != stop).then_some(()).ok_or(())
                })
                .is_err());
            drop(restore);
            let temporary = parent.join(RESTORE_TEMPORARY);
            let component = temporary.join(DATABASE);
            match hostile {
                "symlink" => symlink(&backup_root, &component).unwrap(),
                "hardlink" => fs::hard_link(&component, parent.join("external-link")).unwrap(),
                "directory" => fs::create_dir(&component).unwrap(),
                "socket" => {
                    let short_socket = PathBuf::from(format!(
                        "/tmp/kapsel-restore-{}-{index}.sock",
                        std::process::id()
                    ));
                    let _ = fs::remove_file(&short_socket);
                    let listener = std::os::unix::net::UnixListener::bind(&short_socket).unwrap();
                    fs::rename(&short_socket, &component).unwrap();
                    drop(listener);
                },
                "special-bits" => mode(&component, 0o4600),
                _ => unreachable!(),
            }
            let before = tree_inventory(&temporary);
            assert!(RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .is_err());
            assert_eq!(tree_inventory(&temporary), before);
            assert!(!destination.exists());
        }

        for (index, hostile) in ["symlink-root", "special-root"].into_iter().enumerate() {
            let parent = make_parent(&format!("hostile-root-{index}"));
            let destination = parent.join("state");
            let temporary = parent.join(RESTORE_TEMPORARY);
            if hostile == "symlink-root" {
                symlink(&backup_root, &temporary).unwrap();
            } else {
                fs::create_dir(&temporary).unwrap();
                mode(&temporary, 0o1700);
            }
            assert!(RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .is_err());
            assert!(fs::symlink_metadata(&temporary).is_ok());
        }

        let substitution_parent = make_parent("hostile-root-substitution");
        let substitution_destination = substitution_parent.join("state");
        let substitution_temporary = substitution_parent.join(RESTORE_TEMPORARY);
        let moved_temporary = substitution_parent.join("moved-restore-temporary");
        let restore = RestoreGuard::open_selected_clean(
            &substitution_destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .install_incomplete_with_barrier(1_774_051_201, |phase| {
                if phase == RestoreInstallBarrier::AfterTreeSync {
                    fs::rename(&substitution_temporary, &moved_temporary).unwrap();
                    fs::create_dir(&substitution_temporary).unwrap();
                    mode(&substitution_temporary, 0o700);
                }
                Ok(())
            })
            .is_err());
        assert!(!substitution_destination.exists());
        assert!(substitution_temporary.is_dir());
        assert!(moved_temporary.is_dir());

        for (index, stopped_at) in [
            RestoreInstallBarrier::AfterRename,
            RestoreInstallBarrier::AfterParentSync,
        ]
        .into_iter()
        .enumerate()
        {
            let parent = make_parent(&format!("published-substitution-{index}"));
            let destination = parent.join("state");
            let moved = parent.join("moved-state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    if phase == stopped_at {
                        if phase == RestoreInstallBarrier::AfterRename {
                            fs::rename(&destination, &moved).unwrap();
                            fs::create_dir(&destination).unwrap();
                            mode(&destination, 0o700);
                        } else {
                            let lock = destination.join(LOCK);
                            fs::remove_file(&lock).unwrap();
                            fs::write(&lock, b"").unwrap();
                            mode(&lock, 0o600);
                        }
                    }
                    Ok(())
                })
                .is_err());
            assert!(destination.is_dir());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                RoleIdentities::test_controller(),
                DeploymentProfile::Test,
            )
            .is_err());
        }

        for (index, substituted) in ["component", "source"].into_iter().enumerate() {
            let parent = make_parent(&format!("cleanup-substitution-{index}"));
            let destination = parent.join("state");
            let temporary = parent.join(RESTORE_TEMPORARY);
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    (phase
                        != RestoreInstallBarrier::AfterComponentPartialWrite(
                            RestoreInstallComponent::Incomplete,
                        ))
                    .then_some(())
                    .ok_or(())
                })
                .is_err());
            drop(restore);
            let restore = RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .resume_temporary_installation_with_barrier(1_774_051_202, |phase| {
                    if phase
                        == RestoreInstallBarrier::AfterComponentRemovalSync(
                            RestoreInstallComponent::Incomplete,
                        )
                    {
                        if substituted == "component" {
                            let lock = temporary.join(LOCK);
                            fs::remove_file(&lock).unwrap();
                            fs::write(&lock, b"").unwrap();
                            mode(&lock, 0o600);
                        } else {
                            let current = backup_root.join(CURRENT);
                            let saved = base.join("cleanup-saved-current");
                            fs::rename(&current, &saved).unwrap();
                            fs::copy(&saved, &current).unwrap();
                            mode(&current, 0o400);
                        }
                    }
                    Ok(())
                })
                .is_err());
            drop(restore);
            assert!(temporary.join(LOCK).exists());
            assert!(temporary.join(DEPLOYMENT).exists());
            assert!(temporary.join("receipts").exists());
            if substituted == "source" {
                fs::remove_file(backup_root.join(CURRENT)).unwrap();
                fs::rename(
                    base.join("cleanup-saved-current"),
                    backup_root.join(CURRENT),
                )
                .unwrap();
            }
        }

        let init_parent = make_parent("restore-rejects-init-prefix");
        let init_destination = init_parent.join("state");
        let init_temporary = init_parent.join(".state.initializing");
        fs::create_dir(&init_temporary).unwrap();
        mode(&init_temporary, 0o700);
        assert!(RestoreGuard::open_selected_clean(
            &init_destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .is_err());
        assert!(init_temporary.is_dir());

        let restore_parent = make_parent("init-rejects-restore-prefix");
        let restore_destination = restore_parent.join("state");
        let restore_temporary = restore_parent.join(RESTORE_TEMPORARY);
        fs::create_dir(&restore_temporary).unwrap();
        mode(&restore_temporary, 0o700);
        assert!(StateInitializer::begin(
            &restore_destination,
            RoleIdentities::test_controller(),
            &authority,
            DeploymentProfile::Test,
        )
        .is_err());
        assert!(restore_temporary.is_dir());

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "post-tree pin substitution rows keep their exact restoration beside each denial"
    )]
    fn clean_restore_installation_revalidates_every_selected_pin_before_rename() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let (base, state) = initialized("restore-installation-selected-pin-substitution");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);
        let selected_inventory = tree_inventory(&backup_root);
        let generation = backup_root.join(GENERATIONS).join(GENERATION_ONE);
        let saved_root = base.join("saved-substitutions");
        fs::create_dir(&saved_root).unwrap();
        mode(&saved_root, 0o700);

        for (index, substituted) in [
            "database",
            "current",
            "generation",
            "manifest",
            "backup-lock",
            "parent-lock",
        ]
        .into_iter()
        .enumerate()
        {
            let restore_parent = base.join(format!("pin-parent-{index}"));
            fs::create_dir(&restore_parent).unwrap();
            mode(&restore_parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(restore_parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            let destination = restore_parent.join("state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    if phase != RestoreInstallBarrier::AfterTreeSync {
                        return Ok(());
                    }
                    match substituted {
                        "database" => {
                            let service = generation.join("service");
                            mode(&service, 0o700);
                            let original = service.join(DATABASE);
                            let saved = saved_root.join("database");
                            fs::rename(&original, &saved).unwrap();
                            fs::copy(&saved, &original).unwrap();
                            mode(&original, 0o400);
                            mode(&service, 0o500);
                        },
                        "current" => {
                            let original = backup_root.join(CURRENT);
                            let saved = saved_root.join("current");
                            fs::rename(&original, &saved).unwrap();
                            fs::copy(&saved, &original).unwrap();
                            mode(&original, 0o400);
                        },
                        "generation" => {
                            let generations = backup_root.join(GENERATIONS);
                            mode(&generations, 0o700);
                            mode(&generation, 0o700);
                            let saved = saved_root.join("generation");
                            fs::rename(&generation, &saved).unwrap();
                            fs::create_dir(&generation).unwrap();
                            mode(&generation, 0o500);
                        },
                        "manifest" => {
                            mode(&generation, 0o700);
                            let original = generation.join(MANIFEST);
                            let saved = saved_root.join("manifest");
                            fs::rename(&original, &saved).unwrap();
                            fs::copy(&saved, &original).unwrap();
                            mode(&original, 0o400);
                            mode(&generation, 0o500);
                        },
                        "backup-lock" => {
                            let original = backup_root.join(LOCK);
                            let saved = saved_root.join("backup-lock");
                            fs::rename(&original, &saved).unwrap();
                            fs::write(&original, b"").unwrap();
                            mode(&original, 0o600);
                        },
                        "parent-lock" => {
                            let original = restore_parent.join(PARENT_RESTORE_LOCK);
                            let saved = saved_root.join("parent-lock");
                            fs::rename(&original, &saved).unwrap();
                            fs::write(&original, b"").unwrap();
                            mode(&original, 0o600);
                        },
                        _ => unreachable!(),
                    }
                    Ok(())
                })
                .is_err());
            drop(restore);
            assert!(
                !destination.exists(),
                "substitution {substituted} published"
            );
            assert!(restore_parent.join(RESTORE_TEMPORARY).is_dir());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                RoleIdentities::test_controller(),
                DeploymentProfile::Test,
            )
            .is_err());

            match substituted {
                "database" => {
                    let service = generation.join("service");
                    mode(&service, 0o700);
                    fs::remove_file(service.join(DATABASE)).unwrap();
                    fs::rename(saved_root.join("database"), service.join(DATABASE)).unwrap();
                    mode(&service, 0o500);
                },
                "current" => {
                    fs::remove_file(backup_root.join(CURRENT)).unwrap();
                    fs::rename(saved_root.join("current"), backup_root.join(CURRENT)).unwrap();
                },
                "generation" => {
                    fs::remove_dir(&generation).unwrap();
                    fs::rename(saved_root.join("generation"), &generation).unwrap();
                    mode(&generation, 0o500);
                },
                "manifest" => {
                    mode(&generation, 0o700);
                    fs::remove_file(generation.join(MANIFEST)).unwrap();
                    fs::rename(saved_root.join("manifest"), generation.join(MANIFEST)).unwrap();
                    mode(&generation, 0o500);
                },
                "backup-lock" => {
                    fs::remove_file(backup_root.join(LOCK)).unwrap();
                    fs::rename(saved_root.join("backup-lock"), backup_root.join(LOCK)).unwrap();
                },
                "parent-lock" => {
                    fs::remove_file(restore_parent.join(PARENT_RESTORE_LOCK)).unwrap();
                    fs::rename(
                        saved_root.join("parent-lock"),
                        restore_parent.join(PARENT_RESTORE_LOCK),
                    )
                    .unwrap();
                },
                _ => unreachable!(),
            }
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
        }

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the cleanup matrix keeps every descriptor-relative removal side explicit"
    )]
    fn clean_restore_installation_cleanup_crash_restart_matrix() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let (base, state) = initialized("restore-installation-cleanup-matrix");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        drop(selected);
        drop(backup);
        drop(state);
        let source_root = base.join("state-parent/state");
        let source_inventory = tree_inventory(&source_root);
        let selected_inventory = tree_inventory(&backup_root);
        let mut cleanup_barriers = Vec::new();
        for component in [
            RestoreInstallComponent::Incomplete,
            RestoreInstallComponent::StateLock,
            RestoreInstallComponent::Runner,
            RestoreInstallComponent::Receipts,
            RestoreInstallComponent::Deployment,
            RestoreInstallComponent::Database,
        ] {
            cleanup_barriers.extend([
                RestoreInstallBarrier::AfterComponentUnlink(component),
                RestoreInstallBarrier::AfterComponentRemovalSync(component),
            ]);
        }
        cleanup_barriers.extend([
            RestoreInstallBarrier::AfterTemporaryUnlink,
            RestoreInstallBarrier::AfterCleanupParentSync,
        ]);

        for (index, stopped_at) in cleanup_barriers.into_iter().enumerate() {
            let restore_parent = base.join(format!("cleanup-parent-{index}"));
            fs::create_dir(&restore_parent).unwrap();
            mode(&restore_parent, 0o700);
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(restore_parent.join(PARENT_RESTORE_LOCK))
                .unwrap();
            let destination = restore_parent.join("state");
            let restore = RestoreGuard::open_selected_clean(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .install_incomplete_with_barrier(1_774_051_201, |phase| {
                    (phase
                        != RestoreInstallBarrier::AfterComponentPartialWrite(
                            RestoreInstallComponent::Incomplete,
                        ))
                    .then_some(())
                    .ok_or(())
                })
                .is_err());
            drop(restore);
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
            assert!(crate::state_root::StateGuard::open(
                &destination,
                RoleIdentities::test_controller(),
                DeploymentProfile::Test,
            )
            .is_err());
            let restore = RestoreGuard::reopen_temporary_installation(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .resume_temporary_installation_with_barrier(1_774_051_202, |phase| {
                    (phase != stopped_at).then_some(()).ok_or(())
                })
                .is_err());
            drop(restore);
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
            assert!(crate::state_root::StateGuard::open(
                &destination,
                RoleIdentities::test_controller(),
                DeploymentProfile::Test,
            )
            .is_err());

            if restore_parent.join(RESTORE_TEMPORARY).exists() {
                let restore = RestoreGuard::reopen_temporary_installation(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore
                    .resume_temporary_installation_with_barrier(1_774_051_203, |_| Ok(()))
                    .unwrap();
            } else {
                let restore = RestoreGuard::open_selected_clean(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore.install_incomplete(1_774_051_203).unwrap();
            }
            assert!(destination.is_dir());
            assert!(!restore_parent.join(RESTORE_TEMPORARY).exists());
            let installed_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
            let installed: RestoreIncomplete = serde_json::from_slice(&installed_bytes).unwrap();
            assert_eq!(installed.started_at, 1_774_051_203);
            assert_eq!(tree_inventory(&source_root), source_inventory);
            assert_eq!(tree_inventory(&backup_root), selected_inventory);
        }

        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn clean_restore_cross_transition_matrix() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        exercise_clean_transition_matrix_row();
    }

    #[test]
    fn clean_restore_cross_transition_temporary_substitution_table() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        exercise_clean_transition_temporary_substitution_table();
    }

    #[test]
    fn clean_restore_cross_transition_hostile_table() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        exercise_clean_transition_hostile_table();
    }

    #[test]
    fn clean_restore_open_contention_is_ordered_and_read_only() {
        let _serial = INSTALLATION_TEST_LOCK.lock().unwrap();
        let fixture = clean_transition_fixture("restore-open-contention");
        let destination_inventory = tree_inventory(&fixture.destination);
        let rows = [
            (
                fixture
                    .destination
                    .parent()
                    .unwrap()
                    .join(PARENT_RESTORE_LOCK),
                FlockOperation::NonBlockingLockShared,
                "parent restore lock",
            ),
            (
                fixture.destination.join(LOCK),
                FlockOperation::NonBlockingLockShared,
                "destination state lock",
            ),
            (
                fixture.backup_root.join(LOCK),
                FlockOperation::NonBlockingLockExclusive,
                "backup lock",
            ),
        ];
        for (path, operation, label) in rows {
            let held = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            flock(&held, operation).unwrap();
            assert!(
                reopen_matrix_transition(&fixture, RestoreTransition::InstalledToStopped,).is_err(),
                "restore ignored contended {label}"
            );
            assert_eq!(tree_inventory(&fixture.destination), destination_inventory);
            assert_clean_transition_invariants(&fixture);
            drop(held);
        }
        crate::test_authority::remove_root(&fixture.authority_root);
        cleanup(&fixture.base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restore tracer keeps its complete evidence together"
    )]
    fn selected_clean_backup_reopens_installed_and_advances_stopped_without_readiness() {
        let (base, state) = initialized("restore-installed");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let manifest_digest = selected.manifest_sha256.clone();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let source_deployment = fs::read(base.join("state-parent/state").join(DEPLOYMENT)).unwrap();
        let backup_database = fs::read(
            backup_root
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join("service")
                .join(DATABASE),
        )
        .unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(
            backup_root
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join(DEPLOYMENT),
        )
        .unwrap();
        let backup_manifest = fs::read(
            backup_root
                .join(GENERATIONS)
                .join(GENERATION_ONE)
                .join(MANIFEST),
        )
        .unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(".kapsel-sandbox-restore.lock"))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        for reserved in [PARENT_RESTORE_LOCK, RESTORE_TEMPORARY] {
            assert!(RestoreGuard::open_selected_clean(
                &restore_parent.join(reserved),
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .is_err());
            assert_eq!(
                fs::read_dir(&restore_parent)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<BTreeSet<_>>(),
                std::iter::once(OsString::from(PARENT_RESTORE_LOCK)).collect()
            );
        }
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();

        assert!(restore.install_incomplete(1_774_051_200).is_err());
        assert!(!destination.exists());
        restore.install_incomplete(1_774_051_201).unwrap();
        let expected = [
            ".backup.lock",
            DEPLOYMENT,
            "receipts",
            "restore.incomplete",
            "runner",
            DATABASE,
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
        assert_eq!(
            fs::read_dir(&destination)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            backup_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            source_deployment
        );
        assert!(fs::read_dir(destination.join("receipts"))
            .unwrap()
            .next()
            .is_none());
        assert!(fs::read_dir(destination.join("runner"))
            .unwrap()
            .next()
            .is_none());
        let incomplete_bytes = fs::read(destination.join("restore.incomplete")).unwrap();
        let incomplete: RestoreIncomplete = serde_json::from_slice(&incomplete_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&incomplete).unwrap(), incomplete_bytes);
        assert_eq!(incomplete.generation, 1);
        assert_eq!(incomplete.manifest_sha256, manifest_digest);
        assert_eq!(incomplete.started_at, 1_774_051_201);
        assert_eq!(incomplete.step, "installed");
        assert!(!destination.join("restore.ready").exists());
        let copied = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
        assert_eq!(
            copied
                .query_row(
                    concat!(
                        "SELECT slot, generation, manifest_digest, state, captured_at ",
                        "FROM backup_generations"
                    ),
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "pending".to_owned(),
                1,
                None,
                "pending".to_owned(),
                1_774_051_201,
            )
        );
        assert_eq!(
            copied
                .query_row(
                    "SELECT COUNT(*) FROM backup_authority_references",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(copied);
        for (path, expected_mode) in [
            (destination.clone(), 0o700),
            (destination.join(DATABASE), 0o600),
            (destination.join(DEPLOYMENT), 0o400),
            (destination.join("receipts"), 0o700),
            (destination.join("runner"), 0o700),
            (destination.join(".backup.lock"), 0o600),
            (destination.join("restore.incomplete"), 0o600),
        ] {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o7777, expected_mode);
            if metadata.is_file() {
                assert_eq!(metadata.nlink(), 1);
            }
        }
        drop(restore);
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_err());

        let reopened = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        let competing_state_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(destination.join(LOCK))
            .unwrap();
        assert!(flock(&competing_state_lock, FlockOperation::NonBlockingLockShared).is_err());
        drop(competing_state_lock);
        assert!(reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreStopBarrier::BeforePublication);
                Err(())
            })
            .is_err());
        assert!(reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                if phase == RestoreStopBarrier::BeforePublication {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreStopBarrier::AfterPublication);
                    Err(())
                }
            })
            .is_err());
        drop(reopened);
        let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    concat!(
                        "SELECT slot, generation, manifest_digest, state, captured_at ",
                        "FROM backup_generations"
                    ),
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "current".to_owned(),
                1,
                manifest_digest,
                "current".to_owned(),
                1_774_051_201,
            )
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM backup_authority_references",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);
        let incomplete_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let incomplete: RestoreIncomplete = serde_json::from_slice(&incomplete_bytes).unwrap();
        assert_eq!(incomplete.step, "installed");
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_err());

        let reopened = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                assert!(matches!(phase, RestoreStopBarrier::AfterTemporarySync));
                Err(())
            })
            .is_err());
        drop(reopened);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        assert!(!temporary_bytes.is_empty());
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_err());

        let reopened = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                assert!(matches!(phase, RestoreStopBarrier::AfterTemporarySync));
                Err(())
            })
            .is_err());
        drop(reopened);
        assert!(temporary_path.exists());

        let reopened = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                assert!(matches!(phase, RestoreStopBarrier::AfterRename));
                Err(())
            })
            .is_err());
        drop(reopened);
        assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
        let stopped_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let stopped: RestoreIncomplete = serde_json::from_slice(&stopped_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&stopped).unwrap(), stopped_bytes);
        assert_eq!(stopped.step, "stopped");
        assert!(!destination.join("restore.ready").exists());
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_err());

        let reopened = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        reopened
            .advance_installed_to_stopped_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreStopBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(reopened);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            stopped_bytes
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(
            fs::read(
                backup_root
                    .join(GENERATIONS)
                    .join(GENERATION_ONE)
                    .join("service")
                    .join(DATABASE)
            )
            .unwrap(),
            backup_database
        );
        assert_eq!(
            fs::read(
                backup_root
                    .join(GENERATIONS)
                    .join(GENERATION_ONE)
                    .join(DEPLOYMENT)
            )
            .unwrap(),
            backup_deployment
        );
        assert_eq!(
            fs::read(
                backup_root
                    .join(GENERATIONS)
                    .join(GENERATION_ONE)
                    .join(MANIFEST)
            )
            .unwrap(),
            backup_manifest
        );
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the expired restore tracer crosses every durable transaction and record side"
    )]
    fn selected_stopped_restore_applies_expiry_and_advances_expired_without_readiness() {
        let (base, state) = initialized("restore-expired");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let backup_database_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join("service")
            .join(DATABASE);
        let backup_deployment_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(DEPLOYMENT);
        let backup_manifest_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-expired-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_installed_to_stopped_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);

        let stopped_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let stopped: RestoreIncomplete = serde_json::from_slice(&stopped_bytes).unwrap();
        assert_eq!(stopped.step, "stopped");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let assert_not_ready = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        let assert_empty_public_state = || {
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "unexpected restored row in {table}");
            }
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
        };
        assert_not_ready();
        assert_empty_public_state();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                assert!(matches!(phase, RestoreExpiryBarrier::BeforeExpiryCommit));
                Err(())
            })
            .is_err());
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            stopped_bytes
        );
        assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
        assert_not_ready();
        assert_empty_public_state();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                if matches!(phase, RestoreExpiryBarrier::BeforeExpiryCommit) {
                    Ok(())
                } else {
                    assert!(matches!(phase, RestoreExpiryBarrier::AfterExpiryCommit));
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            stopped_bytes
        );
        assert_not_ready();
        assert_empty_public_state();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreExpiryBarrier::BeforeExpiryCommit
                        | RestoreExpiryBarrier::AfterExpiryCommit
                ) {
                    Ok(())
                } else {
                    assert!(matches!(phase, RestoreExpiryBarrier::AfterTemporarySync));
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_not_ready();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreExpiryBarrier::BeforeExpiryCommit
                        | RestoreExpiryBarrier::AfterExpiryCommit
                ) {
                    Ok(())
                } else {
                    assert!(matches!(phase, RestoreExpiryBarrier::AfterTemporarySync));
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_not_ready();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreExpiryBarrier::BeforeExpiryCommit
                        | RestoreExpiryBarrier::AfterExpiryCommit
                ) {
                    Ok(())
                } else {
                    assert!(matches!(phase, RestoreExpiryBarrier::AfterRename));
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let expired_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let expired: RestoreIncomplete = serde_json::from_slice(&expired_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&expired).unwrap(), expired_bytes);
        assert_eq!(expired.step, "expired");
        assert_not_ready();
        assert_empty_public_state();

        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_stopped_to_expired_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreExpiryBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            expired_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_not_ready();
        assert_empty_public_state();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the receipt restore tracer crosses convergence and every record side"
    )]
    fn selected_expired_restore_converges_empty_receipts_and_advances_without_readiness() {
        let (base, state) = initialized("restore-receipts");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let backup_database_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join("service")
            .join(DATABASE);
        let backup_deployment_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(DEPLOYMENT);
        let backup_manifest_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-receipts-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_installed_to_stopped_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_stopped_to_expired_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);

        let expired_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let expired: RestoreIncomplete = serde_json::from_slice(&expired_bytes).unwrap();
        assert_eq!(expired.step, "expired");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let assert_not_ready = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        let assert_empty_receipt_state = || {
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "unexpected restored row in {table}");
            }
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
        };
        assert_not_ready();
        assert_empty_receipt_state();

        for stopped_at in [
            RestoreReceiptBarrier::BeforeConvergence,
            RestoreReceiptBarrier::AfterConvergence,
        ] {
            let restore = RestoreGuard::reopen_expired_to_receipts(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_expired_to_receipts_with_barrier(&authority, |phase| {
                    if phase == stopped_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert_eq!(
                fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
                expired_bytes
            );
            assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_not_ready();
            assert_empty_receipt_state();
        }

        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_expired_to_receipts_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreReceiptBarrier::BeforeConvergence
                        | RestoreReceiptBarrier::AfterConvergence
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreReceiptBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_not_ready();
        assert_empty_receipt_state();

        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_expired_to_receipts_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreReceiptBarrier::BeforeConvergence
                        | RestoreReceiptBarrier::AfterConvergence
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreReceiptBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_not_ready();
        assert_empty_receipt_state();

        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_expired_to_receipts_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreReceiptBarrier::BeforeConvergence
                        | RestoreReceiptBarrier::AfterConvergence
                        | RestoreReceiptBarrier::AfterTemporarySync
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreReceiptBarrier::AfterRename);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let receipts_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let receipts: RestoreIncomplete = serde_json::from_slice(&receipts_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&receipts).unwrap(), receipts_bytes);
        assert_eq!(receipts.step, "receipts");
        assert_not_ready();
        assert_empty_receipt_state();

        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_expired_to_receipts_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreReceiptBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            receipts_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_not_ready();
        assert_empty_receipt_state();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the runner restore tracer crosses every semantic and record side"
    )]
    fn selected_receipts_restore_reconstructs_no_runner_and_advances_without_readiness() {
        let (base, state) = initialized("restore-runner");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let backup_database_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join("service")
            .join(DATABASE);
        let backup_deployment_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(DEPLOYMENT);
        let backup_manifest_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-runner-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_installed_to_stopped_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_stopped_to_expired_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_expired_to_receipts_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);

        let receipts_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let receipts: RestoreIncomplete = serde_json::from_slice(&receipts_bytes).unwrap();
        assert_eq!(receipts.step, "receipts");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let assert_not_ready = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        let assert_empty_runner_state = || {
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "unexpected restored row in {table}");
            }
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
        };
        assert_not_ready();
        assert_empty_runner_state();

        for stopped_at in [
            RestoreRunnerBarrier::BeforeReconstruction,
            RestoreRunnerBarrier::AfterReconstruction,
            RestoreRunnerBarrier::BeforeReconciliation,
            RestoreRunnerBarrier::AfterReconciliation,
        ] {
            let restore = RestoreGuard::reopen_receipts_to_runner(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_receipts_to_runner_with_barrier(&authority, |phase| {
                    if phase == stopped_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert_eq!(
                fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
                receipts_bytes
            );
            assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_not_ready();
            assert_empty_runner_state();
        }

        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_receipts_to_runner_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreRunnerBarrier::BeforeReconstruction
                        | RestoreRunnerBarrier::AfterReconstruction
                        | RestoreRunnerBarrier::BeforeReconciliation
                        | RestoreRunnerBarrier::AfterReconciliation
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreRunnerBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_not_ready();
        assert_empty_runner_state();

        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_receipts_to_runner_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreRunnerBarrier::BeforeReconstruction
                        | RestoreRunnerBarrier::AfterReconstruction
                        | RestoreRunnerBarrier::BeforeReconciliation
                        | RestoreRunnerBarrier::AfterReconciliation
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreRunnerBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_not_ready();
        assert_empty_runner_state();

        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_receipts_to_runner_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreRunnerBarrier::BeforeReconstruction
                        | RestoreRunnerBarrier::AfterReconstruction
                        | RestoreRunnerBarrier::BeforeReconciliation
                        | RestoreRunnerBarrier::AfterReconciliation
                        | RestoreRunnerBarrier::AfterTemporarySync
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreRunnerBarrier::AfterRename);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let runner_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let runner: RestoreIncomplete = serde_json::from_slice(&runner_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&runner).unwrap(), runner_bytes);
        assert_eq!(runner.step, "runner");
        assert_not_ready();
        assert_empty_runner_state();

        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_receipts_to_runner_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreRunnerBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            runner_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_not_ready();
        assert_empty_runner_state();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the lease restore tracer crosses every empty fixed-point and record side"
    )]
    fn selected_runner_restore_publishes_no_lease_and_advances_without_readiness() {
        let (base, state) = initialized("restore-lease");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let backup_database_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join("service")
            .join(DATABASE);
        let backup_deployment_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(DEPLOYMENT);
        let backup_manifest_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-lease-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_installed_to_stopped_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_stopped_to_expired_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_expired_to_receipts_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_receipts_to_runner_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);

        let runner_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let runner: RestoreIncomplete = serde_json::from_slice(&runner_bytes).unwrap();
        assert_eq!(runner.step, "runner");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let staged_root = authority_root.join("fixed-authority");
        let staged_generation = staged_root
            .join("generations")
            .join("generation-00000000000000000001");
        let staged_manifest = fs::read(staged_generation.join(MANIFEST)).unwrap();
        let staged_current = staged_root.join(CURRENT);
        fs::set_permissions(&staged_current, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&staged_current).unwrap();
        let dispatch = staged_root.join("dispatch");
        let assert_not_ready = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        let assert_empty_lease_state = || {
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "unexpected restored row in {table}");
            }
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(&dispatch).unwrap().next().is_none());
            assert!(!staged_current.exists());
            assert_eq!(
                fs::read(staged_generation.join(MANIFEST)).unwrap(),
                staged_manifest
            );
        };
        assert_not_ready();
        assert_empty_lease_state();

        for stopped_at in [
            RestoreLeaseBarrier::BeforePublicationFixedPoint,
            RestoreLeaseBarrier::AfterPublicationFixedPoint,
        ] {
            let restore = RestoreGuard::reopen_runner_to_lease(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_runner_to_lease_with_barrier(&authority, |phase| {
                    if phase == stopped_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert_eq!(
                fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
                runner_bytes
            );
            assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_not_ready();
            assert_empty_lease_state();
        }

        let restore = RestoreGuard::reopen_runner_to_lease(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_runner_to_lease_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreLeaseBarrier::BeforePublicationFixedPoint
                        | RestoreLeaseBarrier::AfterPublicationFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreLeaseBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_not_ready();
        assert_empty_lease_state();

        let restore = RestoreGuard::reopen_runner_to_lease(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_runner_to_lease_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreLeaseBarrier::BeforePublicationFixedPoint
                        | RestoreLeaseBarrier::AfterPublicationFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreLeaseBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_not_ready();
        assert_empty_lease_state();

        let restore = RestoreGuard::reopen_runner_to_lease(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_runner_to_lease_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreLeaseBarrier::BeforePublicationFixedPoint
                        | RestoreLeaseBarrier::AfterPublicationFixedPoint
                        | RestoreLeaseBarrier::AfterTemporarySync
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreLeaseBarrier::AfterRename);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let lease_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let lease: RestoreIncomplete = serde_json::from_slice(&lease_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&lease).unwrap(), lease_bytes);
        assert_eq!(lease.step, "lease");
        assert_not_ready();
        assert_empty_lease_state();

        let restore = RestoreGuard::reopen_runner_to_lease(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_runner_to_lease_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreLeaseBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            lease_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_not_ready();
        assert_empty_lease_state();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the cleanup restore tracer crosses every empty fixed-point and record side"
    )]
    fn selected_lease_restore_resumes_no_cleanup_and_advances_without_readiness() {
        let (base, state) = initialized("restore-cleanup");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let backup_database_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join("service")
            .join(DATABASE);
        let backup_deployment_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(DEPLOYMENT);
        let backup_manifest_path = backup_root
            .join(GENERATIONS)
            .join(GENERATION_ONE)
            .join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-cleanup-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_installed_to_stopped(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_installed_to_stopped_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_stopped_to_expired(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_stopped_to_expired_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_expired_to_receipts(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_expired_to_receipts_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_receipts_to_runner(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_receipts_to_runner_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);
        let restore = RestoreGuard::reopen_runner_to_lease(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_runner_to_lease_with_barrier(&authority, |_| Ok(()))
            .unwrap();
        drop(restore);

        let lease_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let lease: RestoreIncomplete = serde_json::from_slice(&lease_bytes).unwrap();
        assert_eq!(lease.step, "lease");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let staged_root = authority_root.join("fixed-authority");
        let staged_generation = staged_root
            .join("generations")
            .join("generation-00000000000000000001");
        let staged_manifest = fs::read(staged_generation.join(MANIFEST)).unwrap();
        let staged_current = staged_root.join(CURRENT);
        fs::set_permissions(&staged_current, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&staged_current).unwrap();
        let dispatch = staged_root.join("dispatch");
        let assert_not_ready = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        let assert_empty_cleanup_state = || {
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "unexpected restored row in {table}");
            }
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM backup_generations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(&dispatch).unwrap().next().is_none());
            assert!(!staged_current.exists());
            assert_eq!(
                fs::read(staged_generation.join(MANIFEST)).unwrap(),
                staged_manifest
            );
        };
        assert_not_ready();
        assert_empty_cleanup_state();

        for stopped_at in [
            RestoreCleanupBarrier::BeforeCleanupFixedPoint,
            RestoreCleanupBarrier::AfterCleanupFixedPoint,
        ] {
            let restore = RestoreGuard::reopen_lease_to_cleanup(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_lease_to_cleanup_with_barrier(&authority, |phase| {
                    if phase == stopped_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert_eq!(
                fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
                lease_bytes
            );
            assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_not_ready();
            assert_empty_cleanup_state();
        }

        let restore = RestoreGuard::reopen_lease_to_cleanup(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_lease_to_cleanup_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreCleanupBarrier::BeforeCleanupFixedPoint
                        | RestoreCleanupBarrier::AfterCleanupFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreCleanupBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_not_ready();
        assert_empty_cleanup_state();

        let restore = RestoreGuard::reopen_lease_to_cleanup(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_lease_to_cleanup_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreCleanupBarrier::BeforeCleanupFixedPoint
                        | RestoreCleanupBarrier::AfterCleanupFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreCleanupBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_not_ready();
        assert_empty_cleanup_state();

        let restore = RestoreGuard::reopen_lease_to_cleanup(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_lease_to_cleanup_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreCleanupBarrier::BeforeCleanupFixedPoint
                        | RestoreCleanupBarrier::AfterCleanupFixedPoint
                        | RestoreCleanupBarrier::AfterTemporarySync
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreCleanupBarrier::AfterRename);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let cleanup_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let cleanup_record: RestoreIncomplete = serde_json::from_slice(&cleanup_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&cleanup_record).unwrap(), cleanup_bytes);
        assert_eq!(cleanup_record.step, "cleanup");
        assert_not_ready();
        assert_empty_cleanup_state();

        let restore = RestoreGuard::reopen_lease_to_cleanup(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_lease_to_cleanup_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreCleanupBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            cleanup_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_not_ready();
        assert_empty_cleanup_state();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the validation restore tracer crosses every closed fixed-point and record side"
    )]
    fn selected_cleanup_restore_validates_unique_references_and_advances_without_readiness() {
        let (base, state) = initialized("restore-validation");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let generation = backup_root.join(GENERATIONS).join(GENERATION_ONE);
        let backup_database_path = generation.join("service").join(DATABASE);
        let backup_deployment_path = generation.join(DEPLOYMENT);
        let backup_manifest_path = generation.join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-validation-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        macro_rules! advance {
            ($reopen:ident, $advance:ident) => {{
                let restore = RestoreGuard::$reopen(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore.$advance(&authority, |_| Ok(())).unwrap();
                drop(restore);
            }};
        }
        advance!(
            reopen_installed_to_stopped,
            advance_installed_to_stopped_with_barrier
        );
        advance!(
            reopen_stopped_to_expired,
            advance_stopped_to_expired_with_barrier
        );
        advance!(
            reopen_expired_to_receipts,
            advance_expired_to_receipts_with_barrier
        );
        advance!(
            reopen_receipts_to_runner,
            advance_receipts_to_runner_with_barrier
        );
        advance!(reopen_runner_to_lease, advance_runner_to_lease_with_barrier);
        advance!(
            reopen_lease_to_cleanup,
            advance_lease_to_cleanup_with_barrier
        );

        let cleanup_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let cleanup_record: RestoreIncomplete = serde_json::from_slice(&cleanup_bytes).unwrap();
        assert_eq!(cleanup_record.step, "cleanup");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let staged_root = authority_root.join("fixed-authority");
        let staged_generation = staged_root
            .join("generations")
            .join("generation-00000000000000000001");
        let staged_manifest = fs::read(staged_generation.join(MANIFEST)).unwrap();
        let staged_current = staged_root.join(CURRENT);
        fs::set_permissions(&staged_current, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&staged_current).unwrap();
        let dispatch = staged_root.join("dispatch");
        let assert_closed = || {
            assert!(!destination.join("restore.ready").exists());
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
            let connection = rusqlite::Connection::open(destination.join(DATABASE)).unwrap();
            for table in [
                "runs",
                "tombstones",
                "receipts",
                "receipt_publications",
                "cleanup_records",
                "application_reports",
                "provisioned_object_owners",
                "events",
                "authority_collection",
                "backup_authority_references",
            ] {
                assert_eq!(
                    connection
                        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                            .get::<_, i64>(0))
                        .unwrap(),
                    0,
                    "unexpected restored row in {table}"
                );
            }
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM backup_generations WHERE slot = 'current'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
            assert!(fs::read_dir(destination.join("receipts"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(destination.join("runner"))
                .unwrap()
                .next()
                .is_none());
            assert!(fs::read_dir(&dispatch).unwrap().next().is_none());
            assert!(!staged_current.exists());
            assert_eq!(
                fs::read(staged_generation.join(MANIFEST)).unwrap(),
                staged_manifest
            );
        };
        assert_closed();

        for stopped_at in [
            RestoreValidationBarrier::BeforeValidationFixedPoint,
            RestoreValidationBarrier::AfterValidationFixedPoint,
        ] {
            let restore = RestoreGuard::reopen_cleanup_to_validated(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_cleanup_to_validated_with_barrier(&authority, |phase| {
                    if phase == stopped_at {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(restore);
            assert_eq!(
                fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
                cleanup_bytes
            );
            assert!(!destination.join(RESTORE_STATE_TEMPORARY).exists());
            assert_closed();
        }

        let restore = RestoreGuard::reopen_cleanup_to_validated(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_cleanup_to_validated_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreValidationBarrier::BeforeValidationFixedPoint
                        | RestoreValidationBarrier::AfterValidationFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreValidationBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let temporary_bytes = fs::read(&temporary_path).unwrap();
        fs::write(
            &temporary_path,
            &temporary_bytes[..temporary_bytes.len() / 2],
        )
        .unwrap();
        assert_closed();

        let restore = RestoreGuard::reopen_cleanup_to_validated(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_cleanup_to_validated_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreValidationBarrier::BeforeValidationFixedPoint
                        | RestoreValidationBarrier::AfterValidationFixedPoint
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreValidationBarrier::AfterTemporarySync);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), temporary_bytes);
        assert_closed();

        let restore = RestoreGuard::reopen_cleanup_to_validated(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_cleanup_to_validated_with_barrier(&authority, |phase| {
                if matches!(
                    phase,
                    RestoreValidationBarrier::BeforeValidationFixedPoint
                        | RestoreValidationBarrier::AfterValidationFixedPoint
                        | RestoreValidationBarrier::AfterTemporarySync
                ) {
                    Ok(())
                } else {
                    assert_eq!(phase, RestoreValidationBarrier::AfterRename);
                    Err(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        let validated_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let validated_record: RestoreIncomplete = serde_json::from_slice(&validated_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&validated_record).unwrap(),
            validated_bytes
        );
        assert_eq!(validated_record.step, "validated");
        assert_closed();

        let restore = RestoreGuard::reopen_cleanup_to_validated(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_cleanup_to_validated_with_barrier(&authority, |phase| {
                assert_eq!(phase, RestoreValidationBarrier::AfterStateRootSync);
                Ok(())
            })
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_eq!(
            fs::read(destination.join(DATABASE)).unwrap(),
            destination_database
        );
        assert_eq!(
            fs::read(destination.join(DEPLOYMENT)).unwrap(),
            destination_deployment
        );
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            source_database
        );
        assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
        assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
        assert_eq!(
            fs::read(&backup_deployment_path).unwrap(),
            backup_deployment
        );
        assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        assert_closed();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the readiness tracer crosses the temporary, two-record, unlink, and fsync sides"
    )]
    fn selected_validated_restore_publishes_exact_ready_with_recoverable_retry() {
        let (base, state) = initialized("restore-readiness");
        let backup_root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let backup =
            BackupRootGuard::open_initial(&state, &backup_root, BackupIdentity::current_process())
                .unwrap();
        let selected = backup
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        let selected_manifest = selected.manifest_sha256.clone();
        let selected_compatibility = selected.compatibility_sha256.clone();
        let source_database = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let generation = backup_root.join(GENERATIONS).join(GENERATION_ONE);
        let backup_database_path = generation.join("service").join(DATABASE);
        let backup_deployment_path = generation.join(DEPLOYMENT);
        let backup_manifest_path = generation.join(MANIFEST);
        let backup_database = fs::read(&backup_database_path).unwrap();
        let backup_current = fs::read(backup_root.join(CURRENT)).unwrap();
        let backup_deployment = fs::read(&backup_deployment_path).unwrap();
        let backup_manifest = fs::read(&backup_manifest_path).unwrap();
        drop(selected);
        drop(backup);
        drop(state);

        let restore_parent = base.join("restore-readiness-parent");
        fs::create_dir(&restore_parent).unwrap();
        mode(&restore_parent, 0o700);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(restore_parent.join(PARENT_RESTORE_LOCK))
            .unwrap();
        let destination = restore_parent.join("state");
        let identities = RoleIdentities::test_controller();
        let restore = RestoreGuard::open_selected_clean(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore.install_incomplete(1_774_051_201).unwrap();
        drop(restore);
        macro_rules! advance {
            ($reopen:ident, $advance:ident) => {{
                let restore = RestoreGuard::$reopen(
                    &destination,
                    &backup_root,
                    BackupIdentity::current_process(),
                    BackupIdentity::current_process(),
                    DeploymentProfile::Test,
                )
                .unwrap();
                restore.$advance(&authority, |_| Ok(())).unwrap();
                drop(restore);
            }};
        }
        advance!(
            reopen_installed_to_stopped,
            advance_installed_to_stopped_with_barrier
        );
        advance!(
            reopen_stopped_to_expired,
            advance_stopped_to_expired_with_barrier
        );
        advance!(
            reopen_expired_to_receipts,
            advance_expired_to_receipts_with_barrier
        );
        advance!(
            reopen_receipts_to_runner,
            advance_receipts_to_runner_with_barrier
        );
        advance!(reopen_runner_to_lease, advance_runner_to_lease_with_barrier);
        advance!(
            reopen_lease_to_cleanup,
            advance_lease_to_cleanup_with_barrier
        );
        advance!(
            reopen_cleanup_to_validated,
            advance_cleanup_to_validated_with_barrier
        );

        let validated_bytes = fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap();
        let validated: RestoreIncomplete = serde_json::from_slice(&validated_bytes).unwrap();
        assert_eq!(validated.step, "validated");
        let destination_database = fs::read(destination.join(DATABASE)).unwrap();
        let destination_deployment = fs::read(destination.join(DEPLOYMENT)).unwrap();
        let assert_preserved = || {
            assert_eq!(
                fs::read(destination.join(DATABASE)).unwrap(),
                destination_database
            );
            assert_eq!(
                fs::read(destination.join(DEPLOYMENT)).unwrap(),
                destination_deployment
            );
            assert_eq!(
                fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
                source_database
            );
            assert_eq!(fs::read(backup_root.join(CURRENT)).unwrap(), backup_current);
            assert_eq!(fs::read(&backup_database_path).unwrap(), backup_database);
            assert_eq!(
                fs::read(&backup_deployment_path).unwrap(),
                backup_deployment
            );
            assert_eq!(fs::read(&backup_manifest_path).unwrap(), backup_manifest);
        };
        let assert_not_ready = || {
            assert!(crate::state_root::StateGuard::open(
                &destination,
                identities,
                DeploymentProfile::Test,
            )
            .is_err());
        };
        assert_not_ready();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                assert_eq!(phase, RestoreReadinessBarrier::AfterTemporarySync);
                Err(())
            })
            .is_err());
        drop(restore);
        let temporary_path = destination.join(RESTORE_STATE_TEMPORARY);
        let ready_bytes = fs::read(&temporary_path).unwrap();
        let ready: serde_json::Value = serde_json::from_slice(&ready_bytes).unwrap();
        assert_eq!(ready["schema"], "kapsel.sandbox.restore-ready.v1");
        assert_eq!(ready["source"], "restored");
        assert_eq!(ready["generation"], 1);
        assert_eq!(ready["manifest_sha256"], selected_manifest);
        assert_eq!(ready["compatibility_sha256"], selected_compatibility);
        assert_eq!(ready["completed_at"], 1_774_051_201_i64);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        fs::remove_file(&temporary_path).unwrap();
        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                assert_eq!(phase, RestoreReadinessBarrier::AfterTemporarySync);
                fs::remove_file(&temporary_path).unwrap();
                fs::write(&temporary_path, &ready_bytes).unwrap();
                fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)).unwrap();
                Ok(())
            })
            .is_err());
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        fs::remove_file(&temporary_path).unwrap();
        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                assert_eq!(phase, RestoreReadinessBarrier::AfterTemporarySync);
                fs::remove_file(destination.join(RESTORE_INCOMPLETE)).unwrap();
                fs::write(destination.join(RESTORE_INCOMPLETE), &validated_bytes).unwrap();
                fs::set_permissions(
                    destination.join(RESTORE_INCOMPLETE),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                Ok(())
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), ready_bytes);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        fs::write(&temporary_path, &ready_bytes[..ready_bytes.len() / 2]).unwrap();
        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                assert_eq!(phase, RestoreReadinessBarrier::AfterTemporarySync);
                Err(())
            })
            .is_err());
        drop(restore);
        assert_eq!(fs::read(&temporary_path).unwrap(), ready_bytes);
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterReadyRename {
                    Err(())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!temporary_path.exists());
        assert_eq!(
            fs::read(destination.join("restore.ready")).unwrap(),
            ready_bytes
        );
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterPairSync {
                    Err(())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(restore);
        assert_eq!(
            fs::read(destination.join("restore.ready")).unwrap(),
            ready_bytes
        );
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let ready_path = destination.join(RESTORE_READY);
        let mut mismatched_ready: RestoreReady = serde_json::from_slice(&ready_bytes).unwrap();
        mismatched_ready.completed_at += 1;
        fs::write(&ready_path, serde_json::to_vec(&mismatched_ready).unwrap()).unwrap();
        assert!(RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .is_err());
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        fs::write(&ready_path, &ready_bytes).unwrap();
        fs::set_permissions(&ready_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .is_err());
        fs::set_permissions(&ready_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&ready_path, destination.join("unexpected-ready-link")).unwrap();
        assert!(RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .is_err());
        fs::remove_file(destination.join("unexpected-ready-link")).unwrap();
        fs::write(destination.join("unexpected-state-entry"), b"unexpected").unwrap();
        assert!(RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .is_err());
        fs::remove_file(destination.join("unexpected-state-entry")).unwrap();
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterPairSync {
                    fs::set_permissions(
                        destination.join(DEPLOYMENT),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                Ok(())
            })
            .is_err());
        drop(restore);
        fs::set_permissions(
            destination.join(DEPLOYMENT),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterPairSync {
                    fs::set_permissions(
                        backup_root.join(CURRENT),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                Ok(())
            })
            .is_err());
        drop(restore);
        fs::set_permissions(backup_root.join(CURRENT), fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterPairSync {
                    fs::set_permissions(destination.join(LOCK), fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                Ok(())
            })
            .is_err());
        drop(restore);
        fs::set_permissions(destination.join(LOCK), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterPairSync {
                    fs::remove_file(&ready_path).unwrap();
                    fs::write(&ready_path, &ready_bytes).unwrap();
                    fs::set_permissions(&ready_path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                Ok(())
            })
            .is_err());
        drop(restore);
        assert_eq!(
            fs::read(destination.join(RESTORE_INCOMPLETE)).unwrap(),
            validated_bytes
        );
        assert_not_ready();
        assert_preserved();

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        assert!(restore
            .advance_validated_to_ready_with_barrier(|phase| {
                if phase == RestoreReadinessBarrier::AfterIncompleteUnlink {
                    assert!(crate::state_root::StateGuard::open(
                        &destination,
                        identities,
                        DeploymentProfile::Test,
                    )
                    .is_err());
                    Err(())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(restore);
        assert!(!destination.join(RESTORE_INCOMPLETE).exists());
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_ok());
        assert_preserved();

        for substituted_at in [
            RestoreReadinessBarrier::AfterFinalStateSync,
            RestoreReadinessBarrier::AfterParentSync,
        ] {
            let restore = RestoreGuard::reopen_validated_to_ready(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            assert!(restore
                .advance_validated_to_ready_with_barrier(|phase| {
                    if phase == substituted_at {
                        fs::remove_file(&ready_path).unwrap();
                        fs::write(&ready_path, &ready_bytes).unwrap();
                        fs::set_permissions(&ready_path, fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    Ok(())
                })
                .is_err());
            drop(restore);
            assert_eq!(fs::read(&ready_path).unwrap(), ready_bytes);
            assert_preserved();
        }

        for stopped_at in [
            RestoreReadinessBarrier::AfterFinalStateSync,
            RestoreReadinessBarrier::AfterParentSync,
        ] {
            let restore = RestoreGuard::reopen_validated_to_ready(
                &destination,
                &backup_root,
                BackupIdentity::current_process(),
                BackupIdentity::current_process(),
                DeploymentProfile::Test,
            )
            .unwrap();
            let result = restore.advance_validated_to_ready_with_barrier(|phase| {
                if phase == stopped_at {
                    Err(())
                } else {
                    Ok(())
                }
            });
            drop(restore);
            assert!(result.is_err());
            assert_eq!(
                fs::read(destination.join("restore.ready")).unwrap(),
                ready_bytes
            );
            assert_preserved();
        }

        let restore = RestoreGuard::reopen_validated_to_ready(
            &destination,
            &backup_root,
            BackupIdentity::current_process(),
            BackupIdentity::current_process(),
            DeploymentProfile::Test,
        )
        .unwrap();
        restore
            .advance_validated_to_ready_with_barrier(|_| Ok(()))
            .unwrap();
        drop(restore);
        assert_eq!(
            fs::read(destination.join("restore.ready")).unwrap(),
            ready_bytes
        );
        assert!(crate::state_root::StateGuard::open(
            &destination,
            identities,
            DeploymentProfile::Test,
        )
        .is_ok());
        assert_preserved();
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn initial_clean_capture_crosses_p1_selected_validation_then_p2() {
        let (base, state) = initialized("capture-initial");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_201)
            .unwrap();
        assert_eq!(selected.generation, 1);
        assert_eq!(selected.captured_at, 1_774_051_201);
        let current_bytes = fs::read(root.join(CURRENT)).unwrap();
        let current: CurrentRecord = serde_json::from_slice(&current_bytes).unwrap();
        assert_eq!(current.manifest_sha256, selected.manifest_sha256);
        let copied = rusqlite::Connection::open(
            root.join(GENERATIONS)
                .join(GENERATION_ONE)
                .join("service")
                .join(DATABASE),
        )
        .unwrap();
        assert_eq!(
            copied
                .query_row(
                    concat!(
                        "SELECT generation, state, captured_at FROM backup_generations ",
                        "WHERE slot = 'pending'"
                    ),
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (1, "pending".to_owned(), 1_774_051_201)
        );
        assert_eq!(
            copied
                .query_row(
                    "SELECT COUNT(*) FROM backup_authority_references",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        let service = state.open_stopped_service(&authority).unwrap();
        let publication = service.publication_state().unwrap();
        assert!(matches!(
            publication,
            BackupPublicationState::Current(ref current)
                if current.manifest_digest == selected.manifest_sha256
        ));
        drop(service);
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_without_bytes_retries_same_initial_generation() {
        let (base, state) = initialized("recover-p1-no-bytes");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.generation, pending.generation);
        assert_eq!(selected.captured_at, pending.captured_at);
        let service = state.open_stopped_service(&authority).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            BackupPublicationState::Current(crate::PublishedBackup {
                generation: pending.generation,
                captured_at: pending.captured_at,
                manifest_digest: selected.manifest_sha256.clone(),
                authorities: Vec::new(),
            })
        );
        drop(service);
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_with_exact_incomplete_temporary_restarts_same_generation() {
        let (base, state) = initialized("recover-partial-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        fs::create_dir(root.join(GENERATIONS).join(GENERATION_TMP)).unwrap();
        mode(&root.join(GENERATIONS).join(GENERATION_TMP), 0o700);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.generation, pending.generation);
        assert_eq!(selected.captured_at, pending.captured_at);
        assert!(!root.join(GENERATIONS).join(GENERATION_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_with_closed_partial_temporary_restarts_same_generation() {
        let (base, state) = initialized("recover-populated-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let temporary = root.join(GENERATIONS).join(GENERATION_TMP);
        fs::create_dir(&temporary).unwrap();
        mode(&temporary, 0o700);
        fs::create_dir(temporary.join("service")).unwrap();
        mode(&temporary.join("service"), 0o700);
        fs::copy(
            base.join("state-parent/state").join(DATABASE),
            temporary.join("service").join(DATABASE),
        )
        .unwrap();
        mode(&temporary.join("service").join(DATABASE), 0o400);
        fs::create_dir(temporary.join("receipts")).unwrap();
        mode(&temporary.join("receipts"), 0o500);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert!(!root.join(GENERATIONS).join(GENERATION_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_with_sealed_temporary_finishes_generation_publication() {
        let (base, state) = initialized("recover-sealed-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let complete = install_generation(&root, &state);
        fs::rename(&complete, root.join(GENERATIONS).join(GENERATION_TMP)).unwrap();
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert!(root.join(GENERATIONS).join(GENERATION_ONE).is_dir());
        assert!(!root.join(GENERATIONS).join(GENERATION_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_with_complete_generation_publishes_current_then_finishes_p2() {
        let (base, state) = initialized("recover-complete-generation");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        install_generation(&root, &state);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert!(root.join(CURRENT).is_file());
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Current(ref current)
                if current.generation == 1
                    && current.captured_at == pending.captured_at
                    && current.manifest_digest == selected.manifest_sha256
        ));
        drop(service);
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn empty_writable_current_temporary_is_republished_before_initial_p2() {
        let (base, state) = initialized("recover-empty-current-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let manifest_sha256 = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        fs::write(root.join(CURRENT_TMP), b"").unwrap();
        mode(&root.join(CURRENT_TMP), 0o600);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert_eq!(selected.manifest_sha256, manifest_sha256);
        assert!(root.join(CURRENT).is_file());
        assert!(!root.join(CURRENT_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn strict_prefix_current_temporary_is_republished_before_initial_p2() {
        let (base, state) = initialized("recover-prefix-current-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let manifest_sha256 = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        let expected = serde_json::to_vec(&CurrentRecord {
            schema: "kapsel.sandbox.backup.current.v1".to_owned(),
            generation: 1,
            manifest_sha256: manifest_sha256.clone(),
        })
        .unwrap();
        fs::write(root.join(CURRENT_TMP), &expected[..expected.len() / 2]).unwrap();
        mode(&root.join(CURRENT_TMP), 0o600);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert_eq!(selected.manifest_sha256, manifest_sha256);
        assert!(root.join(CURRENT).is_file());
        assert!(!root.join(CURRENT_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn canonical_current_temporary_is_finished_before_initial_p2() {
        let (base, state) = initialized("recover-current-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let manifest_sha256 = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        fs::write(
            root.join(CURRENT_TMP),
            serde_json::to_vec(&CurrentRecord {
                schema: "kapsel.sandbox.backup.current.v1".to_owned(),
                generation: 1,
                manifest_sha256: manifest_sha256.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        mode(&root.join(CURRENT_TMP), 0o600);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.captured_at, pending.captured_at);
        assert_eq!(selected.manifest_sha256, manifest_sha256);
        assert!(root.join(CURRENT).is_file());
        assert!(!root.join(CURRENT_TMP).exists());
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn nonprefix_current_temporary_fails_without_mutation() {
        let (base, state) = initialized("reject-nonprefix-current-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        install_generation(&root, &state);
        fs::write(root.join(CURRENT_TMP), b"not-a-canonical-prefix").unwrap();
        mode(&root.join(CURRENT_TMP), 0o600);
        let database_before = fs::read(base.join("state-parent/state").join(DATABASE)).unwrap();
        let temporary_before = fs::read(root.join(CURRENT_TMP)).unwrap();
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .is_err());
        assert_eq!(fs::read(root.join(CURRENT_TMP)).unwrap(), temporary_before);
        assert_eq!(
            fs::read(base.join("state-parent/state").join(DATABASE)).unwrap(),
            database_before
        );
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Pending(ref actual) if actual == &pending
        ));
        drop(service);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn selected_generation_with_pending_finishes_initial_p2() {
        let (base, state) = initialized("recover-selected-pending");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let manifest_sha256 = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        fs::write(
            root.join(CURRENT),
            serde_json::to_vec(&CurrentRecord {
                schema: "kapsel.sandbox.backup.current.v1".to_owned(),
                generation: 1,
                manifest_sha256: manifest_sha256.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        mode(&root.join(CURRENT), 0o400);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.manifest_sha256, manifest_sha256);
        assert_eq!(selected.captured_at, pending.captured_at);
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Current(ref current)
                if current.manifest_digest == selected.manifest_sha256
        ));
        drop(service);
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_partial_complete_generation_fails_without_publication() {
        let (base, state) = initialized("reject-partial-complete");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let database = generation.join("service").join(DATABASE);
        mode(&generation.join("service"), 0o700);
        mode(&database, 0o600);
        let mut bytes = fs::read(&database).unwrap();
        bytes[0] ^= 1;
        fs::write(&database, bytes).unwrap();
        mode(&database, 0o400);
        mode(&generation.join("service"), 0o500);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .is_err());
        assert!(!root.join(CURRENT).exists());
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Pending(ref actual) if actual == &pending
        ));
        drop(service);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn pending_complete_generation_with_different_capture_time_fails_before_current() {
        let (base, state) = initialized("reject-mismatched-capture-time");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_202).unwrap();
        drop(service);
        install_generation(&root, &state);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .is_err());
        assert!(!root.join(CURRENT).exists());
        assert!(!root.join(CURRENT_TMP).exists());
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Pending(ref actual) if actual == &pending
        ));
        drop(service);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn hostile_partial_temporary_fails_without_deletion_or_p2() {
        let (base, state) = initialized("reject-hostile-temporary");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let temporary = root.join(GENERATIONS).join(GENERATION_TMP);
        fs::create_dir(&temporary).unwrap();
        mode(&temporary, 0o700);
        fs::write(temporary.join("private-seed"), b"must-not-delete").unwrap();
        mode(&temporary.join("private-seed"), 0o400);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .is_err());
        assert_eq!(
            fs::read(temporary.join("private-seed")).unwrap(),
            b"must-not-delete"
        );
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Pending(ref actual) if actual == &pending
        ));
        drop(service);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn steady_service_digest_mismatch_fails_without_filesystem_mutation() {
        let (base, state) = initialized("reject-steady-digest-mismatch");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let digest = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        fs::write(
            root.join(CURRENT),
            serde_json::to_vec(&CurrentRecord {
                schema: "kapsel.sandbox.backup.current.v1".to_owned(),
                generation: 1,
                manifest_sha256: digest.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        mode(&root.join(CURRENT), 0o400);
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(service.finish_publication(1, &digest).unwrap().is_none());
        drop(service);
        drop(state);
        let database = base.join("state-parent/state").join(DATABASE);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute(
                "UPDATE backup_generations SET manifest_digest = ?1 WHERE slot = 'current'",
                ["0".repeat(64)],
            )
            .unwrap();
        drop(connection);
        let current_before = fs::read(root.join(CURRENT)).unwrap();
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .is_err());
        assert_eq!(fs::read(root.join(CURRENT)).unwrap(), current_before);
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Current(ref current)
                if current.manifest_digest == "0".repeat(64)
        ));
        drop(service);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn complete_generation_without_pending_fails_without_creating_rows() {
        let (base, state) = initialized("reject-complete-without-pending");
        let root = initial_root(&base);
        install_generation(&root, &state);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        drop(state);
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        assert!(guard
            .capture_initial_clean(&authority, 1_774_051_201)
            .is_err());
        let service = state.open_stopped_service(&authority).unwrap();
        assert_eq!(
            service.publication_state().unwrap(),
            BackupPublicationState::Empty
        );
        drop(service);
        assert!(!root.join(CURRENT).exists());
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn exact_initial_steady_state_is_idempotent() {
        let (base, state) = initialized("recover-steady");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let service = state.open_stopped_service(&authority).unwrap();
        let pending = service.begin_publication(1, 1_774_051_201).unwrap();
        drop(service);
        let generation = install_generation(&root, &state);
        let digest = digest_bytes(&fs::read(generation.join(MANIFEST)).unwrap());
        fs::write(
            root.join(CURRENT),
            serde_json::to_vec(&CurrentRecord {
                schema: "kapsel.sandbox.backup.current.v1".to_owned(),
                generation: 1,
                manifest_sha256: digest.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        mode(&root.join(CURRENT), 0o400);
        let service = state.open_stopped_service(&authority).unwrap();
        assert_eq!(service.resume_pending().unwrap(), pending);
        assert!(service.finish_publication(1, &digest).unwrap().is_none());
        drop(service);
        drop(state);
        let before_current = fs::read(root.join(CURRENT)).unwrap();
        let state = reopen_state(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();

        let selected = guard
            .capture_initial_clean(&authority, 1_774_051_299)
            .unwrap();
        assert_eq!(selected.manifest_sha256, digest);
        assert_eq!(selected.captured_at, 1_774_051_201);
        assert_eq!(fs::read(root.join(CURRENT)).unwrap(), before_current);
        selected.verify().unwrap();
        drop(selected);
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn selected_substitution_before_p2_leaves_pending_source_unchanged() {
        let (base, state) = initialized("capture-pre-p2-substitution");
        let root = initial_root(&base);
        let authority_root = base.join("authority");
        fs::create_dir(&authority_root).unwrap();
        mode(&authority_root, 0o700);
        let authority = crate::test_authority::configuration(&authority_root, [7; 32]);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();
        let current_path = root.join(CURRENT);

        assert!(guard
            .capture_initial_clean_with_barrier(&authority, 1_774_051_201, || {
                let original = root.join("original-current");
                fs::rename(&current_path, &original).map_err(|_| ())?;
                fs::copy(&original, &current_path).map_err(|_| ())?;
                mode(&current_path, 0o400);
                Ok(true)
            })
            .is_err());
        let service = state.open_stopped_service(&authority).unwrap();
        assert!(matches!(
            service.publication_state().unwrap(),
            BackupPublicationState::Pending(ref pending) if pending.generation == 1
        ));
        drop(service);
        assert!(root.join(CURRENT).exists());
        assert!(root.join("original-current").exists());
        drop(guard);
        crate::test_authority::remove_root(&authority_root);
        cleanup(&base);
    }

    #[test]
    fn production_backup_identity_is_closed() {
        assert!(BackupIdentity::production(BACKUP_ID, BACKUP_ID).is_ok());
        assert!(BackupIdentity::production(BACKUP_ID + 1, BACKUP_ID).is_err());
        assert!(BackupIdentity::production(BACKUP_ID, BACKUP_ID + 1).is_err());
    }

    #[test]
    fn initial_guard_locks_and_pins_closed_root() {
        let (base, state) = initialized("initial");
        let root = initial_root(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();
        let competing = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(LOCK))
            .unwrap();
        assert!(flock(&competing, FlockOperation::NonBlockingLockExclusive).is_err());
        let moved = root.with_file_name("moved");
        fs::rename(&root, &moved).unwrap();
        symlink(&moved, &root).unwrap();
        assert!(guard.verify_pins().is_err());
        fs::remove_file(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        assert!(guard.verify_pins().is_ok());
        drop(guard);
        cleanup(&base);
    }

    #[test]
    fn canonical_clean_generation_is_reopened_and_validated() {
        let (base, state) = initialized("canonical");
        let root = initial_root(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();
        install_generation(&root, &state);
        let validated = guard.validate_clean_generation().unwrap();
        assert_eq!(validated.generation, 1);
        assert_eq!(validated.captured_at, 1_774_051_201);
        assert_eq!(validated.manifest_sha256.len(), 64);
        assert_eq!(validated.compatibility_sha256.len(), 64);
        validated.verify().unwrap();
        drop(validated);
        drop(guard);
        cleanup(&base);
    }

    #[test]
    fn validated_generation_rejects_generation_and_file_substitution() {
        let (base, state) = initialized("substitution");
        let root = initial_root(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();
        let generation = install_generation(&root, &state);
        let validated = guard.validate_clean_generation().unwrap();

        let moved = generation.with_file_name("moved-generation");
        fs::rename(&generation, &moved).unwrap();
        symlink(&moved, &generation).unwrap();
        assert!(validated.verify().is_err());
        fs::remove_file(&generation).unwrap();
        fs::rename(&moved, &generation).unwrap();
        validated.verify().unwrap();

        mode(&generation, 0o700);
        let manifest = generation.join(MANIFEST);
        let moved_manifest = generation.join("moved-manifest.json");
        fs::rename(&manifest, &moved_manifest).unwrap();
        fs::copy(&moved_manifest, &manifest).unwrap();
        mode(&manifest, 0o400);
        mode(&generation, 0o500);
        assert!(validated.verify().is_err());
        mode(&generation, 0o700);
        fs::remove_file(&manifest).unwrap();
        fs::rename(&moved_manifest, &manifest).unwrap();
        mode(&generation, 0o500);
        validated.verify().unwrap();

        mode(&generation.join("receipts"), 0o700);
        fs::write(generation.join("receipts/extra"), b"extra").unwrap();
        mode(&generation.join("receipts/extra"), 0o400);
        mode(&generation.join("receipts"), 0o500);
        assert!(validated.verify().is_err());
        mode(&generation.join("receipts"), 0o700);
        fs::remove_file(generation.join("receipts/extra")).unwrap();
        mode(&generation.join("receipts"), 0o500);
        validated.verify().unwrap();

        let database = generation.join("service").join(DATABASE);
        mode(&generation.join("service"), 0o700);
        mode(&database, 0o600);
        let mut bytes = fs::read(&database).unwrap();
        bytes[0] ^= 1;
        fs::write(&database, bytes).unwrap();
        mode(&database, 0o400);
        mode(&generation.join("service"), 0o500);
        assert!(validated.verify().is_err());
        drop(validated);
        drop(guard);
        cleanup(&base);
    }

    #[test]
    fn initial_clean_generation_rejects_generation_two() {
        let (base, state) = initialized("generation-two");
        let root = initial_root(&base);
        let guard = BackupRootGuard::open_initial(&state, &root, BackupIdentity::current_process())
            .unwrap();
        let generation = install_generation(&root, &state);
        let second = generation.with_file_name("backup-00000000000000000002");
        fs::rename(&generation, &second).unwrap();
        assert!(guard.validate_clean_generation().is_err());
        drop(guard);
        cleanup(&base);
    }

    #[test]
    fn guards_reject_inventory_mode_manifest_digest_link_and_special_type() {
        let (base, state) = initialized("negative");
        let root = initial_root(&base);
        let identity = BackupIdentity::current_process();
        mode(&root.join(LOCK), 0o640);
        assert!(BackupRootGuard::open_initial(&state, &root, identity).is_err());
        mode(&root.join(LOCK), 0o600);
        let guard = BackupRootGuard::open_initial(&state, &root, identity).unwrap();
        let generation = install_generation(&root, &state);

        mode(&generation.join("receipts"), 0o700);
        assert!(guard.validate_clean_generation().is_err());
        mode(&generation.join("receipts"), 0o500);

        mode(&generation.join(MANIFEST), 0o600);
        let original_manifest = fs::read(generation.join(MANIFEST)).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        value["unknown"] = serde_json::json!(true);
        fs::write(
            generation.join(MANIFEST),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        mode(&generation.join(MANIFEST), 0o400);
        assert!(guard.validate_clean_generation().is_err());
        mode(&generation.join(MANIFEST), 0o600);
        fs::write(generation.join(MANIFEST), &original_manifest).unwrap();
        mode(&generation.join(MANIFEST), 0o400);

        mode(&generation.join("service"), 0o700);
        let database = generation.join("service").join(DATABASE);
        let original_database = fs::read(&database).unwrap();
        mode(&database, 0o600);
        fs::write(&database, b"changed").unwrap();
        mode(&database, 0o400);
        mode(&generation.join("service"), 0o500);
        assert!(guard.validate_clean_generation().is_err());
        mode(&generation.join("service"), 0o700);
        mode(&database, 0o600);
        fs::write(&database, original_database).unwrap();
        mode(&database, 0o400);
        mode(&generation.join("service"), 0o500);

        let outside_link = root.parent().unwrap().join("linked-deployment");
        fs::hard_link(generation.join(DEPLOYMENT), &outside_link).unwrap();
        assert!(guard.validate_clean_generation().is_err());
        fs::remove_file(outside_link).unwrap();

        mode(&generation.join("service"), 0o700);
        fs::remove_file(&database).unwrap();
        symlink(generation.join(MANIFEST), &database).unwrap();
        mode(&generation.join("service"), 0o500);
        assert!(guard.validate_clean_generation().is_err());
        drop(guard);
        cleanup(&base);
    }
}
