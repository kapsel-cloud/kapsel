//! Descriptor-pinned backup-root inventory and complete clean-generation validation.

use std::{
    collections::BTreeSet,
    ffi::OsString,
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

#[derive(Clone, Copy)]
#[allow(
    clippy::enum_variant_names,
    reason = "fault barriers name the durable side reached before simulated process loss"
)]
enum RestoreStopBarrier {
    AfterPublication,
    AfterTemporarySync,
    AfterRename,
}

#[derive(Clone, Copy)]
enum RestoreExpiryBarrier {
    BeforeExpiryCommit,
    AfterExpiryCommit,
    AfterTemporarySync,
    AfterRename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreReceiptBarrier {
    BeforeConvergence,
    AfterConvergence,
    AfterTemporarySync,
    AfterRename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreRunnerBarrier {
    BeforeReconstruction,
    AfterReconstruction,
    BeforeReconciliation,
    AfterReconciliation,
    AfterTemporarySync,
    AfterRename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreLeaseBarrier {
    BeforePublicationFixedPoint,
    AfterPublicationFixedPoint,
    AfterTemporarySync,
    AfterRename,
}

#[derive(Clone, Copy)]
enum RestoreTransition {
    InstalledToStopped,
    StoppedToExpired,
    ExpiredToReceipts,
    ReceiptsToRunner,
    RunnerToLease,
}

impl RestoreTransition {
    fn steps(self) -> (&'static str, &'static str) {
        match self {
            Self::InstalledToStopped => ("installed", "stopped"),
            Self::StoppedToExpired => ("stopped", "expired"),
            Self::ExpiredToReceipts => ("expired", "receipts"),
            Self::ReceiptsToRunner => ("receipts", "runner"),
            Self::RunnerToLease => ("runner", "lease"),
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
        )
    }

    fn open_selected_clean_prefix(
        destination: &Path,
        backup_path: &Path,
        controller: BackupIdentity,
        backup_identity: BackupIdentity,
        profile: crate::state_root::DeploymentProfile,
        installed: bool,
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
        guard.verify(installed, false)?;
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
        if names(temporary, 7)? != expected {
            return Err(());
        }
        validate_directory(temporary, self.controller.uid, self.controller.gid, 0o700)?;
        validate_directory(receipts, self.controller.uid, self.controller.gid, 0o700)?;
        validate_directory(runner, self.controller.uid, self.controller.gid, 0o700)?;
        if !names(receipts, 1)?.is_empty() || !names(runner, 1)?.is_empty() {
            return Err(());
        }
        validate_file(database, self.controller, 0o600, DATABASE_MAX)?;
        validate_file(deployment, self.controller, 0o400, 16 * 1024)?;
        validate_file(state_lock, self.controller, 0o600, 0)?;
        validate_file(incomplete_file, self.controller, 0o600, 1024)?;
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

    fn install_incomplete(&self, started_at: i64) -> Result<(), ()> {
        if started_at < self.manifest.captured_at {
            return Err(());
        }
        self.verify(false, false)?;
        let temporary = create_restored_directory(
            &self.destination_parent,
            RESTORE_TEMPORARY,
            self.controller,
        )?;
        let database = copy_restored_file(
            &self.database,
            &temporary,
            DATABASE,
            self.controller,
            DATABASE_MAX,
        )?;
        let deployment = copy_restored_file(
            &self.deployment,
            &temporary,
            DEPLOYMENT,
            self.controller,
            16 * 1024,
        )?;
        fchmod(&deployment, Mode::from_raw_mode(0o400)).map_err(|_| ())?;
        let receipts = create_restored_directory(&temporary, "receipts", self.controller)?;
        let runner = create_restored_directory(&temporary, "runner", self.controller)?;
        let state_lock = write_restored_file(&temporary, LOCK, b"", self.controller, 0)?;
        let incomplete = RestoreIncomplete {
            schema: "kapsel.sandbox.restore-incomplete.v1".to_owned(),
            generation: self.manifest.generation,
            manifest_sha256: self.manifest_sha256.clone(),
            compatibility_sha256: self.manifest.compatibility_sha256.clone(),
            started_at,
            step: "installed".to_owned(),
        };
        let incomplete_file = write_restored_file(
            &temporary,
            RESTORE_INCOMPLETE,
            &serde_json::to_vec(&incomplete).map_err(|_| ())?,
            self.controller,
            1024,
        )?;
        for file in [&database, &deployment, &state_lock, &incomplete_file] {
            file.sync_all().map_err(|_| ())?;
        }
        for directory in [&receipts, &runner] {
            directory.sync_all().map_err(|_| ())?;
        }
        temporary.sync_all().map_err(|_| ())?;
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
        renameat(
            &self.destination_parent,
            RESTORE_TEMPORARY,
            &self.destination_parent,
            &self.destination_name,
        )
        .map_err(|_| ())?;
        self.destination_parent.sync_all().map_err(|_| ())?;
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
        )?;
        let prefix = guard.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        if !matches!(prefix.record.step.as_str(), "runner" | "lease") {
            return Err(());
        }
        Ok(guard)
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
            prefix.root.sync_all().map_err(|_| ())?;
            self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
            return Ok(());
        }
        if !prefix.current_publication {
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
        if let Some(temporary) = prefix.temporary.take() {
            let bytes = read_bounded(&temporary, 1024)?;
            drop(temporary);
            if bytes != stopped_bytes {
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
            write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &stopped_bytes,
                self.controller,
                1024,
            )?;
            barrier(RestoreStopBarrier::AfterTemporarySync)?;
        }
        self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
        renameat(
            &prefix.root,
            RESTORE_STATE_TEMPORARY,
            &prefix.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(RestoreStopBarrier::AfterRename)?;
        prefix.root.sync_all().map_err(|_| ())?;
        let stopped_prefix =
            self.open_restored_clean_prefix(RestoreTransition::InstalledToStopped)?;
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
            prefix.root.sync_all().map_err(|_| ())?;
            self.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
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
        if let Some(temporary) = prefix.temporary.take() {
            let bytes = read_bounded(&temporary, 1024)?;
            drop(temporary);
            if bytes != expired_bytes {
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
            write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &expired_bytes,
                self.controller,
                1024,
            )?;
            barrier(RestoreExpiryBarrier::AfterTemporarySync)?;
        }
        self.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
        renameat(
            &prefix.root,
            RESTORE_STATE_TEMPORARY,
            &prefix.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(RestoreExpiryBarrier::AfterRename)?;
        prefix.root.sync_all().map_err(|_| ())?;
        let expired_prefix =
            self.open_restored_clean_prefix(RestoreTransition::StoppedToExpired)?;
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
            prefix.root.sync_all().map_err(|_| ())?;
            self.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
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
        if let Some(temporary) = prefix.temporary.take() {
            let bytes = read_bounded(&temporary, 1024)?;
            drop(temporary);
            if bytes != receipts_bytes {
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
            write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &receipts_bytes,
                self.controller,
                1024,
            )?;
            barrier(RestoreReceiptBarrier::AfterTemporarySync)?;
        }
        self.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
        renameat(
            &prefix.root,
            RESTORE_STATE_TEMPORARY,
            &prefix.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(RestoreReceiptBarrier::AfterRename)?;
        prefix.root.sync_all().map_err(|_| ())?;
        let receipts_prefix =
            self.open_restored_clean_prefix(RestoreTransition::ExpiredToReceipts)?;
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
            prefix.root.sync_all().map_err(|_| ())?;
            self.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
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
        if let Some(temporary) = prefix.temporary.take() {
            let bytes = read_bounded(&temporary, 1024)?;
            drop(temporary);
            if bytes != runner_bytes {
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
            write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &runner_bytes,
                self.controller,
                1024,
            )?;
            barrier(RestoreRunnerBarrier::AfterTemporarySync)?;
        }
        self.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
        renameat(
            &prefix.root,
            RESTORE_STATE_TEMPORARY,
            &prefix.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(RestoreRunnerBarrier::AfterRename)?;
        prefix.root.sync_all().map_err(|_| ())?;
        let runner_prefix = self.open_restored_clean_prefix(RestoreTransition::ReceiptsToRunner)?;
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
            prefix.root.sync_all().map_err(|_| ())?;
            self.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
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
        if let Some(temporary) = prefix.temporary.take() {
            let bytes = read_bounded(&temporary, 1024)?;
            drop(temporary);
            if bytes != lease_bytes {
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
            write_restored_file(
                &prefix.root,
                RESTORE_STATE_TEMPORARY,
                &lease_bytes,
                self.controller,
                1024,
            )?;
            barrier(RestoreLeaseBarrier::AfterTemporarySync)?;
        }
        self.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        renameat(
            &prefix.root,
            RESTORE_STATE_TEMPORARY,
            &prefix.root,
            RESTORE_INCOMPLETE,
        )
        .map_err(|_| ())?;
        barrier(RestoreLeaseBarrier::AfterRename)?;
        prefix.root.sync_all().map_err(|_| ())?;
        let lease_prefix = self.open_restored_clean_prefix(RestoreTransition::RunnerToLease)?;
        if lease_prefix.record.step != "lease" || !lease_prefix.current_publication {
            return Err(());
        }
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

fn create_restored_directory(
    parent: &File,
    name: &str,
    controller: BackupIdentity,
) -> Result<File, ()> {
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
    rustix::fs::fchown(
        &directory,
        Some(rustix::process::Uid::from_raw(controller.uid)),
        Some(rustix::process::Gid::from_raw(controller.gid)),
    )
    .map_err(|_| ())?;
    validate_directory(&directory, controller.uid, controller.gid, 0o700)?;
    Ok(directory)
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

fn copy_restored_file(
    source: &File,
    destination: &File,
    name: &str,
    controller: BackupIdentity,
    maximum: u64,
) -> Result<File, ()> {
    let bytes = read_bounded(source, maximum)?;
    write_restored_file(destination, name, &bytes, controller, maximum)
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

fn validate_file(file: &File, identity: BackupIdentity, mode: u32, maximum: u64) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_file()
        && metadata.uid() == identity.uid
        && metadata.gid() == identity.gid
        && metadata.mode() & 0o7777 == mode
        && metadata.nlink() == 1
        && metadata.len() <= maximum
    {
        Ok(())
    } else {
        Err(())
    }
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
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        service_schema,
        state_root::{DeploymentProfile, RoleIdentities, StateInitializer},
        AuthorityConfiguration,
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

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
                assert!(matches!(phase, RestoreStopBarrier::AfterPublication));
                Err(())
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
            .advance_installed_to_stopped_with_barrier(&authority, |_| Err(()))
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
            .advance_stopped_to_expired_with_barrier(&authority, |_| Err(()))
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
            .advance_expired_to_receipts_with_barrier(&authority, |_| Err(()))
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
            .advance_receipts_to_runner_with_barrier(&authority, |_| Err(()))
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
            .advance_runner_to_lease_with_barrier(&authority, |_| Err(()))
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
