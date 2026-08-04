//! Fixed private authority staging for the serialized sandbox.
//!
//! This module is one closed implementation for the approved Slice 4 authority root. It is not a
//! generic secret store, provider interface, or runtime plugin surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use http::Uri;
use rustix::{
    fs::{mkdirat, open, openat, renameat, unlinkat, AtFlags, Mode, OFlags},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const INCOMING_DIRECTORY: &str = "incoming";
const GENERATIONS_DIRECTORY: &str = "generations";
const DISPATCH_DIRECTORY: &str = "dispatch";
const CURRENT_RECORD_NAME: &str = "current";
const CURRENT_RECORD_TEMPORARY_NAME: &str = ".current.tmp";
const MANIFEST_NAME: &str = "manifest.json";
const GENERATION_PREFIX: &str = "generation-";
const GENERATION_TEMPORARY_PREFIX: &str = ".generation-";
const GENERATION_TEMPORARY_SUFFIX: &str = ".tmp";
const CURRENT_RECORD_BYTES_MAX: usize = 1024;
const MANIFEST_BYTES_MAX: usize = 8 * 1024;
const PUBLIC_TRUST_PURPOSE: &str = "kapsel.kap0038.kubernetes-effect-receipt.v2";
const LEASE_PREFIX: &str = "lease-";
const LEASE_TEMPORARY_PREFIX: &str = ".lease-";
const LEASE_TEMPORARY_SUFFIX: &str = ".tmp";
const RUNNER_INPUT_BYTES_MAX: usize = 16 * 1024;
const DISPATCH_ENTRIES_MAX: usize = 64;
const COLLECTION_PREFIX: &str = ".collecting-generation-";

const SOURCE_SPECS: [SourceSpec; 13] = [
    SourceSpec::new("authorization-signing-seed", 32),
    SourceSpec::new("authorization-signing-key-id", 128),
    SourceSpec::new("receipt-signing-seed", 32),
    SourceSpec::new("receipt-signing-key-id", 128),
    SourceSpec::new("tombstone-digest-key", 32),
    SourceSpec::new("runner-kubernetes-api-server", 512),
    SourceSpec::new("runner-kubernetes-ca.pem", 16 * 1024),
    SourceSpec::new("runner-kubernetes-token", 4 * 1024),
    SourceSpec::new("cleanup-kubernetes-api-server", 512),
    SourceSpec::new("cleanup-kubernetes-ca.pem", 16 * 1024),
    SourceSpec::new("cleanup-kubernetes-token", 4 * 1024),
    SourceSpec::new("handoff-endpoint", 64),
    SourceSpec::new("public-receipt-trust.json", 1024),
];

#[derive(Clone, Copy)]
struct SourceSpec {
    name: &'static str,
    maximum: usize,
}

impl SourceSpec {
    const fn new(name: &'static str, maximum: usize) -> Self {
        Self { name, maximum }
    }
}

/// Non-secret identity of one complete fixed authority generation.
#[derive(Clone, Eq, PartialEq)]
pub struct GenerationIdentity {
    pub(crate) generation: u64,
    pub(crate) manifest_digest: String,
}

impl GenerationIdentity {
    /// Constructs one validated, non-secret authority-generation identity.
    ///
    /// # Errors
    ///
    /// Returns [`FixedStagingError::Boundary`] unless the generation is positive and the digest is
    /// exactly 64 lowercase hexadecimal characters.
    #[cfg(test)]
    pub(crate) fn new(
        generation: u64,
        manifest_digest: impl Into<String>,
    ) -> Result<Self, FixedStagingError> {
        let manifest_digest = manifest_digest.into();
        if generation == 0 || !is_lower_hex(&manifest_digest) || manifest_digest.len() != 64 {
            return Err(FixedStagingError::Boundary);
        }
        Ok(Self {
            generation,
            manifest_digest,
        })
    }

    /// Returns the positive monotonic authority generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the SHA-256 digest of the canonical private manifest.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
}

impl fmt::Debug for GenerationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationIdentity")
            .field("generation", &self.generation)
            .field("manifest_digest", &self.manifest_digest)
            .finish()
    }
}

pub(crate) struct FixedStagingInstaller {
    authority: AuthorityRoot,
}

pub(crate) struct FixedStagingReader {
    authority: AuthorityRoot,
}

/// One atomically published, already-opened runner input directory.
pub(crate) struct PublishedRunnerInputs {
    directory: fs::File,
}

impl PublishedRunnerInputs {
    pub(crate) fn directory(&self) -> &fs::File {
        &self.directory
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> Result<Self, FixedStagingError> {
        let directory = fs::File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| FixedStagingError::Boundary)?,
        );
        validate_metadata(
            &directory
                .metadata()
                .map_err(|_| FixedStagingError::Boundary)?,
            true,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            0o700,
        )?;
        Ok(Self { directory })
    }
}

struct AuthorityRoot {
    root_path: PathBuf,
    root: fs::File,
    root_device: u64,
    root_inode: u64,
    controller_uid: u32,
    controller_gid: u32,
    staging_uid: u32,
    staging_gid: u32,
}

struct OpenedManifest {
    directory: fs::File,
    manifest: ManifestV1,
}

/// Bounded failure vocabulary for fixed authority staging and identity validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedStagingError {
    /// Required staged authority is not currently available.
    Unavailable,
    /// A fixed filesystem, identity, schema, or digest boundary was invalid.
    Boundary,
    /// The bounded retained-generation ceiling prevents another rotation.
    RotationCeiling,
}

impl fmt::Display for FixedStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "fixed staging is unavailable",
            Self::Boundary => "fixed staging boundary is invalid",
            Self::RotationCeiling => "fixed staging rotation ceiling is full",
        })
    }
}

impl std::error::Error for FixedStagingError {}

#[derive(Clone)]
struct SourceFile {
    bytes: Vec<u8>,
    digest: String,
}

struct CandidateData {
    source_files: Vec<SourceFile>,
}

pub(crate) struct AuthorizationMaterial {
    pub(crate) signing_seed: [u8; 32],
    pub(crate) signing_key_id: String,
}

pub(crate) struct ReceiptMaterial {
    pub(crate) signing_seed: [u8; 32],
    pub(crate) signing_key_id: String,
}

pub(crate) struct TombstoneMaterial {
    pub(crate) digest_key: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct TombstoneKeyEntry {
    pub(crate) identity: GenerationIdentity,
    pub(crate) digest_key: [u8; 32],
}

pub(crate) struct TombstoneKeyring {
    pub(crate) current: GenerationIdentity,
    pub(crate) entries: Vec<TombstoneKeyEntry>,
}

impl TombstoneKeyring {
    pub(crate) fn key_for(&self, identity: &GenerationIdentity) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|entry| &entry.identity == identity)
            .map(|entry| entry.digest_key)
    }
}

pub(crate) struct RunnerKubernetesMaterial {
    pub(crate) api_server: String,
    pub(crate) ca_bytes: Vec<u8>,
    pub(crate) token: String,
}

pub(crate) struct CleanupKubernetesMaterial {
    pub(crate) api_server: String,
    pub(crate) ca_bytes: Vec<u8>,
    pub(crate) token: String,
}

pub(crate) struct HandoffMaterial {
    pub(crate) endpoint: SocketAddr,
}

pub(crate) struct PublicTrustMaterial {
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestV1 {
    version: u8,
    generation: u64,
    previous_generation: Option<u64>,
    files: Vec<ManifestFileV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFileV1 {
    name: String,
    length: u64,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CurrentRecordV1 {
    version: u8,
    generation: u64,
    manifest_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicReceiptTrustDocument {
    pub(crate) version: u8,
    pub(crate) key_id: String,
    pub(crate) public_key_hex: String,
    pub(crate) accepted_purpose: String,
    pub(crate) not_before_unix_s: i64,
    pub(crate) not_after_unix_s: i64,
}

impl FixedStagingInstaller {
    #[allow(
        clippy::similar_names,
        reason = "the fixed controller and staging UID/GID pairs are deliberately explicit"
    )]
    pub(crate) fn open(
        root_path: impl AsRef<Path>,
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
    ) -> Result<Self, FixedStagingError> {
        if controller_uid == staging_uid || controller_gid == staging_gid {
            return Err(FixedStagingError::Boundary);
        }
        let authority = AuthorityRoot::open_for_process(
            root_path,
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
            staging_uid,
            staging_gid,
        )?;
        authority.validate_installer_directories()?;
        Ok(Self { authority })
    }

    #[cfg(test)]
    fn open_same_identity_for_test(
        root_path: impl AsRef<Path>,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FixedStagingError> {
        let authority = AuthorityRoot::open_for_process(root_path, uid, gid, uid, gid, uid, gid)?;
        authority.validate_installer_directories()?;
        Ok(Self { authority })
    }

    pub(crate) fn activate_incoming(&self) -> Result<GenerationIdentity, FixedStagingError> {
        self.authority.activate_incoming()
    }
}

impl FixedStagingReader {
    #[allow(
        clippy::similar_names,
        reason = "the fixed controller and staging UID/GID pairs are deliberately explicit"
    )]
    pub(crate) fn open(
        root_path: impl AsRef<Path>,
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
    ) -> Result<Self, FixedStagingError> {
        if controller_uid == staging_uid || controller_gid == staging_gid {
            return Err(FixedStagingError::Boundary);
        }
        let authority = AuthorityRoot::open_for_process(
            root_path,
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
            controller_uid,
            controller_gid,
        )?;
        authority.validate_controller_directories()?;
        Ok(Self { authority })
    }

    #[cfg(test)]
    fn open_same_identity_for_test(
        root_path: impl AsRef<Path>,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FixedStagingError> {
        let authority = AuthorityRoot::open_for_process(root_path, uid, gid, uid, gid, uid, gid)?;
        authority.validate_controller_directories()?;
        Ok(Self { authority })
    }

    pub(crate) fn publish_runner_inputs(
        &self,
        run_id: &str,
        lease_epoch: i64,
        inputs: &[(&'static str, Vec<u8>)],
    ) -> Result<PublishedRunnerInputs, FixedStagingError> {
        if !is_run_id(run_id)
            || lease_epoch <= 0
            || inputs.len() != crate::runner_process::INPUT_NAMES.len()
            || inputs
                .iter()
                .map(|(name, _)| *name)
                .ne(crate::runner_process::INPUT_NAMES)
            || inputs
                .iter()
                .any(|(_, bytes)| bytes.is_empty() || bytes.len() > RUNNER_INPUT_BYTES_MAX)
        {
            return Err(FixedStagingError::Boundary);
        }
        self.authority
            .publish_runner_inputs(run_id, lease_epoch, inputs)
    }

    pub(crate) fn remove_retired_dispatch(&self, run_id: &str) -> Result<(), FixedStagingError> {
        if !is_run_id(run_id) {
            return Err(FixedStagingError::Boundary);
        }
        self.authority.remove_dispatch_run(run_id)
    }

    pub(crate) fn dispatch_references(&self) -> Result<BTreeMap<String, i64>, FixedStagingError> {
        self.authority.dispatch_references()
    }

    pub(crate) fn dispatch_run_ids(&self) -> Result<BTreeSet<String>, FixedStagingError> {
        self.dispatch_references()
            .map(|runs| runs.into_keys().collect())
    }

    pub(crate) fn noncurrent_identity(
        &self,
    ) -> Result<Option<GenerationIdentity>, FixedStagingError> {
        let current = self.current_identity()?;
        let generations = self.authority.list_generation_numbers()?;
        let Some(generation) = generations
            .into_iter()
            .find(|generation| *generation != current.generation)
        else {
            return Ok(None);
        };
        self.authority
            .identity_from_generation(generation)
            .map(|(identity, _)| Some(identity))
    }

    pub(crate) fn collect_noncurrent(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        self.authority.collect_noncurrent(identity)
    }

    pub(crate) fn validate_collection_recovery(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        self.authority.validate_collection_recovery(identity)
    }

    pub(crate) fn recover_collection(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        self.authority.validate_collection_recovery(identity)?;
        self.authority.recover_collection(identity)
    }

    pub(crate) fn current_identity(&self) -> Result<GenerationIdentity, FixedStagingError> {
        self.authority.revalidate_root()?;
        self.authority.validate_root_inventory()?;
        self.authority.validate_controller_directories()?;
        let identity = self
            .authority
            .read_current_identity_if_present()?
            .ok_or(FixedStagingError::Unavailable)?;
        self.validate_generation_inventory(&identity)?;
        self.open_pinned_manifest(&identity)?;
        Ok(identity)
    }

    pub(crate) fn validate_identity(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        let current = self
            .authority
            .read_current_identity_if_present()?
            .ok_or(FixedStagingError::Unavailable)?;
        self.validate_generation_inventory(&current)?;
        self.open_pinned_manifest(identity).map(|_| ())
    }

    fn validate_generation_inventory(
        &self,
        current: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        let generations = self.authority.list_generation_numbers()?;
        if generations.is_empty()
            || !generations.contains(&current.generation)
            || generations
                .iter()
                .any(|generation| *generation > current.generation)
        {
            return Err(FixedStagingError::Boundary);
        }
        Ok(())
    }

    pub(crate) fn authorization(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<AuthorizationMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        Ok(AuthorizationMaterial {
            signing_seed: validate_secret_32(
                &self
                    .authority
                    .read_manifest_source(&opened, "authorization-signing-seed")?,
            )?,
            signing_key_id: validate_key_id(
                &self
                    .authority
                    .read_manifest_source(&opened, "authorization-signing-key-id")?,
            )?,
        })
    }

    pub(crate) fn receipt(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<ReceiptMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        let signing_seed = validate_secret_32(
            &self
                .authority
                .read_manifest_source(&opened, "receipt-signing-seed")?,
        )?;
        let signing_key_id = validate_key_id(
            &self
                .authority
                .read_manifest_source(&opened, "receipt-signing-key-id")?,
        )?;
        validate_public_receipt_trust(
            &self
                .authority
                .read_manifest_source(&opened, "public-receipt-trust.json")?,
            &signing_seed,
            &signing_key_id,
        )?;
        Ok(ReceiptMaterial {
            signing_seed,
            signing_key_id,
        })
    }

    pub(crate) fn tombstone(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<TombstoneMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        Ok(TombstoneMaterial {
            digest_key: validate_secret_32(
                &self
                    .authority
                    .read_manifest_source(&opened, "tombstone-digest-key")?,
            )?,
        })
    }

    pub(crate) fn tombstone_keyring(&self) -> Result<TombstoneKeyring, FixedStagingError> {
        let current = self.current_identity()?;
        let mut entries = Vec::new();
        for generation in self.authority.list_generation_numbers()? {
            let (identity, _) = self.authority.identity_from_generation(generation)?;
            let material = self.tombstone(&identity)?;
            entries.push(TombstoneKeyEntry {
                identity,
                digest_key: material.digest_key,
            });
        }
        if entries.is_empty() || entries.len() > 2 {
            return Err(FixedStagingError::Boundary);
        }
        Ok(TombstoneKeyring { current, entries })
    }

    pub(crate) fn runner_kubernetes(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<RunnerKubernetesMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        Ok(RunnerKubernetesMaterial {
            api_server: validate_absolute_uri(
                &self
                    .authority
                    .read_manifest_source(&opened, "runner-kubernetes-api-server")?,
                512,
            )?,
            ca_bytes: validate_bounded_binary(
                &self
                    .authority
                    .read_manifest_source(&opened, "runner-kubernetes-ca.pem")?,
                16 * 1024,
            )?,
            token: validate_ascii_token(
                &self
                    .authority
                    .read_manifest_source(&opened, "runner-kubernetes-token")?,
                4 * 1024,
            )?,
        })
    }

    pub(crate) fn cleanup_kubernetes(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<CleanupKubernetesMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        Ok(CleanupKubernetesMaterial {
            api_server: validate_absolute_uri(
                &self
                    .authority
                    .read_manifest_source(&opened, "cleanup-kubernetes-api-server")?,
                512,
            )?,
            ca_bytes: validate_bounded_binary(
                &self
                    .authority
                    .read_manifest_source(&opened, "cleanup-kubernetes-ca.pem")?,
                16 * 1024,
            )?,
            token: validate_ascii_token(
                &self
                    .authority
                    .read_manifest_source(&opened, "cleanup-kubernetes-token")?,
                4 * 1024,
            )?,
        })
    }

    pub(crate) fn handoff(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<HandoffMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        Ok(HandoffMaterial {
            endpoint: validate_handoff_endpoint(
                &self
                    .authority
                    .read_manifest_source(&opened, "handoff-endpoint")?,
            )?,
        })
    }

    pub(crate) fn public_trust(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<PublicTrustMaterial, FixedStagingError> {
        let opened = self.open_pinned_manifest(identity)?;
        let receipt_seed = validate_secret_32(
            &self
                .authority
                .read_manifest_source(&opened, "receipt-signing-seed")?,
        )?;
        let receipt_key_id = validate_key_id(
            &self
                .authority
                .read_manifest_source(&opened, "receipt-signing-key-id")?,
        )?;
        let bytes = self
            .authority
            .read_manifest_source(&opened, "public-receipt-trust.json")?;
        validate_public_receipt_trust(&bytes, &receipt_seed, &receipt_key_id)?;
        Ok(PublicTrustMaterial { bytes })
    }

    fn open_pinned_manifest(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<OpenedManifest, FixedStagingError> {
        self.authority.revalidate_root()?;
        self.authority.validate_root_inventory()?;
        self.authority.validate_controller_directories()?;
        self.authority.open_generation_manifest(identity)
    }
}

impl AuthorityRoot {
    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        reason = "one private constructor binds both fixed ownership pairs and the selected role"
    )]
    fn open_for_process(
        root_path: impl AsRef<Path>,
        controller_uid: u32,
        controller_gid: u32,
        staging_uid: u32,
        staging_gid: u32,
        process_uid: u32,
        process_gid: u32,
    ) -> Result<Self, FixedStagingError> {
        let root_path = root_path.as_ref();
        if !root_path.is_absolute()
            || rustix::process::getuid().as_raw() != process_uid
            || rustix::process::getgid().as_raw() != process_gid
            || controller_uid == u32::MAX
            || controller_gid == u32::MAX
        {
            return Err(FixedStagingError::Boundary);
        }
        let root = fs::File::from(
            open(
                root_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| FixedStagingError::Unavailable)?,
        );
        let metadata = root
            .metadata()
            .map_err(|_| FixedStagingError::Unavailable)?;
        validate_metadata(&metadata, true, controller_uid, controller_gid, 0o700)?;
        let authority = Self {
            root_path: root_path.to_owned(),
            root,
            root_device: metadata.dev(),
            root_inode: metadata.ino(),
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
        };
        authority.validate_root_inventory()?;
        Ok(authority)
    }

    fn validate_installer_directories(&self) -> Result<(), FixedStagingError> {
        self.open_directory(
            INCOMING_DIRECTORY,
            self.staging_uid,
            self.staging_gid,
            0o700,
        )?;
        self.validate_controller_directories()
    }

    fn validate_controller_directories(&self) -> Result<(), FixedStagingError> {
        self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        self.open_directory(
            DISPATCH_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        Ok(())
    }

    fn activate_incoming(&self) -> Result<GenerationIdentity, FixedStagingError> {
        if let Some(recovered) = self.prepare_for_use()? {
            return Ok(recovered);
        }
        let incoming = self.open_directory(
            INCOMING_DIRECTORY,
            self.staging_uid,
            self.staging_gid,
            0o700,
        )?;
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let _dispatch = self.open_directory(
            DISPATCH_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let current = self.read_current_identity_if_present()?;
        let generation_numbers = self.list_generation_numbers()?;
        if current.is_none() && !generation_numbers.is_empty() {
            return Err(FixedStagingError::Boundary);
        }
        if generation_numbers.len() > 2 {
            return Err(FixedStagingError::Boundary);
        }
        if generation_numbers.len() == 2 {
            return Err(FixedStagingError::RotationCeiling);
        }
        if let Some(identity) = &current {
            if generation_numbers.last().copied() != Some(identity.generation) {
                return Err(FixedStagingError::Boundary);
            }
        }
        let candidate = self.read_candidate(&incoming)?;
        let next_generation = current
            .as_ref()
            .map_or(1, |identity| identity.generation.saturating_add(1));
        if next_generation == 0 {
            return Err(FixedStagingError::Boundary);
        }
        let previous_generation = current.as_ref().map(|identity| identity.generation);
        let identity = self.install_generation(
            &generations,
            next_generation,
            previous_generation,
            &candidate,
        )?;
        self.write_current_record(&identity)?;
        Ok(identity)
    }

    fn prepare_for_use(&self) -> Result<Option<GenerationIdentity>, FixedStagingError> {
        self.revalidate_root()?;
        self.validate_root_inventory()?;
        self.validate_installer_directories()?;
        let recovered_current = self.recover_current_record()?;
        self.recover_temporary_generations()?;
        let recovered_generation = self.recover_renamed_generation()?;
        let recovered = recovered_current.or(recovered_generation);
        self.validate_root_inventory()?;
        Ok(recovered)
    }

    fn install_generation(
        &self,
        generations: &fs::File,
        generation: u64,
        previous_generation: Option<u64>,
        candidate: &CandidateData,
    ) -> Result<GenerationIdentity, FixedStagingError> {
        let temporary_name = temporary_generation_name(generation);
        let final_name = generation_name(generation);
        mkdirat(generations, &temporary_name, Mode::from_raw_mode(0o700))
            .map_err(|_| FixedStagingError::Boundary)?;
        let temporary_directory = fs::File::from(
            openat(
                generations,
                &temporary_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| FixedStagingError::Boundary)?,
        );
        set_descriptor_identity(
            &temporary_directory,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        for (spec, source_file) in SOURCE_SPECS.iter().zip(&candidate.source_files) {
            self.write_private_file(&temporary_directory, spec.name, &source_file.bytes)?;
        }
        let manifest = ManifestV1 {
            version: 1,
            generation,
            previous_generation,
            files: SOURCE_SPECS
                .iter()
                .zip(&candidate.source_files)
                .map(|(spec, source_file)| {
                    Ok(ManifestFileV1 {
                        name: spec.name.to_owned(),
                        length: u64::try_from(source_file.bytes.len())
                            .map_err(|_| FixedStagingError::Boundary)?,
                        sha256: source_file.digest.clone(),
                    })
                })
                .collect::<Result<Vec<_>, FixedStagingError>>()?,
        };
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|_| FixedStagingError::Boundary)?;
        let manifest_digest = lowercase_hex(&Sha256::digest(&manifest_bytes));
        self.write_private_file(&temporary_directory, MANIFEST_NAME, &manifest_bytes)?;
        temporary_directory
            .set_permissions(fs::Permissions::from_mode(0o500))
            .map_err(|_| FixedStagingError::Boundary)?;
        temporary_directory
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        renameat(generations, &temporary_name, generations, &final_name)
            .map_err(|_| FixedStagingError::Boundary)?;
        generations
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        Ok(GenerationIdentity {
            generation,
            manifest_digest,
        })
    }

    fn write_current_record(&self, identity: &GenerationIdentity) -> Result<(), FixedStagingError> {
        let current = CurrentRecordV1 {
            version: 1,
            generation: identity.generation,
            manifest_digest: identity.manifest_digest.clone(),
        };
        let current_bytes =
            serde_json::to_vec(&current).map_err(|_| FixedStagingError::Boundary)?;
        self.write_private_file(&self.root, CURRENT_RECORD_TEMPORARY_NAME, &current_bytes)?;
        renameat(
            &self.root,
            CURRENT_RECORD_TEMPORARY_NAME,
            &self.root,
            CURRENT_RECORD_NAME,
        )
        .map_err(|_| FixedStagingError::Boundary)?;
        self.root
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)
    }

    fn read_candidate(&self, incoming: &fs::File) -> Result<CandidateData, FixedStagingError> {
        validate_directory_inventory(incoming, false)?;
        let files = SOURCE_SPECS
            .iter()
            .map(|spec| {
                read_validated_file(
                    incoming,
                    spec.name,
                    self.staging_uid,
                    self.staging_gid,
                    0o400,
                    spec.maximum,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authorization_signing_seed = validate_secret_32(&files[0])?;
        validate_key_id(&files[1])?;
        let receipt_signing_seed = validate_secret_32(&files[2])?;
        let receipt_signing_key_id = validate_key_id(&files[3])?;
        let tombstone_digest_key = validate_secret_32(&files[4])?;
        validate_absolute_uri(&files[5], 512)?;
        validate_bounded_binary(&files[6], 16 * 1024)?;
        let runner_kubernetes_token = validate_ascii_token(&files[7], 4 * 1024)?;
        validate_absolute_uri(&files[8], 512)?;
        validate_bounded_binary(&files[9], 16 * 1024)?;
        let cleanup_kubernetes_token = validate_ascii_token(&files[10], 4 * 1024)?;
        validate_handoff_endpoint(&files[11])?;
        validate_public_receipt_trust(&files[12], &receipt_signing_seed, &receipt_signing_key_id)?;
        if authorization_signing_seed == receipt_signing_seed
            || authorization_signing_seed == tombstone_digest_key
            || receipt_signing_seed == tombstone_digest_key
            || runner_kubernetes_token == cleanup_kubernetes_token
        {
            return Err(FixedStagingError::Boundary);
        }
        let source_files = files
            .into_iter()
            .map(|bytes| SourceFile {
                digest: lowercase_hex(&Sha256::digest(&bytes)),
                bytes,
            })
            .collect();
        Ok(CandidateData { source_files })
    }

    fn open_generation_manifest(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<OpenedManifest, FixedStagingError> {
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let directory = open_directory_at(
            &generations,
            &generation_name(identity.generation),
            self.controller_uid,
            self.controller_gid,
            0o500,
        )?;
        validate_directory_inventory(&directory, true)?;
        let manifest_bytes = read_validated_file(
            &directory,
            MANIFEST_NAME,
            self.controller_uid,
            self.controller_gid,
            0o400,
            MANIFEST_BYTES_MAX,
        )?;
        let manifest: ManifestV1 =
            serde_json::from_slice(&manifest_bytes).map_err(|_| FixedStagingError::Boundary)?;
        if manifest.version != 1
            || manifest.generation != identity.generation
            || manifest.files.len() != SOURCE_SPECS.len()
            || manifest
                .previous_generation
                .is_some_and(|value| value >= manifest.generation)
            || serde_json::to_vec(&manifest).map_err(|_| FixedStagingError::Boundary)?
                != manifest_bytes
            || lowercase_hex(&Sha256::digest(&manifest_bytes)) != identity.manifest_digest
        {
            return Err(FixedStagingError::Boundary);
        }
        for (spec, manifest_file) in SOURCE_SPECS.iter().zip(&manifest.files) {
            if manifest_file.name != spec.name
                || manifest_file.length == 0
                || manifest_file.length
                    > u64::try_from(spec.maximum).map_err(|_| FixedStagingError::Boundary)?
                || !is_lower_hex(&manifest_file.sha256)
            {
                return Err(FixedStagingError::Boundary);
            }
        }
        Ok(OpenedManifest {
            directory,
            manifest,
        })
    }

    fn read_manifest_source(
        &self,
        opened: &OpenedManifest,
        name: &str,
    ) -> Result<Vec<u8>, FixedStagingError> {
        let index = SOURCE_SPECS
            .iter()
            .position(|spec| spec.name == name)
            .ok_or(FixedStagingError::Boundary)?;
        let spec = SOURCE_SPECS[index];
        let expected = &opened.manifest.files[index];
        let bytes = read_validated_file(
            &opened.directory,
            spec.name,
            self.controller_uid,
            self.controller_gid,
            0o400,
            spec.maximum,
        )?;
        if expected.length != u64::try_from(bytes.len()).map_err(|_| FixedStagingError::Boundary)?
            || expected.sha256 != lowercase_hex(&Sha256::digest(&bytes))
        {
            return Err(FixedStagingError::Boundary);
        }
        Ok(bytes)
    }

    fn read_current_identity_if_present(
        &self,
    ) -> Result<Option<GenerationIdentity>, FixedStagingError> {
        match read_validated_file(
            &self.root,
            CURRENT_RECORD_NAME,
            self.controller_uid,
            self.controller_gid,
            0o400,
            CURRENT_RECORD_BYTES_MAX,
        ) {
            Ok(bytes) => {
                let record: CurrentRecordV1 =
                    serde_json::from_slice(&bytes).map_err(|_| FixedStagingError::Boundary)?;
                if record.version != 1
                    || record.generation == 0
                    || !is_lower_hex(&record.manifest_digest)
                {
                    return Err(FixedStagingError::Boundary);
                }
                let identity = GenerationIdentity {
                    generation: record.generation,
                    manifest_digest: record.manifest_digest,
                };
                self.open_generation_manifest(&identity)?;
                Ok(Some(identity))
            },
            Err(FixedStagingError::Unavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn revalidate_root(&self) -> Result<(), FixedStagingError> {
        let reopened = fs::File::from(
            open(
                &self.root_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| FixedStagingError::Unavailable)?,
        );
        let metadata = reopened
            .metadata()
            .map_err(|_| FixedStagingError::Unavailable)?;
        validate_metadata(
            &metadata,
            true,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        if metadata.dev() != self.root_device || metadata.ino() != self.root_inode {
            return Err(FixedStagingError::Boundary);
        }
        Ok(())
    }

    fn open_directory(
        &self,
        name: &str,
        expected_user: u32,
        expected_group: u32,
        mode: u32,
    ) -> Result<fs::File, FixedStagingError> {
        open_directory_at(&self.root, name, expected_user, expected_group, mode)
    }

    fn write_private_file(
        &self,
        directory: &fs::File,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), FixedStagingError> {
        let descriptor = openat(
            directory,
            name,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o400),
        )
        .map_err(|_| FixedStagingError::Boundary)?;
        let mut file = fs::File::from(descriptor);
        set_descriptor_identity(&file, self.controller_uid, self.controller_gid, 0o400)?;
        file.write_all(bytes)
            .map_err(|_| FixedStagingError::Boundary)?;
        file.sync_all().map_err(|_| FixedStagingError::Boundary)
    }

    fn publish_runner_inputs(
        &self,
        run_id: &str,
        lease_epoch: i64,
        inputs: &[(&'static str, Vec<u8>)],
    ) -> Result<PublishedRunnerInputs, FixedStagingError> {
        self.revalidate_root()?;
        self.validate_root_inventory()?;
        let dispatch = self.open_directory(
            DISPATCH_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        match mkdirat(&dispatch, run_id, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {},
            Err(_) => return Err(FixedStagingError::Boundary),
        }
        let run = open_directory_at(
            &dispatch,
            run_id,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        self.validate_dispatch_run(&run, lease_epoch)?;
        let final_name = lease_name(lease_epoch);
        if directory_names(&run, DISPATCH_ENTRIES_MAX)?
            .iter()
            .any(|name| name == &final_name)
        {
            let directory = open_directory_at(
                &run,
                &final_name,
                self.controller_uid,
                self.controller_gid,
                0o700,
            )?;
            self.validate_published_inputs(&directory, inputs)?;
            return Ok(PublishedRunnerInputs { directory });
        }
        let temporary_name = temporary_lease_name(lease_epoch);
        match mkdirat(&run, &temporary_name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {},
            Err(Errno::EXIST) => {
                self.remove_partial_lease(&run, &temporary_name)?;
                mkdirat(&run, &temporary_name, Mode::from_raw_mode(0o700))
                    .map_err(|_| FixedStagingError::Boundary)?;
            },
            Err(_) => return Err(FixedStagingError::Boundary),
        }
        let temporary = open_directory_at(
            &run,
            &temporary_name,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        for (name, bytes) in inputs {
            self.write_private_file(&temporary, name, bytes)?;
        }
        temporary
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        self.revalidate_root()?;
        require_same_directory_at(&dispatch, run_id, &run)?;
        require_same_directory_at(&run, &temporary_name, &temporary)?;
        renameat(&run, &temporary_name, &run, &final_name)
            .map_err(|_| FixedStagingError::Boundary)?;
        run.sync_all().map_err(|_| FixedStagingError::Boundary)?;
        dispatch
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        let directory = open_directory_at(
            &run,
            &final_name,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        if !same_file(&temporary, &directory)? {
            return Err(FixedStagingError::Boundary);
        }
        self.validate_published_inputs(&directory, inputs)?;
        Ok(PublishedRunnerInputs { directory })
    }

    fn validate_dispatch_run(
        &self,
        run: &fs::File,
        lease_epoch: i64,
    ) -> Result<(), FixedStagingError> {
        let names = directory_names(run, DISPATCH_ENTRIES_MAX)?;
        let mut temporary = None;
        for name in names {
            if let Some(epoch) = parse_lease_name(&name) {
                if epoch > lease_epoch {
                    return Err(FixedStagingError::Boundary);
                }
                self.open_complete_lease(run, &name)?;
                continue;
            }
            let epoch = parse_temporary_lease_name(&name).ok_or(FixedStagingError::Boundary)?;
            if epoch > lease_epoch || temporary.replace(name).is_some() {
                return Err(FixedStagingError::Boundary);
            }
        }
        if let Some(name) = temporary {
            self.remove_partial_lease(run, &name)?;
            run.sync_all().map_err(|_| FixedStagingError::Boundary)?;
        }
        Ok(())
    }

    fn validate_published_inputs(
        &self,
        directory: &fs::File,
        inputs: &[(&'static str, Vec<u8>)],
    ) -> Result<(), FixedStagingError> {
        let names = directory_names(directory, crate::runner_process::INPUT_NAMES.len())?;
        if names.into_iter().collect::<BTreeSet<_>>()
            != crate::runner_process::INPUT_NAMES
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        {
            return Err(FixedStagingError::Boundary);
        }
        for (name, expected) in inputs {
            let actual = read_validated_file(
                directory,
                name,
                self.controller_uid,
                self.controller_gid,
                0o400,
                RUNNER_INPUT_BYTES_MAX,
            )?;
            if actual != *expected {
                return Err(FixedStagingError::Boundary);
            }
        }
        Ok(())
    }

    fn remove_partial_lease(&self, run: &fs::File, name: &str) -> Result<(), FixedStagingError> {
        let directory =
            open_directory_at(run, name, self.controller_uid, self.controller_gid, 0o700)?;
        let names = directory_names(&directory, crate::runner_process::INPUT_NAMES.len())?;
        let allowed = crate::runner_process::INPUT_NAMES
            .into_iter()
            .collect::<BTreeSet<_>>();
        if names.iter().any(|entry| !allowed.contains(entry.as_str())) {
            return Err(FixedStagingError::Boundary);
        }
        for entry in names {
            validate_removable_partial_file(
                &directory,
                &entry,
                self.controller_uid,
                self.controller_gid,
            )?;
            unlinkat(&directory, &entry, AtFlags::empty())
                .map_err(|_| FixedStagingError::Boundary)?;
        }
        directory
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        require_same_directory_at(run, name, &directory)?;
        drop(directory);
        unlinkat(run, name, AtFlags::REMOVEDIR).map_err(|_| FixedStagingError::Boundary)
    }

    fn remove_dispatch_run(&self, run_id: &str) -> Result<(), FixedStagingError> {
        self.revalidate_root()?;
        let dispatch = self.open_directory(
            DISPATCH_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let dispatch_names = directory_names(&dispatch, DISPATCH_ENTRIES_MAX)?;
        if dispatch_names.iter().any(|name| !is_run_id(name)) {
            return Err(FixedStagingError::Boundary);
        }
        if !dispatch_names.iter().any(|name| name == run_id) {
            return Ok(());
        }
        let run = open_directory_at(
            &dispatch,
            run_id,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        for name in directory_names(&run, DISPATCH_ENTRIES_MAX)? {
            if parse_temporary_lease_name(&name).is_some() {
                self.remove_partial_lease(&run, &name)?;
            } else if parse_lease_name(&name).is_some() {
                self.remove_complete_lease(&run, &name)?;
            } else {
                return Err(FixedStagingError::Boundary);
            }
        }
        run.sync_all().map_err(|_| FixedStagingError::Boundary)?;
        require_same_directory_at(&dispatch, run_id, &run)?;
        drop(run);
        unlinkat(&dispatch, run_id, AtFlags::REMOVEDIR).map_err(|_| FixedStagingError::Boundary)?;
        dispatch.sync_all().map_err(|_| FixedStagingError::Boundary)
    }

    fn dispatch_references(&self) -> Result<BTreeMap<String, i64>, FixedStagingError> {
        self.revalidate_root()?;
        let dispatch = self.open_directory(
            DISPATCH_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let mut references = BTreeMap::new();
        for run_id in directory_names(&dispatch, DISPATCH_ENTRIES_MAX)? {
            if !is_run_id(&run_id) {
                return Err(FixedStagingError::Boundary);
            }
            let run = open_directory_at(
                &dispatch,
                &run_id,
                self.controller_uid,
                self.controller_gid,
                0o700,
            )?;
            let mut latest = None;
            for name in directory_names(&run, DISPATCH_ENTRIES_MAX)? {
                let epoch = parse_lease_name(&name).ok_or(FixedStagingError::Boundary)?;
                self.open_complete_lease(&run, &name)?;
                latest = Some(latest.map_or(epoch, |current: i64| current.max(epoch)));
            }
            references.insert(run_id, latest.ok_or(FixedStagingError::Boundary)?);
        }
        Ok(references)
    }

    fn open_complete_lease(
        &self,
        run: &fs::File,
        name: &str,
    ) -> Result<(fs::File, Vec<String>), FixedStagingError> {
        let directory =
            open_directory_at(run, name, self.controller_uid, self.controller_gid, 0o700)?;
        let names = directory_names(&directory, crate::runner_process::INPUT_NAMES.len())?;
        let expected = crate::runner_process::INPUT_NAMES
            .into_iter()
            .collect::<BTreeSet<_>>();
        if names.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
            return Err(FixedStagingError::Boundary);
        }
        for entry in &names {
            validate_removable_runner_input(
                &directory,
                entry,
                self.controller_uid,
                self.controller_gid,
            )?;
        }
        Ok((directory, names))
    }

    fn remove_complete_lease(&self, run: &fs::File, name: &str) -> Result<(), FixedStagingError> {
        let (directory, names) = self.open_complete_lease(run, name)?;
        for entry in names {
            unlinkat(&directory, &entry, AtFlags::empty())
                .map_err(|_| FixedStagingError::Boundary)?;
        }
        directory
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        require_same_directory_at(run, name, &directory)?;
        drop(directory);
        unlinkat(run, name, AtFlags::REMOVEDIR).map_err(|_| FixedStagingError::Boundary)
    }

    fn collect_noncurrent(&self, identity: &GenerationIdentity) -> Result<(), FixedStagingError> {
        self.revalidate_root()?;
        let current = self
            .read_current_identity_if_present()?
            .ok_or(FixedStagingError::Unavailable)?;
        if &current == identity || identity.generation >= current.generation {
            return Err(FixedStagingError::Boundary);
        }
        self.open_generation_manifest(identity)?;
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let name = generation_name(identity.generation);
        let collecting = collection_name(identity.generation);
        if directory_names(&generations, 2)?
            .iter()
            .any(|entry| entry == &collecting)
        {
            return Err(FixedStagingError::Boundary);
        }
        let directory = open_directory_at(
            &generations,
            &name,
            self.controller_uid,
            self.controller_gid,
            0o500,
        )?;
        validate_directory_inventory(&directory, true)?;
        set_descriptor_identity(&directory, self.controller_uid, self.controller_gid, 0o700)?;
        renameat(&generations, &name, &generations, &collecting)
            .map_err(|_| FixedStagingError::Boundary)?;
        generations
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        self.remove_collecting_generation(&generations, &collecting, &directory)
    }

    fn validate_collection_recovery(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<(), FixedStagingError> {
        self.revalidate_root()?;
        let current = self
            .read_current_identity_if_present()?
            .ok_or(FixedStagingError::Unavailable)?;
        if identity.generation.checked_add(1) != Some(current.generation) {
            return Err(FixedStagingError::Boundary);
        }
        self.open_generation_manifest(&current)?;
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let current_name = generation_name(current.generation);
        let name = generation_name(identity.generation);
        let collecting = collection_name(identity.generation);
        let names = directory_names(&generations, 3)?;
        if names
            .iter()
            .any(|entry| entry != &current_name && entry != &name && entry != &collecting)
        {
            return Err(FixedStagingError::Boundary);
        }
        let has_final = names.iter().any(|entry| entry == &name);
        let has_collecting = names.iter().any(|entry| entry == &collecting);
        if has_final && has_collecting {
            return Err(FixedStagingError::Boundary);
        }
        if has_final {
            self.open_generation_manifest(identity)?;
        }
        if has_collecting {
            let directory = open_directory_at(
                &generations,
                &collecting,
                self.controller_uid,
                self.controller_gid,
                0o700,
            )?;
            let allowed = SOURCE_SPECS
                .iter()
                .map(|spec| spec.name)
                .chain(std::iter::once(MANIFEST_NAME))
                .collect::<BTreeSet<_>>();
            let names = directory_names(&directory, SOURCE_SPECS.len() + 1)?;
            if names.iter().any(|entry| !allowed.contains(entry.as_str())) {
                return Err(FixedStagingError::Boundary);
            }
            for entry in names {
                validate_removable_partial_file(
                    &directory,
                    &entry,
                    self.controller_uid,
                    self.controller_gid,
                )?;
            }
        }
        Ok(())
    }

    fn recover_collection(&self, identity: &GenerationIdentity) -> Result<(), FixedStagingError> {
        self.revalidate_root()?;
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let name = generation_name(identity.generation);
        let collecting = collection_name(identity.generation);
        let names = directory_names(&generations, 3)?;
        let has_final = names.iter().any(|entry| entry == &name);
        let has_collecting = names.iter().any(|entry| entry == &collecting);
        if !has_final && !has_collecting {
            return Ok(());
        }
        if has_final && has_collecting {
            return Err(FixedStagingError::Boundary);
        }
        let directory_name = if has_collecting { &collecting } else { &name };
        let directory = open_directory_at_either_mode(
            &generations,
            directory_name,
            self.controller_uid,
            self.controller_gid,
            0o500,
            0o700,
        )?;
        if has_final {
            self.open_generation_manifest(identity)?;
            set_descriptor_identity(&directory, self.controller_uid, self.controller_gid, 0o700)?;
            renameat(&generations, &name, &generations, &collecting)
                .map_err(|_| FixedStagingError::Boundary)?;
            generations
                .sync_all()
                .map_err(|_| FixedStagingError::Boundary)?;
        }
        self.remove_collecting_generation(&generations, &collecting, &directory)
    }

    fn remove_collecting_generation(
        &self,
        generations: &fs::File,
        name: &str,
        directory: &fs::File,
    ) -> Result<(), FixedStagingError> {
        let allowed = SOURCE_SPECS
            .iter()
            .map(|spec| spec.name)
            .chain(std::iter::once(MANIFEST_NAME))
            .collect::<BTreeSet<_>>();
        let names = directory_names(directory, SOURCE_SPECS.len() + 1)?;
        if names.iter().any(|entry| !allowed.contains(entry.as_str())) {
            return Err(FixedStagingError::Boundary);
        }
        for entry in names {
            validate_removable_partial_file(
                directory,
                &entry,
                self.controller_uid,
                self.controller_gid,
            )?;
            unlinkat(directory, &entry, AtFlags::empty())
                .map_err(|_| FixedStagingError::Boundary)?;
            directory
                .sync_all()
                .map_err(|_| FixedStagingError::Boundary)?;
        }
        require_same_directory_at(generations, name, directory)?;
        unlinkat(generations, name, AtFlags::REMOVEDIR).map_err(|_| FixedStagingError::Boundary)?;
        generations
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)
    }

    fn validate_root_inventory(&self) -> Result<(), FixedStagingError> {
        let found = directory_names(&self.root, 5)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let required = [
            INCOMING_DIRECTORY,
            GENERATIONS_DIRECTORY,
            DISPATCH_DIRECTORY,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        if !required.is_subset(&found)
            || found.iter().any(|name| {
                !required.contains(name)
                    && name != CURRENT_RECORD_NAME
                    && name != CURRENT_RECORD_TEMPORARY_NAME
            })
        {
            return Err(FixedStagingError::Boundary);
        }
        Ok(())
    }

    fn recover_current_record(&self) -> Result<Option<GenerationIdentity>, FixedStagingError> {
        let names = directory_names(&self.root, 5)?;
        if !names
            .iter()
            .any(|name| name == CURRENT_RECORD_TEMPORARY_NAME)
        {
            return Ok(None);
        }
        if names.iter().any(|name| name == CURRENT_RECORD_NAME) {
            self.remove_current_temporary()?;
            return Ok(None);
        }
        let Ok(temporary) = read_validated_file(
            &self.root,
            CURRENT_RECORD_TEMPORARY_NAME,
            self.controller_uid,
            self.controller_gid,
            0o400,
            CURRENT_RECORD_BYTES_MAX,
        ) else {
            self.remove_current_temporary()?;
            return Ok(None);
        };
        let Ok(record) = serde_json::from_slice::<CurrentRecordV1>(&temporary) else {
            self.remove_current_temporary()?;
            return Ok(None);
        };
        let identity = GenerationIdentity {
            generation: record.generation,
            manifest_digest: record.manifest_digest,
        };
        if record.version != 1
            || record.generation == 0
            || self.open_generation_manifest(&identity).is_err()
        {
            self.remove_current_temporary()?;
            return Ok(None);
        }
        renameat(
            &self.root,
            CURRENT_RECORD_TEMPORARY_NAME,
            &self.root,
            CURRENT_RECORD_NAME,
        )
        .map_err(|_| FixedStagingError::Boundary)?;
        self.root
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        Ok(Some(identity))
    }

    fn remove_current_temporary(&self) -> Result<(), FixedStagingError> {
        unlinkat(&self.root, CURRENT_RECORD_TEMPORARY_NAME, AtFlags::empty())
            .map_err(|_| FixedStagingError::Boundary)?;
        self.root
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)
    }

    fn recover_temporary_generations(&self) -> Result<(), FixedStagingError> {
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let names = directory_names(&generations, 4)?;
        let mut temporary = None;
        for name in &names {
            if parse_generation_name(name).is_some() {
                continue;
            }
            let generation =
                parse_temporary_generation_name(name).ok_or(FixedStagingError::Boundary)?;
            if temporary.replace((generation, name.as_str())).is_some() {
                return Err(FixedStagingError::Boundary);
            }
        }
        let Some((generation, name)) = temporary else {
            return Ok(());
        };
        let expected = self
            .read_current_identity_if_present()?
            .map_or(Ok(1), |current| {
                current
                    .generation
                    .checked_add(1)
                    .ok_or(FixedStagingError::Boundary)
            })?;
        if generation != expected
            || names
                .iter()
                .any(|entry| entry == &generation_name(expected))
        {
            return Err(FixedStagingError::Boundary);
        }
        self.remove_partial_temporary_generation(&generations, name)?;
        generations
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)
    }

    fn remove_partial_temporary_generation(
        &self,
        generations: &fs::File,
        name: &str,
    ) -> Result<(), FixedStagingError> {
        let directory = open_directory_at_either_mode(
            generations,
            name,
            self.controller_uid,
            self.controller_gid,
            0o700,
            0o500,
        )?;
        let names = directory_names(&directory, SOURCE_SPECS.len() + 1)?;
        let allowed = SOURCE_SPECS
            .iter()
            .map(|spec| spec.name)
            .chain(std::iter::once(MANIFEST_NAME))
            .collect::<BTreeSet<_>>();
        if names.iter().any(|entry| !allowed.contains(entry.as_str())) {
            return Err(FixedStagingError::Boundary);
        }
        set_descriptor_identity(&directory, self.controller_uid, self.controller_gid, 0o700)?;
        for entry in names {
            validate_removable_partial_file(
                &directory,
                &entry,
                self.controller_uid,
                self.controller_gid,
            )?;
            unlinkat(&directory, &entry, AtFlags::empty())
                .map_err(|_| FixedStagingError::Boundary)?;
        }
        directory
            .sync_all()
            .map_err(|_| FixedStagingError::Boundary)?;
        require_same_directory_at(generations, name, &directory)?;
        drop(directory);
        unlinkat(generations, name, AtFlags::REMOVEDIR).map_err(|_| FixedStagingError::Boundary)
    }

    fn list_generation_numbers(&self) -> Result<Vec<u64>, FixedStagingError> {
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let mut numbers = directory_names(&generations, 2)?
            .into_iter()
            .map(|name| parse_generation_name(&name).ok_or(FixedStagingError::Boundary))
            .collect::<Result<Vec<_>, _>>()?;
        numbers.sort_unstable();
        Ok(numbers)
    }

    fn recover_renamed_generation(&self) -> Result<Option<GenerationIdentity>, FixedStagingError> {
        let current = self.read_current_identity_if_present()?;
        let numbers = self.list_generation_numbers()?;
        if numbers.len() > 2 {
            return Err(FixedStagingError::Boundary);
        }
        match current {
            None if numbers.is_empty() => Ok(None),
            None if numbers == [1] => {
                let (identity, previous) = self.identity_from_generation(1)?;
                if previous.is_some() {
                    return Err(FixedStagingError::Boundary);
                }
                self.write_current_record(&identity)?;
                Ok(Some(identity))
            },
            None => Err(FixedStagingError::Boundary),
            Some(current) => {
                if !numbers.contains(&current.generation) {
                    return Err(FixedStagingError::Boundary);
                }
                let newer = numbers
                    .iter()
                    .copied()
                    .filter(|generation| *generation > current.generation)
                    .collect::<Vec<_>>();
                if newer.is_empty() {
                    return Ok(None);
                }
                let expected = current
                    .generation
                    .checked_add(1)
                    .ok_or(FixedStagingError::Boundary)?;
                if newer != [expected] {
                    return Err(FixedStagingError::Boundary);
                }
                let (identity, previous) = self.identity_from_generation(expected)?;
                if previous != Some(current.generation) {
                    return Err(FixedStagingError::Boundary);
                }
                self.write_current_record(&identity)?;
                Ok(Some(identity))
            },
        }
    }

    fn identity_from_generation(
        &self,
        generation: u64,
    ) -> Result<(GenerationIdentity, Option<u64>), FixedStagingError> {
        let generations = self.open_directory(
            GENERATIONS_DIRECTORY,
            self.controller_uid,
            self.controller_gid,
            0o700,
        )?;
        let directory = open_directory_at(
            &generations,
            &generation_name(generation),
            self.controller_uid,
            self.controller_gid,
            0o500,
        )?;
        validate_directory_inventory(&directory, true)?;
        let manifest_bytes = read_validated_file(
            &directory,
            MANIFEST_NAME,
            self.controller_uid,
            self.controller_gid,
            0o400,
            MANIFEST_BYTES_MAX,
        )?;
        let identity = GenerationIdentity {
            generation,
            manifest_digest: lowercase_hex(&Sha256::digest(&manifest_bytes)),
        };
        let opened = self.open_generation_manifest(&identity)?;
        Ok((identity, opened.manifest.previous_generation))
    }
}

fn open_directory_at_either_mode(
    parent: &fs::File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
    first_mode: u32,
    second_mode: u32,
) -> Result<fs::File, FixedStagingError> {
    let directory = fs::File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let metadata = directory
        .metadata()
        .map_err(|_| FixedStagingError::Boundary)?;
    if validate_metadata(&metadata, true, expected_user, expected_group, first_mode).is_err()
        && validate_metadata(&metadata, true, expected_user, expected_group, second_mode).is_err()
    {
        return Err(FixedStagingError::Boundary);
    }
    require_same_directory_at(parent, name, &directory)?;
    Ok(directory)
}

fn require_same_directory_at(
    parent: &fs::File,
    name: &str,
    pinned: &fs::File,
) -> Result<(), FixedStagingError> {
    let reopened = fs::File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let expected = pinned.metadata().map_err(|_| FixedStagingError::Boundary)?;
    let found = reopened
        .metadata()
        .map_err(|_| FixedStagingError::Boundary)?;
    if expected.dev() != found.dev() || expected.ino() != found.ino() {
        return Err(FixedStagingError::Boundary);
    }
    Ok(())
}

fn validate_removable_runner_input(
    directory: &fs::File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
) -> Result<(), FixedStagingError> {
    let file = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let metadata = file.metadata().map_err(|_| FixedStagingError::Boundary)?;
    validate_metadata(&metadata, false, expected_user, expected_group, 0o400)?;
    if metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len()
            > u64::try_from(RUNNER_INPUT_BYTES_MAX).map_err(|_| FixedStagingError::Boundary)?
    {
        return Err(FixedStagingError::Boundary);
    }
    Ok(())
}

fn validate_removable_partial_file(
    directory: &fs::File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
) -> Result<(), FixedStagingError> {
    let file = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let metadata = file.metadata().map_err(|_| FixedStagingError::Boundary)?;
    validate_metadata(&metadata, false, expected_user, expected_group, 0o400)?;
    if metadata.nlink() != 1 {
        return Err(FixedStagingError::Boundary);
    }
    let maximum = SOURCE_SPECS
        .iter()
        .find(|spec| spec.name == name)
        .map_or_else(
            || {
                if crate::runner_process::INPUT_NAMES.contains(&name) {
                    RUNNER_INPUT_BYTES_MAX
                } else {
                    MANIFEST_BYTES_MAX
                }
            },
            |spec| spec.maximum,
        );
    if metadata.len() > u64::try_from(maximum).map_err(|_| FixedStagingError::Boundary)? {
        return Err(FixedStagingError::Boundary);
    }
    Ok(())
}

fn set_descriptor_identity(
    descriptor: &fs::File,
    expected_user: u32,
    expected_group: u32,
    mode: u32,
) -> Result<(), FixedStagingError> {
    rustix::fs::fchown(
        descriptor,
        Some(rustix::process::Uid::from_raw(expected_user)),
        Some(rustix::process::Gid::from_raw(expected_group)),
    )
    .map_err(|_| FixedStagingError::Boundary)?;
    let mode = rustix::fs::RawMode::try_from(mode).map_err(|_| FixedStagingError::Boundary)?;
    rustix::fs::fchmod(descriptor, Mode::from_raw_mode(mode))
        .map_err(|_| FixedStagingError::Boundary)
}

fn open_directory_at(
    directory: &fs::File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
    mode: u32,
) -> Result<fs::File, FixedStagingError> {
    let opened = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let metadata = opened.metadata().map_err(|_| FixedStagingError::Boundary)?;
    validate_metadata(&metadata, true, expected_user, expected_group, mode)?;
    let reopened = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let reopened_metadata = reopened
        .metadata()
        .map_err(|_| FixedStagingError::Boundary)?;
    if metadata.dev() != reopened_metadata.dev() || metadata.ino() != reopened_metadata.ino() {
        return Err(FixedStagingError::Boundary);
    }
    Ok(opened)
}

fn read_validated_file(
    directory: &fs::File,
    name: &str,
    expected_user: u32,
    expected_group: u32,
    mode: u32,
    maximum: usize,
) -> Result<Vec<u8>, FixedStagingError> {
    let file = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                FixedStagingError::Unavailable
            } else {
                FixedStagingError::Boundary
            }
        })?,
    );
    let metadata = file.metadata().map_err(|_| FixedStagingError::Boundary)?;
    validate_metadata(&metadata, false, expected_user, expected_group, mode)?;
    if metadata.nlink() != 1 {
        return Err(FixedStagingError::Boundary);
    }
    if metadata.len() == 0
        || metadata.len() > u64::try_from(maximum).map_err(|_| FixedStagingError::Boundary)?
    {
        return Err(FixedStagingError::Boundary);
    }
    let reopened = fs::File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| FixedStagingError::Boundary)?,
    );
    let reopened_metadata = reopened
        .metadata()
        .map_err(|_| FixedStagingError::Boundary)?;
    if metadata.dev() != reopened_metadata.dev() || metadata.ino() != reopened_metadata.ino() {
        return Err(FixedStagingError::Boundary);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| FixedStagingError::Boundary)?,
    );
    file.take(u64::try_from(maximum + 1).map_err(|_| FixedStagingError::Boundary)?)
        .read_to_end(&mut bytes)
        .map_err(|_| FixedStagingError::Boundary)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(FixedStagingError::Boundary);
    }
    Ok(bytes)
}

fn validate_metadata(
    metadata: &fs::Metadata,
    directory: bool,
    expected_user: u32,
    expected_group: u32,
    mode: u32,
) -> Result<(), FixedStagingError> {
    if metadata.is_dir() != directory
        || metadata.is_file() == directory
        || metadata.uid() != expected_user
        || metadata.gid() != expected_group
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(FixedStagingError::Boundary);
    }
    Ok(())
}

fn directory_names(directory: &fs::File, maximum: usize) -> Result<Vec<String>, FixedStagingError> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory).map_err(|_| FixedStagingError::Boundary)? {
        let entry = entry.map_err(|_| FixedStagingError::Boundary)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if names.len() == maximum {
            return Err(FixedStagingError::Boundary);
        }
        names.push(
            name.to_str()
                .map(str::to_owned)
                .map_err(|_| FixedStagingError::Boundary)?,
        );
    }
    names.sort_unstable();
    Ok(names)
}

fn validate_directory_inventory(
    directory: &fs::File,
    expect_manifest: bool,
) -> Result<(), FixedStagingError> {
    let found = directory_names(directory, SOURCE_SPECS.len() + usize::from(expect_manifest))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut expected = SOURCE_SPECS
        .iter()
        .map(|spec| spec.name.to_owned())
        .collect::<BTreeSet<_>>();
    if expect_manifest {
        expected.insert(MANIFEST_NAME.to_owned());
    }
    if found != expected {
        return Err(FixedStagingError::Boundary);
    }
    Ok(())
}

fn validate_secret_32(bytes: &[u8]) -> Result<[u8; 32], FixedStagingError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| FixedStagingError::Boundary)?;
    if bytes == [0; 32] {
        return Err(FixedStagingError::Boundary);
    }
    Ok(bytes)
}

fn validate_key_id(bytes: &[u8]) -> Result<String, FixedStagingError> {
    let text = std::str::from_utf8(bytes).map_err(|_| FixedStagingError::Boundary)?;
    if text.is_empty()
        || text.len() > 128
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(FixedStagingError::Boundary);
    }
    Ok(text.to_owned())
}

fn validate_bounded_binary(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, FixedStagingError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(FixedStagingError::Boundary);
    }
    Ok(bytes.to_vec())
}

fn validate_absolute_uri(bytes: &[u8], maximum: usize) -> Result<String, FixedStagingError> {
    let text = validate_visible_ascii(bytes, maximum)?;
    let uri = text
        .parse::<Uri>()
        .map_err(|_| FixedStagingError::Boundary)?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || uri
            .path_and_query()
            .is_some_and(|value| value.query().is_some())
        || text.contains('#')
    {
        return Err(FixedStagingError::Boundary);
    }
    Ok(text)
}

fn validate_ascii_token(bytes: &[u8], maximum: usize) -> Result<String, FixedStagingError> {
    let text = validate_visible_ascii(bytes, maximum)?;
    if text.chars().any(char::is_whitespace) {
        return Err(FixedStagingError::Boundary);
    }
    Ok(text)
}

fn validate_handoff_endpoint(bytes: &[u8]) -> Result<SocketAddr, FixedStagingError> {
    let text = validate_visible_ascii(bytes, 64)?;
    let address = text
        .parse::<SocketAddr>()
        .map_err(|_| FixedStagingError::Boundary)?;
    if !address.ip().is_loopback() {
        return Err(FixedStagingError::Boundary);
    }
    Ok(address)
}

fn validate_visible_ascii(bytes: &[u8], maximum: usize) -> Result<String, FixedStagingError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(FixedStagingError::Boundary);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FixedStagingError::Boundary)?;
    if !text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(FixedStagingError::Boundary);
    }
    Ok(text.to_owned())
}

fn validate_public_receipt_trust(
    bytes: &[u8],
    receipt_signing_seed: &[u8; 32],
    receipt_signing_key_id: &str,
) -> Result<PublicReceiptTrustDocument, FixedStagingError> {
    if bytes.len() > 1024 {
        return Err(FixedStagingError::Boundary);
    }
    let trust: PublicReceiptTrustDocument =
        serde_json::from_slice(bytes).map_err(|_| FixedStagingError::Boundary)?;
    if trust.version != 1
        || trust.key_id != receipt_signing_key_id
        || trust.accepted_purpose != PUBLIC_TRUST_PURPOSE
        || trust.not_before_unix_s >= trust.not_after_unix_s
        || !is_lower_hex(&trust.public_key_hex)
    {
        return Err(FixedStagingError::Boundary);
    }
    let verifying_key = SigningKey::from_bytes(receipt_signing_seed)
        .verifying_key()
        .to_bytes();
    if trust.public_key_hex != lowercase_hex(&verifying_key) {
        return Err(FixedStagingError::Boundary);
    }
    Ok(trust)
}

fn is_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_run_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn lease_name(epoch: i64) -> String {
    format!("{LEASE_PREFIX}{epoch:020}")
}

fn temporary_lease_name(epoch: i64) -> String {
    format!("{LEASE_TEMPORARY_PREFIX}{epoch:020}{LEASE_TEMPORARY_SUFFIX}")
}

fn parse_lease_name(name: &str) -> Option<i64> {
    let digits = name.strip_prefix(LEASE_PREFIX)?;
    if digits.len() != 20 {
        return None;
    }
    let epoch = digits.parse::<i64>().ok()?;
    (epoch > 0 && name == lease_name(epoch)).then_some(epoch)
}

fn parse_temporary_lease_name(name: &str) -> Option<i64> {
    let digits = name
        .strip_prefix(LEASE_TEMPORARY_PREFIX)?
        .strip_suffix(LEASE_TEMPORARY_SUFFIX)?;
    if digits.len() != 20 {
        return None;
    }
    let epoch = digits.parse::<i64>().ok()?;
    (epoch > 0 && name == temporary_lease_name(epoch)).then_some(epoch)
}

fn same_file(first: &fs::File, second: &fs::File) -> Result<bool, FixedStagingError> {
    let first = first.metadata().map_err(|_| FixedStagingError::Boundary)?;
    let second = second.metadata().map_err(|_| FixedStagingError::Boundary)?;
    Ok(first.dev() == second.dev() && first.ino() == second.ino())
}

fn collection_name(generation: u64) -> String {
    format!("{COLLECTION_PREFIX}{generation:020}")
}

fn generation_name(generation: u64) -> String {
    format!("{GENERATION_PREFIX}{generation:020}")
}

fn temporary_generation_name(generation: u64) -> String {
    format!("{GENERATION_TEMPORARY_PREFIX}{generation:020}{GENERATION_TEMPORARY_SUFFIX}")
}

fn parse_temporary_generation_name(name: &str) -> Option<u64> {
    let number = name
        .strip_prefix(GENERATION_TEMPORARY_PREFIX)?
        .strip_suffix(GENERATION_TEMPORARY_SUFFIX)?;
    if number.len() != 20 {
        return None;
    }
    let generation = number.parse::<u64>().ok()?;
    (generation != 0 && name == temporary_generation_name(generation)).then_some(generation)
}

fn parse_generation_name(name: &str) -> Option<u64> {
    let number = name.strip_prefix(GENERATION_PREFIX)?;
    if number.len() != 20 {
        return None;
    }
    let generation = number.parse::<u64>().ok()?;
    (generation != 0 && name == generation_name(generation)).then_some(generation)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        installer: FixedStagingInstaller,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "kapsel-fixed-staging-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            for directory in [
                INCOMING_DIRECTORY,
                GENERATIONS_DIRECTORY,
                DISPATCH_DIRECTORY,
            ] {
                fs::create_dir(root.join(directory)).unwrap();
                fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            let installer =
                FixedStagingInstaller::open_same_identity_for_test(&root, uid, gid).unwrap();
            Self {
                root,
                installer,
                uid,
                gid,
            }
        }

        fn incoming(&self) -> PathBuf {
            self.root.join(INCOMING_DIRECTORY)
        }

        fn generations(&self) -> PathBuf {
            self.root.join(GENERATIONS_DIRECTORY)
        }

        fn generation_file(&self, generation: u64, name: &str) -> PathBuf {
            self.generations()
                .join(generation_name(generation))
                .join(name)
        }

        fn create_temporary_generation(&self, name: &str) {
            let path = self.generations().join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
        }

        fn reader(&self) -> FixedStagingReader {
            FixedStagingReader::open_same_identity_for_test(&self.root, self.uid, self.gid).unwrap()
        }

        fn write_valid_candidate(&self) {
            self.write_candidate(valid_candidate());
        }

        fn write_candidate(&self, files: Vec<(&'static str, Vec<u8>)>) {
            let incoming = self.incoming();
            let _ = fs::remove_dir_all(&incoming);
            fs::create_dir(&incoming).unwrap();
            fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
            for (name, bytes) in files {
                let path = incoming.join(name);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn runner_inputs(marker: u8) -> Vec<(&'static str, Vec<u8>)> {
        crate::runner_process::INPUT_NAMES
            .into_iter()
            .map(|name| (name, vec![marker]))
            .collect()
    }

    #[test]
    fn publishes_runner_inputs_as_one_idempotent_lease_directory() {
        let fixture = Fixture::new();
        let reader = fixture.reader();
        let run_id = "0123456789abcdef0123456789abcdef";
        let expected = runner_inputs(7);
        let published = reader.publish_runner_inputs(run_id, 1, &expected).unwrap();
        assert_eq!(
            directory_names(
                published.directory(),
                crate::runner_process::INPUT_NAMES.len()
            )
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
            crate::runner_process::INPUT_NAMES
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert_eq!(
            fs::read(
                fixture
                    .root
                    .join(DISPATCH_DIRECTORY)
                    .join(run_id)
                    .join(lease_name(1))
                    .join("request.json")
            )
            .unwrap(),
            vec![7]
        );
        reader.publish_runner_inputs(run_id, 1, &expected).unwrap();
        assert!(matches!(
            reader.publish_runner_inputs(run_id, 1, &runner_inputs(8)),
            Err(FixedStagingError::Boundary)
        ));
    }

    #[test]
    fn removes_only_complete_retired_dispatch_runs() {
        let fixture = Fixture::new();
        let reader = fixture.reader();
        let run_id = "0123456789abcdef0123456789abcdef";
        reader
            .publish_runner_inputs(run_id, 1, &runner_inputs(7))
            .unwrap();
        reader
            .publish_runner_inputs(run_id, 2, &runner_inputs(8))
            .unwrap();
        assert_eq!(
            reader.dispatch_run_ids().unwrap(),
            BTreeSet::from([run_id.into()])
        );
        reader.remove_retired_dispatch(run_id).unwrap();
        assert!(reader.dispatch_run_ids().unwrap().is_empty());
        reader.remove_retired_dispatch(run_id).unwrap();
    }

    #[test]
    fn collects_only_the_exact_noncurrent_generation() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let first = fixture.installer.activate_incoming().unwrap();
        fixture.write_valid_candidate();
        let second = fixture.installer.activate_incoming().unwrap();
        let reader = fixture.reader();
        assert_eq!(reader.noncurrent_identity().unwrap(), Some(first.clone()));
        reader.collect_noncurrent(&first).unwrap();
        reader.recover_collection(&first).unwrap();
        assert_eq!(reader.current_identity().unwrap(), second);
        assert!(reader.noncurrent_identity().unwrap().is_none());
        assert!(matches!(
            reader.collect_noncurrent(&second),
            Err(FixedStagingError::Boundary)
        ));
    }

    #[test]
    fn resumes_collection_after_the_generation_rename() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let first = fixture.installer.activate_incoming().unwrap();
        fixture.write_valid_candidate();
        fixture.installer.activate_incoming().unwrap();
        let generations = fixture.generations();
        let original = generations.join(generation_name(1));
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        let collecting = generations.join(collection_name(1));
        fs::rename(&original, &collecting).unwrap();
        fs::remove_file(collecting.join("authorization-signing-seed")).unwrap();
        fixture.reader().recover_collection(&first).unwrap();
        assert!(!collecting.exists());
        assert_eq!(fixture.reader().current_identity().unwrap().generation(), 2);
    }

    #[test]
    fn recovers_one_partial_lease_and_rejects_unknown_debris() {
        let fixture = Fixture::new();
        let reader = fixture.reader();
        let run_id = "0123456789abcdef0123456789abcdef";
        let run = fixture.root.join(DISPATCH_DIRECTORY).join(run_id);
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let partial = run.join(temporary_lease_name(1));
        fs::create_dir(&partial).unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o700)).unwrap();
        let file = partial.join("request.json");
        fs::write(&file, [1]).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        reader
            .publish_runner_inputs(run_id, 1, &runner_inputs(7))
            .unwrap();
        fs::write(run.join("unknown"), []).unwrap();
        assert!(matches!(
            reader.publish_runner_inputs(run_id, 2, &runner_inputs(8)),
            Err(FixedStagingError::Boundary)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the privileged network-disabled distinct-identity lane"]
    fn production_distinct_identity_installs_and_reads() {
        struct TestIdentity {
            uid: u32,
            gid: u32,
        }

        let root = PathBuf::from(std::env::var_os("KAPSEL_STAGING_TEST_ROOT").unwrap());
        let controller = TestIdentity {
            uid: std::env::var("KAPSEL_CONTROLLER_UID")
                .unwrap()
                .parse::<u32>()
                .unwrap(),
            gid: std::env::var("KAPSEL_CONTROLLER_GID")
                .unwrap()
                .parse::<u32>()
                .unwrap(),
        };
        let staging = TestIdentity {
            uid: std::env::var("KAPSEL_STAGING_UID")
                .unwrap()
                .parse::<u32>()
                .unwrap(),
            gid: std::env::var("KAPSEL_STAGING_GID")
                .unwrap()
                .parse::<u32>()
                .unwrap(),
        };
        let role = std::env::var("KAPSEL_STAGING_TEST_ROLE").unwrap();
        assert!(
            matches!(role.as_str(), "prepare" | "installer" | "reader"),
            "unexpected staging test role: {role}"
        );
        match role.as_str() {
            "prepare" | "installer" => {
                let incoming = root.join(INCOMING_DIRECTORY);
                for (name, bytes) in valid_candidate() {
                    let path = incoming.join(name);
                    fs::write(&path, bytes).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
                }
                if role == "prepare" {
                    return;
                }
                let installer = FixedStagingInstaller::open(
                    &root,
                    controller.uid,
                    controller.gid,
                    staging.uid,
                    staging.gid,
                )
                .unwrap();
                assert_eq!(installer.activate_incoming().unwrap().generation(), 1);
            },
            "reader" => {
                let reader = FixedStagingReader::open(
                    &root,
                    controller.uid,
                    controller.gid,
                    staging.uid,
                    staging.gid,
                )
                .unwrap();
                let current = reader.current_identity().unwrap();
                assert_eq!(current.generation(), 1);
                assert_eq!(
                    reader.authorization(&current).unwrap().signing_seed,
                    [41; 32]
                );
            },
            _ => {},
        }
    }

    #[test]
    fn activates_and_opens_current_generation() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let identity = fixture.installer.activate_incoming().unwrap();
        assert_eq!(identity.generation, 1);
        let reader = fixture.reader();
        assert_eq!(reader.current_identity().unwrap(), identity);
        let authorization = reader.authorization(&identity).unwrap();
        assert_eq!(authorization.signing_seed, [41; 32]);
        assert_eq!(authorization.signing_key_id, "sandbox-authorization-key");
        let receipt = reader.receipt(&identity).unwrap();
        assert_eq!(receipt.signing_seed, [42; 32]);
        assert_eq!(receipt.signing_key_id, "sandbox-receipt-key");
        assert_eq!(reader.tombstone(&identity).unwrap().digest_key, [43; 32]);
        let runner = reader.runner_kubernetes(&identity).unwrap();
        assert_eq!(runner.api_server, "https://127.0.0.1:6443");
        assert!(!runner.ca_bytes.is_empty());
        assert_eq!(runner.token, "runner-token");
        let cleanup = reader.cleanup_kubernetes(&identity).unwrap();
        assert_eq!(cleanup.api_server, "https://127.0.0.1:7443");
        assert!(!cleanup.ca_bytes.is_empty());
        assert_eq!(cleanup.token, "cleanup-token");
        assert_eq!(
            reader.handoff(&identity).unwrap().endpoint,
            "127.0.0.1:7001".parse().unwrap()
        );
        assert!(!reader.public_trust(&identity).unwrap().bytes.is_empty());
        let manifest = fs::read(
            fixture
                .generations()
                .join("generation-00000000000000000001")
                .join(MANIFEST_NAME),
        )
        .unwrap();
        assert_eq!(
            lowercase_hex(&Sha256::digest(&manifest)),
            identity.manifest_digest
        );
    }

    #[test]
    fn family_reads_isolate_unrelated_payload_corruption() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let identity = fixture.installer.activate_incoming().unwrap();
        let authorization_seed =
            fixture.generation_file(identity.generation, "authorization-signing-seed");
        overwrite_private_file_for_test(&authorization_seed, &[0; 32]);
        let reader = fixture.reader();
        assert_eq!(reader.current_identity().unwrap(), identity);
        assert_eq!(
            reader.cleanup_kubernetes(&identity).unwrap().token,
            "cleanup-token"
        );
        assert!(matches!(
            reader.authorization(&identity),
            Err(FixedStagingError::Boundary)
        ));

        overwrite_private_file_for_test(&authorization_seed, &[41; 32]);
        let cleanup_token =
            fixture.generation_file(identity.generation, "cleanup-kubernetes-token");
        overwrite_private_file_for_test(&cleanup_token, b"cleanup-tokeX");
        assert_eq!(
            reader.authorization(&identity).unwrap().signing_seed,
            [41; 32]
        );
        assert!(matches!(
            reader.cleanup_kubernetes(&identity),
            Err(FixedStagingError::Boundary)
        ));
    }

    #[test]
    fn manifest_and_required_cross_binding_corruption_fail_dependents_only() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let identity = fixture.installer.activate_incoming().unwrap();
        let trust = fixture.generation_file(identity.generation, "public-receipt-trust.json");
        let original_trust = fs::read(&trust).unwrap();
        let mut corrupted_trust = original_trust.clone();
        corrupted_trust[0] ^= 1;
        overwrite_private_file_for_test(&trust, &corrupted_trust);
        let reader = fixture.reader();
        assert_eq!(
            reader.authorization(&identity).unwrap().signing_seed,
            [41; 32]
        );
        assert!(matches!(
            reader.receipt(&identity),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            reader.public_trust(&identity),
            Err(FixedStagingError::Boundary)
        ));

        overwrite_private_file_for_test(&trust, &original_trust);
        let manifest = fixture.generation_file(identity.generation, MANIFEST_NAME);
        let original_manifest = fs::read(&manifest).unwrap();
        let mut corrupted_manifest = original_manifest;
        corrupted_manifest[0] ^= 1;
        overwrite_private_file_for_test(&manifest, &corrupted_manifest);
        assert!(matches!(
            fixture.reader().authorization(&identity),
            Err(FixedStagingError::Boundary)
        ));
    }

    #[test]
    fn rejects_missing_files_exhaustively() {
        for missing in SOURCE_SPECS {
            let fixture = Fixture::new();
            fixture.write_candidate(
                valid_candidate()
                    .into_iter()
                    .filter(|(name, _)| *name != missing.name)
                    .collect(),
            );
            assert_eq!(
                fixture.installer.activate_incoming(),
                Err(FixedStagingError::Boundary)
            );
        }
    }

    #[test]
    fn rejects_extra_file() {
        let fixture = Fixture::new();
        let mut files = valid_candidate();
        files.push(("unexpected", b"extra".to_vec()));
        fixture.write_candidate(files);
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
    }

    #[test]
    fn rejects_malformed_files_exhaustively() {
        for (name, bytes) in malformed_cases() {
            let fixture = Fixture::new();
            let files = valid_candidate()
                .into_iter()
                .map(|(candidate_name, candidate_bytes)| {
                    if candidate_name == name {
                        (candidate_name, bytes.clone())
                    } else {
                        (candidate_name, candidate_bytes)
                    }
                })
                .collect();
            fixture.write_candidate(files);
            assert_eq!(
                fixture.installer.activate_incoming(),
                Err(FixedStagingError::Boundary)
            );
        }
    }

    #[test]
    fn rejects_wrong_modes_exhaustively() {
        for spec in SOURCE_SPECS {
            let fixture = Fixture::new();
            fixture.write_valid_candidate();
            fs::set_permissions(
                fixture.incoming().join(spec.name),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert_eq!(
                fixture.installer.activate_incoming(),
                Err(FixedStagingError::Boundary)
            );
        }
    }

    #[test]
    fn rejects_symlinked_and_hardlinked_files_exhaustively() {
        for spec in SOURCE_SPECS {
            let fixture = Fixture::new();
            fixture.write_valid_candidate();
            let target = fixture.root.join(format!("target-{}", spec.name));
            fs::write(&target, b"linked").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();
            let candidate = fixture.incoming().join(spec.name);
            fs::remove_file(&candidate).unwrap();
            symlink(&target, &candidate).unwrap();
            assert_eq!(
                fixture.installer.activate_incoming(),
                Err(FixedStagingError::Boundary)
            );
        }
        for spec in SOURCE_SPECS {
            let fixture = Fixture::new();
            fixture.write_valid_candidate();
            let target = fixture.root.join(format!("hardlink-{}", spec.name));
            fs::copy(fixture.incoming().join(spec.name), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();
            let candidate = fixture.incoming().join(spec.name);
            fs::remove_file(&candidate).unwrap();
            fs::hard_link(&target, &candidate).unwrap();
            assert_eq!(
                fixture.installer.activate_incoming(),
                Err(FixedStagingError::Boundary)
            );
        }
    }

    #[test]
    fn recovers_partial_current_and_temporary_generation_state() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let identity = fixture.installer.activate_incoming().unwrap();
        let current = fixture.root.join(CURRENT_RECORD_NAME);
        let temporary_current = fixture.root.join(CURRENT_RECORD_TEMPORARY_NAME);
        fs::copy(&current, &temporary_current).unwrap();
        fs::remove_file(&current).unwrap();
        fs::create_dir(fixture.generations().join(temporary_generation_name(2))).unwrap();
        fs::set_permissions(
            fixture.generations().join(temporary_generation_name(2)),
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let recovered = fixture.installer.activate_incoming().unwrap();
        assert_eq!(recovered, identity);
        assert_eq!(fixture.reader().current_identity().unwrap(), identity);
        assert!(fixture.root.join(CURRENT_RECORD_NAME).exists());
        assert!(!fixture.root.join(CURRENT_RECORD_TEMPORARY_NAME).exists());
        assert!(!fixture
            .generations()
            .join(temporary_generation_name(2))
            .exists());
    }

    #[test]
    fn reader_rejects_a_third_generation_inventory_entry() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fixture.installer.activate_incoming().unwrap();
        for generation in [2, 3] {
            let path = fixture.generations().join(generation_name(generation));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert_eq!(
            fixture.reader().current_identity(),
            Err(FixedStagingError::Boundary)
        );
    }

    #[test]
    fn rejects_malformed_nonadjacent_and_multiple_temporary_generations() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fixture.create_temporary_generation(&temporary_generation_name(1));
        assert_eq!(fixture.installer.activate_incoming().unwrap().generation, 1);

        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fixture.installer.activate_incoming().unwrap();
        fixture.create_temporary_generation(".generation-malformed.tmp");
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );

        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fixture.installer.activate_incoming().unwrap();
        fixture.create_temporary_generation(&temporary_generation_name(3));
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );

        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fixture.installer.activate_incoming().unwrap();
        fixture.create_temporary_generation(&temporary_generation_name(2));
        fixture.create_temporary_generation(&temporary_generation_name(3));
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
    }

    #[test]
    fn enforces_rotation_ceiling_and_keeps_old_pins_openable() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let first = fixture.installer.activate_incoming().unwrap();
        fixture.write_valid_candidate();
        let second = fixture.installer.activate_incoming().unwrap();
        assert_eq!(second.generation, 2);
        assert_eq!(
            fixture.reader().authorization(&first).unwrap().signing_seed,
            [41; 32]
        );
        fixture.write_valid_candidate();
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::RotationCeiling)
        );
    }

    #[test]
    fn recovers_fully_renamed_initial_generation_before_current() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let first = fixture.installer.activate_incoming().unwrap();
        fs::remove_file(fixture.root.join(CURRENT_RECORD_NAME)).unwrap();
        assert_eq!(fixture.installer.activate_incoming().unwrap(), first);
        assert_eq!(fixture.reader().current_identity().unwrap(), first);
    }

    #[test]
    fn recovers_fully_renamed_rotated_generation_before_current() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let first = fixture.installer.activate_incoming().unwrap();
        let first_current = fs::read(fixture.root.join(CURRENT_RECORD_NAME)).unwrap();
        fixture.write_valid_candidate();
        let second = fixture.installer.activate_incoming().unwrap();
        assert_eq!(second.generation, first.generation + 1);
        fs::set_permissions(
            fixture.root.join(CURRENT_RECORD_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(fixture.root.join(CURRENT_RECORD_NAME), first_current).unwrap();
        fs::set_permissions(
            fixture.root.join(CURRENT_RECORD_NAME),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        assert_eq!(fixture.installer.activate_incoming().unwrap(), second);
        assert_eq!(fixture.reader().current_identity().unwrap(), second);
    }

    #[test]
    fn rejects_root_substitution_for_installer_and_reader() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        let reader = fixture.reader();
        let displaced = fixture.root.with_extension("displaced");
        fs::rename(&fixture.root, &displaced).unwrap();
        create_authority_layout(&fixture.root);
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
        assert_eq!(reader.current_identity(), Err(FixedStagingError::Boundary));
        fs::remove_dir_all(&displaced).unwrap();
    }

    #[test]
    fn rejects_wrong_role_identity_and_special_permission_bits() {
        let fixture = Fixture::new();
        let different_user = fixture.uid.checked_add(1).unwrap();
        let different_group = fixture.gid.checked_add(1).unwrap();
        assert!(matches!(
            FixedStagingInstaller::open(
                &fixture.root,
                fixture.uid,
                fixture.gid,
                fixture.uid,
                fixture.gid,
            ),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            FixedStagingReader::open(
                &fixture.root,
                fixture.uid,
                fixture.gid,
                fixture.uid,
                fixture.gid,
            ),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            FixedStagingInstaller::open(
                &fixture.root,
                fixture.uid,
                fixture.gid,
                different_user,
                fixture.gid,
            ),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            FixedStagingReader::open(
                &fixture.root,
                different_user,
                fixture.gid,
                fixture.uid,
                fixture.gid,
            ),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            FixedStagingInstaller::open(
                &fixture.root,
                different_user,
                fixture.gid,
                fixture.uid,
                fixture.gid,
            ),
            Err(FixedStagingError::Boundary)
        ));
        assert!(matches!(
            FixedStagingInstaller::open(
                &fixture.root,
                fixture.uid,
                fixture.gid,
                fixture.uid,
                different_group,
            ),
            Err(FixedStagingError::Boundary)
        ));
        fs::write(fixture.root.join("unexpected-root-entry"), b"unexpected").unwrap();
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
        fs::remove_file(fixture.root.join("unexpected-root-entry")).unwrap();
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o1700)).unwrap();
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
    }

    #[test]
    fn rejects_source_special_bits_and_non_https_endpoint() {
        let fixture = Fixture::new();
        fixture.write_valid_candidate();
        fs::set_permissions(
            fixture.incoming().join("authorization-signing-seed"),
            fs::Permissions::from_mode(0o4400),
        )
        .unwrap();
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );

        let fixture = Fixture::new();
        let files = valid_candidate()
            .into_iter()
            .map(|(name, bytes)| {
                if name == "runner-kubernetes-api-server" {
                    (name, b"http://127.0.0.1:6443".to_vec())
                } else {
                    (name, bytes)
                }
            })
            .collect();
        fixture.write_candidate(files);
        assert_eq!(
            fixture.installer.activate_incoming(),
            Err(FixedStagingError::Boundary)
        );
    }

    fn overwrite_private_file_for_test(path: &Path, bytes: &[u8]) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    fn create_authority_layout(root: &Path) {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        for directory in [
            INCOMING_DIRECTORY,
            GENERATIONS_DIRECTORY,
            DISPATCH_DIRECTORY,
        ] {
            fs::create_dir(root.join(directory)).unwrap();
            fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn valid_candidate() -> Vec<(&'static str, Vec<u8>)> {
        let receipt_signing_seed = [42_u8; 32];
        vec![
            ("authorization-signing-seed", vec![41_u8; 32]),
            (
                "authorization-signing-key-id",
                b"sandbox-authorization-key".to_vec(),
            ),
            ("receipt-signing-seed", receipt_signing_seed.to_vec()),
            ("receipt-signing-key-id", b"sandbox-receipt-key".to_vec()),
            ("tombstone-digest-key", vec![43_u8; 32]),
            (
                "runner-kubernetes-api-server",
                b"https://127.0.0.1:6443".to_vec(),
            ),
            (
                "runner-kubernetes-ca.pem",
                b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
            ),
            ("runner-kubernetes-token", b"runner-token".to_vec()),
            (
                "cleanup-kubernetes-api-server",
                b"https://127.0.0.1:7443".to_vec(),
            ),
            (
                "cleanup-kubernetes-ca.pem",
                b"-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n".to_vec(),
            ),
            ("cleanup-kubernetes-token", b"cleanup-token".to_vec()),
            ("handoff-endpoint", b"127.0.0.1:7001".to_vec()),
            (
                "public-receipt-trust.json",
                serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "key_id": "sandbox-receipt-key",
                    "public_key_hex": lowercase_hex(
                        &SigningKey::from_bytes(&receipt_signing_seed)
                            .verifying_key()
                            .to_bytes(),
                    ),
                    "accepted_purpose": PUBLIC_TRUST_PURPOSE,
                    "not_before_unix_s": 1,
                    "not_after_unix_s": 2,
                }))
                .unwrap(),
            ),
        ]
    }

    fn malformed_cases() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("authorization-signing-seed", vec![0_u8; 32]),
            ("authorization-signing-key-id", b"bad key".to_vec()),
            ("receipt-signing-seed", vec![0_u8; 32]),
            ("receipt-signing-key-id", b"bad\nkey".to_vec()),
            ("tombstone-digest-key", vec![41_u8; 32]),
            (
                "runner-kubernetes-api-server",
                b"https://user@127.0.0.1".to_vec(),
            ),
            ("runner-kubernetes-ca.pem", Vec::new()),
            ("runner-kubernetes-token", b"runner token".to_vec()),
            (
                "cleanup-kubernetes-api-server",
                b"https://127.0.0.1?query=1".to_vec(),
            ),
            ("cleanup-kubernetes-ca.pem", Vec::new()),
            ("cleanup-kubernetes-token", b"runner-token".to_vec()),
            ("handoff-endpoint", b"192.0.2.1:7001".to_vec()),
            (
                "public-receipt-trust.json",
                serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "key_id": "sandbox-receipt-key",
                    "public_key_hex": "00".repeat(32),
                    "accepted_purpose": PUBLIC_TRUST_PURPOSE,
                    "not_before_unix_s": 1,
                    "not_after_unix_s": 2,
                }))
                .unwrap(),
            ),
        ]
    }
}
