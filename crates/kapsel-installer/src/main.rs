//! Self-contained installer for the unpublished Kapsel preview.

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "runtime installer validation is Linux-only")
)]

use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
};

#[cfg(target_os = "linux")]
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    mem::MaybeUninit,
    os::fd::OwnedFd,
    path::{Component, Path},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use http::{uri::Scheme, Uri};
#[cfg(target_os = "linux")]
use rustix::fs::{self as rfs, FileType, FlockOperation, Mode, OFlags, RawDir, Stat, CWD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "linux")]
struct OperatorInput {
    _directory: OwnedFd,
    directory_metadata: Stat,
    files: BTreeMap<&'static str, Vec<u8>>,
    _identity: kapsel::ValidatedServiceOperatorInputs,
    path: String,
    bootstrap: BootstrapAuthority,
}

#[cfg(not(target_os = "linux"))]
struct OperatorInput;

#[cfg(target_os = "linux")]
struct InstallerLock {
    _descriptor: OwnedFd,
}

#[cfg(not(target_os = "linux"))]
struct InstallerLock;

struct BootstrapAuthority {
    server: String,
    certificate_authority: Vec<u8>,
    _credential: BootstrapCredential,
}

enum BootstrapCredential {
    Token {
        _token: String,
    },
    ClientCertificate {
        _certificate: Vec<u8>,
        _key: Vec<u8>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapKubeconfig {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    clusters: Vec<NamedCluster>,
    users: Vec<NamedUser>,
    contexts: Vec<NamedContext>,
    #[serde(
        rename = "current-context",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    current_context: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedCluster {
    name: String,
    cluster: Cluster,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedUser {
    name: String,
    user: User,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    token: Option<String>,
    #[serde(
        rename = "client-certificate-data",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    client_certificate_data: Option<String>,
    #[serde(
        rename = "client-key-data",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    client_key_data: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedContext {
    name: String,
    context: Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    cluster: String,
    user: String,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    namespace: Option<String>,
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[cfg(target_os = "linux")]
const OPERATOR_FILES: &[(&str, usize)] = &[
    ("authorization.pub", 32),
    ("bootstrap-kubeconfig.yaml", 64 * 1024),
    ("grant.bin", 4 * 1024),
    ("receipt.seed", 32),
    ("receipt.trust", 1024),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    Install,
    RefreshCredential,
    Uninstall,
}

struct Invocation {
    action: Action,
    operator_input: PathBuf,
    kube_context: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallerTransaction {
    action: Action,
    bootstrap_kubeconfig_initial_sha256: String,
    bootstrap_kubeconfig_sha256: String,
    cluster: TransactionCluster,
    credential_expiration: Option<String>,
    host_resources: Vec<serde_json::Value>,
    input_directory: TransactionInputDirectory,
    installer_sha256: String,
    kube_context: String,
    kubernetes_resources: Vec<serde_json::Value>,
    operator_inputs: TransactionOperatorInputs,
    pending: Option<serde_json::Value>,
    phase: TransactionPhase,
    schema: u64,
    transaction_id: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionCluster {
    ca_sha256: String,
    server: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionInputDirectory {
    device: u64,
    inode: u64,
    mode: u32,
    path: String,
    uid: u32,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionOperatorInputs {
    #[serde(rename = "authorization.pub")]
    authorization_pub: String,
    #[serde(rename = "grant.bin")]
    grant_bin: String,
    #[serde(rename = "receipt.seed")]
    receipt_seed: String,
    #[serde(rename = "receipt.trust")]
    receipt_trust: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Installed,
    Installing,
    PartialUninstall,
    Prepared,
    Refreshing,
    RolledBack,
    RollingBack,
    Uninstalled,
    UninstallingKubernetes,
    UninstallingLocal,
    UninstallingStatic,
}

#[allow(
    dead_code,
    reason = "owner variants are constructed only by an opt-in release bundle"
)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum OwnerClass {
    Evidence,
    Root,
}

struct ExpectedAsset {
    name: &'static str,
    destination: Option<&'static str>,
    mode: Option<u32>,
    owner: OwnerClass,
}

struct Asset {
    bytes: &'static [u8],
    length: usize,
    sha256: &'static str,
}

mod bundle {
    include!(concat!(env!("OUT_DIR"), "/bundle.rs"));
}

#[derive(Clone, Copy, Debug)]
enum InstallerError {
    BundleUnavailable,
    ImplementationIncomplete,
    InvalidArguments,
    InvalidBundle,
    InvalidOperatorInput,
    InstallerLockFailure,
    TransactionFailure,
}

impl InstallerError {
    const fn class(self) -> &'static str {
        match self {
            Self::BundleUnavailable => "bundle_unavailable",
            Self::ImplementationIncomplete => "implementation_incomplete",
            Self::InvalidArguments => "invalid_arguments",
            Self::InvalidBundle => "invalid_bundle",
            Self::InvalidOperatorInput => "invalid_operator_input",
            Self::InstallerLockFailure => "installer_lock_failure",
            Self::TransactionFailure => "transaction_failure",
        }
    }
}

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "Kapsel installer failure: {}",
                error.class()
            );
            ExitCode::FAILURE
        },
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), InstallerError> {
    let invocation = parse_arguments(arguments)?;
    validate_embedded_bundle()?;
    let operator_input =
        validate_operator_input(&invocation.operator_input, &invocation.kube_context)?;
    let _lock = acquire_installer_lock()?;
    if invocation.action == Action::Install {
        let _initial_transaction = prepare_initial_transaction(&invocation, &operator_input)?;
    }

    let _ = invocation.kube_context;
    Err(InstallerError::ImplementationIncomplete)
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Invocation, InstallerError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next().ok_or(InstallerError::InvalidArguments)?;
    let action = match arguments
        .next()
        .as_deref()
        .and_then(OsStr::to_str)
        .ok_or(InstallerError::InvalidArguments)?
    {
        "install" => Action::Install,
        "refresh-credential" => Action::RefreshCredential,
        "uninstall" => Action::Uninstall,
        _ => return Err(InstallerError::InvalidArguments),
    };
    let mut operator_input = None;
    let mut kube_context = None;
    while let Some(option) = arguments.next() {
        let value = arguments.next().ok_or(InstallerError::InvalidArguments)?;
        match option.to_str() {
            Some("--operator-input") if operator_input.is_none() => {
                operator_input = Some(value);
            },
            Some("--kube-context") if kube_context.is_none() => {
                kube_context = Some(value);
            },
            _ => return Err(InstallerError::InvalidArguments),
        }
    }

    let operator_input = PathBuf::from(operator_input.ok_or(InstallerError::InvalidArguments)?);
    if !operator_input.is_absolute() || operator_input.to_str().is_none() {
        return Err(InstallerError::InvalidArguments);
    }
    let kube_context = kube_context
        .ok_or(InstallerError::InvalidArguments)?
        .into_string()
        .map_err(|_| InstallerError::InvalidArguments)?;
    if !valid_kubernetes_name(&kube_context) {
        return Err(InstallerError::InvalidArguments);
    }
    Ok(Invocation {
        action,
        operator_input,
        kube_context,
    })
}

fn valid_kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes
                    .first()
                    .is_some_and(|byte| is_lowercase_alphanumeric(*byte))
                && bytes
                    .last()
                    .is_some_and(|byte| is_lowercase_alphanumeric(*byte))
                && bytes
                    .iter()
                    .copied()
                    .all(|byte| is_lowercase_alphanumeric(byte) || byte == b'-')
        })
}

fn is_lowercase_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn validate_embedded_bundle() -> Result<(), InstallerError> {
    if !bundle::AVAILABLE {
        return Err(InstallerError::BundleUnavailable);
    }
    if bundle::ASSETS.len() != bundle::EXPECTED.len() || bundle::EXPECTED.is_empty() {
        return Err(InstallerError::InvalidBundle);
    }
    let mut total = 0_usize;
    for (expected, asset) in bundle::EXPECTED.iter().zip(bundle::ASSETS) {
        let disposition_is_valid = match expected.owner {
            OwnerClass::Evidence => expected.destination.is_none() && expected.mode.is_none(),
            OwnerClass::Root => {
                expected
                    .destination
                    .is_some_and(|path| path.starts_with('/') && path.len() > 1)
                    && expected.mode.is_some()
            },
        };
        total = total
            .checked_add(asset.length)
            .ok_or(InstallerError::InvalidBundle)?;
        if expected.name.is_empty()
            || asset.bytes.len() != asset.length
            || hex_digest(asset.bytes) != asset.sha256
            || !disposition_is_valid
        {
            return Err(InstallerError::InvalidBundle);
        }
    }
    if total > bundle::BUNDLE_BYTES_MAX {
        return Err(InstallerError::InvalidBundle);
    }
    Ok(())
}

fn parse_bootstrap_kubeconfig(
    bytes: &[u8],
    selected_context: &str,
) -> Result<BootstrapAuthority, InstallerError> {
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_events: 512,
            max_aliases: 0,
            max_anchors: 0,
            max_depth: 16,
            max_documents: 1,
            max_nodes: 128,
            max_total_scalar_bytes: 64 * 1024,
            max_total_comment_bytes: 64 * 1024,
            max_merge_keys: 0,
        },
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        strict_booleans: true,
        no_schema: true,
        with_snippet: false,
    };
    let mut configs: Vec<BootstrapKubeconfig> =
        serde_saphyr::from_slice_multiple_with_options(bytes, options)
            .map_err(|_| InstallerError::InvalidOperatorInput)?;
    if configs.len() != 1 {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let config = configs.pop().ok_or(InstallerError::InvalidOperatorInput)?;
    if config.api_version != "v1"
        || config.kind != "Config"
        || config.clusters.len() != 1
        || config.users.len() != 1
        || config.contexts.len() != 1
        || config
            .current_context
            .as_deref()
            .is_some_and(|current| current != selected_context)
    {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let cluster = config
        .clusters
        .into_iter()
        .next()
        .ok_or(InstallerError::InvalidOperatorInput)?;
    let user = config
        .users
        .into_iter()
        .next()
        .ok_or(InstallerError::InvalidOperatorInput)?;
    let context = config
        .contexts
        .into_iter()
        .next()
        .ok_or(InstallerError::InvalidOperatorInput)?;
    if context.name != selected_context
        || context.context.cluster != cluster.name
        || context.context.user != user.name
        || context
            .context
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != "demo")
        || cluster.name.is_empty()
        || user.name.is_empty()
    {
        return Err(InstallerError::InvalidOperatorInput);
    }

    let server = validate_server(cluster.cluster.server)?;
    let certificate_authority = decode_inline_data(&cluster.cluster.certificate_authority_data)?;
    let credential = match (
        user.user.token,
        user.user.client_certificate_data,
        user.user.client_key_data,
    ) {
        (Some(token), None, None)
            if !token.is_empty() && token.len() <= 16 * 1024 && token.is_ascii() =>
        {
            BootstrapCredential::Token { _token: token }
        },
        (None, Some(certificate), Some(key)) => BootstrapCredential::ClientCertificate {
            _certificate: decode_inline_data(&certificate)?,
            _key: decode_inline_data(&key)?,
        },
        _ => return Err(InstallerError::InvalidOperatorInput),
    };
    Ok(BootstrapAuthority {
        server,
        certificate_authority,
        _credential: credential,
    })
}

fn validate_server(server: String) -> Result<String, InstallerError> {
    let uri = server
        .parse::<Uri>()
        .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let authority = uri
        .authority()
        .ok_or(InstallerError::InvalidOperatorInput)?;
    if server.contains('#')
        || uri.scheme() != Some(&Scheme::HTTPS)
        || authority.host().is_empty()
        || authority.as_str().contains('@')
        || !valid_authority_port(authority)
        || uri
            .path_and_query()
            .and_then(|value| value.query())
            .is_some()
    {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(server)
}

fn valid_authority_port(authority: &http::uri::Authority) -> bool {
    let suffix = &authority.as_str()[authority.host().len()..];
    suffix.is_empty()
        || suffix.strip_prefix(':').is_some_and(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        })
}

fn decode_inline_data(encoded: &str) -> Result<Vec<u8>, InstallerError> {
    const DECODED_MAX: usize = 16 * 1024;
    const ENCODED_MAX: usize = DECODED_MAX.div_ceil(3) * 4;

    if encoded.is_empty() || encoded.len() > ENCODED_MAX || !encoded.is_ascii() {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let mut decoded = [0_u8; DECODED_MAX];
    let length = BASE64
        .decode_slice(encoded, &mut decoded)
        .map_err(|_| InstallerError::InvalidOperatorInput)?;
    if length == 0 {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(decoded[..length].to_vec())
}

const TRANSACTION_BYTES_MAX: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const INSTALLER_BYTES_MAX: usize = 64 * 1024 * 1024;

#[cfg(not(target_os = "linux"))]
fn prepare_initial_transaction(
    _: &Invocation,
    _: &OperatorInput,
) -> Result<Vec<u8>, InstallerError> {
    Err(InstallerError::TransactionFailure)
}

#[cfg(target_os = "linux")]
fn prepare_initial_transaction(
    invocation: &Invocation,
    input: &OperatorInput,
) -> Result<Vec<u8>, InstallerError> {
    let bootstrap_digest = digest_named_input(input, "bootstrap-kubeconfig.yaml")?;
    let transaction = InstallerTransaction {
        action: Action::Install,
        bootstrap_kubeconfig_initial_sha256: bootstrap_digest.clone(),
        bootstrap_kubeconfig_sha256: bootstrap_digest,
        cluster: TransactionCluster {
            ca_sha256: hex_digest(&input.bootstrap.certificate_authority),
            server: input.bootstrap.server.clone(),
        },
        credential_expiration: None,
        host_resources: Vec::new(),
        input_directory: TransactionInputDirectory {
            device: input.directory_metadata.st_dev,
            inode: input.directory_metadata.st_ino,
            mode: input.directory_metadata.st_mode & 0o7777,
            path: input.path.clone(),
            uid: input.directory_metadata.st_uid,
        },
        installer_sha256: digest_running_installer()?,
        kube_context: invocation.kube_context.clone(),
        kubernetes_resources: Vec::new(),
        operator_inputs: TransactionOperatorInputs {
            authorization_pub: digest_named_input(input, "authorization.pub")?,
            grant_bin: digest_named_input(input, "grant.bin")?,
            receipt_seed: digest_named_input(input, "receipt.seed")?,
            receipt_trust: digest_named_input(input, "receipt.trust")?,
        },
        pending: None,
        phase: TransactionPhase::Prepared,
        schema: 1,
        transaction_id: new_transaction_id()?,
    };
    let bytes = encode_transaction(&transaction)?;
    let _ = decode_transaction(&bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn digest_named_input(input: &OperatorInput, name: &str) -> Result<String, InstallerError> {
    input
        .files
        .get(name)
        .map(|bytes| hex_digest(bytes))
        .ok_or(InstallerError::TransactionFailure)
}

fn encode_transaction(transaction: &InstallerTransaction) -> Result<Vec<u8>, InstallerError> {
    validate_initial_transaction(transaction)?;
    let bytes = serde_json::to_vec(transaction).map_err(|_| InstallerError::TransactionFailure)?;
    if bytes.len() > TRANSACTION_BYTES_MAX {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(bytes)
}

fn decode_transaction(bytes: &[u8]) -> Result<InstallerTransaction, InstallerError> {
    if bytes.len() > TRANSACTION_BYTES_MAX {
        return Err(InstallerError::TransactionFailure);
    }
    let transaction = serde_json::from_slice::<InstallerTransaction>(bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    validate_initial_transaction(&transaction)?;
    if serde_json::to_vec(&transaction).map_err(|_| InstallerError::TransactionFailure)? != bytes {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(transaction)
}

fn validate_initial_transaction(transaction: &InstallerTransaction) -> Result<(), InstallerError> {
    let digests = [
        transaction.bootstrap_kubeconfig_initial_sha256.as_str(),
        transaction.bootstrap_kubeconfig_sha256.as_str(),
        transaction.cluster.ca_sha256.as_str(),
        transaction.installer_sha256.as_str(),
        transaction.operator_inputs.authorization_pub.as_str(),
        transaction.operator_inputs.grant_bin.as_str(),
        transaction.operator_inputs.receipt_seed.as_str(),
        transaction.operator_inputs.receipt_trust.as_str(),
        transaction.transaction_id.as_str(),
    ];
    if transaction.action != Action::Install
        || transaction.phase != TransactionPhase::Prepared
        || transaction.schema != 1
        || transaction.bootstrap_kubeconfig_initial_sha256
            != transaction.bootstrap_kubeconfig_sha256
        || transaction.credential_expiration.is_some()
        || !transaction.host_resources.is_empty()
        || !transaction.kubernetes_resources.is_empty()
        || transaction.pending.is_some()
        || transaction.input_directory.uid != 0
        || transaction.input_directory.mode != 0o700
        || !valid_transaction_path(&transaction.input_directory.path)
        || !valid_kubernetes_name(&transaction.kube_context)
        || validate_server(transaction.cluster.server.clone()).is_err()
        || digests.into_iter().any(|digest| !valid_digest(digest))
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_transaction_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(target_os = "linux")]
fn new_transaction_id() -> Result<String, InstallerError> {
    let mut bytes = [0_u8; 32];
    let mut offset = 0;
    while offset < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[offset..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => return Err(InstallerError::TransactionFailure),
            Ok(read) => offset += read,
            Err(rustix::io::Errno::INTR) => {},
            Err(_) => return Err(InstallerError::TransactionFailure),
        }
    }
    Ok(hex_bytes(&bytes))
}

#[cfg(target_os = "linux")]
fn digest_running_installer() -> Result<String, InstallerError> {
    let descriptor = rfs::openat(
        CWD,
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::TransactionFailure)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_size <= 0
        || usize::try_from(before.st_size).map_or(true, |length| length > INSTALLER_BYTES_MAX)
    {
        return Err(InstallerError::TransactionFailure);
    }
    let capacity =
        usize::try_from(before.st_size).map_err(|_| InstallerError::TransactionFailure)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(u64::try_from(INSTALLER_BYTES_MAX).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    let after = rfs::fstat(&file).map_err(|_| InstallerError::TransactionFailure)?;
    if bytes.is_empty()
        || bytes.len() > INSTALLER_BYTES_MAX
        || !stable_file(&before, &after, bytes.len())
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(hex_digest(&bytes))
}

#[cfg(not(target_os = "linux"))]
fn validate_operator_input(_: &std::path::Path, _: &str) -> Result<OperatorInput, InstallerError> {
    Err(InstallerError::InvalidOperatorInput)
}

#[cfg(not(target_os = "linux"))]
fn acquire_installer_lock() -> Result<InstallerLock, InstallerError> {
    Err(InstallerError::InstallerLockFailure)
}

#[cfg(target_os = "linux")]
fn acquire_installer_lock() -> Result<InstallerLock, InstallerError> {
    let root = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InstallerLockFailure)?;
    let run = open_lock_directory(&root, "run")?;
    let run_metadata = rfs::fstat(&run).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !root_owned_directory(&run_metadata) || run_metadata.st_mode & 0o022 != 0 {
        return Err(InstallerError::InstallerLockFailure);
    }
    let lock_directory = open_lock_directory(&run, "lock")?;
    let lock_directory_metadata =
        rfs::fstat(&lock_directory).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !root_owned_directory(&lock_directory_metadata)
        || lock_directory_metadata.st_mode & 0o022 != 0
            && lock_directory_metadata.st_mode & 0o1000 == 0
    {
        return Err(InstallerError::InstallerLockFailure);
    }

    let create_flags = OFlags::RDWR
        | OFlags::CREATE
        | OFlags::EXCL
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC;
    let descriptor = match rfs::openat(
        &lock_directory,
        "kapsel-installer.lock",
        create_flags,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => {
            rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
                .map_err(|_| InstallerError::InstallerLockFailure)?;
            descriptor
        },
        Err(rustix::io::Errno::EXIST) => rfs::openat(
            &lock_directory,
            "kapsel-installer.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| InstallerError::InstallerLockFailure)?,
        Err(_) => return Err(InstallerError::InstallerLockFailure),
    };
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !valid_installer_lock(&before) {
        return Err(InstallerError::InstallerLockFailure);
    }
    rfs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| InstallerError::InstallerLockFailure)?;
    let after = rfs::fstat(&descriptor).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !valid_installer_lock(&after) || !stable_lock(&before, &after) {
        return Err(InstallerError::InstallerLockFailure);
    }
    Ok(InstallerLock {
        _descriptor: descriptor,
    })
}

#[cfg(target_os = "linux")]
fn open_lock_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, InstallerError> {
    rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InstallerLockFailure)
}

#[cfg(target_os = "linux")]
fn root_owned_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_dir() && metadata.st_uid == 0
}

#[cfg(target_os = "linux")]
fn valid_installer_lock(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_file()
        && metadata.st_uid == 0
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_nlink == 1
}

#[cfg(target_os = "linux")]
fn stable_lock(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
}

#[cfg(target_os = "linux")]
fn validate_operator_input(
    path: &Path,
    kube_context: &str,
) -> Result<OperatorInput, InstallerError> {
    let directory = open_absolute_directory_without_symlinks(path)?;
    let before = rfs::fstat(&directory).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !valid_operator_directory(&before) {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let expected = OPERATOR_FILES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if directory_names(&directory)? != expected {
        return Err(InstallerError::InvalidOperatorInput);
    }

    let mut inputs = BTreeMap::new();
    for (name, maximum) in OPERATOR_FILES {
        inputs.insert(*name, read_operator_file(&directory, name, *maximum)?);
    }
    let after = rfs::fstat(&directory).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !stable_directory(&before, &after) {
        return Err(InstallerError::InvalidOperatorInput);
    }

    let authorization_public_key = exact_32(&inputs, "authorization.pub")?;
    let receipt_signing_seed = exact_32(&inputs, "receipt.seed")?;
    let identity = kapsel::validate_service_operator_inputs(
        inputs
            .get("grant.bin")
            .ok_or(InstallerError::InvalidOperatorInput)?,
        &authorization_public_key,
        &receipt_signing_seed,
        inputs
            .get("receipt.trust")
            .ok_or(InstallerError::InvalidOperatorInput)?,
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let bootstrap = parse_bootstrap_kubeconfig(
        inputs
            .get("bootstrap-kubeconfig.yaml")
            .ok_or(InstallerError::InvalidOperatorInput)?,
        kube_context,
    )?;
    Ok(OperatorInput {
        _directory: directory,
        directory_metadata: after,
        files: inputs,
        _identity: identity,
        path: path
            .to_str()
            .ok_or(InstallerError::InvalidOperatorInput)?
            .to_owned(),
        bootstrap,
    })
}

#[cfg(target_os = "linux")]
fn open_absolute_directory_without_symlinks(path: &Path) -> Result<OwnedFd, InstallerError> {
    let mut directory = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                directory = rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| InstallerError::InvalidOperatorInput)?;
                saw_component = true;
            },
            _ => return Err(InstallerError::InvalidOperatorInput),
        }
    }
    if !saw_component {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn valid_operator_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_dir()
        && metadata.st_uid == 0
        && metadata.st_mode & 0o7777 == 0o700
}

#[cfg(target_os = "linux")]
fn directory_names(directory: &OwnedFd) -> Result<BTreeSet<String>, InstallerError> {
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let mut entries = RawDir::new(directory, &mut buffer);
    let mut names = BTreeSet::new();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| InstallerError::InvalidOperatorInput)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| InstallerError::InvalidOperatorInput)?;
        if !names.insert(name.to_owned()) {
            return Err(InstallerError::InvalidOperatorInput);
        }
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn read_operator_file(
    directory: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, InstallerError> {
    let descriptor = rfs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != 0
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
        || before.st_size < 0
        || usize::try_from(before.st_size).map_or(true, |length| length > maximum)
    {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let capacity =
        usize::try_from(before.st_size).map_err(|_| InstallerError::InvalidOperatorInput)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(u64::try_from(maximum).map_err(|_| InstallerError::InvalidOperatorInput)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let after = rfs::fstat(&file).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if bytes.len() > maximum || !stable_file(&before, &after, bytes.len()) {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn exact_32(inputs: &BTreeMap<&str, Vec<u8>>, name: &str) -> Result<[u8; 32], InstallerError> {
    inputs
        .get(name)
        .ok_or(InstallerError::InvalidOperatorInput)?
        .as_slice()
        .try_into()
        .map_err(|_| InstallerError::InvalidOperatorInput)
}

#[cfg(target_os = "linux")]
fn stable_directory(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(target_os = "linux")]
fn stable_file(before: &Stat, after: &Stat, length: usize) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
        && usize::try_from(after.st_size) == Ok(length)
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_CONFIG: &str = concat!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n",
        "    server: https://127.0.0.1:6443\n    certificate-authority-data: Y2E=\n",
        "users:\n- name: fixture\n  user:\n    token: fixture-token\n",
        "contexts:\n- name: nonprod\n  context:\n    cluster: fixture\n    user: fixture\n",
        "    namespace: demo\ncurrent-context: nonprod\n",
    );

    fn initial_transaction() -> InstallerTransaction {
        InstallerTransaction {
            action: Action::Install,
            bootstrap_kubeconfig_initial_sha256: "11".repeat(32),
            bootstrap_kubeconfig_sha256: "11".repeat(32),
            cluster: TransactionCluster {
                ca_sha256: "22".repeat(32),
                server: String::from("https://127.0.0.1:6443"),
            },
            credential_expiration: None,
            host_resources: Vec::new(),
            input_directory: TransactionInputDirectory {
                device: 1,
                inode: 2,
                mode: 0o700,
                path: String::from("/secure/kapsel"),
                uid: 0,
            },
            installer_sha256: "33".repeat(32),
            kube_context: String::from("nonprod"),
            kubernetes_resources: Vec::new(),
            operator_inputs: TransactionOperatorInputs {
                authorization_pub: "44".repeat(32),
                grant_bin: "55".repeat(32),
                receipt_seed: "66".repeat(32),
                receipt_trust: "77".repeat(32),
            },
            pending: None,
            phase: TransactionPhase::Prepared,
            schema: 1,
            transaction_id: "88".repeat(32),
        }
    }

    #[test]
    fn initial_transaction_has_exact_canonical_schema_one_bytes() {
        let h1 = "11".repeat(32);
        let h2 = "22".repeat(32);
        let h3 = "33".repeat(32);
        let h4 = "44".repeat(32);
        let h5 = "55".repeat(32);
        let h6 = "66".repeat(32);
        let h7 = "77".repeat(32);
        let h8 = "88".repeat(32);
        let expected = [
            r#"{"action":"install","bootstrap_kubeconfig_initial_sha256":""#,
            &h1,
            r#"","bootstrap_kubeconfig_sha256":""#,
            &h1,
            r#"","cluster":{"ca_sha256":""#,
            &h2,
            r#"","server":"https://127.0.0.1:6443"},"credential_expiration":null,"#,
            r#""host_resources":[],"input_directory":{"device":1,"inode":2,"mode":448,"#,
            r#""path":"/secure/kapsel","uid":0},"installer_sha256":""#,
            &h3,
            r#"","kube_context":"nonprod","kubernetes_resources":[],"operator_inputs":{"#,
            r#""authorization.pub":""#,
            &h4,
            r#"","grant.bin":""#,
            &h5,
            r#"","receipt.seed":""#,
            &h6,
            r#"","receipt.trust":""#,
            &h7,
            r#""},"pending":null,"phase":"prepared","schema":1,"transaction_id":""#,
            &h8,
            r#""}"#,
        ]
        .concat();
        let encoded = encode_transaction(&initial_transaction()).expect("fixture must encode");
        assert_eq!(encoded, expected.as_bytes());
        assert_eq!(
            decode_transaction(&encoded).expect("canonical bytes must decode"),
            initial_transaction()
        );
        for secret in [
            "fixture-token",
            "private-key",
            "receipt-seed-bytes",
            "grant-bytes",
        ] {
            assert!(!expected.contains(secret));
        }
    }

    #[test]
    fn initial_transaction_rejects_noncanonical_hostile_and_nonprepared_records() {
        let canonical = String::from_utf8(
            encode_transaction(&initial_transaction()).expect("fixture must encode"),
        )
        .expect("fixture must be UTF-8");
        let reordered = format!(
            "{{\"schema\":1,{}",
            canonical[1..].replacen(",\"schema\":1", "", 1)
        );
        let cases = [
            format!(" {canonical}"),
            format!("{canonical}\n"),
            canonical.replacen("\"action\":\"install\"", "\"action\":\"uninstall\"", 1),
            canonical.replacen("\"phase\":\"prepared\"", "\"phase\":\"installed\"", 1),
            canonical.replacen("\"action\":", "\"unknown\":null,\"action\":", 1),
            canonical.replacen(
                "\"action\":\"install\"",
                "\"action\":\"install\",\"action\":\"install\"",
                1,
            ),
            canonical.replacen(&"33".repeat(32), &"AA".repeat(32), 1),
            canonical.replacen("https://", r"https:\/\/", 1),
            canonical.replacen("\"host_resources\":[]", "\"host_resources\":[{}]", 1),
            reordered,
        ];
        for (index, bytes) in cases.into_iter().enumerate() {
            assert!(
                matches!(
                    decode_transaction(bytes.as_bytes()),
                    Err(InstallerError::TransactionFailure)
                ),
                "hostile transaction case {index} was accepted"
            );
        }
        assert!(matches!(
            decode_transaction(&vec![b' '; TRANSACTION_BYTES_MAX + 1]),
            Err(InstallerError::TransactionFailure)
        ));
        for (action, expected) in [
            (Action::Install, "\"install\""),
            (Action::RefreshCredential, "\"refresh-credential\""),
            (Action::Uninstall, "\"uninstall\""),
        ] {
            assert_eq!(
                serde_json::to_string(&action).expect("action must encode"),
                expected
            );
        }
    }

    #[test]
    fn bootstrap_kubeconfig_accepts_only_inline_token_or_certificate_authority() {
        assert!(parse_bootstrap_kubeconfig(TOKEN_CONFIG.as_bytes(), "nonprod").is_ok());
        let ipv6 = TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://[::1]:6443");
        assert!(parse_bootstrap_kubeconfig(ipv6.as_bytes(), "nonprod").is_ok());
        let optional_fields_absent = TOKEN_CONFIG
            .replace("    namespace: demo\n", "")
            .replace("current-context: nonprod\n", "");
        assert!(parse_bootstrap_kubeconfig(optional_fields_absent.as_bytes(), "nonprod").is_ok());
        let certificate = TOKEN_CONFIG.replace(
            "    token: fixture-token\n",
            "    client-certificate-data: Y2VydA==\n    client-key-data: a2V5\n",
        );
        assert!(parse_bootstrap_kubeconfig(certificate.as_bytes(), "nonprod").is_ok());
    }

    #[test]
    fn bootstrap_kubeconfig_rejects_ambient_external_and_ambiguous_authority() {
        let oversized = "A".repeat(21_848);
        let cases = [
            TOKEN_CONFIG.replace(
                "    server: https://127.0.0.1:6443",
                "    server: &server https://127.0.0.1:6443",
            ),
            format!("{TOKEN_CONFIG}unknown: value\n"),
            format!("{TOKEN_CONFIG}current-context: nonprod\n"),
            TOKEN_CONFIG.replace(
                "certificate-authority-data: Y2E=",
                "certificate-authority: /ca",
            ),
            TOKEN_CONFIG.replace(
                "    certificate-authority-data: Y2E=",
                "    certificate-authority-data: Y2E=\n    insecure-skip-tls-verify: true",
            ),
            TOKEN_CONFIG.replace(
                "    certificate-authority-data: Y2E=",
                "    certificate-authority-data: Y2E=\n    proxy-url: https://proxy",
            ),
            TOKEN_CONFIG.replace("    token: fixture-token", "    exec: {}"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "http://127.0.0.1:6443"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://user@127.0.0.1:6443"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:6443?query"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:6443#fragment"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:bad"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:+443"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://[::1]:+443"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:"),
            TOKEN_CONFIG.replace("https://127.0.0.1:6443", "https://127.0.0.1:65536"),
            TOKEN_CONFIG.replace("    namespace: demo", "    namespace: other"),
            TOKEN_CONFIG.replace("    namespace: demo", "    namespace: null"),
            TOKEN_CONFIG.replace("current-context: nonprod", "current-context: null"),
            TOKEN_CONFIG.replace("    token: fixture-token", "    token: null"),
            TOKEN_CONFIG.replace("    token: fixture-token", "    token: true"),
            TOKEN_CONFIG.replace(
                "users:\n",
                concat!(
                    "- name: second\n  cluster:\n",
                    "    server: https://127.0.0.1:6443\n",
                    "    certificate-authority-data: Y2E=\nusers:\n"
                ),
            ),
            format!("{TOKEN_CONFIG}---\n{TOKEN_CONFIG}"),
            TOKEN_CONFIG.replace(
                "    token: fixture-token",
                concat!(
                    "    token: fixture-token\n",
                    "    client-certificate-data: Y2VydA==\n",
                    "    client-key-data: a2V5"
                ),
            ),
            TOKEN_CONFIG.replace("Y2E=", &oversized),
        ];
        for (index, hostile) in cases.into_iter().enumerate() {
            assert!(
                matches!(
                    parse_bootstrap_kubeconfig(hostile.as_bytes(), "nonprod"),
                    Err(InstallerError::InvalidOperatorInput)
                ),
                "hostile case {index} was accepted"
            );
        }
        assert!(matches!(
            parse_bootstrap_kubeconfig(TOKEN_CONFIG.as_bytes(), "other"),
            Err(InstallerError::InvalidOperatorInput)
        ));
    }
}
