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
use rustix::fs::{self as rfs, FileType, Mode, OFlags, RawDir, Stat, CWD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "linux")]
struct OperatorInput {
    _directory: OwnedFd,
    _files: BTreeMap<&'static str, Vec<u8>>,
    _identity: kapsel::ValidatedServiceOperatorInputs,
    _bootstrap: BootstrapAuthority,
}

#[cfg(not(target_os = "linux"))]
struct OperatorInput;

struct BootstrapAuthority {
    _server: String,
    _certificate_authority: Vec<u8>,
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

#[derive(Clone, Copy)]
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

#[derive(Clone, Copy)]
enum InstallerError {
    BundleUnavailable,
    ImplementationIncomplete,
    InvalidArguments,
    InvalidBundle,
    InvalidOperatorInput,
}

impl InstallerError {
    const fn class(self) -> &'static str {
        match self {
            Self::BundleUnavailable => "bundle_unavailable",
            Self::ImplementationIncomplete => "implementation_incomplete",
            Self::InvalidArguments => "invalid_arguments",
            Self::InvalidBundle => "invalid_bundle",
            Self::InvalidOperatorInput => "invalid_operator_input",
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
    let _operator_input =
        validate_operator_input(&invocation.operator_input, &invocation.kube_context)?;

    let _ = (invocation.action, invocation.kube_context);
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
        _server: server,
        _certificate_authority: certificate_authority,
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

#[cfg(not(target_os = "linux"))]
fn validate_operator_input(_: &std::path::Path, _: &str) -> Result<OperatorInput, InstallerError> {
    Err(InstallerError::InvalidOperatorInput)
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
        _files: inputs,
        _identity: identity,
        _bootstrap: bootstrap,
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
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
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
