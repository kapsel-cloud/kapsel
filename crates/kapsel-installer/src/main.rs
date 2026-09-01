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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use http::{uri::Scheme, Uri};
use k8s_openapi::api::apps::v1::Deployment;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "linux")]
mod linux;

struct BootstrapAuthority {
    server: String,
    certificate_authority: Vec<u8>,
    selected_context: String,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallerTransaction {
    action: Action,
    bootstrap_kubeconfig_initial_sha256: String,
    bootstrap_kubeconfig_sha256: String,
    cluster: TransactionCluster,
    credential_expiration: Option<String>,
    host_resources: Vec<HostResource>,
    input_directory: TransactionInputDirectory,
    installer_sha256: String,
    kube_context: String,
    kubernetes_resources: Vec<serde_json::Value>,
    operator_inputs: TransactionOperatorInputs,
    pending: Option<PendingAction>,
    phase: TransactionPhase,
    schema: u64,
    transaction_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionCluster {
    ca_sha256: String,
    server: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionInputDirectory {
    device: u64,
    inode: u64,
    mode: u32,
    path: String,
    uid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HostResource {
    gid: u32,
    kind: HostResourceKind,
    name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HostResourceKind {
    Group,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum PendingAction {
    CreateGroup {
        gid: u32,
        name: String,
        transaction_id: String,
    },
    RemoveGroup {
        group: HostResource,
    },
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
    HostPreflightFailure,
    HostMutationFailure,
    KubernetesPreflightFailure,
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
            Self::HostPreflightFailure => "host_preflight_failure",
            Self::HostMutationFailure => "host_mutation_failure",
            Self::KubernetesPreflightFailure => "kubernetes_preflight_failure",
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

#[cfg(target_os = "linux")]
fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), InstallerError> {
    linux::run(arguments)
}

#[cfg(not(target_os = "linux"))]
fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), InstallerError> {
    let _ = parse_arguments(arguments)?;
    validate_embedded_bundle()?;
    Err(InstallerError::ImplementationIncomplete)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallPhase {
    Prepared,
    Installing,
    RollingBack,
    RolledBack,
}

fn classify_install_phase(phase: TransactionPhase) -> Result<InstallPhase, InstallerError> {
    match phase {
        TransactionPhase::Prepared => Ok(InstallPhase::Prepared),
        TransactionPhase::Installing => Ok(InstallPhase::Installing),
        TransactionPhase::RollingBack => Ok(InstallPhase::RollingBack),
        TransactionPhase::RolledBack => Ok(InstallPhase::RolledBack),
        _ => Err(InstallerError::TransactionFailure),
    }
}

fn validate_fixed_authority(
    identity: &kapsel_authority::ValidatedServiceOperatorInputs,
) -> Result<(), InstallerError> {
    let authorization = &identity.authorization;
    if authorization.namespace == "demo"
        && authorization.deployment == "agent-api"
        && authorization.container == "api"
    {
        Ok(())
    } else {
        Err(InstallerError::InvalidOperatorInput)
    }
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
        selected_context: selected_context.to_owned(),
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
fn matches_stable_identity(
    transaction: &InstallerTransaction,
    expected: &InstallerTransaction,
) -> bool {
    transaction.cluster == expected.cluster
        && transaction.input_directory == expected.input_directory
        && transaction.installer_sha256 == expected.installer_sha256
        && transaction.kube_context == expected.kube_context
        && transaction.operator_inputs == expected.operator_inputs
        && transaction.schema == expected.schema
}

fn encode_transaction(transaction: &InstallerTransaction) -> Result<Vec<u8>, InstallerError> {
    validate_transaction(transaction)?;
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
    validate_transaction(&transaction)?;
    if serde_json::to_vec(&transaction).map_err(|_| InstallerError::TransactionFailure)? != bytes {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(transaction)
}

fn validate_initial_transaction(transaction: &InstallerTransaction) -> Result<(), InstallerError> {
    validate_transaction(transaction)?;
    if transaction.action != Action::Install || transaction.phase != TransactionPhase::Prepared {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(())
}

fn validate_transaction(transaction: &InstallerTransaction) -> Result<(), InstallerError> {
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
    if transaction.schema != 1
        || transaction.credential_expiration.is_some()
        || !transaction.kubernetes_resources.is_empty()
        || !valid_action_phase(transaction.action, transaction.phase)
        || !valid_transaction_state(transaction)
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

fn valid_transaction_state(transaction: &InstallerTransaction) -> bool {
    let groups = transaction.host_resources.as_slice();
    let pending = transaction.pending.as_ref();
    let valid_group = |resource: &HostResource, name: &str| {
        resource.kind == HostResourceKind::Group
            && resource.name == name
            && (101..=999).contains(&resource.gid)
    };
    let valid_groups = |resources: &[HostResource]| match resources {
        [] => true,
        [first] => valid_group(first, "kapsel"),
        [first, second] => {
            valid_group(first, "kapsel")
                && valid_group(second, "kapsel-service-callers")
                && first.gid != second.gid
        },
        _ => false,
    };
    let valid_create = |gid: u32, name: &str, transaction_id: &str| {
        let expected_name = match groups {
            [] => "kapsel",
            [_] => "kapsel-service-callers",
            _ => return false,
        };
        name == expected_name
            && (101..=999).contains(&gid)
            && groups.iter().all(|resource| resource.gid != gid)
            && transaction_id == transaction.transaction_id
    };

    match transaction.phase {
        TransactionPhase::Prepared | TransactionPhase::RolledBack => {
            groups.is_empty() && pending.is_none()
        },
        TransactionPhase::Installing => match pending {
            None => valid_groups(groups),
            Some(PendingAction::CreateGroup {
                gid,
                name,
                transaction_id,
            }) => valid_groups(groups) && valid_create(*gid, name, transaction_id),
            _ => false,
        },
        TransactionPhase::RollingBack => match pending {
            None => valid_groups(groups),
            Some(PendingAction::RemoveGroup { group }) => {
                valid_groups(groups) && groups.last() == Some(group)
            },
            _ => false,
        },
        _ => groups.is_empty() && pending.is_none(),
    }
}

fn valid_action_phase(action: Action, phase: TransactionPhase) -> bool {
    match action {
        Action::Install => matches!(
            phase,
            TransactionPhase::Prepared
                | TransactionPhase::Installing
                | TransactionPhase::Installed
                | TransactionPhase::RollingBack
                | TransactionPhase::RolledBack
        ),
        Action::RefreshCredential => {
            matches!(
                phase,
                TransactionPhase::Refreshing | TransactionPhase::Installed
            )
        },
        Action::Uninstall => matches!(
            phase,
            TransactionPhase::UninstallingLocal
                | TransactionPhase::UninstallingKubernetes
                | TransactionPhase::PartialUninstall
                | TransactionPhase::UninstallingStatic
                | TransactionPhase::Uninstalled
        ),
    }
}

fn legal_transaction_successor(old: &InstallerTransaction, next: &InstallerTransaction) -> bool {
    if validate_transaction(old).is_err() || validate_transaction(next).is_err() {
        return false;
    }
    let transition = matches!(
        (old.phase, next.phase),
        (TransactionPhase::Prepared, TransactionPhase::Installing)
            | (
                TransactionPhase::Installing | TransactionPhase::Refreshing,
                TransactionPhase::Installed
            )
            | (TransactionPhase::Installing, TransactionPhase::RollingBack)
            | (TransactionPhase::RollingBack, TransactionPhase::RolledBack)
            | (TransactionPhase::RolledBack, TransactionPhase::Prepared)
            | (
                TransactionPhase::Installed,
                TransactionPhase::Refreshing | TransactionPhase::UninstallingLocal
            )
            | (
                TransactionPhase::UninstallingLocal | TransactionPhase::PartialUninstall,
                TransactionPhase::UninstallingKubernetes
            )
            | (
                TransactionPhase::UninstallingKubernetes,
                TransactionPhase::PartialUninstall | TransactionPhase::UninstallingStatic
            )
            | (
                TransactionPhase::UninstallingStatic,
                TransactionPhase::Uninstalled
            )
    );
    let mut expected = old.clone();
    expected.phase = next.phase;
    expected.action = match (old.phase, next.phase) {
        (TransactionPhase::Installed, TransactionPhase::Refreshing) => Action::RefreshCredential,
        (TransactionPhase::Installed, TransactionPhase::UninstallingLocal) => Action::Uninstall,
        _ => old.action,
    };
    let phase_successor = transition
        && old.pending.is_none()
        && valid_action_phase(next.action, next.phase)
        && next == &expected;

    let mut renewed = old.clone();
    renewed
        .bootstrap_kubeconfig_sha256
        .clone_from(&next.bootstrap_kubeconfig_sha256);
    let digest_successor = old.phase == next.phase
        && old.pending.is_none()
        && old.bootstrap_kubeconfig_sha256 != next.bootstrap_kubeconfig_sha256
        && valid_digest(&next.bootstrap_kubeconfig_sha256)
        && next == &renewed;

    let pending_successor = if old.phase == next.phase && old.action == next.action {
        let mut expected = old.clone();
        match (old.host_resources.last(), old.pending.as_ref()) {
            (_, None)
                if old.phase == TransactionPhase::Installing && old.host_resources.len() < 2 =>
            {
                expected.pending.clone_from(&next.pending);
                matches!(next.pending, Some(PendingAction::CreateGroup { .. })) && next == &expected
            },
            (
                _,
                Some(PendingAction::CreateGroup {
                    gid,
                    name,
                    transaction_id: _,
                }),
            ) if old.phase == TransactionPhase::Installing => {
                expected.pending = None;
                expected.host_resources.push(HostResource {
                    gid: *gid,
                    kind: HostResourceKind::Group,
                    name: name.clone(),
                });
                next == &expected
            },
            (Some(resource), None) if old.phase == TransactionPhase::RollingBack => {
                expected.pending = Some(PendingAction::RemoveGroup {
                    group: resource.clone(),
                });
                next == &expected
            },
            (Some(resource), Some(PendingAction::RemoveGroup { group }))
                if old.phase == TransactionPhase::RollingBack && resource == group =>
            {
                expected.pending = None;
                expected.host_resources.pop();
                next == &expected
            },
            _ => false,
        }
    } else {
        false
    };
    phase_successor || digest_successor || pending_successor
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

fn validate_deployment_target(deployment: &Deployment) -> Result<(), InstallerError> {
    if deployment.metadata.name.as_deref() != Some("agent-api")
        || deployment.metadata.namespace.as_deref() != Some("demo")
        || deployment.metadata.uid.as_deref().is_none_or(str::is_empty)
        || !deployment.spec.as_ref().is_some_and(|spec| {
            spec.template.spec.as_ref().is_some_and(|pod| {
                pod.containers
                    .iter()
                    .any(|container| container.name == "api")
            })
        })
    {
        return Err(InstallerError::KubernetesPreflightFailure);
    }
    Ok(())
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
fn test_initial_transaction() -> InstallerTransaction {
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
        let encoded = encode_transaction(&test_initial_transaction()).expect("fixture must encode");
        assert_eq!(encoded, expected.as_bytes());
        assert_eq!(
            decode_transaction(&encoded).expect("canonical bytes must decode"),
            test_initial_transaction()
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
            encode_transaction(&test_initial_transaction()).expect("fixture must encode"),
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
            canonical.replacen("\"phase\":\"prepared\"", "\"phase\":\"refreshing\"", 1),
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
    fn phase_successors_are_exact_and_change_nothing_else() {
        let edges = [
            (
                Action::Install,
                TransactionPhase::Prepared,
                Action::Install,
                TransactionPhase::Installing,
            ),
            (
                Action::Install,
                TransactionPhase::Installing,
                Action::Install,
                TransactionPhase::Installed,
            ),
            (
                Action::Install,
                TransactionPhase::Installing,
                Action::Install,
                TransactionPhase::RollingBack,
            ),
            (
                Action::Install,
                TransactionPhase::RollingBack,
                Action::Install,
                TransactionPhase::RolledBack,
            ),
            (
                Action::Install,
                TransactionPhase::RolledBack,
                Action::Install,
                TransactionPhase::Prepared,
            ),
            (
                Action::Install,
                TransactionPhase::Installed,
                Action::RefreshCredential,
                TransactionPhase::Refreshing,
            ),
            (
                Action::RefreshCredential,
                TransactionPhase::Refreshing,
                Action::RefreshCredential,
                TransactionPhase::Installed,
            ),
            (
                Action::Install,
                TransactionPhase::Installed,
                Action::Uninstall,
                TransactionPhase::UninstallingLocal,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingLocal,
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
                Action::Uninstall,
                TransactionPhase::PartialUninstall,
            ),
            (
                Action::Uninstall,
                TransactionPhase::PartialUninstall,
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
                Action::Uninstall,
                TransactionPhase::UninstallingStatic,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingStatic,
                Action::Uninstall,
                TransactionPhase::Uninstalled,
            ),
        ];
        for (old_action, old_phase, next_action, next_phase) in edges {
            let mut old = test_initial_transaction();
            old.action = old_action;
            old.phase = old_phase;
            let mut next = old.clone();
            next.action = next_action;
            next.phase = next_phase;
            assert!(legal_transaction_successor(&old, &next));
            next.cluster.ca_sha256 = "99".repeat(32);
            assert!(!legal_transaction_successor(&old, &next));
        }
        let old = test_initial_transaction();
        let mut skipped = old.clone();
        skipped.phase = TransactionPhase::Installed;
        assert!(!legal_transaction_successor(&old, &skipped));
    }

    #[test]
    fn first_group_pending_and_ownership_successors_are_exact() {
        let mut installing = test_initial_transaction();
        installing.phase = TransactionPhase::Installing;

        let pending = PendingAction::CreateGroup {
            name: String::from("kapsel"),
            gid: 999,
            transaction_id: installing.transaction_id.clone(),
        };
        let mut creating = installing.clone();
        creating.pending = Some(pending.clone());
        assert!(legal_transaction_successor(&installing, &creating));
        assert_eq!(
            serde_json::to_string(&pending).unwrap(),
            format!(
                r#"{{"action":"create_group","gid":999,"name":"kapsel","transaction_id":"{}"}}"#,
                installing.transaction_id
            )
        );

        let group = HostResource {
            gid: 999,
            kind: HostResourceKind::Group,
            name: String::from("kapsel"),
        };
        let mut created = creating.clone();
        created.pending = None;
        created.host_resources.push(group.clone());
        assert!(legal_transaction_successor(&creating, &created));

        let mut rolling_back = created.clone();
        rolling_back.phase = TransactionPhase::RollingBack;
        assert!(legal_transaction_successor(&created, &rolling_back));
        let mut removing = rolling_back.clone();
        removing.pending = Some(PendingAction::RemoveGroup { group });
        assert!(legal_transaction_successor(&rolling_back, &removing));
        let mut removed = removing.clone();
        removed.pending = None;
        removed.host_resources.clear();
        assert!(legal_transaction_successor(&removing, &removed));

        let mut missing_evidence = creating.clone();
        missing_evidence.pending = None;
        assert!(!legal_transaction_successor(&creating, &missing_evidence));

        let mut wrong_evidence = missing_evidence;
        wrong_evidence.host_resources.push(HostResource {
            gid: 998,
            kind: HostResourceKind::Group,
            name: String::from("kapsel"),
        });
        assert!(!legal_transaction_successor(&creating, &wrong_evidence));

        let mut hostile = creating;
        hostile.pending = Some(PendingAction::CreateGroup {
            name: String::from("other"),
            gid: 999,
            transaction_id: hostile.transaction_id.clone(),
        });
        assert!(!legal_transaction_successor(&installing, &hostile));
    }

    #[test]
    fn second_group_pending_ownership_and_reverse_removal_are_exact() {
        let mut first_created = test_initial_transaction();
        first_created.phase = TransactionPhase::Installing;
        first_created.host_resources.push(HostResource {
            gid: 999,
            kind: HostResourceKind::Group,
            name: String::from("kapsel"),
        });
        let mut second_pending = first_created.clone();
        second_pending.pending = Some(PendingAction::CreateGroup {
            gid: 998,
            name: String::from("kapsel-service-callers"),
            transaction_id: first_created.transaction_id.clone(),
        });
        assert!(legal_transaction_successor(&first_created, &second_pending));

        let second = HostResource {
            gid: 998,
            kind: HostResourceKind::Group,
            name: String::from("kapsel-service-callers"),
        };
        let mut second_created = second_pending.clone();
        second_created.pending = None;
        second_created.host_resources.push(second.clone());
        assert!(legal_transaction_successor(
            &second_pending,
            &second_created
        ));

        let mut rolling_back = second_created.clone();
        rolling_back.phase = TransactionPhase::RollingBack;
        assert!(legal_transaction_successor(&second_created, &rolling_back));
        let mut removing_second = rolling_back.clone();
        removing_second.pending = Some(PendingAction::RemoveGroup { group: second });
        assert!(legal_transaction_successor(&rolling_back, &removing_second));
        let mut second_removed = removing_second.clone();
        second_removed.pending = None;
        second_removed.host_resources.pop();
        assert!(legal_transaction_successor(
            &removing_second,
            &second_removed
        ));

        let mut duplicate_gid = second_pending;
        if let Some(PendingAction::CreateGroup { gid, .. }) = duplicate_gid.pending.as_mut() {
            *gid = 999;
        }
        assert!(validate_transaction(&duplicate_gid).is_err());
        let mut wrong_removal = rolling_back;
        wrong_removal.pending = Some(PendingAction::RemoveGroup {
            group: first_created.host_resources[0].clone(),
        });
        assert!(validate_transaction(&wrong_removal).is_err());
    }

    #[test]
    fn bootstrap_digest_successor_is_same_phase_and_initial_digest_is_immutable() {
        let old = test_initial_transaction();
        let mut renewed = old.clone();
        renewed.bootstrap_kubeconfig_sha256 = "99".repeat(32);
        assert!(legal_transaction_successor(&old, &renewed));
        renewed.bootstrap_kubeconfig_initial_sha256 = "99".repeat(32);
        assert!(!legal_transaction_successor(&old, &renewed));

        let mut installing = old.clone();
        installing.phase = TransactionPhase::Installing;
        installing.bootstrap_kubeconfig_sha256 = "99".repeat(32);
        assert!(!legal_transaction_successor(&old, &installing));
    }

    #[test]
    fn install_phase_reopening_is_explicit_and_other_phases_fail_closed() {
        assert_eq!(
            classify_install_phase(TransactionPhase::Prepared).unwrap(),
            InstallPhase::Prepared
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::Installing).unwrap(),
            InstallPhase::Installing
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::RollingBack).unwrap(),
            InstallPhase::RollingBack
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::RolledBack).unwrap(),
            InstallPhase::RolledBack
        );
        assert!(classify_install_phase(TransactionPhase::Installed).is_err());
    }

    #[test]
    fn fixed_authority_and_deployment_target_are_exact() {
        let mut authorization = kapsel_authority::ExactAuthorization {
            authorization_id: String::from("authorization-1"),
            operation_id: String::from("operation-1"),
            namespace: String::from("demo"),
            deployment: String::from("agent-api"),
            container: String::from("api"),
            immutable_image_digest: format!("registry.example/image@sha256:{}", "11".repeat(32)),
        };
        let identity = |authorization| kapsel_authority::ValidatedServiceOperatorInputs {
            authorization,
            authorization_signing_key_id: String::from("owner-key"),
            receipt_signing_key_id: String::from("receipt-key"),
        };
        assert!(validate_fixed_authority(&identity(authorization.clone())).is_ok());
        authorization.container = String::from("sidecar");
        assert!(validate_fixed_authority(&identity(authorization)).is_err());

        let deployment: Deployment = serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1"},
            "spec": {
                "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {
                    "metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": "example@sha256:11"}]}
                }
            }
        }))
        .unwrap();
        assert!(validate_deployment_target(&deployment).is_ok());
        let mut hostile = deployment;
        hostile.metadata.namespace = Some(String::from("other"));
        assert!(validate_deployment_target(&hostile).is_err());
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
