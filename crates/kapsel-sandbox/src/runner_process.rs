//! Fixed descriptor-bootstrap entry point for the native private runner.

#![allow(
    clippy::similar_names,
    reason = "paired UID/GID bindings make exact numeric identity checks auditable"
)]

use std::{
    fs,
    io::{IoSliceMut, Read},
    mem::MaybeUninit,
    os::{
        fd::OwnedFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
};

use kapsel::{
    AgentRequest, Application, ApplicationError, AuthorizationTrust, OperatorConfiguration,
};
use kube::{config::KubeConfigOptions, Config};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{run_application_handoff, HandoffAssignment, HandoffError};

pub(crate) const INPUT_NAMES: [&str; 12] = [
    "request.json",
    "signed-authorization-grant.bin",
    "authorization-trust.json",
    "kubernetes-api-server",
    "kubernetes-ca.pem",
    "kubernetes-namespace",
    "kubernetes-token",
    "receipt-signing-seed",
    "receipt-signing-key-id",
    "handoff-endpoint",
    "handoff-lease-id",
    "handoff-credential",
];
const DOCUMENT_BYTES_MAX: usize = 8 * 1024;
const GRANT_BYTES_MAX: usize = 4 * 1024;
const TEXT_BYTES_MAX: usize = 512;
const BOOTSTRAP_BYTES_MAX: usize = 128 * 1024;
const CREDENTIAL_DOMAIN: &[u8] = b"KAPSEL-SANDBOX-RUNNER-HOST-CREDENTIAL-V1\0";
const READY: &[u8] = b"KAPSEL-SANDBOX-RUNNER-READY-V1\0";
const RELEASE: &[u8] = b"KAPSEL-SANDBOX-RUNNER-RELEASE-V1\0";

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    pub(crate) version: u8,
    pub(crate) run_id: String,
    pub(crate) operation_id: String,
    pub(crate) lease_id: String,
    pub(crate) generation: u64,
    pub(crate) process_id: u32,
    pub(crate) controller_uid: u32,
    pub(crate) controller_gid: u32,
    pub(crate) runner_uid: u32,
    pub(crate) runner_gid: u32,
    pub(crate) credential_verifier: String,
    pub(crate) inputs: Vec<DescriptorIdentity>,
    pub(crate) state: DescriptorIdentity,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DescriptorIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDocument {
    key_id: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

/// Runs the separate runner only from the fixed inherited descriptor inventory.
///
/// # Errors
///
/// Returns one bounded diagnostic when the descriptor boundary, application, or handoff fails.
pub fn run(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    if arguments.count() != 0 {
        return Err("runner bootstrap arguments are invalid");
    }
    let state_identity = establish_identity_and_state()?;
    #[cfg(target_os = "linux")]
    validate_fixed_linux_state_path(&state_identity)?;
    let (bootstrap, inputs) = receive_bootstrap()?;
    validate_boundary(&bootstrap, &state_identity, &inputs)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "runner runtime is unavailable")?;
    runtime.block_on(run_async(bootstrap, inputs))
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed descriptor composition keeps all authority checks before Application"
)]
async fn run_async(
    bootstrap: Bootstrap,
    mut input_files: Vec<fs::File>,
) -> Result<(), &'static str> {
    let payloads = input_files
        .iter_mut()
        .map(|file| read_descriptor(file, 16 * 1024))
        .collect::<Result<Vec<_>, _>>()?;
    let mut inputs = payloads.into_iter();
    let request_document: RequestDocument = read_json_bytes(
        &inputs.next().ok_or("runner input is invalid")?,
        DOCUMENT_BYTES_MAX,
    )?;
    let request = AgentRequest {
        operation_id: request_document.operation_id,
        namespace: request_document.namespace,
        deployment: request_document.deployment,
        container: request_document.container,
        immutable_image_digest: request_document.immutable_image_digest,
    };
    if request.operation_id != bootstrap.operation_id
        || request.operation_id != format!("sandbox-{}", bootstrap.run_id)
    {
        return Err("runner bootstrap identity is invalid");
    }
    let signed_authorization_grant = bounded_bytes(
        inputs.next().ok_or("runner input is invalid")?,
        GRANT_BYTES_MAX,
    )?;
    let trust: TrustDocument = read_json_bytes(
        &inputs.next().ok_or("runner input is invalid")?,
        DOCUMENT_BYTES_MAX,
    )?;
    let authorization_public_key = decode_hex_32(&trust.public_key_hex)?;
    let api_server = read_ascii_bytes(
        inputs.next().ok_or("runner input is invalid")?,
        TEXT_BYTES_MAX,
    )?;
    let ca = bounded_bytes(inputs.next().ok_or("runner input is invalid")?, 16 * 1024)?;
    let namespace = read_ascii_bytes(inputs.next().ok_or("runner input is invalid")?, 63)?;
    let token = read_ascii_bytes(inputs.next().ok_or("runner input is invalid")?, 4 * 1024)?;
    let receipt_signing_seed = exact_32(inputs.next().ok_or("runner input is invalid")?)?;
    let receipt_signing_key_id =
        read_ascii_bytes(inputs.next().ok_or("runner input is invalid")?, 128)?;
    let endpoint = read_ascii_bytes(
        inputs.next().ok_or("runner input is invalid")?,
        TEXT_BYTES_MAX,
    )?
    .parse()
    .map_err(|_| "runner handoff is invalid")?;
    let lease_id = read_ascii_bytes(inputs.next().ok_or("runner input is invalid")?, 32)?;
    let credential = exact_32(inputs.next().ok_or("runner input is invalid")?)?;
    if inputs.next().is_some() {
        return Err("runner input inventory is invalid");
    }
    if lease_id != bootstrap.lease_id
        || credential_verifier(
            &bootstrap.run_id,
            &bootstrap.operation_id,
            &lease_id,
            &credential,
        ) != bootstrap.credential_verifier
    {
        return Err("runner bootstrap authority is stale");
    }

    let kubeconfig_text = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "runner",
        "clusters": [{"name": "runner", "cluster": {
            "server": api_server, "certificate-authority-data": base64(&ca)
        }}],
        "contexts": [{"name": "runner", "context": {
            "cluster": "runner", "user": "runner", "namespace": namespace
        }}],
        "users": [{"name": "runner", "user": {"token": token}}]
    })
    .to_string();
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(&kubeconfig_text)
        .map_err(|_| "runner Kubernetes composition is invalid")?;
    let placeholder = configure_explicit_kubeconfig(&mut kubeconfig)?;
    let mut client_config =
        Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|_| "runner Kubernetes configuration is invalid")?;
    if placeholder {
        client_config.proxy_url = None;
    }
    let kubernetes_client =
        kube::Client::try_from(client_config).map_err(|_| "runner Kubernetes client is invalid")?;

    #[cfg(target_os = "linux")]
    let generation = std::path::PathBuf::from("/run/kapsel-sandbox");
    #[cfg(not(target_os = "linux"))]
    let generation = fs::canonicalize(".").map_err(|_| "runner state generation is invalid")?;
    let run_directory = generation.join("run");
    #[cfg(target_os = "linux")]
    let receipt_directory = std::path::PathBuf::from("./run/receipt-outbox");
    #[cfg(not(target_os = "linux"))]
    let receipt_directory = run_directory.join("receipt-outbox");
    let journal = run_directory.join("gateway.sqlite3");
    validate_owner_private_directory(&run_directory)?;
    validate_owner_private_directory(&receipt_directory)?;
    let application = Application::open(OperatorConfiguration {
        journal_path: journal,
        receipt_output_directory: receipt_directory,
        authorization_trust: AuthorizationTrust {
            key_id: bounded_text(&trust.key_id)?,
            public_key: authorization_public_key,
        },
        signed_authorization_grant,
        kubernetes_client,
        receipt_signing_seed,
        receipt_signing_key_id: bounded_text(&receipt_signing_key_id)?,
    })
    .map_err(|error| application_open_error(&error))?;
    await_authority_release()?;

    run_application_handoff(
        application,
        &request,
        &HandoffAssignment {
            run_id: bootstrap.run_id,
            operation_id: bootstrap.operation_id,
            lease_id,
            credential,
            endpoint,
        },
    )
    .await
    .map_err(|error| match error {
        HandoffError::Rejected => "runner handoff was rejected",
        HandoffError::Unavailable => "runner handoff is unavailable",
        HandoffError::Application => "runner application failed",
    })?;
    Ok(())
}

fn await_authority_release() -> Result<(), &'static str> {
    rustix::net::send(
        rustix::stdio::stdin(),
        READY,
        rustix::net::SendFlags::empty(),
    )
    .map_err(|_| "runner bootstrap release is unavailable")?;
    let mut release = [0_u8; RELEASE.len()];
    let (_, received) = rustix::net::recv(
        rustix::stdio::stdin(),
        &mut release,
        rustix::net::RecvFlags::empty(),
    )
    .map_err(|_| "runner bootstrap release is unavailable")?;
    if received != RELEASE.len() || release != RELEASE {
        return Err("runner bootstrap release is invalid");
    }
    Ok(())
}

fn receive_bootstrap() -> Result<(Bootstrap, Vec<fs::File>), &'static str> {
    let mut bytes = vec![0_u8; BOOTSTRAP_BYTES_MAX + 1];
    let mut input = [IoSliceMut::new(&mut bytes)];
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(INPUT_NAMES.len()))];
    let mut control = rustix::net::RecvAncillaryBuffer::new(&mut control_space);
    #[cfg(target_os = "linux")]
    let flags = rustix::net::RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = rustix::net::RecvFlags::empty();
    let received = rustix::net::recvmsg(rustix::stdio::stdin(), &mut input, &mut control, flags)
        .map_err(|_| "runner bootstrap is invalid")?;
    if received.bytes == 0 || received.bytes > BOOTSTRAP_BYTES_MAX {
        return Err("runner bootstrap is invalid");
    }
    let mut descriptors = Vec::<OwnedFd>::new();
    let mut messages = 0_usize;
    for message in control.drain() {
        match message {
            rustix::net::RecvAncillaryMessage::ScmRights(rights) => {
                messages += 1;
                descriptors.extend(rights);
            },
            _ => return Err("runner bootstrap is invalid"),
        }
    }
    if messages != 1 || descriptors.len() != INPUT_NAMES.len() {
        return Err("runner input inventory is invalid");
    }
    let bootstrap = serde_json::from_slice(&bytes[..received.bytes])
        .map_err(|_| "runner bootstrap is invalid")?;
    Ok((
        bootstrap,
        descriptors.into_iter().map(fs::File::from).collect(),
    ))
}

fn establish_identity_and_state() -> Result<DescriptorIdentity, &'static str> {
    let state = rustix::fs::fstat(rustix::stdio::stdout())
        .map_err(|_| "runner state generation is unavailable")?;
    let state_uid = state.st_uid;
    let state_gid = state.st_gid;
    if state_uid != rustix::process::getuid().as_raw()
        || state_uid != rustix::process::geteuid().as_raw()
        || state_gid != rustix::process::getgid().as_raw()
        || state_gid != rustix::process::getegid().as_raw()
        || state_uid == u32::MAX
        || state_gid == u32::MAX
    {
        return Err("runner process identity is unavailable");
    }
    #[cfg(target_os = "linux")]
    {
        if rustix::process::parent_process_death_signal()
            .ok()
            .flatten()
            != Some(rustix::process::Signal::KILL)
            || !rustix::thread::no_new_privs().unwrap_or(false)
            || !linux_status_has_fixed_identity(state_uid, state_gid)?
        {
            return Err("runner process authority is invalid");
        }
    }
    rustix::process::fchdir(rustix::stdio::stdout())
        .map_err(|_| "runner state generation is unavailable")?;
    Ok(DescriptorIdentity {
        device: descriptor_device(state.st_dev)?,
        inode: state.st_ino,
        length: u64::try_from(state.st_size).map_err(|_| "runner state generation is invalid")?,
    })
}

fn descriptor_device(device: impl TryInto<u64>) -> Result<u64, &'static str> {
    device
        .try_into()
        .map_err(|_| "runner state generation is invalid")
}

#[cfg(target_os = "linux")]
fn validate_fixed_linux_state_path(expected: &DescriptorIdentity) -> Result<(), &'static str> {
    let fixed = fs::File::from(
        rustix::fs::open(
            "/run/kapsel-sandbox",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "runner state generation is invalid")?,
    );
    let current = fs::File::from(
        rustix::fs::open(
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "runner state generation is invalid")?,
    );
    for directory in [&fixed, &current] {
        let metadata = directory
            .metadata()
            .map_err(|_| "runner state generation is invalid")?;
        let found = identity(&metadata);
        if found.device != expected.device
            || found.inode != expected.inode
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.gid() != rustix::process::getegid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err("runner state generation is invalid");
        }
    }
    Ok(())
}

fn read_descriptor(file: &mut fs::File, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "runner private input is invalid")?;
    if bytes.is_empty() || bytes.len() > maximum {
        Err("runner private input is invalid")
    } else {
        Ok(bytes)
    }
}

#[cfg(target_os = "linux")]
fn linux_status_has_fixed_identity(uid: u32, gid: u32) -> Result<bool, &'static str> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|_| "runner process identity is unavailable")?;
    let expected_uid = format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}");
    let expected_gid = format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}");
    Ok(status.lines().any(|line| line == expected_uid)
        && status.lines().any(|line| line == expected_gid)
        && status.lines().any(|line| line.trim_end() == "Groups:"))
}

fn validate_boundary(
    bootstrap: &Bootstrap,
    state_identity: &DescriptorIdentity,
    inputs: &[fs::File],
) -> Result<(), &'static str> {
    let state = fs::metadata(".").map_err(|_| "runner state generation is unavailable")?;
    let found = identity(&state);
    if bootstrap.version != 1
        || bootstrap.generation == 0
        || bootstrap.process_id != std::process::id()
        || bootstrap.runner_uid != rustix::process::getuid().as_raw()
        || bootstrap.runner_gid != rustix::process::getgid().as_raw()
        || bootstrap.inputs.len() != INPUT_NAMES.len()
        || inputs.len() != INPUT_NAMES.len()
        || !state.is_dir()
        || state.uid() != bootstrap.runner_uid
        || state.gid() != bootstrap.runner_gid
        || state.permissions().mode() & 0o777 != 0o700
        || found.device != bootstrap.state.device
        || found.inode != bootstrap.state.inode
        || found.length != bootstrap.state.length
        || state_identity.device != bootstrap.state.device
        || state_identity.inode != bootstrap.state.inode
    {
        return Err("runner bootstrap is invalid");
    }
    for (file, expected) in inputs.iter().zip(&bootstrap.inputs) {
        let metadata = file
            .metadata()
            .map_err(|_| "runner input descriptor binding is stale")?;
        let found = identity(&metadata);
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o400
            || found.device != expected.device
            || found.inode != expected.inode
            || found.length != expected.length
        {
            return Err("runner input descriptor binding is stale");
        }
    }
    Ok(())
}

pub(crate) fn descriptor_identity(metadata: &fs::Metadata) -> DescriptorIdentity {
    identity(metadata)
}

fn identity(metadata: &fs::Metadata) -> DescriptorIdentity {
    DescriptorIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

pub(crate) fn credential_verifier(
    run_id: &str,
    operation_id: &str,
    lease_id: &str,
    credential: &[u8; 32],
) -> String {
    let mut digest = Sha256::new();
    digest.update(CREDENTIAL_DOMAIN);
    digest.update(run_id.as_bytes());
    digest.update(operation_id.as_bytes());
    digest.update(lease_id.as_bytes());
    digest.update(credential);
    lowercase_hex(&digest.finalize())
}

fn application_open_error(error: &ApplicationError) -> &'static str {
    match error {
        ApplicationError::InvalidAuthorizationConfiguration => {
            "runner authorization composition is invalid"
        },
        ApplicationError::InvalidReceiptConfiguration => "runner receipt composition is invalid",
        ApplicationError::InvalidJournalPath => "runner journal composition is invalid",
        ApplicationError::InvalidReceiptOutputDirectory => "runner outbox composition is invalid",
        ApplicationError::OperationFailure => "runner gateway composition is invalid",
        ApplicationError::InvalidGrantProvisioning | ApplicationError::RequestRejected => {
            "runner application composition is invalid"
        },
    }
}

fn configure_explicit_kubeconfig(
    kubeconfig: &mut kube::config::Kubeconfig,
) -> Result<bool, &'static str> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or("runner composition is invalid")?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|context| context.name == current)
        .and_then(|context| context.context.as_ref())
        .ok_or("runner composition is invalid")?;
    let cluster_name = context.cluster.clone();
    let user_name = context.user.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|cluster| cluster.name == cluster_name)
        .and_then(|cluster| cluster.cluster.as_mut())
        .ok_or("runner composition is invalid")?;
    if cluster.certificate_authority.is_some() {
        return Err("runner composition is invalid");
    }
    if let Some(user_name) = user_name {
        let user = kubeconfig
            .auth_infos
            .iter()
            .find(|user| user.name == user_name)
            .and_then(|user| user.auth_info.as_ref())
            .ok_or("runner composition is invalid")?;
        if user.token_file.is_some()
            || user.client_certificate.is_some()
            || user.client_key.is_some()
            || user.auth_provider.is_some()
            || user.exec.is_some()
        {
            return Err("runner composition is invalid");
        }
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
}

fn read_json_bytes<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, &'static str> {
    serde_json::from_slice(bounded_slice(bytes, maximum)?)
        .map_err(|_| "runner composition is invalid")
}

fn read_ascii_bytes(bytes: Vec<u8>, maximum: usize) -> Result<String, &'static str> {
    let bytes = bounded_bytes(bytes, maximum)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "runner private input is invalid")?;
    if !text.is_ascii() || text.contains(['\r', '\n']) {
        return Err("runner private input is invalid");
    }
    Ok(text.to_owned())
}

fn exact_32(bytes: Vec<u8>) -> Result<[u8; 32], &'static str> {
    bytes
        .try_into()
        .map_err(|_| "runner private input is invalid")
}

fn bounded_bytes(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>, &'static str> {
    bounded_slice(&bytes, maximum)?;
    Ok(bytes)
}

fn bounded_slice(bytes: &[u8], maximum: usize) -> Result<&[u8], &'static str> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err("runner private input is invalid")
    } else {
        Ok(bytes)
    }
}

fn validate_owner_private_directory(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::metadata(path).map_err(|_| "runner state generation is unavailable")?;
    if metadata.is_dir()
        && metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.gid() == rustix::process::getgid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700
    {
        Ok(())
    } else {
        Err("runner state generation is invalid")
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("runner private input is invalid");
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "runner private input is invalid")?;
    }
    Ok(output)
}

fn bounded_text(value: &str) -> Result<String, &'static str> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err("runner composition is invalid");
    }
    Ok(value.to_owned())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    output
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
