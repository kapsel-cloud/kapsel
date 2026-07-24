//! Native private runner process composition.

use std::{
    ffi::OsStr,
    fs,
    io::Read,
    net::SocketAddr,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

use rustix::fs::{fstatvfs, mkdirat, openat, readlinkat, Mode, OFlags, StatVfsMountFlags, CWD};

use kapsel::{
    AgentRequest, Application, ApplicationError, AuthorizationTrust, OperatorConfiguration,
};
use kube::{config::KubeConfigOptions, Config};
use serde::Deserialize;

use crate::{run_application_handoff, HandoffAssignment, HandoffError};

const DOCUMENT_BYTES_MAX: usize = 8 * 1024;
const GRANT_BYTES_MAX: usize = 4 * 1024;
const TEXT_BYTES_MAX: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Composition {
    request: PathBuf,
    signed_authorization_grant: PathBuf,
    authorization_trust: PathBuf,
    kubernetes_api_server: PathBuf,
    kubernetes_ca: PathBuf,
    kubernetes_namespace: PathBuf,
    kubernetes_token: PathBuf,
    journal: PathBuf,
    receipt_directory: PathBuf,
    receipt_signing_seed: PathBuf,
    receipt_signing_key_id: PathBuf,
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

/// Runs the separate fixed native runner from exact owner-private inputs.
///
/// # Errors
///
/// Returns one bounded fixed diagnostic when arguments, private files, composition, application,
/// or handoff fail.
pub fn run(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let mut arguments = arguments;
    let mut composition = None;
    let mut handoff = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or("runner arguments are invalid")?;
        match flag.as_str() {
            "--operator-composition" if composition.is_none() => {
                composition = Some(absolute(PathBuf::from(value))?);
            },
            "--handoff" if handoff.is_none() => handoff = Some(absolute(PathBuf::from(value))?),
            _ => return Err("runner arguments are invalid"),
        }
    }
    let composition_path = composition.ok_or("runner arguments are invalid")?;
    let handoff_directory = handoff.ok_or("runner arguments are invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "runner runtime is unavailable")?;
    runtime.block_on(run_async(&composition_path, &handoff_directory))
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed runner composition keeps every private input and no-ambient check together"
)]
async fn run_async(composition_path: &Path, handoff_directory: &Path) -> Result<(), &'static str> {
    let composition: Composition = read_json(composition_path)?;
    initialize_gateway_state(&composition.journal, &composition.receipt_directory)?;
    for path in [
        &composition.request,
        &composition.signed_authorization_grant,
        &composition.authorization_trust,
        &composition.kubernetes_api_server,
        &composition.kubernetes_ca,
        &composition.kubernetes_namespace,
        &composition.kubernetes_token,
        &composition.journal,
        &composition.receipt_directory,
        &composition.receipt_signing_seed,
        &composition.receipt_signing_key_id,
    ] {
        if !path.is_absolute() {
            return Err("runner composition is invalid");
        }
    }
    let request_document: RequestDocument = read_json(&composition.request)?;
    let request = AgentRequest {
        operation_id: request_document.operation_id,
        namespace: request_document.namespace,
        deployment: request_document.deployment,
        container: request_document.container,
        immutable_image_digest: request_document.immutable_image_digest,
    };
    let signed_authorization_grant =
        read_bounded(&composition.signed_authorization_grant, GRANT_BYTES_MAX)?;
    let trust: TrustDocument = read_json(&composition.authorization_trust)?;
    let authorization_public_key = decode_hex_32(&trust.public_key_hex)?;
    let receipt_signing_seed = read_exact_32(&composition.receipt_signing_seed)?;
    let receipt_signing_key_id = read_ascii(&composition.receipt_signing_key_id, 128)?;
    let api_server = read_ascii(&composition.kubernetes_api_server, TEXT_BYTES_MAX)?;
    let namespace = read_ascii(&composition.kubernetes_namespace, 63)?;
    let token = read_ascii(&composition.kubernetes_token, 4 * 1024)?;
    let ca = read_bounded(&composition.kubernetes_ca, 16 * 1024)?;
    let kubeconfig_text = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "runner",
        "clusters": [{
            "name": "runner",
            "cluster": {
                "server": api_server,
                "certificate-authority-data": base64(&ca)
            }
        }],
        "contexts": [{
            "name": "runner",
            "context": {"cluster": "runner", "user": "runner", "namespace": namespace}
        }],
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
    let application = Application::open(OperatorConfiguration {
        journal_path: composition.journal,
        receipt_output_directory: composition.receipt_directory,
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

    validate_private_directory(handoff_directory)?;
    let endpoint_text = read_bounded(&handoff_directory.join("endpoint"), TEXT_BYTES_MAX)?;
    let endpoint = std::str::from_utf8(&endpoint_text)
        .map_err(|_| "runner handoff is invalid")?
        .parse::<SocketAddr>()
        .map_err(|_| "runner handoff is invalid")?;
    let lease_id = String::from_utf8(read_bounded(&handoff_directory.join("lease-id"), 32)?)
        .map_err(|_| "runner handoff is invalid")?;
    if lease_id.len() != 32 {
        return Err("runner handoff is invalid");
    }
    let credential = read_exact_32(&handoff_directory.join("credential"))?;
    run_application_handoff(
        application,
        &request,
        &HandoffAssignment {
            run_id: request
                .operation_id
                .strip_prefix("sandbox-")
                .ok_or("runner handoff is invalid")?
                .to_owned(),
            operation_id: request.operation_id.clone(),
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

fn application_open_error(error: &ApplicationError) -> &'static str {
    match error {
        ApplicationError::InvalidAuthorizationConfiguration => {
            "runner authorization composition is invalid"
        },
        ApplicationError::InvalidReceiptConfiguration => "runner receipt composition is invalid",
        ApplicationError::InvalidJournalPath => "runner journal composition is invalid",
        ApplicationError::InvalidReceiptOutputDirectory => "runner outbox composition is invalid",
        ApplicationError::Gateway(_) => "runner gateway composition is invalid",
        ApplicationError::InvalidGrantProvisioning | ApplicationError::InvalidApplicationState => {
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

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, &'static str> {
    serde_json::from_slice(&read_bounded(path, DOCUMENT_BYTES_MAX)?)
        .map_err(|_| "runner composition is invalid")
}

fn read_ascii(path: &Path, maximum: usize) -> Result<String, &'static str> {
    let bytes = read_bounded(path, maximum)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "runner private input is invalid")?;
    if !text.is_ascii() || text.contains(['\r', '\n']) {
        return Err("runner private input is invalid");
    }
    Ok(text.to_owned())
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

fn read_exact_32(path: &Path) -> Result<[u8; 32], &'static str> {
    read_bounded(path, 32)?
        .try_into()
        .map_err(|_| "runner private input is invalid")
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute() {
        return Err("runner private input is invalid");
    }
    let mut file = open_projected_or_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| "runner private input is unavailable")?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner_private =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o400 | 0o600);
    let group_private =
        metadata.gid() == rustix::process::getgid().as_raw() && matches!(mode, 0o440 | 0o640);
    if !metadata.is_file() || (!owner_private && !group_private) {
        return Err("runner private input is invalid");
    }
    let mut bytes = Vec::with_capacity(maximum.min(4096).saturating_add(1));
    file.by_ref()
        .take(u64::try_from(maximum).map_err(|_| "runner private input is invalid")? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "runner private input is unavailable")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("runner private input is invalid");
    }
    Ok(bytes)
}

fn initialize_gateway_state(journal: &Path, receipt_directory: &Path) -> Result<(), &'static str> {
    let run_directory = journal.parent().ok_or("runner state paths are invalid")?;
    let volume_root = run_directory
        .parent()
        .ok_or("runner state paths are invalid")?;
    if journal.file_name() != Some(OsStr::new("gateway.sqlite3"))
        || run_directory.file_name() != Some(OsStr::new("run"))
        || receipt_directory != run_directory.join("receipt-outbox")
    {
        return Err("runner state paths are invalid");
    }
    let volume = fs::File::from(
        openat(CWD, volume_root, directory_flags(), Mode::empty())
            .map_err(|_| "runner state volume is unavailable")?,
    );
    validate_state_volume(&volume)?;
    let _ = mkdirat(&volume, "run", Mode::from_raw_mode(0o700));
    let run = fs::File::from(
        openat(&volume, "run", directory_flags(), Mode::empty())
            .map_err(|_| "runner state initialization failed")?,
    );
    validate_owner_private_directory(&run)?;
    let _ = mkdirat(&run, "receipt-outbox", Mode::from_raw_mode(0o700));
    let outbox = fs::File::from(
        openat(&run, "receipt-outbox", directory_flags(), Mode::empty())
            .map_err(|_| "runner state initialization failed")?,
    );
    validate_owner_private_directory(&outbox)
}

fn validate_state_volume(directory: &fs::File) -> Result<(), &'static str> {
    let metadata = directory
        .metadata()
        .map_err(|_| "runner state volume is unavailable")?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner_private = metadata.uid() == rustix::process::getuid().as_raw()
        && matches!(mode, 0o700 | 0o750 | 0o770);
    let group_private =
        metadata.gid() == rustix::process::getgid().as_raw() && matches!(mode, 0o750 | 0o770);
    if metadata.is_dir() && (owner_private || group_private) {
        Ok(())
    } else {
        Err("runner state volume is invalid")
    }
}

fn validate_owner_private_directory(directory: &fs::File) -> Result<(), &'static str> {
    let metadata = directory
        .metadata()
        .map_err(|_| "runner state initialization failed")?;
    if metadata.is_dir()
        && metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700
    {
        Ok(())
    } else {
        Err("runner state initialization failed")
    }
}

fn open_projected_or_regular(path: &Path) -> Result<fs::File, &'static str> {
    let parent = path.parent().ok_or("runner private input is invalid")?;
    let name = path.file_name().ok_or("runner private input is invalid")?;
    let directory = fs::File::from(
        openat(CWD, parent, directory_flags(), Mode::empty())
            .map_err(|_| "runner private input is unavailable")?,
    );
    if let Ok(descriptor) = openat(&directory, name, read_flags(), Mode::empty()) {
        return Ok(fs::File::from(descriptor));
    }
    let expected_target = Path::new("..data").join(name);
    let file_target = readlinkat(&directory, name, Vec::new())
        .map_err(|_| "runner private input is unavailable")?;
    if Path::new(OsStr::from_bytes(file_target.to_bytes())) != expected_target {
        return Err("runner projected input escaped its mount");
    }
    let data_target = readlinkat(&directory, "..data", Vec::new())
        .map_err(|_| "runner private input is unavailable")?;
    let data_name = OsStr::from_bytes(data_target.to_bytes());
    let mut components = Path::new(data_name).components();
    let Some(Component::Normal(component)) = components.next() else {
        return Err("runner projected input escaped its mount");
    };
    if components.next().is_some()
        || !component.as_bytes().starts_with(b"..")
        || component.as_bytes() == b".."
    {
        return Err("runner projected input escaped its mount");
    }
    let data_directory = fs::File::from(
        openat(&directory, component, directory_flags(), Mode::empty())
            .map_err(|_| "runner projected input escaped its mount")?,
    );
    openat(&data_directory, name, read_flags(), Mode::empty())
        .map(fs::File::from)
        .map_err(|_| "runner projected input escaped its mount")
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
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

fn validate_private_directory(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("runner handoff is invalid");
    }
    let directory = fs::File::from(
        openat(CWD, path, directory_flags(), Mode::empty())
            .map_err(|_| "runner handoff is unavailable")?,
    );
    let metadata = directory
        .metadata()
        .map_err(|_| "runner handoff is unavailable")?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner_private =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o500 | 0o700);
    let workload_group_private =
        metadata.gid() == rustix::process::getgid().as_raw() && matches!(mode, 0o550 | 0o750);
    let read_only_mount =
        fstatvfs(&directory).is_ok_and(|status| status.f_flag.contains(StatVfsMountFlags::RDONLY));
    if metadata.is_dir() && (owner_private || workload_group_private || read_only_mount) {
        Ok(())
    } else {
        Err("runner handoff is invalid")
    }
}

fn bounded_text(value: &str) -> Result<String, &'static str> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err("runner composition is invalid");
    }
    Ok(value.to_owned())
}

fn absolute(path: PathBuf) -> Result<PathBuf, &'static str> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("runner paths must be absolute")
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn projected_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let generation = root.join("..2026_07_24_00_00_00.000000001");
        if !generation.exists() {
            private_directory(&generation);
            symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        }
        let target = generation.join(name);
        fs::write(&target, bytes).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(Path::new("..data").join(name), root.join(name)).unwrap();
        root.join(name)
    }

    #[test]
    fn projected_atomic_writer_layout_is_accepted_without_allowing_escape_or_substitution() {
        let root =
            std::env::temp_dir().join(format!("kapsel-runner-projected-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let accepted = projected_file(&root, "token", b"exact-token");
        assert_eq!(read_bounded(&accepted, 32).unwrap(), b"exact-token");

        symlink("../outside", root.join("escaped-key")).unwrap();
        assert!(read_bounded(&root.join("escaped-key"), 32).is_err());

        fs::remove_file(root.join("..data")).unwrap();
        symlink("../outside-generation", root.join("..data")).unwrap();
        assert!(read_bounded(&accepted, 32).is_err());

        fs::remove_file(root.join("..data")).unwrap();
        symlink("..2026_07_24_00_00_00.000000001", root.join("..data")).unwrap();
        let generation = root.join("..2026_07_24_00_00_00.000000001");
        fs::remove_file(generation.join("token")).unwrap();
        fs::write(root.join("outside"), b"outside").unwrap();
        symlink(root.join("outside"), generation.join("token")).unwrap();
        assert!(read_bounded(&accepted, 32).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_gateway_volume_initializes_exact_owner_private_run_state() {
        let root =
            std::env::temp_dir().join(format!("kapsel-runner-empty-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let journal = root.join("run/gateway.sqlite3");
        let outbox = root.join("run/receipt-outbox");
        initialize_gateway_state(&journal, &outbox).unwrap();
        for directory in [root.join("run"), outbox] {
            let metadata = fs::metadata(directory).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        assert!(!journal.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
