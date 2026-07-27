//! Private composition and domain projection shared by the CLI and MCP adapters.

use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use http_body_util::Limited;
use kapsel::{
    Application, ApplicationError, AuthorizationTrust, OperationReport, OperationResult,
    OperationState, OperatorConfiguration, TargetRejection,
};
use kube::{config::KubeConfigOptions, Config};
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde::Deserialize;
use tower_http::map_response_body::MapResponseBodyLayer;

const JSON_BYTES_MAX: usize = 16 * 1024;
const GRANT_BYTES_MAX: usize = 4 * 1024;
const KUBERNETES_RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FailureClass {
    OperatorConfiguration,
    RequestRejected,
    OperationFailure,
}

pub(crate) struct OperationProjection<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) state: &'static str,
    pub(crate) result: Option<&'static str>,
    pub(crate) target_rejection: Option<&'static str>,
    pub(crate) receipt_file: Option<&'a str>,
    pub(crate) receipt_sha256: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorDocument {
    signed_authorization_grant: PathBuf,
    authorization_key_id: String,
    authorization_public_key: PathBuf,
    kubeconfig: PathBuf,
    journal: PathBuf,
    receipt_directory: PathBuf,
    receipt_signing_seed: PathBuf,
    receipt_signing_key_id: String,
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime, FailureClass> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FailureClass::OperationFailure)
}

pub(crate) async fn open_application(path: &Path) -> Result<Application, FailureClass> {
    let operator: OperatorDocument = read_json(path)?;
    let configuration = load_operator_configuration(operator).await?;
    Application::open(configuration).map_err(|error| match error {
        ApplicationError::InvalidAuthorizationConfiguration
        | ApplicationError::InvalidReceiptConfiguration
        | ApplicationError::InvalidJournalPath
        | ApplicationError::InvalidReceiptOutputDirectory
        | ApplicationError::InvalidGrantProvisioning => FailureClass::OperatorConfiguration,
        ApplicationError::RequestRejected | ApplicationError::OperationFailure => {
            FailureClass::OperationFailure
        },
    })
}

pub(crate) fn classify_application_operation(error: &ApplicationError) -> FailureClass {
    match error {
        ApplicationError::RequestRejected => FailureClass::RequestRejected,
        _ => FailureClass::OperationFailure,
    }
}

pub(crate) fn project_operation(
    report: &OperationReport,
) -> Result<OperationProjection<'_>, FailureClass> {
    let (receipt_file, receipt_sha256) = match &report.receipt {
        Some(receipt) => (
            Some(
                receipt
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(FailureClass::OperationFailure)?,
            ),
            Some(receipt.digest.as_str()),
        ),
        None => (None, None),
    };
    Ok(OperationProjection {
        operation_id: &report.operation_id,
        state: operation_state(report.state),
        result: report.result.map(operation_result),
        target_rejection: report.target_rejection.map(target_rejection),
        receipt_file,
        receipt_sha256,
    })
}

async fn load_operator_configuration(
    operator: OperatorDocument,
) -> Result<OperatorConfiguration, FailureClass> {
    for path in [
        &operator.signed_authorization_grant,
        &operator.authorization_public_key,
        &operator.kubeconfig,
        &operator.journal,
        &operator.receipt_directory,
        &operator.receipt_signing_seed,
    ] {
        if !path.is_absolute() {
            return Err(FailureClass::OperatorConfiguration);
        }
    }
    let signed_authorization_grant =
        read_bounded(&operator.signed_authorization_grant, GRANT_BYTES_MAX)?;
    let authorization_public_key = read_exact_32(&operator.authorization_public_key)?;
    let receipt_signing_seed = read_exact_32(&operator.receipt_signing_seed)?;
    let kubernetes_client = load_kubernetes_client(&operator.kubeconfig).await?;

    Ok(OperatorConfiguration {
        journal_path: operator.journal,
        receipt_output_directory: operator.receipt_directory,
        authorization_trust: AuthorizationTrust {
            key_id: operator.authorization_key_id,
            public_key: authorization_public_key,
        },
        signed_authorization_grant,
        kubernetes_client,
        receipt_signing_seed,
        receipt_signing_key_id: operator.receipt_signing_key_id,
    })
}

async fn load_kubernetes_client(path: &Path) -> Result<kube::Client, FailureClass> {
    let bytes = read_bounded(path, JSON_BYTES_MAX)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| FailureClass::OperatorConfiguration)?;
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(text)
        .map_err(|_| FailureClass::OperatorConfiguration)?;
    let proxy_placeholder_was_added = configure_explicit_kubeconfig(&mut kubeconfig)?;
    let mut client_config =
        Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|_| FailureClass::OperatorConfiguration)?;
    if proxy_placeholder_was_added {
        client_config.proxy_url = None;
    }
    let response_limit =
        MapResponseBodyLayer::new(|body| Limited::new(body, KUBERNETES_RESPONSE_BYTES_MAX));
    Ok(kube::client::ClientBuilder::try_from(client_config)
        .map_err(|_| FailureClass::OperatorConfiguration)?
        .with_layer(&response_limit)
        .build())
}

fn configure_explicit_kubeconfig(
    kubeconfig: &mut kube::config::Kubeconfig,
) -> Result<bool, FailureClass> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or(FailureClass::OperatorConfiguration)?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|context| context.name == current)
        .and_then(|context| context.context.as_ref())
        .ok_or(FailureClass::OperatorConfiguration)?;
    let cluster_name = context.cluster.clone();
    let user_name = context.user.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|cluster| cluster.name == cluster_name)
        .and_then(|cluster| cluster.cluster.as_mut())
        .ok_or(FailureClass::OperatorConfiguration)?;
    if cluster.certificate_authority.is_some() {
        return Err(FailureClass::OperatorConfiguration);
    }
    if let Some(user_name) = user_name {
        let user = kubeconfig
            .auth_infos
            .iter()
            .find(|user| user.name == user_name)
            .and_then(|user| user.auth_info.as_ref())
            .ok_or(FailureClass::OperatorConfiguration)?;
        if user.token_file.is_some()
            || user.client_certificate.is_some()
            || user.client_key.is_some()
            || user.auth_provider.is_some()
            || user.exec.is_some()
        {
            return Err(FailureClass::OperatorConfiguration);
        }
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
}

fn read_json(path: &Path) -> Result<OperatorDocument, FailureClass> {
    let bytes = read_bounded(path, JSON_BYTES_MAX)?;
    serde_json::from_slice(&bytes).map_err(|_| FailureClass::OperatorConfiguration)
}

fn read_exact_32(path: &Path) -> Result<[u8; 32], FailureClass> {
    read_bounded(path, 32)?
        .try_into()
        .map_err(|_| FailureClass::OperatorConfiguration)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, FailureClass> {
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| FailureClass::OperatorConfiguration)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| FailureClass::OperatorConfiguration)?;
    if !metadata.is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum)
    {
        return Err(FailureClass::OperatorConfiguration);
    }
    let capacity = maximum
        .checked_add(1)
        .ok_or(FailureClass::OperatorConfiguration)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(capacity).map_err(|_| FailureClass::OperatorConfiguration)?)
        .read_to_end(&mut bytes)
        .map_err(|_| FailureClass::OperatorConfiguration)?;
    if bytes.len() > maximum {
        return Err(FailureClass::OperatorConfiguration);
    }
    Ok(bytes)
}

const fn operation_state(value: OperationState) -> &'static str {
    match value {
        OperationState::Requested => "REQUESTED",
        OperationState::Authorized => "AUTHORIZED",
        OperationState::NotAttempted => "NOT_ATTEMPTED",
        OperationState::ApplyStarted => "APPLY_STARTED",
        OperationState::ReceiverObserved => "RECEIVER_OBSERVED",
        OperationState::ReceiptPrepared => "RECEIPT_PREPARED",
        OperationState::ReceiptWritten => "RECEIPT_WRITTEN",
        OperationState::Finalized => "FINALIZED",
    }
}

const fn operation_result(value: OperationResult) -> &'static str {
    match value {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn target_rejection(value: TargetRejection) -> &'static str {
    match value {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the response-bound test immediately"
)]
mod tests {
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        os::unix::fs::PermissionsExt as _,
        path::Path,
        thread,
    };

    use k8s_openapi::api::apps::v1::Deployment;
    use kube::Api;

    use super::*;

    enum ResponseFraming {
        ContentLength,
        Chunked,
        CloseDelimited,
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn response_body(bytes: usize) -> Vec<u8> {
        let prefix = concat!(
            r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"#,
            r#""name":"bounded","namespace":"demo","uid":"uid-1","resourceVersion":"1"}}"#
        );
        assert!(bytes >= prefix.len());
        let mut body = Vec::with_capacity(bytes);
        body.extend_from_slice(prefix.as_bytes());
        body.resize(bytes, b' ');
        body
    }

    fn response_server(
        body: Vec<u8>,
        framing: ResponseFraming,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            match framing {
                ResponseFraming::ContentLength => {
                    write!(
                        stream,
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "content-length: {}\r\nconnection: close\r\n\r\n"
                        ),
                        body.len()
                    )
                    .unwrap();
                    let _ = stream.write_all(&body);
                },
                ResponseFraming::Chunked => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    let _ = write!(stream, "{:x}\r\n", body.len());
                    let _ = stream.write_all(&body);
                    let _ = stream.write_all(b"\r\n0\r\n\r\n");
                },
                ResponseFraming::CloseDelimited => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    let _ = stream.write_all(&body);
                },
            }
        });
        (address, server)
    }

    async fn request_deployment(body_bytes: usize, framing: ResponseFraming) -> bool {
        let body = response_body(body_bytes);
        let (address, server) = response_server(body, framing);
        let root = std::env::temp_dir().join(format!(
            "kapsel-provider-response-bound-{}-{body_bytes}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let kubeconfig = root.join("kubeconfig.yaml");
        private_file(
            &kubeconfig,
            format!(
                concat!(
                    "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                    "  cluster:\n    server: http://{}\ncontexts:\n- name: fixture\n",
                    "  context:\n    cluster: fixture\n    user: fixture\n",
                    "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
                ),
                address
            )
            .as_bytes(),
        );
        let client = load_kubernetes_client(&kubeconfig).await.ok().unwrap();
        let result = Api::<Deployment>::namespaced(client, "demo")
            .get("bounded")
            .await
            .is_ok();
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
        result
    }

    #[tokio::test]
    async fn kubernetes_response_limit_accepts_exact_and_rejects_every_oversized_framing() {
        assert!(
            request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX,
                ResponseFraming::ContentLength
            )
            .await
        );
        assert!(
            !request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX + 1,
                ResponseFraming::ContentLength
            )
            .await
        );
        assert!(
            !request_deployment(KUBERNETES_RESPONSE_BYTES_MAX + 1, ResponseFraming::Chunked).await
        );
        assert!(
            !request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX + 1,
                ResponseFraming::CloseDelimited
            )
            .await
        );
    }
}
