//! TLS and Kubernetes authentication for exactly the private scheduler and cleanup state codecs.
//! This is a deep transport implementation, not a generic protocol or storage interface.

use std::{
    fmt,
    future::{poll_fn, Future},
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Duration,
};

use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use kube::{api::PostParams, Api, Client};
use rustls::{
    pki_types::{
        pem::{PemObject, SectionKind},
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
        ServerName,
    },
    ClientConfig, RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, Instant},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::parse_x509_certificate;

use crate::runner_process::open_projected_or_regular;

const APPLICATION_AUDIENCE: &str = "https://kapsel.dev/sandbox/controller-state/v1";
const SERVER_DNS_NAME: &str = "kapsel-sandbox-controller-state.kapsel-sandbox-system.svc";
const REQUEST_MAGIC: &[u8] = b"KAPSEL-SANDBOX-CONTROLLER-STATE-V1\0";
const ACCEPTED_MAGIC: &[u8] = b"KAPSEL-SANDBOX-CONTROLLER-STATE-ACCEPTED-V1\0";
const AUTHENTICATION_REJECTED_MAGIC: &[u8] =
    b"KAPSEL-SANDBOX-CONTROLLER-AUTHENTICATION-REJECTED-V1\0";
const TOKEN_BYTES_MAX: usize = 16 * 1024;
const PAYLOAD_BYTES_MAX: usize = 64 * 1024;
const PRIVATE_FILE_BYTES_MAX: u64 = 128 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TLS_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const TOKEN_REVIEW_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(not(test))]
const fn token_review_timeout() -> Duration {
    TOKEN_REVIEW_TIMEOUT
}

#[cfg(test)]
const fn token_review_timeout() -> Duration {
    Duration::from_millis(50)
}

#[cfg(not(test))]
const fn idle_timeout() -> Duration {
    IDLE_TIMEOUT
}

#[cfg(test)]
const fn idle_timeout() -> Duration {
    Duration::from_millis(200)
}

const DISPATCH_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(not(test))]
const fn dispatch_timeout() -> Duration {
    DISPATCH_TIMEOUT
}

#[cfg(test)]
const fn dispatch_timeout() -> Duration {
    Duration::from_millis(50)
}

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);

static OPEN_CONNECTIONS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(16)));
static AUTHENTICATED_DISPATCHES: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(8)));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Scheduler,
    Cleanup,
}

impl Role {
    const fn port(self) -> u16 {
        match self {
            Self::Scheduler => 8082,
            Self::Cleanup => 8083,
        }
    }

    const fn username(self) -> &'static str {
        match self {
            Self::Scheduler => "system:serviceaccount:kapsel-sandbox-system:sandbox-scheduler",
            Self::Cleanup => "system:serviceaccount:kapsel-sandbox-system:sandbox-cleanup",
        }
    }
}

#[cfg(test)]
static TEST_BOUND_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

const fn exact_role_port_matches(role: Role, port: u16) -> bool {
    port == role.port()
}

#[cfg(not(test))]
fn role_port_matches(role: Role, port: u16) -> bool {
    exact_role_port_matches(role, port)
}

#[cfg(test)]
pub(crate) fn allow_test_bound_port(port: u16) {
    TEST_BOUND_PORT.store(port, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
fn role_port_matches(role: Role, port: u16) -> bool {
    exact_role_port_matches(role, port)
        || (port != 0 && TEST_BOUND_PORT.load(std::sync::atomic::Ordering::Relaxed) == port)
}

#[derive(Clone)]
pub(crate) struct RoleBinding {
    role: Role,
    service_account_uid: String,
}

impl fmt::Debug for RoleBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleBinding")
            .field("role", &self.role)
            .field("service_account_uid", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ClientInputs {
    ca_bundle_path: PathBuf,
    ca_bundle_sha256: [u8; 32],
    ca_root_count: u8,
    token_path: PathBuf,
}

impl fmt::Debug for ClientInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientInputs { [REDACTED] }")
    }
}

#[derive(Clone)]
pub(crate) struct ServerInputs {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

impl fmt::Debug for ServerInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerInputs { [REDACTED] }")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientError {
    AuthenticationRejected,
    TransportRejected,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationRejected => "authentication_rejected",
            Self::TransportRejected => "transport_rejected",
        })
    }
}

impl std::error::Error for ClientError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerError;

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controller_transport_rejected")
    }
}

impl std::error::Error for ServerError {}

pub(crate) fn role_binding(
    role: Role,
    service_account_uid: String,
) -> Result<RoleBinding, ServerError> {
    if service_account_uid.is_empty()
        || service_account_uid.len() > 253
        || !service_account_uid
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(ServerError);
    }
    Ok(RoleBinding {
        role,
        service_account_uid,
    })
}

pub(crate) fn client_inputs(
    ca_bundle_path: PathBuf,
    ca_bundle_sha256: [u8; 32],
    ca_root_count: u8,
    token_path: PathBuf,
) -> Result<ClientInputs, ServerError> {
    if !matches!(ca_root_count, 1 | 2) {
        return Err(ServerError);
    }
    Ok(ClientInputs {
        ca_bundle_path,
        ca_bundle_sha256,
        ca_root_count,
        token_path,
    })
}

pub(crate) fn server_inputs(certificate_path: PathBuf, private_key_path: PathBuf) -> ServerInputs {
    ServerInputs {
        certificate_path,
        private_key_path,
    }
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ServerError> {
    read_bounded_file_with_privacy(path, maximum, false)
}

fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ServerError> {
    read_bounded_file_with_privacy(path, maximum, true)
}

fn read_bounded_file_with_privacy(
    path: &Path,
    maximum: u64,
    private: bool,
) -> Result<Vec<u8>, ServerError> {
    if !path.is_absolute() {
        return Err(ServerError);
    }
    let mut file = open_projected_or_regular(path).map_err(|_| ServerError)?;
    let metadata = file.metadata().map_err(|_| ServerError)?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner_private =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o400 | 0o600);
    let group_private =
        metadata.gid() == rustix::process::getgid().as_raw() && matches!(mode, 0o440 | 0o640);
    let integrity_protected = match mode {
        0o400 => metadata.uid() == rustix::process::getuid().as_raw(),
        0o440 => {
            metadata.uid() == rustix::process::getuid().as_raw()
                || metadata.gid() == rustix::process::getgid().as_raw()
        },
        0o444 => true,
        _ => false,
    };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
        || (private && !owner_private && !group_private)
        || (!private && !integrity_protected)
    {
        return Err(ServerError);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ServerError)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(ServerError);
    }
    Ok(bytes)
}

fn pem_items(bytes: &[u8]) -> Result<Vec<(SectionKind, Vec<u8>)>, ServerError> {
    strict_pem_envelope(bytes)?;
    <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServerError)
}

fn strict_pem_envelope(bytes: &[u8]) -> Result<(), ServerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ServerError)?;
    let mut label: Option<&str> = None;
    let mut content_lines = 0_usize;
    let mut blocks = 0_usize;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(begin) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|value| value.strip_suffix("-----"))
        {
            if label.is_some()
                || begin.is_empty()
                || !begin
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b' ' || byte.is_ascii_digit())
            {
                return Err(ServerError);
            }
            label = Some(begin);
            content_lines = 0;
        } else if let Some(end) = line
            .strip_prefix("-----END ")
            .and_then(|value| value.strip_suffix("-----"))
        {
            if label != Some(end) || content_lines == 0 {
                return Err(ServerError);
            }
            label = None;
            blocks += 1;
        } else if label.is_none()
            || line.is_empty()
            || line.len() > 64
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(ServerError);
        } else {
            content_lines += 1;
        }
    }
    if label.is_some() || blocks == 0 {
        Err(ServerError)
    } else {
        Ok(())
    }
}

fn trust_bundle_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn make_client_config(inputs: &ClientInputs) -> Result<ClientConfig, ServerError> {
    let bundle = read_bounded_file(&inputs.ca_bundle_path, PRIVATE_FILE_BYTES_MAX)?;
    if trust_bundle_digest(&bundle) != inputs.ca_bundle_sha256 {
        return Err(ServerError);
    }
    let items = pem_items(&bundle)?;
    if items.len() != usize::from(inputs.ca_root_count) || !(1..=2).contains(&items.len()) {
        return Err(ServerError);
    }
    if items.len() == 2 && items[0].1 == items[1].1 {
        return Err(ServerError);
    }
    let mut roots = RootCertStore::empty();
    for (kind, certificate) in items {
        if kind != SectionKind::Certificate {
            return Err(ServerError);
        }
        let (trailing, parsed) = parse_x509_certificate(&certificate).map_err(|_| ServerError)?;
        let basic_constraints = parsed
            .basic_constraints()
            .map_err(|_| ServerError)?
            .ok_or(ServerError)?;
        if !trailing.is_empty() || !basic_constraints.value.ca || !parsed.validity().is_valid() {
            return Err(ServerError);
        }
        roots
            .add(CertificateDer::from(certificate))
            .map_err(|_| ServerError)?;
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ServerError)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn make_server_config(inputs: &ServerInputs) -> Result<ServerConfig, ServerError> {
    let certificate_items = pem_items(&read_bounded_file(
        &inputs.certificate_path,
        PRIVATE_FILE_BYTES_MAX,
    )?)?;
    let [(SectionKind::Certificate, certificate)] = certificate_items.as_slice() else {
        return Err(ServerError);
    };
    let key_items = pem_items(&read_private_file(
        &inputs.private_key_path,
        PRIVATE_FILE_BYTES_MAX,
    )?)?;
    let [key_item] = key_items.as_slice() else {
        return Err(ServerError);
    };
    let private_key = match key_item {
        (SectionKind::RsaPrivateKey, key) => {
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key.clone()))
        },
        (SectionKind::PrivateKey, key) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()))
        },
        (SectionKind::EcPrivateKey, key) => {
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key.clone()))
        },
        _ => return Err(ServerError),
    };
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ServerError)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate.clone())], private_key)
        .map_err(|_| ServerError)
}

fn validate_payload_frame(frame: &[u8]) -> Result<(), ServerError> {
    let length_bytes: [u8; 4] = frame
        .get(..4)
        .ok_or(ServerError)?
        .try_into()
        .map_err(|_| ServerError)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > PAYLOAD_BYTES_MAX || frame.len() != length + 4 {
        return Err(ServerError);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Deadlines {
    absolute: Instant,
    phase: Instant,
}

impl Deadlines {
    fn new(absolute: Instant, phase_duration: Duration) -> Self {
        Self {
            absolute,
            phase: Instant::now() + phase_duration,
        }
    }

    fn remaining(self) -> Result<Duration, ServerError> {
        let now = Instant::now();
        let end = self.absolute.min(self.phase);
        if now >= end {
            return Err(ServerError);
        }
        Ok(idle_timeout().min(end - now))
    }
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut output: &mut [u8],
    deadlines: Deadlines,
) -> Result<(), ServerError> {
    while !output.is_empty() {
        let count = timeout(
            deadlines.remaining()?,
            poll_fn(|context| {
                let mut buffer = ReadBuf::new(output);
                match Pin::new(&mut *reader).poll_read(context, &mut buffer) {
                    std::task::Poll::Ready(Ok(())) => {
                        std::task::Poll::Ready(Ok(buffer.filled().len()))
                    },
                    std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            }),
        )
        .await
        .map_err(|_| ServerError)?
        .map_err(|_| ServerError)?;
        if count == 0 {
            return Err(ServerError);
        }
        output = &mut output[count..];
    }
    Ok(())
}

async fn write_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut input: &[u8],
    deadlines: Deadlines,
) -> Result<(), ServerError> {
    while !input.is_empty() {
        let count = timeout(
            deadlines.remaining()?,
            poll_fn(|context| Pin::new(&mut *writer).poll_write(context, input)),
        )
        .await
        .map_err(|_| ServerError)?
        .map_err(|_| ServerError)?;
        if count == 0 {
            return Err(ServerError);
        }
        input = &input[count..];
    }
    Ok(())
}

async fn require_authenticated_close<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadlines: Deadlines,
) -> Result<(), ServerError> {
    let mut trailing = [0_u8; 1];
    let count = timeout(
        deadlines.remaining()?,
        poll_fn(|context| {
            let mut buffer = ReadBuf::new(&mut trailing);
            match Pin::new(&mut *reader).poll_read(context, &mut buffer) {
                std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(buffer.filled().len())),
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }),
    )
    .await
    .map_err(|_| ServerError)?
    .map_err(|_| ServerError)?;
    if count == 0 {
        Ok(())
    } else {
        Err(ServerError)
    }
}

async fn shut_down<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadlines: Deadlines,
) -> Result<(), ServerError> {
    timeout(
        deadlines.remaining()?,
        poll_fn(|context| Pin::new(&mut *writer).poll_shutdown(context)),
    )
    .await
    .map_err(|_| ServerError)?
    .map_err(|_| ServerError)
}

async fn review_token(
    kubernetes: Client,
    binding: &RoleBinding,
    token: Vec<u8>,
    absolute: Instant,
) -> Result<(), ServerError> {
    let token = String::from_utf8(token).map_err(|_| ServerError)?;
    let request = TokenReview {
        spec: TokenReviewSpec {
            audiences: Some(vec![APPLICATION_AUDIENCE.to_owned()]),
            token: Some(token),
        },
        ..TokenReview::default()
    };
    let remaining = absolute.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ServerError);
    }
    let reviewed = timeout(
        token_review_timeout().min(remaining),
        Api::<TokenReview>::all(kubernetes).create(&PostParams::default(), &request),
    )
    .await
    .map_err(|_| ServerError)?
    .map_err(|_| ServerError)?;
    let status = reviewed.status.ok_or(ServerError)?;
    let user = status.user.ok_or(ServerError)?;
    let audiences_match = status.audiences.as_deref() == Some(&[APPLICATION_AUDIENCE.to_owned()]);
    if status.authenticated != Some(true)
        || status.error.is_some()
        || !audiences_match
        || user.username.as_deref() != Some(binding.role.username())
        || user.uid.as_deref() != Some(binding.service_account_uid.as_str())
    {
        return Err(ServerError);
    }
    Ok(())
}

fn acquire_connection() -> Result<OwnedSemaphorePermit, ServerError> {
    OPEN_CONNECTIONS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ServerError)
}

/// Handles one accepted connection for exactly the role appointed by its local port.
pub(crate) async fn handle_connection<F, Fut>(
    tcp: TcpStream,
    inputs: &ServerInputs,
    binding: &RoleBinding,
    kubernetes: Client,
    dispatch: F,
) -> Result<(), ServerError>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Vec<u8>>,
{
    if !role_port_matches(
        binding.role,
        tcp.local_addr().map_err(|_| ServerError)?.port(),
    ) {
        return Err(ServerError);
    }
    let _connection = acquire_connection()?;
    let absolute = Instant::now() + CONNECTION_TIMEOUT;
    let acceptor = TlsAcceptor::from(Arc::new(make_server_config(inputs)?));
    let tls_remaining = absolute.saturating_duration_since(Instant::now());
    let mut stream = timeout(TLS_TIMEOUT.min(tls_remaining), acceptor.accept(tcp))
        .await
        .map_err(|_| ServerError)?
        .map_err(|_| ServerError)?;
    if stream.get_ref().1.server_name() != Some(SERVER_DNS_NAME) {
        return Err(ServerError);
    }

    let request_deadlines = Deadlines::new(absolute, REQUEST_TIMEOUT);
    let mut magic = [0_u8; REQUEST_MAGIC.len()];
    read_exact(&mut stream, &mut magic, request_deadlines).await?;
    if magic != REQUEST_MAGIC {
        return Err(ServerError);
    }
    let mut token_length = [0_u8; 2];
    read_exact(&mut stream, &mut token_length, request_deadlines).await?;
    let token_length = usize::from(u16::from_be_bytes(token_length));
    if token_length == 0 || token_length > TOKEN_BYTES_MAX {
        return Err(ServerError);
    }
    let mut token = vec![0_u8; token_length];
    read_exact(&mut stream, &mut token, request_deadlines).await?;
    let mut payload_length = [0_u8; 4];
    read_exact(&mut stream, &mut payload_length, request_deadlines).await?;
    let payload_length_value = u32::from_be_bytes(payload_length) as usize;
    if payload_length_value == 0 || payload_length_value > PAYLOAD_BYTES_MAX {
        return Err(ServerError);
    }
    let mut payload = Vec::with_capacity(payload_length_value + 4);
    payload.extend_from_slice(&payload_length);
    payload.resize(payload_length_value + 4, 0);
    read_exact(&mut stream, &mut payload[4..], request_deadlines).await?;
    require_authenticated_close(&mut stream, request_deadlines).await?;

    if review_token(kubernetes, binding, token, absolute)
        .await
        .is_err()
    {
        let response_deadlines = Deadlines::new(absolute, RESPONSE_TIMEOUT);
        write_all(
            &mut stream,
            AUTHENTICATION_REJECTED_MAGIC,
            response_deadlines,
        )
        .await?;
        shut_down(&mut stream, response_deadlines).await?;
        return Ok(());
    }

    let _dispatch = AUTHENTICATED_DISPATCHES
        .clone()
        .try_acquire_owned()
        .map_err(|_| ServerError)?;
    let dispatch_remaining = absolute.saturating_duration_since(Instant::now());
    if dispatch_remaining.is_zero() {
        return Err(ServerError);
    }
    let response = timeout(
        dispatch_timeout().min(dispatch_remaining),
        dispatch(payload),
    )
    .await
    .map_err(|_| ServerError)?;
    validate_payload_frame(&response)?;
    let response_deadlines = Deadlines::new(absolute, RESPONSE_TIMEOUT);
    write_all(&mut stream, ACCEPTED_MAGIC, response_deadlines).await?;
    write_all(&mut stream, &response, response_deadlines).await?;
    shut_down(&mut stream, response_deadlines).await
}

async fn read_marker<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadlines: Deadlines,
) -> Result<Vec<u8>, ServerError> {
    let maximum = ACCEPTED_MAGIC
        .len()
        .max(AUTHENTICATION_REJECTED_MAGIC.len());
    let mut marker = Vec::with_capacity(maximum);
    while marker.len() < maximum {
        let mut byte = [0_u8; 1];
        read_exact(reader, &mut byte, deadlines).await?;
        marker.push(byte[0]);
        if byte[0] == 0 {
            return Ok(marker);
        }
    }
    Err(ServerError)
}

/// Sends one fixed role payload using freshly reopened projected credentials.
pub(crate) async fn request(
    address: SocketAddr,
    role: Role,
    inputs: &ClientInputs,
    payload: &[u8],
) -> Result<Vec<u8>, ClientError> {
    validate_payload_frame(payload).map_err(|_| ClientError::TransportRejected)?;
    if !role_port_matches(role, address.port()) {
        return Err(ClientError::TransportRejected);
    }
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| ClientError::TransportRejected)?
        .map_err(|_| ClientError::TransportRejected)?;
    let absolute = Instant::now() + CONNECTION_TIMEOUT;
    let config = make_client_config(inputs).map_err(|_| ClientError::TransportRejected)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(SERVER_DNS_NAME)
        .map_err(|_| ClientError::TransportRejected)?
        .to_owned();
    let tls_remaining = absolute.saturating_duration_since(Instant::now());
    let mut stream = timeout(
        TLS_TIMEOUT.min(tls_remaining),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| ClientError::TransportRejected)?
    .map_err(|_| ClientError::TransportRejected)?;
    let token = read_private_file(&inputs.token_path, TOKEN_BYTES_MAX as u64)
        .map_err(|_| ClientError::TransportRejected)?;
    let token_length = u16::try_from(token.len()).map_err(|_| ClientError::TransportRejected)?;
    let request_deadlines = Deadlines::new(absolute, REQUEST_TIMEOUT);
    write_all(&mut stream, REQUEST_MAGIC, request_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    write_all(&mut stream, &token_length.to_be_bytes(), request_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    write_all(&mut stream, &token, request_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    write_all(&mut stream, payload, request_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    shut_down(&mut stream, request_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;

    let response_deadlines = Deadlines::new(absolute, RESPONSE_TIMEOUT);
    let marker = read_marker(&mut stream, response_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    if marker == AUTHENTICATION_REJECTED_MAGIC {
        return require_authenticated_close(&mut stream, response_deadlines)
            .await
            .map_or(Err(ClientError::TransportRejected), |()| {
                Err(ClientError::AuthenticationRejected)
            });
    }
    if marker != ACCEPTED_MAGIC {
        return Err(ClientError::TransportRejected);
    }
    let mut length = [0_u8; 4];
    read_exact(&mut stream, &mut length, response_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    let body_length = u32::from_be_bytes(length) as usize;
    if body_length == 0 || body_length > PAYLOAD_BYTES_MAX {
        return Err(ClientError::TransportRejected);
    }
    let mut response = Vec::with_capacity(body_length + 4);
    response.extend_from_slice(&length);
    response.resize(body_length + 4, 0);
    read_exact(&mut stream, &mut response[4..], response_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    require_authenticated_close(&mut stream, response_deadlines)
        .await
        .map_err(|_| ClientError::TransportRejected)?;
    Ok(response)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
    };

    use http::{Response, StatusCode};
    use serde_json::{json, Value};
    use tokio::net::TcpListener;
    use tower_test::mock;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub(crate) static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TlsFixture {
        root: PathBuf,
        server: ServerInputs,
        client: ClientInputs,
    }

    impl TlsFixture {
        fn new(server_name: &str, validity: Validity) -> Result<Self, Box<dyn std::error::Error>> {
            let root = std::env::temp_dir().join(format!(
                "kapsel-controller-transport-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let fixture = match (server_name == SERVER_DNS_NAME, validity) {
                (true, Validity::Current) => "current",
                (false, Validity::Current) => "wrong-name",
                (_, Validity::Expired) => "expired",
                (_, Validity::Future) => "future",
            };
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/controller-transport")
                .join(fixture);
            let certificate_path = root.join("tls.crt");
            let private_key_path = root.join("tls.key");
            let ca_bundle_path = root.join("ca.crt");
            let token_path = root.join("token");
            fs::copy(source.join("cert.pem"), &certificate_path)?;
            fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o400))?;
            fs::copy(source.join("key.pem"), &private_key_path)?;
            fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
            fs::copy(source.join("ca.pem"), &ca_bundle_path)?;
            fs::set_permissions(&ca_bundle_path, fs::Permissions::from_mode(0o400))?;
            let ca_bundle_sha256 = trust_bundle_digest(&fs::read(&ca_bundle_path)?);
            fs::write(&token_path, b"bounded-projected-token")?;
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                server: server_inputs(certificate_path, private_key_path),
                client: client_inputs(ca_bundle_path, ca_bundle_sha256, 1, token_path)?,
                root,
            })
        }
    }

    impl Drop for TlsFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Clone, Copy)]
    enum Validity {
        Current,
        Expired,
        Future,
    }

    fn token_review_client(status: Value) -> (Client, tokio::task::JoinHandle<()>) {
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri().path(),
                "/apis/authentication.k8s.io/v1/tokenreviews"
            );
            let request_body: Value =
                serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                    .unwrap();
            assert_eq!(
                request_body["spec"],
                json!({
                    "audiences": [APPLICATION_AUDIENCE],
                    "token": "bounded-projected-token"
                })
            );
            let body = json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "metadata": {},
                "spec": {
                    "audiences": [APPLICATION_AUDIENCE],
                    "token": "bounded-projected-token"
                },
                "status": status
            });
            send.send_response(
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        });
        (Client::new(transport, "default"), server)
    }

    fn failed_token_review_client(delay: Duration) -> (Client, tokio::task::JoinHandle<()>) {
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            tokio::time::sleep(delay).await;
            let body = json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": "Unavailable",
                "code": 503
            });
            send.send_response(
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        });
        (Client::new(transport, "default"), server)
    }

    fn accepted_status(role: Role, uid: &str) -> Value {
        json!({
            "authenticated": true,
            "audiences": [APPLICATION_AUDIENCE],
            "user": {
                "username": role.username(),
                "uid": uid,
                "groups": ["ignored"],
                "extra": {"ignored": ["ignored"]}
            }
        })
    }

    fn no_review_client() -> (Client, tokio::task::JoinHandle<bool>) {
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let observed = tokio::spawn(async move {
            !matches!(
                timeout(Duration::from_millis(100), handle.next_request()).await,
                Ok(Some(_))
            )
        });
        (Client::new(transport, "default"), observed)
    }

    async fn test_listener(role: Role) -> TcpListener {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _ = role;
        TEST_BOUND_PORT.store(port, Ordering::Relaxed);
        listener
    }

    async fn test_tls_stream(
        address: SocketAddr,
        inputs: &ClientInputs,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(address).await.unwrap();
        let connector = TlsConnector::from(Arc::new(make_client_config(inputs).unwrap()));
        connector
            .connect(
                ServerName::try_from(SERVER_DNS_NAME).unwrap().to_owned(),
                tcp,
            )
            .await
            .unwrap()
    }

    fn request_bytes(payload: &[u8]) -> Vec<u8> {
        let token = b"bounded-projected-token";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&u16::try_from(token.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(token);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn test_deadlines() -> Deadlines {
        let absolute = Instant::now() + Duration::from_secs(1);
        Deadlines::new(absolute, Duration::from_secs(1))
    }

    async fn test_write<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) {
        write_all(writer, bytes, test_deadlines()).await.unwrap();
    }

    async fn test_shutdown<W: AsyncWrite + Unpin>(writer: &mut W) {
        shut_down(writer, test_deadlines()).await.unwrap();
    }

    fn replace_integrity_file(path: &Path, contents: &str) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    async fn run_server_once<F, Fut>(
        listener: TcpListener,
        inputs: ServerInputs,
        binding: RoleBinding,
        client: Client,
        dispatch: F,
    ) -> Result<(), ServerError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: Future<Output = Vec<u8>>,
    {
        let (tcp, _) = listener.accept().await.map_err(|_| ServerError)?;
        handle_connection(tcp, &inputs, &binding, client, dispatch).await
    }

    #[tokio::test]
    async fn contract_literals_and_process_ceilings_are_exact() {
        let _port = TEST_NETWORK.lock().await;
        assert_eq!(
            APPLICATION_AUDIENCE,
            "https://kapsel.dev/sandbox/controller-state/v1"
        );
        assert_eq!(
            SERVER_DNS_NAME,
            "kapsel-sandbox-controller-state.kapsel-sandbox-system.svc"
        );
        assert_eq!(Role::Scheduler.port(), 8082);
        assert_eq!(Role::Cleanup.port(), 8083);
        let mut connections = Vec::new();
        for _ in 0..16 {
            connections.push(OPEN_CONNECTIONS.clone().try_acquire_owned().unwrap());
        }
        assert!(OPEN_CONNECTIONS.clone().try_acquire_owned().is_err());
        drop(connections);
        let mut dispatches = Vec::new();
        for _ in 0..8 {
            dispatches.push(
                AUTHENTICATED_DISPATCHES
                    .clone()
                    .try_acquire_owned()
                    .unwrap(),
            );
        }
        assert!(AUTHENTICATED_DISPATCHES
            .clone()
            .try_acquire_owned()
            .is_err());
        drop(dispatches);
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(TLS_TIMEOUT, Duration::from_secs(3));
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(5));
        assert_eq!(RESPONSE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(1));
        assert_eq!(TOKEN_REVIEW_TIMEOUT, Duration::from_secs(3));
        assert_eq!(DISPATCH_TIMEOUT, Duration::from_secs(5));
        assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(20));
    }

    #[test]
    fn local_errors_and_debug_are_fixed_and_redacted() -> Result<(), ServerError> {
        let client = client_inputs(
            PathBuf::from("/private/ca-bytes"),
            [7; 32],
            1,
            PathBuf::from("/private/token-bytes"),
        )?;
        let server = server_inputs(
            PathBuf::from("/private/cert-bytes"),
            PathBuf::from("/private/key-bytes"),
        );
        let binding = role_binding(Role::Scheduler, "private-uid".to_owned())?;
        let rendered = format!("{client:?} {server:?} {binding:?} {ServerError}");
        assert!(!rendered.contains("/private"));
        assert!(!rendered.contains("private-uid"));
        assert_eq!(
            ClientError::AuthenticationRejected.to_string(),
            "authentication_rejected"
        );
        assert_eq!(
            ClientError::TransportRejected.to_string(),
            "transport_rejected"
        );
        assert_eq!(ServerError.to_string(), "controller_transport_rejected");
        Ok(())
    }

    #[test]
    fn payload_framing_is_bounded_and_exact() {
        assert!(validate_payload_frame(&[0, 0, 0, 1, b'x']).is_ok());
        assert!(validate_payload_frame(&[0, 0, 0, 0]).is_err());
        assert!(validate_payload_frame(&[0, 0, 0, 2, b'x']).is_err());
        assert!(validate_payload_frame(&[0, 0, 0, 1, b'x', b'y']).is_err());
        let mut oversized = vec![0_u8; PAYLOAD_BYTES_MAX + 5];
        let length = u32::try_from(PAYLOAD_BYTES_MAX + 1).unwrap();
        oversized[..4].copy_from_slice(&length.to_be_bytes());
        assert!(validate_payload_frame(&oversized).is_err());
    }

    #[tokio::test]
    async fn both_roles_use_exact_token_review_and_dispatch_once() {
        let _port = TEST_NETWORK.lock().await;
        let dispatches = Arc::new(AtomicUsize::new(0));
        for (role, uid) in [
            (Role::Scheduler, "scheduler-uid"),
            (Role::Cleanup, "cleanup-uid"),
        ] {
            let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
            let listener = test_listener(role).await;
            let address = listener.local_addr().unwrap();
            let (kubernetes, mock_server) = token_review_client(accepted_status(role, uid));
            let observed = Arc::clone(&dispatches);
            let binding = role_binding(role, uid.to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let server = tokio::spawn(async move {
                run_server_once(
                    listener,
                    server_inputs,
                    binding,
                    kubernetes,
                    move |payload| async move {
                        observed.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(payload, [0, 0, 0, 1, b'q']);
                        vec![0, 0, 0, 1, b'a']
                    },
                )
                .await
            });
            let response = request(address, role, &fixture.client, &[0, 0, 0, 1, b'q'])
                .await
                .unwrap();
            assert_eq!(response, [0, 0, 0, 1, b'a']);
            server.await.unwrap().unwrap();
            mock_server.await.unwrap();
        }
        assert_eq!(dispatches.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table proves every TokenReview identity field fails before dispatch"
    )]
    async fn authentication_negatives_return_one_fixed_class_without_dispatch() {
        let _port = TEST_NETWORK.lock().await;
        let rejected_statuses = [
            Value::Null,
            json!({
                "authenticated": false,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [],
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE, APPLICATION_AUDIENCE],
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE, "extra"],
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE]
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {"uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {"username": Role::Scheduler.username()}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {"username": Role::Cleanup.username(), "uid": "scheduler-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {
                    "username": "system:serviceaccount:other:sandbox-scheduler",
                    "uid": "scheduler-uid"
                }
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "user": {"username": Role::Scheduler.username(), "uid": "recreated-uid"}
            }),
            json!({
                "authenticated": true,
                "audiences": [APPLICATION_AUDIENCE],
                "error": "upstream detail",
                "user": {"username": Role::Scheduler.username(), "uid": "scheduler-uid"}
            }),
        ];
        for status in rejected_statuses {
            let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
            let listener = test_listener(Role::Scheduler).await;
            let address = listener.local_addr().unwrap();
            let (kubernetes, mock_server) = token_review_client(status);
            let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let dispatches = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&dispatches);
            let server = tokio::spawn(async move {
                run_server_once(
                    listener,
                    server_inputs,
                    binding,
                    kubernetes,
                    move |_| async move {
                        observed.fetch_add(1, Ordering::Relaxed);
                        vec![0, 0, 0, 1, b'a']
                    },
                )
                .await
            });
            assert_eq!(
                request(
                    address,
                    Role::Scheduler,
                    &fixture.client,
                    &[0, 0, 0, 1, b'q']
                )
                .await,
                Err(ClientError::AuthenticationRejected)
            );
            assert_eq!(dispatches.load(Ordering::Relaxed), 0);
            server.await.unwrap().unwrap();
            mock_server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn token_review_api_error_and_timeout_are_redacted_authentication_rejections() {
        let _port = TEST_NETWORK.lock().await;
        for delay in [Duration::ZERO, Duration::from_millis(100)] {
            let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
            let listener = test_listener(Role::Scheduler).await;
            let address = listener.local_addr().unwrap();
            let (kubernetes, mock_server) = failed_token_review_client(delay);
            let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let dispatches = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&dispatches);
            let server = tokio::spawn(async move {
                run_server_once(
                    listener,
                    server_inputs,
                    binding,
                    kubernetes,
                    move |_| async move {
                        observed.fetch_add(1, Ordering::Relaxed);
                        vec![0, 0, 0, 1, b'a']
                    },
                )
                .await
            });
            assert_eq!(
                request(
                    address,
                    Role::Scheduler,
                    &fixture.client,
                    &[0, 0, 0, 1, b'q']
                )
                .await,
                Err(ClientError::AuthenticationRejected)
            );
            assert_eq!(dispatches.load(Ordering::Relaxed), 0);
            server.await.unwrap().unwrap();
            mock_server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_delayed_dispatch_responses_are_transport_rejected() {
        let _port = TEST_NETWORK.lock().await;
        for kind in 0_u8..3 {
            let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
            let listener = test_listener(Role::Scheduler).await;
            let address = listener.local_addr().unwrap();
            let (kubernetes, mock_server) =
                token_review_client(accepted_status(Role::Scheduler, "scheduler-uid"));
            let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let server = tokio::spawn(async move {
                run_server_once(
                    listener,
                    server_inputs,
                    binding,
                    kubernetes,
                    move |_| async move {
                        match kind {
                            0 => vec![0, 0, 0, 1, b'a', b'x'],
                            1 => {
                                let mut response = vec![0_u8; PAYLOAD_BYTES_MAX + 5];
                                let length = u32::try_from(PAYLOAD_BYTES_MAX + 1).unwrap();
                                response[..4].copy_from_slice(&length.to_be_bytes());
                                response
                            },
                            _ => {
                                tokio::time::sleep(Duration::from_millis(75)).await;
                                vec![0, 0, 0, 1, b'a']
                            },
                        }
                    },
                )
                .await
            });
            assert_eq!(
                request(
                    address,
                    Role::Scheduler,
                    &fixture.client,
                    &[0, 0, 0, 1, b'q']
                )
                .await,
                Err(ClientError::TransportRejected)
            );
            assert!(server.await.unwrap().is_err());
            mock_server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn wrong_name_and_certificate_validity_fail_before_token_review() {
        let _port = TEST_NETWORK.lock().await;
        for (name, validity) in [
            ("wrong.kapsel-sandbox-system.svc", Validity::Current),
            (SERVER_DNS_NAME, Validity::Expired),
            (SERVER_DNS_NAME, Validity::Future),
        ] {
            let fixture = TlsFixture::new(name, validity).unwrap();
            let listener = test_listener(Role::Scheduler).await;
            let address = listener.local_addr().unwrap();
            let (transport, mut handle) = mock::pair::<
                http::Request<kube::client::Body>,
                http::Response<kube::client::Body>,
            >();
            let no_review = tokio::spawn(async move {
                !matches!(
                    timeout(Duration::from_millis(100), handle.next_request()).await,
                    Ok(Some(_))
                )
            });
            let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let server = tokio::spawn(async move {
                run_server_once(
                    listener,
                    server_inputs,
                    binding,
                    Client::new(transport, "default"),
                    |_| async { vec![0, 0, 0, 1, b'a'] },
                )
                .await
            });
            assert_eq!(
                request(
                    address,
                    Role::Scheduler,
                    &fixture.client,
                    &[0, 0, 0, 1, b'q']
                )
                .await,
                Err(ClientError::TransportRejected)
            );
            assert!(server.await.unwrap().is_err());
            assert!(no_review.await.unwrap());
        }
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one serialized port test covers the pre-authentication wire rejection matrix"
    )]
    async fn unknown_ca_plaintext_trailing_truncated_and_missing_close_notify_never_authenticate() {
        let _port = TEST_NETWORK.lock().await;

        let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
        let other_ca =
            TlsFixture::new("wrong.kapsel-sandbox-system.svc", Validity::Current).unwrap();
        let listener = test_listener(Role::Scheduler).await;
        let address = listener.local_addr().unwrap();
        let (kubernetes, no_review) = no_review_client();
        let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
        let server_inputs = fixture.server.clone();
        let server = tokio::spawn(async move {
            run_server_once(listener, server_inputs, binding, kubernetes, |_| async {
                vec![0, 0, 0, 1, b'a']
            })
            .await
        });
        assert_eq!(
            request(
                address,
                Role::Scheduler,
                &other_ca.client,
                &[0, 0, 0, 1, b'q']
            )
            .await,
            Err(ClientError::TransportRejected)
        );
        assert!(server.await.unwrap().is_err());
        assert!(no_review.await.unwrap());

        let mut wrong_magic = request_bytes(&[0, 0, 0, 1, b'q']);
        wrong_magic[0] = b'X';
        let mut zero_token = REQUEST_MAGIC.to_vec();
        zero_token.extend_from_slice(&0_u16.to_be_bytes());
        let mut oversized_token = REQUEST_MAGIC.to_vec();
        let oversized_token_length = u16::try_from(TOKEN_BYTES_MAX).unwrap() + 1;
        oversized_token.extend_from_slice(&oversized_token_length.to_be_bytes());
        let malformed = [
            (wrong_magic, true),
            (zero_token, true),
            (oversized_token, true),
            (request_bytes(&[0, 1, 0, 1]), true),
            (request_bytes(&[0, 0, 0, 1, b'q', b'x']), true),
            (request_bytes(&[0, 0, 0, 2, b'q']), true),
            (request_bytes(&[0, 0, 0, 1, b'q']), false),
        ];
        for (bytes, graceful) in malformed {
            let listener = test_listener(Role::Scheduler).await;
            let address = listener.local_addr().unwrap();
            let (kubernetes, no_review) = no_review_client();
            let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
            let server_inputs = fixture.server.clone();
            let server = tokio::spawn(async move {
                run_server_once(listener, server_inputs, binding, kubernetes, |_| async {
                    vec![0, 0, 0, 1, b'a']
                })
                .await
            });
            let mut stream = test_tls_stream(address, &fixture.client).await;
            test_write(&mut stream, &bytes).await;
            if graceful {
                test_shutdown(&mut stream).await;
            }
            drop(stream);
            assert!(server.await.unwrap().is_err());
            assert!(no_review.await.unwrap());
        }

        let listener = test_listener(Role::Scheduler).await;
        let address = listener.local_addr().unwrap();
        let (kubernetes, no_review) = no_review_client();
        let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
        let server_inputs = fixture.server.clone();
        let server = tokio::spawn(async move {
            run_server_once(listener, server_inputs, binding, kubernetes, |_| async {
                vec![0, 0, 0, 1, b'a']
            })
            .await
        });
        let mut trickle = test_tls_stream(address, &fixture.client).await;
        test_write(&mut trickle, &REQUEST_MAGIC[..1]).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _ = write_all(&mut trickle, &REQUEST_MAGIC[1..], test_deadlines()).await;
        drop(trickle);
        assert!(server.await.unwrap().is_err());
        assert!(no_review.await.unwrap());

        let listener = test_listener(Role::Scheduler).await;
        let address = listener.local_addr().unwrap();
        let (kubernetes, no_review) = no_review_client();
        let binding = role_binding(Role::Scheduler, "scheduler-uid".to_owned()).unwrap();
        let server_inputs = fixture.server.clone();
        let server = tokio::spawn(async move {
            run_server_once(listener, server_inputs, binding, kubernetes, |_| async {
                vec![0, 0, 0, 1, b'a']
            })
            .await
        });
        let mut plaintext = TcpStream::connect(address).await.unwrap();
        test_write(&mut plaintext, REQUEST_MAGIC).await;
        test_shutdown(&mut plaintext).await;
        assert!(server.await.unwrap().is_err());
        assert!(no_review.await.unwrap());
    }

    #[test]
    fn malformed_multiple_and_unexpected_pem_are_rejected_without_path_disclosure() {
        let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
        let cert = fs::read_to_string(&fixture.server.certificate_path).unwrap();
        let key = fs::read_to_string(&fixture.server.private_key_path).unwrap();
        replace_integrity_file(&fixture.server.certificate_path, &format!("{cert}{cert}"));
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
        replace_integrity_file(
            &fixture.server.certificate_path,
            &format!("{cert}unexpected"),
        );
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
        replace_integrity_file(&fixture.server.certificate_path, "not pem");
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));

        replace_integrity_file(&fixture.server.certificate_path, &cert);
        fs::write(&fixture.server.private_key_path, "not pem").unwrap();
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
        fs::write(&fixture.server.private_key_path, format!("{key}{key}")).unwrap();
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
        let mismatched_key = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/controller-transport/wrong-name/key.pem"),
        )
        .unwrap();
        fs::write(&fixture.server.private_key_path, mismatched_key).unwrap();
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
        fs::write(&fixture.server.private_key_path, &key).unwrap();
        fs::set_permissions(
            &fixture.server.private_key_path,
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));

        replace_integrity_file(&fixture.client.ca_bundle_path, &cert);
        replace_integrity_file(&fixture.client.ca_bundle_path, &key);
        assert_eq!(make_client_config(&fixture.client).err(), Some(ServerError));
        fs::set_permissions(
            &fixture.client.token_path,
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            read_private_file(&fixture.client.token_path, TOKEN_BYTES_MAX as u64).err(),
            Some(ServerError)
        );
        assert!(!format!("{ServerError:?} {ServerError}").contains(fixture.root.to_str().unwrap()));
    }

    #[test]
    fn trust_bundle_is_valid_current_ordered_distinct_and_integrity_protected() {
        let fixture = TlsFixture::new(SERVER_DNS_NAME, Validity::Current).unwrap();
        let other = TlsFixture::new("wrong.kapsel-sandbox-system.svc", Validity::Current).unwrap();
        let current = fs::read_to_string(&fixture.client.ca_bundle_path).unwrap();
        let next = fs::read_to_string(&other.client.ca_bundle_path).unwrap();
        let ordered = format!("{current}{next}");
        replace_integrity_file(&fixture.client.ca_bundle_path, &ordered);
        let inputs = client_inputs(
            fixture.client.ca_bundle_path.clone(),
            trust_bundle_digest(ordered.as_bytes()),
            2,
            fixture.client.token_path.clone(),
        )
        .unwrap();
        assert!(make_client_config(&inputs).is_ok());

        let reversed = format!("{next}{current}");
        replace_integrity_file(&fixture.client.ca_bundle_path, &reversed);
        assert_eq!(make_client_config(&inputs).err(), Some(ServerError));

        let duplicate = format!("{current}{current}");
        replace_integrity_file(&fixture.client.ca_bundle_path, &duplicate);
        let duplicate_inputs = client_inputs(
            fixture.client.ca_bundle_path.clone(),
            trust_bundle_digest(duplicate.as_bytes()),
            2,
            fixture.client.token_path.clone(),
        )
        .unwrap();
        assert_eq!(
            make_client_config(&duplicate_inputs).err(),
            Some(ServerError)
        );

        let leaf = fs::read_to_string(&fixture.server.certificate_path).unwrap();
        replace_integrity_file(&fixture.client.ca_bundle_path, &leaf);
        let leaf_inputs = client_inputs(
            fixture.client.ca_bundle_path.clone(),
            trust_bundle_digest(leaf.as_bytes()),
            1,
            fixture.client.token_path.clone(),
        )
        .unwrap();
        assert_eq!(make_client_config(&leaf_inputs).err(), Some(ServerError));

        for name in ["expired-root", "future-root"] {
            let invalid = fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/controller-transport")
                    .join(name)
                    .join("ca.pem"),
            )
            .unwrap();
            replace_integrity_file(&fixture.client.ca_bundle_path, &invalid);
            let invalid_inputs = client_inputs(
                fixture.client.ca_bundle_path.clone(),
                trust_bundle_digest(invalid.as_bytes()),
                1,
                fixture.client.token_path.clone(),
            )
            .unwrap();
            assert_eq!(make_client_config(&invalid_inputs).err(), Some(ServerError));
        }

        replace_integrity_file(&fixture.client.ca_bundle_path, &current);
        fs::set_permissions(
            &fixture.client.ca_bundle_path,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let writable_inputs = client_inputs(
            fixture.client.ca_bundle_path.clone(),
            trust_bundle_digest(current.as_bytes()),
            1,
            fixture.client.token_path.clone(),
        )
        .unwrap();
        assert_eq!(
            make_client_config(&writable_inputs).err(),
            Some(ServerError)
        );

        fs::set_permissions(
            &fixture.server.certificate_path,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(make_server_config(&fixture.server).err(), Some(ServerError));
    }

    #[test]
    fn role_port_is_not_caller_selectable() {
        assert!(exact_role_port_matches(Role::Scheduler, 8082));
        assert!(exact_role_port_matches(Role::Cleanup, 8083));
        assert!(!exact_role_port_matches(Role::Scheduler, 8083));
        assert!(!exact_role_port_matches(Role::Cleanup, 8082));
    }
}
