//! Connection admission, task ownership and bounded authenticated socket I/O.

#[cfg(test)]
use std::future::Future;
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use kapsel::AgentRequest;
#[cfg(test)]
use kapsel::ApplicationError;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::{Mutex as AsyncMutex, Semaphore},
    task::spawn_blocking,
    time::timeout,
};

use super::{
    protocol::{
        self, invalid_request, operation_failure, render_submission, response_length_allowed,
        Command, ResponseClass, SubmissionAdmission,
    },
    ApplicationExecution, ApplicationReads,
};

pub(super) const CONNECTIONS_MAX: usize = 8;
const IO_DEADLINE: Duration = Duration::from_secs(2);

pub(super) struct ServerState<R, E> {
    reads: Arc<Mutex<R>>,
    execution: Arc<AsyncMutex<E>>,
    submission: Arc<Semaphore>,
}

impl<R, E> ServerState<R, E> {
    pub(super) fn new(reads: R, execution: E) -> Self {
        Self {
            reads: Arc::new(Mutex::new(reads)),
            execution: Arc::new(AsyncMutex::new(execution)),
            submission: Arc::new(Semaphore::new(1)),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl<R> ServerState<R, UnavailableExecution> {
    fn read_only(reads: Arc<Mutex<R>>) -> Self {
        Self {
            reads,
            execution: Arc::new(AsyncMutex::new(UnavailableExecution)),
            submission: Arc::new(Semaphore::new(1)),
        }
    }
}

impl<R, E> Clone for ServerState<R, E> {
    fn clone(&self) -> Self {
        Self {
            reads: self.reads.clone(),
            execution: self.execution.clone(),
            submission: self.submission.clone(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
struct UnavailableExecution;

#[cfg(all(test, target_os = "linux"))]
impl ApplicationExecution for UnavailableExecution {
    fn matches(&self, _request: &AgentRequest) -> bool {
        false
    }

    fn execute(
        &mut self,
        _request: AgentRequest,
    ) -> impl Future<Output = Result<(), ApplicationError>> + Send {
        std::future::ready(Err(ApplicationError::OperationFailure))
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connections<R: ApplicationReads + 'static>(
    listener: UnixListener,
    expected_gid: u32,
    reads: Arc<Mutex<R>>,
    connections: usize,
) -> io::Result<()> {
    serve_connections_with_state(
        listener,
        expected_gid,
        ServerState::read_only(reads),
        connections,
    )
    .await
}

pub(super) async fn serve_connections_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
    connections: usize,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(CONNECTIONS_MAX));
    let mut handlers = Vec::with_capacity(connections.min(CONNECTIONS_MAX));
    for _ in 0..connections {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        handlers.push(tokio::spawn(async move {
            serve_connection_with_state(stream, expected_gid, state).await;
            drop(permit);
        }));
    }
    for handler in handlers {
        handler
            .await
            .map_err(|_| io::Error::other("connection task failed"))?;
    }
    drop(state.execution.lock().await);
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) async fn serve_connections_forever<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(CONNECTIONS_MAX));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            serve_connection_with_state(stream, expected_gid, state).await;
            drop(permit);
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connection<R: ApplicationReads + 'static>(
    stream: UnixStream,
    expected_gid: u32,
    reads: Arc<Mutex<R>>,
) {
    serve_connection_with_state(stream, expected_gid, ServerState::read_only(reads)).await;
}

async fn serve_connection_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    mut stream: UnixStream,
    expected_gid: u32,
    state: ServerState<R, E>,
) {
    let Ok(credentials) = stream.peer_cred() else {
        return;
    };
    if credentials.gid() != expected_gid {
        return;
    }
    let Ok(body) = read_request_with_deadline(&mut stream).await else {
        return;
    };
    let (response, class) = dispatch_with_state(&body, &state).await;
    if !response_length_allowed(response.len(), class) {
        return;
    }
    let _ = write_response_with_deadline(&mut stream, &response).await;
}

async fn read_request_with_deadline(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    timeout(IO_DEADLINE, read_request_frame(input))
        .await
        .map_err(|_| io::Error::other("request deadline exceeded"))?
}

async fn read_request_frame(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    input.read_exact(&mut prefix).await?;
    let length =
        protocol::request_length(prefix).ok_or_else(|| io::Error::other("invalid frame length"))?;
    let mut body = vec![0_u8; length];
    input.read_exact(&mut body).await?;
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing).await? != 0 {
        return Err(io::Error::other("trailing input"));
    }
    Ok(body)
}

async fn write_response_with_deadline(
    output: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> io::Result<()> {
    timeout(IO_DEADLINE, write_response_frame(output, body))
        .await
        .map_err(|_| io::Error::other("response deadline exceeded"))?
}

async fn write_response_frame(
    output: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(body.len()).map_err(|_| io::Error::other("response too large"))?;
    output.write_all(&length.to_be_bytes()).await?;
    output.write_all(body).await?;
    output.shutdown().await
}

async fn dispatch_with_state<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    bytes: &[u8],
    state: &ServerState<R, E>,
) -> (Vec<u8>, ResponseClass) {
    let Some(command) = protocol::decode(bytes) else {
        return (invalid_request(), ResponseClass::Ordinary);
    };
    match command {
        Command::Read(request) => {
            let reads = state.reads.clone();
            spawn_blocking(move || {
                reads.lock().map_or_else(
                    |_| (operation_failure(), ResponseClass::Ordinary),
                    |reads| reads.read(request),
                )
            })
            .await
            .unwrap_or_else(|_| (operation_failure(), ResponseClass::Ordinary))
        },
        Command::Submit(request) => (
            render_submission(admit_submission(state, request)),
            ResponseClass::Ordinary,
        ),
    }
}

fn admit_submission<R, E>(state: &ServerState<R, E>, request: AgentRequest) -> SubmissionAdmission
where
    E: ApplicationExecution + 'static,
{
    let Ok(permit) = state.submission.clone().try_acquire_owned() else {
        return SubmissionAdmission::Busy;
    };
    let Ok(mut execution) = state.execution.clone().try_lock_owned() else {
        return SubmissionAdmission::OperationFailure;
    };
    if !execution.matches(&request) {
        return SubmissionAdmission::OperationFailure;
    }
    let task = tokio::spawn(async move {
        let result = execution.execute(request).await;
        drop(result);
        drop(execution);
        drop(permit);
    });
    drop(task);
    SubmissionAdmission::Accepted
}

#[cfg(test)]
mod tests {
    use kapsel::{SetDeploymentImageReceipt, SetDeploymentImageStatus};

    use super::{super::protocol::REQUEST_BYTES_MAX, *};

    #[test]
    fn shared_grammar_rejects_each_field_before_application_access() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ApplicationAccess(Arc<AtomicUsize>);
        impl ApplicationReads for ApplicationAccess {
            fn status(&self, _: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(ApplicationError::OperationFailure)
            }

            fn receipt(&self, _: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(ApplicationError::OperationFailure)
            }
        }
        impl ApplicationExecution for ApplicationAccess {
            fn matches(&self, _: &AgentRequest) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst);
                false
            }

            fn execute(
                &mut self,
                _: AgentRequest,
            ) -> impl Future<Output = Result<(), ApplicationError>> + Send {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(ApplicationError::OperationFailure))
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(
                ApplicationAccess(calls.clone()),
                ApplicationAccess(calls.clone()),
            );
            let valid = serde_json::json!({
                "request": "submit_set_deployment_image",
                "operation_id": "op-1",
                "namespace": "demo",
                "deployment": "agent-api",
                "container": "api",
                "immutable_image_digest": format!("image@sha256:{}", "0".repeat(64)),
            });
            for field in [
                "operation_id",
                "namespace",
                "deployment",
                "container",
                "immutable_image_digest",
            ] {
                let mut invalid = valid.clone();
                invalid[field] = "".into();
                let (response, _) =
                    dispatch_with_state(invalid.to_string().as_bytes(), &state).await;
                assert_eq!(response, invalid_request(), "{field}");
                assert_eq!(state.submission.available_permits(), 1);
            }
            for request in [
                "get_set_deployment_image_status",
                "get_set_deployment_image_receipt",
            ] {
                let invalid = serde_json::json!({"request": request, "operation_id": ""});
                let (response, _) =
                    dispatch_with_state(invalid.to_string().as_bytes(), &state).await;
                assert_eq!(response, invalid_request());
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let (response, _) = dispatch_with_state(valid.to_string().as_bytes(), &state).await;
            assert_eq!(response, operation_failure());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn frame_reader_enforces_length_body_eof_and_trailing_bounds() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for (bytes, accepted) in [
                ([1_u32.to_be_bytes().as_slice(), b"x"].concat(), true),
                ([0_u32.to_be_bytes().as_slice(), b""].concat(), false),
                (
                    [
                        u32::try_from(REQUEST_BYTES_MAX + 1)
                            .unwrap()
                            .to_be_bytes()
                            .as_slice(),
                        b"",
                    ]
                    .concat(),
                    false,
                ),
                ([2_u32.to_be_bytes().as_slice(), b"x"].concat(), false),
                ([1_u32.to_be_bytes().as_slice(), b"xy"].concat(), false),
            ] {
                let (mut client, mut server) = tokio::io::duplex(REQUEST_BYTES_MAX + 8);
                client.write_all(&bytes).await.unwrap();
                client.shutdown().await.unwrap();
                assert_eq!(read_request_frame(&mut server).await.is_ok(), accepted);
            }
            let body = vec![b'x'; REQUEST_BYTES_MAX];
            let (mut client, mut server) = tokio::io::duplex(REQUEST_BYTES_MAX + 8);
            client
                .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            client.write_all(&body).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(read_request_frame(&mut server).await.unwrap(), body);
        });
    }

    #[test]
    fn aggregate_read_and_write_deadlines_abandon_stalled_io() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_idle_writer, mut idle_reader) = tokio::io::duplex(1);
            assert!(read_request_with_deadline(&mut idle_reader).await.is_err());

            let (mut stalled_writer, mut stalled_reader) = tokio::io::duplex(1);
            assert!(
                write_response_with_deadline(&mut stalled_writer, b"bounded")
                    .await
                    .is_err()
            );
            drop(stalled_writer);
            let mut partial = Vec::new();
            stalled_reader.read_to_end(&mut partial).await.unwrap();
            let complete = [7_u32.to_be_bytes().as_slice(), b"bounded"].concat();
            assert!(!partial.is_empty());
            assert_ne!(partial, complete);
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "linux_tests.rs"]
mod linux_tests;
