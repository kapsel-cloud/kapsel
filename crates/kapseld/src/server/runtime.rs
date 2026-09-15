//! Connection admission, task ownership and bounded authenticated socket I/O.

#[cfg(test)]
mod admission_tests;
mod jobs;
#[cfg(all(test, target_os = "linux"))]
mod retirement_tests;

use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use kapsel::{ServiceAdmission, ServiceError};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::{oneshot, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
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
    connections: Arc<Semaphore>,
    jobs: Arc<jobs::Jobs>,
    selected: Arc<Mutex<Weak<Selection>>>,
    #[cfg(test)]
    after_failed_acquisition: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct Selection {
    operation_id: String,
    _permit: OwnedSemaphorePermit,
}

impl<R, E> ServerState<R, E> {
    pub(super) fn new(reads: R, execution: E) -> Self {
        Self {
            reads: Arc::new(Mutex::new(reads)),
            execution: Arc::new(AsyncMutex::new(execution)),
            submission: Arc::new(Semaphore::new(1)),
            connections: Arc::new(Semaphore::new(CONNECTIONS_MAX)),
            jobs: Arc::new(jobs::Jobs::new()),
            selected: Arc::new(Mutex::new(Weak::new())),
            #[cfg(test)]
            after_failed_acquisition: None,
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
            connections: Arc::new(Semaphore::new(CONNECTIONS_MAX)),
            jobs: Arc::new(jobs::Jobs::new()),
            selected: Arc::new(Mutex::new(Weak::new())),
            after_failed_acquisition: None,
        }
    }
}

impl<R, E> Clone for ServerState<R, E> {
    fn clone(&self) -> Self {
        Self {
            reads: self.reads.clone(),
            execution: self.execution.clone(),
            submission: self.submission.clone(),
            connections: self.connections.clone(),
            jobs: self.jobs.clone(),
            selected: self.selected.clone(),
            #[cfg(test)]
            after_failed_acquisition: self.after_failed_acquisition.clone(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
struct UnavailableExecution;

#[cfg(all(test, target_os = "linux"))]
impl ApplicationExecution for UnavailableExecution {
    fn execute(
        &mut self,
        _operation_id: String,
        _acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> impl Future<Output = Result<(), ServiceError>> + Send {
        std::future::ready(Err(ServiceError::OperationFailure))
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

#[cfg(any(not(target_os = "linux"), test, feature = "test-harness"))]
pub(super) async fn serve_connections_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
    connections: usize,
) -> io::Result<()> {
    serve(
        listener,
        expected_gid,
        state,
        Some(connections),
        std::future::pending(),
    )
    .await
}

#[cfg(target_os = "linux")]
pub(super) async fn serve_until_stopped<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
    limit: Option<usize>,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    serve(listener, expected_gid, state, limit, stop).await
}

async fn serve<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
    limit: Option<usize>,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    tokio::pin!(stop);
    let mut handlers = JoinSet::new();
    let mut accepted = 0;
    let mut failed_handler = false;
    let mut result = loop {
        if limit.is_some_and(|limit| accepted >= limit) {
            break Ok(());
        }
        let stream = tokio::select! {
            biased;
            () = &mut stop => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => break Err(error),
            },
        };
        if limit.is_some() {
            accepted += 1;
        }
        while let Some(handler) = handlers.try_join_next() {
            failed_handler |= handler.is_err();
        }
        let Ok(permit) = state.connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        handlers.spawn(async move {
            serve_admitted_connection(stream, expected_gid, state, Arc::new(permit)).await;
        });
    };
    drop(listener);
    while let Some(handler) = handlers.join_next().await {
        failed_handler |= handler.is_err();
    }
    if failed_handler && result.is_ok() {
        result = Err(io::Error::other("connection task failed"));
    }
    // Keep the current-thread reactor driven until physical storage ownership is gone.
    state.jobs.drain().await;
    result
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connection<R: ApplicationReads + 'static>(
    stream: UnixStream,
    expected_gid: u32,
    reads: Arc<Mutex<R>>,
) {
    serve_connection_with_state(stream, expected_gid, ServerState::read_only(reads)).await;
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connection_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    stream: UnixStream,
    expected_gid: u32,
    state: ServerState<R, E>,
) {
    let Ok(permit) = state.connections.clone().try_acquire_owned() else {
        return;
    };
    serve_admitted_connection(stream, expected_gid, state, Arc::new(permit)).await;
}

async fn serve_admitted_connection<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    mut stream: UnixStream,
    expected_gid: u32,
    state: ServerState<R, E>,
    connection: Arc<OwnedSemaphorePermit>,
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
    let deadline = Instant::now() + IO_DEADLINE;
    let (response, class) = dispatch_admitted(&body, &state, connection.clone(), deadline).await;
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

#[cfg(test)]
async fn dispatch_with_state<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    bytes: &[u8],
    state: &ServerState<R, E>,
) -> (Vec<u8>, ResponseClass) {
    let Ok(permit) = state.connections.clone().try_acquire_owned() else {
        return (Vec::new(), ResponseClass::Ordinary);
    };
    dispatch_admitted(bytes, state, Arc::new(permit), Instant::now() + IO_DEADLINE).await
}

async fn dispatch_admitted<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    bytes: &[u8],
    state: &ServerState<R, E>,
    connection: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
) -> (Vec<u8>, ResponseClass) {
    let Some(command) = protocol::decode(bytes) else {
        return (invalid_request(), ResponseClass::Ordinary);
    };
    match command {
        Command::Read(request) => {
            let reads = state.reads.clone();
            let (response, received) = oneshot::channel();
            if state
                .jobs
                .spawn(connection, None, move || {
                    let result = reads.lock().map_or_else(
                        |_| (operation_failure(), ResponseClass::Ordinary),
                        |reads| reads.read(request),
                    );
                    let _ = response.send(result);
                })
                .is_err()
            {
                return (Vec::new(), ResponseClass::Ordinary);
            }
            match timeout_at(deadline, received).await {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => (operation_failure(), ResponseClass::Ordinary),
                Err(_) => (Vec::new(), ResponseClass::Ordinary),
            }
        },
        Command::Submit(request) => (
            render_submission(admit_submission(state, request, connection, deadline).await),
            ResponseClass::Ordinary,
        ),
    }
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "moved selection leases must span the complete probe decision"
)]
async fn admit_submission<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    state: &ServerState<R, E>,
    operation_id: String,
    connection: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
) -> SubmissionAdmission {
    let (response, received) = oneshot::channel();
    // Hold publication exclusion while acquiring or pinning the current generation. A probe's
    // strong reference retains its permit, so completion cannot replace that generation mid-read.
    let selection = {
        let Ok(mut selected) = state.selected.lock() else {
            return SubmissionAdmission::Error(ServiceError::OperationFailure);
        };
        if let Ok(permit) = state.submission.clone().try_acquire_owned() {
            let selection = Arc::new(Selection {
                operation_id: operation_id.clone(),
                _permit: permit,
            });
            *selected = Arc::downgrade(&selection);
            Ok(selection)
        } else {
            #[cfg(test)]
            if let Some(hook) = &state.after_failed_acquisition {
                hook();
            }
            Err(selected.upgrade())
        }
    };
    let spawned = match selection {
        Ok(selection) => {
            let execution = state.execution.clone();
            let runtime = tokio::runtime::Handle::current();
            state.jobs.spawn(connection, Some(selection), move || {
                let mut response = Some(response);
                let result = runtime.block_on(async {
                    let mut execution = execution.lock().await;
                    execution
                        .execute(operation_id, |decision| {
                            if let Some(response) = response.take() {
                                let _ = response.send(SubmissionAdmission::Decided(decision));
                            }
                        })
                        .await
                });
                if let Some(response) = response {
                    let _ = response.send(SubmissionAdmission::Error(
                        result.err().unwrap_or(ServiceError::OperationFailure),
                    ));
                }
            })
        },
        Err(pinned) => {
            let reads = state.reads.clone();
            let selected = state.selected.clone();
            // The supervisor and physical closure both retain the probed generation.
            state.jobs.spawn(connection, pinned.clone(), move || {
                let result = reads
                    .lock()
                    .map_err(|_| ServiceError::OperationFailure)
                    .and_then(|reads| reads.admitted_state(&operation_id));
                let current = selected.lock().map(|selected| selected.upgrade());
                let decision = match (result, current) {
                    (Ok(Some(phase)), _) => {
                        SubmissionAdmission::Decided(ServiceAdmission::Admitted(phase))
                    },
                    (Err(error), _) => SubmissionAdmission::Error(error),
                    // Final physical retirement can race failed acquisition and weak upgrade.
                    // Without an original pin, a matching successor may have come and gone.
                    (Ok(None), _) if pinned.is_none() => SubmissionAdmission::Indeterminate,
                    (Ok(None), Ok(current)) => {
                        if pinned
                            .as_ref()
                            .is_some_and(|owner| owner.operation_id == operation_id)
                            || current
                                .as_ref()
                                .is_some_and(|owner| owner.operation_id == operation_id)
                        {
                            SubmissionAdmission::Indeterminate
                        } else {
                            SubmissionAdmission::Decided(ServiceAdmission::Busy)
                        }
                    },
                    (Ok(None), Err(_)) => {
                        SubmissionAdmission::Error(ServiceError::OperationFailure)
                    },
                };
                let _ = response.send(decision);
                drop(pinned);
            })
        },
    };
    if spawned.is_err() {
        return SubmissionAdmission::Error(ServiceError::OperationFailure);
    }
    match timeout_at(deadline, received).await {
        Ok(Ok(decision)) => decision,
        Ok(Err(_)) => SubmissionAdmission::Error(ServiceError::OperationFailure),
        Err(_) => SubmissionAdmission::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::protocol::{ReadRequest, REQUEST_BYTES_MAX},
        *,
    };

    #[test]
    fn invalid_requests_are_rejected_before_application_access() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ApplicationAccess(Arc<AtomicUsize>);
        impl ApplicationReads for ApplicationAccess {
            fn read(&self, _: ReadRequest) -> (Vec<u8>, ResponseClass) {
                self.0.fetch_add(1, Ordering::SeqCst);
                (operation_failure(), ResponseClass::Ordinary)
            }

            fn admitted_state(
                &self,
                _: &str,
            ) -> Result<Option<kapsel::OperationState>, ServiceError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(ServiceError::OperationFailure)
            }
        }
        impl ApplicationExecution for ApplicationAccess {
            fn execute(
                &mut self,
                _: String,
                _: impl FnOnce(ServiceAdmission) + Send,
            ) -> impl Future<Output = Result<(), ServiceError>> + Send {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(ServiceError::OperationFailure))
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
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
            let valid_body = valid.to_string();
            for duplicate in [
                r#""request":"submit_set_deployment_image""#,
                r#""\u006fperation_id":"op-1""#,
            ] {
                let invalid = format!("{{{duplicate},{}", &valid_body[1..]);
                let (response, class) = dispatch_with_state(invalid.as_bytes(), &state).await;
                assert_eq!(
                    response,
                    br#"{"version":1,"status":"ERROR","error_class":"invalid_request"}"#
                );
                assert!(matches!(class, ResponseClass::Ordinary));
                assert_eq!(state.submission.available_permits(), 1);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let valid =
                br#"{"version":1,"request":"submit_set_deployment_image","operation_id":"op-1"}"#;
            let (response, _) = dispatch_with_state(valid, &state).await;
            assert_eq!(response, operation_failure());
            state.jobs.drain().await;
            drop(state);
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
