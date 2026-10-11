//! Real Unix socket framing, peer authentication and physical work ownership.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "fail-fast physical socket fixtures"
)]

use std::{
    fs,
    os::unix::{fs::PermissionsExt as _, net::UnixStream as StdUnixStream},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
};

use ed25519_dalek::SigningKey;
use http::{Request, Response, StatusCode};
use kapsel::{
    provision_exact_grant, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperationState, ServiceApplication as Application, ServiceApproval,
    ServiceConfiguration,
};
use kube::{client::Body, Client};
use serde_json::Value;
use tokio::{net::UnixStream, runtime::Builder};
use tower_test::mock;

use super::*;
use crate::server::protocol::{ReadRequest, REQUEST_BYTES_MAX};

const SUBMIT: &[u8] = concat!(
    r#"{"version":1,"request":"submit_set_deployment_image","#,
    r#""operation_id":"socket-op"}"#,
)
.as_bytes();
const STATUS: &[u8] = concat!(
    r#"{"version":1,"request":"get_set_deployment_image_status","#,
    r#""operation_id":"socket-op"}"#,
)
.as_bytes();
const RECEIPT: &[u8] = concat!(
    r#"{"version":1,"request":"get_set_deployment_image_receipt","#,
    r#""operation_id":"socket-op"}"#,
)
.as_bytes();

#[derive(Default)]
struct ReadGate {
    entered: bool,
    released: bool,
}

type Gate = Arc<(Mutex<ReadGate>, Condvar)>;

struct ReleaseRead(Gate);

impl Drop for ReleaseRead {
    fn drop(&mut self) {
        self.0 .0.lock().unwrap().released = true;
        self.0 .1.notify_all();
    }
}

struct RecordingReads {
    calls: Arc<AtomicUsize>,
    body: Vec<u8>,
    gate: Option<Gate>,
}

impl RecordingReads {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            calls,
            body: br#"{"version":1,"status":"NOT_FOUND"}"#.to_vec(),
            gate: None,
        }
    }
}

impl ApplicationReads for RecordingReads {
    fn read(&self, request: ReadRequest) -> (Vec<u8>, ResponseClass) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            let mut state = gate.0.lock().unwrap();
            state.entered = true;
            gate.1.notify_all();
            while !state.released {
                state = gate.1.wait(state).unwrap();
            }
            drop(state);
        }
        let class = if matches!(request, ReadRequest::Receipt(_)) {
            ResponseClass::Receipt
        } else {
            ResponseClass::Ordinary
        };
        (self.body.clone(), class)
    }

    fn admitted_state(&self, _: &str) -> Result<Option<OperationState>, ServiceError> {
        Ok(None)
    }
}

struct ParkedExecution {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl ApplicationExecution for ParkedExecution {
    async fn execute(
        &mut self,
        _: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<ServiceStop, ServiceError> {
        acknowledged(ServiceAdmission::Admitted(OperationState::Requested));
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Ok(ServiceStop::Finished)
    }
}

struct ReleaseExecution(Arc<Semaphore>);

impl Drop for ReleaseExecution {
    fn drop(&mut self) {
        self.0.add_permits(1);
    }
}

#[test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "state moves into the server until physical execution retires"
)]
fn finite_socket_server_retains_the_final_admitted_execution() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let root = workspace("final-execution");
            let socket = root.join("socket");
            let listener = UnixListener::bind(&socket).unwrap();
            let entered = Arc::new(Semaphore::new(0));
            let release = Arc::new(Semaphore::new(0));
            let _release_on_unwind = ReleaseExecution(release.clone());
            let state = ServerState::new(
                RecordingReads::new(Arc::default()),
                ParkedExecution {
                    entered: entered.clone(),
                    release: release.clone(),
                },
            );
            let mut client = UnixStream::connect(&socket).await.unwrap();
            let gid = client.peer_cred().unwrap().gid();
            let mut server = tokio::spawn(serve_connections_with_state(listener, gid, state, 1));
            write_frame(&mut client, SUBMIT).await;
            assert_eq!(read_frame(&mut client).await["status"], "ADMITTED");
            entered.acquire().await.unwrap().forget();
            assert!(timeout(Duration::from_millis(20), &mut server)
                .await
                .is_err());
            release.add_permits(1);
            server.await.unwrap().unwrap();
            fs::remove_dir_all(root).unwrap();
        });
}

struct FixtureExecution {
    application: Application,
    client: Client,
    calls: Arc<AtomicUsize>,
}

impl ApplicationExecution for FixtureExecution {
    async fn execute(
        &mut self,
        id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<ServiceStop, ServiceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.application
            .select(
                &id,
                kapsel::ServiceExecution {
                    git_receiver: None,
                    kubernetes_client: Some(self.client.clone()),
                    receipt_signing: Some(([42; 32], "socket-receipt-key".into())),
                },
                acknowledged,
            )
            .await
    }
}

fn application(root: &Path) -> ServiceConfiguration {
    let key = SigningKey::from_bytes(&[41; 32]);
    let intent = ExactAuthorization {
        approved_target: Some(ApprovedTarget {
            uid: "uid-1".into(),
            resource_version: "1".into(),
        }),
        authorization_id: "socket-auth".into(),
        operation_id: "socket-op".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: format!("image@sha256:{}", "0".repeat(64)),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &intent,
        signing_seed: &[41; 32],
        signing_key_id: "socket-authorization-key",
    })
    .unwrap();
    ServiceConfiguration {
        journal_path: fs::canonicalize(root).unwrap().join("journal.sqlite3"),
        authorization_trust: vec![AuthorizationTrust {
            key_id: "socket-authorization-key".into(),
            public_key: key.verifying_key().to_bytes(),
        }],
        approvals: vec![ServiceApproval {
            signed_grant: grant,
            label: "socket action".into(),
        }],
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one wire/application composition checks acknowledgement and physical ownership"
)]
fn socket_admission_disconnect_contention_and_reads_share_one_real_application() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let root = workspace("application");
            let (service, mut receiver) = mock::pair::<Request<Body>, Response<Body>>();
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(
                Application::open(application(&root)).unwrap(),
                FixtureExecution {
                    application: Application::open(application(&root)).unwrap(),
                    client: Client::new(service, "demo"),
                    calls: calls.clone(),
                },
            );
            for (request, status) in [
                (
                    br#"{"version":1,"request":"list_approved_actions","after":null}"#.as_slice(),
                    "READY",
                ),
                (
                    br#"{"version":1,"request":"list_operation_history","after":null}"#.as_slice(),
                    "READY",
                ),
                (STATUS, "NOT_FOUND"),
                (RECEIPT, "NOT_FOUND"),
            ] {
                let response = exchange(&state, request).await;
                assert_eq!(response["status"], status);
                match serde_json::from_slice::<Value>(request).unwrap()["request"].as_str() {
                    Some("list_approved_actions") => {
                        assert_eq!(response["entries"].as_array().unwrap().len(), 1);
                        assert_eq!(response["entries"][0]["operation_id"], "socket-op");
                        assert_eq!(response["entries"][0]["approved_target"]["uid"], "uid-1");
                        assert!(response["next_cursor"].is_null());
                    },
                    Some("list_operation_history") => {
                        assert_eq!(response["entries"], serde_json::json!([]));
                    },
                    _ => {},
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(timeout(Duration::from_millis(10), receiver.next_request())
                .await
                .is_err());

            let admission = exchange(&state, SUBMIT).await;
            assert_eq!(admission["status"], "ADMITTED");
            assert_eq!(admission["phase"], "requested");
            let (request, release) = timeout(Duration::from_secs(1), receiver.next_request())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.method(), http::Method::GET);
            // The acknowledgement must refer to actual retained history, not just a callback.
            let journal = rusqlite::Connection::open_with_flags(
                root.join("journal.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            assert_eq!(
                journal
                    .query_row(
                        "SELECT operation_id FROM kubernetes_image_operations",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "socket-op"
            );
            drop(journal);

            let repeated = exchange(&state, SUBMIT).await;
            assert_eq!(repeated["status"], "ADMITTED");
            assert_eq!(repeated["phase"], "authorized");
            let observed = exchange(&state, STATUS).await;
            assert_eq!(observed["status"], "IN_PROGRESS");
            assert_eq!(observed["execution"]["disposition"], "active");
            assert_eq!(observed["execution"]["next_action"], "wait");
            assert_eq!(observed["approved_target"]["uid"], "uid-1");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(timeout(Duration::from_millis(10), receiver.next_request())
                .await
                .is_err());
            release.send_response(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(Vec::<u8>::new()))
                    .unwrap(),
            );
            timeout(Duration::from_secs(1), state.jobs.drain())
                .await
                .unwrap();
            assert_eq!(exchange(&state, STATUS).await["status"], "NOT_ATTEMPTED");
            assert_eq!(state.submission.available_permits(), 1);
            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
}

#[test]
fn unauthorized_peers_and_bad_frames_never_enter_application_reads() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(RecordingReads::new(calls.clone()), UnavailableExecution);
            for (raw, denied) in [
                (b"SECRET_UNPARSED_BODY".to_vec(), true),
                (vec![0, 0, 0], false),
                (0_u32.to_be_bytes().to_vec(), false),
                (
                    u32::try_from(REQUEST_BYTES_MAX + 1)
                        .unwrap()
                        .to_be_bytes()
                        .to_vec(),
                    false,
                ),
                ([2_u32.to_be_bytes().as_slice(), b"x"].concat(), false),
                ([1_u32.to_be_bytes().as_slice(), b"xy"].concat(), false),
            ] {
                let (mut client, server) = socket_pair();
                let gid = server
                    .peer_cred()
                    .unwrap()
                    .gid()
                    .wrapping_add(u32::from(denied));
                let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
                let _ = client.write_all(&raw).await;
                let _ = client.shutdown().await;
                assert_closed(&mut client).await;
                handler.await.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
            let bad = exchange(
                &state,
                concat!(
                    r#"{"version":1,"request":"get_set_deployment_image_status","#,
                    r#""operation_id":"op","credential":"SECRET"}"#,
                )
                .as_bytes(),
            )
            .await;
            assert_eq!(bad["error_class"], "invalid_request");
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            state.jobs.drain().await;
            drop(state);
        });
}

#[test]
fn oversized_responses_close_without_disclosing_a_partial_frame() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for (request, length) in [(STATUS, 16 * 1024 + 1), (RECEIPT, 40 * 1024 + 1)] {
                let reads = RecordingReads {
                    body: vec![b'x'; length],
                    ..RecordingReads::new(Arc::default())
                };
                let (mut client, server) = socket_pair();
                let gid = server.peer_cred().unwrap().gid();
                let handler =
                    tokio::spawn(serve_connection(server, gid, Arc::new(Mutex::new(reads))));
                write_frame(&mut client, request).await;
                assert_closed(&mut client).await;
                handler.await.unwrap();
            }
        });
}

#[test]
fn partial_progress_cannot_restart_the_real_socket_deadline() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(RecordingReads::new(calls.clone()), UnavailableExecution);
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            let deadline = Instant::now() + IO_DEADLINE + Duration::from_millis(200);
            let prefix = u32::try_from(STATUS.len()).unwrap().to_be_bytes();
            client.write_all(&prefix[..2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            client.write_all(&prefix[2..]).await.unwrap();
            client.write_all(&STATUS[..STATUS.len() / 2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(750)).await;
            client.write_all(&STATUS[STATUS.len() / 2..]).await.unwrap();
            // No EOF: completing the body must not give it a new deadline.
            timeout_at(deadline, assert_closed(&mut client))
                .await
                .unwrap();
            handler.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            state.jobs.drain().await;
            drop(state);
        });
}

#[test]
fn timed_out_storage_keeps_its_permit_until_physical_retirement() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let gate = Arc::new((Mutex::new(ReadGate::default()), Condvar::new()));
            let release = ReleaseRead(gate.clone());
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(
                RecordingReads {
                    gate: Some(gate.clone()),
                    ..RecordingReads::new(calls.clone())
                },
                UnavailableExecution,
            );
            let (mut blocked_client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let blocked = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            write_frame(&mut blocked_client, STATUS).await;
            let deadline = Instant::now() + Duration::from_secs(1);
            while !gate.0.lock().unwrap().entered {
                assert!(Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            let (mut idle_client, server) = socket_pair();
            let idle = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            idle_client.write_all(&[0]).await.unwrap();
            assert_closed(&mut idle_client).await;
            idle.await.unwrap();
            assert_closed(&mut blocked_client).await;
            blocked.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX - 1);
            drop(release);
            timeout(Duration::from_secs(1), state.jobs.drain())
                .await
                .unwrap();
            assert_eq!(state.connections.available_permits(), CONNECTIONS_MAX);
        });
}

#[test]
fn full_socket_capacity_recovers_after_one_connection_retires() {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let root = workspace("capacity");
            let socket = root.join("socket");
            let listener = UnixListener::bind(&socket).unwrap();
            let gid = socket_pair().1.peer_cred().unwrap().gid();
            let calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(RecordingReads::new(calls.clone()), UnavailableExecution);
            let server = tokio::spawn(serve_connections_with_state(
                listener,
                gid,
                state.clone(),
                CONNECTIONS_MAX + 2,
            ));
            let mut clients = Vec::new();
            for _ in 0..CONNECTIONS_MAX {
                clients.push(UnixStream::connect(&socket).await.unwrap());
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            while state.connections.available_permits() != 0 {
                assert!(Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            let mut rejected = UnixStream::connect(&socket).await.unwrap();
            assert_closed(&mut rejected).await;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            drop(clients.remove(0));
            while state.connections.available_permits() == 0 {
                assert!(Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            let mut replacement = UnixStream::connect(&socket).await.unwrap();
            write_frame(&mut replacement, STATUS).await;
            assert_eq!(read_frame(&mut replacement).await["status"], "NOT_FOUND");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            drop(clients);
            server.await.unwrap().unwrap();
            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
}

fn workspace(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("kapseld-socket-{name}-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn socket_pair() -> (UnixStream, UnixStream) {
    let (client, server) = StdUnixStream::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    (
        UnixStream::from_std(client).unwrap(),
        UnixStream::from_std(server).unwrap(),
    )
}

async fn exchange<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    state: &ServerState<R, E>,
    request: &[u8],
) -> Value {
    let (mut client, server) = socket_pair();
    let gid = server.peer_cred().unwrap().gid();
    let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
    write_frame(&mut client, request).await;
    let response = read_frame(&mut client).await;
    handler.await.unwrap();
    response
}

async fn write_frame(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn read_frame(stream: &mut UnixStream) -> Value {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(length <= 40 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["version"], 1);
    value
}

async fn assert_closed(stream: &mut UnixStream) {
    let mut bytes = Vec::new();
    match timeout(
        IO_DEADLINE + Duration::from_millis(500),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    {
        Ok(_) => {},
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
        Err(error) => panic!("unexpected socket closure: {error}"),
    }
    assert!(bytes.is_empty());
}
