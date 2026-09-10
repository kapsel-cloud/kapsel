//! Socket composition regressions crossing the production runtime.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled Linux fixtures fail the socket contract tests immediately"
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
use kapsel::{
    provision_exact_grant, AgentRequest, Application, AuthorizationTrust, ExactAuthorization,
    GrantProvisioning, OperatorConfiguration, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    TargetRejection,
};
use tokio::{net::UnixStream, runtime::Builder};
use tower_test::mock;

use super::{super::protocol::REQUEST_BYTES_MAX, *};

#[derive(Default)]
struct TestReads {
    status_calls: Arc<AtomicUsize>,
    receipt_calls: Arc<AtomicUsize>,
}

impl ApplicationReads for TestReads {
    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        self.status_calls.fetch_add(1, Ordering::Relaxed);
        match operation_id {
            "in-progress" => Ok(SetDeploymentImageStatus::InProgress),
            "deployment-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                TargetRejection::DeploymentNotFound,
            )),
            "container-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                TargetRejection::ContainerNotFound,
            )),
            "invalid-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                TargetRejection::InvalidTarget,
            )),
            "succeeded" => Ok(SetDeploymentImageStatus::Succeeded),
            "failed" => Ok(SetDeploymentImageStatus::Failed),
            "unknown" => Ok(SetDeploymentImageStatus::Unknown),
            "operation-error" => Err(ApplicationError::OperationFailure),
            _ => Ok(SetDeploymentImageStatus::NotFound),
        }
    }

    fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        self.receipt_calls.fetch_add(1, Ordering::Relaxed);
        match operation_id {
            "not-ready" => Ok(SetDeploymentImageReceipt::NotReady),
            "ready" => Ok(SetDeploymentImageReceipt::Ready {
                bytes: vec![0x00, 0xab, 0xff],
                sha256: String::from(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ),
            }),
            "operation-error" => Err(ApplicationError::OperationFailure),
            _ => Ok(SetDeploymentImageReceipt::NotFound),
        }
    }
}

struct ReadyReads {
    bytes: Vec<u8>,
    sha256: String,
}

impl ApplicationReads for ReadyReads {
    fn status(&self, _operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        Ok(SetDeploymentImageStatus::NotFound)
    }

    fn receipt(&self, _operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        Ok(SetDeploymentImageReceipt::Ready {
            bytes: self.bytes.clone(),
            sha256: self.sha256.clone(),
        })
    }
}

#[derive(Default)]
struct BlockingState {
    started: bool,
    release: bool,
}

struct BlockingReads {
    gate: Arc<(Mutex<BlockingState>, Condvar)>,
    status_calls: Arc<AtomicUsize>,
}

impl ApplicationReads for BlockingReads {
    fn status(&self, _operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        self.status_calls.fetch_add(1, Ordering::Relaxed);
        let (lock, condition) = &*self.gate;
        let mut state = lock.lock().unwrap();
        state.started = true;
        condition.notify_all();
        while !state.release {
            state = condition.wait(state).unwrap();
        }
        drop(state);
        Ok(SetDeploymentImageStatus::NotFound)
    }

    fn receipt(&self, _operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        Ok(SetDeploymentImageReceipt::NotFound)
    }
}

struct BlockingExecution {
    started: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl ApplicationExecution for BlockingExecution {
    fn matches(&self, _request: &AgentRequest) -> bool {
        true
    }

    async fn execute(&mut self, _request: AgentRequest) -> Result<(), ApplicationError> {
        self.started.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|_| ApplicationError::OperationFailure)?
            .forget();
        Ok(())
    }
}

struct CountingExecution<E> {
    inner: E,
    matches_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
}

impl<E: ApplicationExecution> ApplicationExecution for CountingExecution<E> {
    fn matches(&self, request: &AgentRequest) -> bool {
        self.matches_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.matches(request)
    }

    async fn execute(&mut self, request: AgentRequest) -> Result<(), ApplicationError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(request).await
    }
}

#[test]
fn finite_server_waits_for_the_final_accepted_execution() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root =
            std::env::temp_dir().join(format!("kapseld-final-execution-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let socket = root.join("kapseld.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let state = ServerState::new(
            TestReads::default(),
            BlockingExecution {
                started: started.clone(),
                release: release.clone(),
            },
        );
        let mut client = UnixStream::connect(&socket).await.unwrap();
        let expected_gid = client.peer_cred().unwrap().gid();
        let mut server = tokio::spawn(serve_connections_with_state(
            listener,
            expected_gid,
            state,
            1,
        ));

        write_frame_and_close(&mut client, submit_request().as_bytes()).await;
        assert_eq!(read_frame(&mut client).await, br#"{"status":"ACCEPTED"}"#);
        started.acquire().await.unwrap().forget();
        assert!(timeout(Duration::from_millis(20), &mut server)
            .await
            .is_err());

        release.add_permits(1);
        server.await.unwrap().unwrap();
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn authenticated_status_not_found_crosses_one_complete_frame() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (client, server) = StdUnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        let mut client = UnixStream::from_std(client).unwrap();
        let server = UnixStream::from_std(server).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        let expected_gid = server.peer_cred().unwrap().gid();
        let handler = tokio::spawn(serve_connection(server, expected_gid, reads));
        let request = br#"{"request":"get_set_deployment_image_status","operation_id":"missing"}"#;
        write_frame_and_close(&mut client, request).await;
        assert_eq!(read_frame(&mut client).await, br#"{"status":"NOT_FOUND"}"#);
        handler.await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn authenticated_status_and_receipt_projection_matrix_crosses_exact_frames() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let status_calls = Arc::new(AtomicUsize::new(0));
        let receipt_calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: status_calls.clone(),
            receipt_calls: receipt_calls.clone(),
        }));
        for (operation_id, expected) in [
            ("not-found", r#"{"status":"NOT_FOUND"}"#),
            ("in-progress", r#"{"status":"IN_PROGRESS"}"#),
            (
                "deployment-rejection",
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
            ),
            (
                "container-rejection",
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"CONTAINER_NOT_FOUND"}"#,
            ),
            (
                "invalid-rejection",
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"INVALID_TARGET"}"#,
            ),
            ("succeeded", r#"{"status":"SUCCEEDED"}"#),
            ("failed", r#"{"status":"FAILED"}"#),
            ("unknown", r#"{"status":"UNKNOWN"}"#),
            (
                "operation-error",
                r#"{"status":"ERROR","error_class":"operation_failure"}"#,
            ),
        ] {
            let request = format!(
                concat!(
                    "{{\"request\":\"get_set_deployment_image_status\",",
                    "\"operation_id\":\"{operation_id}\"}}"
                ),
                operation_id = operation_id
            );
            assert_socket_response(reads.clone(), request.as_bytes(), expected.as_bytes()).await;
        }
        for (operation_id, expected) in [
            ("not-found", r#"{"status":"NOT_FOUND"}"#),
            ("not-ready", r#"{"status":"NOT_READY"}"#),
            (
                "ready",
                concat!(
                    "{\"status\":\"READY\",\"receipt_hex\":\"00abff\",",
                    "\"receipt_sha256\":\"",
                    r#"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
                ),
            ),
            (
                "operation-error",
                r#"{"status":"ERROR","error_class":"operation_failure"}"#,
            ),
        ] {
            let request = format!(
                concat!(
                    "{{\"request\":\"get_set_deployment_image_receipt\",",
                    "\"operation_id\":\"{operation_id}\"}}"
                ),
                operation_id = operation_id
            );
            assert_socket_response(reads.clone(), request.as_bytes(), expected.as_bytes()).await;
        }
        assert_eq!(status_calls.load(Ordering::Relaxed), 9);
        assert_eq!(receipt_calls.load(Ordering::Relaxed), 4);
    });
}

#[test]
fn over_limit_receipt_projection_closes_without_disclosure() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let reads = Arc::new(Mutex::new(ReadyReads {
            bytes: vec![0x55; 20 * 1024],
            sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        }));
        let handler = tokio::spawn(serve_connection(server, gid, reads));
        write_frame_and_close(
            &mut client,
            br#"{"request":"get_set_deployment_image_receipt","operation_id":"receipt-op"}"#,
        )
        .await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        handler.await.unwrap();
    });
}

#[test]
fn socket_status_and_receipt_compose_real_application_reads_without_kubernetes() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-application-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (application, mut kubernetes) = application(&root);
        let reads = Arc::new(Mutex::new(application));
        for (request, expected) in [
            (
                concat!(
                    r#"{"request":"get_set_deployment_image_status","#,
                    r#""operation_id":"socket-op-1"}"#
                )
                .as_bytes(),
                br#"{"status":"NOT_FOUND"}"#.as_slice(),
            ),
            (
                concat!(
                    r#"{"request":"get_set_deployment_image_receipt","#,
                    r#""operation_id":"socket-op-1"}"#
                )
                .as_bytes(),
                br#"{"status":"NOT_FOUND"}"#.as_slice(),
            ),
        ] {
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection(server, gid, reads.clone()));
            write_frame_and_close(&mut client, request).await;
            assert_eq!(read_frame(&mut client).await, expected);
            handler.await.unwrap();
        }
        assert!(
            timeout(Duration::from_millis(10), kubernetes.next_request())
                .await
                .is_err()
        );
        drop(reads);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn authenticated_submit_accepts_one_real_application_execution() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root =
            std::env::temp_dir().join(format!("kapseld-accepted-execution-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let state = ServerState::new(projection, execution);

        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
        write_frame_and_close(&mut client, submit_request().as_bytes()).await;
        assert_eq!(read_frame(&mut client).await, br#"{"status":"ACCEPTED"}"#);
        handler.await.unwrap();

        let (_, response) = timeout(Duration::from_secs(1), kubernetes.next_request())
            .await
            .unwrap()
            .unwrap();
        response.send_response(
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(Vec::<u8>::new()))
                .unwrap(),
        );

        wait_for_not_attempted(&state, gid).await;

        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn overlapping_submit_is_busy_without_a_second_application_attempt() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-busy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let matches_calls = Arc::new(AtomicUsize::new(0));
        let execute_calls = Arc::new(AtomicUsize::new(0));
        let state = ServerState::new(
            projection,
            CountingExecution {
                inner: execution,
                matches_calls: matches_calls.clone(),
                execute_calls: execute_calls.clone(),
            },
        );

        let (mut first_client, first_server) = socket_pair();
        let gid = first_server.peer_cred().unwrap().gid();
        let first_handler = tokio::spawn(serve_connection_with_state(
            first_server,
            gid,
            state.clone(),
        ));
        write_frame_and_close(&mut first_client, submit_request().as_bytes()).await;
        assert_eq!(
            read_frame(&mut first_client).await,
            br#"{"status":"ACCEPTED"}"#
        );
        first_handler.await.unwrap();
        let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(matches_calls.load(Ordering::SeqCst), 1);
        assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

        let (mut second_client, second_server) = socket_pair();
        let second_handler = tokio::spawn(serve_connection_with_state(
            second_server,
            gid,
            state.clone(),
        ));
        write_frame_and_close(&mut second_client, submit_request().as_bytes()).await;
        assert_eq!(
            read_frame(&mut second_client).await,
            br#"{"status":"BUSY"}"#
        );
        second_handler.await.unwrap();
        assert_eq!(matches_calls.load(Ordering::SeqCst), 1);
        assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
        assert!(
            timeout(Duration::from_millis(10), kubernetes.next_request())
                .await
                .is_err()
        );

        send_not_found(provider_response);
        wait_for_not_attempted(&state, gid).await;
        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn reconnect_status_remains_available_while_execution_waits_on_provider() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root =
            std::env::temp_dir().join(format!("kapseld-concurrent-status-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let state = ServerState::new(projection, execution);

        let (mut submit_client, submit_server) = socket_pair();
        let gid = submit_server.peer_cred().unwrap().gid();
        let submit_handler = tokio::spawn(serve_connection_with_state(
            submit_server,
            gid,
            state.clone(),
        ));
        write_frame_and_close(&mut submit_client, submit_request().as_bytes()).await;
        assert_eq!(
            read_frame(&mut submit_client).await,
            br#"{"status":"ACCEPTED"}"#
        );
        submit_handler.await.unwrap();
        let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
            .await
            .unwrap()
            .unwrap();

        let (mut status_client, status_server) = socket_pair();
        let status_handler = tokio::spawn(serve_connection_with_state(
            status_server,
            gid,
            state.clone(),
        ));
        write_frame_and_close(
            &mut status_client,
            br#"{"request":"get_set_deployment_image_status","operation_id":"socket-op-1"}"#,
        )
        .await;
        assert_eq!(
            timeout(Duration::from_secs(1), read_frame(&mut status_client))
                .await
                .unwrap(),
            br#"{"status":"IN_PROGRESS"}"#
        );
        status_handler.await.unwrap();

        send_not_found(provider_response);
        wait_for_not_attempted(&state, gid).await;
        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn client_disconnect_before_response_does_not_cancel_execution() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-disconnect-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let state = ServerState::new(projection, execution);

        let (mut submit_client, submit_server) = socket_pair();
        let gid = submit_server.peer_cred().unwrap().gid();
        let submit_handler = tokio::spawn(serve_connection_with_state(
            submit_server,
            gid,
            state.clone(),
        ));
        write_frame_and_close(&mut submit_client, submit_request().as_bytes()).await;
        drop(submit_client);
        submit_handler.await.unwrap();

        let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
            .await
            .unwrap()
            .unwrap();
        send_not_found(provider_response);
        wait_for_not_attempted(&state, gid).await;

        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn retry_race_after_apply_started_keeps_one_provider_mutation() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-replay-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let state = ServerState::new(projection, execution);
        let gid = submit_and_read(&state).await.0;

        let (target_request, target_response) =
            timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(target_request.method(), http::Method::GET);
        send_deployment(target_response, &deployment("1", 1, false));

        let (apply_request, apply_response) =
            timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(apply_request.method(), http::Method::PATCH);
        send_deployment(apply_response, &deployment("2", 2, false));

        let (observation_request, observation_response) =
            timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(observation_request.method(), http::Method::GET);
        let (_, competing_response) = submit_and_read(&state).await;
        assert_eq!(competing_response, br#"{"status":"BUSY"}"#);
        assert!(
            timeout(Duration::from_millis(10), kubernetes.next_request())
                .await
                .is_err()
        );
        send_deployment(observation_response, &deployment("3", 2, true));
        wait_for_status(&state, gid, br#"{"status":"SUCCEEDED"}"#).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let (_, replay_response) = submit_and_read(&state).await;
            if replay_response == br#"{"status":"ACCEPTED"}"# {
                break;
            }
            assert_eq!(replay_response, br#"{"status":"BUSY"}"#);
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while state.submission.available_permits() == 0 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            timeout(Duration::from_millis(20), kubernetes.next_request())
                .await
                .is_err()
        );

        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn grant_mismatched_submit_is_bounded_without_execution() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-mismatch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let (projection, execution, mut kubernetes) = applications(&root);
        let state = ServerState::new(projection, execution);

        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
        let mismatched =
            submit_request().replace("\"container\":\"api\"", "\"container\":\"other\"");
        write_frame_and_close(&mut client, mismatched.as_bytes()).await;
        assert_eq!(
            read_frame(&mut client).await,
            br#"{"status":"ERROR","error_class":"operation_failure"}"#
        );
        handler.await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), kubernetes.next_request())
                .await
                .is_err()
        );

        drop(state);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn peer_denial_happens_before_body_read_or_application_access() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (mut client, server) = socket_pair();
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        let denied_gid = server.peer_cred().unwrap().gid().wrapping_add(1);
        let handler = tokio::spawn(serve_connection(server, denied_gid, reads));
        let _ = client.write_all(b"SECRET_UNPARSED_BODY").await;
        let mut response = Vec::new();
        match client.read_to_end(&mut response).await {
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
            Err(error) => panic!("unexpected denied-peer read failure: {error}"),
        }
        handler.await.unwrap();
        assert!(response.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn incomplete_zero_oversized_and_trailing_frames_close_without_application_access() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        for bytes in [
            vec![0_u8, 0, 0],
            0_u32.to_be_bytes().to_vec(),
            u32::try_from(REQUEST_BYTES_MAX + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            [1_u32.to_be_bytes().as_slice(), b""].concat(),
            [1_u32.to_be_bytes().as_slice(), b"xy"].concat(),
        ] {
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection(server, gid, reads.clone()));
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            handler.await.unwrap();
            assert!(response.is_empty());
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn missing_write_half_close_expires_under_the_complete_frame_deadline() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        let handler = tokio::spawn(serve_connection(server, gid, reads));
        let request = br#"{"request":"get_set_deployment_image_status","operation_id":"slow"}"#;
        client
            .write_all(&u32::try_from(request.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        client.write_all(request).await.unwrap();
        tokio::time::sleep(IO_DEADLINE + Duration::from_millis(50)).await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        handler.await.unwrap();
        assert!(response.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn staged_prefix_body_and_eof_progress_share_one_aggregate_deadline() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        let handler = tokio::spawn(serve_connection(server, gid, reads));
        let request = br#"{"request":"get_set_deployment_image_status","operation_id":"slow"}"#;
        let prefix = u32::try_from(request.len()).unwrap().to_be_bytes();
        client.write_all(&prefix[..2]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        client.write_all(&prefix[2..]).await.unwrap();
        client
            .write_all(&request[..request.len() / 2])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(750)).await;
        client
            .write_all(&request[request.len() / 2..])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = client.shutdown().await;
        let mut response = Vec::new();
        match client.read_to_end(&mut response).await {
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
            Err(error) => panic!("unexpected staged-frame read failure: {error}"),
        }
        handler.await.unwrap();
        assert!(response.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn blocked_application_read_does_not_prevent_another_frame_deadline() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let gate = Arc::new((Mutex::new(BlockingState::default()), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(BlockingReads {
            gate: gate.clone(),
            status_calls: calls.clone(),
        }));

        let (mut blocked_client, blocked_server) = socket_pair();
        let gid = blocked_server.peer_cred().unwrap().gid();
        let blocked_handler = tokio::spawn(serve_connection(blocked_server, gid, reads.clone()));
        write_frame_and_close(
            &mut blocked_client,
            br#"{"request":"get_set_deployment_image_status","operation_id":"blocked"}"#,
        )
        .await;
        let started_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            if gate.0.lock().unwrap().started {
                break;
            }
            assert!(tokio::time::Instant::now() < started_deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let (mut idle_client, idle_server) = socket_pair();
        let idle_handler = tokio::spawn(serve_connection(idle_server, gid, reads));
        idle_client.write_all(&[0_u8]).await.unwrap();
        let mut idle_response = Vec::new();
        let idle_result = timeout(
            IO_DEADLINE + Duration::from_millis(500),
            idle_client.read_to_end(&mut idle_response),
        )
        .await
        .unwrap();
        assert!(
            idle_result.is_ok()
                || idle_result.unwrap_err().kind() == io::ErrorKind::ConnectionReset
        );
        idle_handler.await.unwrap();
        assert!(idle_response.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        {
            let mut state = gate.0.lock().unwrap();
            state.release = true;
            drop(state);
            gate.1.notify_all();
        }
        assert_eq!(
            read_frame(&mut blocked_client).await,
            br#"{"status":"NOT_FOUND"}"#
        );
        blocked_handler.await.unwrap();
    });
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table keeps the authenticated hostile-request matrix explicit"
)]
fn authenticated_hostile_json_and_submit_matrix_has_no_application_effect() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let status_calls = Arc::new(AtomicUsize::new(0));
        let receipt_calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: status_calls.clone(),
            receipt_calls: receipt_calls.clone(),
        }));
        let invalid = br#"{"status":"ERROR","error_class":"invalid_request"}"#;
        let immutable_image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        for request in [
            vec![0xff],
            b"{".to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","#,
                r#""operation_id":"a"}{}"#
            )
            .as_bytes()
            .to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                r#""operation_id":"SECRET_DUPLICATE"}"#
            )
            .as_bytes()
            .to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","#,
                r#""operation_id":"a","unknown":1}"#
            )
            .as_bytes()
            .to_vec(),
            br#"{"request":"get_set_deployment_image_status"}"#.to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","#,
                r#""operation_id":null}"#
            )
            .as_bytes()
            .to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","#,
                r#""operation_id":1}"#
            )
            .as_bytes()
            .to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                r#""namespace":"demo"}"#
            )
            .as_bytes()
            .to_vec(),
            concat!(
                r#"{"request":"get_set_deployment_image_receipt","operation_id":"a","#,
                r#""container":"api"}"#
            )
            .as_bytes()
            .to_vec(),
            br#"{"request":"unknown","operation_id":"a"}"#.to_vec(),
            format!(
                concat!(
                    r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                    r#""deployment":"agent-api","container":"api","#,
                    r#""immutable_image_digest":"{immutable_image}"}}"#
                ),
                immutable_image = immutable_image
            )
            .into_bytes(),
            format!(
                concat!(
                    r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                    r#""namespace":null,"deployment":"agent-api","container":"api","#,
                    r#""immutable_image_digest":"{immutable_image}"}}"#
                ),
                immutable_image = immutable_image
            )
            .into_bytes(),
            concat!(
                r#"{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                r#""immutable_image_digest":"registry.example/agent-api:latest"}"#
            )
            .as_bytes()
            .to_vec(),
            format!(
                concat!(
                    r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                    r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                    r#""immutable_image_digest":"{immutable_image}","retry":true}}"#
                ),
                immutable_image = immutable_image
            )
            .into_bytes(),
        ] {
            assert_socket_response(reads.clone(), &request, invalid).await;
        }
        let submit = format!(
            concat!(
                r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                r#""immutable_image_digest":"{immutable_image}"}}"#
            ),
            immutable_image = immutable_image
        );
        assert_socket_response(
            reads,
            submit.as_bytes(),
            br#"{"status":"ERROR","error_class":"operation_failure"}"#,
        )
        .await;
        assert_eq!(status_calls.load(Ordering::Relaxed), 0);
        assert_eq!(receipt_calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn saturation_closes_ninth_and_new_connection_succeeds_after_permit_recovery() {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let root = std::env::temp_dir().join(format!("kapseld-cap-{}", std::process::id()));
        let _ = std::fs::remove_file(&root);
        let listener = UnixListener::bind(&root).unwrap();
        let gid = socket_pair().1.peer_cred().unwrap().gid();
        let calls = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(Mutex::new(TestReads {
            status_calls: calls.clone(),
            receipt_calls: Arc::new(AtomicUsize::new(0)),
        }));
        let server = tokio::spawn(serve_connections(listener, gid, reads, 10));
        let mut admitted = Vec::new();
        for _ in 0..CONNECTIONS_MAX {
            admitted.push(UnixStream::connect(&root).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut ninth = UnixStream::connect(&root).await.unwrap();
        let mut denied = Vec::new();
        let denied_result = timeout(Duration::from_millis(500), ninth.read_to_end(&mut denied))
            .await
            .unwrap();
        assert!(
            denied_result.is_ok()
                || denied_result.unwrap_err().kind() == io::ErrorKind::ConnectionReset
        );
        assert!(denied.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        drop(admitted.remove(0));
        let mut tenth = UnixStream::connect(&root).await.unwrap();
        write_frame_and_close(
            &mut tenth,
            br#"{"request":"get_set_deployment_image_status","operation_id":"cap-op"}"#,
        )
        .await;
        assert_eq!(read_frame(&mut tenth).await, br#"{"status":"NOT_FOUND"}"#);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        drop(admitted);
        server.await.unwrap().unwrap();
        std::fs::remove_file(root).unwrap();
    });
}

async fn assert_socket_response(reads: Arc<Mutex<TestReads>>, request: &[u8], expected: &[u8]) {
    let (mut client, server) = socket_pair();
    let gid = server.peer_cred().unwrap().gid();
    let handler = tokio::spawn(serve_connection(server, gid, reads));
    write_frame_and_close(&mut client, request).await;
    assert_eq!(read_frame(&mut client).await, expected);
    handler.await.unwrap();
}

fn application(
    root: &Path,
) -> (
    Application,
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
) {
    let (projection, _execution, handle) = applications(root);
    (projection, handle)
}

fn applications(
    root: &Path,
) -> (
    Application,
    Application,
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
) {
    let seed = [41_u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "socket-auth-1".into(),
        operation_id: "socket-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &seed,
        signing_key_id: "socket-authorization-key",
    })
    .unwrap();
    let (service, handle) =
        mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
    let client = kube::Client::new(service, "demo");
    let configuration = |client| OperatorConfiguration {
        journal_path: fs::canonicalize(root).unwrap().join("journal.sqlite3"),
        receipt_output_directory: Some(fs::canonicalize(root.join("receipts")).unwrap()),
        authorization_trust: AuthorizationTrust {
            key_id: "socket-authorization-key".into(),
            public_key: key.verifying_key().to_bytes(),
        },
        signed_authorization_grant: grant.clone(),
        kubernetes_client: client,
        receipt_signing_seed: [42_u8; 32],
        receipt_signing_key_id: "socket-receipt-key".into(),
    };
    (
        Application::open(configuration(client.clone())).unwrap(),
        Application::open(configuration(client)).unwrap(),
        handle,
    )
}

async fn wait_for_not_attempted<E: ApplicationExecution + 'static>(
    state: &ServerState<Application, E>,
    gid: u32,
) {
    wait_for_status(
        state,
        gid,
        br#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
    )
    .await;
}

fn every_expected_field_matches(observed: &serde_json::Value, expected: &[u8]) -> bool {
    let Ok(expected) = serde_json::from_slice::<serde_json::Value>(expected) else {
        return false;
    };
    let (Some(observed), Some(expected)) = (observed.as_object(), expected.as_object()) else {
        return false;
    };
    expected
        .iter()
        .all(|(field, value)| observed.get(field) == Some(value))
}

async fn wait_for_status<E: ApplicationExecution + 'static>(
    state: &ServerState<Application, E>,
    gid: u32,
    expected: &[u8],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let (mut client, server) = socket_pair();
        let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
        write_frame_and_close(
            &mut client,
            br#"{"request":"get_set_deployment_image_status","operation_id":"socket-op-1"}"#,
        )
        .await;
        let response = read_frame(&mut client).await;
        handler.await.unwrap();
        let observed: serde_json::Value = serde_json::from_slice(&response).unwrap();
        if every_expected_field_matches(&observed, expected) {
            break;
        }
        assert_eq!(
            observed.get("status"),
            Some(&serde_json::json!("IN_PROGRESS"))
        );
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn submit_and_read<E: ApplicationExecution + 'static>(
    state: &ServerState<Application, E>,
) -> (u32, Vec<u8>) {
    let (mut client, server) = socket_pair();
    let gid = server.peer_cred().unwrap().gid();
    let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
    write_frame_and_close(&mut client, submit_request().as_bytes()).await;
    let response = read_frame(&mut client).await;
    handler.await.unwrap();
    (gid, response)
}

fn send_not_found(response: tower_test::mock::SendResponse<http::Response<kube::client::Body>>) {
    response.send_response(
        http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(kube::client::Body::from(Vec::<u8>::new()))
            .unwrap(),
    );
}

fn send_deployment(
    response: tower_test::mock::SendResponse<http::Response<kube::client::Body>>,
    body: &serde_json::Value,
) {
    response.send_response(
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    );
}

fn deployment(resource_version: &str, generation: i64, observed: bool) -> serde_json::Value {
    let old_image = concat!(
        "registry.example/agent-api@sha256:",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    let image = concat!(
        "registry.example/agent-api@sha256:",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    let mut deployment = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "agent-api",
            "namespace": "demo",
            "uid": "uid-1",
            "resourceVersion": resource_version,
            "generation": generation
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {
                "metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{
                    "name": "api",
                    "image": if generation == 1 { old_image } else { image }
                }]}
            }
        },
        "status": {"observedGeneration": generation}
    });
    if observed {
        deployment["metadata"]["annotations"] = serde_json::json!({
            "kapsel.dev/kap0038-operation-id": "socket-op-1"
        });
        deployment["status"] = serde_json::json!({
            "observedGeneration": 2,
            "updatedReplicas": 1,
            "availableReplicas": 1,
            "unavailableReplicas": 0,
            "conditions": [{
                "type": "Available",
                "status": "True",
                "reason": "MinimumReplicasAvailable"
            }]
        });
    }
    deployment
}

fn submit_request() -> String {
    let request = submit_agent_request();
    format!(
        concat!(
            "{{\"request\":\"submit_set_deployment_image\",",
            "\"operation_id\":\"{}\",\"namespace\":\"{}\",",
            "\"deployment\":\"{}\",\"container\":\"{}\",",
            "\"immutable_image_digest\":\"{}\"}}"
        ),
        request.operation_id,
        request.namespace,
        request.deployment,
        request.container,
        request.immutable_image_digest
    )
}

fn submit_agent_request() -> AgentRequest {
    AgentRequest {
        operation_id: "socket-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    }
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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

async fn write_frame_and_close(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut body).await.unwrap();
    body
}
