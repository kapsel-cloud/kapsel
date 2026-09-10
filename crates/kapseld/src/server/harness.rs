//! Private process fixtures using the production runtime and Application bridge.

use std::{io, process::ExitCode, sync::Arc, time::Duration};

use kapsel::{
    AgentRequest, Application, ApplicationError, SetDeploymentImageReceipt,
    SetDeploymentImageStatus, TargetRejection,
};
use tokio::net::UnixListener;

use super::{
    runtime::{serve_connections_with_state, ServerState, CONNECTIONS_MAX},
    ApplicationExecution, ApplicationReads,
};

pub(super) fn run() -> ExitCode {
    let Ok(path) = std::env::var("KAPSELD_TEST_SOCKET") else {
        return ExitCode::from(4);
    };
    let Ok(expected_gid) = std::env::var("KAPSELD_TEST_EXPECTED_GID") else {
        return ExitCode::from(4);
    };
    let Ok(expected_gid) = expected_gid.parse::<u32>() else {
        return ExitCode::from(4);
    };
    let Ok(connections) = std::env::var("KAPSELD_TEST_CONNECTIONS") else {
        return ExitCode::from(4);
    };
    let Ok(connections) = connections.parse::<usize>() else {
        return ExitCode::from(4);
    };
    if connections == 0 || connections > CONNECTIONS_MAX + 2 {
        return ExitCode::from(4);
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(4);
    };
    let result = if let Some(root) = std::env::var_os("KAPSELD_TEST_APPLICATION_ROOT") {
        run_application_test_harness(
            &runtime,
            std::path::Path::new(&path),
            expected_gid,
            connections,
            std::path::Path::new(&root),
        )
    } else {
        let status = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = ServerState::new(
            HarnessReads {
                status: status.clone(),
                release: release.clone(),
                status_reads: std::sync::atomic::AtomicU8::new(0),
            },
            HarnessExecution { status, release },
        );
        runtime.block_on(async {
            let listener = UnixListener::bind(&path)?;
            let result =
                serve_connections_with_state(listener, expected_gid, state, connections).await;
            let removal = std::fs::remove_file(path);
            result.and(removal)
        })
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

fn run_application_test_harness(
    runtime: &tokio::runtime::Runtime,
    socket: &std::path::Path,
    expected_gid: u32,
    connections: usize,
    root: &std::path::Path,
) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(io::Error::other("invalid application fixture"));
    }
    runtime.block_on(async {
        let mut execution = open_test_application(root)?;
        execution
            .reconcile()
            .await
            .map_err(|_| io::Error::other("startup reconciliation failed"))?;
        let reads = open_test_application(root)?;
        let listener = UnixListener::bind(socket)?;
        let result = serve_connections_with_state(
            listener,
            expected_gid,
            ServerState::new(reads, execution),
            connections,
        )
        .await;
        let removal = std::fs::remove_file(socket);
        result.and(removal)
    })
}

fn open_test_application(root: &std::path::Path) -> io::Result<Application> {
    use ed25519_dalek::SigningKey;
    use kapsel::{
        provision_exact_grant, AuthorizationTrust, ExactAuthorization, GrantProvisioning,
        OperatorConfiguration,
    };

    let url = std::env::var("KAPSELD_TEST_KUBERNETES_URL")
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let cluster_url = url
        .parse()
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let config = kube::Config::new(cluster_url);
    if config.cluster_url.scheme_str() != Some("http")
        || config.cluster_url.host() != Some("127.0.0.1")
        || config.cluster_url.port_u16().is_none()
    {
        return Err(io::Error::other("invalid application fixture"));
    }
    let kubernetes_client = kube::Client::try_from(config)
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "process-auth".into(),
        operation_id: "process-op".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    };
    let signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "process-authorization-key",
    })
    .map_err(|_| io::Error::other("invalid application fixture"))?;
    let (receipt_directory, receipt_signing_seed, receipt_signing_key_id) =
        match std::env::var("KAPSELD_TEST_RECEIPT_CONFIGURATION").as_deref() {
            Ok("A") => (
                root.join("receipts-a"),
                [42_u8; 32],
                "process-receipt-key-a",
            ),
            Ok("B") => (
                root.join("receipts-b"),
                [43_u8; 32],
                "process-receipt-key-b",
            ),
            _ => return Err(io::Error::other("invalid application fixture")),
        };
    Application::open(OperatorConfiguration {
        journal_path: root.join("journal.sqlite3"),
        receipt_output_directory: Some(receipt_directory),
        authorization_trust: AuthorizationTrust {
            key_id: "process-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        },
        signed_authorization_grant,
        kubernetes_client,
        receipt_signing_seed,
        receipt_signing_key_id: receipt_signing_key_id.into(),
    })
    .map_err(|_| io::Error::other("application open failed"))
}

struct HarnessReads {
    status: Arc<std::sync::atomic::AtomicU8>,
    release: Arc<std::sync::atomic::AtomicBool>,
    status_reads: std::sync::atomic::AtomicU8,
}

impl ApplicationReads for HarnessReads {
    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        use std::{sync::atomic::Ordering, time::Instant};

        if operation_id != "process-op" {
            return Ok(SetDeploymentImageStatus::NotFound);
        }
        let first_read = self.status_reads.fetch_add(1, Ordering::AcqRel) == 0;
        if !first_read {
            self.release.store(true, Ordering::Release);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match (first_read, self.status.load(Ordering::Acquire)) {
                (true, 1) => return Ok(SetDeploymentImageStatus::InProgress),
                (false, 2) => {
                    return Ok(SetDeploymentImageStatus::NotAttempted(
                        TargetRejection::DeploymentNotFound,
                    ));
                },
                (_, _) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                },
                (_, _) => return Err(ApplicationError::OperationFailure),
            }
        }
    }

    fn receipt(&self, _operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        Ok(SetDeploymentImageReceipt::NotFound)
    }
}

struct HarnessExecution {
    status: Arc<std::sync::atomic::AtomicU8>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

impl ApplicationExecution for HarnessExecution {
    fn matches(&self, request: &AgentRequest) -> bool {
        request.operation_id == "process-op"
            && request.namespace == "demo"
            && request.deployment == "agent-api"
            && request.container == "api"
            && request.immutable_image_digest
                == concat!(
                    "registry.example/agent-api@sha256:",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                )
    }

    async fn execute(&mut self, _request: AgentRequest) -> Result<(), ApplicationError> {
        use std::sync::atomic::Ordering;

        self.status.store(1, Ordering::Release);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.release.load(Ordering::Acquire) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ApplicationError::OperationFailure);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.status.store(2, Ordering::Release);
        Ok(())
    }
}
