//! Private process fixtures using the production runtime and service application bridge.

use std::{
    io,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use kapsel::{
    ServiceAdmission, ServiceApplication, ServiceError, ServiceExecution,
    SetDeploymentImageReceipt, SetDeploymentImageStatus, TargetRejection,
};
use tokio::net::UnixListener;

use super::{
    protocol::{self, ReadRequest, ResponseClass},
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
    let result = runtime.block_on(async {
        let result = if let Some(root) = std::env::var_os("KAPSELD_TEST_APPLICATION_ROOT") {
            let root = std::path::Path::new(&root);
            let (reads, _) = open_test_application(root)?;
            let (application, material) = open_test_application(root)?;
            let listener = UnixListener::bind(&path)?;
            serve_connections_with_state(
                listener,
                expected_gid,
                ServerState::new(
                    reads,
                    HarnessApplication {
                        application,
                        material,
                    },
                ),
                connections,
            )
            .await
        } else {
            let status = Arc::new(AtomicU8::new(0));
            let release = Arc::new(AtomicBool::new(false));
            let state = ServerState::new(
                HarnessReads {
                    status: status.clone(),
                    release: release.clone(),
                    status_reads: AtomicU8::new(0),
                },
                HarnessExecution { status, release },
            );
            let listener = UnixListener::bind(&path)?;
            serve_connections_with_state(listener, expected_gid, state, connections).await
        };
        let cleanup = std::fs::remove_file(path);
        result.and(cleanup)
    });
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

struct HarnessApplication {
    application: ServiceApplication,
    material: ServiceExecution,
}
impl ApplicationExecution for HarnessApplication {
    async fn execute(
        &mut self,
        id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<(), ServiceError> {
        self.application
            .select(
                &id,
                ServiceExecution {
                    kubernetes_client: self.material.kubernetes_client.clone(),
                    receipt_signing: self.material.receipt_signing.clone(),
                },
                acknowledged,
            )
            .await
    }
}

fn open_test_application(
    root: &std::path::Path,
) -> io::Result<(ServiceApplication, ServiceExecution)> {
    use ed25519_dalek::SigningKey;
    use kapsel::{
        provision_exact_grant, AuthorizationTrust, ExactAuthorization, GrantProvisioning,
        ServiceApproval, ServiceConfiguration,
    };
    if !root.is_absolute() {
        return Err(io::Error::other("invalid application fixture"));
    }
    let url = std::env::var("KAPSELD_TEST_KUBERNETES_URL")
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let cluster_url = url
        .parse()
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let mut config = kube::Config::new(cluster_url);
    if config.cluster_url.scheme_str() != Some("http")
        || config.cluster_url.host() != Some("127.0.0.1")
        || config.cluster_url.port_u16().is_none()
    {
        return Err(io::Error::other("invalid application fixture"));
    }
    config.default_retry = false;
    let kubernetes_client = kube::Client::try_from(config)
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        approved_target: Some(kapsel::ApprovedTarget {
            uid: "uid-1".into(),
            resource_version: "1".into(),
        }),
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
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "process-authorization-key",
    })
    .map_err(|_| io::Error::other("invalid application fixture"))?;
    let signing = match std::env::var("KAPSELD_TEST_RECEIPT_CONFIGURATION").as_deref() {
        Ok("A") => ([42_u8; 32], "process-receipt-key-a"),
        Ok("B") => ([43_u8; 32], "process-receipt-key-b"),
        _ => return Err(io::Error::other("invalid application fixture")),
    };
    let application = ServiceApplication::open(ServiceConfiguration {
        journal_path: root.join("journal.sqlite3"),
        authorization_trust: vec![AuthorizationTrust {
            key_id: "process-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        }],
        approvals: vec![ServiceApproval {
            signed_grant: grant,
            label: "process action".into(),
        }],
    })
    .map_err(|_| io::Error::other("application open failed"))?;
    Ok((
        application,
        ServiceExecution {
            kubernetes_client: Some(kubernetes_client),
            receipt_signing: Some((signing.0, signing.1.into())),
        },
    ))
}

struct HarnessReads {
    status: Arc<AtomicU8>,
    release: Arc<AtomicBool>,
    status_reads: AtomicU8,
}
impl HarnessReads {
    fn status(&self, id: &str) -> Result<SetDeploymentImageStatus, ServiceError> {
        if id != "process-op" {
            return Ok(SetDeploymentImageStatus::NotFound);
        }
        let first_read = self.status_reads.fetch_add(1, Ordering::AcqRel) == 0;
        if !first_read {
            self.release.store(true, Ordering::Release);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match (first_read, self.status.load(Ordering::Acquire)) {
                (true, 1) => return Ok(SetDeploymentImageStatus::InProgress),
                (false, 2) => {
                    return Ok(SetDeploymentImageStatus::NotAttempted(
                        TargetRejection::DeploymentNotFound,
                    ))
                },
                (_, _) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                },
                _ => return Err(ServiceError::OperationFailure),
            }
        }
    }
}
impl ApplicationReads for HarnessReads {
    fn read(&self, request: ReadRequest) -> (Vec<u8>, ResponseClass) {
        match request {
            ReadRequest::Status(id) => (
                protocol::render_status_with_targets(
                    self.status(&id)
                        .map(|status| (status, kapsel::OperationTargets::default())),
                ),
                ResponseClass::Ordinary,
            ),
            ReadRequest::Receipt(_) => (
                protocol::render_receipt(Ok(SetDeploymentImageReceipt::NotFound)),
                ResponseClass::Receipt,
            ),
            _ => (protocol::invalid_request(), ResponseClass::Ordinary),
        }
    }
    fn admitted_state(&self, id: &str) -> Result<Option<kapsel::OperationState>, ServiceError> {
        if id != "process-op" {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(match self.status.load(Ordering::Acquire) {
            0 => None,
            1 => Some(kapsel::OperationState::Requested),
            _ => Some(kapsel::OperationState::NotAttempted),
        })
    }
}
struct HarnessExecution {
    status: Arc<AtomicU8>,
    release: Arc<AtomicBool>,
}
impl ApplicationExecution for HarnessExecution {
    async fn execute(
        &mut self,
        id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<(), ServiceError> {
        if id != "process-op" {
            return Err(ServiceError::InvalidRequest);
        }
        self.status.store(1, Ordering::Release);
        acknowledged(ServiceAdmission::Admitted(
            kapsel::OperationState::Requested,
        ));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.release.load(Ordering::Acquire) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ServiceError::OperationFailure);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.status.store(2, Ordering::Release);
        Ok(())
    }
}
