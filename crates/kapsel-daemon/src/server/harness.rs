//! Socket/process mechanics through the production runtime.
//! Real applications use fixed-root startup.

use std::{
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use kapsel::{
    OperationReceipt, OperationState, OperationStatus, OperationTargets, ServiceAdmission,
    ServiceError, ServiceStop, TargetRejection,
};
use tokio::{net::UnixListener, runtime::Builder, time::Instant};

use super::{
    protocol::{self, ReadRequest, ResponseClass},
    runtime::{serve_connections_with_state, ServerState, CONNECTIONS_MAX},
    ApplicationExecution, ApplicationReads,
};

const FIXTURE_INITIAL: u8 = 0;
const FIXTURE_ADMITTED: u8 = 1;
const FIXTURE_FINISHED: u8 = 2;

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

    let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
        return ExitCode::from(4);
    };
    let result = runtime.block_on(async {
        let result = {
            let status = Arc::new(AtomicU8::new(FIXTURE_INITIAL));
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

struct HarnessReads {
    status: Arc<AtomicU8>,
    release: Arc<AtomicBool>,
    status_reads: AtomicU8,
}
impl HarnessReads {
    fn status(&self, operation_id: &str) -> Result<OperationStatus, ServiceError> {
        if operation_id != "process-op" {
            return Ok(OperationStatus::NotFound);
        }
        let first_read = self.status_reads.fetch_add(1, Ordering::AcqRel) == 0;
        if !first_read {
            self.release.store(true, Ordering::Release);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match (first_read, self.status.load(Ordering::Acquire)) {
                (true, FIXTURE_ADMITTED) => return Ok(OperationStatus::InProgress),
                (false, FIXTURE_FINISHED) => {
                    return Ok(OperationStatus::NotAttempted(
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
            ReadRequest::Status(operation_id) => (
                protocol::render_status_with_targets(
                    self.status(&operation_id)
                        .map(|status| (status, OperationTargets::default())),
                ),
                ResponseClass::Ordinary,
            ),
            ReadRequest::Receipt(_) => (
                protocol::render_receipt(Ok(OperationReceipt::NotFound)),
                ResponseClass::Receipt,
            ),
            _ => (protocol::invalid_request(), ResponseClass::Ordinary),
        }
    }
    fn admitted_state(&self, operation_id: &str) -> Result<Option<OperationState>, ServiceError> {
        if operation_id != "process-op" {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(match self.status.load(Ordering::Acquire) {
            FIXTURE_INITIAL => None,
            FIXTURE_ADMITTED => Some(OperationState::Requested),
            _ => Some(OperationState::NotAttempted),
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
        operation_id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<ServiceStop, ServiceError> {
        if operation_id != "process-op" {
            return Err(ServiceError::InvalidRequest);
        }

        self.status.store(FIXTURE_ADMITTED, Ordering::Release);
        acknowledged(ServiceAdmission::Admitted(OperationState::Requested));

        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.release.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(ServiceError::OperationFailure);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        self.status.store(FIXTURE_FINISHED, Ordering::Release);
        Ok(ServiceStop::Finished)
    }
}
