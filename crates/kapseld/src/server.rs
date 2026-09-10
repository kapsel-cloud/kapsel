//! Fixed startup and the narrow bridge to the accepted Application interface.

#[cfg(all(target_os = "linux", feature = "test-harness"))]
mod harness;
mod protocol;
mod runtime;

#[cfg(target_os = "linux")]
use std::io;
use std::{future::Future, process::ExitCode};

use kapsel::{
    AgentRequest, Application, ApplicationError, SetDeploymentImageReceipt,
    SetDeploymentImageStatus,
};
use protocol::{ReadRequest, ResponseClass};
#[cfg(target_os = "linux")]
use runtime::{serve_connections_forever, CONNECTIONS_MAX};
use runtime::{serve_connections_with_state, ServerState};

trait ApplicationReads: Send {
    fn read(&self, request: ReadRequest) -> (Vec<u8>, ResponseClass) {
        match request {
            ReadRequest::Status(operation_id) => (
                protocol::render_status_with_targets(self.status_with_targets(&operation_id)),
                ResponseClass::Ordinary,
            ),
            ReadRequest::Receipt(operation_id) => (
                protocol::render_receipt(self.receipt(&operation_id)),
                ResponseClass::Receipt,
            ),
        }
    }

    fn status_with_targets(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError> {
        self.status(operation_id)
            .map(|status| (status, kapsel::OperationTargets::default()))
    }

    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError>;

    fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError>;
}

impl ApplicationReads for Application {
    fn status_with_targets(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError> {
        self.read_set_deployment_image_status_with_targets(operation_id)
    }

    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        self.read_set_deployment_image_status(operation_id)
    }

    fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        self.read_set_deployment_image_receipt(operation_id)
    }
}

trait ApplicationExecution: Send {
    fn matches(&self, request: &AgentRequest) -> bool;

    fn execute(
        &mut self,
        request: AgentRequest,
    ) -> impl Future<Output = Result<(), ApplicationError>> + Send;
}

impl ApplicationExecution for Application {
    fn matches(&self, request: &AgentRequest) -> bool {
        self.request_matches_authorized_grant(request)
    }

    async fn execute(&mut self, request: AgentRequest) -> Result<(), ApplicationError> {
        Self::execute(self, &request).await.map(|_| ())
    }
}

pub(crate) fn run() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "test-harness")]
        if std::env::var_os("KAPSELD_TEST_SOCKET").is_some() {
            return harness::run();
        }
        run_installed()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = serve_connections_with_state::<Application, Application>;
        let _ = ServerState::<Application, Application>::new;
        ExitCode::from(4)
    }
}

#[cfg(target_os = "linux")]
fn run_installed() -> ExitCode {
    use crate::startup::InstallationInputs;

    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--operator-config"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/etc/kapsel/operator.json"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--socket"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/run/kapsel/kapseld.sock"))
        || arguments.next().is_some()
    {
        return ExitCode::from(4);
    }
    #[cfg(feature = "test-harness")]
    let installation_root = std::env::var_os("KAPSELD_TEST_INSTALLATION_ROOT")
        .map_or_else(|| std::path::PathBuf::from("/"), std::path::PathBuf::from);
    #[cfg(not(feature = "test-harness"))]
    let installation_root = std::path::PathBuf::from("/");
    #[cfg(feature = "test-harness")]
    let connections = match std::env::var("KAPSELD_TEST_CONNECTIONS") {
        Ok(value) => match value.parse::<usize>() {
            Ok(value) if value > 0 && value <= CONNECTIONS_MAX + 2 => Some(value),
            _ => return ExitCode::from(4),
        },
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return ExitCode::from(4),
    };
    #[cfg(not(feature = "test-harness"))]
    let connections = None;
    let Ok(inputs) = InstallationInputs::open_at(&installation_root) else {
        return ExitCode::from(4);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(4);
    };
    let result = runtime.block_on(async {
        let mut execution = inputs
            .open_application()
            .await
            .map_err(|_| io::Error::other("application open failed"))?;
        execution
            .reconcile()
            .await
            .map_err(|_| io::Error::other("startup reconciliation failed"))?;
        let reads = inputs
            .open_application()
            .await
            .map_err(|_| io::Error::other("application open failed"))?;
        let listener = inputs.bind_listener()?;
        let state = ServerState::new(reads, execution);
        let expected_gid = rustix::process::getegid().as_raw();
        match connections {
            Some(connections) => {
                serve_connections_with_state(listener, expected_gid, state, connections).await
            },
            None => serve_connections_forever(listener, expected_gid, state).await,
        }
    });
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}
