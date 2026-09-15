//! Fixed startup and the narrow bridge to the accepted Application interface.

#[cfg(all(target_os = "linux", feature = "test-harness"))]
mod harness;
mod protocol;
mod runtime;

#[cfg(target_os = "linux")]
use std::io;
use std::{future::Future, process::ExitCode};

use kapsel::{ServiceAdmission, ServiceApplication, ServiceError, ServiceExecution};
use protocol::{ReadRequest, ResponseClass};
#[cfg(not(target_os = "linux"))]
use runtime::serve_connections_with_state;
#[cfg(target_os = "linux")]
use runtime::serve_until_stopped;
use runtime::ServerState;
#[cfg(all(target_os = "linux", feature = "test-harness"))]
use runtime::CONNECTIONS_MAX;

trait ApplicationReads: Send {
    fn read(&self, request: ReadRequest) -> (Vec<u8>, ResponseClass);

    fn admitted_state(
        &self,
        operation_id: &str,
    ) -> Result<Option<kapsel::OperationState>, ServiceError>;
}

impl ApplicationReads for ServiceApplication {
    fn read(&self, request: ReadRequest) -> (Vec<u8>, ResponseClass) {
        let ordinary = ResponseClass::Ordinary;
        match request {
            ReadRequest::Status(id) => (
                protocol::render_status_with_targets(self.status(&id)),
                ordinary,
            ),
            ReadRequest::Receipt(id) => (
                protocol::render_receipt(self.receipt(&id)),
                ResponseClass::Receipt,
            ),
            ReadRequest::List(after) => {
                let result = self.approved_actions(after.as_deref()).and_then(|entries| {
                    let next_cursor = match entries.last() {
                        Some(last)
                            if !self
                                .approved_actions(Some(&last.request.operation_id))?
                                .is_empty() =>
                        {
                            Some(last.request.operation_id.clone())
                        },
                        _ => None,
                    };
                    Ok(protocol::render_catalog(entries, next_cursor.as_deref()))
                });
                (result.unwrap_or_else(protocol::service_error), ordinary)
            },
            ReadRequest::History(after) => (
                self.history(after.as_deref())
                    .map_or_else(protocol::service_error, protocol::render_history),
                ordinary,
            ),
        }
    }

    fn admitted_state(
        &self,
        operation_id: &str,
    ) -> Result<Option<kapsel::OperationState>, ServiceError> {
        Self::admitted_state(self, operation_id)
    }
}

pub(crate) trait ApplicationExecution: Send {
    fn execute(
        &mut self,
        operation_id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> impl Future<Output = Result<(), ServiceError>> + Send;
}

pub(crate) struct ExecutionApplication {
    pub(crate) application: ServiceApplication,
    pub(crate) kubeconfig: Option<Vec<u8>>,
    pub(crate) receipt_seed: Option<Vec<u8>>,
    pub(crate) receipt_signing_key_id: String,
}

impl ApplicationExecution for ExecutionApplication {
    async fn execute(
        &mut self,
        operation_id: String,
        acknowledged: impl FnOnce(ServiceAdmission) + Send,
    ) -> Result<(), ServiceError> {
        let material = ServiceExecution::from_operator_snapshots(
            self.kubeconfig.as_deref(),
            self.receipt_seed.as_deref(),
            &self.receipt_signing_key_id,
        )
        .await;
        self.application
            .select(&operation_id, material, acknowledged)
            .await
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
        let _ = serve_connections_with_state::<ServiceApplication, ExecutionApplication>;
        let _ = ServerState::<ServiceApplication, ExecutionApplication>::new;
        ExitCode::from(4)
    }
}

#[cfg(target_os = "linux")]
fn run_installed() -> ExitCode {
    #[cfg(feature = "test-harness")]
    let installation_root = std::env::var_os("KAPSELD_TEST_INSTALLATION_ROOT")
        .map_or_else(|| std::path::PathBuf::from("/"), std::path::PathBuf::from);
    #[cfg(not(feature = "test-harness"))]
    let installation_root = std::path::PathBuf::from("/");
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.as_slice() == [std::ffi::OsStr::new("--replace-operator-config")] {
        return crate::startup::replace_operator_config(&installation_root);
    }
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--operator-config"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/etc/kapsel/operator.json"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--socket"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/run/kapsel/kapseld.sock"))
        || arguments.next().is_some()
    {
        return ExitCode::from(4);
    }
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
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(4);
    };
    if runtime
        .block_on(serve_installed(installation_root, connections))
        .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

#[cfg(target_os = "linux")]
async fn serve_installed(
    installation_root: std::path::PathBuf,
    connections: Option<usize>,
) -> io::Result<()> {
    use crate::startup::InstallationInputs;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(feature = "test-harness")]
    let stop_marker = installation_root.join("control/stop.ready");
    let mut startup = tokio::task::spawn_blocking(move || {
        let inputs = InstallationInputs::open_at(&installation_root)?;
        let reads = inputs
            .open_application()
            .map_err(|_| io::Error::other("application open failed"))?;
        let execution = inputs
            .open_execution()
            .map_err(|_| io::Error::other("application open failed"))?;
        Ok::<_, io::Error>((inputs, reads, execution))
    });
    let (opened, stopped) = tokio::select! {
        biased;
        _ = terminate.recv() => {
            #[cfg(feature = "test-harness")]
            let _ = std::fs::write(&stop_marker, b"");
            (startup.await, true)
        },
        opened = &mut startup => (opened, false),
    };
    let (inputs, reads, execution) =
        opened.map_err(|_| io::Error::other("startup task failed"))??;
    // Give pending reactor notifications a turn before deciding whether startup may serve.
    tokio::task::yield_now().await;
    let stopped = stopped
        || tokio::select! {
            biased;
            _ = terminate.recv() => true,
            () = std::future::ready(()) => false,
        };
    let result = if stopped {
        drop(execution);
        drop(reads);
        Ok(())
    } else {
        match inputs.bind_listener() {
            Ok(listener) => {
                let state = ServerState::new(reads, execution);
                serve_until_stopped(
                    listener,
                    rustix::process::getegid().as_raw(),
                    state,
                    connections,
                    async {
                        terminate.recv().await;
                        #[cfg(feature = "test-harness")]
                        let _ = std::fs::write(&stop_marker, b"");
                    },
                )
                .await
            },
            Err(error) => {
                drop(execution);
                drop(reads);
                Err(error)
            },
        }
    };
    drop(inputs);
    result
}
