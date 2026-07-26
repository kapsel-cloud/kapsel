//! Native process composition for the fixed Kapsel sandbox.

#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "the operator process emits only bounded startup and fixed local error status"
)]

mod native_listener;

use std::{
    env, fs,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{
    run_cleanup_role, run_cleanup_state_role, run_runner_process, run_scheduler_role,
    run_scheduler_state_role, serve_private_handoff, set_global_stop, Service,
};

const USAGE: &str = concat!(
    "usage: kapsel-sandbox <init|serve|handoff-serve|retention|scheduler-state-serve|",
    "cleanup-state-serve|scheduler|cleanup|stop|clear-stop|runner> <role-specific arguments>"
);
const RETENTION_INTERVAL: Duration = Duration::from_mins(1);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kapsel-sandbox: {message}");
            ExitCode::from(2)
        },
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive role dispatch keeps native authority composition visible"
)]
fn run() -> Result<(), &'static str> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() == Some("runner") {
        return run_runner_process(arguments);
    }
    let configuration = Configuration::parse(env::args().skip(1))?;
    configuration.validate_role_arguments()?;
    match configuration.command {
        Command::Scheduler => {
            let state_token = configuration.state_token.ok_or(USAGE)?;
            let kubernetes_token = configuration.kubernetes_token.ok_or(USAGE)?;
            require_distinct_tokens("scheduler", &state_token, &kubernetes_token)?;
            let kubernetes_ca = configuration.kubernetes_ca.ok_or(USAGE)?;
            let runtime = native_runtime("scheduler")?;
            runtime.block_on(async move {
                let client =
                    projected_kubernetes_client("scheduler", kubernetes_ca, kubernetes_token)?;
                run_scheduler_role(
                    configuration.state_endpoint.ok_or(USAGE)?,
                    configuration.state_ca_bundle.ok_or(USAGE)?,
                    configuration.state_ca_sha256.ok_or(USAGE)?,
                    configuration.state_ca_root_count.ok_or(USAGE)?,
                    state_token,
                    client,
                )
                .await
            })
        },
        Command::Cleanup => {
            let state_token = configuration.state_token.ok_or(USAGE)?;
            let kubernetes_token = configuration.kubernetes_token.ok_or(USAGE)?;
            require_distinct_tokens("cleanup", &state_token, &kubernetes_token)?;
            let kubernetes_ca = configuration.kubernetes_ca.ok_or(USAGE)?;
            let runtime = native_runtime("cleanup")?;
            runtime.block_on(async move {
                let client =
                    projected_kubernetes_client("cleanup", kubernetes_ca, kubernetes_token)?;
                run_cleanup_role(
                    configuration.state_endpoint.ok_or(USAGE)?,
                    configuration.state_ca_bundle.ok_or(USAGE)?,
                    configuration.state_ca_sha256.ok_or(USAGE)?,
                    configuration.state_ca_root_count.ok_or(USAGE)?,
                    state_token,
                    client,
                )
                .await
            })
        },
        Command::Stop | Command::ClearStop => {
            let database = configuration.database.as_ref().ok_or(USAGE)?;
            let stopped = matches!(configuration.command, Command::Stop);
            set_global_stop(database, stopped).map_err(|_| {
                if stopped {
                    "global stop could not be committed"
                } else {
                    "global stop could not be cleared"
                }
            })
        },
        Command::Init
        | Command::Serve
        | Command::HandoffServe
        | Command::Retention
        | Command::SchedulerStateServe
        | Command::CleanupStateServe => {
            let database = configuration.database.as_ref().ok_or(USAGE)?;
            let receipts = configuration.receipts.as_ref().ok_or(USAGE)?;
            let digest_key_file = configuration.digest_key_file.as_ref().ok_or(USAGE)?;
            if matches!(configuration.command, Command::Init) {
                initialize_directory(database.parent().ok_or("database parent is unavailable")?)?;
                initialize_directory(receipts)?;
            }
            let digest_key = read_secret_32(digest_key_file)?;
            let mut service = Service::open(database, receipts, digest_key, unix_time()?)
                .map_err(|_| "service state is unavailable")?;
            match configuration.command {
                Command::Init => set_origin(&mut service, configuration.origin.as_deref()),
                Command::Serve => {
                    set_origin(&mut service, configuration.origin.as_deref())?;
                    native_listener::serve(service, configuration.listen.ok_or(USAGE)?)
                },
                Command::HandoffServe => {
                    let listener = std::net::TcpListener::bind(configuration.listen.ok_or(USAGE)?)
                        .map_err(|_| "private handoff listener is unavailable")?;
                    serve_private_handoff(&listener, &std::sync::Arc::new(service))
                        .map_err(|_| "private handoff listener failed")
                },
                Command::Retention => run_retention(&service),
                Command::SchedulerStateServe => {
                    let runtime = native_runtime("scheduler-state")?;
                    runtime.block_on(async move {
                        let client = projected_kubernetes_client(
                            "scheduler-state",
                            configuration.kubernetes_ca.ok_or(USAGE)?,
                            configuration.kubernetes_token.ok_or(USAGE)?,
                        )?;
                        run_scheduler_state_role(
                            service,
                            configuration.listen.ok_or(USAGE)?,
                            configuration.state_certificate.ok_or(USAGE)?,
                            configuration.state_private_key.ok_or(USAGE)?,
                            configuration.scheduler_service_account_uid.ok_or(USAGE)?,
                            client,
                            configuration.handoff_endpoint.ok_or(USAGE)?,
                        )
                        .await
                    })
                },
                Command::CleanupStateServe => {
                    let runtime = native_runtime("cleanup-state")?;
                    runtime.block_on(async move {
                        let client = projected_kubernetes_client(
                            "cleanup-state",
                            configuration.kubernetes_ca.ok_or(USAGE)?,
                            configuration.kubernetes_token.ok_or(USAGE)?,
                        )?;
                        run_cleanup_state_role(
                            service,
                            configuration.listen.ok_or(USAGE)?,
                            configuration.state_certificate.ok_or(USAGE)?,
                            configuration.state_private_key.ok_or(USAGE)?,
                            configuration.cleanup_service_account_uid.ok_or(USAGE)?,
                            client,
                        )
                        .await
                    })
                },
                Command::Scheduler | Command::Cleanup | Command::Stop | Command::ClearStop => {
                    unreachable!()
                },
            }
        },
    }
}

fn projected_kubernetes_client(
    role: &str,
    ca_path: PathBuf,
    token_path: PathBuf,
) -> Result<kube::Client, &'static str> {
    let configuration_error = match role {
        "scheduler-state" => "scheduler-state Kubernetes configuration is unavailable",
        "cleanup-state" => "cleanup-state Kubernetes configuration is unavailable",
        "cleanup" => "cleanup Kubernetes configuration is unavailable",
        _ => "scheduler Kubernetes configuration is unavailable",
    };
    let client_error = match role {
        "scheduler-state" => "scheduler-state Kubernetes client is unavailable",
        "cleanup-state" => "cleanup-state Kubernetes client is unavailable",
        "cleanup" => "cleanup Kubernetes client is unavailable",
        _ => "scheduler Kubernetes client is unavailable",
    };
    let host = env::var("KUBERNETES_SERVICE_HOST").map_err(|_| configuration_error)?;
    let port = env::var("KUBERNETES_SERVICE_PORT").map_err(|_| configuration_error)?;
    let cluster_url = format!("https://{host}:{port}")
        .parse()
        .map_err(|_| configuration_error)?;
    let mut config = kube::Config::new(cluster_url);
    config.root_cert_file = Some(ca_path);
    config.auth_info.token_file = Some(
        token_path
            .into_os_string()
            .into_string()
            .map_err(|_| configuration_error)?,
    );
    kube::Client::try_from(config).map_err(|_| client_error)
}

fn native_runtime(role: &str) -> Result<tokio::runtime::Runtime, &'static str> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| match role {
            "cleanup" => "cleanup runtime is unavailable",
            "scheduler-state" => "scheduler-state runtime is unavailable",
            "cleanup-state" => "cleanup-state runtime is unavailable",
            _ => "scheduler runtime is unavailable",
        })
}

fn set_origin(service: &mut Service, origin: Option<&str>) -> Result<(), &'static str> {
    service
        .set_origin(origin.unwrap_or("https://kapsel.invalid"))
        .map_err(|_| "origin is invalid")
}

fn run_retention(service: &Service) -> Result<(), &'static str> {
    loop {
        thread::sleep(RETENTION_INTERVAL);
        service
            .sweep_retention(unix_time()?)
            .map_err(|_| "retention sweep failed")?;
    }
}

#[derive(Clone, Copy)]
enum Command {
    Init,
    Serve,
    HandoffServe,
    Retention,
    SchedulerStateServe,
    CleanupStateServe,
    Scheduler,
    Cleanup,
    Stop,
    ClearStop,
}

struct Configuration {
    command: Command,
    database: Option<PathBuf>,
    receipts: Option<PathBuf>,
    digest_key_file: Option<PathBuf>,
    origin: Option<String>,
    listen: Option<SocketAddr>,
    handoff_endpoint: Option<SocketAddr>,
    state_endpoint: Option<SocketAddr>,
    state_ca_bundle: Option<PathBuf>,
    state_ca_sha256: Option<[u8; 32]>,
    state_ca_root_count: Option<u8>,
    state_token: Option<PathBuf>,
    state_certificate: Option<PathBuf>,
    state_private_key: Option<PathBuf>,
    scheduler_service_account_uid: Option<String>,
    cleanup_service_account_uid: Option<String>,
    kubernetes_ca: Option<PathBuf>,
    kubernetes_token: Option<PathBuf>,
}

impl Configuration {
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive parser keeps the fixed role argument vocabulary visible"
    )]
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let mut arguments = arguments;
        let command = match arguments.next().as_deref() {
            Some("init") => Command::Init,
            Some("serve") => Command::Serve,
            Some("handoff-serve") => Command::HandoffServe,
            Some("retention") => Command::Retention,
            Some("scheduler-state-serve") => Command::SchedulerStateServe,
            Some("cleanup-state-serve") => Command::CleanupStateServe,
            Some("scheduler") => Command::Scheduler,
            Some("cleanup") => Command::Cleanup,
            Some("stop") => Command::Stop,
            Some("clear-stop") => Command::ClearStop,
            _ => return Err(USAGE),
        };
        let mut configuration = Self {
            command,
            database: None,
            receipts: None,
            digest_key_file: None,
            origin: None,
            listen: None,
            handoff_endpoint: None,
            state_endpoint: None,
            state_ca_bundle: None,
            state_ca_sha256: None,
            state_ca_root_count: None,
            state_token: None,
            state_certificate: None,
            state_private_key: None,
            scheduler_service_account_uid: None,
            cleanup_service_account_uid: None,
            kubernetes_ca: None,
            kubernetes_token: None,
        };
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(USAGE)?;
            match flag.as_str() {
                "--database" if configuration.database.is_none() => {
                    configuration.database = Some(absolute(PathBuf::from(value))?);
                },
                "--receipts" if configuration.receipts.is_none() => {
                    configuration.receipts = Some(absolute(PathBuf::from(value))?);
                },
                "--digest-key-file" if configuration.digest_key_file.is_none() => {
                    configuration.digest_key_file = Some(absolute(PathBuf::from(value))?);
                },
                "--origin" if configuration.origin.is_none() => configuration.origin = Some(value),
                "--listen" if configuration.listen.is_none() => {
                    configuration.listen =
                        Some(value.parse().map_err(|_| "listen address is invalid")?);
                },
                "--handoff-endpoint" if configuration.handoff_endpoint.is_none() => {
                    configuration.handoff_endpoint =
                        Some(value.parse().map_err(|_| "handoff endpoint is invalid")?);
                },
                "--state-endpoint" if configuration.state_endpoint.is_none() => {
                    configuration.state_endpoint =
                        Some(value.parse().map_err(|_| "state endpoint is invalid")?);
                },
                "--state-ca-bundle" if configuration.state_ca_bundle.is_none() => {
                    configuration.state_ca_bundle = Some(absolute(PathBuf::from(value))?);
                },
                "--state-ca-sha256" if configuration.state_ca_sha256.is_none() => {
                    configuration.state_ca_sha256 = Some(parse_sha256(&value)?);
                },
                "--state-ca-root-count" if configuration.state_ca_root_count.is_none() => {
                    configuration.state_ca_root_count = Some(
                        value
                            .parse()
                            .map_err(|_| "state CA root count is invalid")?,
                    );
                },
                "--state-token" if configuration.state_token.is_none() => {
                    configuration.state_token = Some(absolute(PathBuf::from(value))?);
                },
                "--state-certificate" if configuration.state_certificate.is_none() => {
                    configuration.state_certificate = Some(absolute(PathBuf::from(value))?);
                },
                "--state-private-key" if configuration.state_private_key.is_none() => {
                    configuration.state_private_key = Some(absolute(PathBuf::from(value))?);
                },
                "--scheduler-service-account-uid"
                    if configuration.scheduler_service_account_uid.is_none() =>
                {
                    configuration.scheduler_service_account_uid = Some(value);
                },
                "--cleanup-service-account-uid"
                    if configuration.cleanup_service_account_uid.is_none() =>
                {
                    configuration.cleanup_service_account_uid = Some(value);
                },
                "--kubernetes-ca" if configuration.kubernetes_ca.is_none() => {
                    configuration.kubernetes_ca = Some(absolute(PathBuf::from(value))?);
                },
                "--kubernetes-token" if configuration.kubernetes_token.is_none() => {
                    configuration.kubernetes_token = Some(absolute(PathBuf::from(value))?);
                },
                _ => return Err(USAGE),
            }
        }
        Ok(configuration)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive command matrix keeps forbidden authority combinations visible"
    )]
    fn validate_role_arguments(&self) -> Result<(), &'static str> {
        let state_client = self.state_endpoint.is_some()
            || self.state_ca_bundle.is_some()
            || self.state_ca_sha256.is_some()
            || self.state_ca_root_count.is_some()
            || self.state_token.is_some();
        let state_server = self.state_certificate.is_some()
            || self.state_private_key.is_some()
            || self.scheduler_service_account_uid.is_some()
            || self.cleanup_service_account_uid.is_some();
        let kubernetes_client = self.kubernetes_ca.is_some() || self.kubernetes_token.is_some();
        match self.command {
            Command::Scheduler
                if self.database.is_some()
                    || self.receipts.is_some()
                    || self.digest_key_file.is_some()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.handoff_endpoint.is_some()
                    || state_server
                    || self.kubernetes_ca.is_none()
                    || self.kubernetes_token.is_none()
                    || self.state_endpoint.is_none()
                    || self
                        .state_endpoint
                        .is_some_and(|value| value.port() != 8082)
                    || self.state_ca_bundle.is_none()
                    || self.state_ca_sha256.is_none()
                    || !matches!(self.state_ca_root_count, Some(1 | 2))
                    || self.state_token.is_none() =>
            {
                Err(USAGE)
            },
            Command::Cleanup
                if self.database.is_some()
                    || self.receipts.is_some()
                    || self.digest_key_file.is_some()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.handoff_endpoint.is_some()
                    || state_server
                    || self.kubernetes_ca.is_none()
                    || self.kubernetes_token.is_none()
                    || self.state_endpoint.is_none()
                    || self
                        .state_endpoint
                        .is_some_and(|value| value.port() != 8083)
                    || self.state_ca_bundle.is_none()
                    || self.state_ca_sha256.is_none()
                    || !matches!(self.state_ca_root_count, Some(1 | 2))
                    || self.state_token.is_none() =>
            {
                Err(USAGE)
            },
            Command::SchedulerStateServe
                if !kubernetes_client
                    || self.kubernetes_ca.is_none()
                    || self.kubernetes_token.is_none()
                    || state_client
                    || self.database.is_none()
                    || self.receipts.is_none()
                    || self.digest_key_file.is_none()
                    || self.origin.is_some()
                    || self.listen.is_none()
                    || self.listen.is_some_and(|value| value.port() != 8082)
                    || self.handoff_endpoint.is_none()
                    || self.state_certificate.is_none()
                    || self.state_private_key.is_none()
                    || self.scheduler_service_account_uid.is_none()
                    || self.cleanup_service_account_uid.is_some() =>
            {
                Err(USAGE)
            },
            Command::CleanupStateServe
                if !kubernetes_client
                    || self.kubernetes_ca.is_none()
                    || self.kubernetes_token.is_none()
                    || state_client
                    || self.database.is_none()
                    || self.receipts.is_none()
                    || self.digest_key_file.is_none()
                    || self.origin.is_some()
                    || self.listen.is_none()
                    || self.listen.is_some_and(|value| value.port() != 8083)
                    || self.handoff_endpoint.is_some()
                    || self.state_certificate.is_none()
                    || self.state_private_key.is_none()
                    || self.scheduler_service_account_uid.is_some()
                    || self.cleanup_service_account_uid.is_none() =>
            {
                Err(USAGE)
            },
            Command::Stop | Command::ClearStop
                if self.database.is_none()
                    || self.receipts.is_some()
                    || self.digest_key_file.is_some()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.handoff_endpoint.is_some()
                    || state_client
                    || state_server
                    || kubernetes_client =>
            {
                Err(USAGE)
            },
            Command::Init
                if state_client
                    || state_server
                    || kubernetes_client
                    || self.listen.is_some()
                    || self.handoff_endpoint.is_some() =>
            {
                Err("init does not accept transport configuration")
            },
            Command::Serve
                if state_client
                    || state_server
                    || kubernetes_client
                    || self.listen.is_none()
                    || self.handoff_endpoint.is_some() =>
            {
                Err("serve transport configuration is invalid")
            },
            Command::HandoffServe
                if state_client
                    || state_server
                    || kubernetes_client
                    || self.origin.is_some()
                    || self.listen.is_none()
                    || self.handoff_endpoint.is_some() =>
            {
                Err("handoff-serve transport configuration is invalid")
            },
            Command::Retention
                if state_client
                    || state_server
                    || kubernetes_client
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.handoff_endpoint.is_some() =>
            {
                Err("retention does not accept transport configuration")
            },
            _ => Ok(()),
        }
    }
}

fn require_distinct_tokens(
    role: &str,
    state_token: &Path,
    kubernetes_token: &Path,
) -> Result<(), &'static str> {
    let diagnostic = match role {
        "cleanup" => "cleanup state token must be distinct from Kubernetes API authority",
        _ => "scheduler state token must be distinct from Kubernetes API authority",
    };
    if state_token == kubernetes_token {
        return Err(diagnostic);
    }
    if let (Ok(state), Ok(kubernetes)) = (fs::metadata(state_token), fs::metadata(kubernetes_token))
    {
        if state.dev() == kubernetes.dev() && state.ino() == kubernetes.ino() {
            return Err(diagnostic);
        }
    }
    Ok(())
}

fn parse_sha256(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 {
        return Err("state CA digest is invalid");
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| "state CA digest is invalid")?,
            16,
        )
        .map_err(|_| "state CA digest is invalid")?;
    }
    Ok(output)
}

fn absolute(path: PathBuf) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("operator paths must be absolute");
    }
    Ok(path)
}

fn initialize_directory(path: &Path) -> Result<(), &'static str> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "service directory permissions could not be set"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err("service directory could not be created"),
    }
}

fn read_secret_32(path: &Path) -> Result<[u8; 32], &'static str> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "digest key is unavailable")?;
    let mut file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| "digest key metadata is unavailable")?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner_private =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o400 | 0o600);
    let projected_group_private =
        metadata.gid() == rustix::process::getgid().as_raw() && mode == 0o440;
    if !metadata.is_file() || (!owner_private && !projected_group_private) {
        return Err("digest key must be an owner- or workload-group-private regular file");
    }
    let mut bytes = Vec::with_capacity(33);
    file.by_ref()
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| "digest key could not be read")?;
    bytes
        .try_into()
        .map_err(|_| "digest key must contain exactly 32 bytes")
}

fn unix_time() -> Result<i64, &'static str> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system time is out of range")
}
