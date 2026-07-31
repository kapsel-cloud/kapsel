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
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{
    run_runner_process, serve_private_handoff, set_global_stop, ControllerConfiguration,
    ControllerRole, RetentionRole, Service,
};

const USAGE: &str = concat!(
    "usage: kapsel-sandbox <init|serve|handoff-serve|controller|retention|stop|clear-stop> ",
    "<role-specific arguments>"
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

fn run() -> Result<(), &'static str> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() == Some("runner-bootstrap") {
        return run_runner_process(env::args().skip(2));
    }
    let configuration = Configuration::parse(env::args().skip(1))?;
    configuration.validate_role_arguments()?;
    if matches!(configuration.command, Command::Stop | Command::ClearStop) {
        let database = configuration.database.as_ref().ok_or(USAGE)?;
        let stopped = matches!(configuration.command, Command::Stop);
        return set_global_stop(database, stopped).map_err(|_| {
            if stopped {
                "global stop could not be committed"
            } else {
                "global stop could not be cleared"
            }
        });
    }

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
        Command::Controller => run_controller(
            service,
            ControllerConfiguration::new(
                configuration.runner_inputs.ok_or(USAGE)?,
                configuration.runner_generations.ok_or(USAGE)?,
                configuration.runner_uid.ok_or(USAGE)?,
                configuration.runner_gid.ok_or(USAGE)?,
                configuration.handoff_endpoint.ok_or(USAGE)?,
            ),
        ),
        Command::Retention => run_retention(service),
        Command::Stop | Command::ClearStop => unreachable!(),
    }
}

fn set_origin(service: &mut Service, origin: Option<&str>) -> Result<(), &'static str> {
    service
        .set_origin(origin.unwrap_or("https://kapsel.invalid"))
        .map_err(|_| "origin is invalid")
}

fn run_controller(
    service: Service,
    configuration: ControllerConfiguration,
) -> Result<(), &'static str> {
    let mut role = ControllerRole::new(service, configuration);
    loop {
        match role
            .run_once(unix_time()?)
            .map_err(|_| "controller scheduling or runner launch failed")?
        {
            Some(_) => {
                if !role
                    .wait()
                    .map_err(|_| "controller runner wait failed")?
                    .success()
                {
                    return Err("controller runner failed");
                }
            },
            None => thread::sleep(Duration::from_secs(1)),
        }
    }
}

fn run_retention(service: Service) -> Result<(), &'static str> {
    let role = RetentionRole::new(service);
    loop {
        thread::sleep(RETENTION_INTERVAL);
        role.run_once(unix_time()?)
            .map_err(|_| "retention sweep failed")?;
    }
}

#[derive(Clone, Copy)]
enum Command {
    Init,
    Serve,
    HandoffServe,
    Controller,
    Retention,
    Stop,
    ClearStop,
}

struct Configuration {
    command: Command,
    database: Option<PathBuf>,
    receipts: Option<PathBuf>,
    digest_key_file: Option<PathBuf>,
    origin: Option<String>,
    listen: Option<std::net::SocketAddr>,
    runner_inputs: Option<PathBuf>,
    runner_generations: Option<PathBuf>,
    runner_uid: Option<u32>,
    runner_gid: Option<u32>,
    handoff_endpoint: Option<std::net::SocketAddr>,
}

impl Configuration {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let mut arguments = arguments;
        let command = match arguments.next().as_deref() {
            Some("init") => Command::Init,
            Some("serve") => Command::Serve,
            Some("handoff-serve") => Command::HandoffServe,
            Some("controller") => Command::Controller,
            Some("retention") => Command::Retention,
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
            runner_inputs: None,
            runner_generations: None,
            runner_uid: None,
            runner_gid: None,
            handoff_endpoint: None,
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
                "--runner-inputs" if configuration.runner_inputs.is_none() => {
                    configuration.runner_inputs = Some(absolute(PathBuf::from(value))?);
                },
                "--runner-generations" if configuration.runner_generations.is_none() => {
                    configuration.runner_generations = Some(absolute(PathBuf::from(value))?);
                },
                "--runner-uid" if configuration.runner_uid.is_none() => {
                    configuration.runner_uid =
                        Some(value.parse().map_err(|_| "runner uid is invalid")?);
                },
                "--runner-gid" if configuration.runner_gid.is_none() => {
                    configuration.runner_gid =
                        Some(value.parse().map_err(|_| "runner gid is invalid")?);
                },
                "--handoff-endpoint" if configuration.handoff_endpoint.is_none() => {
                    let endpoint = value
                        .parse::<std::net::SocketAddr>()
                        .map_err(|_| "handoff endpoint is invalid")?;
                    if !endpoint.ip().is_loopback() {
                        return Err("handoff endpoint must be loopback");
                    }
                    configuration.handoff_endpoint = Some(endpoint);
                },
                _ => return Err(USAGE),
            }
        }
        Ok(configuration)
    }

    fn validate_role_arguments(&self) -> Result<(), &'static str> {
        match self.command {
            Command::Stop | Command::ClearStop
                if self.database.is_none()
                    || self.receipts.is_some()
                    || self.digest_key_file.is_some()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.has_runner_configuration() =>
            {
                Err(USAGE)
            },
            Command::Init if self.listen.is_some() || self.has_runner_configuration() => {
                Err("init does not accept transport or runner configuration")
            },
            Command::Serve if self.listen.is_none() => {
                Err("serve transport configuration is invalid")
            },
            Command::HandoffServe
                if self.origin.is_some()
                    || self.listen.is_none()
                    || self.has_runner_configuration() =>
            {
                Err("handoff-serve transport configuration is invalid")
            },
            Command::Controller
                if self.origin.is_some()
                    || self.listen.is_some()
                    || self.runner_inputs.is_none()
                    || self.runner_generations.is_none()
                    || self.runner_uid.is_none()
                    || self.runner_gid.is_none()
                    || self.handoff_endpoint.is_none() =>
            {
                Err("controller runner configuration is invalid")
            },
            Command::Retention
                if self.origin.is_some()
                    || self.listen.is_some()
                    || self.has_runner_configuration() =>
            {
                Err("retention does not accept transport or runner configuration")
            },
            Command::Stop | Command::ClearStop => Ok(()),
            _ if self.database.is_none()
                || self.receipts.is_none()
                || self.digest_key_file.is_none() =>
            {
                Err(USAGE)
            },
            _ if !matches!(self.command, Command::Controller)
                && self.has_runner_configuration() =>
            {
                Err(USAGE)
            },
            _ => Ok(()),
        }
    }

    fn has_runner_configuration(&self) -> bool {
        self.runner_inputs.is_some()
            || self.runner_generations.is_some()
            || self.runner_uid.is_some()
            || self.runner_gid.is_some()
            || self.handoff_endpoint.is_some()
    }
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
