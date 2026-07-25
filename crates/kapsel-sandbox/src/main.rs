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

use kapsel_sandbox::{run_runner_process, serve_private_handoff, set_global_stop, Service};

const USAGE: &str = "usage: kapsel-sandbox <init|serve|handoff-serve|retention> \
--database <absolute-path> --receipts <absolute-directory> \
--digest-key-file <absolute-path> [--origin <https-origin>] \
[--listen <socket-address>]; or kapsel-sandbox <stop|clear-stop> \
--database <absolute-path>; or kapsel-sandbox runner --operator-composition \
<absolute-path> --handoff <absolute-directory>";
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
    if arguments.next().as_deref() == Some("runner") {
        return run_runner_process(arguments);
    }
    let configuration = Configuration::parse(env::args().skip(1))?;
    configuration.validate_role_arguments()?;
    match configuration.command {
        Command::Stop | Command::ClearStop => {
            if configuration.receipts.is_some()
                || configuration.digest_key_file.is_some()
                || configuration.origin.is_some()
                || configuration.listen.is_some()
            {
                return Err(USAGE);
            }
            let stopped = matches!(configuration.command, Command::Stop);
            set_global_stop(&configuration.database, stopped).map_err(|_| {
                if stopped {
                    "global stop could not be committed"
                } else {
                    "global stop could not be cleared"
                }
            })
        },
        Command::Init | Command::Serve | Command::HandoffServe | Command::Retention => {
            let receipts = configuration.receipts.ok_or(USAGE)?;
            let digest_key_file = configuration.digest_key_file.ok_or(USAGE)?;
            if matches!(configuration.command, Command::Init) {
                initialize_directory(
                    configuration
                        .database
                        .parent()
                        .ok_or("database parent is unavailable")?,
                )?;
                initialize_directory(&receipts)?;
            }
            let digest_key = read_secret_32(&digest_key_file)?;
            let mut service =
                Service::open(&configuration.database, &receipts, digest_key, unix_time()?)
                    .map_err(|_| "service state is unavailable")?;
            match configuration.command {
                Command::Init => set_origin(&mut service, configuration.origin.as_deref()),
                Command::Serve => {
                    set_origin(&mut service, configuration.origin.as_deref())?;
                    let listen = configuration.listen.ok_or("serve requires --listen")?;
                    native_listener::serve(service, listen)
                },
                Command::HandoffServe => {
                    let listen = configuration
                        .listen
                        .ok_or("handoff-serve requires --listen")?;
                    let listener = std::net::TcpListener::bind(listen)
                        .map_err(|_| "private handoff listener is unavailable")?;
                    serve_private_handoff(&listener, &std::sync::Arc::new(service))
                        .map_err(|_| "private handoff listener failed")
                },
                Command::Retention => run_retention(&service),
                Command::Stop | Command::ClearStop => unreachable!(),
            }
        },
    }
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
    Stop,
    ClearStop,
}

struct Configuration {
    command: Command,
    database: PathBuf,
    receipts: Option<PathBuf>,
    digest_key_file: Option<PathBuf>,
    origin: Option<String>,
    listen: Option<SocketAddr>,
}

impl Configuration {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let mut arguments = arguments;
        let command = match arguments.next().as_deref() {
            Some("init") => Command::Init,
            Some("serve") => Command::Serve,
            Some("handoff-serve") => Command::HandoffServe,
            Some("retention") => Command::Retention,
            Some("stop") => Command::Stop,
            Some("clear-stop") => Command::ClearStop,
            _ => return Err(USAGE),
        };
        let mut database = None;
        let mut receipts = None;
        let mut digest_key_file = None;
        let mut origin = None;
        let mut listen = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(USAGE)?;
            match flag.as_str() {
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--receipts" if receipts.is_none() => receipts = Some(PathBuf::from(value)),
                "--digest-key-file" if digest_key_file.is_none() => {
                    digest_key_file = Some(PathBuf::from(value));
                },
                "--origin" if origin.is_none() => origin = Some(value),
                "--listen" if listen.is_none() => {
                    listen = Some(value.parse().map_err(|_| "listen address is invalid")?);
                },
                _ => return Err(USAGE),
            }
        }
        let database = absolute(database.ok_or(USAGE)?)?;
        let receipts = receipts.map(absolute).transpose()?;
        let digest_key_file = digest_key_file.map(absolute).transpose()?;
        Ok(Self {
            command,
            database,
            receipts,
            digest_key_file,
            origin,
            listen,
        })
    }

    fn validate_role_arguments(&self) -> Result<(), &'static str> {
        match self.command {
            Command::Init if self.listen.is_some() => Err("init does not accept --listen"),
            Command::Serve if self.listen.is_none() => Err("serve requires --listen"),
            Command::HandoffServe if self.origin.is_some() => {
                Err("handoff-serve does not accept --origin")
            },
            Command::HandoffServe if self.listen.is_none() => {
                Err("handoff-serve requires --listen")
            },
            Command::Retention if self.origin.is_some() => {
                Err("retention does not accept --origin")
            },
            Command::Retention if self.listen.is_some() => {
                Err("retention does not accept --listen")
            },
            _ => Ok(()),
        }
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
