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
    time::{SystemTime, UNIX_EPOCH},
};

use kapsel_sandbox::{set_global_stop, Service};

const USAGE: &str = "usage: kapsel-sandbox <init|serve> --database <absolute-path> \
--receipts <absolute-directory> --digest-key-file <absolute-path> \
[--origin <https-origin>] [--listen <socket-address>]; or kapsel-sandbox \
<stop|clear-stop> --database <absolute-path>";

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
    let configuration = Configuration::parse(env::args().skip(1))?;
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
        Command::Init | Command::Serve => {
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
            service
                .set_origin(
                    configuration
                        .origin
                        .as_deref()
                        .unwrap_or("https://kapsel.invalid"),
                )
                .map_err(|_| "origin is invalid")?;
            match configuration.command {
                Command::Init => reject_listen(configuration.listen),
                Command::Serve => {
                    let listen = configuration.listen.ok_or("serve requires --listen")?;
                    native_listener::serve(service, listen)
                },
                Command::Stop | Command::ClearStop => unreachable!(),
            }
        },
    }
}

fn reject_listen(listen: Option<SocketAddr>) -> Result<(), &'static str> {
    if listen.is_some() {
        return Err("operator stop commands do not accept --listen");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Command {
    Init,
    Serve,
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
