//! Native process composition for the fixed Kapsel sandbox.

#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "the operator process emits only bounded startup and fixed local error status"
)]

#[path = "native_listener.rs"]
mod native_listener;

use std::{
    env,
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    run_runner_process, serve_private_handoff, state_root, AuthorityConfiguration,
    CleanupController, ControllerConfiguration, ControllerRole, RetentionController, Service,
};

const USAGE: &str = concat!(
    "usage: kapsel-sandbox ",
    "<stage-authority|init|serve|handoff-serve|controller|retention|stop|clear-stop> ",
    "<role-specific arguments>"
);
const RETENTION_INTERVAL: Duration = Duration::from_mins(1);

pub(crate) fn main(profile: state_root::DeploymentProfile) -> ExitCode {
    match run(profile) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kapsel-sandbox: {message}");
            ExitCode::from(2)
        },
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed closed command composition keeps role fencing and state guards visible"
)]
fn run(profile: state_root::DeploymentProfile) -> Result<(), &'static str> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() == Some("runner-bootstrap") {
        return run_runner_process(env::args().skip(2));
    }
    let configuration = Configuration::parse(env::args().skip(1))?;
    configuration.validate_role_arguments()?;
    if matches!(configuration.command, Command::StageAuthority) {
        role_identities(&configuration, profile)
            .map_err(|()| "production role identities are invalid")?;
        let authority = AuthorityConfiguration::new(
            configuration.authority_root.clone().ok_or(USAGE)?,
            configuration.controller_uid.ok_or(USAGE)?,
            configuration.controller_gid.ok_or(USAGE)?,
            configuration.staging_uid.ok_or(USAGE)?,
            configuration.staging_gid.ok_or(USAGE)?,
        );
        authority
            .activate_incoming()
            .map_err(|_| "incoming authority activation failed")?;
        return Ok(());
    }
    if matches!(configuration.command, Command::Stop | Command::ClearStop) {
        let identities = controller_identity(profile);
        let state = state_root::StateGuard::open(
            configuration.state_root.as_ref().ok_or(USAGE)?,
            identities,
            profile,
        )
        .map_err(|()| "service state is unavailable")?;
        let stopped = matches!(configuration.command, Command::Stop);
        return state.set_global_stop(stopped).map_err(|_| {
            if stopped {
                "global stop could not be committed"
            } else {
                "global stop could not be cleared"
            }
        });
    }

    let mut identities = role_identities(&configuration, profile)
        .map_err(|()| "production role identities are invalid")?;
    if matches!(configuration.command, Command::Controller) {
        identities = identities
            .validate_runner(
                configuration.runner_uid.ok_or(USAGE)?,
                configuration.runner_gid.ok_or(USAGE)?,
            )
            .map_err(|()| "production runner identity is invalid")?;
    }
    let authority = AuthorityConfiguration::new(
        configuration.authority_root.clone().ok_or(USAGE)?,
        configuration.controller_uid.ok_or(USAGE)?,
        configuration.controller_gid.ok_or(USAGE)?,
        configuration.staging_uid.ok_or(USAGE)?,
        configuration.staging_gid.ok_or(USAGE)?,
    );
    if matches!(configuration.command, Command::Init) {
        let initializer = state_root::StateInitializer::begin(
            configuration.state_root.as_ref().ok_or(USAGE)?,
            identities,
            &authority,
            profile,
        )
        .map_err(|()| "service state could not be initialized")?;
        let now = unix_time()?;
        if initializer.is_migration() {
            if configuration.origin.is_some() {
                return Err("migration cannot change the existing origin");
            }
            return initializer
                .publish(now)
                .map_err(|()| "service state could not be published");
        }
        let mut service = Service::open(
            initializer
                .database()
                .map_err(|()| "service state was substituted")?,
            initializer
                .receipts()
                .map_err(|()| "service state was substituted")?,
            &authority,
            now,
        )
        .map_err(|_| "service state is unavailable")?;
        initializer
            .verify()
            .map_err(|()| "service state was substituted")?;
        set_origin(&mut service, configuration.origin.as_deref())?;
        drop(service);
        return initializer
            .publish(now)
            .map_err(|()| "service state could not be published");
    }
    let state = state_root::StateGuard::open(
        configuration.state_root.as_ref().ok_or(USAGE)?,
        identities,
        profile,
    )
    .map_err(|()| "service state is unavailable")?;
    let mut service = state
        .open_service(&authority, unix_time()?)
        .map_err(|_| "service state is unavailable")?;
    state
        .verify()
        .map_err(|()| "service state was substituted")?;
    match configuration.command {
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
                state
                    .runner()
                    .map_err(|()| "service state was substituted")?,
                configuration.runner_uid.ok_or(USAGE)?,
                configuration.runner_gid.ok_or(USAGE)?,
            ),
        ),
        Command::Retention => run_retention(service),
        Command::Init | Command::StageAuthority | Command::Stop | Command::ClearStop => {
            unreachable!()
        },
    }
}

#[allow(
    clippy::similar_names,
    reason = "fixed controller and staging UID/GID pairs remain deliberately explicit"
)]
fn role_identities(
    configuration: &Configuration,
    profile: state_root::DeploymentProfile,
) -> Result<state_root::RoleIdentities, ()> {
    let controller_uid = configuration.controller_uid.ok_or(())?;
    let controller_gid = configuration.controller_gid.ok_or(())?;
    let staging_uid = configuration.staging_uid.ok_or(())?;
    let staging_gid = configuration.staging_gid.ok_or(())?;
    match profile {
        state_root::DeploymentProfile::Production => {
            state_root::RoleIdentities::validate_authority(
                controller_uid,
                controller_gid,
                staging_uid,
                staging_gid,
            )
        },
        #[cfg(any(test, feature = "state-root-test-harness"))]
        state_root::DeploymentProfile::Test => state_root::RoleIdentities::validate_test_authority(
            controller_uid,
            controller_gid,
            staging_uid,
            staging_gid,
        ),
    }
}

fn controller_identity(profile: state_root::DeploymentProfile) -> state_root::RoleIdentities {
    match profile {
        state_root::DeploymentProfile::Production => state_root::RoleIdentities::controller(),
        #[cfg(any(test, feature = "state-root-test-harness"))]
        state_root::DeploymentProfile::Test => state_root::RoleIdentities::test_controller(),
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
    let cleanup = CleanupController::new(service.clone());
    let mut role = ControllerRole::new(service, configuration);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "controller cleanup runtime is unavailable")?;
    loop {
        let now_unix_s = unix_time()?;
        if role
            .run_once(now_unix_s)
            .map_err(|_| "controller scheduling or runner launch failed")?
            .is_some()
        {
            if !role
                .wait()
                .map_err(|_| "controller runner wait failed")?
                .success()
            {
                return Err("controller runner failed");
            }
        } else {
            runtime
                .block_on(cleanup.run_once(now_unix_s))
                .map_err(|_| "controller cleanup failed")?;
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn run_retention(service: Service) -> Result<(), &'static str> {
    let role = RetentionController::new(service);
    loop {
        role.run_once(unix_time()?)
            .map_err(|_| "retention sweep failed")?;
        thread::sleep(RETENTION_INTERVAL);
    }
}

#[derive(Clone, Copy)]
enum Command {
    StageAuthority,
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
    state_root: Option<PathBuf>,
    origin: Option<String>,
    listen: Option<std::net::SocketAddr>,
    runner_uid: Option<u32>,
    runner_gid: Option<u32>,
    authority_root: Option<PathBuf>,
    controller_uid: Option<u32>,
    controller_gid: Option<u32>,
    staging_uid: Option<u32>,
    staging_gid: Option<u32>,
}

impl Configuration {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let mut arguments = arguments;
        let command = match arguments.next().as_deref() {
            Some("stage-authority") => Command::StageAuthority,
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
            state_root: None,
            origin: None,
            listen: None,
            runner_uid: None,
            runner_gid: None,
            authority_root: None,
            controller_uid: None,
            controller_gid: None,
            staging_uid: None,
            staging_gid: None,
        };
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or(USAGE)?;
            match flag.as_str() {
                "--state-root" if configuration.state_root.is_none() => {
                    configuration.state_root = Some(absolute(PathBuf::from(value))?);
                },
                "--origin" if configuration.origin.is_none() => configuration.origin = Some(value),
                "--listen" if configuration.listen.is_none() => {
                    configuration.listen =
                        Some(value.parse().map_err(|_| "listen address is invalid")?);
                },

                "--runner-uid" if configuration.runner_uid.is_none() => {
                    configuration.runner_uid =
                        Some(value.parse().map_err(|_| "runner uid is invalid")?);
                },
                "--runner-gid" if configuration.runner_gid.is_none() => {
                    configuration.runner_gid =
                        Some(value.parse().map_err(|_| "runner gid is invalid")?);
                },
                "--authority-root" if configuration.authority_root.is_none() => {
                    configuration.authority_root = Some(absolute(PathBuf::from(value))?);
                },
                "--controller-uid" if configuration.controller_uid.is_none() => {
                    configuration.controller_uid =
                        Some(value.parse().map_err(|_| "controller uid is invalid")?);
                },
                "--controller-gid" if configuration.controller_gid.is_none() => {
                    configuration.controller_gid =
                        Some(value.parse().map_err(|_| "controller gid is invalid")?);
                },
                "--staging-uid" if configuration.staging_uid.is_none() => {
                    configuration.staging_uid =
                        Some(value.parse().map_err(|_| "staging uid is invalid")?);
                },
                "--staging-gid" if configuration.staging_gid.is_none() => {
                    configuration.staging_gid =
                        Some(value.parse().map_err(|_| "staging gid is invalid")?);
                },
                _ => return Err(USAGE),
            }
        }
        Ok(configuration)
    }

    fn validate_role_arguments(&self) -> Result<(), &'static str> {
        match self.command {
            Command::StageAuthority
                if self.state_root.is_some()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.has_runner_configuration()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("stage-authority configuration is invalid")
            },
            Command::Stop | Command::ClearStop
                if self.state_root.is_none()
                    || self.origin.is_some()
                    || self.listen.is_some()
                    || self.has_runner_configuration()
                    || self.has_authority_configuration() =>
            {
                Err(USAGE)
            },
            Command::Init
                if self.listen.is_some()
                    || self.has_runner_configuration()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("init authority configuration is invalid")
            },
            Command::Serve
                if self.listen.is_none()
                    || self.has_runner_configuration()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("serve transport configuration is invalid")
            },
            Command::HandoffServe
                if self.origin.is_some()
                    || self.listen.is_none()
                    || self.has_runner_configuration()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("handoff-serve transport or authority configuration is invalid")
            },
            Command::Controller
                if self.origin.is_some()
                    || self.listen.is_some()
                    || self.runner_uid.is_none()
                    || self.runner_gid.is_none()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("controller runner or authority configuration is invalid")
            },
            Command::Retention
                if self.origin.is_some()
                    || self.listen.is_some()
                    || self.has_runner_configuration()
                    || !self.has_complete_authority_configuration() =>
            {
                Err("retention authority configuration is invalid")
            },
            Command::StageAuthority | Command::Stop | Command::ClearStop => Ok(()),
            _ if self.state_root.is_none() || !self.has_complete_authority_configuration() => {
                Err(USAGE)
            },
            _ => Ok(()),
        }
    }

    fn has_runner_configuration(&self) -> bool {
        self.runner_uid.is_some() || self.runner_gid.is_some()
    }

    fn has_authority_configuration(&self) -> bool {
        self.authority_root.is_some()
            || self.controller_uid.is_some()
            || self.controller_gid.is_some()
            || self.staging_uid.is_some()
            || self.staging_gid.is_some()
    }

    fn has_complete_authority_configuration(&self) -> bool {
        self.authority_root.is_some()
            && self.controller_uid.is_some()
            && self.controller_gid.is_some()
            && self.staging_uid.is_some()
            && self.staging_gid.is_some()
    }
}

fn absolute(path: PathBuf) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("operator paths must be absolute");
    }
    Ok(path)
}

fn unix_time() -> Result<i64, &'static str> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system time is out of range")
}
