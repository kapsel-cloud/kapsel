//! Operator provisioning and offline inspection executable for Kapsel.

mod command;
mod transport_support;

use std::{io::Write as _, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let subcommand = arguments.next();
    match command::run(subcommand.into_iter().chain(arguments)) {
        Ok(output) => {
            if writeln!(std::io::stdout().lock(), "{output}").is_err() {
                return ExitCode::from(4);
            }
            ExitCode::SUCCESS
        },
        Err(error) => {
            let machine_output = error.machine_output();
            let diagnostic = error.diagnostic();
            let _ = writeln!(std::io::stdout().lock(), "{machine_output}");
            let _ = writeln!(std::io::stderr().lock(), "{diagnostic}");
            ExitCode::from(error.exit_code())
        },
    }
}
