//! Local evaluator command for the pre-V1 KAP-0038 experiment.

mod command;
mod mcp;

use std::{io::Write as _, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let subcommand = arguments.next();
    if subcommand.as_deref() == Some(std::ffi::OsStr::new("mcp")) {
        return mcp::run(arguments);
    }
    match command::run(subcommand.into_iter().chain(arguments)) {
        Ok(output) => {
            if writeln!(std::io::stdout().lock(), "{output}").is_err() {
                return ExitCode::from(4);
            }
            ExitCode::SUCCESS
        },
        Err(error) => {
            let machine = error.machine_output();
            let diagnostic = error.diagnostic();
            let _ = writeln!(std::io::stdout().lock(), "{machine}");
            let _ = writeln!(std::io::stderr().lock(), "{diagnostic}");
            ExitCode::from(error.exit_code())
        },
    }
}
