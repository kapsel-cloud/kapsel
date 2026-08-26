//! Process shell for the unpublished KAP-0074 resident socket candidate.

mod server;
#[cfg(target_os = "linux")]
mod startup;

use std::process::ExitCode;

fn main() -> ExitCode {
    server::run()
}
