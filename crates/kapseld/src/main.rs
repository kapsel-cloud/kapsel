//! Process shell for the unpublished Kapsel service.

mod server;
#[cfg(target_os = "linux")]
mod startup;

use std::process::ExitCode;

fn main() -> ExitCode {
    server::run()
}
