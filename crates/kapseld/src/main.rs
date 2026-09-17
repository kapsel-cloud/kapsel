//! Process shell for the unpublished Kapsel service.

mod diagnostics;
mod server;
#[cfg(target_os = "linux")]
mod startup;

use std::process::ExitCode;

use diagnostics::emit as diagnostic;

fn main() -> ExitCode {
    diagnostics::initialize();
    // The journal surface accepts fixed codes, never panic payloads or source paths.
    std::panic::set_hook(Box::new(|_| diagnostic("internal_failure")));
    server::run()
}
