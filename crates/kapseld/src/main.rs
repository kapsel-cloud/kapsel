//! Process shell for the unpublished KAP-0074 resident socket candidate.

mod server;

use std::process::ExitCode;

fn main() -> ExitCode {
    server::run()
}
