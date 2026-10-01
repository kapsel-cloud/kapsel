//! Process shell for the unpublished Kapsel service.

mod diagnostics;
mod server;
#[cfg(target_os = "linux")]
mod startup;

use std::{ffi::OsStr, io::Write as _, process::ExitCode};

use diagnostics::emit as diagnostic;

const HELP: &str = "kapseld: operator-owned Linux resident service
Usage:
  kapseld --help | --version
  kapseld --operator-config /etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock
  kapseld --replace-operator-config < candidate.json
Use systemctl start/stop/status kapseld.service and journalctl -u kapseld.service.
Replacement requires the service identity and a stopped daemon. Retain all history.
Replacement: PUBLISHED/0, NOT_PUBLISHED/4, INDETERMINATE/5.
Lost responses require inspection, never automatic replay. Invalid usage exits 2.";

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let [argument] = arguments.as_slice() {
        let text = if argument == "--help" {
            Some(HELP.to_owned())
        } else if argument == "--version" {
            Some(format!("kapseld {}", env!("CARGO_PKG_VERSION")))
        } else {
            None
        };
        if let Some(text) = text {
            return if writeln!(std::io::stdout(), "{text}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            };
        }
    }
    let replace = arguments.as_slice() == [OsStr::new("--replace-operator-config")];
    let serve = arguments.as_slice()
        == [
            OsStr::new("--operator-config"),
            OsStr::new("/etc/kapsel/operator.json"),
            OsStr::new("--socket"),
            OsStr::new("/run/kapsel/kapseld.sock"),
        ];
    #[cfg(feature = "test-harness")]
    let serve = serve || std::env::var_os("KAPSELD_TEST_SOCKET").is_some();
    if !serve && !replace {
        let _ = writeln!(
            std::io::stderr(),
            "kapseld: invalid_usage: use kapseld --help"
        );
        return ExitCode::from(2);
    }
    diagnostics::initialize();
    // The journal surface accepts fixed codes, never panic payloads or source paths.
    std::panic::set_hook(Box::new(|_| diagnostic("internal_failure")));
    server::run(replace)
}
