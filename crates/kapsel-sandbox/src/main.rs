//! Native process entry for the fixed Kapsel sandbox.

fn main() -> std::process::ExitCode {
    kapsel_sandbox::run_native_process()
}
