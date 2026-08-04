//! Integration-test process entry for the private unprivileged state-root profile.

fn main() -> std::process::ExitCode {
    kapsel_sandbox::run_state_root_test_harness()
}
