//! Black-box package-version identity proof.

use std::process::Command;

#[test]
fn version_reports_the_exact_package_identity_without_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("kapsel {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn version_rejects_additional_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args(["--version", "unexpected"])
        .env_clear()
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"command\":\"kapsel\",\"status\":\"ERROR\",\"error_class\":\"command_input\"}\n"
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Kapsel command failure: command_input\n"
    );
}
