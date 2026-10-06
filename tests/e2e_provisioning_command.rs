//! Operator provisioning survives retirement of direct caller execution.

#![allow(
    clippy::unwrap_used,
    reason = "controlled binary fixtures fail immediately"
)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn operator_can_provision_exact_grant_without_overwriting_or_accepting_bad_seeds() {
    let root = std::env::temp_dir().join(format!("kapsel-e2e-provision-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let authorization = root.join("authorization.json");
    let seed = root.join("owner.seed");
    let grant = root.join("grant.bin");
    fs::write(
        &authorization,
        serde_json::to_vec(&serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("example/api@sha256:{}", "a".repeat(64)),
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&seed, [7; 32]).unwrap();
    let run = |output: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .arg("provision-grant")
            .arg("--authorization")
            .arg(&authorization)
            .arg("--signing-seed")
            .arg(&seed)
            .args(["--signing-key-id", "owner-key"])
            .arg("--output")
            .arg(output)
            .output()
            .unwrap()
    };
    let output = run(&grant);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"command\":\"provision-grant\",\"status\":\"PROVISIONED\"}\n"
    );
    assert_eq!(
        fs::metadata(&grant).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = fs::read(&grant).unwrap();
    assert_eq!(run(&grant).status.code(), Some(3));
    assert_eq!(fs::read(&grant).unwrap(), original);
    for length in [31, 33] {
        fs::write(&seed, vec![7; length]).unwrap();
        let destination = root.join(format!("bad-{length}.grant"));
        assert_eq!(run(&destination).status.code(), Some(3));
        assert!(!destination.exists());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_execution_commands_are_rejected_before_reading_operator_or_request_paths() {
    for command in ["operate", "mcp"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([command, "--operator-config", "/unavailable/operator.json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            output.stdout,
            b"{\"command\":\"kapsel\",\"status\":\"ERROR\",\"error_class\":\"command_input\"}\n"
        );
        assert!(output.stderr.len() < 4096);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(!help.contains("kapsel operate"));
    assert!(!help.contains("kapsel mcp --"));
    assert!(help.contains("kapseld"));
    assert!(help.contains("kapsel inspect"));
}
