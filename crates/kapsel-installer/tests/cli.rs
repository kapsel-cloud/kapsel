//! Black-box command grammar and development-bundle refusal.

#![allow(
    clippy::panic,
    reason = "fixture setup and subprocess failures must fail the owning test immediately"
)]

use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::ffi::OsStringExt as _,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const FAILURE_PREFIX: &str = "Kapsel installer failure: ";

fn run(arguments: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kapsel-installer"))
        .args(arguments)
        .env("KUBECONFIG", "/must/not/be/read")
        .output()
        .unwrap_or_else(|error| panic!("installer subprocess failed: {error}"))
}

fn assert_private_failure(output: &Output, class: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("{FAILURE_PREFIX}{class}\n")
    );
    assert!(output.stderr.len() <= 4 * 1024);
}

#[test]
fn exact_three_commands_reach_the_unavailable_bundle_boundary_without_mutation() {
    let temporary = std::env::temp_dir().join(format!(
        "kapsel-installer-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir(&temporary).unwrap_or_else(|error| panic!("fixture create failed: {error}"));

    for command in ["install", "refresh-credential", "uninstall"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel-installer"))
            .args([
                command,
                "--operator-input",
                "/secure/kapsel",
                "--kube-context",
                "nonprod.example",
            ])
            .current_dir(&temporary)
            .env("HOME", &temporary)
            .env("KUBECONFIG", "/must/not/be/read")
            .output()
            .unwrap_or_else(|error| panic!("installer subprocess failed: {error}"));
        assert_private_failure(&output, "bundle_unavailable");
        let entries = fs::read_dir(&temporary)
            .unwrap_or_else(|error| panic!("fixture read failed: {error}"))
            .count();
        assert_eq!(entries, 0);
    }

    fs::remove_dir(&temporary).unwrap_or_else(|error| panic!("fixture cleanup failed: {error}"));
}

#[test]
fn option_order_is_insignificant_but_each_option_is_required_exactly_once() {
    let accepted = run(&[
        OsStr::new("install"),
        OsStr::new("--kube-context"),
        OsStr::new("nonprod"),
        OsStr::new("--operator-input"),
        OsStr::new("/secure/kapsel"),
    ]);
    assert_private_failure(&accepted, "bundle_unavailable");

    for arguments in [
        vec!["install", "--operator-input", "/secure/kapsel"],
        vec!["install", "--kube-context", "nonprod"],
        vec![
            "install",
            "--operator-input",
            "/secure/kapsel",
            "--operator-input",
            "/other",
            "--kube-context",
            "nonprod",
        ],
        vec![
            "install",
            "--operator-input",
            "/secure/kapsel",
            "--kube-context",
            "nonprod",
            "--kube-context",
            "other",
        ],
    ] {
        let arguments = arguments.iter().map(OsStr::new).collect::<Vec<_>>();
        assert_private_failure(&run(&arguments), "invalid_arguments");
    }
}

#[test]
fn kubernetes_context_boundaries_are_exact() {
    let maximum = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let oversized = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    for context in ["0", "nonprod.example", maximum.as_str()] {
        let output = run(&[
            OsStr::new("install"),
            OsStr::new("--operator-input"),
            OsStr::new("/secure/kapsel"),
            OsStr::new("--kube-context"),
            OsStr::new(context),
        ]);
        assert_private_failure(&output, "bundle_unavailable");
    }
    for context in [
        "",
        "-bad",
        "bad-",
        "bad..name",
        "Uppercase",
        &"a".repeat(64),
        oversized.as_str(),
    ] {
        let output = run(&[
            OsStr::new("install"),
            OsStr::new("--operator-input"),
            OsStr::new("/secure/kapsel"),
            OsStr::new("--kube-context"),
            OsStr::new(context),
        ]);
        assert_private_failure(&output, "invalid_arguments");
    }

    let non_utf8 = OsString::from_vec(vec![0xff]);
    let output = run(&[
        OsStr::new("install"),
        OsStr::new("--operator-input"),
        OsStr::new("/secure/kapsel"),
        OsStr::new("--kube-context"),
        &non_utf8,
    ]);
    assert_private_failure(&output, "invalid_arguments");
}

#[test]
fn unknown_commands_options_positionals_and_hostile_values_are_rejected_without_disclosure() {
    assert_private_failure(&run(&[]), "invalid_arguments");
    let cases = [
        vec![String::new()],
        vec!["upgrade".to_owned()],
        vec![
            "install".to_owned(),
            "--operator-input".to_owned(),
            "relative/secret-input".to_owned(),
            "--kube-context".to_owned(),
            "nonprod".to_owned(),
        ],
        vec![
            "install".to_owned(),
            "--operator-input".to_owned(),
            "/secret/input".to_owned(),
            "--kube-context".to_owned(),
            "Uppercase".to_owned(),
        ],
        vec![
            "install".to_owned(),
            "--operator-input".to_owned(),
            "/secret/input".to_owned(),
            "--kube-context".to_owned(),
            "bad..context".to_owned(),
        ],
        vec![
            "install".to_owned(),
            "--operator-input".to_owned(),
            "/secret/input".to_owned(),
            "--kube-context".to_owned(),
            "nonprod".to_owned(),
            "trailing-secret".to_owned(),
        ],
        vec![
            "install".to_owned(),
            "--operator-input".to_owned(),
            "/secret/input".to_owned(),
            "--kube-context".to_owned(),
            "nonprod".to_owned(),
            "--force".to_owned(),
            "true".to_owned(),
        ],
    ];

    for arguments in cases {
        let arguments = arguments.iter().map(OsStr::new).collect::<Vec<_>>();
        let output = run(&arguments);
        assert_private_failure(&output, "invalid_arguments");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("secret"));
    }
}
