//! Black-box contract tests for the production offline inspection command.

#![allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the end-to-end test immediately"
)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use ed25519_dalek::SigningKey;
use kapsel::ReceiptTrust;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "kapsel-e2e-inspection-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let receipt = root.join("receipt.bin");
    let trust = root.join("trust.bin");
    fs::write(
        &receipt,
        decode_hex(include_str!("../vectors/kap0038-receipt.hex")),
    )
    .unwrap();
    fs::write(
        &trust,
        decode_hex(include_str!("../vectors/kap0038-trust.hex")),
    )
    .unwrap();
    (root, receipt, trust)
}

fn inspect(receipt: &Path, trust: &Path, extra: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kapsel"));
    command.args([
        "inspect",
        "--receipt",
        receipt.to_str().unwrap(),
        "--trust",
        trust.to_str().unwrap(),
        "--evaluation-time-unix-s",
        "150",
    ]);
    command
        .args(extra)
        .env("KUBECONFIG", "/unavailable/ambient-kubeconfig")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap()
}

#[test]
fn canonical_vectors_are_inspected_at_the_explicit_time() {
    let (root, receipt, trust) = fixture();
    let output = inspect(&receipt, &trust, &[]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with(
        "{\"command\":\"inspect\",\"status\":\"INSPECTED\",\"operation_id\":\"op-001\""
    ));
    assert!(stdout.contains("\"authorization_id\":\"auth-001\""));
    assert!(stdout.contains("\"immutable_image_digest\":"));
    assert!(stdout.contains("\"observed_operation_marker\":\"op-001\""));
    assert!(stdout.contains("\"requested_generation\":2"));
    assert!(stdout.contains("\"rollout_condition_type\":\"Progressing\""));
    assert!(stdout.contains("\"rollout_condition_reason\":\"ProgressDeadlineExceeded\""));
    assert!(stdout.contains("\"result\":\"FAILED\""));
    let mut previous_position = 0;
    for field in [
        "operation_id",
        "authorization_id",
        "authorization_signer_key_id",
        "authorization_grant_digest",
        "namespace",
        "deployment",
        "container",
        "immutable_image_digest",
        "write_strategy",
        "target_uid",
        "target_resource_version",
        "receiver_uid",
        "observed_image",
        "observed_operation_marker",
        "current_generation",
        "requested_generation",
        "observed_generation",
        "observed_resource_version",
        "desired_replicas",
        "updated_replicas",
        "available_replicas",
        "unavailable_replicas",
        "rollout_condition_type",
        "rollout_condition_status",
        "rollout_condition_reason",
        "result",
        "non_claims",
    ] {
        let position = stdout.find(&format!("\"{field}\":")).unwrap();
        assert!(
            position > previous_position,
            "inspection field order changed at {field}"
        );
        previous_position = position;
    }
    assert!(stdout.ends_with(concat!(
        "\"non_claims\":\"no-exactly-once;no-causation;no-kubernetes-truth;",
        "no-complete-capture;no-witnessing;not-production\"}\n"
    )));
    assert!(stdout.len() < 64 * 1024);
    assert!(output.stderr.is_empty());
    assert!(!stdout.contains("VERIFIED"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_unavailable_image_fixture_is_classifier_complete() {
    let (root, _, _) = fixture();
    let receipt = root.join("sandbox-receipt.bin");
    let trust = root.join("sandbox-trust.bin");
    fs::write(
        &receipt,
        decode_hex(include_str!(
            "../docs/fixtures/sandbox-v1/unavailable-image.receipt.hex"
        )),
    )
    .unwrap();
    fs::write(
        &trust,
        ReceiptTrust {
            key_id: "sandbox-receipt-test-key".into(),
            public_key: SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();

    let output = inspect(&receipt, &trust, &[]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"status\":\"INSPECTED\""));
    assert!(stdout.contains(concat!(
        "\"operation_id\":\"sandbox-",
        "fedcba9876543210fedcba9876543210\""
    )));
    assert!(stdout.contains("\"rollout_condition_reason\":\"ProgressDeadlineExceeded\""));
    assert!(stdout.contains("\"result\":\"FAILED\""));
    assert!(!stdout.contains("VERIFIED"));
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_bytes_and_explicit_lower_limits_use_owned_status_vocabulary() {
    let (root, receipt, trust) = fixture();
    let malformed = root.join("malformed.bin");
    fs::write(&malformed, b"not-a-receipt").unwrap();

    for output in [
        inspect(&malformed, &trust, &[]),
        inspect(&receipt, &trust, &["--statement-bytes-max", "1"]),
    ] {
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("\"status\":\"STRUCTURE_REJECTED\""));
        assert!(!stdout.contains("VERIFIED"));
        assert!(output.stderr.is_empty());
    }
    let invalid_limit = inspect(&receipt, &trust, &["--receipt-bytes-max", "0"]);
    assert_eq!(invalid_limit.status.code(), Some(2));
    assert!(String::from_utf8(invalid_limit.stdout)
        .unwrap()
        .contains("\"error_class\":\"command_input\""));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn signature_and_separate_trust_failures_keep_distinct_statuses() {
    let (root, receipt, trust) = fixture();
    let mut bad_signature = fs::read(&receipt).unwrap();
    *bad_signature.last_mut().unwrap() ^= 1;
    let bad_receipt = root.join("bad-signature.bin");
    fs::write(&bad_receipt, bad_signature).unwrap();
    let signature_output = inspect(&bad_receipt, &trust, &[]);
    assert!(String::from_utf8(signature_output.stdout)
        .unwrap()
        .contains("\"status\":\"SIGNATURE_REJECTED\""));

    let wrong_trust = root.join("wrong-trust.bin");
    fs::write(
        &wrong_trust,
        ReceiptTrust {
            key_id: "other-key".into(),
            public_key: SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    let trust_output = inspect(&receipt, &wrong_trust, &[]);
    let stdout = String::from_utf8(trust_output.stdout).unwrap();
    assert!(stdout.contains("\"status\":\"UNTRUSTED_SIGNER\""));
    assert!(stdout.contains("\"operation_id\":\"op-001\""));
    assert!(!stdout.contains("VERIFIED"));
    fs::remove_dir_all(root).unwrap();
}
