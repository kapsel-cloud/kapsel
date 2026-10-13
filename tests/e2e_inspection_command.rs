//! A pinned machine record and rejected signature bind the actual offline CLI to its inspector.
#![allow(clippy::unwrap_used, reason = "controlled canonical vectors")]

use std::{fs, path::Path, process::Command};

fn decode_hex(text: &str) -> Vec<u8> {
    let (pairs, remainder) = text.trim().as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "canonical vector has an odd number of nibbles"
    );
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn inspect(root: &Path, receipt: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "inspect",
            "--receipt",
            receipt,
            "--trust",
            "trust",
            "--evaluation-time-unix-s",
            "150",
        ])
        .current_dir(root)
        .env("KUBECONFIG", "/unavailable/ambient-kubeconfig")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap()
}

#[test]
fn canonical_machine_bytes_and_rejected_signature_bind_the_offline_command() {
    let root = std::env::temp_dir().join(format!("kapsel-inspection-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let receipt = decode_hex(include_str!("../vectors/effect-gateway-receipt.hex"));
    fs::write(root.join("receipt"), &receipt).unwrap();
    fs::write(
        root.join("trust"),
        decode_hex(include_str!("../vectors/effect-gateway-trust.hex")),
    )
    .unwrap();
    let output = inspect(&root, "receipt");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "{\"command\":\"inspect\",\"status\":\"INSPECTED\",",
            "\"operation_id\":\"op-001\",\"authorization_id\":\"auth-001\",",
            "\"authorization_signer_key_id\":\"kap0038-authorization-test-key\",",
            "\"authorization_grant_digest\":",
            "\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"namespace\":\"demo\",\"deployment\":\"agent-api\",\"container\":\"api\",",
            "\"immutable_image_digest\":",
            "\"registry.example/example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
            "\"write_strategy\":\"conditional-strategic-merge-patch\",",
            "\"target_uid\":\"deployment-uid-1\",",
            "\"target_resource_version\":\"resource-version-0\",",
            "\"receiver_uid\":\"deployment-uid-1\",",
            "\"observed_image\":",
            "\"registry.example/example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",",
            "\"observed_operation_marker\":\"op-001\",",
            "\"current_generation\":2,\"requested_generation\":2,",
            "\"observed_generation\":2,",
            "\"observed_resource_version\":\"resource-version-2\",",
            "\"desired_replicas\":1,\"updated_replicas\":0,",
            "\"available_replicas\":0,\"unavailable_replicas\":1,",
            "\"rollout_condition_type\":\"Progressing\",",
            "\"rollout_condition_status\":\"False\",",
            "\"rollout_condition_reason\":\"ProgressDeadlineExceeded\",",
            "\"result\":\"FAILED\",\"approved_target\":null,",
            "\"attempt_target\":{\"resource_version\":\"resource-version-0\",",
            "\"uid\":\"deployment-uid-1\"},",
            "\"observed_target\":{\"resource_version\":\"resource-version-2\",",
            "\"uid\":\"deployment-uid-1\"},",
            "\"non_claims\":\"no-exactly-once;no-causation;no-kubernetes-truth;",
            "no-complete-capture;no-witnessing;not-production\"}\n"
        )
    );

    let mut bad_signature = receipt;
    *bad_signature.last_mut().unwrap() ^= 1;
    fs::write(root.join("bad-signature"), bad_signature).unwrap();
    let output = inspect(&root, "bad-signature");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["status"], "SIGNATURE_REJECTED");
    assert!(record["operation_id"].is_null() && record["non_claims"].is_null());
    fs::remove_dir_all(root).unwrap();
}
