//! Operator configuration preparation authenticates authority without opening retained state.
#![allow(clippy::unwrap_used, reason = "controlled operator-command fixtures")]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::PathBuf,
    process::{Command, Output},
};

use kapsel::{
    provision_exact_grant, ApprovedTarget, ExactAuthorization, GrantProvisioning,
    ServiceApplication,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("kapsel-config-cli-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let seed = [41; 32];
        fs::write(
            path.join("key.pub"),
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let authorization = ExactAuthorization {
            authorization_id: "approval-1".into(),
            operation_id: "op-1".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: format!("registry.example/api@sha256:{}", "0".repeat(64)),
            approved_target: Some(ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "1".into(),
            }),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &seed,
            signing_key_id: "key-1",
        })
        .unwrap();
        fs::write(path.join("grant"), grant).unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args(args)
            .current_dir(&self.0)
            .env_clear()
            .output()
            .unwrap()
    }

    fn prepare(&self, grant: &str, output: &str) -> Output {
        self.run(&[
            "prepare-service-config",
            "--authorization-key",
            "key-1",
            "key.pub",
            "--approval",
            "Approved image",
            grant,
            "--receipt-signing-key-id",
            "receipt-key",
            "--output",
            output,
        ])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn preparation_and_static_validation_preserve_inputs_and_never_require_a_journal() {
    let fixture = Fixture::new();
    let grant_before = fs::read(fixture.0.join("grant")).unwrap();
    let prepared = fixture.prepare("grant", "candidate.json");
    assert!(prepared.status.success(), "{:?}", prepared.stderr);
    assert!(prepared.stderr.is_empty());
    let candidate = fixture.0.join("candidate.json");
    let before = fs::read(&candidate).unwrap();
    assert_eq!(
        fs::metadata(&candidate).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!fixture.prepare("grant", "candidate.json").status.success());
    assert_eq!(fs::read(&candidate).unwrap(), before);
    let validated = fixture.run(&[
        "validate-service-config",
        "--operator-config",
        "candidate.json",
    ]);
    assert!(validated.status.success());
    assert_eq!(
        validated.stdout,
        b"{\"command\":\"validate-service-config\",\"status\":\"VALIDATED_STATIC\"}\n"
    );
    assert!(validated.stderr.is_empty());
    assert_eq!(fs::read(&candidate).unwrap(), before);
    assert_eq!(fs::read(fixture.0.join("grant")).unwrap(), grant_before);

    let absent_root = fixture.0.join("must-not-be-created");
    let mut document =
        kapsel::parse_service_operator_document(&before, absent_root.join("journal.sqlite3"))
            .unwrap();
    assert!(ServiceApplication::validate_static_configuration(&document.configuration).is_ok());
    assert!(!absent_root.exists());
    document
        .configuration
        .approvals
        .push(kapsel::ServiceApproval {
            signed_grant: grant_before,
            label: "Duplicate operation".into(),
        });
    assert!(ServiceApplication::validate_static_configuration(&document.configuration).is_err());
    assert!(!absent_root.exists());

    // Authentication, not just JSON structure, is required before any output creation.
    fs::write(fixture.0.join("bad-grant"), b"SECRET_INVALID_GRANT").unwrap();
    let rejected = fixture.prepare("bad-grant", "rejected.json");
    assert!(!rejected.status.success());
    assert!(!fixture.0.join("rejected.json").exists());
    assert!(!String::from_utf8(rejected.stderr)
        .unwrap()
        .contains("SECRET"));
    symlink("grant", fixture.0.join("linked-grant")).unwrap();
    assert!(!fixture
        .prepare("linked-grant", "rejected.json")
        .status
        .success());
    assert!(!fixture.0.join("rejected.json").exists());
    fs::write(fixture.0.join("oversized.json"), vec![b' '; 160 * 1024 + 1]).unwrap();
    assert!(!fixture
        .run(&[
            "validate-service-config",
            "--operator-config",
            "oversized.json"
        ])
        .status
        .success());
    assert_eq!(fs::read(&candidate).unwrap(), before);
    assert!(!fixture.0.join("journal.sqlite3").exists());
}
