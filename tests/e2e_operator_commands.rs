//! One public provisioning/configuration trace binds command output to real HTTP and private files.
#![allow(
    clippy::unwrap_used,
    reason = "controlled binary and receiver fixtures"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use kapsel::{parse_service_operator_document, ServiceApplication};
use kapsel_authority::{
    verify_authorization_grant, ApprovedTarget, AuthorizationTrust, ExactAuthorization,
};

struct OperatorFiles(PathBuf);

impl OperatorFiles {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("kapsel-operator-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }

    #[allow(
        clippy::panic,
        reason = "fail the fixture only after killing and reaping its child"
    )]
    fn run(&self, arguments: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args(arguments)
            .current_dir(&self.0)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "operator command exceeded its fixture deadline: {:?}",
                    output.status
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
        child.wait_with_output().unwrap()
    }

    fn provision(&self, snapshot: bool, output: &str) -> Output {
        let mut arguments = vec![
            if snapshot {
                "provision-snapshot-grant"
            } else {
                "provision-grant"
            },
            "--authorization",
            "intent.json",
            "--signing-seed",
            "owner.seed",
            "--signing-key-id",
            "owner-key",
            "--output",
            output,
        ];
        if snapshot {
            arguments.extend(["--kubeconfig", "kubeconfig"]);
        }
        self.run(&arguments)
    }

    fn prepare(&self, output: &str) -> Output {
        self.run(&[
            "prepare-service-config",
            "--authorization-key",
            "owner-key",
            "owner.pub",
            "--approval",
            "Approved image",
            "snapshot.grant",
            "--receipt-signing-key-id",
            "receipt-key",
            "--output",
            output,
        ])
    }
}

impl Drop for OperatorFiles {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn snapshot_receiver(root: &Path) -> thread::JoinHandle<std::io::Result<()>> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write(
        root.join("kubeconfig"),
        format!(
            concat!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: explicit\n  cluster:\n",
        "    server: http://{}\n",
        "contexts:\n- name: explicit\n  context:\n    cluster: explicit\n    user: explicit\n",
        "current-context: explicit\nusers:\n- name: explicit\n  user:\n    token: fixture-token\n",
    ),
            listener.local_addr().unwrap()
        ),
    )
    .unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no snapshot request");
                    thread::sleep(Duration::from_millis(5));
                },
                Err(error) => return Err(error),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let mut request = [0; 4096];
        let mut length = 0;
        loop {
            stream
                .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
                .unwrap();
            let read = stream.read(&mut request[length..]).unwrap();
            assert!(
                read > 0 && length + read < request.len(),
                "incomplete bounded request"
            );
            length += read;
            if request[..length]
                .windows(4)
                .any(|bytes| bytes == b"\r\n\r\n")
            {
                break;
            }
        }
        assert!(request[..length]
            .starts_with(b"GET /apis/apps/v1/namespaces/demo/deployments/agent-api HTTP/1.1\r\n"));
        let body = br#"{"apiVersion":"apps/v1","kind":"Deployment",
            "metadata":{"uid":"deployment-uid-1","resourceVersion":"7"},
            "spec":{"template":{"spec":{"containers":[{"name":"api"}]}}}}"#;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        write!(
            stream,
            concat!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                "content-length: {}\r\nconnection: close\r\n\r\n"
            ),
            body.len()
        )
        .unwrap();
        stream.write_all(body)
    })
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keep the command-to-grant-to-document observations together"
)]
fn public_operator_commands_bind_snapshot_authority_and_static_configuration_without_history() {
    let files = OperatorFiles::new();
    let seed = [41; 32];
    let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    fs::write(files.0.join("owner.seed"), seed).unwrap();
    fs::write(files.0.join("owner.pub"), public_key).unwrap();
    fs::write(
        files.0.join("intent.json"),
        serde_json::to_vec(&serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("registry.example/api@sha256:{}", "a".repeat(64)),
        }))
        .unwrap(),
    )
    .unwrap();

    let version = files.run(&["--version"]);
    assert!(version.status.success() && version.stderr.is_empty());
    assert_eq!(
        version.stdout,
        format!("kapsel {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );

    // Both provisioning entry points use explicit intent and the same private output owner.
    let legacy = files.provision(false, "legacy.grant");
    assert!(legacy.status.success() && legacy.stderr.is_empty());
    assert_eq!(
        legacy.stdout,
        b"{\"command\":\"provision-grant\",\"status\":\"PROVISIONED\"}\n"
    );
    let receiver = snapshot_receiver(&files.0);
    let snapshot = files.provision(true, "snapshot.grant");
    receiver.join().unwrap().unwrap();
    assert!(snapshot.status.success(), "{:?}", snapshot.stderr);
    assert_eq!(
        snapshot.stdout,
        b"{\"command\":\"provision-snapshot-grant\",\"status\":\"PROVISIONED\"}\n"
    );
    assert!(snapshot.stderr.is_empty());
    let original = fs::read(files.0.join("snapshot.grant")).unwrap();
    let (authorization, signer, _) = verify_authorization_grant(
        &original,
        &AuthorizationTrust {
            key_id: "owner-key".into(),
            public_key,
        },
    )
    .unwrap()
    .into_parts();
    assert_eq!(signer, "owner-key");
    assert_eq!(
        authorization,
        ExactAuthorization {
            authorization_id: "auth-1".into(),
            operation_id: "op-1".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: format!("registry.example/api@sha256:{}", "a".repeat(64)),
            approved_target: Some(ApprovedTarget {
                uid: "deployment-uid-1".into(),
                resource_version: "7".into(),
            }),
        }
    );

    let prepared = files.prepare("candidate.json");
    assert!(prepared.status.success() && prepared.stderr.is_empty());
    assert_eq!(
        prepared.stdout,
        b"{\"command\":\"prepare-service-config\",\"status\":\"PREPARED\"}\n"
    );
    let candidate = fs::read(files.0.join("candidate.json")).unwrap();
    let absent = files.0.join("not-created/journal");
    let document = parse_service_operator_document(&candidate, absent.clone()).unwrap();
    assert_eq!(document.receipt_signing_key_id, "receipt-key");
    assert_eq!(document.configuration.approvals[0].signed_grant, original);
    assert_eq!(document.configuration.approvals[0].label, "Approved image");
    assert!(ServiceApplication::validate_static_configuration(&document.configuration).is_ok());
    assert!(!absent.parent().unwrap().exists());
    let validation = files.run(&[
        "validate-service-config",
        "--operator-config",
        "candidate.json",
    ]);
    assert!(validation.status.success() && validation.stderr.is_empty());
    assert_eq!(
        validation.stdout,
        b"{\"command\":\"validate-service-config\",\"status\":\"VALIDATED_STATIC\"}\n"
    );
    for output in ["legacy.grant", "snapshot.grant", "candidate.json"] {
        assert_eq!(
            fs::metadata(files.0.join(output))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert_eq!(fs::read(files.0.join("snapshot.grant")).unwrap(), original);
    assert_eq!(fs::read(files.0.join("candidate.json")).unwrap(), candidate);
    assert_eq!(files.prepare("candidate.json").status.code(), Some(3));
    assert_eq!(fs::read(files.0.join("candidate.json")).unwrap(), candidate);

    fs::write(files.0.join("snapshot.grant"), b"SECRET_INVALID_GRANT").unwrap();
    let refused = files.prepare("rejected.json");
    assert_eq!(refused.status.code(), Some(3));
    assert_eq!(
        refused.stdout,
        concat!(
            "{\"command\":\"prepare-service-config\",\"status\":\"ERROR\",",
            "\"error_class\":\"operator_configuration\"}\n",
        )
        .as_bytes()
    );
    assert_eq!(
        refused.stderr,
        b"Kapsel command failure: operator_configuration\n"
    );
    assert!(!files.0.join("rejected.json").exists());
    assert!(!files.0.join("journal.sqlite3").exists());
}
