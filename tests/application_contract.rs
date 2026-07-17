//! Public application-interface contract tests.

#![allow(
    clippy::unwrap_used,
    reason = "controlled test-fixture failures must fail the contract test immediately"
)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use tower_test::mock;

use kapsel::*;

fn request() -> AgentRequest {
    AgentRequest {
        operation_id: "application-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    }
}

fn authorization(request: &AgentRequest) -> ExactAuthorization {
    ExactAuthorization {
        authorization_id: "application-auth-1".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    }
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

type KubernetesHandle =
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>;

fn configuration(root: &Path) -> OperatorConfiguration {
    configuration_and_handle(root).0
}

fn configuration_and_handle(root: &Path) -> (OperatorConfiguration, KubernetesHandle) {
    let request = request();
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&request),
        signing_seed: &authorization_seed,
        signing_key_id: "application-authorization-key",
    })
    .unwrap();
    let output = root.join("receipts");
    private_directory(&output);
    let output = fs::canonicalize(output).unwrap();
    let (service, handle) =
        mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
    let configuration = OperatorConfiguration {
        journal_path: fs::canonicalize(root).unwrap().join("journal.sqlite3"),
        receipt_output_directory: output,
        authorization_trust: AuthorizationTrust {
            key_id: "application-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        },
        signed_authorization_grant,
        kubernetes_client: kube::Client::new(service, "demo"),
        receipt_signing_seed: [42_u8; 32],
        receipt_signing_key_id: "application-receipt-key".into(),
    };
    (configuration, handle)
}

#[tokio::test]
async fn execute_owns_target_rejection_lifecycle() {
    let root =
        std::env::temp_dir().join(format!("kapsel-application-execute-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, mut handle) = configuration_and_handle(&root);
    let mut application = Application::open(configuration).unwrap();
    let responder = tokio::spawn(async move {
        let (_, send) = handle.next_request().await.unwrap();
        send.send_response(
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "deployments.apps agent-api not found",
                        "reason": "NotFound",
                        "details": {
                            "name": "agent-api",
                            "group": "apps",
                            "kind": "deployments"
                        },
                        "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });

    let report = application.execute(&request()).await.unwrap();

    assert_eq!(report.state, OperationState::NotAttempted);
    assert_eq!(
        report.target_rejection,
        Some(TargetRejection::DeploymentNotFound)
    );
    assert_eq!(report.result, None);
    assert_eq!(report.receipt, None);
    responder.await.unwrap();
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn request_only_submission_uses_operator_configured_grant() {
    let root =
        std::env::temp_dir().join(format!("kapsel-application-submit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let application = Application::open(configuration(&root)).unwrap();
    let request = request();

    assert_eq!(
        application.submit(&request).unwrap(),
        SubmissionResult::Created
    );
    assert_eq!(
        application.report().unwrap(),
        Some(OperationReport {
            operation_id: request.operation_id,
            state: OperationState::Authorized,
            result: None,
            target_rejection: None,
            receipt: None,
        })
    );
    assert_eq!(
        fs::metadata(root.join("journal.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn invalid_operator_configuration_precedes_journal_creation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-configuration-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut configuration = configuration(&root);
    configuration.signed_authorization_grant = b"self-appointed".to_vec();
    let journal = configuration.journal_path.clone();

    assert!(matches!(
        Application::open(configuration),
        Err(ApplicationError::InvalidAuthorizationConfiguration)
    ));
    assert!(!journal.exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn unsafe_journal_path_is_rejected_before_creation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-journal-path-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut configuration = configuration(&root);
    configuration.journal_path = PathBuf::from("relative-journal.sqlite3");

    assert!(matches!(
        Application::open(configuration),
        Err(ApplicationError::InvalidJournalPath)
    ));
    assert!(!Path::new("relative-journal.sqlite3").exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn mismatched_intent_does_not_create_an_operation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-mismatch-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let application = Application::open(configuration(&root)).unwrap();
    let mut mismatched = request();
    mismatched.container = "other".into();

    assert!(matches!(
        application.submit(&mismatched),
        Err(ApplicationError::Gateway(
            GatewayError::AuthorizationMismatch
        ))
    ));
    assert_eq!(application.report().unwrap(), None);
    drop(application);
    fs::remove_dir_all(root).unwrap();
}
