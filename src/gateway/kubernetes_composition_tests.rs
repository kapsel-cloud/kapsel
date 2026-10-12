//! Real Kubernetes adapter HTTP facts bound independently to signed receipt fields.

mod receiver;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::*;

fn request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "comparison-op".into(),
        namespace: "demo".into(),
        deployment: "api".into(),
        container: "api".into(),
        immutable_image_digest: receiver::IMAGE.into(),
    }
}

fn inspected_statement(bytes: &[u8]) -> ReceiptStatement {
    let trust = ReceiptTrust {
        key_id: "comparison-receipt".into(),
        public_key: SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
        not_before_unix_s: 0,
        not_after_unix_s: i64::MAX,
    }
    .encode()
    .unwrap();
    let inspection = inspect_receipt(bytes, &trust, 1, InspectionLimits::default());
    assert_eq!(inspection.status(), InspectionStatus::Inspected);
    inspection.statement().unwrap().clone()
}

// Receiver-owned JSON, not the production observation decoder, supplies expected fields.
fn assert_retained_facts(case: &str, bytes: &[u8], receiver: &Value) {
    let request = request();
    let statement = inspected_statement(bytes);
    assert_eq!(statement.approved_target.as_ref().unwrap().uid, "uid-1");
    assert_eq!(
        statement.approved_target.as_ref().unwrap().resource_version,
        "opaque-1"
    );
    assert_eq!(statement.target_uid, "uid-1");
    assert_eq!(statement.target_resource_version, "opaque-1");
    assert_eq!(statement.operation_id, request.operation_id);
    assert_eq!(statement.namespace, request.namespace);
    assert_eq!(statement.deployment, request.deployment);
    assert_eq!(statement.container, request.container);
    assert_eq!(
        statement.immutable_image_digest,
        request.immutable_image_digest
    );
    assert_eq!(json!(statement.receiver_uid), receiver["metadata"]["uid"]);
    assert_eq!(
        json!(statement.observed_resource_version),
        receiver["metadata"]["resourceVersion"]
    );
    assert_eq!(
        json!(statement.current_generation),
        receiver["metadata"]["generation"]
    );
    assert_eq!(
        statement.requested_generation,
        match case {
            "preflight-race" | "intervening-writer" | "target-replacement" => None,
            "retained-marker" => Some(3),
            _ => Some(2),
        }
    );
    assert_eq!(
        json!(statement.observed_generation),
        receiver["status"]["observedGeneration"]
    );
    assert_eq!(
        json!(statement.observed_image),
        receiver["spec"]["template"]["spec"]["containers"][0]["image"]
    );
    assert_eq!(
        json!(statement.observed_operation_marker),
        receiver["metadata"]["annotations"]["kapsel.dev/kap0038-operation-id"]
    );
    assert_eq!(
        json!(statement.desired_replicas),
        receiver["spec"]["replicas"]
    );
    assert_eq!(
        json!(statement.updated_replicas),
        receiver["status"]["updatedReplicas"]
    );
    assert_eq!(
        json!(statement.available_replicas),
        receiver["status"]["availableReplicas"]
    );
    assert_eq!(
        json!(statement.unavailable_replicas),
        receiver["status"]["unavailableReplicas"]
    );
    let condition = &receiver["status"]["conditions"][0];
    assert_eq!(json!(statement.rollout_condition_type), condition["type"]);
    assert_eq!(
        json!(statement.rollout_condition_status),
        condition["status"]
    );
    assert_eq!(
        json!(statement.rollout_condition_reason),
        condition["reason"]
    );
}

#[tokio::test(start_paused = true)]
async fn adapter_receipts_bind_independent_http_facts() {
    for (case, expected, persisted, gets) in [
        ("healthy", OperationResult::Succeeded, 1, 2),
        ("failed", OperationResult::Failed, 1, 2),
        ("lost-response", OperationResult::Succeeded, 1, 2),
        ("preflight-race", OperationResult::Unknown, 0, 181),
        ("slow-rollout", OperationResult::Unknown, 1, 181),
        ("intervening-writer", OperationResult::Unknown, 1, 181),
        ("retained-marker", OperationResult::Succeeded, 1, 2),
        ("target-replacement", OperationResult::Unknown, 1, 181),
    ] {
        let root = std::env::temp_dir().join(format!(
            "kapsel-adapter-receipts-{}-{case}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut gateway = Gateway::open_for_test(root.join("journal.sqlite3")).unwrap();
        let request = request();
        let approval = ExactAuthorization {
            authorization_id: "comparison-approval".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
            approved_target: Some(ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "opaque-1".into(),
            }),
        };
        let grant =
            sign_authorization_grant(&approval, &[7; 32], "effect-gateway-authorization-test-key")
                .unwrap();
        gateway.submit_authorized(&request, &grant).unwrap();
        let evidence = Arc::new(Mutex::new(receiver::initial_evidence()));
        let lose_response = matches!(
            case,
            "lost-response" | "intervening-writer" | "retained-marker" | "target-replacement"
        );
        let (client, task) = receiver::client(evidence.clone(), case, lose_response);
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        let result = gateway
            .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
            .await;
        if case == "preflight-race" || lose_response {
            assert!(matches!(result, Err(GatewayError::KubernetesApply)));
            gateway
                .run_operation_once_with_adapter(&request.operation_id, &mut adapter)
                .await
                .unwrap();
        } else {
            result.unwrap();
        }
        gateway
            .finalize_operation_receipt_once(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &[42; 32],
                    key_id: "comparison-receipt",
                },
            )
            .unwrap();
        assert_eq!(
            gateway.result(&request.operation_id).unwrap(),
            Some(expected),
            "{case}"
        );
        let (bytes, _) = Gateway::read_loaded_receipt(
            gateway
                .loaded_for_test(&request.operation_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let facts = evidence.lock().unwrap().clone();
        assert_retained_facts(case, &bytes, &facts["object"]);
        let requests = facts["requests"].as_array().unwrap();
        assert_eq!(
            requests.iter().filter(|r| r["method"] == "PATCH").count(),
            1,
            "{case}"
        );
        assert_eq!(
            requests.iter().filter(|r| r["method"] == "GET").count(),
            gets,
            "{case}"
        );
        assert_eq!(facts["persisted_patches"], persisted, "{case}");
        task.abort();
        task.await.unwrap_err();
        drop(gateway);
        fs::remove_dir_all(root).unwrap();
    }
}
