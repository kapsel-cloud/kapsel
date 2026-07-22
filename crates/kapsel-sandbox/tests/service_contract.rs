//! Exported sandbox service contract tests.

#![allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must stop the contract test"
)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use http::{Request, StatusCode};
use kapsel::{
    provision_exact_grant, AuthorizationTrust, ExactAuthorization, GrantProvisioning,
    OperatorConfiguration,
};
use kapsel_sandbox::{
    AdmissionDisposition, CleanupAbsenceEvidence, CleanupObjectAbsence, CleanupState,
    DispatchLease, ExecutionState, ProvisionedObject, ProvisionedTarget, ProvisioningSpecification,
    Scenario, Service, ServiceError,
};
use tower_test::mock;

const NOW: i64 = 1_774_051_200;

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture(name: &str) -> (PathBuf, Service) {
    let root = std::env::temp_dir().join(format!("kapsel-sandbox-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    private_directory(&root.join("receipts"));
    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW,
    )
    .unwrap();
    (root, service)
}

fn key(index: u8) -> String {
    format!("{index:032x}")
}

fn verify_target(
    service: &Service,
    lease: &DispatchLease,
    namespace_uid: &str,
    now_unix_s: i64,
) -> ProvisioningSpecification {
    let specification = service
        .provisioning_specification(lease, now_unix_s)
        .unwrap();
    service
        .verify_provisioned_target(
            lease,
            &ProvisionedTarget {
                namespace_uid: namespace_uid.into(),
                policy_revision: specification.policy_revision.clone(),
                policy_inventory_digest: specification.policy_inventory_digest.clone(),
                cleanup_identity: specification.cleanup_identity.clone(),
                objects: provisioned_objects(&specification, namespace_uid),
            },
            now_unix_s,
        )
        .unwrap();
    specification
}

fn provisioned_objects(
    specification: &ProvisioningSpecification,
    namespace_uid: &str,
) -> Vec<ProvisionedObject> {
    specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| ProvisionedObject {
            identity: object.identity.clone(),
            uid: if index == 0 {
                namespace_uid.to_owned()
            } else {
                format!("{namespace_uid}-object-{index}")
            },
            owner_label: specification.cleanup_identity.clone(),
            content_digest: object.content_digest.clone(),
        })
        .collect()
}

fn cleanup_absence(
    specification: &ProvisioningSpecification,
    namespace_uid: &str,
) -> CleanupAbsenceEvidence {
    let objects = provisioned_objects(specification, namespace_uid)
        .into_iter()
        .map(|object| {
            let parts = object.identity.split('/').collect::<Vec<_>>();
            let (kind, namespace, name) = match parts.as_slice() {
                ["Namespace", name] => ("Namespace".to_owned(), None, (*name).to_owned()),
                [kind, namespace, name] => (
                    (*kind).to_owned(),
                    Some((*namespace).to_owned()),
                    (*name).to_owned(),
                ),
                _ => unreachable!("fixed policy identity"),
            };
            CleanupObjectAbsence {
                kind,
                namespace,
                name,
                uid: object.uid,
                owner_label: object.owner_label,
                present: false,
            }
        })
        .collect();
    CleanupAbsenceEvidence {
        namespace_uid: namespace_uid.to_owned(),
        objects,
    }
}

fn application_configuration(
    root: &Path,
    run_id: &str,
    scenario: Scenario,
) -> (
    OperatorConfiguration,
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
) {
    let operation_id = format!("sandbox-{run_id}");
    let image = match scenario {
        Scenario::Healthy => concat!(
            "registry.k8s.io/pause@sha256:",
            "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
        ),
        Scenario::UnavailableImage => concat!(
            "registry.k8s.io/pause@sha256:",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    };
    let request = kapsel::AgentRequest {
        operation_id: operation_id.clone(),
        namespace: format!("sandbox-{run_id}"),
        deployment: "sandbox-target".into(),
        container: "target".into(),
        immutable_image_digest: image.into(),
    };
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        authorization_id: format!("auth-{run_id}"),
        operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "sandbox-authorization-key",
    })
    .unwrap();
    let journal_root = root.join(run_id);
    if !journal_root.exists() {
        private_directory(&journal_root);
        private_directory(&journal_root.join("gateway-receipts"));
    }
    let (transport, handle) = mock::pair();
    (
        OperatorConfiguration {
            journal_path: fs::canonicalize(&journal_root)
                .unwrap()
                .join("journal.sqlite3"),
            receipt_output_directory: fs::canonicalize(journal_root.join("gateway-receipts"))
                .unwrap(),
            authorization_trust: AuthorizationTrust {
                key_id: "sandbox-authorization-key".into(),
                public_key: authorization_key.verifying_key().to_bytes(),
            },
            signed_authorization_grant: grant,
            kubernetes_client: kube::Client::new(transport, "sandbox"),
            receipt_signing_seed: [42; 32],
            receipt_signing_key_id: "sandbox-receipt-key".into(),
        },
        handle,
    )
}

#[test]
fn database_entry_rejects_symlink_and_permissive_file_before_sqlite_open() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-database-entry-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    private_directory(&root.join("receipts"));
    let database = root.join("sandbox.sqlite3");
    let target = root.join("redirect-target");
    fs::write(&target, b"must remain unchanged").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &database).unwrap();
    assert!(matches!(
        Service::open(&database, root.join("receipts"), [7; 32], NOW),
        Err(ServiceError::Unavailable)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"must remain unchanged");
    fs::remove_file(&database).unwrap();
    fs::remove_file(&target).unwrap();

    fs::write(&database, []).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Service::open(&database, root.join("receipts"), [7; 32], NOW),
        Err(ServiceError::Unavailable)
    ));
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::remove_file(&database).unwrap();
    Service::open(&database, root.join("receipts"), [7; 32], NOW).unwrap();
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admission_is_durable_idempotent_stopped_and_bounded() {
    let (root, service) = fixture("admission");
    let database = root.join("sandbox.sqlite3");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    assert_eq!(first.disposition, AdmissionDisposition::Created);
    drop(service);

    let service = Service::open(&database, root.join("receipts"), [7; 32], NOW + 1).unwrap();
    let replay = service.admit(&key(1), Scenario::Healthy, NOW + 1).unwrap();
    assert_eq!(replay.disposition, AdmissionDisposition::Replayed);
    assert_eq!(replay.run_id, first.run_id);
    assert_eq!(
        service.admit(&key(1), Scenario::UnavailableImage, NOW + 1),
        Err(ServiceError::IdempotencyConflict)
    );
    service.set_global_stop(true).unwrap();
    assert_eq!(
        service.admit(&key(2), Scenario::Healthy, NOW + 1),
        Err(ServiceError::Unavailable)
    );
    assert_eq!(
        service
            .admit(&key(1), Scenario::Healthy, NOW + 1)
            .unwrap()
            .run_id,
        first.run_id
    );
    service.set_global_stop(false).unwrap();
    for index in 2..=32 {
        service.admit(&key(index), Scenario::Healthy, NOW).unwrap();
    }
    assert_eq!(
        service.admit(&key(33), Scenario::Healthy, NOW),
        Err(ServiceError::CapacitySaturated)
    );
    assert_eq!(service.dispatch_next(NOW + 2).unwrap().run_id, first.run_id);
    for _ in 1..8 {
        service.dispatch_next(NOW + 2).unwrap();
    }
    assert_eq!(
        service.dispatch_next(NOW + 2),
        Err(ServiceError::ActiveSaturated)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn queued_age_does_not_consume_dispatch_window_or_block_fair_order() {
    let (root, service) = fixture("queued-dispatch-deadline");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let second = service.admit(&key(2), Scenario::Healthy, NOW + 10).unwrap();
    let third = service.admit(&key(3), Scenario::Healthy, NOW + 20).unwrap();
    let database = root.join("sandbox.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    let admitted: (i64, Option<i64>, String, String) = connection
        .query_row(
            concat!(
                "SELECT deadline_seconds, deadline_at, policy_inventory, ",
                "policy_inventory_digest FROM runs WHERE run_id = ?1"
            ),
            [&first.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(admitted.0, 180);
    assert_eq!(admitted.1, None);
    assert!(!admitted.2.is_empty());
    assert_eq!(admitted.3.len(), 64);

    let first_lease = service.dispatch_next(NOW + 1_000).unwrap();
    assert_eq!(first_lease.run_id, first.run_id);
    assert_eq!(
        service
            .provisioning_specification(&first_lease, NOW + 1_000)
            .unwrap()
            .deadline_at_unix_s,
        NOW + 1_180
    );
    let second_lease = service.dispatch_next(NOW + 1_001).unwrap();
    assert_eq!(second_lease.run_id, second.run_id);
    assert_eq!(
        service
            .provisioning_specification(&second_lease, NOW + 1_001)
            .unwrap()
            .deadline_at_unix_s,
        NOW + 1_181
    );
    let third_lease = service.dispatch_next(NOW + 1_002).unwrap();
    assert_eq!(third_lease.run_id, third.run_id);
    assert_eq!(
        service
            .provisioning_specification(&third_lease, NOW + 1_002)
            .unwrap()
            .deadline_at_unix_s,
        NOW + 1_182
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cross_run_provisioned_object_uid_reuse_is_rejected() {
    let (root, service) = fixture("cross-run-object-uid");
    let first = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let first_lease = service.dispatch_next(NOW + 1).unwrap();
    let first_specification = verify_target(&service, &first_lease, "cross-run-uid-one", NOW + 1);
    let first_objects = provisioned_objects(&first_specification, "cross-run-uid-one");

    let second = service.admit(&key(2), Scenario::Healthy, NOW).unwrap();
    let second_lease = service.dispatch_next(NOW + 1).unwrap();
    let second_specification = service
        .provisioning_specification(&second_lease, NOW + 1)
        .unwrap();
    let mut second_objects = provisioned_objects(&second_specification, "cross-run-uid-two");
    second_objects[4].uid = first_objects[4].uid.clone();
    let second_target = ProvisionedTarget {
        namespace_uid: "cross-run-uid-two".into(),
        policy_revision: second_specification.policy_revision.clone(),
        policy_inventory_digest: second_specification.policy_inventory_digest.clone(),
        cleanup_identity: second_specification.cleanup_identity,
        objects: second_objects,
    };
    assert_eq!(
        service.verify_provisioned_target(&second_lease, &second_target, NOW + 1),
        Err(ServiceError::OwnershipMismatch)
    );
    assert_ne!(first.run_id, second.run_id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn repeated_verification_keeps_historical_cleanup_ownership() {
    let (root, service) = fixture("append-only-cleanup-ownership");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    let namespace_uid = "append-only-namespace-uid";
    let mut first_objects = provisioned_objects(&specification, namespace_uid);
    first_objects.push(ProvisionedObject {
        identity: format!("ConfigMap/{}/historical-extra", specification.namespace),
        uid: "historical-extra-uid".into(),
        owner_label: specification.cleanup_identity.clone(),
        content_digest: "1".repeat(64),
    });
    let first_target = ProvisionedTarget {
        namespace_uid: namespace_uid.into(),
        policy_revision: specification.policy_revision.clone(),
        policy_inventory_digest: specification.policy_inventory_digest.clone(),
        cleanup_identity: specification.cleanup_identity.clone(),
        objects: first_objects,
    };
    assert_eq!(
        service.verify_provisioned_target(&lease, &first_target, NOW + 1),
        Err(ServiceError::PolicyMismatch)
    );
    verify_target(&service, &lease, namespace_uid, NOW + 1);
    service
        .record_setup_failure(&lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            namespace_uid,
            NOW + 3,
        )
        .unwrap();
    let current_only = cleanup_absence(&specification, namespace_uid);
    assert_eq!(
        service.complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &current_only,
            NOW + 4,
        ),
        Err(ServiceError::OwnershipMismatch)
    );
    let mut complete = current_only;
    complete.objects.push(CleanupObjectAbsence {
        kind: "ConfigMap".into(),
        namespace: Some(specification.namespace.clone()),
        name: "historical-extra".into(),
        uid: "historical-extra-uid".into(),
        owner_label: specification.cleanup_identity.clone(),
        present: false,
    });
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &complete,
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        service
            .snapshot(&admission.run_id, NOW + 4)
            .unwrap()
            .cleanup_state,
        CleanupState::Succeeded
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test preserves policy evidence, rejection, and cleanup restart proof"
)]
async fn application_rejection_and_cleanup_remain_separate_across_restart() {
    let (root, service) = fixture("application");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    assert_eq!(lease.run_id, admission.run_id);
    assert_eq!(
        service.recoverable_runs().unwrap().as_slice(),
        std::slice::from_ref(&admission.run_id)
    );
    let specification = verify_target(&service, &lease, "namespace-uid-1", NOW + 1);
    let stored_objects: String = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT provisioned_objects FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<ProvisionedObject>>(&stored_objects).unwrap(),
        provisioned_objects(&specification, "namespace-uid-1")
    );
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let responder = tokio::spawn(async move {
        let (_, send) = handle.next_request().await.unwrap();
        send.send_response(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "reason": "NotFound",
                        "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    let report = service
        .execute_application(&lease, configuration, NOW + 2)
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(report.execution_state, ExecutionState::NotAttempted);
    assert_eq!(
        report.target_rejection.as_deref(),
        Some("DEPLOYMENT_NOT_FOUND")
    );

    let before = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(before.execution_state, ExecutionState::NotAttempted);
    assert_eq!(before.receiver_result, None);
    assert_eq!(before.cleanup_state, CleanupState::Pending);
    assert_eq!(
        service.start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "other-uid",
            NOW + 3,
        ),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "namespace-uid-1",
            NOW + 3,
        )
        .unwrap();
    service
        .fail_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "namespace-uid-1",
            NOW + 4,
        )
        .unwrap();
    let failed = service.snapshot(&admission.run_id, NOW + 4).unwrap();
    assert_eq!(failed.cleanup_state, CleanupState::Failed);
    assert_eq!(failed.receiver_result, None);
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 5,
    )
    .unwrap();
    let assert_mismatch = |evidence: &CleanupAbsenceEvidence| {
        assert_eq!(
            service.complete_cleanup(
                &admission.run_id,
                &specification.cleanup_identity,
                evidence,
                NOW + 5,
            ),
            Err(ServiceError::OwnershipMismatch)
        );
    };
    let mut wrong_kind = cleanup_absence(&specification, "namespace-uid-1");
    wrong_kind.objects[2].kind = "OtherKind".into();
    assert_mismatch(&wrong_kind);
    let mut wrong_namespace = cleanup_absence(&specification, "namespace-uid-1");
    wrong_namespace.objects[2].namespace = Some("other-namespace".into());
    assert_mismatch(&wrong_namespace);
    let mut wrong_name = cleanup_absence(&specification, "namespace-uid-1");
    wrong_name.objects[2].name = "other-name".into();
    assert_mismatch(&wrong_name);
    let mut wrong_uid = cleanup_absence(&specification, "namespace-uid-1");
    wrong_uid.objects[2].uid = "other-object-uid".into();
    assert_mismatch(&wrong_uid);
    let mut wrong_owner = cleanup_absence(&specification, "namespace-uid-1");
    wrong_owner.objects[2].owner_label = "cleanup-other".into();
    assert_mismatch(&wrong_owner);
    let mut still_present = cleanup_absence(&specification, "namespace-uid-1");
    still_present.objects[7].present = true;
    assert_eq!(
        service.complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &still_present,
            NOW + 5,
        ),
        Err(ServiceError::InvalidTransition)
    );
    let mut missing = cleanup_absence(&specification, "namespace-uid-1");
    missing.objects.pop();
    assert_eq!(
        service.complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &missing,
            NOW + 5,
        ),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &cleanup_absence(&specification, "namespace-uid-1"),
            NOW + 5,
        )
        .unwrap();
    let terminal = service.snapshot(&admission.run_id, NOW + 5).unwrap();
    assert_eq!(terminal.execution_state, ExecutionState::NotAttempted);
    assert_eq!(terminal.cleanup_state, CleanupState::Succeeded);
    assert!(!terminal.receipt_available);
    assert!(service.recoverable_runs().unwrap().is_empty());
    let page = service.events(&admission.run_id, 0, 64, NOW + 5).unwrap();
    assert_eq!(page.events.len(), 6);
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn pre_submit_marker_crash_submits_same_request_on_reconciliation() {
    let (root, service) = fixture("pre-submit-crash");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    verify_target(&service, &lease, "pre-submit-namespace-uid", NOW + 1);
    let database = root.join("sandbox.sqlite3");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE runs SET application_invoked = 1 WHERE run_id = ?1",
            [&admission.run_id],
        )
        .unwrap();
    assert!(!root.join(&admission.run_id).exists());
    drop(service);

    let service = Service::open(&database, root.join("receipts"), [7; 32], NOW + 2).unwrap();
    let recovered = service
        .recover_run(&admission.run_id, Some(&lease), NOW + 2)
        .unwrap();
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    let terminal = service
        .reconcile_application(&recovered, configuration, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    responder.await.unwrap();
    assert_eq!(terminal.operation_id, admission.operation_id);
    assert_eq!(terminal.execution_state, ExecutionState::NotAttempted);
    assert_eq!(
        terminal.target_rejection.as_deref(),
        Some("DEPLOYMENT_NOT_FOUND")
    );
    let page = service.events(&admission.run_id, 0, 64, NOW + 2).unwrap();
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.target_rejection.as_deref() == Some("DEPLOYMENT_NOT_FOUND"))
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test proves cancellation at provider ambiguity and lease recovery"
)]
async fn uncertain_invocation_recovers_with_one_mutation_and_same_operation() {
    let (root, service) = fixture("uncertain-invocation");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    verify_target(&service, &lease, "uncertain-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let target = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": old_image}]}}},
        "status": {"observedGeneration": 1}
    });
    let patched = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": image}]}}}
    });
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&target).unwrap(),
                ))
                .unwrap(),
        );
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::PATCH);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&patched).unwrap(),
                ))
                .unwrap(),
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });
    let interrupted = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        service.execute_application(&lease, configuration, NOW + 2),
    )
    .await;
    assert!(interrupted.is_err());
    responder.abort();
    let running = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(running.execution_state, ExecutionState::Running);
    assert_eq!(running.receiver_result, None);
    service
        .record_deadline(&admission.run_id, NOW + 181)
        .unwrap();
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 182,
    )
    .unwrap();
    let recovered_lease = service
        .recover_run(&admission.run_id, None, NOW + 182)
        .unwrap();
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let observed = serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
            "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
            "template": {"metadata": {"labels": {"app": "sandbox"}},
                "spec": {"containers": [{"name": "target", "image": image}]}}},
        "status": {"observedGeneration": 2, "updatedReplicas": 1,
            "availableReplicas": 1, "unavailableReplicas": 0,
            "conditions": [{"type": "Available", "status": "True",
                "reason": "MinimumReplicasAvailable"}]}
    });
    let responder = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        send.send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&observed).unwrap(),
                ))
                .unwrap(),
        );
    });
    let terminal = service
        .reconcile_application(&recovered_lease, configuration, NOW + 182)
        .await
        .unwrap()
        .unwrap();
    responder.await.unwrap();
    assert_eq!(terminal.operation_id, admission.operation_id);
    assert_eq!(terminal.receiver_result.as_deref(), Some("SUCCEEDED"));
    let receipt = service.receipt(&admission.run_id, NOW + 183).unwrap();
    let page = service.events(&admission.run_id, 0, 64, NOW + 183).unwrap();
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    drop(service);
    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 184,
    )
    .unwrap();
    assert_eq!(
        service.receipt(&admission.run_id, NOW + 184).unwrap(),
        receipt
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test keeps the Application, receipt, and restart proof contiguous"
)]
async fn report_and_receipt_reference_crash_recovers_exact_bytes() {
    let (root, service) = fixture("healthy-application");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    verify_target(&service, &lease, "healthy-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let responses = vec![
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}},
            "status": {"observedGeneration": 2, "updatedReplicas": 1,
                "availableReplicas": 1, "unavailableReplicas": 0,
                "conditions": [{"type": "Available", "status": "True",
                    "reason": "MinimumReplicasAvailable"}]}
        }),
    ];
    let responder = tokio::spawn(async move {
        for body in responses {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        }
    });
    let database = root.join("sandbox.sqlite3");
    let receipt_directory = root.join("receipts");
    let held_receipt_directory = root.join("receipts-held");
    fs::rename(&receipt_directory, &held_receipt_directory).unwrap();
    fs::write(&receipt_directory, b"block receipt object creation").unwrap();
    assert!(matches!(
        service
            .execute_application(&lease, configuration, NOW + 2)
            .await,
        Err(kapsel_sandbox::RunError::Service(ServiceError::Unavailable))
    ));
    responder.await.unwrap();
    fs::remove_file(&receipt_directory).unwrap();
    fs::rename(&held_receipt_directory, &receipt_directory).unwrap();
    let snapshot = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::Terminal);
    assert_eq!(snapshot.receiver_result.as_deref(), Some("SUCCEEDED"));
    assert!(!snapshot.receipt_available);

    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch(concat!(
            "CREATE TRIGGER fail_receipt_reference BEFORE INSERT ON receipts ",
            "BEGIN SELECT RAISE(ABORT, 'injected receipt reference crash'); END;"
        ))
        .unwrap();
    let (configuration, _unused_handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    assert!(matches!(
        service
            .reconcile_application(&lease, configuration, NOW + 3)
            .await,
        Err(kapsel_sandbox::RunError::Service(ServiceError::Unavailable))
    ));
    let receipt_path = fs::read_dir(&receipt_directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "receipt")
        })
        .unwrap();
    let object_bytes_before_recovery = fs::read(&receipt_path).unwrap();
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_receipt_reference;")
        .unwrap();
    service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert!(receipt_path.exists());
    let pending_publication: i64 = rusqlite::Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending_publication, 1);
    drop(service);

    let service = Service::open(&database, &receipt_directory, [7; 32], NOW + 4).unwrap();
    let (configuration, _unused_handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    let recovered = service
        .reconcile_application(&lease, configuration, NOW + 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.execution_state, ExecutionState::Terminal);
    assert_eq!(recovered.operation_id, admission.operation_id);
    assert_eq!(recovered.receiver_result.as_deref(), Some("SUCCEEDED"));
    let receipt = service.receipt(&admission.run_id, NOW + 4).unwrap();
    assert_eq!(receipt, object_bytes_before_recovery);
    let page = service.events(&admission.run_id, 0, 64, NOW + 4).unwrap();
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.kind == "execution.terminal")
            .count(),
        1
    );
    assert_eq!(
        page.events
            .iter()
            .filter(|event| event.kind == "receipt.available")
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one vertical test proves the fixed unavailable-image Application classification"
)]
async fn unavailable_image_application_preserves_failed_receiver_result() {
    let (root, service) = fixture("unavailable-application");
    let admission = service
        .admit(&key(1), Scenario::UnavailableImage, NOW)
        .unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    verify_target(&service, &lease, "unavailable-namespace-uid", NOW + 1);
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::UnavailableImage);
    let operation_id = admission.operation_id.clone();
    let image = concat!(
        "registry.k8s.io/pause@sha256:",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    let old_image = concat!(
        "registry.k8s.io/pause@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let responses = vec![
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"uid": "deployment-uid", "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": operation_id}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "sandbox"}},
                "template": {"metadata": {"labels": {"app": "sandbox"}},
                    "spec": {"containers": [{"name": "target", "image": image}]}}},
            "status": {"observedGeneration": 2, "updatedReplicas": 1,
                "availableReplicas": 0, "unavailableReplicas": 1,
                "conditions": [{"type": "Progressing", "status": "False",
                    "reason": "ProgressDeadlineExceeded"}]}
        }),
    ];
    let responder = tokio::spawn(async move {
        for body in responses {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            );
        }
    });
    let snapshot = service
        .execute_application(&lease, configuration, NOW + 2)
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::Terminal);
    assert_eq!(snapshot.receiver_result.as_deref(), Some("FAILED"));
    assert!(snapshot.receipt_available);
    assert!(!service
        .receipt(&admission.run_id, NOW + 3)
        .unwrap()
        .is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one test keeps policy mismatch, lease recovery, and deadline proof together"
)]
async fn policy_deadline_and_scheduler_lease_fail_closed_before_application() {
    let (root, service) = fixture("policy-lease");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    assert_eq!(specification.policy_revision, "sandbox-policy-v1");
    assert_eq!(specification.deadline_seconds, 180);
    assert_eq!(specification.deadline_at_unix_s, NOW + 181);
    assert_eq!(specification.required_objects.len(), 10);
    assert_eq!(
        specification.required_objects[0].identity,
        format!("Namespace/sandbox-{}", admission.run_id)
    );
    assert_eq!(
        service.recover_run(&admission.run_id, None, NOW + 2),
        Err(ServiceError::LeaseBusy)
    );
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 2,
    )
    .unwrap();
    let recovered = service
        .recover_run(&admission.run_id, Some(&lease), NOW + 2)
        .unwrap();
    let recovered_specification = service
        .provisioning_specification(&recovered, NOW + 2)
        .unwrap();
    assert_eq!(recovered_specification, specification);
    assert_eq!(
        service.provisioning_specification(&lease, NOW + 2),
        Err(ServiceError::LeaseBusy)
    );
    let target = ProvisionedTarget {
        namespace_uid: "policy-namespace-uid".into(),
        policy_revision: specification.policy_revision.clone(),
        policy_inventory_digest: specification.policy_inventory_digest.clone(),
        cleanup_identity: specification.cleanup_identity.clone(),
        objects: provisioned_objects(&specification, "policy-namespace-uid"),
    };
    let mut missing = target.clone();
    missing.objects.pop();
    assert_eq!(
        service.verify_provisioned_target(&recovered, &missing, NOW + 2),
        Err(ServiceError::PolicyMismatch)
    );
    let mut stale = target.clone();
    stale.policy_revision = "sandbox-policy-stale".into();
    assert_eq!(
        service.verify_provisioned_target(&recovered, &stale, NOW + 2),
        Err(ServiceError::PolicyMismatch)
    );
    let mut permissive = target.clone();
    permissive.objects[6].content_digest = "0".repeat(64);
    assert_eq!(
        service.verify_provisioned_target(&recovered, &permissive, NOW + 2),
        Err(ServiceError::PolicyMismatch)
    );
    let mut duplicate_uid = target.clone();
    duplicate_uid.objects[1].uid = duplicate_uid.objects[0].uid.clone();
    assert_eq!(
        service.verify_provisioned_target(&recovered, &duplicate_uid, NOW + 2),
        Err(ServiceError::OwnershipMismatch)
    );
    let mut wrong_owner = target;
    wrong_owner.objects[7].owner_label = "cleanup-other".into();
    assert_eq!(
        service.verify_provisioned_target(&recovered, &wrong_owner, NOW + 2),
        Err(ServiceError::OwnershipMismatch)
    );
    let (configuration, mut handle) =
        application_configuration(&root, &admission.run_id, Scenario::Healthy);
    assert!(matches!(
        service
            .execute_application(&recovered, configuration, NOW + 2)
            .await,
        Err(kapsel_sandbox::RunError::Service(
            ServiceError::PolicyMismatch
        ))
    ));
    let provider_request =
        tokio::time::timeout(std::time::Duration::from_millis(20), handle.next_request()).await;
    assert!(matches!(provider_request, Ok(None) | Err(_)));
    service
        .record_setup_failure(&recovered, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    let deadline_admission = service.admit(&key(2), Scenario::Healthy, NOW).unwrap();
    service.dispatch_next(NOW + 1).unwrap();
    assert_eq!(
        service.record_deadline(&deadline_admission.run_id, NOW + 180),
        Err(ServiceError::InvalidTransition)
    );
    service
        .record_deadline(&deadline_admission.run_id, NOW + 181)
        .unwrap();
    let deadline_snapshot = service
        .snapshot(&deadline_admission.run_id, NOW + 181)
        .unwrap();
    assert_eq!(deadline_snapshot.execution_state, ExecutionState::Running);
    assert_eq!(deadline_snapshot.receiver_result, None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pagination_every_cursor_is_snapshot_consistent_during_append_and_bounded() {
    let (root, service) = fixture("event-pagination");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = verify_target(&service, &lease, "pagination-namespace-uid", NOW + 1);
    service
        .record_setup_failure(&lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    let service = std::sync::Arc::new(service);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let reader = std::sync::Arc::clone(&service);
    let reader_barrier = std::sync::Arc::clone(&barrier);
    let reader_run_id = admission.run_id.clone();
    let reader_thread = std::thread::spawn(move || {
        reader_barrier.wait();
        reader.events(&reader_run_id, 0, 64, NOW + 3).unwrap()
    });
    barrier.wait();
    service
        .start_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            "pagination-namespace-uid",
            NOW + 3,
        )
        .unwrap();
    let concurrent_page = reader_thread.join().unwrap();
    assert_eq!(
        concurrent_page.events.last().map(|event| event.sequence),
        Some(concurrent_page.last_sequence)
    );
    service
        .complete_cleanup(
            &admission.run_id,
            &specification.cleanup_identity,
            &cleanup_absence(&specification, "pagination-namespace-uid"),
            NOW + 4,
        )
        .unwrap();
    let all = service.events(&admission.run_id, 0, 64, NOW + 4).unwrap();
    for after in 0..=all.last_sequence {
        let page = service
            .events(&admission.run_id, after, 64, NOW + 4)
            .unwrap();
        let expected = all
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(page.events, expected);
        assert_eq!(page.last_sequence, all.last_sequence);
    }
    assert_eq!(
        service.events(&admission.run_id, 0, 65, NOW + 4),
        Err(ServiceError::InvalidRequest)
    );
    assert!(all.events.len() <= 64);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_resource_setup_cleanup_survives_restart_and_expires() {
    let (root, service) = fixture("no-resource-cleanup");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    assert_eq!(
        service.record_setup_failure_without_resources(&lease, "cleanup-wrong", NOW + 2),
        Err(ServiceError::OwnershipMismatch)
    );
    service
        .record_setup_failure_without_resources(&lease, &specification.cleanup_identity, NOW + 2)
        .unwrap();
    let active: i64 = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM cleanup_records WHERE active = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, 0);
    let page = service.events(&admission.run_id, 0, 64, NOW + 2).unwrap();
    assert_eq!(page.events.len(), 5);
    assert!(page
        .events
        .windows(2)
        .all(|pair| pair[1].sequence == pair[0].sequence + 1));
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 3,
    )
    .unwrap();
    let snapshot = service.snapshot(&admission.run_id, NOW + 3).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::ServiceFailed);
    assert_eq!(snapshot.cleanup_state, CleanupState::Succeeded);
    assert_eq!(snapshot.receiver_result, None);
    assert!(service.recoverable_runs().unwrap().is_empty());
    service.sweep_retention(NOW + 86_400).unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    let retained: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runs WHERE run_id = ?1",
            [&admission.run_id],
            |row| row.get(0),
        )
        .unwrap();
    let tombstones: i64 = connection
        .query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(tombstones, 1);
    drop(connection);
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 172_800,
    )
    .unwrap();
    let tombstones: i64 = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tombstones, 0);
    let replacement = service
        .admit(&key(1), Scenario::UnavailableImage, NOW + 172_800)
        .unwrap();
    assert_ne!(replacement.run_id, admission.run_id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_restart_after_both_retention_windows_leaves_no_due_tombstone() {
    let (root, service) = fixture("direct-forty-eight-hour-restart");
    let admission = service.admit(&key(1), Scenario::Healthy, NOW).unwrap();
    drop(service);

    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW + 172_800,
    )
    .unwrap();
    let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
    let retained: i64 = connection
        .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
        .unwrap();
    let tombstones: i64 = connection
        .query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(tombstones, 0);
    drop(connection);
    let replacement = service
        .admit(&key(1), Scenario::UnavailableImage, NOW + 172_800)
        .unwrap();
    assert_ne!(replacement.run_id, admission.run_id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps hostile parsing and bounded error disclosure contiguous"
)]
fn strict_http_translation_rejects_hostile_or_authority_input_without_echo() {
    let (root, service) = fixture("http");
    let body = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .header("idempotency-key", key(1))
        .body(body)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    let run_id = value["run_id"].as_str().unwrap();
    assert_eq!(run_id.len(), 32);
    let text = String::from_utf8(response.body().clone()).unwrap();
    assert!(!text.contains(&key(1)));
    assert!(!text.contains("journal"));
    assert!(!text.contains("credential"));

    let hostile = br#"{"api_version":"v1","scenario":"healthy","namespace":"owned"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", hostile.len())
        .header("idempotency-key", key(2))
        .header("authorization", "secret")
        .body(hostile)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(response.body().clone()).unwrap();
    assert!(!text.contains("secret"));
    assert!(!text.contains("owned"));

    let bounded = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let query_request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs?forwarded=true")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", bounded.len())
        .header("idempotency-key", key(6))
        .body(bounded.clone())
        .unwrap();
    assert_eq!(
        service.handle_http(&query_request, NOW).status(),
        StatusCode::BAD_REQUEST
    );
    for header_name in [
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-client-cert",
        "x-client-cert",
        "x-amzn-mtls-clientcert",
        "x-arr-clientcert",
        "traceparent",
        "x-b3-traceid",
        "baggage",
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/sandbox/v1/runs")
            .header("host", "kapsel.invalid")
            .header("content-type", "application/json")
            .header("content-length", bounded.len())
            .header("idempotency-key", key(6))
            .header(header_name, "hostile-routing-value")
            .body(bounded.clone())
            .unwrap();
        assert_eq!(
            service.handle_http(&request, NOW).status(),
            StatusCode::BAD_REQUEST,
            "header {header_name} must fail closed"
        );
    }

    let path = format!("/sandbox/v1/runs/{run_id}/events?after=0&limit=64");
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "kapsel.invalid")
        .body(Vec::new())
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::OK);
    let event_value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(event_value["events"].as_array().unwrap().len(), 1);

    let duplicate = br#"{"api_version":"v1","scenario":"healthy","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", duplicate.len())
        .header("idempotency-key", key(3))
        .body(duplicate)
        .unwrap();
    assert_eq!(
        service.handle_http(&request, NOW).status(),
        StatusCode::BAD_REQUEST
    );

    let unsupported = br#"{"api_version":"v2","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v2/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", unsupported.len())
        .header("idempotency-key", key(4))
        .body(unsupported)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(value["error"]["code"], "unsupported_version");

    service.set_global_stop(true).unwrap();
    let unavailable = br#"{"api_version":"v1","scenario":"healthy"}"#.to_vec();
    let request = Request::builder()
        .method("POST")
        .uri("/sandbox/v1/runs")
        .header("host", "kapsel.invalid")
        .header("content-type", "application/json")
        .header("content-length", unavailable.len())
        .header("idempotency-key", key(5))
        .body(unavailable)
        .unwrap();
    let response = service.handle_http(&request, NOW);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "30");
    let value: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(value["error"]["code"], "service_unavailable");
    fs::remove_dir_all(root).unwrap();
}
