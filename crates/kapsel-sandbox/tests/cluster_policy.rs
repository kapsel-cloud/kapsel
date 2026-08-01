//! Public-interface proof for the fixed provider-neutral cluster policy.

#![allow(
    clippy::panic,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unwrap_used,
    reason = "controlled provider-neutral fixture failures must stop the focused contract test"
)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use kapsel_sandbox::{
    ClusterBoundaryObservation, ConditionalDeploymentObservation, ExecutionState,
    ObservedClusterComposition, ObservedPolicyObject, ProvisioningSpecification, Scenario, Service,
    ServiceError,
};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> (PathBuf, Service) {
    let suffix = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "kapsel-sandbox-cluster-policy-{}-{name}-{suffix}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("receipts")).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(root.join("receipts"), fs::Permissions::from_mode(0o700)).unwrap();
    let service = Service::open(
        root.join("sandbox.sqlite3"),
        root.join("receipts"),
        [7; 32],
        NOW,
    )
    .unwrap();
    (root, service)
}

fn observed(mut body: Value, uid: &str) -> ObservedPolicyObject {
    body["metadata"]["uid"] = json!(uid);
    body["metadata"]["resourceVersion"] = json!("17");
    ObservedPolicyObject { body }
}

fn exact_run_objects(specification: &ProvisioningSpecification) -> Vec<ObservedPolicyObject> {
    specification
        .required_objects
        .iter()
        .enumerate()
        .map(|(index, object)| {
            observed(
                object.canonical_body.clone(),
                &format!("run-object-{index}"),
            )
        })
        .collect()
}

fn boundary() -> ClusterBoundaryObservation {
    let (objects, behavior_records) = Service::cluster_boundary_specification().unwrap();
    ClusterBoundaryObservation {
        objects: objects
            .into_iter()
            .enumerate()
            .map(|(index, object)| {
                observed(object.canonical_body, &format!("boundary-object-{index}"))
            })
            .collect(),
        behavior_records,
    }
}

#[test]
fn weakened_cluster_policy_rejects_before_application_and_holds_capacity() {
    let (root, service) = fixture("weakened");
    let admitted = service
        .admit("11111111111111111111111111111111", Scenario::Healthy, NOW)
        .unwrap();
    let queued = service
        .admit("22222222222222222222222222222222", Scenario::Healthy, NOW)
        .unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    let mut run_objects = exact_run_objects(&specification);
    let default_deny = run_objects
        .iter_mut()
        .find(|object| object.body["kind"] == "NetworkPolicy")
        .unwrap();
    default_deny.body["spec"]
        .as_object_mut()
        .unwrap()
        .remove("policyTypes");

    let observation = ObservedClusterComposition {
        boundary: boundary(),
        run_objects,
        generated_children: Vec::new(),
        owned_orphans: Vec::new(),
    };
    assert_eq!(
        service.verify_observed_cluster(&lease, &observation, NOW + 1),
        Err(ServiceError::PolicyMismatch)
    );
    let snapshot = service.snapshot(&admitted.run_id, NOW + 1).unwrap();
    assert_eq!(snapshot.execution_state, ExecutionState::Running);
    assert_eq!(snapshot.receiver_result, None);
    assert!(!snapshot.receipt_available);
    assert_eq!(
        service.dispatch_next(NOW + 1),
        Err(ServiceError::ActiveSaturated)
    );
    assert_eq!(queued.run_id.len(), 32);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn complete_composition_downgrade_matrix_fails_closed_before_invocation() {
    let cases: Vec<(&str, Box<dyn Fn(&mut ObservedClusterComposition)>)> = vec![
        (
            "missing",
            Box::new(|value| {
                value.run_objects.pop();
            }),
        ),
        (
            "extra",
            Box::new(|value| value.run_objects.push(value.run_objects[1].clone())),
        ),
        (
            "duplicate",
            Box::new(|value| value.run_objects[2] = value.run_objects[1].clone()),
        ),
        (
            "oversized-response",
            Box::new(|value| {
                value.run_objects[0].body["oversized"] = json!("x".repeat(2 * 1024 * 1024));
            }),
        ),
        (
            "stale-revision",
            Box::new(|value| {
                value.run_objects[1].body["metadata"]["labels"]["kapsel.dev/policy-revision"] =
                    json!("stale");
            }),
        ),
        (
            "wrong-owner",
            Box::new(|value| {
                value.run_objects[3].body["metadata"]["labels"]["kapsel.dev/cleanup-owner"] =
                    json!("wrong");
            }),
        ),
        (
            "runtime-fallback",
            Box::new(|value| {
                value.boundary.objects[0].body["handler"] = json!("fallback");
            }),
        ),
        (
            "network-fallback",
            Box::new(|value| {
                value.boundary.behavior_records[0]["fallback_behavior"] = json!("allow");
            }),
        ),
        (
            "admission-drift",
            Box::new(|value| {
                value.boundary.behavior_records[1]["failure_policy"] = json!("Ignore");
            }),
        ),
        (
            "canary-substitution",
            Box::new(|value| {
                let canary = value.boundary.objects.last_mut().unwrap();
                canary.body["data"]["sentinel"] = json!("changed");
            }),
        ),
        (
            "runner-rbac-widening",
            Box::new(|value| {
                let role = value
                    .run_objects
                    .iter_mut()
                    .find(|object| {
                        object.body["kind"] == "Role"
                            && object.body["metadata"]["name"] == "sandbox-runner"
                    })
                    .unwrap();
                role.body["rules"][0]["verbs"] = json!(["get", "list", "patch"]);
            }),
        ),
        (
            "quota-widening",
            Box::new(|value| {
                let quota = value
                    .run_objects
                    .iter_mut()
                    .find(|object| object.body["kind"] == "ResourceQuota")
                    .unwrap();
                quota.body["spec"]["hard"]["pods"] = json!("2");
            }),
        ),
        (
            "network-widening",
            Box::new(|value| {
                let policy = value
                    .run_objects
                    .iter_mut()
                    .find(|object| object.body["kind"] == "NetworkPolicy")
                    .unwrap();
                policy.body["spec"]["egress"] = json!([{}]);
            }),
        ),
        (
            "security-downgrade",
            Box::new(|value| {
                let deployment = value
                    .run_objects
                    .iter_mut()
                    .find(|object| object.body["kind"] == "Deployment")
                    .unwrap();
                deployment.body["spec"]["template"]["spec"]["hostNetwork"] = json!(true);
            }),
        ),
        (
            "unknown-default",
            Box::new(|value| {
                value.run_objects[1].body["serverAdded"] = json!(true);
            }),
        ),
        (
            "owned-orphan",
            Box::new(|value| {
                value.owned_orphans.push(value.run_objects[1].clone());
            }),
        ),
    ];
    for (index, (name, mutate)) in cases.into_iter().enumerate() {
        let (root, service) = fixture(name);
        let key = format!("{index:032x}");
        let admission = service.admit(&key, Scenario::Healthy, NOW).unwrap();
        let lease = service.dispatch_next(NOW + 1).unwrap();
        let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
        let mut composition = ObservedClusterComposition {
            boundary: boundary(),
            run_objects: exact_run_objects(&specification),
            generated_children: Vec::new(),
            owned_orphans: Vec::new(),
        };
        mutate(&mut composition);
        assert!(
            matches!(
                service.verify_observed_cluster(&lease, &composition, NOW + 1),
                Err(ServiceError::PolicyMismatch | ServiceError::OwnershipMismatch)
            ),
            "case {name}"
        );
        let snapshot = service.snapshot(&admission.run_id, NOW + 1).unwrap();
        assert_eq!(snapshot.execution_state, ExecutionState::Running);
        assert_eq!(snapshot.receiver_result, None);
        assert!(!snapshot.receipt_available);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn exact_conditional_old_new_comparison_allows_only_image_and_operation_annotation() {
    let (root, service) = fixture("conditional");
    service
        .admit("33333333333333333333333333333333", Scenario::Healthy, NOW)
        .unwrap();
    let lease = service.dispatch_next(NOW + 1).unwrap();
    let specification = service.provisioning_specification(&lease, NOW + 1).unwrap();
    let exact_composition = ObservedClusterComposition {
        boundary: boundary(),
        run_objects: exact_run_objects(&specification),
        generated_children: Vec::new(),
        owned_orphans: Vec::new(),
    };
    service
        .verify_observed_cluster(&lease, &exact_composition, NOW + 1)
        .unwrap();
    let mut substituted_provisioning_version = exact_composition.clone();
    substituted_provisioning_version
        .run_objects
        .iter_mut()
        .find(|object| object.body["kind"] == "Deployment")
        .unwrap()
        .body["metadata"]["resourceVersion"] = json!("18");
    assert_eq!(
        service.verify_observed_cluster(&lease, &substituted_provisioning_version, NOW + 1),
        Err(ServiceError::PolicyMismatch)
    );
    let deployment_uid = exact_composition
        .run_objects
        .iter()
        .find(|object| object.body["kind"] == "Deployment")
        .unwrap()
        .body["metadata"]["uid"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut substituted_boundary = exact_composition;
    substituted_boundary.boundary.objects[0].body["metadata"]["uid"] =
        json!("substituted-boundary-uid");
    assert_eq!(
        service.verify_observed_cluster(&lease, &substituted_boundary, NOW + 1),
        Err(ServiceError::PolicyMismatch)
    );
    let mut old = specification
        .required_objects
        .iter()
        .find(|object| object.canonical_body["kind"] == "Deployment")
        .unwrap()
        .canonical_body
        .clone();
    old["metadata"]["uid"] = json!(deployment_uid);
    old["metadata"]["resourceVersion"] = json!("17");
    let mut accepted = old.clone();
    accepted["spec"]["template"]["spec"]["containers"][0]["image"] = json!(concat!(
        "registry.k8s.io/pause@sha256:",
        "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
    ));
    accepted["metadata"]["annotations"]["kapsel.dev/kap0038-operation-id"] =
        json!(format!("sandbox-{}", lease.run_id));
    let exact = ConditionalDeploymentObservation {
        old_object: old.clone(),
        new_object: accepted.clone(),
    };
    service
        .verify_conditional_deployment(&lease, &exact, NOW + 1)
        .unwrap();

    let mut denied = Vec::new();
    let mut changed = accepted.clone();
    changed["spec"]["replicas"] = json!(2);
    denied.push((old.clone(), changed));
    let mut changed = accepted.clone();
    changed["metadata"]["annotations"]["extra"] = json!("forbidden");
    denied.push((old.clone(), changed));
    let mut changed = accepted.clone();
    changed["spec"]["template"]["spec"]["containers"][1]["image"] = json!("wrong");
    denied.push((old.clone(), changed));
    let mut hostile_old = old.clone();
    hostile_old["spec"]["template"]["spec"]["hostNetwork"] = json!(true);
    denied.push((hostile_old, accepted.clone()));
    let mut substituted_uid_old = old.clone();
    let mut substituted_uid_new = accepted.clone();
    substituted_uid_old["metadata"]["uid"] = json!("replacement-deployment-uid");
    substituted_uid_new["metadata"]["uid"] = json!("replacement-deployment-uid");
    denied.push((substituted_uid_old, substituted_uid_new));
    let mut substituted_version_old = old.clone();
    let mut substituted_version_new = accepted.clone();
    substituted_version_old["metadata"]["resourceVersion"] = json!("18");
    substituted_version_new["metadata"]["resourceVersion"] = json!("18");
    denied.push((substituted_version_old, substituted_version_new));
    let mut digest_old = old.clone();
    digest_old["metadata"]["annotations"]["kapsel.dev/canonical-deployment-digest"] =
        json!("z".repeat(64));
    denied.push((digest_old, accepted));
    for (old_object, new_object) in denied {
        assert_eq!(
            service.verify_conditional_deployment(
                &lease,
                &ConditionalDeploymentObservation {
                    old_object,
                    new_object,
                },
                NOW + 1,
            ),
            Err(ServiceError::PolicyMismatch)
        );
    }
    fs::remove_dir_all(root).unwrap();
}
