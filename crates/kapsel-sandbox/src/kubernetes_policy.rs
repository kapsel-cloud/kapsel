//! Fixed Kubernetes policy rendering for the one sandbox deployment experiment.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const REVISION: &str = "sandbox-policy-v3";
const RUNNERS_NAMESPACE: &str = "kapsel-sandbox-runners";
const RUNNER_ACCOUNT: &str = "kapsel-sandbox-runner";
const CLEANUP_NAMESPACE: &str = "kapsel-sandbox-cleanup";
const RUNTIME_CLASS: &str = "kapsel-sandbox-runtime-v1";
pub(crate) const BASE_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
);

pub(crate) struct RenderedPolicyObject {
    pub(crate) identity: String,
    pub(crate) body: Value,
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed baseline stays compile-time composed and directly auditable"
)]
pub(crate) fn boundary_objects() -> Vec<RenderedPolicyObject> {
    let baseline = json!({
        "kapsel.dev/policy-revision": REVISION,
        "kapsel.dev/sandbox-owner": "kapsel-cluster-baseline"
    });
    let metadata = |name: &str, namespace: Option<&str>| {
        let mut value = json!({"name": name, "labels": baseline});
        if let Some(namespace) = namespace {
            value["namespace"] = json!(namespace);
        }
        value
    };
    let object = |identity: &str, body: Value| RenderedPolicyObject {
        identity: identity.into(),
        body,
    };
    let mut objects = vec![object(
        "RuntimeClass/kapsel-sandbox-runtime-v1",
        json!({
            "apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
            "metadata": metadata("kapsel-sandbox-runtime-v1", None),
            "handler": "kapsel.dev/sandbox-runtime-v1"
        }),
    )];
    for namespace in [
        "kapsel-sandbox-provisioner",
        "kapsel-sandbox-runners",
        "kapsel-sandbox-cleanup",
    ] {
        let mut labels = baseline.clone();
        labels["kubernetes.io/metadata.name"] = json!(namespace);
        objects.push(object(
            &format!("Namespace/{namespace}"),
            json!({
                "apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": namespace, "labels": labels}
            }),
        ));
    }
    for (namespace, account) in [
        ("kapsel-sandbox-provisioner", "kapsel-sandbox-provisioner"),
        ("kapsel-sandbox-runners", RUNNER_ACCOUNT),
        ("kapsel-sandbox-cleanup", "kapsel-sandbox-cleanup"),
    ] {
        objects.push(object(
            &format!("ServiceAccount/{namespace}/{account}"),
            json!({
                "apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": metadata(account, Some(namespace)),
                "automountServiceAccountToken": false
            }),
        ));
    }
    let provisioner_rules = json!([
        {
            "apiGroups": ["node.k8s.io"],
            "resources": ["runtimeclasses"],
            "verbs": ["get", "list"]
        },
        {
            "apiGroups": [""],
            "resources": ["namespaces", "serviceaccounts", "resourcequotas", "limitranges"],
            "verbs": ["get", "list", "create"]
        },
        {
            "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]
        },
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["clusterroles", "clusterrolebindings"],
            "verbs": ["get", "list"]
        },
        {
            "apiGroups": ["apps"], "resources": ["deployments"],
            "verbs": ["get", "list", "create"]
        },
        {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
        {
            "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"],
            "verbs": ["get", "list", "create"]
        },
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["roles", "rolebindings"],
            "verbs": ["get", "list", "create", "bind", "escalate"]
        }
    ]);
    let cleanup_rules = json!([
        {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get", "delete"]},
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["roles", "rolebindings"],
            "resourceNames": ["sandbox-cleanup"], "verbs": ["get", "delete"]
        }
    ]);
    for (name, rules, namespace, account) in [
        (
            "kapsel-sandbox-provisioner-v1",
            provisioner_rules,
            "kapsel-sandbox-provisioner",
            "kapsel-sandbox-provisioner",
        ),
        (
            "kapsel-sandbox-cleanup-v1",
            cleanup_rules,
            "kapsel-sandbox-cleanup",
            "kapsel-sandbox-cleanup",
        ),
    ] {
        objects.push(object(
            &format!("ClusterRole/{name}"),
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": metadata(name, None), "rules": rules
            }),
        ));
        objects.push(object(
            &format!("ClusterRoleBinding/{name}"),
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": metadata(name, None),
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole", "name": name
                },
                "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": namespace}]
            }),
        ));
    }
    let canary_labels = json!({
        "kapsel.dev/policy-revision": REVISION,
        "kapsel.dev/sandbox-owner": "kapsel-operator-canary"
    });
    let mut canary_namespace_labels = canary_labels.clone();
    canary_namespace_labels["kubernetes.io/metadata.name"] = json!("kapsel-sandbox-canary");
    objects.push(object(
        "Namespace/kapsel-sandbox-canary",
        json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": "kapsel-sandbox-canary", "labels": canary_namespace_labels}
        }),
    ));
    objects.push(object(
        "ConfigMap/kapsel-sandbox-canary/isolation-canary",
        json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {
                "name": "isolation-canary", "namespace": "kapsel-sandbox-canary",
                "labels": canary_labels
            },
            "data": {"sentinel": "kapsel-sandbox-canary-v1"}
        }),
    ));
    objects
}

pub(crate) fn behavior_records() -> Result<Vec<Value>, ()> {
    parse_behavior_records(&[
        include_str!("../../../deploy/sandbox/network-boundary-record.json"),
        include_str!("../../../deploy/sandbox/composition-admission-rule.json"),
        include_str!("../../../deploy/sandbox/operator-admission-rule.json"),
        include_str!("../../../deploy/sandbox/cleanup-admission-rule.json"),
    ])
}

fn parse_behavior_records(records: &[&str]) -> Result<Vec<Value>, ()> {
    records
        .iter()
        .map(|record| serde_json::from_str(record).map_err(|_| ()))
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed renderer keeps the exact ten-object policy locally reviewable"
)]
pub(crate) fn render(run_id: &str, selected_image: &str) -> Result<Vec<RenderedPolicyObject>, ()> {
    let namespace = format!("sandbox-{run_id}");
    let cleanup = format!("cleanup-{run_id}");
    let labels = json!({
        "kapsel.dev/cleanup-epoch": format!("cleanup-{run_id}-1"),
        "kapsel.dev/cleanup-owner": cleanup,
        "kapsel.dev/policy-revision": REVISION,
        "kapsel.dev/provisioning-generation": format!("provision-{run_id}-1"),
        "kapsel.dev/sandbox-owner": cleanup,
        "kapsel.dev/sandbox-run-id": run_id,
    });
    let metadata = |name: &str, object_namespace: Option<&str>| {
        let mut value = json!({"name": name, "labels": labels});
        if let Some(object_namespace) = object_namespace {
            value["namespace"] = json!(object_namespace);
        }
        value
    };
    let namespaced =
        |kind: &str, object_namespace: &str, name: &str, body: Value| RenderedPolicyObject {
            identity: format!("{kind}/{object_namespace}/{name}"),
            body,
        };
    let mut deployment_metadata = metadata("sandbox-target", Some(&namespace));
    deployment_metadata["annotations"] = json!({
        "kapsel.dev/selected-image": selected_image
    });

    let mut objects = vec![
        RenderedPolicyObject {
            identity: format!("Namespace/{namespace}"),
            body: json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "kapsel.dev/cleanup-epoch": format!("cleanup-{run_id}-1"),
                        "kapsel.dev/cleanup-owner": cleanup,
                        "kapsel.dev/policy-revision": REVISION,
                        "kapsel.dev/provisioning-generation": format!("provision-{run_id}-1"),
                        "kapsel.dev/sandbox-owner": cleanup,
                        "kapsel.dev/sandbox-run-id": run_id,
                        "kubernetes.io/metadata.name": namespace,
                        "pod-security.kubernetes.io/enforce": "restricted",
                        "pod-security.kubernetes.io/enforce-version": "v1.35"
                    }
                }
            }),
        },
        namespaced(
            "ServiceAccount",
            &namespace,
            "sandbox-target",
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": metadata("sandbox-target", Some(&namespace)),
                "automountServiceAccountToken": false
            }),
        ),
        namespaced(
            "Role",
            &namespace,
            "sandbox-runner",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": metadata("sandbox-runner", Some(&namespace)),
                "rules": [{
                    "apiGroups": ["apps"],
                    "resources": ["deployments"],
                    "resourceNames": ["sandbox-target"],
                    "verbs": ["get", "patch"]
                }]
            }),
        ),
        namespaced(
            "RoleBinding",
            &namespace,
            "sandbox-runner",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": metadata("sandbox-runner", Some(&namespace)),
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "sandbox-runner"
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": RUNNER_ACCOUNT,
                    "namespace": RUNNERS_NAMESPACE
                }]
            }),
        ),
        namespaced(
            "Role",
            &namespace,
            "sandbox-cleanup",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": metadata("sandbox-cleanup", Some(&namespace)),
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["limitranges", "pods", "resourcequotas", "serviceaccounts"],
                        "verbs": ["get", "list", "delete"]
                    },
                    {
                        "apiGroups": ["apps"],
                        "resources": ["deployments", "replicasets"],
                        "verbs": ["get", "list", "delete"]
                    },
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "resources": ["networkpolicies"],
                        "verbs": ["get", "list", "delete"]
                    },
                    {
                        "apiGroups": ["rbac.authorization.k8s.io"],
                        "resources": ["rolebindings", "roles"],
                        "verbs": ["get", "list", "delete"]
                    }
                ]
            }),
        ),
        namespaced(
            "RoleBinding",
            &namespace,
            "sandbox-cleanup",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": metadata("sandbox-cleanup", Some(&namespace)),
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "sandbox-cleanup"
                },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "kapsel-sandbox-cleanup",
                    "namespace": CLEANUP_NAMESPACE
                }]
            }),
        ),
        namespaced(
            "ResourceQuota",
            &namespace,
            "sandbox-quota",
            json!({
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": metadata("sandbox-quota", Some(&namespace)),
                "spec": {"hard": {
                    "count/configmaps": "0",
                    "count/deployments.apps": "1",
                    "count/endpointslices.discovery.k8s.io": "0",
                    "count/jobs.batch": "0",
                    "count/limitranges": "1",
                    "count/networkpolicies.networking.k8s.io": "1",
                    "count/persistentvolumeclaims": "0",
                    "count/replicasets.apps": "2",
                    "count/resourcequotas": "1",
                    "count/rolebindings.rbac.authorization.k8s.io": "2",
                    "count/roles.rbac.authorization.k8s.io": "2",
                    "count/secrets": "0",
                    "count/serviceaccounts": "2",
                    "count/services": "0",
                    "limits.cpu": "500m",
                    "limits.ephemeral-storage": "128Mi",
                    "limits.memory": "128Mi",
                    "pods": "1",
                    "requests.cpu": "200m",
                    "requests.ephemeral-storage": "32Mi",
                    "requests.memory": "64Mi"
                }}
            }),
        ),
        namespaced(
            "LimitRange",
            &namespace,
            "sandbox-limits",
            json!({
                "apiVersion": "v1",
                "kind": "LimitRange",
                "metadata": metadata("sandbox-limits", Some(&namespace)),
                "spec": {"limits": [{
                    "type": "Container",
                    "max": {"cpu": "250m", "ephemeral-storage": "64Mi", "memory": "64Mi"},
                    "min": {"cpu": "10m", "ephemeral-storage": "1Mi", "memory": "16Mi"}
                }]}
            }),
        ),
        namespaced(
            "NetworkPolicy",
            &namespace,
            "default-deny",
            json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": metadata("default-deny", Some(&namespace)),
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
            }),
        ),
        namespaced(
            "Deployment",
            &namespace,
            "sandbox-target",
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": deployment_metadata,
                "spec": {
                    "replicas": 1,
                    "progressDeadlineSeconds": 30,
                    "revisionHistoryLimit": 0,
                    "strategy": {"type": "Recreate"},
                    "selector": {"matchLabels": {"app.kubernetes.io/name": "sandbox-target"}},
                    "template": {
                        "metadata": {"labels": {
                            "app.kubernetes.io/name": "sandbox-target",
                            "kapsel.dev/cleanup-epoch": format!("cleanup-{run_id}-1"),
                            "kapsel.dev/cleanup-owner": cleanup,
                            "kapsel.dev/policy-revision": REVISION,
                            "kapsel.dev/provisioning-generation": format!("provision-{run_id}-1"),
                            "kapsel.dev/sandbox-owner": cleanup,
                            "kapsel.dev/sandbox-run-id": run_id
                        }},
                        "spec": {
                            "automountServiceAccountToken": false,
                            "enableServiceLinks": false,
                            "runtimeClassName": RUNTIME_CLASS,
                            "serviceAccountName": "sandbox-target",
                            "terminationGracePeriodSeconds": 5,
                            "securityContext": {
                                "runAsNonRoot": true,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}
                            },
                            "containers": [
                                fixed_container("target"),
                                fixed_container("untargeted")
                            ]
                        }
                    }
                }
            }),
        ),
    ];
    let inventory_digest = inventory_digest(&objects)?;
    if let Some(deployment) = objects.last_mut() {
        deployment.body["metadata"]["annotations"]["kapsel.dev/policy-inventory-digest"] =
            json!(inventory_digest);
        let deployment_digest = canonical_deployment_digest(&deployment.body);
        deployment.body["metadata"]["annotations"]["kapsel.dev/canonical-deployment-digest"] =
            json!(deployment_digest);
    }
    Ok(objects)
}

fn fixed_container(name: &str) -> Value {
    json!({
        "name": name,
        "image": BASE_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["/pause"],
        "resources": {
            "requests": {"cpu": "100m", "ephemeral-storage": "16Mi", "memory": "32Mi"},
            "limits": {"cpu": "250m", "ephemeral-storage": "64Mi", "memory": "64Mi"}
        },
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": true,
            "runAsNonRoot": true
        }
    })
}

pub(crate) fn content_digest(body: &Value) -> String {
    hex(&Sha256::digest(body.to_string().as_bytes()))
}

pub(crate) fn canonical_deployment_digest(body: &Value) -> String {
    let mut canonical = body.clone();
    canonical
        .pointer_mut("/metadata/annotations")
        .and_then(Value::as_object_mut)
        .map(|annotations| annotations.remove("kapsel.dev/canonical-deployment-digest"));
    content_digest(&canonical)
}

fn inventory_digest(objects: &[RenderedPolicyObject]) -> Result<String, ()> {
    let canonical = objects
        .iter()
        .map(|object| {
            let mut body = object.body.clone();
            if body.get("kind").and_then(Value::as_str) == Some("Deployment") {
                if let Some(annotations) = body
                    .pointer_mut("/metadata/annotations")
                    .and_then(Value::as_object_mut)
                {
                    annotations.remove("kapsel.dev/policy-inventory-digest");
                    annotations.remove("kapsel.dev/canonical-deployment-digest");
                }
            }
            json!({"identity": object.identity, "canonical_body": body})
        })
        .collect::<Vec<_>>();
    let mut digest = Sha256::new();
    digest.update(REVISION.as_bytes());
    digest.update([0]);
    let canonical = serde_json::to_vec(&canonical).map_err(|_| ())?;
    digest.update(canonical);
    Ok(hex(&digest.finalize()))
}

pub(crate) fn observed_content_digest(expected: &Value, observed: &Value) -> Option<String> {
    let mut normalized = observed.clone();
    normalized.as_object_mut()?.remove("status");
    let metadata = normalized.get_mut("metadata")?.as_object_mut()?;
    for key in [
        "creationTimestamp",
        "generation",
        "managedFields",
        "resourceVersion",
        "selfLink",
        "uid",
    ] {
        metadata.remove(key);
    }
    match normalized.get("kind")?.as_str()? {
        "Namespace" => {
            remove_exact(&mut normalized, "/spec/finalizers", &json!(["kubernetes"]))?;
            remove_empty_object(&mut normalized, "/spec")?;
        },
        "ServiceAccount" => {
            remove_exact(&mut normalized, "/secrets", &json!([]))?;
        },
        "Deployment" => {
            remove_exact(&mut normalized, "/spec/minReadySeconds", &json!(0))?;
            remove_exact(&mut normalized, "/spec/paused", &json!(false))?;
            remove_exact(
                &mut normalized,
                "/spec/template/metadata/creationTimestamp",
                &Value::Null,
            )?;
            for index in 0..2 {
                remove_exact(
                    &mut normalized,
                    &format!("/spec/template/spec/containers/{index}/terminationMessagePath"),
                    &json!("/dev/termination-log"),
                )?;
                remove_exact(
                    &mut normalized,
                    &format!("/spec/template/spec/containers/{index}/terminationMessagePolicy"),
                    &json!("File"),
                )?;
            }
            remove_exact(
                &mut normalized,
                "/spec/template/spec/dnsPolicy",
                &json!("ClusterFirst"),
            )?;
            remove_exact(
                &mut normalized,
                "/spec/template/spec/restartPolicy",
                &json!("Always"),
            )?;
            remove_exact(
                &mut normalized,
                "/spec/template/spec/schedulerName",
                &json!("default-scheduler"),
            )?;
            remove_exact(
                &mut normalized,
                "/spec/template/spec/serviceAccount",
                &json!("sandbox-target"),
            )?;
        },
        "Service" => {
            remove_string(&mut normalized, "/spec/clusterIP")?;
            remove_string_array(&mut normalized, "/spec/clusterIPs")?;
            remove_string_array(&mut normalized, "/spec/ipFamilies")?;
            remove_exact(
                &mut normalized,
                "/spec/ipFamilyPolicy",
                &json!("SingleStack"),
            )?;
            remove_exact(
                &mut normalized,
                "/spec/internalTrafficPolicy",
                &json!("Cluster"),
            )?;
            remove_exact(&mut normalized, "/spec/sessionAffinity", &json!("None"))?;
        },
        _ => {},
    }
    (normalized == *expected).then(|| content_digest(expected))
}

pub(crate) fn observed_template_matches(expected: &Value, observed: &Value) -> bool {
    let mut observed = observed.clone();
    let Some(labels) = observed
        .pointer_mut("/metadata/labels")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    labels.remove("pod-template-hash");
    let expected_deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {},
        "spec": {"template": expected}
    });
    let observed_deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {},
        "spec": {"template": observed}
    });
    observed_content_digest(&expected_deployment, &observed_deployment).is_some()
}

fn remove_exact(root: &mut Value, pointer: &str, expected: &Value) -> Option<()> {
    let (parent, key) = pointer.rsplit_once('/')?;
    let Some(parent) = root.pointer_mut(parent) else {
        return Some(());
    };
    let object = parent.as_object_mut()?;
    let Some(value) = object.get(key) else {
        return Some(());
    };
    if value != expected {
        return None;
    }
    object.remove(key);
    Some(())
}

fn remove_empty_object(root: &mut Value, pointer: &str) -> Option<()> {
    let Some(value) = root.pointer(pointer) else {
        return Some(());
    };
    if value.as_object()?.is_empty() {
        remove_pointer(root, pointer)
    } else {
        None
    }
}

fn remove_string(root: &mut Value, pointer: &str) -> Option<()> {
    let Some(value) = root.pointer(pointer) else {
        return Some(());
    };
    if value.as_str()?.is_empty() {
        None
    } else {
        remove_pointer(root, pointer)
    }
}

fn remove_string_array(root: &mut Value, pointer: &str) -> Option<()> {
    let Some(value) = root.pointer(pointer) else {
        return Some(());
    };
    let values = value.as_array()?;
    if values.is_empty() || values.iter().any(|value| value.as_str().is_none()) {
        None
    } else {
        remove_pointer(root, pointer)
    }
}

fn remove_pointer(root: &mut Value, pointer: &str) -> Option<()> {
    let (parent, key) = pointer.rsplit_once('/')?;
    root.pointer_mut(parent)?.as_object_mut()?.remove(key)?;
    Some(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_embedded_behavior_record_fails_closed() {
        assert!(parse_behavior_records(&[r#"{"revision":"v1"}"#, "{"]).is_err());
        assert_eq!(behavior_records().unwrap().len(), 4);
    }

    #[test]
    fn policy_render_is_exact_bounded_and_server_owned() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let selected_image = concat!(
            "registry.k8s.io/pause@sha256:",
            "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
        );
        let objects = render(run_id, selected_image).unwrap();
        assert_eq!(objects.len(), 10);
        assert_eq!(objects[0].identity, format!("Namespace/sandbox-{run_id}"));
        assert_eq!(
            objects[1].identity,
            format!("ServiceAccount/sandbox-{run_id}/sandbox-target")
        );
        assert_eq!(
            objects[4].identity,
            format!("Role/sandbox-{run_id}/sandbox-cleanup")
        );
        let deployment = &objects[9].body;
        assert_eq!(
            deployment["spec"]["template"]["spec"]["runtimeClassName"],
            RUNTIME_CLASS
        );
        assert_eq!(
            deployment["spec"]["template"]["spec"]["containers"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        let serialized =
            serde_json::to_string(&objects.iter().map(|item| &item.body).collect::<Vec<_>>())
                .unwrap();
        for forbidden in [
            "LoadBalancer",
            "NodePort",
            "hostPath",
            "privileged",
            "\"image\":\"latest\"",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        assert!(objects
            .iter()
            .all(|item| content_digest(&item.body).len() == 64));
        let quota = &objects[6].body["spec"]["hard"];
        assert_eq!(quota["pods"], "1");
        assert_eq!(quota["count/endpointslices.discovery.k8s.io"], "0");
        assert_eq!(quota["count/networkpolicies.networking.k8s.io"], "1");
        assert_eq!(quota["count/secrets"], "0");
        assert_eq!(quota["count/persistentvolumeclaims"], "0");
        assert_eq!(quota["count/jobs.batch"], "0");
        assert_eq!(
            deployment["metadata"]["annotations"]["kapsel.dev/selected-image"],
            selected_image
        );
    }

    #[test]
    fn observed_digest_allows_only_exact_server_defaults() {
        let expected = render(
            "0123456789abcdef0123456789abcdef",
            concat!(
                "registry.k8s.io/pause@sha256:",
                "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
            ),
        )
        .unwrap();
        let deployment = &expected[9].body;
        let mut observed = deployment.clone();
        observed["metadata"]["uid"] = json!("deployment-uid");
        observed["metadata"]["resourceVersion"] = json!("17");
        observed["metadata"]["generation"] = json!(1);
        observed["metadata"]["creationTimestamp"] = json!("2026-07-25T00:00:00Z");
        observed["metadata"]["managedFields"] = json!([]);
        observed["status"] = json!({"availableReplicas": 1});
        observed["spec"]["minReadySeconds"] = json!(0);
        observed["spec"]["paused"] = json!(false);
        observed["spec"]["template"]["metadata"]["creationTimestamp"] = Value::Null;
        observed["spec"]["template"]["spec"]["dnsPolicy"] = json!("ClusterFirst");
        observed["spec"]["template"]["spec"]["restartPolicy"] = json!("Always");
        observed["spec"]["template"]["spec"]["schedulerName"] = json!("default-scheduler");
        observed["spec"]["template"]["spec"]["serviceAccount"] = json!("sandbox-target");
        for container in observed["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .unwrap()
        {
            container["terminationMessagePath"] = json!("/dev/termination-log");
            container["terminationMessagePolicy"] = json!("File");
        }
        assert_eq!(
            observed_content_digest(deployment, &observed),
            Some(content_digest(deployment))
        );

        let mut hostile = observed.clone();
        hostile["spec"]["template"]["spec"]["hostNetwork"] = json!(true);
        assert_eq!(observed_content_digest(deployment, &hostile), None);
        let mut permissive = observed;
        permissive["spec"]["template"]["spec"]["containers"][0]["securityContext"]
            ["readOnlyRootFilesystem"] = json!(false);
        assert_eq!(observed_content_digest(deployment, &permissive), None);
    }
}
