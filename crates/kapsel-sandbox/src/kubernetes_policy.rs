//! Fixed Kubernetes policy rendering for the one sandbox deployment experiment.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const REVISION: &str = "sandbox-policy-v2";
const RUNNERS_NAMESPACE: &str = "kapsel-sandbox-runners";
const BASE_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
);

pub(crate) struct RenderedPolicyObject {
    pub(crate) identity: String,
    pub(crate) body: Value,
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed renderer keeps the exact eleven-object policy locally reviewable"
)]
pub(crate) fn render(run_id: &str) -> Vec<RenderedPolicyObject> {
    let namespace = format!("sandbox-{run_id}");
    let cleanup = format!("cleanup-{run_id}");
    let runner = format!("runner-{run_id}");
    let labels = json!({
        "kapsel.dev/cleanup-owner": cleanup,
        "kapsel.dev/policy-revision": REVISION,
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

    vec![
        RenderedPolicyObject {
            identity: format!("Namespace/{namespace}"),
            body: json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "kapsel.dev/cleanup-owner": cleanup,
                        "kapsel.dev/policy-revision": REVISION,
                        "kapsel.dev/sandbox-run-id": run_id,
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
            "ServiceAccount",
            RUNNERS_NAMESPACE,
            &runner,
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": metadata(&runner, Some(RUNNERS_NAMESPACE)),
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
                    "verbs": ["get", "list", "watch", "patch"]
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
                    "name": runner,
                    "namespace": RUNNERS_NAMESPACE
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
                    "configmaps": "2",
                    "count/deployments.apps": "1",
                    "count/endpointslices.discovery.k8s.io": "2",
                    "count/jobs.batch": "0",
                    "count/networkpolicies.networking.k8s.io": "4",
                    "count/persistentvolumeclaims": "0",
                    "count/replicasets.apps": "4",
                    "count/secrets": "0",
                    "count/services": "1",
                    "limits.cpu": "4",
                    "limits.ephemeral-storage": "8Gi",
                    "limits.memory": "4Gi",
                    "pods": "4",
                    "requests.cpu": "2",
                    "requests.ephemeral-storage": "4Gi",
                    "requests.memory": "2Gi",
                    "services": "1"
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
                    "max": {"cpu": "2", "ephemeral-storage": "4Gi", "memory": "2Gi"},
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
            "NetworkPolicy",
            &namespace,
            "fixed-egress",
            json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": metadata("fixed-egress", Some(&namespace)),
                "spec": {
                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "sandbox-target"}},
                    "policyTypes": ["Egress"],
                    "egress": [{
                        "to": [{
                            "namespaceSelector": {"matchLabels": {
                                "kubernetes.io/metadata.name": "kube-system"
                            }},
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}
                        }],
                        "ports": [
                            {"port": 53, "protocol": "UDP"},
                            {"port": 53, "protocol": "TCP"}
                        ]
                    }]
                }
            }),
        ),
        namespaced(
            "Deployment",
            &namespace,
            "sandbox-target",
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": metadata("sandbox-target", Some(&namespace)),
                "spec": {
                    "replicas": 1,
                    "progressDeadlineSeconds": 30,
                    "revisionHistoryLimit": 3,
                    "selector": {"matchLabels": {"app.kubernetes.io/name": "sandbox-target"}},
                    "template": {
                        "metadata": {"labels": {
                            "app.kubernetes.io/name": "sandbox-target",
                            "kapsel.dev/cleanup-owner": cleanup,
                            "kapsel.dev/sandbox-run-id": run_id
                        }},
                        "spec": {
                            "automountServiceAccountToken": false,
                            "enableServiceLinks": false,
                            "runtimeClassName": "gvisor",
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
        namespaced(
            "Service",
            &namespace,
            "sandbox-target",
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": metadata("sandbox-target", Some(&namespace)),
                "spec": {
                    "type": "ClusterIP",
                    "selector": {"app.kubernetes.io/name": "sandbox-target"},
                    "ports": [{
                        "name": "synthetic",
                        "port": 8080,
                        "protocol": "TCP",
                        "targetPort": 8080
                    }]
                }
            }),
        ),
    ]
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

#[cfg(test)]
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
            remove_exact(
                &mut normalized,
                "/spec/strategy",
                &json!({
                    "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"},
                    "type": "RollingUpdate"
                }),
            )?;
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
    fn policy_render_is_exact_bounded_and_server_owned() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let objects = render(run_id);
        assert_eq!(objects.len(), 11);
        assert_eq!(objects[0].identity, format!("Namespace/sandbox-{run_id}"));
        assert_eq!(
            objects[1].identity,
            format!("ServiceAccount/sandbox-{run_id}/sandbox-target")
        );
        assert_eq!(
            objects[2].identity,
            format!("ServiceAccount/{RUNNERS_NAMESPACE}/runner-{run_id}")
        );
        let deployment = &objects[9].body;
        assert_eq!(
            deployment["spec"]["template"]["spec"]["runtimeClassName"],
            "gvisor"
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
        let quota = &objects[5].body["spec"]["hard"];
        assert_eq!(quota["pods"], "4");
        assert_eq!(quota["count/endpointslices.discovery.k8s.io"], "2");
        assert_eq!(quota["count/networkpolicies.networking.k8s.io"], "4");
        assert_eq!(quota["count/secrets"], "0");
        assert_eq!(quota["count/persistentvolumeclaims"], "0");
        assert_eq!(quota["count/jobs.batch"], "0");
        let aggregate = content_digest(&Value::Array(
            objects.iter().map(|item| item.body.clone()).collect(),
        ));
        assert_eq!(
            aggregate,
            "d25a20dd7559178fdd33bcd2f64e9ebf86ff3da48b3796db32f79ca90f738baa"
        );
    }

    #[test]
    fn observed_digest_allows_only_exact_server_defaults() {
        let expected = render("0123456789abcdef0123456789abcdef");
        let deployment = &expected[9].body;
        let mut observed = deployment.clone();
        observed["metadata"]["uid"] = json!("deployment-uid");
        observed["metadata"]["resourceVersion"] = json!("17");
        observed["metadata"]["generation"] = json!(1);
        observed["metadata"]["creationTimestamp"] = json!("2026-07-25T00:00:00Z");
        observed["metadata"]["managedFields"] = json!([]);
        observed["status"] = json!({"availableReplicas": 1});
        observed["spec"]["strategy"] = json!({
            "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"},
            "type": "RollingUpdate"
        });
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
