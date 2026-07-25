#!/usr/bin/env python3
"""Validate the non-executed KAP-0053 GKE authorization candidate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "deploy/sandbox/gate2-gke-fixture.json"
STORAGE_PATH = ROOT / "deploy/sandbox/gate2-gke-storage-class.json"
JOURNAL_PATH = ROOT / "deploy/sandbox/journal-volume-template.json"
WORKLOAD_PATH = ROOT / "deploy/sandbox/workload-template.json"
SYSTEM_WORKLOAD_PATH = ROOT / "deploy/sandbox/gate2-system-workload.json"


class InvalidFixture(AssertionError):
    """Raised when the candidate broadens or omits a locked invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidFixture(message)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_system_workload(workload: dict[str, Any], bindings: dict[str, Any]) -> None:
    require(workload["api_version"] == "kapsel.sandbox.gate2-system-workload/v1", "system workload API")
    status = workload["status"]
    require(not status["execution_authorized"] and not status["composition_complete"], "system workload remains blocked")
    require(not status["directly_applicable"], "evidence wrapper is not directly applicable")
    require(not status["network_access_control_complete"], "network access control blocker")
    require(status["missing_roles"] == ["scheduler", "cleanup-reconciler"], "exact missing roles")
    objects = workload["objects"]
    canonical_objects = json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()
    rendered_digest = f"sha256:{hashlib.sha256(canonical_objects).hexdigest()}"
    require(rendered_digest == status["rendered_objects_sha256"], "complete rendered-object equality")
    require(rendered_digest == "sha256:12f56539a1b2acc12a3df436f0206f2cc6ddc4bfa87eff9beef5b1848e077373", "locked rendered-object digest")
    require([(item["apiVersion"], item["kind"]) for item in objects] == [
        ("v1", "Namespace"),
        ("v1", "ServiceAccount"),
        ("v1", "Service"),
        ("apps/v1", "StatefulSet"),
    ], "exact system object inventory")
    namespace, account, service, stateful_set = objects
    require(namespace["metadata"] == {
        "name": "kapsel-sandbox-system",
        "labels": {"kapsel.dev/gate2": "true", "kapsel.dev/policy-revision": "sandbox-policy-v1"},
    }, "system namespace")
    require(account["metadata"]["name"] == "kapsel-gate2-sandbox-api", "system service account")
    require(account["metadata"]["namespace"] == "kapsel-sandbox-system", "system account namespace")
    require(account["automountServiceAccountToken"] is False, "no ambient system token")
    service_spec = service["spec"]
    require(service_spec["type"] == "ClusterIP" and service_spec["clusterIP"] == "None", "headless private service")
    require(service_spec["publishNotReadyAddresses"] is False, "no unready handoff")
    require(service_spec["ports"] == [
        {"name": "private-http1", "port": 8080, "targetPort": "private-http1", "protocol": "TCP"},
        {"name": "private-handoff", "port": 8081, "targetPort": "private-handoff", "protocol": "TCP"},
    ], "exact private ports")
    specification = stateful_set["spec"]
    require(specification["replicas"] == 1 and specification["serviceName"] == "kapsel-sandbox-private", "singleton system writer")
    require(specification["updateStrategy"] == {"type": "OnDelete"}, "explicit system rollback")
    pod = specification["template"]["spec"]
    require(pod["automountServiceAccountToken"] is False, "pod token disabled")
    require(pod["serviceAccountName"] == "kapsel-gate2-sandbox-api", "exact system identity")
    require(pod["terminationGracePeriodSeconds"] == 30, "bounded termination")
    require(pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}, "pod seccomp")
    init = pod["initContainers"]
    require(len(init) == 1 and init[0]["name"] == "initialize-durable-layout", "one layout initializer")
    expected_state = ["--database", "/var/lib/kapsel-sandbox/admission/sandbox.sqlite3", "--receipts", "/var/lib/kapsel-sandbox/receipts", "--digest-key-file", "/var/run/kapsel-keys/tombstone-digest.seed"]
    require(init[0]["args"] == ["init", *expected_state], "exact initializer command")
    containers = pod["containers"]
    require([container["name"] for container in containers] == ["native-api", "private-handoff", "periodic-retention"], "exact implemented system roles")
    commands = {container["name"]: container["args"] for container in containers}
    require(commands["native-api"] == ["serve", *expected_state, "--origin", "https://kapsel.invalid", "--listen", "0.0.0.0:8080"], "exact native API command")
    require(commands["private-handoff"] == ["handoff-serve", *expected_state, "--listen", "0.0.0.0:8081"], "exact handoff command")
    require(commands["periodic-retention"] == [bindings["GATE2_RETENTION_SUBCOMMAND"], *expected_state], "exact retention command")
    for container in [init[0], *containers]:
        require(container["image"] == "${KAPSEL_SANDBOX_IMAGE_DIGEST}", "one locked image placeholder")
        require(container["imagePullPolicy"] == "IfNotPresent", "image pull policy")
        security = container["securityContext"]
        require(security["allowPrivilegeEscalation"] is False, "no privilege escalation")
        require(security["capabilities"] == {"drop": ["ALL"]}, "all capabilities dropped")
        require(security["readOnlyRootFilesystem"] and security["runAsNonRoot"], "confined process")
        require(set(container["resources"]) == {"requests", "limits"}, "bounded role resources")
        mounts = container["volumeMounts"]
        require(mounts == [
            {"name": "system-state", "mountPath": "/var/lib/kapsel-sandbox"},
            {"name": "tombstone-digest-key", "mountPath": "/var/run/kapsel-keys", "readOnly": True},
        ], "exact system mounts")
    require(pod["volumes"] == [{
        "name": "tombstone-digest-key",
        "secret": {"secretName": "kapsel-gate2-tombstone-digest", "defaultMode": 288},
    }], "exact tombstone projection placeholder")
    claims = specification["volumeClaimTemplates"]
    require(len(claims) == 1 and claims[0]["metadata"]["name"] == "system-state", "one system claim")
    claim = claims[0]["spec"]
    require(claim["accessModes"] == ["ReadWriteOncePod"], "system RWOP")
    require(claim["resources"]["requests"]["storage"] == "20Gi", "system claim size")
    require(claim["storageClassName"] == "${GATE2_STORAGE_CLASS}", "system storage placeholder")
    require(bindings["GATE2_STORAGE_CLASS"] == "kapsel-gate2-regional-pd-balanced", "system storage binding")
    serialized = json.dumps(workload, sort_keys=True)
    require(all(term not in serialized for term in ("LoadBalancer", "NodePort", "hostNetwork", "hostPath", '"runner"')), "no public, host, or runner authority")
    require(set(workload["non_claims"]) == {
        "no_scheduler_or_cleanup_reconciler",
        "no_networkpolicy_or_public_endpoint",
        "no_secret_manager_staging_proof",
        "no_workload_identity_binding_proof",
        "no_provider_render_or_apply",
        "no_gate2_authorization",
    }, "system workload non-claims")


def validate(candidate: dict[str, Any], storage_class: dict[str, Any], system_workload: dict[str, Any]) -> None:
    status = candidate["status"]
    require(status["kind"] == "authorization_candidate", "candidate kind")
    require(status["execution_authorized"] is False, "execution must remain unauthorized")
    require(status["fixture_revision"] is None, "reviewed fixture revision blocker")
    require(candidate["reproduction_lock"]["fixture_source_digest"] is None, "reviewed fixture digest blocker")
    require(set(status["forbidden_without_later_approval"]) == {
        "provider_mutation",
        "credential_use",
        "image_push",
        "resource_creation",
        "spend",
        "endpoint_or_dns_change",
        "public_traffic",
    }, "approval boundaries")

    cluster = candidate["cluster"]
    require(cluster["provider"] == "google-cloud" and cluster["product"] == "gke", "provider")
    require(cluster["mode"] == "standard" and cluster["topology"] == "regional", "GKE mode")
    require(cluster["region"] == "europe-north1", "region")
    require(cluster["zones"] == ["europe-north1-a", "europe-north1-b", "europe-north1-c"], "zones")
    require(cluster["release_channel"] == "regular", "release channel")
    require(cluster["kubernetes_version"] == "1.35.6-gke.1127000", "GKE version")
    require(cluster["node_image"] == "COS_CONTAINERD", "node image")
    require(cluster["runtime_class"] == "gvisor", "runtime class")
    require(cluster["cni_policy_mode"] == "dataplane-v2-cilium-ebpf-networkpolicy-always-on", "CNI")
    require(cluster["private_nodes"] and cluster["workload_identity_federation"], "private identity")
    require(cluster["node_service_account"] == "kapsel-gate2-node@${PROJECT_ID}.iam.gserviceaccount.com", "node identity")
    identities = cluster["workload_identities"]
    require(identities["node_gsa"] == cluster["node_service_account"], "node GSA")
    require(identities["operator_principal_binding_digest"] is None, "operator identity blocker")
    require(identities["kubernetes_rbac_binding_digest"] is None, "operator RBAC blocker")
    expected_gsas = {
        "grant-signer": "kapsel-gate2-grant-signer@${PROJECT_ID}.iam.gserviceaccount.com",
        "receipt-stager": "kapsel-gate2-receipt-stager@${PROJECT_ID}.iam.gserviceaccount.com",
        "sandbox-api": "kapsel-gate2-sandbox-api@${PROJECT_ID}.iam.gserviceaccount.com",
        "runner": "kapsel-gate2-runner@${PROJECT_ID}.iam.gserviceaccount.com",
        "cleanup-controller": "kapsel-gate2-cleanup-controller@${PROJECT_ID}.iam.gserviceaccount.com",
    }
    require(identities["ksa_to_gsa_bindings"] == expected_gsas, "exact separate workload GSAs")
    require(len(set(expected_gsas.values())) == 5, "distinct workload GSAs")
    require("no Secret Manager access" in identities["node_iam_rule"], "node secret denial")
    require(cluster["dns_control_plane_endpoint"] and not cluster["ip_control_plane_endpoints"], "control plane")
    require(all(cluster[key] is None for key in ("application_service", "ingress", "load_balancer", "public_address", "public_dns")), "public surface")
    require(cluster["network"]["private_google_access"] and not cluster["network"]["cloud_nat"], "private network")

    pools = {pool["name"]: pool for pool in candidate["node_pools"]}
    require(set(pools) == {"default-pool", "sandbox"}, "node pool inventory")
    system = pools["default-pool"]
    sandbox = pools["sandbox"]
    require(system["machine_type"] == "e2-standard-2", "system machine")
    require(system["node_locations"] == ["europe-north1-a"], "one-zone system pool")
    require(system["num_nodes_per_location"] == 1 and system["total_nodes"] == 1, "system count")
    require(not system["sandbox"] and not system["autoscaling"] and not system["spot"], "system controls")
    require(sandbox["machine_type"] == "n2-standard-4", "sandbox machine")
    require(sandbox["node_locations"] == cluster["zones"], "sandbox zones")
    require(sandbox["num_nodes_per_location"] == 1 and sandbox["total_nodes"] == 3, "sandbox count")
    require(sandbox["sandbox"] and sandbox["sandbox_type"] == "gvisor", "gVisor pool")
    require(not sandbox["autoscaling"] and not sandbox["spot"] and not sandbox["ordinary_runtime_fallback"], "sandbox fail closed")
    require(sum(pool["total_nodes"] for pool in pools.values()) == 4, "four-node ceiling")

    bindings = candidate["template_bindings"]
    require(bindings["GATE2_RUNTIME_CLASS"] == "gvisor", "runtime binding")
    require(bindings["GATE2_STORAGE_CLASS"] == "kapsel-gate2-regional-pd-balanced", "storage binding")
    require(bindings["GATE2_KUBERNETES_AUDIENCE"] is None, "audience blocker")
    require(bindings["KAPSEL_SANDBOX_IMAGE_DIGEST"] is None, "registry blocker")
    require(bindings["GATE2_RUNNER_SUBCOMMAND"] is None, "runner blocker")
    require(bindings["GATE2_RETENTION_SUBCOMMAND"] == "retention", "retention role binding")
    roles = candidate["service_role_composition"]
    require(roles == {
        "rendered_file": "deploy/sandbox/gate2-system-workload.json",
        "native_api": {"subcommand": "serve", "system_state_writer": True, "public_http_owner": True},
        "private_handoff": {"subcommand": "handoff-serve", "system_state_writer": True, "public_service_forbidden": True},
        "periodic_retention": {"subcommand": "retention", "system_state_writer": True, "fixed_interval_seconds": 60, "transport_listener": False},
        "scheduler": None,
        "cleanup_reconciler": None,
        "shared_system_state_volume": True,
        "runner_system_state_mount": False,
    }, "bounded current service-role composition")
    validate_system_workload(system_workload, bindings)

    require(storage_class["apiVersion"] == "storage.k8s.io/v1", "storage API")
    require(storage_class["kind"] == "StorageClass", "storage kind")
    require(storage_class["metadata"]["name"] == bindings["GATE2_STORAGE_CLASS"], "storage name")
    require(storage_class["provisioner"] == "pd.csi.storage.gke.io", "CSI provisioner")
    require(storage_class["parameters"] == {"type": "pd-balanced", "replication-type": "regional-pd"}, "regional PD")
    require(storage_class["reclaimPolicy"] == "Delete", "reclaim policy")
    require(storage_class["volumeBindingMode"] == "WaitForFirstConsumer", "volume binding")
    topology = storage_class["allowedTopologies"][0]["matchLabelExpressions"][0]
    require(topology["key"] == "topology.gke.io/zone" and topology["values"] == cluster["zones"], "storage topology")

    storage = candidate["storage"]
    require(storage["access_mode"] == "ReadWriteOncePod", "RWOP")
    require(storage["system_state_gib"] == 20, "system storage")
    require(storage["gateway_journal_gib_per_active_run"] == 1, "journal storage")
    require(storage["maximum_active_runs"] == 8, "active runs")
    require(storage["retention_seconds"] == 86400, "storage retention")
    require(storage["primary_writer_must_be_destroyed_before_restore"], "writer fence")
    require(storage["concurrent_source_and_restore_mount"] == "reject", "restore exclusion")
    require(not storage["multi_volume_atomicity_claimed"], "snapshot non-claim")
    journal = load(JOURNAL_PATH)
    workload = load(WORKLOAD_PATH)
    require(journal["claim"]["spec"]["accessModes"] == ["ReadWriteOncePod"], "journal template RWOP")
    require(journal["claim"]["spec"]["resources"]["requests"]["storage"] == "1Gi", "journal template size")
    workload_claim = workload["spec"]["volumeClaimTemplates"][0]["spec"]
    require(workload_claim["accessModes"] == ["ReadWriteOncePod"], "system template RWOP")
    require(workload_claim["resources"]["requests"]["storage"] == "20Gi", "system template size")

    keys = {entry["role"]: entry for entry in candidate["key_inventory"]}
    require(set(keys) == {"authorization-grant", "receipt-signing", "tombstone-digest"}, "key roles")
    require(len({entry["access_identity"] for entry in keys.values()}) == 3, "separate key identities")
    for entry in keys.values():
        require(entry["version_identity"] is None, "key version blocker")
        require(entry["allowed_action"] == "secretmanager.versions.access via roles/secretmanager.secretAccessor on one role-specific secret resource; application requests one pinned version", "narrow secret access")
        require("browser" in entry["denied_subjects"] and "target-workload" in entry["denied_subjects"], "key denials")
        require(entry["backup_continuity"].startswith("no secret payload backup"), "key backup rule")
    require(keys["receipt-signing"]["required_length_bytes"] == 32, "receipt seed length")
    require("accepted owner-private projected receipt-signing channel" in keys["receipt-signing"]["delivery"], "accepted signing channel")

    audit = candidate["audit_and_retention"]
    fixed = audit["provider_fixed_management"]
    require(fixed["bucket"] == "_Required" and fixed["retention_days"] == 400, "fixed provider retention")
    require(not fixed["configurable"] and fixed["actual_record_review_required"], "fixed record review")
    require(set(fixed["allowed_fields"]) == {"administrative_operation", "operator_or_service_identity", "provider_resource_identity", "time", "status"}, "management exception allowlist")
    require({"visitor_locator", "run_id", "operation_id", "request_or_patch_body", "secret_payload"}.issubset(fixed["forbidden_fields"]), "management exception denials")
    configurable = audit["configurable_records"]
    require(configurable["maximum_retention_seconds"] == 86400, "configurable retention ceiling")
    require(configurable["shortest_practical_logical_retention_seconds"] == 600, "Pub/Sub minimum retention")
    require(configurable["destination_kind"] == "pubsub", "sole configurable audit destination")
    require(configurable["topic"] == "kapsel-gate2-audit", "audit topic")
    require(configurable["subscription"] == "kapsel-gate2-audit-review", "audit subscription")
    require(configurable["subscription_message_retention_seconds"] == 600, "subscription retention")
    require(not configurable["retain_acknowledged_messages"], "no acknowledged replay")
    require(configurable["subscription_expiration"] == "never-during-authorized-experiment", "subscription continuity")
    require(configurable["exclude_duplicate_default_storage"], "default duplicate exclusion")
    require(configurable["additional_sinks"] == [], "no duplicate sinks")
    require(not configurable["physical_deletion_claimed"], "no physical deletion claim")
    require(configurable["no_kapsel_query_or_replay_after_seconds"] == 86400, "query/replay ceiling")
    require(configurable["source_documents"] == [
        "https://cloud.google.com/logging/docs/export/configure_export_v2#pubsub",
        "https://cloud.google.com/pubsub/docs/subscription-properties#message-retention-duration",
        "https://cloud.google.com/sdk/gcloud/reference/pubsub/subscriptions/create",
        "https://cloud.google.com/sdk/gcloud/reference/logging/sinks/create",
    ], "official audit-route sources")
    require(configurable["log_filter"] == "(log_id(\"cloudaudit.googleapis.com/data_access\") AND (protoPayload.serviceName=\"secretmanager.googleapis.com\" OR resource.type=\"k8s_cluster\")) OR log_id(\"cloudaudit.googleapis.com/policy\")", "audit filter")
    require(set(configurable["types"]) == {"Secret Manager Data Access", "Kubernetes Data Access", "Policy Denied proof"}, "bounded audit types")
    require(set(configurable["disabled_sources"]) == {"GKE system logs", "GKE workload logs", "GKE API server component logs", "GKE scheduler component logs", "GKE controller-manager component logs", "application diagnostics"}, "disabled configurable telemetry")
    require(configurable["dedicated_sink"] == "kapsel-gate2-audit", "audit sink")

    authorization = candidate["private_authorization_binding"]
    require(authorization["duration_seconds"] == 86400, "experiment duration")
    require(authorization["maximum_gross_spend_usd"] == 100, "spend ceiling")
    require(authorization["cleanup_window_inside_duration"], "cleanup window")
    require(authorization["dedicated_experiment_project_required"], "dedicated project")
    require(all(authorization[key] is None for key in ("account_binding_digest", "cleanup_owner_binding_digest", "reviewer_binding_digest", "approved_at", "expires_at", "default_sink_baseline_digest", "audit_topic_policy_baseline_digest", "audit_sink_writer_identity_digest")), "private approval blockers")

    inventory = candidate["inventory"]
    inventory_ids = [entry["id"] for entry in inventory]
    require(len(inventory_ids) == len(set(inventory_ids)) == 23, "complete unique inventory")
    require(all(entry["create_step"] > 0 and entry["delete_step"] > 0 for entry in inventory), "inventory order")
    require(all(len(entry["absence_argv"]) >= 3 for entry in inventory), "absence checks")
    require(all(entry["absence_argv"][0] in {"gcloud", "kubectl", "python3"} for entry in inventory), "bounded absence tools")
    require(all(entry["absence_postcondition"] for entry in inventory), "absence postconditions")
    required_inventory = {"budget", "audit-topic", "audit-subscription", "logging-sink", "audit-topic-writer-policy", "default-sink-exclusion", "audit-policy-delta", "vpc", "subnet-and-ranges", "artifact-repository", "authorization-grant-secret", "receipt-signing-secret", "tombstone-digest-secret", "service-accounts", "iam-bindings", "regional-cluster", "system-node", "three-sandbox-nodes", "kubernetes-policy-and-workloads", "system-state-regional-disk", "eight-journal-regional-disks", "snapshot-generation", "raw-evidence"}
    require(set(inventory_ids) == required_inventory, "inventory entries")
    inventory_by_id = {entry["id"]: entry for entry in inventory}
    require("--billing-account=${BILLING_ACCOUNT_ID}" in inventory_by_id["budget"]["absence_argv"], "budget absence account")
    require(inventory_by_id["default-sink-exclusion"]["absence_argv"][:4] == ["gcloud", "logging", "sinks", "describe"], "default exclusion absence")
    require(inventory_by_id["service-accounts"]["absence_argv"][:4] == ["gcloud", "iam", "service-accounts", "list"], "service account absence")
    require(inventory_by_id["iam-bindings"]["absence_argv"] == ["gcloud", "projects", "get-iam-policy", "${PROJECT_ID}", "--filter=bindings.members:kapsel-gate2-", "--project=${PROJECT_ID}"], "IAM binding absence")
    require(inventory_by_id["service-accounts"]["absence_argv"] == ["gcloud", "iam", "service-accounts", "list", "--filter=email:kapsel-gate2-", "--project=${PROJECT_ID}"], "service account absence filter")
    require(inventory_by_id["system-node"]["absence_argv"] == ["gcloud", "compute", "instances", "list", "--filter=(labels.goog-k8s-cluster-name=kapsel-gate2 AND name~default-pool)", "--project=${PROJECT_ID}"], "system node absence filter")
    require(inventory_by_id["three-sandbox-nodes"]["absence_argv"] == ["gcloud", "compute", "instances", "list", "--filter=(labels.goog-k8s-cluster-name=kapsel-gate2 AND name~sandbox)", "--project=${PROJECT_ID}"], "sandbox node absence filter")
    exact_disk_absence = ["gcloud", "compute", "disks", "list", "--filter=labels.goog-k8s-cluster-name=kapsel-gate2", "--project=${PROJECT_ID}"]
    require(inventory_by_id["system-state-regional-disk"]["absence_argv"] == exact_disk_absence, "system disk absence")
    require(inventory_by_id["eight-journal-regional-disks"]["absence_argv"] == exact_disk_absence, "journal disk absence")
    absence_prefixes = {
        "budget": ("gcloud", "billing", "budgets", "list"),
        "audit-topic": ("gcloud", "pubsub", "topics", "describe"),
        "audit-subscription": ("gcloud", "pubsub", "subscriptions", "describe"),
        "logging-sink": ("gcloud", "logging", "sinks", "describe"),
        "audit-topic-writer-policy": ("gcloud", "pubsub", "topics", "get-iam-policy"),
        "default-sink-exclusion": ("gcloud", "logging", "sinks", "describe"),
        "audit-policy-delta": ("gcloud", "projects", "get-iam-policy"),
        "vpc": ("gcloud", "compute", "networks", "list"),
        "subnet-and-ranges": ("gcloud", "compute", "networks", "subnets"),
        "artifact-repository": ("gcloud", "artifacts", "repositories", "list"),
        "authorization-grant-secret": ("gcloud", "secrets", "describe"),
        "receipt-signing-secret": ("gcloud", "secrets", "describe"),
        "tombstone-digest-secret": ("gcloud", "secrets", "describe"),
        "service-accounts": ("gcloud", "iam", "service-accounts", "list"),
        "iam-bindings": ("gcloud", "projects", "get-iam-policy"),
        "regional-cluster": ("gcloud", "container", "clusters", "list"),
        "system-node": ("gcloud", "compute", "instances", "list"),
        "three-sandbox-nodes": ("gcloud", "compute", "instances", "list"),
        "kubernetes-policy-and-workloads": ("kubectl", "get"),
        "system-state-regional-disk": ("gcloud", "compute", "disks", "list"),
        "eight-journal-regional-disks": ("gcloud", "compute", "disks", "list"),
        "snapshot-generation": ("gcloud", "compute", "snapshots", "describe"),
        "raw-evidence": ("python3", "scripts/test-sandbox-gate2-fixture.py", "--assert-private-evidence-deletion-receipt"),
    }
    require(all(tuple(inventory_by_id[item]["absence_argv"][:len(prefix)]) == prefix for item, prefix in absence_prefixes.items()), "exact absence command classes")

    commands = candidate["commands"]
    require(commands["tool_versions"]["gcloud"] == "577.0.0", "gcloud lock")
    provision = commands["provision_argv_preview"]
    teardown = commands["teardown_argv"]
    require(all(set(entry) == {"sequence", "inventory_ids", "rollback_inventory_sequences", "argv"} for entry in provision), "provision command schema")
    require(all(set(entry) == {"sequence", "inventory_ids", "argv"} for entry in teardown), "teardown command schema")
    require(all(set(entry["rollback_inventory_sequences"]) == set(entry["inventory_ids"]) for entry in provision), "partial rollback mapping")
    allowed_provision_prefixes = {
        ("gcloud", "billing", "budgets", "create"),
        ("gcloud", "pubsub", "topics", "create"),
        ("gcloud", "pubsub", "subscriptions", "create"),
        ("gcloud", "pubsub", "topics", "set-iam-policy"),
        ("gcloud", "logging", "sinks", "create"),
        ("gcloud", "logging", "sinks", "update"),
        ("gcloud", "projects", "set-iam-policy"),
        ("gcloud", "compute", "networks", "create"),
        ("gcloud", "compute", "networks", "subnets"),
        ("gcloud", "artifacts", "repositories", "create"),
        ("gcloud", "secrets", "create"),
        ("gcloud", "iam", "service-accounts", "create"),
        ("gcloud", "container", "clusters", "create"),
        ("gcloud", "container", "node-pools", "create"),
        ("kubectl", "create", "--filename=${OWNER_PRIVATE_RENDERED_GATE2_OBJECTS}"),
        ("kubectl", "create", "--filename=${OWNER_PRIVATE_RENDERED_JOURNAL_CLAIMS}"),
        ("kubectl", "create", "--filename=${OWNER_PRIVATE_RENDERED_SNAPSHOT_OBJECT}"),
        ("python3", "${OWNER_PRIVATE_EVIDENCE_CAPTURE_TOOL}", "--output=${OWNER_PRIVATE_EVIDENCE_DIRECTORY}"),
    }
    require(all(tuple(entry["argv"][:4]) in allowed_provision_prefixes or tuple(entry["argv"][:3]) in allowed_provision_prefixes for entry in provision), "known provision commands")
    allowed_teardown_prefixes = {
        ("kubectl", "delete", "namespace"),
        ("gcloud", "compute", "snapshots", "delete"),
        ("gcloud", "compute", "disks", "delete"),
        ("gcloud", "container", "clusters", "delete"),
        ("gcloud", "secrets", "delete"),
        ("gcloud", "artifacts", "repositories", "delete"),
        ("gcloud", "projects", "set-iam-policy"),
        ("gcloud", "iam", "service-accounts", "delete"),
        ("gcloud", "logging", "sinks", "update"),
        ("gcloud", "logging", "sinks", "delete"),
        ("gcloud", "pubsub", "subscriptions", "delete"),
        ("gcloud", "pubsub", "topics", "delete"),
        ("gcloud", "pubsub", "topics", "set-iam-policy"),
        ("gcloud", "compute", "networks", "subnets"),
        ("gcloud", "compute", "networks", "delete"),
        ("gcloud", "billing", "budgets", "delete"),
        ("python3", "scripts/test-sandbox-gate2-fixture.py", "--assert-private-evidence-deletion-receipt"),
    }
    require(all(tuple(entry["argv"][:4]) in allowed_teardown_prefixes or tuple(entry["argv"][:3]) in allowed_teardown_prefixes for entry in teardown), "known teardown commands")
    require(all(entry["sequence"] == inventory_by_id[item]["create_step"] for entry in provision for item in entry["inventory_ids"]), "provision inventory order")
    require(all(entry["rollback_inventory_sequences"][item] == inventory_by_id[item]["delete_step"] for entry in provision for item in entry["inventory_ids"]), "rollback inventory order")
    require(all(entry["sequence"] == inventory_by_id[item]["delete_step"] for entry in teardown for item in entry["inventory_ids"]), "teardown inventory order")
    flattened = "\n".join(" ".join(entry["argv"]) for entry in provision)
    require("--enable-dataplane-v2" in flattened and "--enable-private-nodes" in flattened, "cluster network flags")
    require("--enable-dns-access" in flattened and "--no-enable-ip-access" in flattened, "endpoint flags")
    require("--sandbox=type=gvisor" in flattened, "sandbox flag")
    require("--num-nodes=1" in flattened and "europe-north1-a,europe-north1-b,europe-north1-c" in flattened, "regional node arithmetic")
    require("--node-pool=system" not in flattened, "unsupported initial pool name flag")
    require("--logging=NONE" in flattened and "--monitoring=NONE" in flattened, "configurable telemetry disabled")
    topic_create = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "pubsub", "topics", "create"])
    subscription_create = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "pubsub", "subscriptions", "create"])
    sink_create = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "logging", "sinks", "create"])
    topic_policy = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "pubsub", "topics", "set-iam-policy"])
    require(topic_create == ["gcloud", "pubsub", "topics", "create", "kapsel-gate2-audit", "--project=${PROJECT_ID}"], "exact audit topic without acknowledged-message retention")
    require(subscription_create == ["gcloud", "pubsub", "subscriptions", "create", "kapsel-gate2-audit-review", "--topic=kapsel-gate2-audit", "--message-retention-duration=600s", "--expiration-period=never", "--no-retain-acked-messages", "--project=${PROJECT_ID}"], "exact audit subscription")
    require(sink_create == ["gcloud", "logging", "sinks", "create", "kapsel-gate2-audit", "pubsub.googleapis.com/projects/${PROJECT_ID}/topics/kapsel-gate2-audit", "--log-filter=${GATE2_CONFIGURABLE_AUDIT_LOG_FILTER}", "--unique-writer-identity", "--project=${PROJECT_ID}"], "exact sole audit sink")
    require(topic_policy == ["gcloud", "pubsub", "topics", "set-iam-policy", "kapsel-gate2-audit", "${OWNER_PRIVATE_ADD_GATE2_TOPIC_POLICY_FILE}", "--project=${PROJECT_ID}"], "exact sink-writer policy command")
    require(commands["audit_topic_policy_restore_rule"] == "before digest must equal the private authorization binding; the unique sink writer receives only roles/pubsub.publisher on the one topic; after removing that binding, the policy digest must equal the baseline", "sink writer publisher only")
    require(sum(entry["argv"][:4] == ["gcloud", "pubsub", "topics", "create"] for entry in provision) == 1, "one audit topic")
    require(sum(entry["argv"][:4] == ["gcloud", "pubsub", "subscriptions", "create"] for entry in provision) == 1, "one audit subscription")
    require(sum(entry["argv"][:4] == ["gcloud", "logging", "sinks", "create"] for entry in provision) == 1, "one audit sink")
    cluster_create = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "container", "clusters", "create"])
    sandbox_create = next(entry["argv"] for entry in provision if entry["argv"][:4] == ["gcloud", "container", "node-pools", "create"])
    expected_cluster_create = [
        "gcloud", "container", "clusters", "create", "kapsel-gate2", "--region=europe-north1",
        "--release-channel=regular", "--cluster-version=1.35.6-gke.1127000", "--network=kapsel-gate2",
        "--subnetwork=kapsel-gate2-europe-north1", "--cluster-secondary-range-name=kapsel-gate2-pods",
        "--services-secondary-range-name=kapsel-gate2-services", "--enable-private-nodes", "--enable-ip-alias",
        "--enable-dataplane-v2", "--enable-dns-access", "--no-enable-ip-access",
        "--workload-pool=${PROJECT_ID}.svc.id.goog", "--service-account=${NODE_GSA}",
        "--workload-metadata=GKE_METADATA", "--addons=GcePersistentDiskCsiDriver",
        "--machine-type=e2-standard-2", "--num-nodes=1", "--node-locations=europe-north1-a",
        "--image-type=COS_CONTAINERD", "--disk-size=100", "--labels=kapsel-gate2=true",
        "--logging=NONE", "--monitoring=NONE", "--project=${PROJECT_ID}",
    ]
    expected_sandbox_create = [
        "gcloud", "container", "node-pools", "create", "sandbox", "--cluster=kapsel-gate2",
        "--region=europe-north1", "--machine-type=n2-standard-4", "--num-nodes=1",
        "--node-locations=europe-north1-a,europe-north1-b,europe-north1-c", "--image-type=COS_CONTAINERD",
        "--disk-size=100", "--sandbox=type=gvisor", "--service-account=${NODE_GSA}",
        "--workload-metadata=GKE_METADATA", "--node-labels=kapsel.dev/sandbox=true", "--project=${PROJECT_ID}",
    ]
    require(cluster_create == expected_cluster_create, "exact cluster argv")
    require(sandbox_create == expected_sandbox_create, "exact sandbox pool argv")
    require("--node-taints" not in flattened, "locked runner has no custom-taint toleration")
    require("--service-account=${NODE_GSA}" in flattened and "--workload-metadata=GKE_METADATA" in flattened, "node identity flags")
    require(identities["node_project_roles"] == ["roles/container.defaultNodeServiceAccount"], "node project roles")
    require(identities["node_repository_roles"] == ["roles/artifactregistry.reader"], "node repository roles")
    require(identities["operator_project_roles"] == ["roles/container.clusterViewer"], "operator roles")
    require(identities["workload_secret_permissions"] == ["secretmanager.versions.access via roles/secretmanager.secretAccessor on one role-specific secret resource; application requests one pinned version"], "workload secret scope")
    require(set(identities["forbidden_iam_bindings"]) == {"roles/owner", "roles/editor", "project-level roles/secretmanager.secretAccessor", "project-level roles/artifactregistry.reader for workload identities", "user-managed service-account keys"}, "forbidden IAM")
    require(identities["allowed_binding_matrix"] == {
        "node-project": "kapsel-gate2-node@${PROJECT_ID}.iam.gserviceaccount.com -> roles/container.defaultNodeServiceAccount",
        "node-repository": "kapsel-gate2-node@${PROJECT_ID}.iam.gserviceaccount.com -> roles/artifactregistry.reader on kapsel-gate2 only",
        "operator-project": "private approved operator -> roles/container.clusterViewer plus separately reviewed Kubernetes RBAC",
        "grant-secret": "grant-signer KSA/GSA -> roles/secretmanager.secretAccessor on kapsel-gate2-authorization-grant only",
        "receipt-secret": "receipt-stager KSA/GSA -> roles/secretmanager.secretAccessor on kapsel-gate2-receipt-signing only",
        "tombstone-secret": "sandbox-api KSA/GSA -> roles/secretmanager.secretAccessor on kapsel-gate2-tombstone-digest only",
    }, "allowed IAM matrix")
    require(identities["ksa_to_gsa_bindings"]["cleanup-controller"] == "kapsel-gate2-cleanup-controller@${PROJECT_ID}.iam.gserviceaccount.com", "cleanup identity")
    require(all(word not in flattened for word in ("LoadBalancer", "NodePort", "ingress", "cloud-nat")), "no public surface commands")
    require("--dns-endpoint" in commands["operator_connection_argv"], "DNS operator route")
    covered_create = {item for entry in provision for item in entry["inventory_ids"]}
    covered_delete = {item for entry in teardown for item in entry["inventory_ids"]}
    require(covered_create == set(inventory_ids), "full provision coverage")
    require(covered_delete == set(inventory_ids), "full teardown coverage")
    require([entry["sequence"] for entry in teardown] == sorted(entry["sequence"] for entry in teardown), "teardown order")
    require(any(entry["argv"][:4] == ["gcloud", "container", "clusters", "delete"] for entry in teardown), "cluster teardown")
    require(any(entry["argv"][:4] == ["gcloud", "pubsub", "subscriptions", "delete"] for entry in teardown), "audit subscription teardown")
    require(any(entry["argv"][:4] == ["gcloud", "pubsub", "topics", "delete"] for entry in teardown), "audit topic teardown")
    require(any(entry["argv"][:4] == ["gcloud", "billing", "budgets", "delete"] for entry in teardown), "budget teardown")
    require(any("iam-bindings" in entry["inventory_ids"] for entry in teardown), "IAM teardown")
    require("every teardown entry" in commands["partial_failure_rule"], "partial failure rule")
    require("every inventory absence_argv" in commands["final_absence_rule"], "final absence rule")
    require("current policy etag" in commands["optimistic_policy_rule"] and "aborts on etag conflict" in commands["optimistic_policy_rule"], "optimistic IAM/audit restore")
    require(commands["pre_audit_route_delete_drain_argv"][:4] == ["gcloud", "pubsub", "subscriptions", "pull"], "audit drain")
    require("--auto-ack" in commands["pre_audit_route_delete_drain_argv"], "drained messages cannot replay")
    require("600 seconds" in commands["audit_route_expiry_rule"], "logical retention rule")
    require("neither resource" in commands["audit_route_expiry_rule"], "24-hour absence rule")
    require(commands["default_sink_baseline_before_argv"] == commands["default_sink_baseline_after_argv"], "default sink comparison")
    require("after digest must equal before digest" in commands["default_sink_restore_rule"], "default sink restore")
    all_argv = commands["read_only_preflight"] + [entry["argv"] for entry in provision] + [entry["argv"] for entry in teardown] + [entry["absence_argv"] for entry in inventory] + [commands[key] for key in ("operator_connection_argv", "pre_audit_route_delete_drain_argv", "default_sink_baseline_before_argv", "default_sink_baseline_after_argv")]
    require(all("--project=${PROJECT_ID}" in argv for argv in all_argv if argv[0] == "gcloud" and argv[1] != "billing"), "explicit project scope")
    require("approved private account-binding digest" in commands["project_scope_rule"], "project binding rule")
    disk_delete = next(entry["argv"] for entry in teardown if entry["argv"][:4] == ["gcloud", "compute", "disks", "delete"])
    expected_disks = ["${OWNER_PRIVATE_SYSTEM_DISK_NAME}"] + [f"${{OWNER_PRIVATE_JOURNAL_DISK_{index}}}" for index in range(1, 9)]
    require(disk_delete[4:13] == expected_disks, "exact regional disk argv")
    require("--region=europe-north1" in disk_delete, "regional disk deletion")
    placeholder_allowlist = set(commands["environment_placeholder_allowlist"])
    used_placeholders = {match for argv in all_argv for item in argv for match in re.findall(r"\$\{([A-Z0-9_]+)\}", item)}
    require(used_placeholders.issubset(placeholder_allowlist), "command placeholder allowlist")

    cost = candidate["cost"]
    require(cost["duration_hours"] == 24 and cost["maximum_gross_spend_usd"] == 100, "cost bounds")
    require(cost["screened_subtotal_usd"] == 21.13, "screened subtotal")
    require(cost["raw_quantities"]["n2_standard_4_nodes"] == 3 and cost["raw_quantities"]["e2_standard_2_nodes"] == 1, "cost node counts")
    require(cost["reject_if_repriced_gross_ceiling_exceeds_usd"] == 100, "reprice stop")
    require(cost["budget_alert_is_not_hard_stop"], "budget non-claim")
    require(set(entry["billing_class"] for entry in inventory) == set(cost["allowed_billing_classes"]), "inventory billing coverage")
    require({"load-balancer", "public-address", "cloud-nat", "internet-egress"}.issubset(cost["forbidden_unpriced_classes"]), "unpriced class denial")

    blockers = set(candidate["execution_blockers"])
    require({"reviewed_execution_revision_and_fixture_digest", "registry_digest", "private_account_binding", "cleanup_owner_binding", "absolute_approval_and_expiry", "kubernetes_token_audience", "provider_runner_subcommand", "scheduler_and_cleanup_controller_composition", "complete_rendered_service_role_manifests", "secret_version_identities", "audit_sink_writer_identity_and_topic_policy_binding", "actual_required_log_field_review", "effective_iam_and_kubernetes_rbac_review", "current_version_and_price_recheck", "node_service_account_binding", "workload_identity_bindings", "operator_iam_and_rbac_binding", "default_sink_baseline_and_restore_digest"} == blockers, "execution blockers")
    require(candidate["reproduction_lock"]["registry_digest"] is None, "registry digest blocker")
    require(candidate["reproduction_lock"]["fixture_source_digest"] is None, "fixture digest blocker")
    require("no_gate2_authorization" in candidate["non_claims"], "Gate 2 non-claim")

    serialized = json.dumps(candidate, sort_keys=True)
    require(not re.search(r"[0-9]{12}", serialized), "provider project number must not be committed")
    require("PRIVATE KEY" not in serialized and "BEGIN PRIVATE" not in serialized, "private material")
    require("@gmail.com" not in serialized and "@googlemail.com" not in serialized, "personal account")


def negative_cases(candidate: dict[str, Any], storage_class: dict[str, Any], system_workload: dict[str, Any]) -> None:
    cases: list[dict[str, Any]] = []
    public = copy.deepcopy(candidate)
    public["cluster"]["load_balancer"] = "external"
    cases.append(public)
    retention = copy.deepcopy(candidate)
    retention["audit_and_retention"]["configurable_records"]["subscription_message_retention_seconds"] = 86400
    cases.append(retention)
    duplicate_bucket = copy.deepcopy(candidate)
    duplicate_bucket["audit_and_retention"]["configurable_records"]["destination_kind"] = "logging-bucket"
    cases.append(duplicate_bucket)
    replay = copy.deepcopy(candidate)
    replay["audit_and_retention"]["configurable_records"]["retain_acknowledged_messages"] = True
    cases.append(replay)
    shared_writer = copy.deepcopy(candidate)
    sink = next(entry for entry in shared_writer["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "logging", "sinks", "create"])
    sink["argv"].remove("--unique-writer-identity")
    cases.append(shared_writer)
    extra_topic = copy.deepcopy(candidate)
    topic = next(entry for entry in extra_topic["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "pubsub", "topics", "create"])
    extra_topic["commands"]["provision_argv_preview"].append(copy.deepcopy(topic))
    cases.append(extra_topic)
    extra_subscription = copy.deepcopy(candidate)
    subscription = next(entry for entry in extra_subscription["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "pubsub", "subscriptions", "create"])
    extra_subscription["commands"]["provision_argv_preview"].append(copy.deepcopy(subscription))
    cases.append(extra_subscription)
    broad_writer = copy.deepcopy(candidate)
    broad_writer["commands"]["audit_topic_policy_restore_rule"] += "; roles/owner"
    cases.append(broad_writer)
    runner_mount = copy.deepcopy(candidate)
    runner_mount["service_role_composition"]["runner_system_state_mount"] = True
    cases.append(runner_mount)
    retention_listener = copy.deepcopy(candidate)
    retention_listener["service_role_composition"]["periodic_retention"]["transport_listener"] = True
    cases.append(retention_listener)
    broad_key = copy.deepcopy(candidate)
    broad_key["key_inventory"][1]["allowed_action"] = "roles/secretmanager.secretAccessor on project"
    cases.append(broad_key)
    runnable = copy.deepcopy(candidate)
    runnable["status"]["execution_authorized"] = True
    cases.append(runnable)
    node_drift = copy.deepcopy(candidate)
    node_drift["node_pools"][0]["node_locations"] = candidate["cluster"]["zones"]
    cases.append(node_drift)
    missing_teardown = copy.deepcopy(candidate)
    missing_teardown["commands"]["teardown_argv"] = missing_teardown["commands"]["teardown_argv"][:1]
    cases.append(missing_teardown)
    fake_absence = copy.deepcopy(candidate)
    fake_absence["inventory"][0]["absence_argv"] = ["true"]
    cases.append(fake_absence)
    missing_billing = copy.deepcopy(candidate)
    missing_billing["cost"]["allowed_billing_classes"] = []
    cases.append(missing_billing)
    invalid_command = copy.deepcopy(candidate)
    invalid_command["commands"]["provision_argv_preview"][0]["argv"] = ["gcloud", "invented", "command", "create"]
    cases.append(invalid_command)
    machine_drift = copy.deepcopy(candidate)
    cluster_command = next(entry for entry in machine_drift["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "container", "clusters", "create"])
    cluster_command["argv"] = [item.replace("--machine-type=e2-standard-2", "--machine-type=e2-standard-32") for item in cluster_command["argv"]]
    cases.append(machine_drift)
    identity_alias = copy.deepcopy(candidate)
    identity_alias["cluster"]["workload_identities"]["ksa_to_gsa_bindings"]["grant-signer"] = identity_alias["cluster"]["workload_identities"]["ksa_to_gsa_bindings"]["cleanup-controller"]
    cases.append(identity_alias)
    disk_filter_drift = copy.deepcopy(candidate)
    next(entry for entry in disk_filter_drift["inventory"] if entry["id"] == "system-state-regional-disk")["absence_argv"] = ["gcloud", "compute", "disks", "list", "--filter=name:unrelated", "--project=${PROJECT_ID}"]
    cases.append(disk_filter_drift)
    broad_key_action = copy.deepcopy(candidate)
    broad_key_action["key_inventory"][0]["allowed_action"] += " plus project accessor"
    cases.append(broad_key_action)
    service_absence_drift = copy.deepcopy(candidate)
    next(entry for entry in service_absence_drift["inventory"] if entry["id"] == "service-accounts")["absence_argv"][4] = "--filter=email:unrelated-"
    cases.append(service_absence_drift)
    system_node_absence_drift = copy.deepcopy(candidate)
    next(entry for entry in system_node_absence_drift["inventory"] if entry["id"] == "system-node")["absence_argv"][4] = "--filter=name:unrelated-system"
    cases.append(system_node_absence_drift)
    sandbox_node_absence_drift = copy.deepcopy(candidate)
    next(entry for entry in sandbox_node_absence_drift["inventory"] if entry["id"] == "three-sandbox-nodes")["absence_argv"][4] = "--filter=name:unrelated-sandbox"
    cases.append(sandbox_node_absence_drift)
    default_node_identity = copy.deepcopy(candidate)
    default_cluster_command = next(entry for entry in default_node_identity["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "container", "clusters", "create"])
    default_cluster_command["argv"] = [item for item in default_cluster_command["argv"] if not item.startswith("--service-account=")]
    cases.append(default_node_identity)
    autoscaling_drift = copy.deepcopy(candidate)
    autoscaling_pool = next(entry for entry in autoscaling_drift["commands"]["provision_argv_preview"] if entry["argv"][:4] == ["gcloud", "container", "node-pools", "create"])
    autoscaling_pool["argv"].extend(["--enable-autoscaling", "--max-nodes=100"])
    cases.append(autoscaling_drift)
    project_secret_access = copy.deepcopy(candidate)
    project_secret_access["cluster"]["workload_identities"]["workload_secret_permissions"] = ["project-level roles/secretmanager.secretAccessor"]
    cases.append(project_secret_access)
    widened_fixed = copy.deepcopy(candidate)
    widened_fixed["audit_and_retention"]["provider_fixed_management"]["allowed_fields"].append("run_id")
    cases.append(widened_fixed)
    for mutated in cases:
        try:
            validate(mutated, storage_class, system_workload)
        except InvalidFixture:
            continue
        raise InvalidFixture("negative fixture mutation was accepted")

    workload_cases: list[dict[str, Any]] = []
    authorized_workload = copy.deepcopy(system_workload)
    authorized_workload["status"]["execution_authorized"] = True
    workload_cases.append(authorized_workload)
    public_service = copy.deepcopy(system_workload)
    public_service["objects"][2]["spec"]["type"] = "LoadBalancer"
    workload_cases.append(public_service)
    ambient_token = copy.deepcopy(system_workload)
    ambient_token["objects"][3]["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
    workload_cases.append(ambient_token)
    extra_runner = copy.deepcopy(system_workload)
    extra_runner["objects"][3]["spec"]["template"]["spec"]["containers"].append({"name": "runner"})
    workload_cases.append(extra_runner)
    retention_transport = copy.deepcopy(system_workload)
    retention = retention_transport["objects"][3]["spec"]["template"]["spec"]["containers"][2]
    retention["args"].extend(["--listen", "0.0.0.0:9090"])
    workload_cases.append(retention_transport)
    writable_key = copy.deepcopy(system_workload)
    writable_key["objects"][3]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][1]["readOnly"] = False
    workload_cases.append(writable_key)
    resource_drift = copy.deepcopy(system_workload)
    resource_drift["objects"][3]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "999"
    workload_cases.append(resource_drift)
    command_wrapper = copy.deepcopy(system_workload)
    command_wrapper["objects"][3]["spec"]["template"]["spec"]["containers"][0]["command"] = ["sh", "-c"]
    workload_cases.append(command_wrapper)
    credential_environment = copy.deepcopy(system_workload)
    credential_environment["objects"][3]["spec"]["template"]["spec"]["containers"][0]["env"] = [{"name": "TOKEN", "value": "ambient"}]
    workload_cases.append(credential_environment)
    selector_drift = copy.deepcopy(system_workload)
    selector_drift["objects"][2]["spec"]["selector"] = {"app": "other"}
    workload_cases.append(selector_drift)
    host_pid = copy.deepcopy(system_workload)
    host_pid["objects"][3]["spec"]["template"]["spec"]["hostPID"] = True
    workload_cases.append(host_pid)
    privileged = copy.deepcopy(system_workload)
    privileged["objects"][3]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
    workload_cases.append(privileged)
    workload_identity = copy.deepcopy(system_workload)
    workload_identity["objects"][1]["metadata"]["annotations"] = {"iam.gke.io/gcp-service-account": "broad@example.invalid"}
    workload_cases.append(workload_identity)
    for mutated in workload_cases:
        try:
            validate(candidate, storage_class, mutated)
        except InvalidFixture:
            continue
        raise InvalidFixture("negative system-workload mutation was accepted")


def assert_private_evidence_deletion_receipt() -> None:
    raw = os.environ.get("KAPSEL_GATE2_PRIVATE_EVIDENCE_DELETION_RECEIPT")
    require(raw is not None, "private evidence deletion receipt path is required")
    path = Path(raw)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "safe deletion receipt")
    receipt = load(path)
    require(set(receipt) == {"schema", "evidence_binding_digest", "deleted_at", "absence_verified_at", "deletion_method"}, "deletion receipt schema")
    require(receipt["schema"] == "kapsel.sandbox.private-evidence-deletion/v1", "deletion receipt kind")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["evidence_binding_digest"]) is not None, "evidence binding digest")
    require(receipt["deleted_at"] <= receipt["absence_verified_at"], "deletion chronology")
    require(receipt["deletion_method"] in {"filesystem-secure-delete", "encrypted-key-destruction"}, "deletion method")


def main() -> None:
    if sys.argv[1:] == ["--assert-private-evidence-deletion-receipt"]:
        assert_private_evidence_deletion_receipt()
        print("sandbox Gate 2 private evidence deletion receipt: ok")
        return
    require(not sys.argv[1:], "unexpected arguments")
    candidate = load(FIXTURE_PATH)
    storage_class = load(STORAGE_PATH)
    system_workload = load(SYSTEM_WORKLOAD_PATH)
    validate(candidate, storage_class, system_workload)
    negative_cases(candidate, storage_class, system_workload)
    print("sandbox Gate 2 GKE authorization candidate: ok (offline, execution blocked)")


if __name__ == "__main__":
    main()
