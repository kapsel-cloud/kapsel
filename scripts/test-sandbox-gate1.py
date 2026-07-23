#!/usr/bin/env python3
"""Validate the provider-neutral KAP-0053 Gate 1 fixture without infrastructure."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "deploy" / "sandbox"
OWNER_LABEL = "kapsel.dev/sandbox-owner"
OPERATION_ANNOTATION = "kapsel.dev/kap0038-operation-id"


def load(name: str) -> dict:
    return json.loads((FIXTURE / name).read_text(encoding="utf-8"))


def selected_container(deployment: dict, name: str) -> dict:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    selected = [container for container in containers if container.get("name") == name]
    if len(selected) != 1:
        raise ValueError("selected container is not unique")
    return selected[0]


def accepted(username: str, preconditions: dict, old: dict, new: dict) -> bool:
    try:
        namespace = preconditions["namespace"]
        run_id = preconditions["run_id"]
        if preconditions["owner"] != run_id or namespace != f"sandbox-{run_id}":
            return False
        expected_runner = f"system:serviceaccount:kapsel-sandbox-runners:runner-{run_id}"
        if username != expected_runner:
            return False
        metadata = old["metadata"]
        new_metadata = new["metadata"]
        exact = {
            "name": preconditions["deployment"],
            "namespace": namespace,
            "uid": preconditions["deployment_uid"],
            "resourceVersion": preconditions["resource_version"],
        }
        if any(metadata.get(key) != value for key, value in exact.items()):
            return False
        if any(new_metadata.get(key) != value for key, value in exact.items()):
            return False
        if metadata.get("labels", {}).get(OWNER_LABEL) != preconditions["owner"]:
            return False
        if new_metadata.get("labels", {}).get(OWNER_LABEL) != preconditions["owner"]:
            return False
        old_container = selected_container(old, preconditions["container"])
        new_container = selected_container(new, preconditions["container"])
        if old_container.get("image") != preconditions["current_image"]:
            return False
        if new_container.get("image") != preconditions["immutable_image_digest"]:
            return False
        if (
            new_metadata.get("annotations", {}).get(OPERATION_ANNOTATION)
            != preconditions["operation_id"]
        ):
            return False

        normalized = copy.deepcopy(new)
        selected_container(normalized, preconditions["container"])["image"] = old_container[
            "image"
        ]
        old_annotations = metadata.get("annotations", {})
        normalized_annotations = normalized["metadata"].setdefault("annotations", {})
        if OPERATION_ANNOTATION in old_annotations:
            normalized_annotations[OPERATION_ANNOTATION] = old_annotations[OPERATION_ANNOTATION]
        else:
            normalized_annotations.pop(OPERATION_ANNOTATION, None)
            if not normalized_annotations:
                normalized["metadata"].pop("annotations", None)
        return normalized == old
    except (KeyError, TypeError, ValueError):
        return False


def accepted_object(fixture: dict) -> dict:
    output = copy.deepcopy(fixture["old_object"])
    preconditions = fixture["preconditions"]
    selected_container(output, preconditions["container"])["image"] = preconditions[
        "immutable_image_digest"
    ]
    output["metadata"].setdefault("annotations", {})[OPERATION_ANNOTATION] = preconditions[
        "operation_id"
    ]
    return output


def render_run_template(value: object, run_id: str) -> object:
    if isinstance(value, str):
        return value.replace("${RUN_ID}", run_id)
    if isinstance(value, list):
        return [render_run_template(item, run_id) for item in value]
    if isinstance(value, dict):
        return {key: render_run_template(item, run_id) for key, item in value.items()}
    return value


def accepted_journal_mount(
    username: str,
    rule: dict,
    canonical_template: dict,
    pod: dict,
) -> bool:
    try:
        run_id = pod["metadata"]["labels"][rule["required_run_label"]]
        expected = render_run_template(canonical_template, run_id)
        if username != rule["request_username"]:
            return False
        if pod["kind"] != rule["matched_kind"]:
            return False
        if pod["metadata"]["namespace"] != rule["matched_namespace"]:
            return False
        if pod != expected:
            return False
        spec = pod["spec"]
        container = spec["containers"][0]
        mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
        volumes = {volume["name"]: volume for volume in spec["volumes"]}
        writable = rule["writable_volume"]
        writable_mounts = {
            name for name, mount in mounts.items() if mount.get("readOnly", False) is False
        }
        if writable_mounts != {writable["name"]}:
            return False
        claim = volumes[writable["name"]]["persistentVolumeClaim"]
        if claim["claimName"] != writable["claim_name_template"].replace("${RUN_ID}", run_id):
            return False
        if claim.get("readOnly", False) is not False:
            return False
        return all(
            mounts[name]["readOnly"] is True and "persistentVolumeClaim" not in volumes[name]
            for name in rule["read_only_channels"]
        )
    except (KeyError, TypeError):
        return False


def prove_journal_mount_rule() -> None:
    fixture = load("journal-volume-template.json")
    rule = load("journal-mount-admission-rule.json")
    template = fixture["runner_pod_template"]
    run_id = "0123456789abcdef0123456789abcdef"
    pod = render_run_template(template, run_id)
    assert isinstance(pod, dict)
    username = fixture["authorized_mount"]["request_username"]
    assert accepted_journal_mount(username, rule, template, pod)

    denied: list[tuple[str, dict]] = []
    for name, mutate in [
        ("metadata", lambda value: value["metadata"].update({"annotations": {"x": "y"}})),
        ("pod name", lambda value: value["metadata"].update({"name": "runner-other"})),
        ("run label", lambda value: value["metadata"]["labels"].update({rule["required_run_label"]: "other"})),
        ("namespace", lambda value: value["metadata"].update({"namespace": f"sandbox-{run_id}"})),
        ("service account", lambda value: value["spec"].update({"serviceAccountName": "other"})),
        ("token", lambda value: value["spec"].update({"automountServiceAccountToken": True})),
        ("runtime class", lambda value: value["spec"].update({"runtimeClassName": "runc"})),
        ("command", lambda value: value["spec"]["containers"][0].update({"command": ["sh"]})),
        ("arguments", lambda value: value["spec"]["containers"][0].update({"args": ["serve"]})),
        ("environment", lambda value: value["spec"]["containers"][0]["env"].append({"name": "SECRET", "value": "x"})),
        ("environment from", lambda value: value["spec"]["containers"][0]["envFrom"].append({"secretRef": {"name": "other"}})),
        ("image", lambda value: value["spec"]["containers"][0].update({"image": "attacker@sha256:" + "a" * 64})),
        ("pod security", lambda value: value["spec"].update({"securityContext": {"runAsUser": 0}})),
        ("container security", lambda value: value["spec"]["containers"][0].update({"securityContext": {"privileged": True}})),
        ("extra mount", lambda value: value["spec"]["containers"][0]["volumeMounts"].append({"name": "other", "mountPath": "/other"})),
        ("writable authority", lambda value: value["spec"]["containers"][0]["volumeMounts"][1].update({"readOnly": False})),
        ("other claim", lambda value: value["spec"]["volumes"][0]["persistentVolumeClaim"].update({"claimName": "journal-other"})),
        ("secret projection", lambda value: value["spec"]["volumes"][2]["projected"]["sources"].append({"secret": {"name": "other"}})),
        ("extra volume", lambda value: value["spec"]["volumes"].append({"name": "other", "secret": {"secretName": "other"}})),
        ("second container", lambda value: value["spec"]["containers"].append(copy.deepcopy(value["spec"]["containers"][0]))),
    ]:
        candidate = copy.deepcopy(pod)
        mutate(candidate)
        denied.append((name, candidate))
    for name, candidate in denied:
        assert not accepted_journal_mount(username, rule, template, candidate), name
    assert not accepted_journal_mount(
        "system:serviceaccount:other:scheduler", rule, template, pod
    )


def prove_operator_composition() -> None:
    authority = load("runner-authority-composition.json")
    journal = load("journal-volume-template.json")
    patch_rule = load("operator-admission-rule.json")
    admission = load("admission-fixture.json")
    run_id = "0123456789abcdef0123456789abcdef"
    identity = authority["runner_identity"]
    expected_principal = identity["principal_template"]
    assert journal["authorized_mount"]["principal_template"] == expected_principal
    assert patch_rule["runner_username_template"].replace("{run_id}", "${RUN_ID}") == (
        expected_principal
    )
    assert admission["request_username"] == expected_principal.replace("${RUN_ID}", run_id)

    service_account = authority["runner_service_account_template"]
    assert service_account == {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": identity["service_account_name_template"],
            "namespace": identity["namespace"],
        },
        "automountServiceAccountToken": False,
    }
    role_binding = authority["target_role_binding_template"]
    assert role_binding["metadata"]["namespace"] == "sandbox-${RUN_ID}"
    assert role_binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": identity["service_account_name_template"],
            "namespace": identity["namespace"],
        }
    ]
    pod = journal["runner_pod_template"]
    assert pod["spec"]["serviceAccountName"] == identity["service_account_name_template"]
    container = pod["spec"]["containers"][0]
    assert container["command"] == ["/usr/local/bin/kapsel-sandbox"]
    assert container["env"] == [] and container["envFrom"] == []

    mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
    volumes = {volume["name"]: volume for volume in pod["spec"]["volumes"]}
    assert set(mounts) == set(volumes)
    assert {name for name, mount in mounts.items() if not mount["readOnly"]} == {
        "gateway-state"
    }
    for channel in [
        "operator-composition",
        "kubernetes-controller",
        "authorization-inputs",
        "receipt-signing",
        "receipt-handoff",
    ]:
        assert mounts[channel]["readOnly"] is True
        assert "persistentVolumeClaim" not in volumes[channel]

    operator = authority["operator_configuration"]
    assert set(operator) == {
        "journal_path",
        "receipt_output_directory",
        "authorization_trust",
        "signed_authorization_grant",
        "kubernetes_client",
        "receipt_signing_seed",
        "receipt_signing_key_id",
    }
    for name, source in operator.items():
        assert isinstance(source["owner"], str) and source["owner"]
        assert isinstance(source["channel"], str) and source["channel"] in mounts
        assert isinstance(source["path"], str) and source["path"].startswith("/")
        mount_path = mounts[source["channel"]]["mountPath"]
        assert source["path"] == mount_path or source["path"].startswith(f"{mount_path}/"), name

    handoff = authority["receipt_handoff"]
    assert isinstance(handoff["owner"], str) and handoff["owner"]
    assert handoff["channel"] == "receipt-handoff"
    assert handoff["path"] == mounts["receipt-handoff"]["mountPath"]
    assert handoff["source_directory"] == operator["receipt_output_directory"]["path"]
    assert operator["authorization_trust"]["owner"] != operator["signed_authorization_grant"]["owner"]
    assert operator["receipt_signing_seed"]["channel"] == "receipt-signing"
    assert operator["receipt_signing_seed"]["channel"] != operator["authorization_trust"]["channel"]

    controller_sources = volumes["kubernetes-controller"]["projected"]["sources"]
    tokens = [source["serviceAccountToken"] for source in controller_sources if "serviceAccountToken" in source]
    assert tokens == [
        {
            "audience": "${GATE2_KUBERNETES_AUDIENCE}",
            "expirationSeconds": 600,
            "path": "token",
        }
    ]
    assert authority["constraints"] == {
        "agent_request_owns_no_operator_input": True,
        "one_owner_and_one_path_per_operator_input": True,
        "one_writable_volume": "gateway-state",
        "all_authority_channels_read_only": True,
        "receipt_handoff_cannot_re_sign_or_replace": True,
    }


def prove_admission_rule() -> None:
    rule = load("operator-admission-rule.json")
    fixture = load("admission-fixture.json")
    old = fixture["old_object"]
    preconditions = fixture["preconditions"]
    new = accepted_object(fixture)
    assert rule["deny_unknown_mutation"] is True
    assert rule["runner_username_template"] == (
        "system:serviceaccount:kapsel-sandbox-runners:runner-{run_id}"
    )
    assert set(rule["allowed_mutations"]) == {
        "selected_named_container.image",
        f"metadata.annotations[{OPERATION_ANNOTATION}]",
    }
    assert set(rule["required_preconditions"]) == set(preconditions)
    assert accepted(fixture["request_username"], preconditions, old, new)

    denied: list[tuple[str, dict]] = []
    for name, mutate in [
        ("runtime class", lambda value: value["spec"]["template"]["spec"].update({"runtimeClassName": "runc"})),
        ("service account", lambda value: value["spec"]["template"]["spec"].update({"serviceAccountName": "attacker"})),
        ("owner", lambda value: value["metadata"]["labels"].update({OWNER_LABEL: "other"})),
        ("uid", lambda value: value["metadata"].update({"uid": "replacement"})),
        ("resource version", lambda value: value["metadata"].update({"resourceVersion": "18"})),
        ("replicas", lambda value: value["spec"].update({"replicas": 2})),
        ("sidecar image", lambda value: value["spec"]["template"]["spec"]["containers"][1].update({"image": "attacker@sha256:" + "c" * 64})),
        ("volume", lambda value: value["spec"]["template"]["spec"].update({"volumes": [{"name": "host", "hostPath": {"path": "/"}}]})),
        ("label", lambda value: value["spec"]["template"]["metadata"]["labels"].update({"attacker": "true"})),
        ("security context", lambda value: value["spec"]["template"]["spec"]["containers"][0].update({"securityContext": {"privileged": True}})),
        ("extra annotation", lambda value: value["metadata"]["annotations"].update({"attacker": "true"})),
        ("wrong operation", lambda value: value["metadata"]["annotations"].update({OPERATION_ANNOTATION: "other-operation"})),
        ("wrong image", lambda value: selected_container(value, preconditions["container"]).update({"image": "attacker@sha256:" + "d" * 64})),
    ]:
        candidate = copy.deepcopy(new)
        mutate(candidate)
        denied.append((name, candidate))
    for name, candidate in denied:
        assert not accepted(fixture["request_username"], preconditions, old, candidate), name
    wrong_run = copy.deepcopy(preconditions)
    wrong_run["run_id"] = "ffffffffffffffffffffffffffffffff"
    assert not accepted(fixture["request_username"], wrong_run, old, new)
    assert not accepted("system:serviceaccount:other:sandbox-runner", preconditions, old, new)


def prove_storage_and_lock() -> None:
    storage = load("storage-composition.json")
    lock = load("gate1-lock.json")
    workload = load("workload-template.json")
    journal = load("journal-volume-template.json")
    journal_rule = load("journal-mount-admission-rule.json")
    assert storage["system_state"]["durable_paths"] == {
        "admission_database": "/var/lib/kapsel-sandbox/admission/sandbox.sqlite3",
        "receipt_directory": "/var/lib/kapsel-sandbox/receipts",
        "ownership_metadata": "/var/lib/kapsel-sandbox/ownership",
    }
    assert storage["system_state"]["volume_access_mode"] == "ReadWriteOncePod"
    per_run = storage["per_run_gateway_journal"]
    assert per_run["one_volume_per_run"] is True
    assert per_run["outside_target_namespace"] is True
    assert per_run["volume_access_mode"] == "ReadWriteOncePod"
    assert per_run["mount_path"] == "/var/lib/kapsel-runner/state"
    assert per_run["api_access"] is False
    assert per_run["other_runner_access"] is False
    assert set(storage["backup_set"]) == {"system_state", "active_run_gateway_journals"}
    assert storage["backup_protocol"] == [
        "activate_global_stop_using_admission_database_only",
        "pause_new_dispatch_and_cleanup_without_advancing_any_run_lifecycle",
        "record_one_backup_generation_and_each_exact_lifecycle_seam_in_system_state",
        "freeze_active_run_journal_receipt_reference_ownership_and_capacity_inventory",
        "quiesce_api_scheduler_cleanup_and_each_exact_runner_without_execute_reconcile_or_lifecycle_advance",
        "checkpoint_and_fsync_each_store_while_still_mounted_only_by_its_quiesced_exact_writer",
        "prove_every_writer_acknowledged_quiescence_then_stop_all_write_capable_processes",
        "prove_every_source_volume_detached_after_checkpoint_and_fsync",
        "snapshot_system_state_volume_and_each_inventoried_active_run_journal_volume",
        "record_snapshot_ids_source_volume_identities_content_digests_and_captured_lifecycle_seams",
        "reject_incomplete_mixed_generation_or_seam_drifted_backup_sets",
        "expire_each_snapshot_no_later_than_its_source_data",
        "restart_only_after_the_complete_generation_is_recorded_or_keep_global_stop_for_operator_review",
    ]
    assert storage["fixed_backup_seams"] == [
        "durable_admission_before_dispatch",
        "after_dispatch_before_apply_started",
        "after_apply_started_including_ambiguous_provider_window",
        "receiver_terminal_before_immutable_receipt_publication",
        "before_and_after_receipt_reference_publication",
        "during_uid_safe_cleanup",
    ]
    assert storage["restore_protocol"] == [
        "activate_global_stop_using_admission_database_only",
        "select_one_complete_backup_generation_manifest",
        "prove_original_writers_absent_and_original_volumes_detached",
        "restore_system_state_and_each_active_run_journal_to_distinct_new_volume_identities",
        "bind_system_state_to_only_the_system_identity",
        "bind_each_journal_to_only_its_recorded_exact_runner_identity",
        "reapply_retention_before_readiness",
        "recover_each_same_run_operation_journal_and_capacity_identity",
        "verify_receipt_bytes_and_uid_owner_metadata",
        "prove_no_second_mount_or_runnable_journal_clone",
        "keep_global_stop_until_operator_review",
    ]
    terminal_paths = storage["gateway_journal_terminal_paths"]
    assert terminal_paths["receiver_result"] == {
        "delete_within_seconds_after_all": 3600,
        "required_facts": [
            "kapsel_finalized",
            "public_report_projection_durable",
            "frozen_receipt_bytes_verified_in_receipt_storage",
        ],
    }
    assert terminal_paths["not_attempted"] == {
        "delete_within_seconds_after_all": 3600,
        "required_facts": [
            "terminal_rejection_projection_durable",
            "cleanup_ownership_handed_off",
        ],
        "receipt_required": False,
    }
    assert terminal_paths["pre_application_service_failed"] == {
        "delete_empty_allocated_volume_within_seconds_after_all": 3600,
        "required_facts": [
            "application_invocation_proven_absent",
            "terminal_service_failed_projection_durable",
            "cleanup_ownership_handed_off",
        ],
        "gateway_journal_required": False,
    }
    assert terminal_paths["unresolved_recovery"] == {
        "may_outlive_public_expiry": True,
        "delete_before_terminal_path_forbidden": True,
        "cleanup_completion_does_not_extend_retention": True,
    }
    assert "snapshot_consistency_is_unproved" in storage["unproved_until_gate_2_or_3"]
    assert storage["retention_seconds"]["backup_maximum_age"] <= 86400
    assert journal["one_claim_per_run"] is True
    assert journal["claim"]["spec"]["accessModes"] == ["ReadWriteOncePod"]
    assert journal["authorized_mount"]["principal_template"] == per_run["writer_identity_template"]
    assert journal["authorized_mount"]["request_username"] == journal_rule["request_username"]
    assert journal_rule["comparison"] == "complete_rendered_object_equality"
    assert journal_rule["undeclared_fields"] == "deny"
    assert journal["runner_pod_template"]["spec"]["serviceAccountName"] == "runner-${RUN_ID}"
    assert journal["authorized_mount"]["namespace"] != journal["target_namespace_template"]
    assert lock["gate1_execution_revision"] == "bd67be9b469672b895a6214322b4dc7ff942da33"
    assert lock["gate1_local_image_id"] == (
        "sha256:4d85515113eccf5cb56618fd5b406632111ac429a25352e385942c40733d3480"
    )
    assert lock["local_image_platform"] == "linux/arm64"
    assert lock["correction_status"] == "evidence_recorded_pending_independent_review"
    assert lock["independently_reviewed_evidence_revision"] is None
    superseded = lock["superseded_gate1_evidence"]
    assert len(superseded) == 2
    assert all(len(item["execution_revision"]) == 40 for item in superseded)
    assert all(item["local_image_id"].startswith("sha256:") for item in superseded)
    assert [item["reason"] for item in superseded] == [
        "shared_gateway_journal_topology_violated_deployment_contract",
        "runner_operator_configuration_topology_incomplete",
    ]
    assert lock["provider"] is None and lock["region"] is None
    assert lock["public_endpoint"] is None
    assert lock["local_image_build_command"] == (
        "docker build --pull=false -f deploy/sandbox/Containerfile "
        "-t kapsel-sandbox:gate1 ."
    )
    assert lock["gate1_non_claims"] == [
        "no_provider_selected",
        "no_provider_credentials_or_resources",
        "no_managed_key_custody",
        "no_live_isolation_or_policy_enforcement",
        "no_backup_or_restore_enforcement",
        "no_endpoint_or_public_traffic",
        "no_bounded_cost",
    ]
    assert lock["fixed_limits"] == {
        "queued_runs": 32,
        "active_runs": 8,
        "execution_deadline_seconds": 180,
        "public_retention_seconds": 86400,
        "tombstone_retention_seconds": 86400,
    }
    assert workload["kind"] == "StatefulSet"
    pod = workload["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsUser"] == 65532
    assert pod["securityContext"]["runAsGroup"] == 65532
    assert pod["securityContext"]["fsGroup"] == 65532
    assert pod["volumes"][0]["secret"]["defaultMode"] == 0o440
    init = pod["initContainers"]
    containers = pod["containers"]
    assert len(init) == 1 and init[0]["args"][0] == "init"
    assert len(containers) == 1 and containers[0]["args"][0] == "serve"
    assert init[0]["image"] == "${KAPSEL_SANDBOX_IMAGE_DIGEST}"
    assert containers[0]["image"] == "${KAPSEL_SANDBOX_IMAGE_DIGEST}"
    mounts = init[0]["volumeMounts"] + containers[0]["volumeMounts"]
    assert all(mount["name"] != "gateway-journal" for mount in mounts)
    assert all("journals" not in mount["mountPath"] for mount in mounts)
    claim_template = workload["spec"]["volumeClaimTemplates"][0]
    assert claim_template["metadata"]["name"] == storage["system_state"]["volume_name"]
    claim = claim_template["spec"]
    assert claim["accessModes"] == [storage["system_state"]["volume_access_mode"]]
    assert claim["storageClassName"] == "${GATE2_STORAGE_CLASS}"
    assert not list(FIXTURE.glob("*service*.json"))
    assert not list(FIXTURE.glob("*ingress*.json"))

    containerfile = (FIXTURE / "Containerfile").read_text(encoding="utf-8").splitlines()
    from_lines = [line for line in containerfile if line.startswith("FROM ")]
    assert len(from_lines) == 2
    assert all("rust@sha256:" in line and len(line.split("sha256:", 1)[1].split()[0]) == 64 for line in from_lines)
    assert "USER 65532:65532" in containerfile
    assert 'ENTRYPOINT ["/usr/local/bin/kapsel-sandbox"]' in containerfile

    digest = hashlib.sha256()
    for name in [
        "Containerfile",
        "admission-fixture.json",
        "operator-admission-rule.json",
        "storage-composition.json",
        "journal-volume-template.json",
        "journal-mount-admission-rule.json",
        "runner-authority-composition.json",
        "workload-template.json",
    ]:
        body = (FIXTURE / name).read_bytes()
        digest.update(len(name).to_bytes(2, "big"))
        digest.update(name.encode("ascii"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    assert digest.hexdigest() == lock["fixture_bundle_sha256"]


def main() -> None:
    prove_admission_rule()
    prove_journal_mount_rule()
    prove_operator_composition()
    prove_storage_and_lock()
    print("sandbox Gate 1 offline fixture: ok (exact patch rule, storage lock, non-claims)")


if __name__ == "__main__":
    main()
