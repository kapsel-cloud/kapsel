#!/usr/bin/env python3
"""Validate topology-neutral sandbox preservation and the Gate 0 deletion boundary."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "deploy" / "sandbox"
OWNER_LABEL = "kapsel.dev/cleanup-owner"
OPERATION_ANNOTATION = "kapsel.dev/kap0038-operation-id"
CANONICAL_DIGEST_ANNOTATION = "kapsel.dev/canonical-deployment-digest"
RUNNER_IDENTITY = (
    "system:serviceaccount:kapsel-sandbox-runners:kapsel-sandbox-runner"
)
OLD_COMMANDS = (
    "scheduler-state-serve",
    "cleanup-state-serve",
    "scheduler",
    "cleanup",
    "stage-controller-tls",
    "stage-tombstone-key",
    "stage-authorization-grant",
    "stage-receipt-signing",
)
DELETED_PATHS = (
    "crates/kapsel-sandbox/src/backup.rs",
    "crates/kapsel-sandbox/src/controller_state_transport.rs",
    "crates/kapsel-sandbox/src/scheduler_state.rs",
    "crates/kapsel-sandbox/src/cleanup_state.rs",
    "crates/kapsel-sandbox/src/key_staging.rs",
    "crates/kapsel-sandbox/src/kubernetes_scheduler.rs",
    "crates/kapsel-sandbox/src/kubernetes_cleanup.rs",
    "crates/kapsel-sandbox/tests/fixtures/controller-transport",
    "deploy/sandbox/storage-composition.json",
    "deploy/sandbox/journal-volume-template.json",
    "deploy/sandbox/journal-mount-admission-rule.json",
    "deploy/sandbox/runner-authority-composition.json",
    "deploy/sandbox/workload-template.json",
    "deploy/sandbox/gate1-lock.json",
    "deploy/sandbox/gate2-gke-fixture.json",
    "deploy/sandbox/gate2-gke-storage-class.json",
    "deploy/sandbox/gate2-system-workload.json",
    "deploy/sandbox/Containerfile",
    "deploy/sandbox/Containerfile.gate2-candidate",
    "deploy/sandbox/gate2-image-candidate.json",
    "scripts/test-sandbox-gate1.py",
    "scripts/test-sandbox-gate2-fixture.py",
    "scripts/test-sandbox-gate2-image-candidate.sh",
)


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def selected_container(deployment: dict, name: str) -> dict:
    selected = [
        container
        for container in deployment["spec"]["template"]["spec"]["containers"]
        if container.get("name") == name
    ]
    if len(selected) != 1:
        raise ValueError("selected container is not unique")
    return selected[0]


def canonical_deployment_digest(deployment: dict) -> str:
    canonical = copy.deepcopy(deployment)
    metadata = canonical["metadata"]
    for key in (
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "managedFields",
        "selfLink",
    ):
        metadata.pop(key, None)
    canonical.pop("status", None)
    metadata["annotations"].pop(CANONICAL_DIGEST_ANNOTATION, None)
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def accepted(username: str, preconditions: dict, old: dict, new: dict) -> bool:
    try:
        if username != RUNNER_IDENTITY:
            return False
        namespace = preconditions["namespace"]
        run_id = preconditions["run_id"]
        if (
            preconditions["owner"] != f"cleanup-{run_id}"
            or namespace != f"sandbox-{run_id}"
            or preconditions["operation_id"] != f"sandbox-{run_id}"
            or preconditions["policy_revision"] != "sandbox-policy-v3"
            or not is_sha256(preconditions["policy_inventory_digest"])
            or not is_sha256(preconditions["canonical_deployment_digest"])
        ):
            return False
        exact = {
            "name": preconditions["deployment"],
            "namespace": namespace,
            "uid": preconditions["deployment_uid"],
            "resourceVersion": preconditions["resource_version"],
        }
        old_metadata = old["metadata"]
        new_metadata = new["metadata"]
        if any(old_metadata.get(key) != value for key, value in exact.items()):
            return False
        if any(new_metadata.get(key) != value for key, value in exact.items()):
            return False
        expected_labels = {
            "kapsel.dev/cleanup-epoch": f"cleanup-{run_id}-1",
            OWNER_LABEL: preconditions["owner"],
            "kapsel.dev/policy-revision": preconditions["policy_revision"],
            "kapsel.dev/provisioning-generation": f"provision-{run_id}-1",
            "kapsel.dev/sandbox-owner": preconditions["owner"],
            "kapsel.dev/sandbox-run-id": run_id,
        }
        if any(old_metadata.get("labels", {}).get(key) != value for key, value in expected_labels.items()):
            return False
        if any(new_metadata.get("labels", {}).get(key) != value for key, value in expected_labels.items()):
            return False
        old_annotations = old_metadata.get("annotations", {})
        if (
            old_annotations.get("kapsel.dev/policy-inventory-digest")
            != preconditions["policy_inventory_digest"]
            or old_annotations.get("kapsel.dev/selected-image")
            != preconditions["immutable_image_digest"]
            or old_annotations.get(CANONICAL_DIGEST_ANNOTATION)
            != preconditions["canonical_deployment_digest"]
            or canonical_deployment_digest(old)
            != preconditions["canonical_deployment_digest"]
            or OPERATION_ANNOTATION in old_annotations
        ):
            return False
        old_container = selected_container(old, preconditions["container"])
        new_container = selected_container(new, preconditions["container"])
        if old_container.get("image") != preconditions["current_image"]:
            return False
        if new_container.get("image") != preconditions["immutable_image_digest"]:
            return False
        if new_metadata.get("annotations", {}).get(OPERATION_ANNOTATION) != preconditions[
            "operation_id"
        ]:
            return False
        normalized = copy.deepcopy(new)
        selected_container(normalized, preconditions["container"])["image"] = old_container[
            "image"
        ]
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


def prove_exact_patch() -> None:
    fixture = load("admission-fixture.json")
    rule = load("operator-admission-rule.json")
    assert set(rule) == {
        "api_version",
        "kind",
        "identity",
        "failure_policy",
        "validation_action",
        "runner_identity",
        "owner_label",
        "operation_annotation",
        "canonical_digest_annotation",
        "canonical_digest_domain",
        "required_preconditions",
        "allowed_mutations",
        "deny_unknown_mutation",
    }
    assert rule == {
        "api_version": "kapsel.sandbox.policy/v3",
        "kind": "ExactDeploymentImageRule",
        "identity": "conditional-operation-v1",
        "failure_policy": "Fail",
        "validation_action": "Deny",
        "runner_identity": RUNNER_IDENTITY,
        "owner_label": OWNER_LABEL,
        "operation_annotation": OPERATION_ANNOTATION,
        "canonical_digest_annotation": CANONICAL_DIGEST_ANNOTATION,
        "canonical_digest_domain": (
            "canonical-old-deployment-without-server-identity-status-or-"
            "canonical-digest-annotation"
        ),
        "required_preconditions": [
            "run_id",
            "namespace",
            "deployment",
            "deployment_uid",
            "resource_version",
            "owner",
            "container",
            "current_image",
            "immutable_image_digest",
            "operation_id",
            "policy_revision",
            "policy_inventory_digest",
            "canonical_deployment_digest",
        ],
        "allowed_mutations": [
            "selected_named_container.image",
            f"metadata.annotations[{OPERATION_ANNOTATION}]",
        ],
        "deny_unknown_mutation": True,
    }
    assert fixture["request_username"] == rule["runner_identity"]
    old = fixture["old_object"]
    accepted_update = accepted_object(fixture)
    assert accepted(fixture["request_username"], fixture["preconditions"], old, accepted_update)

    for mutation in (
        lambda value: value["metadata"].update({"uid": "wrong"}),
        lambda value: value["metadata"].update({"resourceVersion": "18"}),
        lambda value: value["metadata"]["labels"].update({OWNER_LABEL: "wrong"}),
        lambda value: value["spec"].update({"replicas": 2}),
        lambda value: selected_container(value, "target").update({"name": "other"}),
        lambda value: value["metadata"]["annotations"].update({"extra": "forbidden"}),
    ):
        denied = copy.deepcopy(accepted_update)
        mutation(denied)
        assert not accepted(fixture["request_username"], fixture["preconditions"], old, denied)
    assert not accepted("other", fixture["preconditions"], old, accepted_update)
    hostile_old = copy.deepcopy(old)
    hostile_old["spec"]["template"]["spec"]["hostNetwork"] = True
    assert not accepted(
        fixture["request_username"], fixture["preconditions"], hostile_old, accepted_update
    )
    wrong_digest = copy.deepcopy(fixture["preconditions"])
    wrong_digest["canonical_deployment_digest"] = "z" * 64
    assert not accepted(fixture["request_username"], wrong_digest, old, accepted_update)
    wrong_digest["canonical_deployment_digest"] = "0" * 64
    assert not accepted(fixture["request_username"], wrong_digest, old, accepted_update)


def prove_deletion_boundary() -> None:
    for relative in DELETED_PATHS:
        assert not (ROOT / relative).exists(), f"superseded path remains: {relative}"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "crates" / "kapsel-sandbox" / "src").glob("*.rs")
    )
    main_source = (ROOT / "crates/kapsel-sandbox/src/main.rs").read_text(encoding="utf-8")
    for command in OLD_COMMANDS:
        assert f'"{command}"' not in main_source, f"superseded CLI mode remains: {command}"
    for token in (
        "external_resource_slots",
        "TokenReview",
        "BackupPublication",
        "PublishedBackup",
        "BackupPublicationState",
        "StoppedBackupService",
        "BackupSourceDescriptors",
        "BackupStateGuard",
        "DeploymentSnapshot",
        "backup_generations",
        "backup_authority_references",
        ".kapsel-sandbox-restore.lock",
        ".backup.lock",
        "restore.ready",
        "restore.incomplete",
    ):
        assert token not in source, f"superseded compiled token remains: {token}"
    root_library = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
    assert "sandbox_gateway_schema_digest" not in root_library
    root_gateway = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src/gateway").rglob("*.rs")
    )
    assert "sandbox_schema_digest" not in root_gateway
    makefile = (ROOT / "Makefile.toml").read_text(encoding="utf-8")
    for task in (
        "test-sandbox-gate1",
        "build-sandbox-gate1-image",
        "test-sandbox-gate2-image-candidate",
        "test-sandbox-gate2-fixture",
        "test-sandbox-backup-restore",
    ):
        assert f"[tasks.{task}]" not in makefile, f"superseded task remains: {task}"

    for retained in (
        "crates/kapsel-sandbox/src/runner_handoff.rs",
        "crates/kapsel-sandbox/src/runner_process.rs",
        "scripts/test-sandbox-contract.py",
        "scripts/test-sandbox-package-boundary.py",
        "docs/fixtures/sandbox-v1/README.md",
    ):
        assert (ROOT / retained).exists(), f"retained boundary missing: {retained}"


def main() -> None:
    prove_exact_patch()
    prove_deletion_boundary()
    print("sandbox topology-neutral preservation: ok")


if __name__ == "__main__":
    main()
