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
        if username != f"system:serviceaccount:{namespace}:sandbox-runner":
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


def prove_admission_rule() -> None:
    rule = load("operator-admission-rule.json")
    fixture = load("admission-fixture.json")
    old = fixture["old_object"]
    preconditions = fixture["preconditions"]
    new = accepted_object(fixture)
    assert rule["deny_unknown_mutation"] is True
    assert set(rule["allowed_mutations"]) == {
        "selected_named_container.image",
        f"metadata.annotations[{OPERATION_ANNOTATION}]",
    }
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
    assert not accepted("system:serviceaccount:other:sandbox-runner", preconditions, old, new)


def prove_storage_and_lock() -> None:
    storage = load("storage-composition.json")
    lock = load("gate1-lock.json")
    workload = load("workload-template.json")
    assert storage["single_writer_fence"] == {
        "required": True,
        "primary_must_be_stopped": True,
        "volume_access_mode": "ReadWriteOncePod",
        "restore_requires_new_volume_identity": True,
        "concurrent_mount_is_failure": True,
    }
    assert set(storage["backup_set"]) == set(storage["durable_paths"])
    assert storage["retention_seconds"]["backup_maximum_age"] <= 86400
    assert len(lock["gate1_execution_revision"]) == 40
    assert lock["provider"] is None and lock["region"] is None
    assert lock["public_endpoint"] is None
    assert lock["local_image_build_command"] == (
        "docker build --pull=false -f deploy/sandbox/Containerfile "
        "-t kapsel-sandbox:gate1 ."
    )
    image_id = lock["gate1_local_image_id"]
    assert image_id.startswith("sha256:") and len(image_id) == 71
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
    claim = workload["spec"]["volumeClaimTemplates"][0]["spec"]
    assert claim["accessModes"] == [storage["single_writer_fence"]["volume_access_mode"]]
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
    prove_storage_and_lock()
    print("sandbox Gate 1 offline fixture: ok (exact patch rule, storage lock, non-claims)")


if __name__ == "__main__":
    main()
