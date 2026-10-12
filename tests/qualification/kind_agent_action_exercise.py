"""Operator and deterministic caller fixture for the packaged Kubernetes journey."""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from typing import TypedDict

EXPECTED = {
    "healthy": "SUCCEEDED",
    "stale": "NOT_ATTEMPTED",
    "recreated": "NOT_ATTEMPTED",
    "race": "UNKNOWN",
    "failed": "FAILED",
    "deleted": "UNKNOWN",
    "service-loss": "SUCCEEDED",
    "caller-loss": "UNKNOWN",
    "independent": "SUCCEEDED",
}


class CallerIdentity(TypedDict):
    user: int
    group: int
    extra_groups: list[int]


def finalized_evidence(journal: pathlib.Path, operation_id: str) -> tuple[bytes, bytes, str]:
    """Read bounded original evidence independently of the service's receipt projection."""
    assert journal.is_file() and not journal.is_symlink()
    assert journal.stat().st_size <= 64 * 1024 * 1024
    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        row = connection.execute(
            """
            SELECT signed_authorization_grant, receipt_bytes, receipt_key_id
            FROM kubernetes_image_operations
            WHERE operation_id = ? AND state = 'finalized'
              AND length(signed_authorization_grant) BETWEEN 1 AND 4096
              AND length(receipt_bytes) BETWEEN 1 AND 16384
              AND length(receipt_key_id) BETWEEN 1 AND 128
            """,
            (operation_id,),
        ).fetchone()
    assert row is not None, "missing bounded finalized evidence"
    grant, receipt_bytes, signer = row
    assert isinstance(grant, bytes) and isinstance(receipt_bytes, bytes)
    assert isinstance(signer, str) and len(signer.encode()) <= 128
    return grant, receipt_bytes, signer


def retained_row(journal: pathlib.Path, operation_id: str) -> tuple[object, ...]:
    """Independently snapshot every column of one bounded format-6 fixture row."""
    assert journal.is_file() and not journal.is_symlink()
    assert journal.stat().st_size <= 64 * 1024 * 1024
    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        row = connection.execute(
            "SELECT * FROM kubernetes_image_operations WHERE operation_id = ?", (operation_id,)
        ).fetchone()
    assert row is not None
    return row


def install_binaries(artifact: pathlib.Path) -> None:
    """Replace fixture executables without changing authority or history. Stop the service first."""
    for source, destination in (
        ("bin/kapsel", "/usr/bin/kapsel"),
        ("bin/kapsel-service-client", "/usr/bin/kapsel-service-client"),
        ("bin/kapsel-service-mcp", "/usr/bin/kapsel-service-mcp"),
        ("libexec/kapsel/kapseld", "/usr/libexec/kapsel/kapseld"),
    ):
        pathlib.Path(destination).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact / source, destination)
        pathlib.Path(destination).chmod(0o755)


def main() -> None:
    def fixture_api(path, method="GET", document=None, content_type="application/json"):
        request = urllib.request.Request(
            cluster["server"] + path,
            data=None if document is None else json.dumps(document).encode(),
            method=method,
            headers={
                "Authorization": "Bearer " + fixture_token,
                "User-Agent": "kapsel-journey-fixture",
                "Content-Type": content_type,
            },
        )
        try:
            response = urllib.request.urlopen(request, context=context, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(262145)
            assert len(body) <= 262144
            return response.code, body

    def receiver(name, patch=None):
        status, body = fixture_api(
            "/apis/apps/v1/namespaces/demo/deployments/" + name,
            "GET" if patch is None else "PATCH",
            patch,
            "application/merge-patch+json",
        )
        assert status == 200, status
        return json.loads(body)

    def replica_sets():
        status, body = fixture_api(
            "/apis/apps/v1/namespaces/demo/replicasets?labelSelector=app%3Dhealthy"
        )
        assert status == 200
        return len(json.loads(body)["items"])

    def admission_events(expected_count):
        status, body = fixture_api(
            "/api/v1/namespaces/demo/pods?labelSelector=app%3Dreceiver-admission"
        )
        assert status == 200
        pods = json.loads(body)["items"]
        assert len(pods) == 1
        status, body = fixture_api(
            "/api/v1/namespaces/demo/pods/" + pods[0]["metadata"]["name"] + "/log"
        )
        assert status == 200
        events = [
            line
            for line in body.decode().splitlines()
            if line.startswith("KAPSEL_ADMISSION_EFFECT ") and line.endswith("operation_id=healthy")
        ]
        deadline = time.monotonic() + 10
        while len(events) < expected_count:
            assert time.monotonic() < deadline, "admission log visibility deadline"
            time.sleep(0.1)
            status, body = fixture_api(
                "/api/v1/namespaces/demo/pods/" + pods[0]["metadata"]["name"] + "/log"
            )
            assert status == 200
            events = [
                line
                for line in body.decode().splitlines()
                if line.startswith("KAPSEL_ADMISSION_EFFECT ")
                and line.endswith("operation_id=healthy")
            ]
        assert len(events) == expected_count
        return events

    def command(arguments, **kwargs):
        result = subprocess.run(arguments, capture_output=True, timeout=30, **kwargs)
        assert result.returncode == 0, (arguments[0], result.returncode)
        return result.stdout

    def publish(value):
        result = command(
            [service, "--replace-operator-config"],
            input=value,
            user=61000,
            group=61000,
            extra_groups=[],
        )
        assert result == b"PUBLISHED\n"

    def read(*arguments):
        result = json.loads(command([client, *arguments], **identity))
        assert result["version"] == 1
        return result

    def wait(case, predicate, seconds=200):
        deadline = time.monotonic() + seconds
        result = None
        while time.monotonic() < deadline:
            assert process is not None and process.poll() is None, "service exited"
            result = read("status", case)
            if predicate(result):
                return result
            assert result.get("execution", {}).get("disposition") != "operator_required", (
                case,
                result.get("execution"),
            )
            assert not pathlib.Path("/evidence/barrier.violation").exists(), (
                "receiver barrier failed"
            )
            time.sleep(0.1)
        raise AssertionError(("status deadline", case, result))

    def start():
        nonlocal process
        process = subprocess.Popen(
            [
                service,
                "--operator-config",
                "/etc/kapsel/operator.json",
                "--socket",
                "/run/kapsel/kapseld.sock",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            user=61000,
            group=61000,
            extra_groups=[],
            umask=0o077,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, "service startup failed"
            result = subprocess.run(
                [client, "history"], capture_output=True, timeout=10, **identity
            )
            if result.returncode == 0:
                return
            time.sleep(0.05)
        raise AssertionError("history unavailable")

    def stop(crash=False):
        assert process is not None, "service retirement requires a started service"
        if crash:
            process.kill()
        else:
            process.terminate()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode == (-9 if crash else 0)
        assert len(diagnostics) <= 4096
        for secret in (
            token.encode(),
            pathlib.Path("approval.seed").read_bytes().hex().encode(),
            pathlib.Path("receipt.seed").read_bytes().hex().encode(),
        ):
            assert secret not in diagnostics

    def receipt(case, suffix):
        path = pathlib.Path("/tmp/" + case + "-" + suffix + ".receipt")
        assert read("receipt", case, str(path))["status"] == "READY"
        report = json.loads(
            command(
                [
                    "/usr/bin/kapsel",
                    "inspect",
                    "--receipt",
                    str(path),
                    "--trust",
                    "receipt.trust",
                    "--evaluation-time-unix-s",
                    pathlib.Path("evaluation-time.txt").read_text().strip(),
                ]
            )
        )
        assert report["status"] == "INSPECTED"
        assert report["operation_id"] == case, report
        assert report["result"] == EXPECTED[case], report
        original = targets[case]
        assert report["target_uid"] == original["uid"]
        assert report["target_resource_version"] == original["resourceVersion"]
        if case == "deleted":
            assert report["receiver_uid"] is None and report["observed_image"] is None
            assert report["observed_operation_marker"] is None
        elif case == "failed":
            actual = receiver("agent-" + case)
            assert (
                report["observed_image"]
                == actual["spec"]["template"]["spec"]["containers"][0]["image"]
            )
            assert report["observed_operation_marker"] == case
            assert report["rollout_condition_reason"] == "ProgressDeadlineExceeded"
            assert any(
                c.get("reason") == "ProgressDeadlineExceeded"
                for c in actual["status"]["conditions"]
            )
        return path.read_bytes()

    os.umask(0o077)
    pathlib.Path("/evidence").mkdir(mode=0o700)
    settings = json.loads(pathlib.Path("/inputs/settings.json").read_text())
    workspace = pathlib.Path("/operator")
    workspace.mkdir(mode=0o700)
    os.chdir(workspace)

    guide = pathlib.Path("/artifact/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md").read_text()
    match = re.findall(r"<!-- example-keys -->\s*```sh\n(.*?)\n```", guide, re.S)
    assert len(match) == 1, "artifact lacks the public key-generation example"
    subprocess.run(["sh", "-eu", "-c", match[0]], check=True, timeout=30)
    for directory in ("/usr/libexec", "/usr/libexec/kapsel"):
        pathlib.Path(directory).mkdir(mode=0o755, exist_ok=True)
        pathlib.Path(directory).chmod(0o755)
    retained_artifact = pathlib.Path("/retained-artifact")
    install_binaries(retained_artifact if retained_artifact.is_dir() else pathlib.Path("/artifact"))
    for path, mode in (("/etc/kapsel", 0o700), ("/var/lib/kapsel", 0o700), ("/run/kapsel", 0o750)):
        pathlib.Path(path).mkdir(mode=mode)
        pathlib.Path(path).chmod(mode)
        os.chown(path, 61000, 61000)

    config = json.loads(pathlib.Path("/inputs/kubeconfig.json").read_text())
    cluster = config["clusters"][0]["cluster"]
    context = ssl.create_default_context(
        cadata=base64.b64decode(cluster["certificate-authority-data"]).decode()
    )
    token = config["users"][0]["user"]["token"]
    fixture_token = pathlib.Path("/inputs/fixture-token").read_text()

    # The fixture operator explicitly owns these disposable Deployments. No GitOps reconciler is
    # disabled. Each approval is independently assessed. Conflicting intent is not provisioned.
    prepare = [
        "/usr/bin/kapsel",
        "prepare-service-config",
        "--authorization-key",
        "approval-key-1",
        "approval.pub",
    ]
    healthy_replica_sets = replica_sets()
    targets = {}
    original_sidecars = {}
    for case in settings["cases"]:
        deployment = receiver("agent-" + case)
        targets[case] = deployment["metadata"]
        original_sidecars[case] = next(
            c
            for c in deployment["spec"]["template"]["spec"]["containers"]
            if c["name"] == "untouched"
        )["image"]
        intent = {
            "authorization_id": "approval-" + case,
            "operation_id": case,
            "namespace": "demo",
            "deployment": "agent-" + case,
            "container": "api",
            "immutable_image_digest": settings["failed_image"]
            if case == "failed"
            else settings["desired"],
        }
        pathlib.Path(case + ".json").write_text(json.dumps(intent))
        command(
            [
                "/usr/bin/kapsel",
                "provision-snapshot-grant",
                "--authorization",
                case + ".json",
                "--kubeconfig",
                "/inputs/kubeconfig.json",
                "--signing-seed",
                "approval.seed",
                "--signing-key-id",
                "approval-key-1",
                "--output",
                case + ".grant",
            ]
        )
        prepare += ["--approval", "Approved " + case, case + ".grant"]
    prepare += ["--receipt-signing-key-id", "receipt-key-1", "--output", "candidate.json"]
    command(prepare)
    document = pathlib.Path("candidate.json").read_bytes()

    service = "/usr/libexec/kapsel/kapseld"
    client = "/usr/bin/kapsel-service-client"
    identity: CallerIdentity = {"user": 61001, "group": 61000, "extra_groups": []}
    process: subprocess.Popen[bytes] | None = None
    barrier: subprocess.Popen[bytes] | None = None
    reports = []
    original_receipts: dict[str, bytes] = {}
    original_rows: dict[str, tuple[object, ...]] = {}
    journal = pathlib.Path("/var/lib/kapsel/journal.sqlite3")

    try:
        barrier = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "/inputs/kind_receiver_barrier.py",
                "/inputs",
                "/evidence",
                "/operator",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ready = pathlib.Path("/operator/barrier.ready")
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert barrier.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        service_config = json.loads(json.dumps(config))
        service_config["clusters"][0]["cluster"] = {
            "server": "http://127.0.0.1:" + ready.read_text()
        }
        pathlib.Path("service-kubeconfig.json").write_text(json.dumps(service_config))
        for source, target in (
            ("service-kubeconfig.json", "/etc/kapsel/kubeconfig.yaml"),
            ("receipt.seed", "/etc/kapsel/receipt.seed"),
        ):
            shutil.copyfile(source, target)
            os.chmod(target, 0o600)
            os.chown(target, 61000, 61000)
        publish(document)
        receiver("agent-stale", {"metadata": {"annotations": {"journey-fixture/stale": "true"}}})
        recreated = receiver("agent-recreated")
        recreated_path = "/apis/apps/v1/namespaces/demo/deployments/agent-recreated"
        assert fixture_api(recreated_path, "DELETE", {})[0] in (200, 202)
        deadline = time.monotonic() + 10
        while fixture_api(recreated_path)[0] != 404:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        recreated["metadata"] = {
            "name": "agent-recreated",
            "namespace": "demo",
            "labels": {"app": "recreated"},
        }
        recreated.pop("status", None)
        assert (
            fixture_api(
                "/apis/apps/v1/namespaces/demo/deployments", "POST", recreated, "application/json"
            )[0]
            == 201
        )
        assert receiver("agent-recreated")["metadata"]["uid"] != targets["recreated"]["uid"]
        start()
        catalog = read("list")
        catalog_ids = {entry["operation_id"] for entry in catalog["entries"]}
        while catalog["next_cursor"] is not None:
            assert len(catalog_ids) < len(settings["cases"]), "catalog cursor did not finish"
            catalog = read("list", catalog["next_cursor"])
            next_ids = {entry["operation_id"] for entry in catalog["entries"]}
            assert next_ids and catalog_ids.isdisjoint(next_ids)
            catalog_ids.update(next_ids)
        assert catalog_ids == set(settings["cases"]), catalog_ids
        assert read("history")["entries"] == []
        # These probes run under the exact caller identity, not merely a polite tool allowlist.
        custody_probe = pathlib.Path("/inputs/caller_custody_probe.py").read_bytes()
        probe_result = subprocess.run(
            [sys.executable, "-I", "-"],
            input=custody_probe,
            capture_output=True,
            timeout=10,
            cwd="/tmp",
            **identity,
        )
        assert probe_result.returncode == 0, probe_result.stderr[:2048]
        if settings["agent"]:
            pathlib.Path("/operator/caller-ready").touch()
            selection = pathlib.Path("/operator/selection.json")
            deadline = time.monotonic() + 150
            while not selection.exists():
                assert time.monotonic() < deadline, "agent completion deadline"
                time.sleep(0.1)
            assert json.loads(selection.read_text()) == {"operation_id": "healthy"}

        for case in settings["cases"]:
            started = time.monotonic()
            started_unix_s = time.time()
            interrupted_unix_s = None
            resumed_unix_s = None
            stored_read_ms = None
            if case == "independent":
                # This success crosses product TLS/CA handling, not the HTTP barrier's TLS client.
                stop()
                assert cluster["server"].startswith("https://")
                assert not cluster.get("insecure-skip-tls-verify", False)
                shutil.copyfile("/inputs/kubeconfig.json", "/etc/kapsel/kubeconfig.yaml")
                os.chmod("/etc/kapsel/kubeconfig.yaml", 0o600)
                os.chown("/etc/kapsel/kubeconfig.yaml", 61000, 61000)
                start()
            if case == "caller-loss":
                # The public framed socket request is sent by the caller process, which exits without
                # reading an acknowledgement. Reconnect never invents another operation identity.
                body = json.dumps(
                    {"version": 1, "request": "submit_set_deployment_image", "operation_id": case}
                ).encode()
                framed_request = len(body).to_bytes(4, "big") + body
                lost_ack_source = pathlib.Path("/inputs/submit_without_ack.py").read_bytes()
                command(
                    [sys.executable, "-I", "-", framed_request.hex()],
                    input=lost_ack_source,
                    cwd="/tmp",
                    **identity,
                )
            elif not (settings["agent"] and case == "healthy"):
                assert read("submit", case)["status"] == "ADMITTED"

            if case in ("failed", "deleted"):
                record = pathlib.Path("/evidence/" + case + ".patch.json")
                deadline = time.monotonic() + 20
                while not record.exists() or "status" not in json.loads(record.read_text()):
                    assert time.monotonic() < deadline and barrier.poll() is None
                    time.sleep(0.01)
                assert json.loads(record.read_text())["status"] == 200
                stop(crash=True)
                if case == "deleted":
                    deleted_path = "/apis/apps/v1/namespaces/demo/deployments/agent-deleted"
                    assert fixture_api(deleted_path, "DELETE", {})[0] in (200, 202)
                    deadline = time.monotonic() + 10
                    while fixture_api(deleted_path)[0] != 404:
                        assert time.monotonic() < deadline
                        time.sleep(0.05)
                pathlib.Path("/operator/" + case + ".release").touch()
                start()
                assert read("status", case)["execution"]["disposition"] == "resume_required"
                assert read("submit", case)["status"] == "ADMITTED"

            if case == "race":
                stopped = wait(
                    case, lambda r: r["execution"]["disposition"] == "operator_required", seconds=20
                )
                assert stopped["status"] == "IN_PROGRESS"
                with closing(
                    sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True, timeout=1)
                ) as connection:
                    assert connection.execute(
                        "SELECT state FROM kubernetes_image_operations WHERE operation_id = ?",
                        (case,),
                    ).fetchone() == ("apply_started",)
                assert (
                    json.loads(pathlib.Path("/evidence/race.patch.json").read_text())["status"]
                    == 409
                )
                stop()
                start()
                assert read("status", case)["execution"]["disposition"] == "resume_required"
                assert read("submit", case)["status"] == "ADMITTED"

            if case == "service-loss":
                assert read("status", "healthy")["status"] == "SUCCEEDED"
                deadline = time.monotonic() + 20
                while True:
                    deployment = receiver("agent-" + case)
                    container = deployment["spec"]["template"]["spec"]["containers"][0]
                    if container["image"] == settings["desired"]:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.02)

                reads = pathlib.Path("/evidence/" + case + ".gets.jsonl")
                deadline = time.monotonic() + 10
                while not reads.exists() or reads.read_bytes().count(b"\n") < 2:
                    assert time.monotonic() < deadline, "no live observation before interruption"
                    time.sleep(0.01)
                interrupted_unix_s = time.time()
                stop(crash=True)
                attempted_row = retained_row(journal, case)
                install_binaries(pathlib.Path("/artifact"))
                start()
                assert retained_row(journal, case) == attempted_row
                state = read("status", case)
                assert state["status"] == "IN_PROGRESS", state
                assert state["execution"]["disposition"] == "resume_required", state
                # Startup has not resumed this operation or selected "independent".
                # The caller explicitly reselects the same ID.
                assert read("status", "independent")["status"] == "NOT_FOUND"
                resumed_unix_s = time.time()
                assert read("submit", case)["status"] == "ADMITTED"
            if case == "caller-loss":
                wait(case, lambda r: r["execution"]["disposition"] == "active", seconds=20)
                time.sleep(35)
                read_started = time.monotonic()
                assert read("status", case)["status"] == "IN_PROGRESS"
                pending_path = pathlib.Path("/tmp/in-flight.receipt")
                pending = subprocess.run(
                    ["/usr/bin/kapsel-service-client", "receipt", case, str(pending_path)],
                    capture_output=True,
                    timeout=10,
                    **identity,
                )
                assert pending.returncode == 4 and b"receipt_unavailable" in pending.stderr
                assert not pending_path.exists(), "in-flight receipt was exported"
                stored_read_ms = round((time.monotonic() - read_started) * 1000, 3)
                busy = read("submit", "independent")
                assert busy["status"] == "NOT_ADMITTED" and busy["reason"] == "BUSY", busy
                assert read("status", "independent")["status"] == "NOT_FOUND"
            terminal = wait(
                case, lambda r: r["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED")
            )
            finished_unix_s = time.time()
            expected = EXPECTED[case]
            assert terminal["status"] == expected, (case, terminal)
            captured = None
            if case not in ("stale", "recreated", "independent"):
                captured = json.loads(pathlib.Path("/evidence/" + case + ".patch.json").read_text())
                assert captured["request"] == {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": "agent-" + case,
                        "namespace": "demo",
                        "uid": targets[case]["uid"],
                        "resourceVersion": targets[case]["resourceVersion"],
                        "annotations": {"kapsel.dev/kap0038-operation-id": case},
                    },
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "api",
                                        "image": settings["failed_image"]
                                        if case == "failed"
                                        else settings["desired"],
                                    }
                                ]
                            }
                        }
                    },
                }
            if case == "independent":
                current = receiver("agent-independent")
                containers = {
                    c["name"]: c["image"] for c in current["spec"]["template"]["spec"]["containers"]
                }
                assert current["metadata"]["uid"] == targets[case]["uid"]
                assert containers == {
                    "api": settings["desired"],
                    "untouched": original_sidecars[case],
                }
                assert current["metadata"]["annotations"]["kapsel.dev/kap0038-operation-id"] == case
            if case == "healthy":
                assert captured is not None
                current = receiver("agent-healthy")
                containers = current["spec"]["template"]["spec"]["containers"]
                assert len(containers) == 2
                assert (
                    containers[0]["name"] == "api" and containers[0]["image"] == settings["desired"]
                )
                assert containers[1]["name"] == "untouched"
                assert containers[1]["image"] == original_sidecars[case]
                assert current["metadata"]["generation"] == targets[case]["generation"] + 1
                assert replica_sets() == healthy_replica_sets + 1
                assert len(admission_events(1)) == 1
                status, _ = fixture_api(
                    "/apis/apps/v1/namespaces/demo/deployments/agent-healthy",
                    "PATCH",
                    captured["request"],
                    "application/strategic-merge-patch+json",
                )
                assert status == 409
                after_replay = receiver("agent-healthy")
                for field in ("uid", "resourceVersion", "generation"):
                    assert after_replay["metadata"][field] == current["metadata"][field]
                assert after_replay["spec"] == current["spec"]
                assert replica_sets() == healthy_replica_sets + 1
                events = admission_events(2)
                assert len(events) == 2 and len(set(events)) == 2
                pathlib.Path("/evidence/admission.json").write_text(
                    json.dumps(
                        {
                            "replay_status": status,
                            "effects": events,
                            "replica_sets": replica_sets(),
                            "unchanged_generation": after_replay["metadata"]["generation"],
                        }
                    )
                )

            retained: tuple[bytes, bytes, str] | None = None
            finalized_row: tuple[object, ...] | None = None
            if case == "service-loss":
                # A terminal status establishes receipt commit, but no receipt has reached the
                # caller. Kill before its first export, then change signing material while cold.
                retained = finalized_evidence(journal, case)
                finalized_row = retained_row(journal, case)
                assert retained[0] == pathlib.Path(case + ".grant").read_bytes()
                assert retained[2] == "receipt-key-1"
                pathlib.Path("/evidence/service-loss.grant").write_bytes(retained[0])
                pathlib.Path("/evidence/service-loss.receipt").write_bytes(retained[1])
                pathlib.Path("/evidence/service-loss.retained.json").write_text(
                    json.dumps(
                        {
                            "journal_format": 6,
                            "operation_id": case,
                            "receipt_signer": retained[2],
                            "grant_sha256": hashlib.sha256(retained[0]).hexdigest(),
                            "receipt_sha256": hashlib.sha256(retained[1]).hexdigest(),
                        },
                        indent=2,
                    )
                    + "\n"
                )
                stop(crash=True)
                install_binaries(pathlib.Path("/artifact"))
                rotated_seed = pathlib.Path("/etc/kapsel/receipt.seed")
                rotated_seed.write_bytes(bytes([113]) * 32)
                changed = json.loads(document)
                changed["receipt_signing_key_id"] = "rotated-receipt-key"
                publish(json.dumps(changed).encode())
                start()
                assert read("status", case) == terminal
                assert finalized_evidence(journal, case) == retained
                assert retained_row(journal, case) == finalized_row
                assert receipt("healthy", "rotated-old") == original_receipts["healthy"]
                assert retained_row(journal, "healthy") == original_rows["healthy"]

            frozen: bytes | None = None
            if case in ("stale", "recreated"):
                assert terminal["target_rejection"] == "STALE_APPROVAL", terminal
                digest = None
            else:
                frozen = receipt(case, "first")
                digest = hashlib.sha256(frozen).hexdigest()
                original_receipts[case] = frozen
                original_rows[case] = retained_row(journal, case)
                assert read("submit", case) == {
                    "version": 1,
                    "status": "ADMITTED",
                    "phase": "finalized",
                }
                assert receipt(case, "duplicate") == frozen

            if retained is not None:
                assert frozen == retained[1], "receipt loss must not cause re-signing"
                assert finalized_evidence(journal, case) == retained
                assert retained_row(journal, case) == finalized_row
                # Restore current fixture material only. Do not rewrite retained history.
                stop()
                shutil.copyfile("receipt.seed", "/etc/kapsel/receipt.seed")
                publish(document)
                start()
                assert read("status", case) == terminal
                assert receipt(case, "restored") == frozen

            if case == "caller-loss":
                deadline = time.monotonic() + 120
                while True:
                    actual = receiver("agent-" + case)
                    status = actual["status"]
                    if (
                        status.get("observedGeneration") == actual["metadata"]["generation"]
                        and status.get("availableReplicas") == 1
                        and status.get("updatedReplicas") == 1
                        and status.get("unavailableReplicas", 0) == 0
                    ):
                        break
                    assert time.monotonic() < deadline, "late live rollout availability deadline"
                    time.sleep(1)
                assert time.monotonic() - started > 180
                assert read("status", case) == terminal
                assert receipt(case, "late-available") == frozen
                # A conflicting follow-on approval was deliberately never provisioned. Hostile ID
                # selection cannot make it available, including after an enforced cold replacement.
                assert read("submit", "conflicting-b")["status"] == "ERROR"
                stop()
                changed = json.loads(document)
                changed["approvals"] = [
                    a for a in changed["approvals"] if a["label"] == "Approved independent"
                ]
                publish(json.dumps(changed).encode())
                start()
                assert read("submit", "conflicting-b")["status"] == "ERROR"
                assert read("status", "conflicting-b")["status"] == "NOT_FOUND"
                assert read("status", case) == terminal
                assert receipt(case, "restart") == frozen
                assert receipt("healthy", "old-result") == original_receipts["healthy"]
                assert retained_row(journal, "healthy") == original_rows["healthy"]

            reports.append(
                {
                    "case": case,
                    "status": expected,
                    "receiver_transport": "direct-https"
                    if case == "independent"
                    else "loopback-http",
                    "seconds": round(time.monotonic() - started, 3),
                    "started_unix_s": started_unix_s,
                    "finished_unix_s": finished_unix_s,
                    "interrupted_unix_s": interrupted_unix_s,
                    "resumed_unix_s": resumed_unix_s,
                    "stored_read_ms": stored_read_ms,
                    "receipt_sha256": digest,
                    "receipt_commit_loss": retained is not None,
                    "retained_format6_replacement": retained is not None
                    and retained_artifact.is_dir(),
                    "retained_attempted_recovery": case == "service-loss"
                    and retained_artifact.is_dir(),
                    "original_healthy_receipt_preserved": case == "caller-loss"
                    and retained_artifact.is_dir(),
                }
            )
            assert not pathlib.Path("/evidence/barrier.violation").exists(), (
                "product sent another PATCH"
            )
            print(json.dumps(reports[-1]), flush=True)

        stop()
        pathlib.Path("/evidence/results.json").write_text(json.dumps(reports, indent=2) + "\n")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        if barrier is not None and barrier.poll() is None:
            barrier.terminate()
            barrier.wait(timeout=10)


if __name__ == "__main__":
    main()
