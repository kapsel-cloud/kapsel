"""Operator and deterministic caller fixture for the packaged Kubernetes journey."""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from typing import TypedDict


class CallerIdentity(TypedDict):
    user: int
    group: int
    extra_groups: list[int]


def main() -> None:
    def receiver(name, patch=None):
        data = None if patch is None else json.dumps(patch).encode()
        request = urllib.request.Request(
            cluster["server"] + "/apis/apps/v1/namespaces/demo/deployments/" + name,
            data=data,
            method="GET" if patch is None else "PATCH",
            headers={
                "Authorization": "Bearer " + token,
                "User-Agent": "kapsel-journey-fixture",
                "Content-Type": "application/merge-patch+json",
            },
        )
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            body = response.read(262145)
            assert len(body) <= 262144
            return json.loads(body)

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
        while time.monotonic() < deadline:
            assert process is not None and process.poll() is None, "service exited"
            result = read("status", case)
            if predicate(result):
                return result
            time.sleep(0.1)
        raise AssertionError("status deadline: " + case)

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
        assert report["result"] == ("UNKNOWN" if case == "caller-loss" else "SUCCEEDED"), report
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
    for source, destination in (
        ("bin/kapsel", "/usr/bin/kapsel"),
        ("bin/kapsel-service-client", "/usr/bin/kapsel-service-client"),
        ("bin/kapsel-service-mcp", "/usr/bin/kapsel-service-mcp"),
        ("libexec/kapsel/kapseld", "/usr/libexec/kapsel/kapseld"),
    ):
        pathlib.Path(destination).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile("/artifact/" + source, destination)
        pathlib.Path(destination).chmod(0o755)
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

    # The fixture operator explicitly owns these disposable Deployments. No GitOps reconciler is
    # disabled. B is independently assessed; conflicting intent is never provisioned to the caller.
    prepare = [
        "/usr/bin/kapsel",
        "prepare-service-config",
        "--authorization-key",
        "approval-key-1",
        "approval.pub",
    ]
    for case in settings["cases"]:
        intent = {
            "authorization_id": "approval-" + case,
            "operation_id": case,
            "namespace": "demo",
            "deployment": "agent-" + case,
            "container": "api",
            "immutable_image_digest": settings["desired"],
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

    for source, target in (
        ("/inputs/kubeconfig.json", "/etc/kapsel/kubeconfig.yaml"),
        ("receipt.seed", "/etc/kapsel/receipt.seed"),
    ):
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        os.chown(target, 61000, 61000)
    service = "/usr/libexec/kapsel/kapseld"
    client = "/usr/bin/kapsel-service-client"
    identity: CallerIdentity = {"user": 61001, "group": 61000, "extra_groups": []}

    publish(document)
    receiver("agent-stale", {"metadata": {"annotations": {"journey-fixture/stale": "true"}}})
    process: subprocess.Popen[bytes] | None = None
    reports = []

    try:
        start()
        catalog = read("list")
        assert {entry["operation_id"] for entry in catalog["entries"]} == set(settings["cases"])
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

            if case == "service-loss":
                deadline = time.monotonic() + 20
                while True:
                    deployment = receiver("agent-" + case)
                    container = deployment["spec"]["template"]["spec"]["containers"][0]
                    if container["image"] == settings["desired"]:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.02)

                stop(crash=True)
                start()
                state = read("status", case)
                assert state["status"] == "IN_PROGRESS", state
                assert state["execution"]["disposition"] == "resume_required", state
                # Startup has not selected B or resumed A. The caller explicitly reselects original A.
                assert read("status", "independent")["status"] == "NOT_FOUND"
                assert read("submit", case)["status"] == "ADMITTED"
            terminal = wait(
                case, lambda r: r["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED")
            )
            if case == "stale":
                expected = "NOT_ATTEMPTED"
            elif case == "caller-loss":
                expected = "UNKNOWN"
            else:
                expected = "SUCCEEDED"
            assert terminal["status"] == expected, (case, terminal)

            frozen: bytes | None = None
            if case == "stale":
                assert terminal["target_rejection"] == "STALE_APPROVAL", terminal
                digest = None
            else:
                frozen = receipt(case, "first")
                digest = hashlib.sha256(frozen).hexdigest()
                assert read("submit", case) == {
                    "version": 1,
                    "status": "ADMITTED",
                    "phase": "finalized",
                }
                assert receipt(case, "duplicate") == frozen

            if case == "caller-loss":
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
                assert receipt("healthy", "old-result")

            reports.append(
                {
                    "case": case,
                    "status": expected,
                    "seconds": round(time.monotonic() - started, 3),
                    "receipt_sha256": digest,
                }
            )
            print(json.dumps(reports[-1]), flush=True)

        stop()
        pathlib.Path("/evidence/results.json").write_text(json.dumps(reports, indent=2) + "\n")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)


if __name__ == "__main__":
    main()
