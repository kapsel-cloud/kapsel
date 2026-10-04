"""Execute the packaged operator guide in an isolated disposable Linux container."""

import importlib.util
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class OperatorExample:
    """Bind public example inputs; main owns service lifetime and recovery ordering."""

    fixture: ModuleType
    guide: str
    client: pathlib.Path
    service: pathlib.Path

    def block(self, name: str, language: str) -> str:
        matches = re.findall(
            rf"<!-- example-{name} -->\s*```{language}\n(.*?)\n```", self.guide, re.S
        )
        assert len(matches) == 1, name
        return matches[0]

    def start(self) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [
                str(self.service),
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

    def publish(self, document: bytes) -> None:
        """Publish operator-held bytes while main keeps the service stopped."""
        result = subprocess.run(
            [str(self.service), "--replace-operator-config"],
            input=document,
            capture_output=True,
            user=61000,
            group=61000,
            extra_groups=[],
            timeout=30,
        )
        assert (result.returncode, result.stdout, result.stderr) == (0, b"PUBLISHED\n", b"")

    def read(self, command: list[str]):
        return self.fixture.service_client(self.client, command, 61001, 61000)

    def wait_for_read(self, process: subprocess.Popen[bytes] | None, command: list[str], predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process is not None and process.poll() is None, "service exited"
            try:
                result = self.read(command)
            except RuntimeError:
                time.sleep(0.02)
                continue
            if predicate(result):
                return result
            time.sleep(0.02)
        raise AssertionError("documented operation did not reach expected state")


def prepare_example_authority(example: OperatorExample) -> None:
    fixture = example.fixture
    subprocess.run(["sh", "-eu", "-c", example.block("keys", "sh")], check=True, timeout=30)
    assert pathlib.Path("approval.seed").read_bytes() != pathlib.Path("receipt.seed").read_bytes()
    for name in ("approval.seed", "receipt.seed", "approval.pub", "receipt.pub", "receipt.trust"):
        assert pathlib.Path(name).stat().st_mode & 0o777 == 0o600

    expected_deployment = json.loads(fixture.deployment("1", 1, False))
    for field in ("uid", "resourceVersion", "generation"):
        del expected_deployment["metadata"][field]
    assert json.loads(example.block("deployment", "json")) == expected_deployment

    authorization = json.loads(example.block("authorization", "json"))
    assert authorization["operation_id"] == fixture.OPERATION
    assert authorization["immutable_image_digest"] == fixture.IMAGE
    pathlib.Path("authorization.json").write_text(json.dumps(authorization))


def prepare_operator_configuration(example: OperatorExample, binary: pathlib.Path) -> bytes:
    subprocess.run(["sh", "-eu", "-c", example.block("prepare", "sh")], check=True, timeout=30)
    assert example.fixture.KubernetesFixture.requests == 1
    assert example.fixture.KubernetesFixture.mutations == 0

    document = pathlib.Path("operator.candidate.json").read_bytes()
    expected_configuration = {
        "service_configuration_version": 1,
        "authorization_keys": [
            {
                "key_id": "approval-key-1",
                "public_key_hex": pathlib.Path("approval.pub").read_bytes().hex(),
            }
        ],
        "approvals": [
            {
                "label": "Approved image for agent-api",
                "signed_grant_hex": pathlib.Path("approval.grant").read_bytes().hex(),
            }
        ],
        "receipt_signing_key_id": "receipt-key-1",
    }
    assert json.loads(document) == expected_configuration
    subprocess.run(
        [str(binary), "validate-service-config", "--operator-config", "operator.candidate.json"],
        check=True,
        timeout=10,
    )
    return document


def main() -> None:
    spec = importlib.util.spec_from_file_location("fixture", "/fixture.py")
    assert spec is not None and spec.loader is not None, "artifact fixture unavailable"
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    guide = pathlib.Path("/guide.md").read_text()

    started = time.monotonic()
    os.umask(0o077)
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="operator-"))
    os.chdir(workspace)
    binary = pathlib.Path("/usr/bin/kapsel")
    shutil.copyfile("/artifact/bin/kapsel", binary)
    binary.chmod(0o755)
    client = pathlib.Path("/artifact/bin/kapsel-service-client")
    service = pathlib.Path("/artifact/libexec/kapsel/kapseld")
    example = OperatorExample(fixture, guide, client, service)
    prepare_example_authority(example)

    fixture.reset_kubernetes_fixture()
    fixture.KubernetesFixture.receiver_responses.insert(0, fixture.deployment("1", 1, False))
    server = fixture.http.server.ThreadingHTTPServer(("127.0.0.1", 0), fixture.KubernetesFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    pathlib.Path("kubeconfig.yaml").write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "current-context": "fixture",
                "clusters": [
                    {
                        "name": "fixture",
                        "cluster": {"server": f"http://127.0.0.1:{server.server_port}"},
                    }
                ],
                "contexts": [
                    {"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}
                ],
                "users": [{"name": "fixture", "user": {}}],
            }
        )
    )
    process = None

    try:
        document = prepare_operator_configuration(example, binary)
        configuration = json.loads(document)

        for path, mode in (
            ("/etc/kapsel", 0o700),
            ("/var/lib/kapsel", 0o700),
            ("/run/kapsel", 0o750),
        ):
            pathlib.Path(path).mkdir(mode=mode)
            pathlib.Path(path).chmod(mode)
            os.chown(path, 61000, 61000)
        # Start without receiver material. Read availability and admission are independent of it.
        example.publish(document)
        print("Cold publication: PUBLISHED", flush=True)
        process = example.start()
        print(
            "List:",
            json.dumps(example.wait_for_read(process, ["list"], lambda r: r["status"] == "READY")),
            flush=True,
        )
        assert example.read(["history"])["entries"] == []
        assert fixture.KubernetesFixture.requests == 1

        admitted = example.read(["submit", fixture.OPERATION])
        assert admitted == json.loads(example.block("admitted", "json"))
        print("Submit:", json.dumps(admitted), flush=True)

        unavailable = example.wait_for_read(
            process,
            ["status", fixture.OPERATION],
            lambda r: r.get("execution", {}).get("condition") == "receiver_unavailable",
        )
        assert unavailable["status"] == "IN_PROGRESS"
        assert unavailable["execution"]["action_owner"] == "operator"
        assert fixture.KubernetesFixture.requests == 1
        process.terminate()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode == 0
        assert b"receiver_unavailable" in diagnostics

        fixture.write_private(
            pathlib.Path("/etc/kapsel/kubeconfig.yaml"),
            pathlib.Path("kubeconfig.yaml").read_bytes(),
        )
        os.chown("/etc/kapsel/kubeconfig.yaml", 61000, 61000)

        # Keep valid execution material but remove the actual receiver listener. This is a transport
        # outage, distinct from missing credentials, and cannot become a receiver result.
        port = server.server_port
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        process = example.start()
        example.wait_for_read(
            process,
            ["status", fixture.OPERATION],
            lambda r: r.get("execution", {}).get("disposition") == "resume_required",
        )
        assert fixture.KubernetesFixture.requests == 1

        selected = example.read(["submit", fixture.OPERATION])
        assert selected == {"version": 1, "status": "ADMITTED", "phase": "authorized"}, selected
        offline = example.wait_for_read(
            process,
            ["status", fixture.OPERATION],
            lambda r: r.get("execution", {}).get("condition") == "preflight_unavailable",
        )
        assert offline["status"] == "IN_PROGRESS"
        assert fixture.KubernetesFixture.mutations == 0
        assert fixture.KubernetesFixture.requests == 1

        server = fixture.http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), fixture.KubernetesFixture
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        assert example.read(["submit", fixture.OPERATION]) == selected
        print(
            "Receiver access restored: explicit same-ID selection, no replacement approval",
            flush=True,
        )
        stopped = example.wait_for_read(
            process,
            ["status", fixture.OPERATION],
            lambda r: r.get("execution", {}).get("condition") == "signing_unavailable",
        )
        assert stopped["status"] == "IN_PROGRESS"
        assert stopped["execution"] == json.loads(example.block("signing", "json"))
        assert fixture.KubernetesFixture.mutations == 1
        print("Signing unavailable:", json.dumps(stopped), flush=True)
        process.terminate()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode == 0
        fixture.write_private(
            pathlib.Path("/etc/kapsel/receipt.seed"), pathlib.Path("receipt.seed").read_bytes()
        )
        os.chown("/etc/kapsel/receipt.seed", 61000, 61000)
        recovery_request_baseline = fixture.KubernetesFixture.requests
        process = example.start()
        resumed = example.wait_for_read(
            process,
            ["status", fixture.OPERATION],
            lambda r: r.get("execution", {}).get("disposition") == "resume_required",
        )
        assert fixture.KubernetesFixture.requests == recovery_request_baseline
        assert resumed["execution"] == json.loads(example.block("resume", "json"))
        print("Read-first restart:", json.dumps(resumed), flush=True)
        readmitted = example.read(["submit", fixture.OPERATION])
        assert readmitted == json.loads(example.block("readmitted", "json"))
        print("Same-ID submit:", json.dumps(readmitted), flush=True)
        complete = example.wait_for_read(
            process, ["status", fixture.OPERATION], lambda r: r["status"] == "SUCCEEDED"
        )
        assert fixture.KubernetesFixture.requests == recovery_request_baseline, (
            "completion acquired new receiver facts"
        )
        print("Completed:", json.dumps(complete), flush=True)
        receipt = pathlib.Path("/tmp/documented-example.receipt")
        print(
            "Receipt:",
            json.dumps(example.read(["receipt", fixture.OPERATION, str(receipt)])),
            flush=True,
        )
        inspection = subprocess.run(
            [
                str(binary),
                "inspect",
                "--receipt",
                str(receipt),
                "--trust",
                "receipt.trust",
                "--evaluation-time-unix-s",
                pathlib.Path("evaluation-time.txt").read_text().strip(),
            ],
            capture_output=True,
            check=True,
            timeout=10,
        )
        report = json.loads(inspection.stdout)
        assert report["status"] == "INSPECTED", report
        print("Inspection:", inspection.stdout.decode().strip(), flush=True)
        assert fixture.KubernetesFixture.mutations == 1
        assert fixture.KubernetesFixture.requests == 4
        print(
            f"Documented example: one PATCH, same-ID signing recovery; {time.monotonic() - started:.2f}s",
            flush=True,
        )

        # Exercise loss of an external trust appointment, not loss/replacement of the retained grant.
        # Remediation uses only cold publication and the original operator-held document.
        frozen = receipt.read_bytes()
        process.terminate()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode == 0
        journal = pathlib.Path("/var/lib/kapsel/journal.sqlite3")
        retained = journal.read_bytes()
        withdrawn = dict(configuration, approvals=[], authorization_keys=[])
        example.publish(json.dumps(withdrawn).encode())
        assert journal.read_bytes() == retained
        # Execution material is deliberately unavailable throughout historical read recovery.
        pathlib.Path("/etc/kapsel/kubeconfig.yaml").unlink()
        pathlib.Path("/etc/kapsel/receipt.seed").unlink()
        process = example.start()
        inaccessible = {"version": 1, "status": "ERROR", "error_class": "authority_unavailable"}
        assert (
            example.wait_for_read(
                process, ["status", fixture.OPERATION], lambda r: r == inaccessible
            )
            == inaccessible
        )
        history = example.read(["history"])
        assert history["entries"] == [
            {
                "operation_id": fixture.OPERATION,
                "status": "ERROR",
                "error_class": "authority_unavailable",
            }
        ]
        assert example.read(["submit", fixture.OPERATION]) == inaccessible
        denied_receipt = pathlib.Path("/tmp/unavailable-authority.receipt")
        denied = subprocess.run(
            [str(client), "receipt", fixture.OPERATION, str(denied_receipt)],
            capture_output=True,
            user=61001,
            group=61000,
            extra_groups=[],
            timeout=10,
        )
        assert denied.returncode != 0 and not denied_receipt.exists()
        assert fixture.KubernetesFixture.requests == recovery_request_baseline
        process.terminate()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode == 0
        assert b"original_authority_unavailable" in diagnostics
        assert journal.read_bytes() == retained
        for private in (
            pathlib.Path("approval.seed").read_bytes().hex().encode(),
            pathlib.Path("receipt.seed").read_bytes().hex().encode(),
            pathlib.Path("approval.grant").read_bytes().hex().encode(),
        ):
            assert private not in diagnostics + denied.stdout + denied.stderr
        print(
            "Missing original trust: authority_unavailable; history preserved; export refused",
            flush=True,
        )

        example.publish(document)
        process = example.start()
        recovered = example.wait_for_read(
            process, ["status", fixture.OPERATION], lambda r: r["status"] == "SUCCEEDED"
        )
        assert recovered == complete
        original = pathlib.Path("/tmp/restored-authority.receipt")
        assert example.read(["receipt", fixture.OPERATION, str(original)])["status"] == "READY"
        assert original.read_bytes() == frozen
        assert fixture.KubernetesFixture.requests == recovery_request_baseline
        assert fixture.KubernetesFixture.mutations == 1
        process.terminate()
        process.communicate(timeout=30)
        assert process.returncode == 0
        assert journal.read_bytes() == retained
        print(
            "Original trust restored: identical receipt, no receiver or signing material, zero HTTP",
            flush=True,
        )

        # Fault preparation only: mark this disposable journal unsupported. The operator procedure
        # must stop here, not rewrite the version, restore an older database, or create a new ID.
        with sqlite3.connect(journal) as connection:
            connection.execute("PRAGMA user_version = 4")
        refused = journal.read_bytes()
        process = example.start()
        _, diagnostics = process.communicate(timeout=30)
        assert process.returncode != 0
        assert any(
            code in diagnostics
            for code in (b"storage_history_invalid", b"storage_or_operation_blocked")
        )  # Published v0.3 retains its original fixed code.
        assert journal.read_bytes() == refused
        assert fixture.KubernetesFixture.requests == recovery_request_baseline
        assert fixture.KubernetesFixture.mutations == 1
        print(
            "Unsupported-version fixture: startup refused, journal unchanged; stop and inspect",
            flush=True,
        )
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.communicate(timeout=30)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
