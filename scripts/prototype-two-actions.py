#!/usr/bin/env python3
"""Run the isolated two-action endpoint against counted loopback HTTP, never a cluster."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import platform
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import traceback
import urllib.parse
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent
ACTION_A = "action-a"
ACTION_B = "action-b"
IMAGE = "example/api@sha256:" + "a" * 64
OLD_IMAGE = "example/api@sha256:" + "f" * 64
SOURCES = ["tests/two_action_endpoint_prototype.rs", "scripts/prototype-two-actions.py"]


def build() -> pathlib.Path:
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "two_action_endpoint_prototype",
            "--no-run",
            "--message-format=json",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr)[-8192:])
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if (
            event.get("executable")
            and event.get("target", {}).get("name") == "two_action_endpoint_prototype"
        ):
            return pathlib.Path(event["executable"])
    raise RuntimeError("prototype test executable was not built")


def deployment(name: str) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": "demo",
            "uid": "uid-" + name,
            "resourceVersion": "1",
            "generation": 1,
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {"spec": {"containers": [{"name": "api", "image": OLD_IMAGE}]}},
        },
        "status": {
            "observedGeneration": 1,
            "updatedReplicas": 1,
            "availableReplicas": 1,
            "unavailableReplicas": 0,
            "conditions": [{"type": "Available", "status": "True"}],
        },
    }


class Receiver(http.server.HTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ReceiverHandler)
        self.targets = {name: deployment(name) for name in ("api", "worker")}
        self.requests: list[dict[str, Any]] = []
        self.fail_a = False
        self.unknown_a = False
        self.failure: BaseException | None = None

    def handle_error(self, _request: Any, _client_address: Any) -> None:
        self.failure = RuntimeError("receiver fixture assertion failed: " + traceback.format_exc())


class ReceiverHandler(http.server.BaseHTTPRequestHandler):
    server: Receiver

    def log_message(self, _format: str, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.respond(False)

    def do_PATCH(self) -> None:
        self.respond(True)

    def respond(self, patch: bool) -> None:
        self.connection.settimeout(3)
        path = urllib.parse.urlsplit(self.path).path
        name = path.rsplit("/", 1)[-1]
        assert path == f"/apis/apps/v1/namespaces/demo/deployments/{name}"
        assert name in self.server.targets
        size = int(self.headers.get("Content-Length", "0"))
        assert 0 <= size <= 4096
        body = json.loads(self.rfile.read(size)) if size else None
        assert len(self.server.requests) < 100
        event = {"method": self.command, "path": self.path, "body": body}
        self.server.requests.append(event)
        target = self.server.targets[name]
        code = 200
        if patch:
            assert body["metadata"]["uid"] == target["metadata"]["uid"]
            assert body["metadata"]["resourceVersion"] == target["metadata"]["resourceVersion"]
            assert set(body) == {"apiVersion", "kind", "metadata", "spec"}
            assert body["apiVersion"] == "apps/v1" and body["kind"] == "Deployment"
            assert set(body["metadata"]) == {
                "name",
                "namespace",
                "uid",
                "resourceVersion",
                "annotations",
            }
            assert body["metadata"]["name"] == name and body["metadata"]["namespace"] == "demo"
            assert set(body["metadata"]["annotations"]) == {"kapsel.dev/kap0038-operation-id"}
            identity = body["metadata"]["annotations"]["kapsel.dev/kap0038-operation-id"]
            assert identity in (ACTION_A, ACTION_B)
            assert body["spec"] == {
                "template": {"spec": {"containers": [{"name": "api", "image": IMAGE}]}},
            }
            target["metadata"].update(
                resourceVersion="2",
                generation=2,
                annotations=body["metadata"]["annotations"],
            )
            target["spec"]["template"]["spec"]["containers"][0]["image"] = IMAGE
            target["status"]["observedGeneration"] = 2
        elif self.server.fail_a and name == "api":
            self.server.fail_a = False
            code = 503
        result = json.loads(json.dumps(target))
        if not patch and self.server.unknown_a and name == "api":
            result["metadata"]["uid"] = "replacement-uid"
        if code != 200:
            result = {"apiVersion": "v1", "kind": "Status", "code": code, "reason": "Unavailable"}
        event["response_code"] = code
        event["response_facts"] = {
            "uid": result.get("metadata", {}).get("uid"),
            "resource_version": result.get("metadata", {}).get("resourceVersion"),
        }
        payload = json.dumps(result).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class Workflow:
    def __init__(self, binary: pathlib.Path, root: pathlib.Path, same_target: bool) -> None:
        self.binary, self.root = binary, root
        self.receiver = Receiver()
        self.thread = threading.Thread(target=self.receiver.serve_forever, daemon=True)
        self.thread.start()
        self.started = time.monotonic()
        self.events: list[dict[str, Any]] = []
        self.approved: dict[str, float] = {}
        self.record(
            "operator_assessment",
            relationship="conflicting" if same_target else "independent fixture targets",
        )
        self.process: subprocess.Popen[bytes] | None = None
        self.log = (root / "child.log").open("wb")
        requests = []
        for identity, target in [
            (ACTION_A, "api"),
            (ACTION_B, "api" if same_target else "worker"),
        ]:
            requests.append(
                {
                    "operation_id": identity,
                    "namespace": "demo",
                    "deployment": target,
                    "container": "api",
                    "immutable_image_digest": IMAGE,
                }
            )
        (root / "requests.json").write_text(json.dumps(requests))
        (root / "receiver").write_text(f"127.0.0.1:{self.receiver.server_port}")
        for mode, identity in [("approve-a", ACTION_A), ("approve-b", ACTION_B)]:
            self.operator(mode)
            self.approved[identity] = time.monotonic()
            self.record("operator", mode=mode, elapsed_ms=self.elapsed())

    def elapsed(self) -> float:
        return round((time.monotonic() - self.started) * 1000, 3)

    def record(self, kind: str, **values: Any) -> None:
        self.events.append({"kind": kind, **values})

    def operator(self, mode: str) -> None:
        env = {**os.environ, "PROTOTYPE_ROOT": str(self.root), "PROTOTYPE_MODE": mode}
        subprocess.run(
            [str(self.binary), "--ignored", "--exact", "two_action_endpoint_child"],
            env=env,
            stdout=self.log,
            stderr=self.log,
            check=True,
            timeout=10,
        )

    def start(self, seam: str = "") -> None:
        for name in ("ready", "paused", "continue", "endpoint.sock", "execution-result"):
            (self.root / name).unlink(missing_ok=True)
        (self.root / "pause").write_text(seam)
        env = {**os.environ, "PROTOTYPE_ROOT": str(self.root), "PROTOTYPE_MODE": "serve"}
        self.process = subprocess.Popen(
            [str(self.binary), "--ignored", "--exact", "two_action_endpoint_child"],
            env=env,
            stdout=self.log,
            stderr=self.log,
        )
        self.wait(lambda: (self.root / "ready").exists())
        self.record("operator", mode="start", reconciliation="explicit selection only")

    def kill(self) -> None:
        if self.process is not None:
            self.process.kill()
            code = self.process.wait(timeout=5)
            self.record("process_exit", returncode=code)
            self.process = None

    def wait(self, condition: Any) -> None:
        deadline = time.monotonic() + 35
        while not condition():
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(
                    "endpoint exited: " + (self.root / "child.log").read_text()[-8192:]
                )
            if time.monotonic() > deadline:
                raise RuntimeError("bounded workflow wait expired")
            time.sleep(0.005)
        if self.receiver.failure:
            raise self.receiver.failure

    def call(
        self, request: str, identity: str, *, record: bool = True, **extra: Any
    ) -> dict[str, Any]:
        body = {"request": request, "operation_id": identity, **extra}
        payload = json.dumps(body).encode()
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(3)
            stream.connect(str(self.root / "endpoint.sock"))
            stream.sendall(struct.pack("!I", len(payload)) + payload)
            stream.shutdown(socket.SHUT_WR)
            prefix = receive(stream, 4)
            length = struct.unpack("!I", prefix)[0]
            assert 0 < length <= 40 * 1024
            response = json.loads(receive(stream, length))
            assert stream.recv(1) == b""
        if record:
            timing = {}
            if request == "select" and identity in self.approved:
                timing["approval_to_selection_ms"] = round(
                    (time.monotonic() - self.approved[identity]) * 1000,
                    3,
                )
            self.record("caller", request=body, response=response, **timing)
        return response

    def select(self, identity: str) -> None:
        (self.root / "execution-result").unlink(missing_ok=True)
        assert self.call("select", identity) == {"status": "ACCEPTED"}

    def complete(self, identity: str, expected: str) -> None:
        self.wait(lambda: (self.root / "execution-result").exists())
        # Give the endpoint a turn to collect the completed task before the next admission.
        self.wait(lambda: self.call("status", identity, record=False).get("status") == expected)
        time.sleep(0.01)
        assert self.call("status", identity)["status"] == expected
        self.journal()

    def journal(self) -> list[dict[str, Any]]:
        connection = sqlite3.connect(f"file:{self.root / 'journal.sqlite3'}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        with connection:
            rows = [
                dict(row)
                for row in connection.execute("""
                SELECT operation_id, state, authorization_id, authorization_grant_digest,
                       approved_uid, approved_resource_version, apply_attempted,
                       target_uid, target_resource_version, target_rejection, result, receipt_digest
                FROM kubernetes_image_operations ORDER BY operation_id
            """)
            ]
        connection.close()
        self.record("journal", rows=rows)
        return rows

    def frozen(self, identity: str) -> dict[str, Any]:
        response = self.call("receipt", identity)
        assert response["status"] == "READY"
        assert (
            hashlib.sha256(bytes.fromhex(response["receipt_hex"])).hexdigest()
            == response["receipt_sha256"]
        )
        return response

    def close(self) -> None:
        self.kill()
        self.receiver.shutdown()
        self.thread.join(timeout=3)
        self.receiver.server_close()
        self.log.close()


def receive(stream: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise RuntimeError("short prototype response")
        result.extend(chunk)
    return bytes(result)


def run_case(binary: pathlib.Path, name: str) -> dict[str, Any]:
    same_target = name in ("same-target", "unknown-conflict")
    with tempfile.TemporaryDirectory(prefix="two-actions-", dir="/tmp") as scratch:
        root = pathlib.Path(scratch).resolve()
        workflow = Workflow(binary, root, same_target)
        try:
            exercise(workflow, name)
            requests = workflow.receiver.requests
            patches = [request for request in requests if request["method"] == "PATCH"]
            expected = 1 if name in ("same-target", "unknown-conflict", "before-http") else 2
            assert len(patches) == expected, (name, len(patches), expected)
            assert not workflow.receiver.failure
            return {
                "case": name,
                "evidence_class": "mock HTTP + real process exit",
                "http_mutations": len(patches),
                "receiver_requests": requests,
                "workflow": workflow.events,
            }
        except Exception as error:
            detail = f"case {name}: {error}; receiver={workflow.receiver.requests}"
            raise RuntimeError(detail[-8192:]) from error
        finally:
            workflow.close()


def verify_process_loss_recovery(workflow: Workflow, seam: str) -> None:
    workflow.wait(lambda: (workflow.root / "paused").exists())
    rows = workflow.journal()
    if seam == "accepted":
        assert rows == []
    else:
        assert rows[0]["state"] == ("authorized" if seam == "authorized" else "apply_started")
        assert rows[0]["apply_attempted"] == int(seam != "authorized")
    expected_patches = int(seam == "after-http")
    assert (
        sum(request["method"] == "PATCH" for request in workflow.receiver.requests)
        == expected_patches
    )
    assert workflow.call("select", ACTION_B) == {"status": "BUSY"}
    assert workflow.call("select", ACTION_A) == {"status": "BUSY"}
    assert workflow.call("status", ACTION_B) == {"status": "NOT_FOUND"}
    workflow.kill()
    workflow.start()
    before = len(workflow.receiver.requests)
    assert workflow.call("status", ACTION_A)["status"] == (
        "NOT_FOUND" if seam == "accepted" else "IN_PROGRESS"
    )
    assert workflow.call("receipt", ACTION_A)["status"] == (
        "NOT_FOUND" if seam == "accepted" else "NOT_READY"
    )
    assert len(workflow.receiver.requests) == before
    workflow.select(ACTION_A)


def exercise(workflow: Workflow, name: str) -> None:
    seam = name if name in ("accepted", "authorized", "before-http", "after-http") else ""
    unknown = name in ("unknown-conflict", "unknown-independent")
    workflow.start("after-http" if unknown else seam)
    assert workflow.call("status", ACTION_A) == {"status": "NOT_FOUND"}
    assert workflow.call("status", ACTION_B) == {"status": "NOT_FOUND"}
    if name == "transient":
        workflow.receiver.fail_a = True
    workflow.select(ACTION_A)
    if seam:
        verify_process_loss_recovery(workflow, seam)
    if name == "transient":
        workflow.complete(ACTION_A, "IN_PROGRESS")
        assert (workflow.root / "execution-result").read_text() == "operation_failure"
        original_a = workflow.journal()[0]
        assert original_a["state"] == "authorized" and original_a["apply_attempted"] == 0
        workflow.select(ACTION_B)
        workflow.complete(ACTION_B, "SUCCEEDED")
        assert workflow.journal()[0] == original_a
        workflow.select(ACTION_A)
    # The shim holds the PATCH response, so the observation change cannot race the GET.
    if unknown:
        workflow.wait(lambda: (workflow.root / "paused").exists())
        workflow.receiver.unknown_a = True
        (workflow.root / "continue").write_text("continue")
    expected_a = "UNKNOWN" if unknown or seam == "before-http" else "SUCCEEDED"
    workflow.complete(ACTION_A, expected_a)
    if name == "unknown-conflict":
        original_receipt = workflow.frozen(ACTION_A)
        workflow.record(
            "caller_hold",
            identity=ACTION_B,
            reason="conflicts with UNKNOWN A; operator decision required",
        )
        assert workflow.call("status", ACTION_B) == {"status": "NOT_FOUND"}
        assert len(workflow.journal()) == 1
        workflow.kill()
        workflow.start()
        assert workflow.call("status", ACTION_A) == {"status": "UNKNOWN"}
        assert workflow.frozen(ACTION_A) == original_receipt
        assert workflow.call("status", ACTION_B) == {"status": "NOT_FOUND"}
        return
    if name != "transient":
        workflow.select(ACTION_B)
        workflow.complete(ACTION_B, "NOT_ATTEMPTED" if name == "same-target" else "SUCCEEDED")
    verify_terminal_evidence(workflow, name, expected_a)


def verify_terminal_evidence(workflow: Workflow, name: str, expected_a: str) -> None:
    original_receipts = {ACTION_A: workflow.frozen(ACTION_A)}
    if name == "same-target":
        assert workflow.call("status", ACTION_B)["target_rejection"] == "StaleApproval"
        assert workflow.call("receipt", ACTION_B) == {"status": "NOT_READY"}
    else:
        original_receipts[ACTION_B] = workflow.frozen(ACTION_B)
    before = len(workflow.receiver.requests)
    workflow.select(ACTION_A)
    workflow.complete(ACTION_A, expected_a)
    assert len(workflow.receiver.requests) == before
    assert workflow.call("select", ACTION_A, container="other") == {"error": "invalid_request"}
    assert workflow.call("select", "unapproved") == {"error": "unknown_identity"}
    terminal_statuses = {
        identity: workflow.call("status", identity) for identity in (ACTION_A, ACTION_B)
    }
    original_rows = workflow.journal()
    workflow.kill()
    workflow.start()
    for identity, expected_status in terminal_statuses.items():
        assert workflow.call("status", identity) == expected_status
    for identity, receipt in original_receipts.items():
        assert workflow.frozen(identity) == receipt
    assert workflow.journal() == original_rows
    assert len(workflow.receiver.requests) == before
    if name == "independent":
        reject_replacement_authority(workflow, original_receipts, original_rows)


def reject_replacement_authority(
    workflow: Workflow,
    original_receipts: dict[str, dict[str, Any]],
    original_rows: list[dict[str, Any]],
) -> None:
    workflow.kill()
    workflow.operator("replacement-a")
    original_grant = (workflow.root / "0.grant").read_bytes()
    (workflow.root / "0.grant").write_bytes((workflow.root / "replacement.grant").read_bytes())
    workflow.start()
    assert workflow.call("status", ACTION_A) == {"error": "operation_failure"}
    assert workflow.call("receipt", ACTION_A) == {"error": "operation_failure"}
    count = len(workflow.receiver.requests)
    workflow.select(ACTION_A)
    workflow.wait(lambda: (workflow.root / "execution-result").exists())
    assert (workflow.root / "execution-result").read_text() == "operation_failure"
    assert len(workflow.receiver.requests) == count
    assert workflow.frozen(ACTION_B) == original_receipts[ACTION_B]
    workflow.kill()
    (workflow.root / "0.grant").write_bytes(original_grant)
    workflow.start()
    assert workflow.frozen(ACTION_A) == original_receipts[ACTION_A]
    assert workflow.journal() == original_rows


def main() -> None:
    binary = build()
    names = [
        "independent",
        "same-target",
        "transient",
        "accepted",
        "authorized",
        "before-http",
        "after-http",
        "unknown-conflict",
        "unknown-independent",
    ]
    results = [run_case(binary, name) for name in names]
    evidence = {
        "source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip(),
        "prototype_sha256": {
            name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in SOURCES
        },
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "command": "python3 scripts/prototype-two-actions.py",
        "bounds": {"identities_per_run": 2, "execution_slots": 1, "http_requests_per_run_max": 100},
        "results": results,
        "limitations": [
            "not live Kubernetes",
            "test-only transport shim",
            "no power-loss proof",
            "no production adoption",
        ],
    }
    encoded = json.dumps(evidence, indent=2)
    assert len(encoded) < 512 * 1024
    print(encoded)


if __name__ == "__main__":
    main()
