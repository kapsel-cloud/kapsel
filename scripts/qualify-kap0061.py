#!/usr/bin/env python3
"""Run the frozen KAP-0061 x86-64 measurement workloads with bounded JSON output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

IMAGE = "i" * 440 + "@sha256:" + "0" * 64
OPERATION_ID = "o" * 128
AUTHORIZATION_ID = "a" * 128
NAMESPACE = "n" * 63
DEPLOYMENT = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
CONTAINER = "c" * 63
AUTHORIZATION_KEY_ID = "qualification-authorization-key"
AUTHORIZATION_PUBLIC_KEY = bytes.fromhex(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
)
WARMUPS = 5
SAMPLES = 30
IMAGE_DIGEST = (
    "registry.example/qualification@sha256:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=True, **kwargs)


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)


def private_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def maximum_authorization() -> dict[str, str]:
    return {
        "authorization_id": AUTHORIZATION_ID,
        "operation_id": OPERATION_ID,
        "namespace": NAMESPACE,
        "deployment": DEPLOYMENT,
        "container": CONTAINER,
        "immutable_image_digest": IMAGE,
    }


def ordinary_request() -> dict[str, str]:
    return {
        "operation_id": "qualification-op-1",
        "namespace": "demo",
        "deployment": "agent-api",
        "container": "api",
        "immutable_image_digest": IMAGE_DIGEST,
    }


def write_kubeconfig(path: Path, address: tuple[str, int]) -> None:
    private_file(
        path,
        (
            "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n"
            f"  cluster:\n    server: http://{address[0]}:{address[1]}\n"
            "contexts:\n- name: fixture\n"
            "  context:\n    cluster: fixture\n    user: fixture\n"
            "current-context: fixture\nusers:\n- name: fixture\n  user: {}\n"
        ).encode(),
    )


def provision(binary: Path, root: Path, authorization: dict[str, str]) -> None:
    authorization_path = root / "authorization.json"
    seed_path = root / "authorization.seed"
    private_file(
        authorization_path,
        json.dumps(authorization, separators=(",", ":")).encode(),
    )
    private_file(seed_path, bytes([7]) * 32)
    run(
        [
            str(binary),
            "provision-grant",
            "--authorization",
            str(authorization_path),
            "--signing-seed",
            str(seed_path),
            "--signing-key-id",
            AUTHORIZATION_KEY_ID,
            "--output",
            str(root / "grant.bin"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def operator_fixture(
    binary: Path,
    root: Path,
    address: tuple[str, int],
    request: dict[str, str],
) -> tuple[Path, Path]:
    private_directory(root)
    receipts = root / "receipts"
    private_directory(receipts)
    authorization = dict(request)
    authorization["authorization_id"] = "qualification-auth-1"
    provision(binary, root, authorization)
    private_file(root / "authorization.pub", AUTHORIZATION_PUBLIC_KEY)
    private_file(root / "receipt.seed", bytes([42]) * 32)
    write_kubeconfig(root / "kubeconfig.yaml", address)
    request_path = root / "request.json"
    private_file(request_path, json.dumps(request, separators=(",", ":")).encode())
    operator_path = root / "operator.json"
    operator = {
        "signed_authorization_grant": str(root / "grant.bin"),
        "authorization_key_id": AUTHORIZATION_KEY_ID,
        "authorization_public_key": str(root / "authorization.pub"),
        "kubeconfig": str(root / "kubeconfig.yaml"),
        "journal": str(root / "journal.sqlite3"),
        "receipt_directory": str(receipts),
        "receipt_signing_seed": str(root / "receipt.seed"),
        "receipt_signing_key_id": "qualification-receipt-key",
    }
    private_file(operator_path, json.dumps(operator, separators=(",", ":")).encode())
    return request_path, operator_path


def deployment_response(
    request: dict[str, str], resource_version: str, receiver: bool
) -> bytes:
    metadata: dict[str, Any] = {
        "name": request["deployment"],
        "namespace": request["namespace"],
        "uid": "deployment-uid-1",
        "resourceVersion": resource_version,
        "generation": 2 if receiver else 1,
    }
    image = request["immutable_image_digest"] if receiver else IMAGE_DIGEST.replace("0", "a")
    if receiver:
        metadata["annotations"] = {
            "kapsel.dev/kap0038-operation-id": request["operation_id"]
        }
    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata,
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {
                "metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{"name": request["container"], "image": image}]},
            },
        },
    }
    if receiver:
        document["status"] = {
            "observedGeneration": 2,
            "updatedReplicas": 1,
            "availableReplicas": 1,
            "unavailableReplicas": 0,
            "conditions": [
                {"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable"}
            ],
        }
    return json.dumps(document, separators=(",", ":")).encode()


class FixtureServer:
    def __init__(self, responses: list[bytes]) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.address = self.listener.getsockname()
        self.responses = responses
        self.methods: list[str] = []
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            for body in self.responses:
                connection, _ = self.listener.accept()
                with connection:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    self.methods.append(data.split(b" ", 1)[0].decode("ascii"))
                    header = (
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                        + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode()
                    )
                    connection.sendall(header + body)
        except BaseException as error:  # surfaced by finish
            self.error = error
        finally:
            self.listener.close()

    def finish(self) -> None:
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("fixture server did not consume its finite response plan")
        if self.error is not None:
            raise self.error


def sample_child(command: list[str], stdin_bytes: bytes = b"") -> dict[str, int]:
    payload = json.dumps({"command": command, "stdin_hex": stdin_bytes.hex()})
    completed = run(
        [sys.executable, __file__, "--sample", payload],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = json.loads(completed.stdout)
    if set(result) != {"wall_us", "cpu_us", "rss_bytes", "returncode", "stdout_bytes", "stderr_bytes"}:
        raise RuntimeError("measurement wrapper returned an unexpected shape")
    return result


def one_sample(payload: str) -> None:
    request = json.loads(payload)
    command = request["command"]
    stdin_bytes = bytes.fromhex(request["stdin_hex"])
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    completed = subprocess.run(command, input=stdin_bytes, capture_output=True, check=False)
    elapsed = (time.monotonic_ns() - started) // 1000
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_us = int(
        ((after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)) * 1_000_000
    )
    rss_bytes = int(after.ru_maxrss) * 1024
    output = {
        "wall_us": elapsed,
        "cpu_us": cpu_us,
        "rss_bytes": rss_bytes,
        "returncode": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
    }
    sys.stdout.write(json.dumps(output, separators=(",", ":")))


def record(
    measurements: dict[str, list[dict[str, int]]],
    name: str,
    result: dict[str, int],
    expected_code: int,
) -> None:
    if result["returncode"] != expected_code:
        raise RuntimeError(f"{name} returned {result['returncode']}, expected {expected_code}")
    measurements.setdefault(name, []).append(result)


def run_internal_test(repo: Path, test_name: str, marker: str) -> Any:
    completed = run(
        [
            "cargo",
            "test",
            "--release",
            "--locked",
            "-p",
            "kapsel",
            "--lib",
            test_name,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "CARGO_TARGET_DIR": "/tmp/kap0061-target"},
    )
    line = next(line for line in completed.stdout.decode().splitlines() if line.startswith(marker))
    return json.loads(line.removeprefix(marker))


def run_internal_measurements(repo: Path) -> dict[str, list[int]]:
    return run_internal_test(
        repo,
        "gateway::tests::qualification::kap0061_internal_phase_measurements",
        "KAP0061_MEASUREMENTS=",
    )


def measure(repo: Path, output: Path) -> None:
    target = Path("/tmp/kap0061-target")
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    run(["cargo", "build", "--release", "--locked", "-p", "kapsel"], cwd=repo, env=environment)
    ordinary = Path("/tmp/kap0061-kapsel")
    shutil.copy2(target / "release/kapsel", ordinary)
    run(
        ["cargo", "build", "--release", "--locked", "-p", "kapsel", "--features", "demo-harness"],
        cwd=repo,
        env=environment,
    )
    demonstration = Path("/tmp/kap0061-kapsel-demo")
    shutil.copy2(target / "release/kapsel", demonstration)

    measurements: dict[str, list[dict[str, int]]] = {}
    with tempfile.TemporaryDirectory(prefix="kap0061-measure-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        receipt = root / "canonical.receipt"
        trust = root / "canonical.trust"
        private_file(receipt, bytes.fromhex((repo / "vectors/kap0038-receipt.hex").read_text().strip()))
        private_file(trust, bytes.fromhex((repo / "vectors/kap0038-trust.hex").read_text().strip()))

        for index in range(WARMUPS + SAMPLES):
            result = sample_child([str(ordinary)])
            if index >= WARMUPS:
                record(measurements, "process_startup", result, 2)

            grant_root = root / f"grant-{index}"
            private_directory(grant_root)
            authorization_path = grant_root / "authorization.json"
            seed_path = grant_root / "seed"
            private_file(
                authorization_path,
                json.dumps(maximum_authorization(), separators=(",", ":")).encode(),
            )
            private_file(seed_path, bytes([7]) * 32)
            command = [
                str(ordinary),
                "provision-grant",
                "--authorization",
                str(authorization_path),
                "--signing-seed",
                str(seed_path),
                "--signing-key-id",
                AUTHORIZATION_KEY_ID,
                "--output",
                str(grant_root / "grant.bin"),
            ]
            result = sample_child(command)
            if index >= WARMUPS:
                record(measurements, "grant_provision", result, 0)

            result = sample_child(
                [
                    str(ordinary),
                    "inspect",
                    "--receipt",
                    str(receipt),
                    "--trust",
                    str(trust),
                    "--evaluation-time-unix-s",
                    "150",
                ]
            )
            if index >= WARMUPS:
                record(measurements, "offline_inspection", result, 0)

            fresh_root = root / f"fresh-{index}"
            request_path, operator_path = operator_fixture(
                ordinary, fresh_root, ("127.0.0.1", 9), ordinary_request()
            )
            _ = request_path
            result = sample_child(
                [str(ordinary), "mcp", "--operator-config", str(operator_path)]
            )
            if index >= WARMUPS:
                record(measurements, "journal_fresh_open", result, 0)
            result = sample_child(
                [str(ordinary), "mcp", "--operator-config", str(operator_path)]
            )
            if index >= WARMUPS:
                record(measurements, "journal_marked_open", result, 0)

            request = ordinary_request()
            success_server = FixtureServer(
                [
                    deployment_response(request, "1", False),
                    deployment_response(request, "2", True),
                    deployment_response(request, "3", True),
                ]
            )
            success_root = root / f"success-{index}"
            request_path, operator_path = operator_fixture(
                ordinary, success_root, success_server.address, request
            )
            result = sample_child(
                [
                    str(ordinary),
                    "operate",
                    "--request",
                    str(request_path),
                    "--operator-config",
                    str(operator_path),
                ]
            )
            success_server.finish()
            if success_server.methods.count("PATCH") != 1:
                raise RuntimeError("complete_success did not perform exactly one patch")
            if index >= WARMUPS:
                record(measurements, "complete_success", result, 0)

            recovery_request = ordinary_request()
            recovery_server = FixtureServer(
                [
                    deployment_response(recovery_request, "1", False),
                    deployment_response(recovery_request, "2", True),
                ]
            )
            recovery_root = root / f"recovery-{index}"
            recovery_request_path, recovery_operator_path = operator_fixture(
                ordinary, recovery_root, recovery_server.address, recovery_request
            )
            marker = recovery_root / "after-apply.ready"
            demo_environment = {
                **os.environ,
                "KAPSEL_DEMO_CONTROL_DIRECTORY": str(recovery_root),
                "KAPSEL_DEMO_PAUSE": "after_apply",
            }
            child = subprocess.Popen(
                [
                    str(demonstration),
                    "operate",
                    "--request",
                    str(recovery_request_path),
                    "--operator-config",
                    str(recovery_operator_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=demo_environment,
            )
            deadline = time.monotonic() + 10
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not marker.exists():
                child.kill()
                child.wait()
                raise RuntimeError("demonstration process did not reach after_apply")
            child.kill()
            child.wait()
            recovery_server.finish()
            if recovery_server.methods.count("PATCH") != 1:
                raise RuntimeError("recovery setup did not perform exactly one patch")
            observe_server = FixtureServer([deployment_response(recovery_request, "3", True)])
            write_kubeconfig(recovery_root / "kubeconfig.yaml", observe_server.address)
            result = sample_child(
                [
                    str(ordinary),
                    "operate",
                    "--request",
                    str(recovery_request_path),
                    "--operator-config",
                    str(recovery_operator_path),
                ]
            )
            observe_server.finish()
            if "PATCH" in observe_server.methods:
                raise RuntimeError("complete_recovery performed a second patch")
            if index >= WARMUPS:
                record(measurements, "complete_recovery", result, 0)

    internal = run_internal_measurements(repo)
    growth = run_internal_test(
        repo,
        "gateway::tests::qualification::kap0061_journal_growth_measurement",
        "KAP0061_GROWTH=",
    )
    result = {
        "schema_version": 1,
        "warmups": WARMUPS,
        "samples": SAMPLES,
        "process_measurements": measurements,
        "internal_wall_us": internal,
        "growth": growth,
        "wire_sizes": {
            "canonical_grant_bytes": len(bytes.fromhex((repo / "vectors/kap0038-grant.hex").read_text().strip())),
            "canonical_receipt_bytes": len(bytes.fromhex((repo / "vectors/kap0038-receipt.hex").read_text().strip())),
            "canonical_statement_bytes": len(bytes.fromhex((repo / "vectors/kap0038-statement.hex").read_text().strip())),
            "canonical_trust_bytes": len(bytes.fromhex((repo / "vectors/kap0038-trust.hex").read_text().strip())),
        },
        "binary": {
            "ordinary_sha256": hashlib.sha256(ordinary.read_bytes()).hexdigest(),
            "ordinary_bytes": ordinary.stat().st_size,
            "demo_sha256": hashlib.sha256(demonstration.read_bytes()).hexdigest(),
            "demo_bytes": demonstration.stat().st_size,
        },
    }
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.sample is not None:
        one_sample(arguments.sample)
        return
    if arguments.output is None:
        parser.error("--output is required")
    measure(Path.cwd(), arguments.output)


if __name__ == "__main__":
    main()
