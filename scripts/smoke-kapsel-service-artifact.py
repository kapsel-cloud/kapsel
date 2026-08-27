#!/usr/bin/env python3
"""Exercise only extracted Kapsel service artifact files in a clean Linux container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading

SOCKET = pathlib.Path("/run/kapsel/kapseld.sock")
IMAGE = (
    "registry.example/agent-api@sha256:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def receive_exact(stream: socket.socket, length: int) -> bytes:
    value = b""
    while len(value) < length:
        chunk = stream.recv(length - len(value))
        if not chunk:
            raise RuntimeError("client request ended early")
        value += chunk
    return value


def exchange(binary: pathlib.Path, arguments: list[str], expected: dict[str, object], response: bytes):
    SOCKET.unlink(missing_ok=True)
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(SOCKET))
                os.chmod(SOCKET, 0o660)
                listener.listen(1)
                stream, _ = listener.accept()
                with stream:
                    length = int.from_bytes(receive_exact(stream, 4), "big")
                    body = receive_exact(stream, length)
                    if stream.recv(1) != b"":
                        raise RuntimeError("client request has trailing bytes")
                    if json.loads(body) != expected:
                        raise RuntimeError("client request changed")
                    stream.sendall(len(response).to_bytes(4, "big") + response)
                    stream.shutdown(socket.SHUT_WR)
        except BaseException as error:  # noqa: BLE001 - thread transports exact failure
            failures.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
    finally:
        thread.join(timeout=10)
        SOCKET.unlink(missing_ok=True)
    if thread.is_alive() or failures:
        raise RuntimeError(f"service client fixture failed: {failures}")
    return result


def smoke(root: pathlib.Path, expected_kapsel_version: str) -> None:
    if SOCKET.parent.exists():
        raise RuntimeError("Kapsel service artifact smoke requires an absent /run/kapsel")
    SOCKET.parent.mkdir(mode=0o750)
    client = root / "bin/kapsel-service-client"
    kapsel = root / "bin/kapsel"
    daemon = root / "libexec/kapsel/kapseld"
    version = subprocess.run(
        [str(kapsel), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    if version.stdout != f"kapsel {expected_kapsel_version}\n".encode() or version.stderr:
        raise RuntimeError("Kapsel service artifact kapsel identity changed")
    invalid_daemon = subprocess.run(
        [str(daemon)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    if invalid_daemon.returncode != 4 or invalid_daemon.stdout or invalid_daemon.stderr:
        raise RuntimeError("service daemon fixed argv boundary changed")

    status_request = {"request": "get_set_deployment_image_status", "operation_id": "service-op"}
    status = exchange(client, ["status", "service-op"], status_request, b'{"status":"UNKNOWN"}')
    if status.returncode != 0 or status.stdout != b'{"status":"UNKNOWN"}\n' or status.stderr:
        raise RuntimeError("service client status path changed")

    submit_request = {
        "request": "submit_set_deployment_image",
        "operation_id": "service-op",
        "namespace": "demo",
        "deployment": "agent-api",
        "container": "api",
        "immutable_image_digest": IMAGE,
    }
    submitted = exchange(
        client,
        ["submit", "service-op", "demo", "agent-api", "api", IMAGE],
        submit_request,
        b'{"status":"ACCEPTED"}',
    )
    if submitted.returncode != 0 or submitted.stdout != b'{"status":"ACCEPTED"}\n':
        raise RuntimeError("service client submit path changed")

    receipt_bytes = b"exact frozen receipt bytes"
    digest = hashlib.sha256(receipt_bytes).hexdigest()
    response = json.dumps(
        {
            "status": "READY",
            "receipt_hex": receipt_bytes.hex(),
            "receipt_sha256": digest,
        },
        separators=(",", ":"),
    ).encode()
    with tempfile.TemporaryDirectory(prefix="kapsel-service-smoke-") as temporary:
        output = pathlib.Path(temporary) / "receipt"
        receipt_request = {
            "request": "get_set_deployment_image_receipt",
            "operation_id": "service-op",
        }
        previous_umask = os.umask(0o777)
        try:
            retrieved = exchange(
                client,
                ["receipt", "service-op", str(output)],
                receipt_request,
                response,
            )
        finally:
            os.umask(previous_umask)
        report = json.loads(retrieved.stdout)
        if (
            retrieved.returncode != 0
            or output.read_bytes() != receipt_bytes
            or output.stat().st_mode & 0o777 != 0o600
            or report
            != {"status": "READY", "receipt_sha256": digest, "output": str(output)}
        ):
            raise RuntimeError("service client exact receipt path changed")
        refused = exchange(
            client,
            ["receipt", "service-op", str(output)],
            receipt_request,
            response,
        )
        if refused.returncode != 4 or output.read_bytes() != receipt_bytes:
            raise RuntimeError("service client replaced an existing receipt")
    SOCKET.parent.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extracted-root", required=True, type=pathlib.Path)
    parser.add_argument("--expected-kapsel-version", required=True)
    arguments = parser.parse_args()
    smoke(arguments.extracted_root.resolve(), arguments.expected_kapsel_version)
    print("Kapsel service artifact smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
