#!/usr/bin/env python3
"""Explicit selected-artifact smoke and disposable installed-service qualification.

Authenticate and extract before invoking this program with Python isolated mode. This is
maintainer assurance, not a consumer verifier, installer or product authority input.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import http.server
import json
import os
import pathlib
import pwd
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from typing import BinaryIO, cast

BINARIES = {
    "ordinary": "bin/kapsel",
    "service": "libexec/kapsel/kapseld",
    "client": "bin/kapsel-service-client",
    "mcp_bridge": "bin/kapsel-service-mcp",
}
IMAGE = "registry.example/kapsel/agent-api@sha256:" + "0123456789abcdef" * 4
OLD_IMAGE = "registry.example/kapsel/agent-api@sha256:" + "a" * 64
OPERATION = "artifact-op-1"
SERVICE_DIAGNOSTIC_BYTES_MAX = 4096
FORBIDDEN = [b"SECRET_PROVIDER_CANARY", b"KUBECONFIG_AMBIENT_CANARY"]
DESTINATIONS = {
    "ordinary": pathlib.Path("/usr/bin/kapsel"),
    "service": pathlib.Path("/usr/libexec/kapsel/kapseld"),
    "client": pathlib.Path("/usr/bin/kapsel-service-client"),
    "mcp_bridge": pathlib.Path("/usr/bin/kapsel-service-mcp"),
}
PRIVATE_ROOTS = ("/etc/kapsel", "/var/lib/kapsel", "/run/kapsel")
GUIDE = "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md"
PROGRAM = "share/kapsel/qualification.py"


def run_bounded(
    arguments: Sequence[str | pathlib.Path],
    *,
    input_bytes: bytes | None = None,
    stdout_max: int,
    stderr_max: int,
    timeout: float,
    check: bool = False,
    env: Mapping[str, str] | None = None,
    cwd: pathlib.Path | None = None,
    user: int | None = None,
    group: int | None = None,
    extra_groups: Sequence[int] | None = None,
    umask: int = -1,
) -> subprocess.CompletedProcess[bytes]:
    command = [str(argument) for argument in arguments]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
        user=user,
        group=group,
        extra_groups=extra_groups,
        umask=umask,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    output = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    limits = {stdout_fd: stdout_max, stderr_fd: stderr_max}
    input_view = memoryview(input_bytes or b"")
    input_offset = 0
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            events = selector.select(remaining)
            if not events:
                continue
            for key, mask in events:
                stream = cast(BinaryIO, key.fileobj)
                file_descriptor = stream.fileno()
                if mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(file_descriptor, input_view[input_offset:])
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_view)
                    else:
                        input_offset += written
                    if input_offset == len(input_view) or written == 0:
                        selector.unregister(stream)
                        stream.close()
                    continue

                data = output[file_descriptor]
                allowance = limits[file_descriptor] - len(data) + 1
                chunk = os.read(file_descriptor, min(8192, max(1, allowance)))
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if len(data) + len(chunk) > limits[file_descriptor]:
                    raise RuntimeError("subprocess output exceeded its byte bound")
                data.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        returncode = process.wait(timeout=remaining)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    result = subprocess.CompletedProcess(
        command, returncode, bytes(output[stdout_fd]), bytes(output[stderr_fd])
    )
    if check and returncode != 0:
        raise RuntimeError("subprocess command failed")
    return result


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ServiceStderrDrain:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stderr is not None
        self.process = process
        self.source = process.stderr
        self.diagnostic = bytearray()
        self.overflow = False
        self.read_failed = False
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        try:
            self.thread.start()
        except BaseException:
            self.source.close()
            raise

    def _drain(self) -> None:
        try:
            os.set_blocking(self.source.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(self.source, selectors.EVENT_READ)
                while not self.stopping.is_set():
                    if not selector.select(0.1):
                        continue
                    remaining = SERVICE_DIAGNOSTIC_BYTES_MAX - len(self.diagnostic)
                    chunk = os.read(self.source.fileno(), min(1024, remaining + 1))
                    if not chunk:
                        return
                    self.diagnostic.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self.overflow = True
                        self.process.kill()
                        return
        except OSError:
            self.read_failed = True
        finally:
            self.source.close()

    def finish(self) -> None:
        if self.thread.ident is None:
            return
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            self.read_failed = True
            self.stopping.set()
            self.thread.join(timeout=1)

    def failed(self) -> bool:
        return self.overflow or self.read_failed


def read_bounded_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise RuntimeError("release input is not a bounded regular file")
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("release input exceeded its byte bound")
    return data


def deployment(resource_version: str, generation: int, observed: bool) -> bytes:
    metadata: dict[str, object] = {
        "name": "agent-api",
        "namespace": "demo",
        "uid": "artifact-deployment-uid",
        "resourceVersion": resource_version,
        "generation": generation,
    }
    value: dict[str, object] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata,
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {
                "metadata": {"labels": {"app": "agent-api"}},
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "image": OLD_IMAGE if generation == 1 else IMAGE,
                        }
                    ]
                },
            },
        },
    }
    if observed:
        metadata["annotations"] = {"kapsel.dev/kap0038-operation-id": OPERATION}
        value["status"] = {
            "observedGeneration": 2,
            "updatedReplicas": 1,
            "availableReplicas": 1,
            "unavailableReplicas": 0,
            "conditions": [
                {
                    "type": "Available",
                    "status": "True",
                    "reason": "MinimumReplicasAvailable",
                }
            ],
        }
    return json.dumps(value, separators=(",", ":")).encode()


class KubernetesFixture(http.server.BaseHTTPRequestHandler):
    receiver_responses: list[bytes] = []
    requests = 0
    mutations = 0

    def log_message(self, format: str, *arguments: object) -> None:
        del format, arguments

    def respond(self) -> None:
        type(self).requests += 1
        if not type(self).receiver_responses:
            self.send_error(500)
            return
        body = type(self).receiver_responses.pop(0)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = respond

    def do_PATCH(self) -> None:
        type(self).mutations += 1
        patch = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
        expected = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "artifact-deployment-uid",
                "resourceVersion": "1",
                "annotations": {"kapsel.dev/kap0038-operation-id": OPERATION},
            },
            "spec": {"template": {"spec": {"containers": [{"name": "api", "image": IMAGE}]}}},
        }
        path = "/apis/apps/v1/namespaces/demo/deployments/agent-api"
        if patch != expected or self.path not in (path, path + "?"):
            self.send_error(400)
            return
        self.respond()


def reset_kubernetes_fixture() -> None:
    KubernetesFixture.receiver_responses = [
        deployment("1", 1, False),
        deployment("2", 2, False),
        deployment("3", 2, True),
    ]
    KubernetesFixture.requests = 0
    KubernetesFixture.mutations = 0


def run_binary(binary: pathlib.Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    result = run_bounded(
        [binary, *arguments],
        stdout_max=64 * 1024,
        stderr_max=4 * 1024,
        timeout=60,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "KUBECONFIG": "KUBECONFIG_AMBIENT_CANARY"},
    )
    for canary in FORBIDDEN:
        if canary in result.stdout or canary in result.stderr:
            raise RuntimeError("installed binary disclosed a canary")
    return result


def exercise_mcp(binary: pathlib.Path, version: str, caller_uid: int, caller_gid: int) -> None:
    """Cross the installed ID-only bridge without acquiring new receiver facts."""
    messages = [
        {
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "artifact-smoke", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": {
                "name": "kapsel.get_status",
                "arguments": {"operation_id": OPERATION},
            },
        },
    ]
    process = run_bounded(
        [binary],
        input_bytes=b"".join(
            json.dumps(message, separators=(",", ":")).encode() + b"\n" for message in messages
        ),
        stdout_max=3 * 96 * 1024,
        stderr_max=1,
        timeout=30,
        user=caller_uid,
        group=caller_gid,
        extra_groups=[],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    if process.returncode or process.stderr:
        raise RuntimeError("installed service MCP lifecycle failed")
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    if len(responses) != 3 or responses[0]["result"]["serverInfo"] != {
        "name": "kapsel-service",
        "version": version,
    }:
        raise RuntimeError("installed bridge version disagrees with artifact metadata")
    tools = responses[1]["result"]["tools"]
    expected = {
        "kapsel.list_approved_actions",
        "kapsel.list_operation_history",
        "kapsel.get_status",
        "kapsel.get_receipt",
        "kapsel.submit",
    }
    if len(tools) != 5 or {tool["name"] for tool in tools} != expected:
        raise RuntimeError("installed bridge tool list is not fixed")
    for tool in tools:
        properties = set(tool["inputSchema"]["properties"])
        if properties != (
            {"after"} if tool["name"].startswith("kapsel.list_") else {"operation_id"}
        ):
            raise RuntimeError("installed bridge schema exposed authority fields")
    call = responses[2]["result"]
    if (
        call["isError"]
        or json.loads(call["content"][0]["text"])["service"]["status"] != "SUCCEEDED"
    ):
        raise RuntimeError("installed bridge changed the stored outcome")


def exercise_version(binary: pathlib.Path, expected_version: object) -> None:
    if not isinstance(expected_version, str):
        raise RuntimeError("release metadata package version is invalid")
    result = run_bounded(
        [binary, "--version"],
        check=True,
        stdout_max=128,
        stderr_max=1,
        timeout=10,
        env={},
    )
    if result.stdout != f"kapsel {expected_version}\n".encode() or result.stderr:
        raise RuntimeError("installed executable version identity disagrees")


def systemctl(*arguments: str) -> str:
    result = run_bounded(
        ["systemctl", *arguments],
        check=True,
        stdout_max=64 * 1024,
        stderr_max=16 * 1024,
        timeout=60,
    )
    return result.stdout.decode().strip()


def refuse_systemd_references(parent: pathlib.Path) -> None:
    # Include dangling enablement links and aliases, without adopting or deleting them.
    for name in ("kapseld.service", "kapseld.service.d"):
        if os.path.lexists(parent / name):
            raise RuntimeError("native qualification refuses an existing unit or override")
    for path in [*parent.glob("*"), *parent.glob("*/*")]:
        if path.name == "kapseld.service" or (
            path.is_symlink() and path.resolve().name == "kapseld.service"
        ):
            raise RuntimeError("native qualification refuses existing service references")


def require_disabled_unit() -> None:
    result = run_bounded(
        ["systemctl", "is-enabled", "kapseld.service"],
        stdout_max=1024,
        stderr_max=1024,
        timeout=10,
    )
    if result.returncode != 1 or result.stdout.decode().strip() != "disabled":
        raise RuntimeError("qualification unit is not disabled")


def install_systemd_assets(root: pathlib.Path) -> tuple[int, int, int]:
    if (
        os.uname().machine != "x86_64"
        or pathlib.Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise RuntimeError("native qualification requires x86-64 Linux with systemd as PID 1")
    if pathlib.Path("/.dockerenv").exists():
        raise RuntimeError("native qualification refuses a Docker container")
    print("native architecture:", os.uname().machine)
    print(pathlib.Path("/etc/os-release").read_text().strip())
    print(systemctl("--version"))
    for name in ("kapsel", "kapsel-service-caller"):
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("native qualification refuses existing identities")
    for name in ("kapsel", "kapsel-service-callers"):
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("native qualification refuses existing groups")
    unit_paths = (
        run_bounded(
            ["systemd-analyze", "--system", "unit-paths"],
            check=True,
            stdout_max=64 * 1024,
            stderr_max=16 * 1024,
            timeout=10,
        )
        .stdout.decode()
        .splitlines()
    )
    if not unit_paths or any(not pathlib.Path(path).is_absolute() for path in unit_paths):
        raise RuntimeError("systemd unit search paths are unavailable")
    for parent in unit_paths:
        refuse_systemd_references(pathlib.Path(parent))
    if systemctl("show", "kapseld.service", "-p", "LoadState", "--value") != "not-found":
        raise RuntimeError("native qualification refuses a loaded service")
    subprocess.run(
        ["install", "-d", "-m", "0755", "/usr/share/kapsel", "/usr/share/doc/kapsel"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=10,
    )
    for document in (root / "share/doc/kapsel").iterdir():
        destination = pathlib.Path("/usr/share/doc/kapsel") / document.name
        with destination.open("xb") as output:
            output.write(document.read_bytes())
        destination.chmod(0o644)
        if destination.read_bytes() != document.read_bytes():
            raise RuntimeError("installed document identity differs")
    for asset, destination in (
        ("kapseld.service", "/usr/lib/systemd/system/kapseld.service"),
        ("kapseld.conf", "/usr/lib/sysusers.d/kapseld.conf"),
        ("kapseld-rbac.yaml", "/usr/share/kapsel/kapseld-rbac.yaml"),
    ):
        path = pathlib.Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write((root / "share/kapsel" / asset).read_bytes())
        path.chmod(0o644)
        if path.read_bytes() != (root / "share/kapsel" / asset).read_bytes():
            raise RuntimeError("installed native asset identity differs")
    subprocess.run(
        ["systemd-sysusers", "/usr/lib/sysusers.d/kapseld.conf"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    subprocess.run(
        [
            "useradd",
            "--system",
            "--no-create-home",
            "--gid",
            "kapsel-service-callers",
            "--shell",
            "/usr/sbin/nologin",
            "kapsel-service-caller",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    systemctl("daemon-reload")
    require_disabled_unit()
    return (
        pwd.getpwnam("kapsel").pw_uid,
        pwd.getpwnam("kapsel-service-caller").pw_uid,
        grp.getgrnam("kapsel-service-callers").gr_gid,
    )


def exercise_journald_failure() -> None:
    # No operator document exists yet. This must fail closed and emit only the fixed category.
    subprocess.run(
        ["systemctl", "start", "kapseld.service"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    deadline = time.monotonic() + 10
    while systemctl("show", "kapseld.service", "-p", "ActiveState", "--value") != "failed":
        if time.monotonic() >= deadline:
            raise RuntimeError("unprovisioned native service did not fail closed")
        time.sleep(0.05)
    invocation = systemctl("show", "kapseld.service", "-p", "InvocationID", "--value")
    if len(invocation) != 32 or any(value not in "0123456789abcdef" for value in invocation):
        raise RuntimeError("native service invocation identity is unavailable")
    subprocess.run(
        ["journalctl", "--sync"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    diagnostic = run_bounded(
        ["journalctl", f"_SYSTEMD_INVOCATION_ID={invocation}", "--output=cat", "--no-pager"],
        check=True,
        stdout_max=64 * 1024,
        stderr_max=16 * 1024,
        timeout=30,
    ).stdout
    if b"provisioning_unavailable" not in diagnostic or any(
        value in diagnostic for value in FORBIDDEN
    ):
        raise RuntimeError("native journald provisioning diagnostic missing or unsafe")
    systemctl("stop", "kapseld.service")
    print("Broken setup: startup failed with provisioning_unavailable (operator document absent).")
    print("Diagnosis: systemctl status kapseld.service; journalctl -u kapseld.service")
    print("Next: prepare and publish the explicit approval, then start the service.")


def service_client(binary: pathlib.Path, arguments: list[str], uid: int, gid: int) -> dict:
    result = run_bounded(
        [binary, *arguments],
        stdout_max=64 * 1024,
        stderr_max=1,
        user=uid,
        group=gid,
        extra_groups=[],
        timeout=10,
    )
    if result.returncode != 0 or result.stderr:
        raise RuntimeError("artifact service client failed")
    if any(canary in result.stdout for canary in FORBIDDEN):
        raise RuntimeError("artifact service client disclosed private material")
    response = json.loads(result.stdout)
    if response.get("version") != 1:
        raise RuntimeError("artifact service protocol identity changed")
    return response


def selected_artifact(root: pathlib.Path, revision: str) -> dict:
    """Bind already authenticated extracted inputs before any installation or process launch."""
    metadata = json.loads(read_bounded_regular(root / "RELEASE-METADATA.json", 16 * 1024))
    if metadata["source_revision"] != revision:
        raise RuntimeError("qualification source revision differs")
    if metadata["source_dirty"]:
        raise RuntimeError("qualification requires a clean committed-source artifact")
    for name, relative in BINARIES.items():
        value = read_bounded_regular(root / relative, 32 * 1024 * 1024)
        if (len(value), hashlib.sha256(value).hexdigest()) != (
            metadata[f"{name}_binary_bytes"],
            metadata[f"{name}_binary_sha256"],
        ):
            raise RuntimeError("selected binary identity differs")
    for relative in (
        PROGRAM,
        GUIDE,
        "share/kapsel/kapseld.service",
        "share/kapsel/kapseld.conf",
        "share/kapsel/kapseld-rbac.yaml",
    ):
        identity = metadata["asset_files"][relative]
        value = read_bounded_regular(root / relative, 128 * 1024)
        if (len(value), hashlib.sha256(value).hexdigest()) != (
            identity["bytes"],
            identity["sha256"],
        ):
            raise RuntimeError("selected qualification asset identity differs")
    if read_bounded_regular(pathlib.Path(__file__), 128 * 1024) != read_bounded_regular(
        root / PROGRAM, 128 * 1024
    ):
        raise RuntimeError("qualification must execute the selected authenticated program")
    return metadata


def executable_smoke(root: pathlib.Path, metadata: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="kapsel-executable-smoke-") as temporary:
        binary = pathlib.Path(temporary) / "kapsel"
        shutil.copyfile(root / BINARIES["ordinary"], binary)
        binary.chmod(0o755)
        if sha256(binary) != metadata["ordinary_binary_sha256"]:
            raise RuntimeError("copied executable identity differs")
        exercise_version(binary, metadata["package_version"])
        help_result = run_binary(binary, ["--help"])
        if help_result.returncode or any(
            command in help_result.stdout for command in (b"kapsel operate", b"kapsel mcp --")
        ):
            raise RuntimeError("artifact help advertises retired execution")
        for command in ("operate", "mcp"):
            if run_binary(binary, [command, "--operator-config", "/unavailable"]).returncode != 2:
                raise RuntimeError("artifact accepts retired direct execution")
        binary.unlink()
        if binary.exists():
            raise RuntimeError("smoke did not remove its copied executable")
    print("Extracted executable smoke: ok", flush=True)


def guide_block(guide: str, name: str, language: str = "sh") -> str:
    matches = re.findall(rf"<!-- example-{name} -->\s*```{language}\n(.*?)\n```", guide, re.S)
    if len(matches) != 1:
        raise RuntimeError(f"packaged guide block {name} is not unique")
    return matches[0]


def execute_guide(guide: str, name: str, workspace: pathlib.Path) -> bytes:
    result = run_bounded(
        ["/bin/sh", "-eu", "-c", guide_block(guide, name)],
        cwd=workspace,
        stdout_max=64 * 1024,
        stderr_max=4096,
        timeout=30,
        check=True,
        env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if result.stderr:
        raise RuntimeError("packaged guide command emitted unexpected diagnostics")
    return result.stdout


def install(root: pathlib.Path, native: bool) -> tuple[int, int, int]:
    """Fresh disposable setup. Failure retains its partial installation, never rolls history back."""
    if os.geteuid() != 0 or (not native and not pathlib.Path("/.dockerenv").is_file()):
        raise RuntimeError("installed qualification requires root and a disposable environment")
    paths = [
        *PRIVATE_ROOTS,
        *DESTINATIONS.values(),
        "/usr/libexec/kapsel",
        "/usr/share/kapsel",
        "/usr/share/doc/kapsel",
        "/usr/lib/sysusers.d/kapseld.conf",
        "/var/lib/kapsel-installer",
        "/run/lock/kapsel-installer.lock",
        "/tmp/kapsel-artifact-receipt-0",
        "/tmp/kapsel-artifact-receipt-1",
    ]
    if any(os.path.lexists(path) for path in paths):
        raise RuntimeError("qualification refuses existing installation or state")
    if native:
        identities = install_systemd_assets(root)
    else:
        for name in ("kapsel", "kapsel-service-caller"):
            try:
                pwd.getpwnam(name)
            except KeyError:
                pass
            else:
                raise RuntimeError("qualification refuses existing identities")
        for name in ("kapsel", "kapsel-service-callers"):
            try:
                grp.getgrnam(name)
            except KeyError:
                pass
            else:
                raise RuntimeError("qualification refuses existing groups")
        run_bounded(
            ["groupadd", "--gid", "61000", "kapsel-service-callers"],
            stdout_max=1024,
            stderr_max=4096,
            timeout=10,
            check=True,
        )
        for name, uid in (("kapsel", "61000"), ("kapsel-service-caller", "61001")):
            run_bounded(
                [
                    "useradd",
                    "--uid",
                    uid,
                    "--no-create-home",
                    "--gid",
                    "kapsel-service-callers",
                    "--shell",
                    "/usr/sbin/nologin",
                    name,
                ],
                stdout_max=1024,
                stderr_max=4096,
                timeout=10,
                check=True,
            )
        identities = (61000, 61001, 61000)
    service_uid, caller_uid, caller_gid = identities
    if service_uid == caller_uid or 0 in (service_uid, caller_uid):
        raise RuntimeError("qualification requires distinct unprivileged identities")
    for name, destination in DESTINATIONS.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        value = read_bounded_regular(root / BINARIES[name], 32 * 1024 * 1024)
        with destination.open("xb") as output:
            output.write(value)
        destination.chmod(0o755)
        if destination.read_bytes() != value:
            raise RuntimeError("installed executable identity differs")
    for path in PRIVATE_ROOTS:
        directory = pathlib.Path(path)
        directory.mkdir(mode=0o750 if path == "/run/kapsel" else 0o700)
        os.chown(directory, service_uid, caller_gid)
    if native:
        exercise_journald_failure()
    return identities


class InstalledService:
    """Two fixed launch profiles, not a lifecycle or receiver abstraction."""

    def __init__(self, native: bool, uid: int, gid: int) -> None:
        self.native = native
        self.uid, self.gid = uid, gid
        self.process: subprocess.Popen[bytes] | None = None
        self.drain: ServiceStderrDrain | None = None

    def start(self) -> None:
        if self.native:
            systemctl("start", "kapseld.service")
        else:
            self.process = subprocess.Popen(
                [
                    DESTINATIONS["service"],
                    "--operator-config",
                    "/etc/kapsel/operator.json",
                    "--socket",
                    "/run/kapsel/kapseld.sock",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                user=self.uid,
                group=self.gid,
                extra_groups=[],
                umask=0o077,
            )
            self.drain = ServiceStderrDrain(self.process)
            self.drain.start()

    def stop(self) -> None:
        if self.native:
            systemctl("stop", "kapseld.service")
            if (
                systemctl("show", "kapseld.service", "-p", "MainPID", "--value"),
                systemctl("show", "kapseld.service", "-p", "ActiveState", "--value"),
            ) != ("0", "inactive"):
                raise RuntimeError("native service did not retire")
        elif self.process is not None:
            process, drain = self.process, self.drain
            try:
                process.terminate()
                process.wait(timeout=30)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
            finally:
                if drain is not None:
                    drain.finish()
                self.process = self.drain = None
            if process.returncode != 0 or drain is None or drain.failed():
                raise RuntimeError("direct service did not retire gracefully")


def installed_service(root: pathlib.Path, metadata: dict, native: bool) -> None:
    uid, caller_uid, gid = install(root, native)
    guide = (root / GUIDE).read_text()
    service = InstalledService(native, uid, gid)
    reset_kubernetes_fixture()
    KubernetesFixture.receiver_responses.insert(0, deployment("1", 1, False))
    receiver = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KubernetesFixture)
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    # The root operator owns the workspace; neither the service nor caller can traverse it.
    with tempfile.TemporaryDirectory(prefix="kapsel-operator-") as temporary:
        workspace = pathlib.Path(temporary)
        try:
            execute_guide(guide, "keys", workspace)
            expected = json.loads(deployment("1", 1, False))
            for field in ("uid", "resourceVersion", "generation"):
                del expected["metadata"][field]
            if json.loads(guide_block(guide, "deployment", "json")) != expected:
                raise RuntimeError("guide deployment differs from the concrete receiver")
            authorization = guide_block(guide, "authorization", "json")
            (workspace / "authorization.json").write_text(authorization)
            (workspace / "kubeconfig.yaml").write_text(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n"
                f"  cluster:\n    server: http://127.0.0.1:{receiver.server_port}\n"
                "contexts:\n- name: fixture\n  context:\n    cluster: fixture\n    user: fixture\n"
                "current-context: fixture\nusers:\n- name: fixture\n  user: {}\n"
            )
            prepared = execute_guide(guide, "prepare", workspace)
            if b'"status":"PREPARED"' not in prepared.replace(b" ", b""):
                raise RuntimeError("guide did not prepare the candidate")
            if (KubernetesFixture.requests, KubernetesFixture.mutations) != (1, 0):
                raise RuntimeError("guide preparation did not read exactly one snapshot")
            if (workspace / "approval.seed").read_bytes() == (
                workspace / "receipt.seed"
            ).read_bytes():
                raise RuntimeError("guide did not create separate keys")
            for name in (
                "approval.seed",
                "receipt.seed",
                "approval.pub",
                "receipt.pub",
                "receipt.trust",
            ):
                if (workspace / name).stat().st_mode & 0o777 != 0o600:
                    raise RuntimeError("guide material is not private")
            candidate = workspace / "operator.candidate.json"
            document = candidate.read_bytes()
            configuration = json.loads(document)
            if (
                configuration["authorization_keys"]
                != [
                    {
                        "key_id": "approval-key-1",
                        "public_key_hex": (workspace / "approval.pub").read_bytes().hex(),
                    }
                ]
                or configuration["receipt_signing_key_id"] != "receipt-key-1"
            ):
                raise RuntimeError("guide configuration selected different material")
            if execute_guide(guide, "publish", workspace) != b"PUBLISHED\n":
                raise RuntimeError("guide cold publication failed")
            if pathlib.Path("/etc/kapsel/operator.json").read_bytes() != document:
                raise RuntimeError("published bytes differ from the guide candidate")
            trust = pathlib.Path("/etc/kapsel/example-receipt.trust")
            shutil.copyfile(workspace / "receipt.trust", trust)
            trust.chmod(0o600)
            evaluation = (workspace / "evaluation-time.txt").read_text().strip()
            pathlib.Path("/etc/kapsel/example-evaluation-time.txt").write_text(evaluation + "\n")

            def read(arguments: list[str]) -> dict:
                return service_client(DESTINATIONS["client"], arguments, caller_uid, gid)

            def wait(command: list[str], status: str) -> dict:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if service.process is not None and service.process.poll() is not None:
                        raise RuntimeError("installed service exited")
                    try:
                        response = read(command)
                        if response.get("status") == status:
                            return response
                    except RuntimeError:
                        pass
                    time.sleep(0.02)
                raise RuntimeError("installed service did not expose the expected stored read")

            service.start()
            wait(["list"], "READY")
            if read(["history"])["entries"] or KubernetesFixture.requests != 1:
                raise RuntimeError("startup/history read contacted the receiver or adopted history")
            socket = pathlib.Path("/run/kapsel/kapseld.sock").stat()
            if (stat.S_IMODE(socket.st_mode), socket.st_uid, socket.st_gid) != (0o660, uid, gid):
                raise RuntimeError("installed socket custody differs")
            denied = run_bounded(
                [sys.executable, "-I", "-c", "open('/etc/kapsel/operator.json','rb')"],
                user=caller_uid,
                group=gid,
                extra_groups=[],
                stdout_max=1024,
                stderr_max=4096,
                timeout=5,
            )
            if denied.returncode == 0 or b"PermissionError" not in denied.stderr:
                raise RuntimeError("caller accessed private material")
            if read(["submit", OPERATION]) != {
                "version": 1,
                "status": "ADMITTED",
                "phase": "requested",
            }:
                raise RuntimeError("installed client did not select the guide approval")
            original_status = wait(["status", OPERATION], "SUCCEEDED")
            exercise_mcp(DESTINATIONS["mcp_bridge"], metadata["package_version"], caller_uid, gid)
            receipt = pathlib.Path("/tmp/kapsel-artifact-receipt-0")
            read(["receipt", OPERATION, str(receipt)])
            frozen = receipt.read_bytes()
            export = run_bounded(
                [DESTINATIONS["client"], "receipt", OPERATION, receipt],
                user=caller_uid,
                group=gid,
                extra_groups=[],
                stdout_max=65536,
                stderr_max=4096,
                timeout=10,
            )
            if export.returncode == 0 or receipt.read_bytes() != frozen:
                raise RuntimeError("receipt export overwrote an existing destination")
            inspection = run_binary(
                DESTINATIONS["ordinary"],
                [
                    "inspect",
                    "--receipt",
                    str(receipt),
                    "--trust",
                    str(trust),
                    "--evaluation-time-unix-s",
                    evaluation,
                ],
            )
            report = json.loads(inspection.stdout)
            if inspection.returncode or (
                report["status"],
                report["result"],
                report["operation_id"],
            ) != ("INSPECTED", "SUCCEEDED", OPERATION):
                raise RuntimeError("installed inspection did not bind original approved evidence")
            for key, value in {
                "authorization_id": "approval-1",
                "authorization_signer_key_id": "approval-key-1",
                "immutable_image_digest": IMAGE,
                "target_uid": "artifact-deployment-uid",
                "target_resource_version": "1",
                "observed_operation_marker": OPERATION,
                "approved_target": {"uid": "artifact-deployment-uid", "resource_version": "1"},
            }.items():
                if report[key] != value:
                    raise RuntimeError("installed receipt changed original approved evidence")
            service.stop()
            journal = pathlib.Path("/var/lib/kapsel/journal.sqlite3")
            retained = journal.read_bytes()
            configuration["approvals"][0]["label"] = "After cold replacement"
            candidate.write_text(json.dumps(configuration))
            if (
                execute_guide(guide, "publish", workspace) != b"PUBLISHED\n"
                or journal.read_bytes() != retained
            ):
                raise RuntimeError("cold publication changed retained history")
            service.start()
            catalog = wait(["list"], "READY")
            if "After cold replacement" not in json.dumps(catalog):
                raise RuntimeError("restart did not load the cold replacement")
            if read(["status", OPERATION]) != original_status:
                raise RuntimeError("read-first restart changed the original outcome")
            read(["history"])
            repeated = pathlib.Path("/tmp/kapsel-artifact-receipt-1")
            read(["receipt", OPERATION, str(repeated)])
            if repeated.read_bytes() != frozen:
                raise RuntimeError("restart changed original receipt bytes")
            service.stop()
            if journal.read_bytes() != retained or (
                KubernetesFixture.requests,
                KubernetesFixture.mutations,
            ) != (4, 1):
                raise RuntimeError("installed reads changed history or acquired receiver facts")
            if native:
                require_disabled_unit()
            print(
                "Installed guide: one PATCH; cold read-first restart; original receipt; stopped retained state",
                flush=True,
            )
        finally:
            try:
                service.stop()
            finally:
                receiver.shutdown()
                receiver.server_close()
                thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--profile", required=True, choices=("smoke", "direct", "systemd"))
    arguments = parser.parse_args()
    root = arguments.artifact.absolute()
    metadata = selected_artifact(root, arguments.expected_revision)
    if arguments.profile == "smoke":
        executable_smoke(root, metadata)
    else:
        installed_service(root, metadata, arguments.profile == "systemd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
