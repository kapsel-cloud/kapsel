#!/usr/bin/env python3
"""Execute the extracted Kapsel release artifact in a clean Linux environment."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time

IMAGE = (
    "registry.example/kapsel/agent-api@sha256:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
OLD_IMAGE = (
    "registry.example/kapsel/agent-api@sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
OPERATION = "artifact-op-1"
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663"
)
SMOKE_IMAGE = (
    "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
)
NON_CLAIMS = "not-production;no-stable-cli;no-stable-receipt;no-other-targets"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024
FILE_BYTES_MAX = 32 * 1024 * 1024
AUTHORIZATION_PUBLIC_KEY = bytes.fromhex(
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
)
FORBIDDEN = [
    b"SECRET_PROVIDER_CANARY",
    bytes([9]) * 32,
    b"KUBECONFIG_AMBIENT_CANARY",
]


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_bounded_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise RuntimeError("release input is not a bounded regular file")
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("release input exceeded its byte bound")
    return data


def verify_checksum(archive: pathlib.Path, checksum: pathlib.Path) -> bytes:
    checksum_bytes = read_bounded_regular(checksum, 256)
    archive_bytes = read_bounded_regular(archive, ARCHIVE_BYTES_MAX)
    expected = f"{hashlib.sha256(archive_bytes).hexdigest()}  {archive.name}\n".encode()
    if checksum_bytes != expected:
        raise RuntimeError("release archive checksum mismatch")
    return archive_bytes


def validate_archive(archive: pathlib.Path, archive_bytes: bytes) -> dict[str, object]:
    suffix = f"-{TARGET}.tar.gz"
    if not archive.name.startswith("kapsel-") or not archive.name.endswith(suffix):
        raise RuntimeError("release archive name does not identify the supported target")
    version = archive.name[len("kapsel-") : -len(suffix)]
    if not version:
        raise RuntimeError("release archive name has no package version")
    basename = archive.name.removesuffix(".tar.gz")
    expected = {
        f"{basename}/",
        f"{basename}/bin/",
        f"{basename}/bin/kapsel",
        f"{basename}/libexec/",
        f"{basename}/libexec/kapsel-demo-harness",
        f"{basename}/share/",
        f"{basename}/share/kapsel/",
        f"{basename}/share/kapsel/demo-kind-crash-recovery.sh",
        f"{basename}/share/kapsel/kap0038-trust.hex",
        f"{basename}/share/doc/",
        f"{basename}/share/doc/kapsel/",
        f"{basename}/share/doc/kapsel/EVALUATOR.md",
        f"{basename}/CHANGELOG.md",
        f"{basename}/LICENSE",
        f"{basename}/RELEASE-METADATA.json",
    }
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as release:
        members: list[tarfile.TarInfo] = []
        for member in release:
            members.append(member)
            if len(members) > len(expected):
                raise RuntimeError("release archive has too many entries")
        names = {member.name + ("/" if member.isdir() else "") for member in members}
        ordered_names = [member.name for member in members]
        if names != expected or ordered_names != sorted(ordered_names):
            raise RuntimeError("release archive layout or ordering is not canonical")
        expanded_size = sum(member.size for member in members if member.isfile())
        if expanded_size > EXPANDED_BYTES_MAX:
            raise RuntimeError("release archive exceeds its expanded bound")
        for member in members:
            if member.isfile() and member.size > FILE_BYTES_MAX:
                raise RuntimeError("release archive entry exceeds its file bound")
            identity = (member.uid, member.gid, member.uname, member.gname, member.mtime)
            if identity != (0, 0, "", "", 0):
                raise RuntimeError("release archive metadata is not normalized")
            executable = member.isdir() or member.name.endswith(
                ("/kapsel", "/kapsel-demo-harness", ".sh")
            )
            expected_mode = 0o755 if executable else 0o644
            if member.mode != expected_mode:
                raise RuntimeError("release archive mode is not canonical")
        metadata_file = release.extractfile(f"{basename}/RELEASE-METADATA.json")
        license_file = release.extractfile(f"{basename}/LICENSE")
        ordinary = release.extractfile(f"{basename}/bin/kapsel")
        demonstration = release.extractfile(f"{basename}/libexec/kapsel-demo-harness")
        if any(
            value is None for value in (metadata_file, license_file, ordinary, demonstration)
        ):
            raise RuntimeError("release archive evidence could not be read")
        metadata_bytes = metadata_file.read()
        license_bytes = license_file.read()
        ordinary_bytes = ordinary.read()
        demonstration_bytes = demonstration.read()
    if not metadata_bytes.endswith(b"\n"):
        raise RuntimeError("release metadata has no trailing newline")
    metadata = json.loads(metadata_bytes)
    expected_keys = [
        "artifact_schema",
        "package_version",
        "rust_target",
        "source_revision",
        "source_dirty",
        "license",
        "license_sha256",
        "builder_image",
        "smoke_image",
        "ordinary_binary_sha256",
        "demo_binary_sha256",
        "non_claims",
    ]
    if list(metadata) != expected_keys:
        raise RuntimeError("release metadata fields or order changed")
    if metadata["artifact_schema"] != "kapsel.release-artifact.v1":
        raise RuntimeError("release metadata schema changed")
    if metadata["package_version"] != version or metadata["rust_target"] != TARGET:
        raise RuntimeError("release metadata disagrees with archive identity")
    revision = metadata["source_revision"]
    invalid_revision = (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    )
    if invalid_revision:
        raise RuntimeError("release source revision is not canonical")
    if not isinstance(metadata["source_dirty"], bool):
        raise RuntimeError("release dirty state is not boolean")
    license_digest = hashlib.sha256(license_bytes).hexdigest()
    if metadata["license"] != "Apache-2.0" or metadata["license_sha256"] != license_digest:
        raise RuntimeError("release license provenance disagrees")
    if metadata["builder_image"] != BUILDER_IMAGE or metadata["smoke_image"] != SMOKE_IMAGE:
        raise RuntimeError("release container provenance disagrees")
    if metadata["non_claims"] != NON_CLAIMS:
        raise RuntimeError("release non-claims changed")
    if metadata["ordinary_binary_sha256"] != hashlib.sha256(ordinary_bytes).hexdigest():
        raise RuntimeError("release ordinary binary digest disagrees")
    if metadata["demo_binary_sha256"] != hashlib.sha256(demonstration_bytes).hexdigest():
        raise RuntimeError("release demo binary digest disagrees")
    return metadata


def extract_exact_archive(
    archive: pathlib.Path,
    archive_bytes: bytes,
    destination: pathlib.Path,
) -> pathlib.Path:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as release:
        members = release.getmembers()
        top_levels = {pathlib.PurePosixPath(member.name).parts[0] for member in members}
        if len(top_levels) != 1:
            raise RuntimeError("release archive must have one top-level directory")
        top_level = top_levels.pop()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise RuntimeError("release archive contains an unsafe entry")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("release archive file could not be read")
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode)
            else:
                raise RuntimeError("release archive contains an unsupported entry")
    return destination / top_level


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
    responses: list[bytes] = []
    requests = 0

    def log_message(self, format: str, *arguments: object) -> None:
        del format, arguments

    def respond(self) -> None:
        type(self).requests += 1
        if not type(self).responses:
            self.send_error(500)
            return
        body = type(self).responses.pop(0)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = respond
    do_PATCH = respond


def reset_kubernetes_fixture() -> None:
    KubernetesFixture.responses = [
        deployment("1", 1, False),
        deployment("2", 2, False),
        deployment("3", 2, True),
    ]
    KubernetesFixture.requests = 0


def write_private(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def run_binary(binary: pathlib.Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [str(binary), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "KUBECONFIG": "KUBECONFIG_AMBIENT_CANARY"},
    )
    if len(result.stdout) > 64 * 1024 or len(result.stderr) > 4 * 1024:
        raise RuntimeError("installed binary output exceeded its bound")
    for canary in FORBIDDEN:
        if canary in result.stdout or canary in result.stderr:
            raise RuntimeError("installed binary disclosed a canary")
    return result


def prepare_inputs(root: pathlib.Path, server_address: tuple[str, int]) -> dict[str, pathlib.Path]:
    receipts = root / "receipts"
    receipts.mkdir(mode=0o700)
    authorization = root / "authorization.json"
    request = root / "request.json"
    operator = root / "operator.json"
    write_private(
        authorization,
        json.dumps(
            {
                "authorization_id": "artifact-auth-1",
                "operation_id": OPERATION,
                "namespace": "demo",
                "deployment": "agent-api",
                "container": "api",
                "immutable_image_digest": IMAGE,
            },
            separators=(",", ":"),
        ).encode(),
    )
    write_private(
        request,
        json.dumps(
            {
                "operation_id": OPERATION,
                "namespace": "demo",
                "deployment": "agent-api",
                "container": "api",
                "immutable_image_digest": IMAGE,
            },
            separators=(",", ":"),
        ).encode(),
    )
    write_private(root / "authorization.seed", bytes([9]) * 32)
    write_private(root / "authorization.pub", AUTHORIZATION_PUBLIC_KEY)
    write_private(root / "receipt.seed", bytes([9]) * 32)
    host, port = server_address
    write_private(
        root / "kubeconfig.yaml",
        (
            "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n"
            f"  cluster:\n    server: http://{host}:{port}\n"
            "contexts:\n- name: fixture\n  context:\n"
            "    cluster: fixture\n    user: fixture\ncurrent-context: fixture\n"
            "users:\n- name: fixture\n  user: {}\n"
        ).encode(),
    )
    return {
        "authorization": authorization,
        "request": request,
        "operator": operator,
        "receipts": receipts,
    }


def write_operator(
    root: pathlib.Path,
    grant: pathlib.Path,
    receipts: pathlib.Path,
    receipt_seed: pathlib.Path,
    receipt_key_id: str,
    output: pathlib.Path,
) -> None:
    write_private(
        output,
        json.dumps(
            {
                "signed_authorization_grant": str(grant),
                "authorization_key_id": "artifact-authorization-key",
                "authorization_public_key": str(root / "authorization.pub"),
                "kubeconfig": str(root / "kubeconfig.yaml"),
                "journal": str(root / "journal.sqlite3"),
                "receipt_directory": str(receipts),
                "receipt_signing_seed": str(receipt_seed),
                "receipt_signing_key_id": receipt_key_id,
            },
            separators=(",", ":"),
        ).encode(),
    )


def provision_and_write_operator(
    binary: pathlib.Path,
    root: pathlib.Path,
    paths: dict[str, pathlib.Path],
) -> None:
    grant = root / "grant.bin"
    provision = run_binary(
        binary,
        [
            "provision-grant",
            "--authorization",
            str(paths["authorization"]),
            "--signing-seed",
            str(root / "authorization.seed"),
            "--signing-key-id",
            "artifact-authorization-key",
            "--output",
            str(grant),
        ],
    )
    if provision.returncode != 0 or b'"status":"PROVISIONED"' not in provision.stdout:
        raise RuntimeError("installed grant provisioning failed")
    write_operator(
        root,
        grant,
        paths["receipts"],
        root / "receipt.seed",
        "kap0038-test-key",
        paths["operator"],
    )


def execute_and_restart(binary: pathlib.Path, paths: dict[str, pathlib.Path]) -> pathlib.Path:
    arguments = [
        "operate",
        "--request",
        str(paths["request"]),
        "--operator-config",
        str(paths["operator"]),
    ]
    first = run_binary(binary, arguments)
    if first.returncode != 0:
        raise RuntimeError("installed operation failed")
    report = json.loads(first.stdout)
    if report["state"] != "FINALIZED" or report["result"] != "SUCCEEDED":
        raise RuntimeError("installed operation returned the wrong outcome")
    restarted = run_binary(binary, arguments)
    if restarted.returncode != 0 or json.loads(restarted.stdout) != report:
        raise RuntimeError("installed ordinary restart changed the report")
    receipts = list(paths["receipts"].glob("*.receipt"))
    if len(receipts) != 1:
        raise RuntimeError("installed operation did not publish exactly one receipt")
    return receipts[0]


def wait_for_marker(process: subprocess.Popen[bytes], marker: pathlib.Path) -> None:
    deadline = time.monotonic() + 15
    while not marker.exists():
        if process.poll() is not None:
            raise RuntimeError("installed demo process exited before its marker")
        if time.monotonic() >= deadline:
            raise RuntimeError("installed demo marker timed out")
        time.sleep(0.02)


def kill_demo_at_seam(
    binary: pathlib.Path,
    paths: dict[str, pathlib.Path],
    control: pathlib.Path,
    seam: str,
    marker: pathlib.Path,
    log: pathlib.Path,
) -> None:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "KAPSEL_DEMO_CONTROL_DIRECTORY": str(control),
        "KAPSEL_DEMO_PAUSE": seam,
    }
    with log.open("wb") as output:
        process = subprocess.Popen(
            [
                str(binary),
                "operate",
                "--request",
                str(paths["request"]),
                "--operator-config",
                str(paths["operator"]),
            ],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        try:
            wait_for_marker(process, marker)
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    if process.returncode == 0 or log.stat().st_size > 64 * 1024:
        raise RuntimeError("installed demo seam did not fail within bounds")


def exercise_demo_binary(
    binary: pathlib.Path,
    artifact_root: pathlib.Path,
    temporary_root: pathlib.Path,
) -> None:
    reset_kubernetes_fixture()
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KubernetesFixture)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    evaluation = temporary_root / "demo-evaluation"
    evaluation.mkdir(mode=0o700)
    control = evaluation / "control"
    control.mkdir(mode=0o700)
    try:
        paths = prepare_inputs(evaluation, fixture.server_address)
        provision_and_write_operator(binary, evaluation, paths)
        kill_demo_at_seam(
            binary,
            paths,
            control,
            "after_apply",
            control / "after-apply.ready",
            evaluation / "after-apply.log",
        )
        if control.joinpath("provider-apply-count").read_text() != "1":
            raise RuntimeError("installed demo repeated its provider mutation")
        kill_demo_at_seam(
            binary,
            paths,
            control,
            "after_receipt_publish",
            control / "after-receipt-publish.ready",
            evaluation / "after-publication.log",
        )
        if KubernetesFixture.requests != 3:
            raise RuntimeError("installed demo recovery repeated provider activity")
        receipts = list(paths["receipts"].glob("*.receipt"))
        if len(receipts) != 1:
            raise RuntimeError("installed demo did not freeze one receipt")
        frozen = receipts[0].read_bytes()

        rotated_receipts = evaluation / "rotated-receipts"
        rotated_receipts.mkdir(mode=0o700)
        rotated_seed = evaluation / "rotated.seed"
        write_private(rotated_seed, bytes([8]) * 32)
        rotated_operator = evaluation / "rotated-operator.json"
        write_operator(
            evaluation,
            evaluation / "grant.bin",
            rotated_receipts,
            rotated_seed,
            "rotated-receipt-key",
            rotated_operator,
        )
        finalized = run_binary(
            binary,
            [
                "operate",
                "--request",
                str(paths["request"]),
                "--operator-config",
                str(rotated_operator),
            ],
        )
        final_report = json.loads(finalized.stdout) if finalized.returncode == 0 else {}
        if final_report.get("state") != "FINALIZED" or final_report.get("result") != "SUCCEEDED":
            raise RuntimeError("installed demo did not finalize the receiver outcome after restart")
        if control.joinpath("provider-apply-count").read_text() != "1":
            raise RuntimeError("installed demo changed its provider apply count")
        if receipts[0].read_bytes() != frozen or any(rotated_receipts.iterdir()):
            raise RuntimeError("installed demo changed frozen receipt settings")
        trust = evaluation / "receipt.trust"
        trust_hex = artifact_root.joinpath(
            "share", "kapsel", "kap0038-trust.hex"
        ).read_text().strip()
        write_private(trust, bytes.fromhex(trust_hex))
        inspect_receipt(binary, receipts[0], trust)
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)
        shutil.rmtree(evaluation)


def inspect_receipt(binary: pathlib.Path, receipt: pathlib.Path, trust: pathlib.Path) -> None:
    inspection = run_binary(
        binary,
        [
            "inspect",
            "--receipt",
            str(receipt),
            "--trust",
            str(trust),
            "--evaluation-time-unix-s",
            "150",
        ],
    )
    if inspection.returncode != 0:
        raise RuntimeError("installed offline inspection failed")
    report = json.loads(inspection.stdout)
    if report["status"] != "INSPECTED" or report["result"] != "SUCCEEDED":
        raise RuntimeError("installed offline inspection returned the wrong result")
    if b"VERIFIED" in inspection.stdout:
        raise RuntimeError("installed offline inspection emitted forbidden vocabulary")


def exercise_mcp(binary: pathlib.Path, operator: pathlib.Path, version: str) -> None:
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
                "name": "kubernetes.set_deployment_image",
                "arguments": {
                    "operation_id": OPERATION,
                    "namespace": "demo",
                    "deployment": "agent-api",
                    "container": "api",
                    "immutable_image_digest": IMAGE,
                },
            },
        },
    ]
    input_bytes = b"".join(
        json.dumps(message, separators=(",", ":")).encode() + b"\n" for message in messages
    )
    process = subprocess.run(
        [str(binary), "mcp", "--operator-config", str(operator)],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    if process.returncode != 0 or process.stderr:
        raise RuntimeError("installed MCP lifecycle failed")
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    if responses[0]["result"]["serverInfo"] != {"name": "kapsel", "version": version}:
        raise RuntimeError("installed MCP version disagrees with artifact metadata")
    tools = responses[1]["result"]["tools"]
    if len(tools) != 1 or tools[0]["name"] != "kubernetes.set_deployment_image":
        raise RuntimeError("installed MCP tool list is not fixed")
    properties = set(tools[0]["inputSchema"]["properties"])
    expected = {
        "operation_id",
        "namespace",
        "deployment",
        "container",
        "immutable_image_digest",
    }
    if properties != expected:
        raise RuntimeError("installed MCP tool schema exposed the wrong fields")
    call = responses[2]["result"]
    if call["isError"] or json.loads(call["content"][0]["text"])["result"] != "SUCCEEDED":
        raise RuntimeError("installed MCP call changed the application outcome")


def smoke(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    expected_revision: str | None = None,
) -> None:
    archive_bytes = verify_checksum(archive, checksum)
    metadata = validate_archive(archive, archive_bytes)
    if expected_revision is not None and metadata["source_revision"] != expected_revision:
        raise RuntimeError("release source revision disagrees with the expected revision")
    with tempfile.TemporaryDirectory(prefix="kapsel-clean-smoke-") as temporary:
        root = extract_exact_archive(archive, archive_bytes, pathlib.Path(temporary))
        binary = root / "bin" / "kapsel"
        if sha256(binary) != metadata["ordinary_binary_sha256"]:
            raise RuntimeError("installed ordinary binary digest mismatch")
        if sha256(root / "libexec" / "kapsel-demo-harness") != metadata["demo_binary_sha256"]:
            raise RuntimeError("installed demo binary digest mismatch")

        reset_kubernetes_fixture()
        fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KubernetesFixture)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        evaluation = pathlib.Path(temporary) / "evaluation"
        evaluation.mkdir(mode=0o700)
        try:
            paths = prepare_inputs(evaluation, fixture.server_address)
            provision_and_write_operator(binary, evaluation, paths)
            receipt = execute_and_restart(binary, paths)
            if KubernetesFixture.requests != 3:
                raise RuntimeError("installed ordinary restart repeated provider activity")
            trust = evaluation / "receipt.trust"
            trust_hex = root.joinpath("share", "kapsel", "kap0038-trust.hex").read_text().strip()
            write_private(trust, bytes.fromhex(trust_hex))
            inspect_receipt(binary, receipt, trust)
            exercise_mcp(binary, paths["operator"], metadata["package_version"])
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=5)
        shutil.rmtree(evaluation)
        if evaluation.exists():
            raise RuntimeError("artifact smoke did not clean its evaluation directory")
        exercise_demo_binary(
            root / "libexec" / "kapsel-demo-harness",
            root,
            pathlib.Path(temporary),
        )


def run_live_demo(archive: pathlib.Path, checksum: pathlib.Path) -> None:
    archive_bytes = verify_checksum(archive, checksum)
    validate_archive(archive, archive_bytes)
    with tempfile.TemporaryDirectory(prefix="kapsel-live-artifact-") as temporary:
        root = extract_exact_archive(archive, archive_bytes, pathlib.Path(temporary))
        subprocess.run(
            [str(root / "share" / "kapsel" / "demo-kind-crash-recovery.sh")],
            cwd=root,
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--live-demo", action="store_true")
    arguments = parser.parse_args()
    archive = arguments.archive.resolve()
    checksum = archive.with_name(archive.name + ".sha256")
    if arguments.live_demo:
        run_live_demo(archive, checksum)
        print("Kapsel release artifact live demo: ok")
    else:
        smoke(archive, checksum, arguments.expected_revision)
        print("Kapsel release artifact smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
