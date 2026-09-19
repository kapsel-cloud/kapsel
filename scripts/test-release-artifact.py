#!/usr/bin/env python3
"""Black-box smoke tests for the assembled Kapsel release artifact."""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "assemble-release-artifact.py"
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
RELEASE_ARCHIVE: pathlib.Path | None = None
EXAMPLE_REVISION: str | None = None


def release_archive() -> pathlib.Path:
    if RELEASE_ARCHIVE is None:
        raise RuntimeError("--archive is required")
    return RELEASE_ARCHIVE


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


SMOKE_SPEC = importlib.util.spec_from_file_location(
    "smoke_release_artifact",
    ROOT / "scripts" / "smoke-release-artifact.py",
)
if SMOKE_SPEC is None or SMOKE_SPEC.loader is None:
    raise RuntimeError("could not load the release verifier")
SMOKE = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(SMOKE)
ASSEMBLY_SPEC = importlib.util.spec_from_file_location("assemble_release_artifact", ASSEMBLER)
if ASSEMBLY_SPEC is None or ASSEMBLY_SPEC.loader is None:
    raise RuntimeError("could not load the release assembler")
ASSEMBLY = importlib.util.module_from_spec(ASSEMBLY_SPEC)
ASSEMBLY_SPEC.loader.exec_module(ASSEMBLY)


class ZeroReader(io.RawIOBase):
    def __init__(self, remaining: int) -> None:
        self.remaining = remaining

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:
        count = min(len(buffer), self.remaining)
        if count == 0:
            return 0
        buffer[:count] = b"\0" * count
        self.remaining -= count
        return count


def synthetic_archive(
    archive: pathlib.Path,
    *,
    mutate: str | None = None,
) -> bytes:
    basename = archive.name.removesuffix(".tar.gz")
    ordinary = b"ordinary"
    service = b"service"
    client = b"client"
    metadata = {
        "artifact_schema": "kapsel.release-artifact.v3",
        "package_version": "0.2.0",
        "rust_target": TARGET,
        "source_revision": "1" * 40,
        "source_tree": "2" * 40,
        "source_dirty": False,
        "cargo_lock_sha256": "3" * 64,
        "cargo_graph_sha256": "4" * 64,
        "cargo_package_count": 1,
        "cargo_relationship_count": 1,
        "license": "Apache-2.0",
        "license_sha256": hashlib.sha256(b"license").hexdigest(),
        "builder_image": BUILDER_IMAGE,
        "smoke_image": SMOKE_IMAGE,
        "ordinary_binary_bytes": len(ordinary),
        "ordinary_binary_sha256": hashlib.sha256(ordinary).hexdigest(),
        "service_binary_bytes": len(service),
        "service_binary_sha256": hashlib.sha256(service).hexdigest(),
        "client_binary_bytes": len(client),
        "client_binary_sha256": hashlib.sha256(client).hexdigest(),
        "non_claims": "service-preview;not-production;no-public-rust-api;no-other-targets",
    }
    files: dict[str, bytes | int] = {
        f"{basename}/bin/kapsel": ordinary,
        f"{basename}/libexec/kapsel/kapseld": service,
        f"{basename}/bin/kapsel-service-client": client,
        f"{basename}/share/kapsel/kapseld.service": b"unit\n",
        f"{basename}/share/kapsel/kapseld.conf": b"sysusers\n",
        f"{basename}/share/kapsel/kapseld-rbac.yaml": b"rbac\n",
        f"{basename}/share/doc/kapsel/COMMANDS.md": b"commands\n",
        f"{basename}/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md": b"operator\n",
        f"{basename}/share/doc/kapsel/KAPSEL_SERVICE.md": b"service\n",
        f"{basename}/share/doc/kapsel/PRIVACY.md": b"privacy\n",
        f"{basename}/share/doc/kapsel/RELEASE.md": b"release\n",
        f"{basename}/share/doc/kapsel/SECURITY.md": b"security\n",
        f"{basename}/share/doc/kapsel/UPGRADE.md": b"upgrade\n",
        f"{basename}/CHANGELOG.md": b"changelog\n",
        f"{basename}/LICENSE": b"license",
        f"{basename}/RELEASE-METADATA.json": (
            json.dumps(metadata, indent=2, separators=(",", ": ")) + "\n"
        ).encode(),
    }
    if mutate == "service-digest":
        files[f"{basename}/libexec/kapsel/kapseld"] = b"changed"
    if mutate == "client-digest":
        files[f"{basename}/bin/kapsel-service-client"] = b"changed"
    if mutate == "old-schema":
        metadata["artifact_schema"] = "kapsel.release-artifact.v2"
        files[f"{basename}/RELEASE-METADATA.json"] = (json.dumps(metadata) + "\n").encode()
    if mutate == "oversized-file":
        files[f"{basename}/CHANGELOG.md"] = 32 * 1024 * 1024 + 1
    if mutate == "oversized-expanded":
        for name in ["COMMANDS.md", "KAPSEL_SERVICE_OPERATOR.md", "KAPSEL_SERVICE.md"]:
            files[f"{basename}/share/doc/kapsel/{name}"] = 22 * 1024 * 1024
    directories = {
        f"{basename}/",
        f"{basename}/bin/",
        f"{basename}/libexec/",
        f"{basename}/libexec/kapsel/",
        f"{basename}/share/",
        f"{basename}/share/kapsel/",
        f"{basename}/share/doc/",
        f"{basename}/share/doc/kapsel/",
    }
    entries = sorted([*directories, *files])
    if mutate in {"extra", "traversal", "absolute", "duplicate"}:
        added = {
            "extra": f"{basename}/EXTRA",
            "traversal": f"{basename}/../escape",
            "absolute": "/escape",
            "duplicate": f"{basename}/CHANGELOG.md",
        }[mutate]
        entries.append(added)
        entries.sort()
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        archive_format = {
            "pax": tarfile.PAX_FORMAT,
            "gnu": tarfile.GNU_FORMAT,
        }.get(mutate, tarfile.USTAR_FORMAT)
        with tarfile.open(fileobj=compressed, mode="w", format=archive_format) as release:
            for name in entries:
                is_directory = name.endswith("/")
                information = tarfile.TarInfo(name)
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                information.mtime = 0
                information.mode = (
                    0o755
                    if is_directory
                    or name.endswith(("/kapsel", "/kapseld", "/kapsel-service-client"))
                    else 0o644
                )
                if mutate == "unsafe-mode" and name.endswith("/CHANGELOG.md"):
                    information.mode = 0o666
                if mutate == "executable-unit" and name.endswith("/kapseld.service"):
                    information.mode = 0o755
                if mutate == "pax" and name.endswith("/CHANGELOG.md"):
                    information.pax_headers = {"comment": "hidden extension"}
                if is_directory:
                    information.type = tarfile.DIRTYPE
                    release.addfile(information)
                    continue
                value = files.get(name, b"extra\n")
                if mutate in {"symlink", "hardlink", "special"} and name.endswith("/CHANGELOG.md"):
                    information.type = {
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "special": tarfile.CHRTYPE,
                    }[mutate]
                    information.linkname = "LICENSE"
                    release.addfile(information)
                    continue
                information.type = tarfile.REGTYPE
                if isinstance(value, int):
                    information.size = value
                    release.addfile(information, ZeroReader(value))
                else:
                    information.size = len(value)
                    release.addfile(information, io.BytesIO(value))
    return output.getvalue()


class ReleaseVerifierTests(unittest.TestCase):
    def test_native_qualification_preserves_and_refuses_dangling_enablement(self) -> None:
        for kind in ("wants", "requires", "alias", "linked-directory"):
            with (
                self.subTest(kind=kind),
                tempfile.TemporaryDirectory(prefix="kapsel-unit-reference-") as temporary,
            ):
                private = pathlib.Path(temporary)
                units = private / "units"
                units.mkdir()
                target = private / "vendor/kapseld.service"
                if kind == "alias":
                    link = units / "alias.service"
                else:
                    directory = units / (
                        "multi-user.target.requires"
                        if kind == "requires"
                        else "multi-user.target.wants"
                    )
                    if kind == "linked-directory":
                        external = private / "dependencies"
                        external.mkdir()
                        directory.symlink_to(external, target_is_directory=True)
                    else:
                        directory.mkdir()
                    link = directory / "kapseld.service"
                link.symlink_to(target)
                with self.assertRaisesRegex(RuntimeError, "existing service references"):
                    SMOKE.refuse_systemd_references(units)
                self.assertTrue(link.is_symlink())
                self.assertFalse(target.exists())

    def test_native_qualification_rejects_dirty_artifact_before_host_commands(self) -> None:
        with (
            mock.patch.object(
                SMOKE, "verified_release", return_value=(b"", {"source_dirty": True})
            ),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "clean committed-source"):
                SMOKE.smoke(
                    pathlib.Path("/unused"), pathlib.Path("/unused"), "0" * 40, service_systemd=True
                )
            command.assert_not_called()

    def test_native_qualification_refuses_wrong_platform_before_host_commands(self) -> None:
        with (
            mock.patch.object(SMOKE.os, "uname", return_value=SimpleNamespace(machine="aarch64")),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "x86-64 Linux"):
                SMOKE.install_systemd_assets(pathlib.Path("/unused"))
            command.assert_not_called()

    def test_service_qualification_refuses_unprivileged_invocation(self) -> None:
        with (
            mock.patch.object(SMOKE.os, "geteuid", return_value=1000),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                SMOKE.exercise_service(pathlib.Path("/unused"), pathlib.Path("/unused"), True)
            command.assert_not_called()

    def test_documented_bootstrap_never_executes_after_authentication_failure(self) -> None:
        document = ROOT.joinpath("docs/RELEASE.md").read_text()
        marker = "archive=kapsel-0.3.0-preview.1-x86_64-unknown-linux-gnu.tar.gz"
        block = marker + document.split(marker, 1)[1].split("```", 1)[0]
        with tempfile.TemporaryDirectory(prefix="kapsel-bootstrap-") as temporary:
            private = pathlib.Path(temporary)
            for name, code in {
                "cosign": 'exit "$AUTH_EXIT"',
                "sha256sum": 'exit "$CHECKSUM_EXIT"',
                "python3": ': > "$EXECUTED"',
            }.items():
                program = private / name
                program.write_text("#!/bin/sh\n" + code + "\n")
                program.chmod(0o755)
            for auth_exit, checksum_exit in [(1, 0), (0, 1), (0, 0)]:
                with self.subTest(auth=auth_exit, checksum=checksum_exit):
                    executed = private / "executed"
                    executed.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["/bin/sh", "-c", block],
                        cwd=private,
                        capture_output=True,
                        env={
                            "PATH": str(private),
                            "AUTH_EXIT": str(auth_exit),
                            "CHECKSUM_EXIT": str(checksum_exit),
                            "EXECUTED": str(executed),
                        },
                        timeout=5,
                        check=False,
                    )
                    successful = auth_exit == checksum_exit == 0
                    self.assertEqual(result.returncode == 0, successful)
                    self.assertEqual(executed.exists(), successful)

    def test_graph_includes_service_only_dependencies_but_not_dev_dependencies(self) -> None:
        packages = [
            {
                "id": name,
                "name": name,
                "version": "1.0.0",
                "source": None,
                "license": "MIT",
                "manifest_path": manifest,
            }
            for name, manifest in [
                ("kapsel", "/workspace/Cargo.toml"),
                ("kapseld", "/workspace/crates/kapseld/Cargo.toml"),
                ("service-only", "/registry/service-only/Cargo.toml"),
                ("test-only", "/registry/test-only/Cargo.toml"),
            ]
        ]
        nodes = [{"id": package["id"], "deps": []} for package in packages]
        nodes[1]["deps"] = [
            {"pkg": "kapsel", "dep_kinds": [{"kind": None}]},
            {"pkg": "service-only", "dep_kinds": [{"kind": "build"}]},
            {"pkg": "test-only", "dep_kinds": [{"kind": "dev"}]},
        ]
        graph, edges, root = ASSEMBLY.cargo_graph(
            {"packages": packages, "resolve": {"nodes": nodes}}
        )
        self.assertEqual(
            {package["name"] for package in graph}, {"kapsel", "kapseld", "service-only"}
        )
        self.assertEqual(len(edges), 2)
        self.assertEqual(root, "SPDXRef-Package-kapsel-source")

    def test_canonical_synthetic_archive_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-canonical-") as temporary:
            archive = pathlib.Path(temporary) / "kapsel-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
            metadata = SMOKE.validate_archive(archive, synthetic_archive(archive))
        self.assertEqual(metadata["package_version"], "0.2.0")

    def test_safe_extraction_negative_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-negative-") as temporary:
            archive = pathlib.Path(temporary) / "kapsel-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
            for mutation in [
                "service-digest",
                "client-digest",
                "old-schema",
                "executable-unit",
                "extra",
                "traversal",
                "absolute",
                "duplicate",
                "symlink",
                "hardlink",
                "special",
                "unsafe-mode",
                "oversized-file",
                "oversized-expanded",
                "pax",
                "gnu",
            ]:
                with self.subTest(mutation=mutation):
                    with self.assertRaises(RuntimeError):
                        SMOKE.validate_archive(archive, synthetic_archive(archive, mutate=mutation))

    def test_compressed_archive_size_excess_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-compressed-") as temporary:
            path = pathlib.Path(temporary) / "oversized.tar.gz"
            with path.open("wb") as output:
                output.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(RuntimeError):
                SMOKE.read_bounded_regular(path, 32 * 1024 * 1024)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlinks")
    def test_sidecar_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-sidecar-") as temporary:
            root = pathlib.Path(temporary)
            target = root / "target"
            target.write_text("value")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                SMOKE.read_bounded_regular(link, 256)


class ReleaseArtifactTests(unittest.TestCase):
    def test_documented_operator_example(self) -> None:
        """Execute guide preparation with extracted binaries and the existing HTTP fixture."""
        archive = release_archive()
        revision = (
            EXAMPLE_REVISION
            or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        )
        with tempfile.TemporaryDirectory(prefix="kapsel-doc-example-") as temporary:
            root = SMOKE.extract_release(
                archive,
                pathlib.Path(str(archive) + ".sha256"),
                revision,
                pathlib.Path(temporary) / "extracted",
            )
            # Only extracted binaries, their checksum-bound fixture and authored documentation
            # enter this container. No source build or private operator guidance is available.
            script = r"""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time

spec = importlib.util.spec_from_file_location("fixture", "/fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
guide = pathlib.Path("/guide.md").read_text()

def block(name, language):
    matches = re.findall(
        rf"<!-- example-{name} -->\s*```{language}\n(.*?)\n```", guide, re.S
    )
    assert len(matches) == 1, name
    return matches[0]

started = time.monotonic()
os.umask(0o077)
workspace = pathlib.Path(tempfile.mkdtemp(prefix="operator-"))
os.chdir(workspace)
binary = pathlib.Path("/usr/bin/kapsel")
shutil.copyfile("/artifact/bin/kapsel", binary)
binary.chmod(0o755)
client = pathlib.Path("/artifact/bin/kapsel-service-client")
service = pathlib.Path("/artifact/libexec/kapsel/kapseld")
subprocess.run(["sh", "-eu", "-c", block("keys", "sh")], check=True, timeout=30)
assert pathlib.Path("approval.seed").read_bytes() != pathlib.Path("receipt.seed").read_bytes()
for name in ("approval.seed", "receipt.seed", "approval.pub", "receipt.pub", "receipt.trust"):
    assert pathlib.Path(name).stat().st_mode & 0o777 == 0o600
target = json.loads(fixture.deployment("1", 1, False))
for field in ("uid", "resourceVersion", "generation"):
    del target["metadata"][field]
assert json.loads(block("deployment", "json")) == target
intent = json.loads(block("authorization", "json"))
assert intent["operation_id"] == fixture.OPERATION
assert intent["immutable_image_digest"] == fixture.IMAGE
pathlib.Path("authorization.json").write_text(json.dumps(intent))
fixture.reset_kubernetes_fixture()
fixture.KubernetesFixture.responses.insert(0, fixture.deployment("1", 1, False))
server = fixture.http.server.ThreadingHTTPServer(("127.0.0.1", 0), fixture.KubernetesFixture)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
pathlib.Path("kubeconfig.yaml").write_text(json.dumps({
    "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
    "clusters": [{"name": "fixture", "cluster": {
        "server": f"http://127.0.0.1:{server.server_port}"
    }}],
    "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
    "users": [{"name": "fixture", "user": {}}],
}))
process = None

def start():
    return subprocess.Popen(
        [str(service), "--operator-config", "/etc/kapsel/operator.json",
         "--socket", "/run/kapsel/kapseld.sock"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        user=61000, group=61000, extra_groups=[], umask=0o077,
    )

def read(command):
    return fixture.service_client(client, command, 61001, 61000)

def wait_for_read(command, predicate):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        assert process.poll() is None, "service exited"
        try:
            result = read(command)
        except RuntimeError:
            time.sleep(0.02)
            continue
        if predicate(result):
            return result
        time.sleep(0.02)
    raise AssertionError("documented operation did not reach expected state")

try:
    subprocess.run(["sh", "-eu", "-c", block("prepare", "sh")], check=True, timeout=30)
    assert fixture.KubernetesFixture.requests == 1
    assert fixture.KubernetesFixture.mutations == 0
    document = pathlib.Path("operator.candidate.json").read_bytes()
    config = json.loads(document)
    assert config == {
        "service_configuration_version": 1,
        "authorization_keys": [{"key_id": "approval-key-1",
            "public_key_hex": pathlib.Path("approval.pub").read_bytes().hex()}],
        "approvals": [{"label": "Approved image for agent-api",
            "signed_grant_hex": pathlib.Path("approval.grant").read_bytes().hex()}],
        "receipt_signing_key_id": "receipt-key-1",
    }
    subprocess.run([str(binary), "validate-service-config", "--operator-config",
                    "operator.candidate.json"], check=True, timeout=10)
    for path, mode in (("/etc/kapsel", 0o700), ("/var/lib/kapsel", 0o700),
                       ("/run/kapsel", 0o750)):
        pathlib.Path(path).mkdir(mode=mode)
        pathlib.Path(path).chmod(mode)
        os.chown(path, 61000, 61000)
    fixture.write_private(pathlib.Path("/etc/kapsel/kubeconfig.yaml"),
                          pathlib.Path("kubeconfig.yaml").read_bytes())
    os.chown("/etc/kapsel/kubeconfig.yaml", 61000, 61000)
    published = subprocess.run([str(service), "--replace-operator-config"], input=document,
        capture_output=True, user=61000, group=61000, extra_groups=[], timeout=30)
    assert (published.returncode, published.stdout, published.stderr) == (0, b"PUBLISHED\n", b"")
    print("Cold publication: PUBLISHED", flush=True)
    process = start()
    print("List:", json.dumps(wait_for_read(["list"], lambda r: r["status"] == "READY")), flush=True)
    assert read(["history"])["entries"] == []
    assert fixture.KubernetesFixture.requests == 1
    admitted = read(["submit", fixture.OPERATION])
    assert admitted == json.loads(block("admitted", "json"))
    print("Submit:", json.dumps(admitted), flush=True)
    stopped = wait_for_read(["status", fixture.OPERATION],
        lambda r: r.get("execution", {}).get("condition") == "signing_unavailable")
    assert stopped["status"] == "IN_PROGRESS"
    assert stopped["execution"] == json.loads(block("signing", "json"))
    assert fixture.KubernetesFixture.mutations == 1
    print("Signing unavailable:", json.dumps(stopped), flush=True)
    process.terminate()
    _, diagnostics = process.communicate(timeout=30)
    assert process.returncode == 0
    fixture.write_private(pathlib.Path("/etc/kapsel/receipt.seed"), pathlib.Path("receipt.seed").read_bytes())
    os.chown("/etc/kapsel/receipt.seed", 61000, 61000)
    before = fixture.KubernetesFixture.requests
    process = start()
    resumed = wait_for_read(["status", fixture.OPERATION],
        lambda r: r.get("execution", {}).get("disposition") == "resume_required")
    assert fixture.KubernetesFixture.requests == before
    assert resumed["execution"] == json.loads(block("resume", "json"))
    print("Read-first restart:", json.dumps(resumed), flush=True)
    readmitted = read(["submit", fixture.OPERATION])
    assert readmitted == json.loads(block("readmitted", "json"))
    print("Same-ID submit:", json.dumps(readmitted), flush=True)
    complete = wait_for_read(["status", fixture.OPERATION], lambda r: r["status"] == "SUCCEEDED")
    assert fixture.KubernetesFixture.requests == before, "completion acquired new receiver facts"
    print("Completed:", json.dumps(complete), flush=True)
    receipt = pathlib.Path("/tmp/documented-example.receipt")
    print("Receipt:", json.dumps(read(["receipt", fixture.OPERATION, str(receipt)])), flush=True)
    inspection = subprocess.run([str(binary), "inspect", "--receipt", str(receipt),
        "--trust", "receipt.trust", "--evaluation-time-unix-s",
        pathlib.Path("evaluation-time.txt").read_text().strip()],
        capture_output=True, check=True, timeout=10)
    report = json.loads(inspection.stdout)
    assert report["status"] == "INSPECTED", report
    print("Inspection:", inspection.stdout.decode().strip(), flush=True)
    assert fixture.KubernetesFixture.mutations == 1
    assert fixture.KubernetesFixture.requests == 4
    print(f"Documented example: one PATCH, same-ID signing recovery; {time.monotonic() - started:.2f}s", flush=True)
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        process.communicate(timeout=30)
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
"""
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-i",
                    "--platform",
                    "linux/amd64",
                    "--volume",
                    f"{root}:/artifact:ro",
                    "--volume",
                    f"{archive}.verify.py:/fixture.py:ro",
                    "--volume",
                    f"{ROOT / 'docs/KAPSEL_SERVICE_OPERATOR.md'}:/guide.md:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "-",
                ],
                input=script.encode(),
                check=True,
                timeout=180,
            )

    def test_dirty_source_is_rejected_before_build(self) -> None:
        sentinel = ROOT / ".kapsel-release-dirty-test"
        sentinel.write_text("dirty\n")
        try:
            with tempfile.TemporaryDirectory(prefix="kapsel-release-rejected-") as temporary:
                result = subprocess.run(
                    [
                        "python3",
                        str(ASSEMBLER),
                        "--output-directory",
                        temporary,
                    ],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release assembly requires a clean worktree", result.stderr)
                self.assertEqual(list(pathlib.Path(temporary).iterdir()), [])
        finally:
            sentinel.unlink(missing_ok=True)

    def test_extraction_companion_needs_no_checkout_or_executable_invocation(self) -> None:
        archive = release_archive()
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with tempfile.TemporaryDirectory(prefix="kapsel-extraction-only-") as temporary:
            private = pathlib.Path(temporary)
            destination = private / "extracted"
            command = [
                "python3",
                str(archive) + ".verify.py",
                "--archive",
                str(archive),
                "--expected-revision",
                revision,
                "--extract-to",
                str(destination),
            ]
            result = subprocess.run(
                command, cwd=private, capture_output=True, text=True, timeout=30, check=True
            )
            extracted = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(result.stdout.strip(), str(extracted))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue((extracted / "share/kapsel/kapseld.service").is_file())
            before = (extracted / "RELEASE-METADATA.json").read_bytes()
            refused = subprocess.run(
                command, cwd=private, capture_output=True, timeout=30, check=False
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual((extracted / "RELEASE-METADATA.json").read_bytes(), before)
            # A bad revision must fail before creating any destination.
            wrong = private / "wrong"
            command[-1] = str(wrong)
            command[command.index("--expected-revision") + 1] = "0" * 40
            refused = subprocess.run(
                command, cwd=private, capture_output=True, timeout=30, check=False
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(wrong.exists())
            # Even a dangling destination symlink is not an empty extraction root.
            link = private / "link"
            link.symlink_to(private / "absent")
            with self.assertRaises(FileExistsError):
                SMOKE.extract_release(
                    archive, archive.with_name(archive.name + ".sha256"), revision, link
                )
            self.assertFalse((private / "absent").exists())

    def test_verifier_companion_is_digest_bound(self) -> None:
        archive = release_archive()
        with tempfile.TemporaryDirectory(prefix="kapsel-verifier-tamper-") as temporary:
            copied = pathlib.Path(temporary) / archive.name
            for suffix in ("", ".sha256", ".spdx.json", ".SHA256SUMS", ".verify.py"):
                shutil.copyfile(str(archive) + suffix, str(copied) + suffix)
            with pathlib.Path(str(copied) + ".verify.py").open("ab") as verifier:
                verifier.write(b"\n# altered\n")
            destination = pathlib.Path(temporary) / "extracted"
            with self.assertRaisesRegex(RuntimeError, "digest manifest mismatch"):
                SMOKE.extract_release(
                    copied, pathlib.Path(str(copied) + ".sha256"), "0" * 40, destination
                )
            self.assertFalse(destination.exists())

    def test_reference_archive_has_verified_exact_layout_and_smoke(self) -> None:
        expected_dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        )
        archive = release_archive()
        SMOKE.read_bounded_regular(archive, 32 * 1024 * 1024)
        with contextlib.nullcontext(archive.parent) as output:
            version = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())["workspace"][
                "package"
            ]["version"]
            basename = f"kapsel-{version}-{TARGET}"
            self.assertEqual(archive.name, f"{basename}.tar.gz")
            checksum = output / f"{archive.name}.sha256"
            sbom = output / f"{archive.name}.spdx.json"
            manifest = output / f"{archive.name}.SHA256SUMS"
            verifier = output / f"{archive.name}.verify.py"
            self.assertEqual(
                SMOKE.read_bounded_regular(verifier, 64 * 1024),
                ROOT.joinpath("scripts/smoke-release-artifact.py").read_bytes(),
            )
            checksum_bytes = SMOKE.read_bounded_regular(checksum, 1024)
            sbom_bytes = SMOKE.read_bounded_regular(sbom, 2 * 1024 * 1024)
            manifest_bytes = SMOKE.read_bounded_regular(manifest, 1024)
            self.assertEqual(checksum_bytes.decode(), f"{sha256(archive)}  {archive.name}\n")
            expected_manifest = "".join(
                f"{sha256(path)}  {path.name}\n"
                for path in sorted([archive, checksum, sbom, verifier], key=lambda path: path.name)
            )
            self.assertEqual(manifest_bytes.decode(), expected_manifest)

            expected = {
                f"{basename}/",
                f"{basename}/bin/",
                f"{basename}/bin/kapsel",
                f"{basename}/libexec/",
                f"{basename}/libexec/kapsel/",
                f"{basename}/libexec/kapsel/kapseld",
                f"{basename}/bin/kapsel-service-client",
                f"{basename}/share/",
                f"{basename}/share/kapsel/",
                f"{basename}/share/kapsel/kapseld.service",
                f"{basename}/share/kapsel/kapseld.conf",
                f"{basename}/share/kapsel/kapseld-rbac.yaml",
                f"{basename}/share/doc/",
                f"{basename}/share/doc/kapsel/",
                f"{basename}/share/doc/kapsel/COMMANDS.md",
                f"{basename}/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
                f"{basename}/share/doc/kapsel/KAPSEL_SERVICE.md",
                f"{basename}/share/doc/kapsel/PRIVACY.md",
                f"{basename}/share/doc/kapsel/RELEASE.md",
                f"{basename}/share/doc/kapsel/SECURITY.md",
                f"{basename}/share/doc/kapsel/UPGRADE.md",
                f"{basename}/CHANGELOG.md",
                f"{basename}/LICENSE",
                f"{basename}/RELEASE-METADATA.json",
            }
            with tarfile.open(archive, "r:gz") as release:
                members = release.getmembers()
                names = {member.name + ("/" if member.isdir() else "") for member in members}
                self.assertEqual(names, expected)
                ordered_names = [member.name for member in members]
                self.assertEqual(ordered_names, sorted(ordered_names))
                for member in members:
                    identity = (
                        member.uid,
                        member.gid,
                        member.uname,
                        member.gname,
                        member.mtime,
                    )
                    self.assertEqual(identity, (0, 0, "", "", 0))
                    executable = member.isdir() or member.name.endswith(
                        ("/kapsel", "/kapseld", "/kapsel-service-client")
                    )
                    expected_mode = 0o755 if executable else 0o644
                    self.assertEqual(member.mode, expected_mode, member.name)

                for asset in ("kapseld.service", "kapseld.conf", "kapseld-rbac.yaml"):
                    asset_file = release.extractfile(f"{basename}/share/kapsel/{asset}")
                    self.assertIsNotNone(asset_file)
                    self.assertEqual(
                        asset_file.read(),
                        ROOT.joinpath("crates/kapseld/deploy", asset).read_bytes(),
                    )

                for document_name in [
                    "COMMANDS.md",
                    "KAPSEL_SERVICE_OPERATOR.md",
                    "KAPSEL_SERVICE.md",
                    "PRIVACY.md",
                    "RELEASE.md",
                    "SECURITY.md",
                    "UPGRADE.md",
                ]:
                    document_file = release.extractfile(
                        f"{basename}/share/doc/kapsel/{document_name}"
                    )
                    self.assertIsNotNone(document_file)
                    document = document_file.read().decode()
                    for link in re.findall(
                        r"]\((?!https?://|#|mailto:)([^)\s]+[.]md)(?:#[^)]+)?\)", document
                    ):
                        target = posixpath.normpath(f"{basename}/share/doc/kapsel/{link}")
                        self.assertTrue(target.startswith(f"{basename}/"))
                        self.assertIn(target, names, document_name)

                metadata_file = release.extractfile(f"{basename}/RELEASE-METADATA.json")
                self.assertIsNotNone(metadata_file)
                metadata_bytes = metadata_file.read()
                self.assertTrue(metadata_bytes.endswith(b"\n"))
                metadata = json.loads(metadata_bytes)
                self.assertEqual(metadata["artifact_schema"], "kapsel.release-artifact.v3")
                self.assertEqual(metadata["package_version"], version)
                self.assertEqual(metadata["rust_target"], TARGET)
                revision = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
                self.assertEqual(metadata["source_revision"], revision)
                tree = subprocess.run(
                    ["git", "rev-parse", "HEAD^{tree}"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
                self.assertEqual(metadata["source_tree"], tree)
                self.assertEqual(metadata["source_dirty"], expected_dirty)
                self.assertEqual(metadata["cargo_lock_sha256"], sha256(ROOT / "Cargo.lock"))
                self.assertEqual(metadata["license"], "Apache-2.0")
                manifest = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())
                self.assertEqual(metadata["license"], manifest["workspace"]["package"]["license"])
                license_file = release.extractfile(f"{basename}/LICENSE")
                self.assertIsNotNone(license_file)
                license_bytes = license_file.read()
                self.assertEqual(license_bytes, ROOT.joinpath("LICENSE").read_bytes())
                self.assertEqual(
                    hashlib.sha256(license_bytes).hexdigest(),
                    metadata["license_sha256"],
                )
                self.assertEqual(metadata["builder_image"], BUILDER_IMAGE)
                self.assertEqual(metadata["smoke_image"], SMOKE_IMAGE)
                self.assertEqual(
                    metadata["non_claims"],
                    "service-preview;not-production;no-public-rust-api;no-other-targets",
                )
                self.assertEqual(
                    list(metadata),
                    [
                        "artifact_schema",
                        "package_version",
                        "rust_target",
                        "source_revision",
                        "source_tree",
                        "source_dirty",
                        "cargo_lock_sha256",
                        "cargo_graph_sha256",
                        "cargo_package_count",
                        "cargo_relationship_count",
                        "license",
                        "license_sha256",
                        "builder_image",
                        "smoke_image",
                        "ordinary_binary_bytes",
                        "ordinary_binary_sha256",
                        "service_binary_bytes",
                        "service_binary_sha256",
                        "client_binary_bytes",
                        "client_binary_sha256",
                        "non_claims",
                    ],
                )

                for name, path in {
                    "ordinary": "bin/kapsel",
                    "service": "libexec/kapsel/kapseld",
                    "client": "bin/kapsel-service-client",
                }.items():
                    binary_file = release.extractfile(f"{basename}/{path}")
                    self.assertIsNotNone(binary_file)
                    binary = binary_file.read()
                    self.assertEqual(len(binary), metadata[f"{name}_binary_bytes"])
                    self.assertEqual(
                        hashlib.sha256(binary).hexdigest(), metadata[f"{name}_binary_sha256"]
                    )
                    self.assertEqual(binary[:4], b"\x7fELF")
                    self.assertEqual(binary[4:6], b"\x02\x01")
                    self.assertEqual(int.from_bytes(binary[18:20], "little"), 62)

            sbom_document = json.loads(sbom_bytes)
            self.assertEqual(sbom_document["spdxVersion"], "SPDX-2.3")
            self.assertEqual(
                sbom_document["documentNamespace"],
                f"https://github.com/kapsel-cloud/kapsel/sbom/{revision}/{sha256(archive)}",
            )
            self.assertEqual(
                sbom_document["creationInfo"]["creators"],
                ["Tool: kapsel-release-sbom/1"],
            )
            self.assertIn(
                "SPDXRef-Package-kapsel-archive",
                {package["SPDXID"] for package in sbom_document["packages"]},
            )
            self.assertIn(
                "SPDXRef-Package-kapsel-source",
                {package["SPDXID"] for package in sbom_document["packages"]},
            )

            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--volume",
                    f"{output}:/input:ro",
                    "--volume",
                    f"{ROOT / 'scripts' / 'smoke-release-artifact.py'}:/smoke.py:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "/smoke.py",
                    "--archive",
                    f"/input/{archive.name}",
                    "--expected-revision",
                    revision,
                    "--service-container",
                ],
                cwd=ROOT,
                check=True,
                timeout=180,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument(
        "--example-revision",
        help="independently accepted revision for the documented example only; default checkout HEAD",
    )
    arguments, unittest_arguments = parser.parse_known_args()
    RELEASE_ARCHIVE = pathlib.Path(os.path.abspath(arguments.archive))
    EXAMPLE_REVISION = arguments.example_revision
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
