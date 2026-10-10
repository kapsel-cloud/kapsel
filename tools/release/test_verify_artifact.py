#!/usr/bin/env python3
"""Focused offline release verifier regressions."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

import verify_artifact as VERIFY

TARGET = "x86_64-unknown-linux-gnu"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def add_entry(release: tarfile.TarFile, name: str, value: bytes | None) -> None:
    information = tarfile.TarInfo(name)
    information.uid = 0
    information.gid = 0
    information.uname = ""
    information.gname = ""
    information.mtime = 0
    if value is None:
        information.type = tarfile.DIRTYPE
        information.mode = 0o755
        release.addfile(information)
        return
    information.type = tarfile.REGTYPE
    information.mode = 0o755 if name.endswith(tuple(VERIFY.BINARIES.values())) else 0o644
    information.size = len(value)
    release.addfile(information, io.BytesIO(value))


def write_complete_artifact(root: pathlib.Path) -> pathlib.Path:
    archive = root / f"kapsel-0.2.0-{TARGET}.tar.gz"
    basename = archive.name.removesuffix(".tar.gz")
    binaries = {
        "ordinary": b"ordinary",
        "service": b"service",
        "client": b"client",
        "mcp_bridge": b"mcp-bridge",
    }
    cargo_packages = [
        {
            "SPDXID": "SPDXRef-Package-kapsel-source",
            "name": "kapsel",
            "versionInfo": "0.2.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
        },
        {
            "SPDXID": "SPDXRef-Package-kapsel-daemon",
            "name": "kapsel-daemon",
            "versionInfo": "0.2.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
        },
    ]
    cargo_relationships = [
        {
            "spdxElementId": "SPDXRef-Package-kapsel-source",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-kapsel-daemon",
            "comment": "fixture graph edge",
        }
    ]
    graph = {
        "packages": cargo_packages,
        "relationships": cargo_relationships,
        "root_package_id": "SPDXRef-Package-kapsel-source",
    }
    metadata = {
        "artifact_schema": "kapsel.release-artifact.v3",
        "package_version": "0.2.0",
        "rust_target": TARGET,
        "source_revision": "1" * 40,
        "source_tree": "2" * 40,
        "source_dirty": False,
        "cargo_lock_sha256": "3" * 64,
        "cargo_graph_sha256": digest(
            json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
        ),
        "cargo_package_count": len(cargo_packages),
        "cargo_relationship_count": len(cargo_relationships),
        "license": "Apache-2.0",
        "license_sha256": digest(b"license"),
        "builder_image": VERIFY.BUILDER_IMAGE,
        "smoke_image": VERIFY.SMOKE_IMAGE,
    }
    for name, value in binaries.items():
        metadata[f"{name}_binary_bytes"] = len(value)
        metadata[f"{name}_binary_sha256"] = digest(value)
    metadata["non_claims"] = VERIFY.NON_CLAIMS
    files = {
        f"{basename}/bin/kapsel": binaries["ordinary"],
        f"{basename}/libexec/kapsel/kapseld": binaries["service"],
        f"{basename}/bin/kapsel-service-client": binaries["client"],
        f"{basename}/bin/kapsel-service-mcp": binaries["mcp_bridge"],
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
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as release:
                for name in sorted([*directories, *files]):
                    add_entry(release, name, files.get(name))

    archive_bytes = archive.read_bytes()
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{archive.name} software bill of materials",
        "documentNamespace": (
            f"https://github.com/kapsel-cloud/kapsel/sbom/{'1' * 40}/{digest(archive_bytes)}"
        ),
        "comment": ";".join(
            [
                f"source_revision={'1' * 40}",
                f"source_tree={'2' * 40}",
                f"rust_target={TARGET}",
                f"builder_image={VERIFY.BUILDER_IMAGE}",
                f"cargo_lock_sha256={'3' * 64}",
                f"cargo_graph_sha256={metadata['cargo_graph_sha256']}",
            ]
        ),
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z",
            "creators": [f"Tool: {VERIFY.SBOM_GENERATOR}"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-kapsel-archive",
                "name": archive.name,
                "versionInfo": "0.2.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "packageFileName": archive.name,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest(archive_bytes)}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "Apache-2.0",
                "copyrightText": "NOASSERTION",
            },
            *cargo_packages,
        ],
        "files": [
            {
                "SPDXID": "SPDXRef-File-" + path.replace("/", "-"),
                "fileName": f"./{path}",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": metadata[f"{name}_binary_sha256"]}
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            for name, path in VERIFY.BINARIES.items()
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-kapsel-archive",
            },
            {
                "spdxElementId": "SPDXRef-Package-kapsel-archive",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-Package-kapsel-source",
            },
            *[
                {
                    "spdxElementId": "SPDXRef-Package-kapsel-archive",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-File-" + path.replace("/", "-"),
                }
                for path in VERIFY.BINARIES.values()
            ],
            *cargo_relationships,
        ],
    }
    sidecars = {
        ".sha256": f"{digest(archive_bytes)}  {archive.name}\n".encode(),
        ".spdx.json": (json.dumps(sbom, indent=2, separators=(",", ": ")) + "\n").encode(),
        ".verify.py": pathlib.Path(VERIFY.__file__).read_bytes(),
    }
    for suffix, value in sidecars.items():
        archive.with_name(archive.name + suffix).write_bytes(value)
    manifest_paths = [archive, *(archive.with_name(archive.name + suffix) for suffix in sidecars)]
    archive.with_name(archive.name + ".SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(manifest_paths, key=lambda path: path.name)
        )
    )
    return archive


class BoundedProcessTests(unittest.TestCase):
    def test_output_overflow_is_rejected_before_waiting_for_completion(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "byte bound"):
            VERIFY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.write(1, b'x' * 65536); time.sleep(5)",
                ],
                stdout_max=1024,
                stderr_max=1024,
                timeout=10,
            )

    def test_hanging_command_is_killed_at_the_deadline(self) -> None:
        with self.assertRaises(subprocess.TimeoutExpired):
            VERIFY.run_bounded(
                [sys.executable, "-I", "-c", "import time; time.sleep(5)"],
                stdout_max=1024,
                stderr_max=1024,
                timeout=0.1,
            )

    def test_closed_output_fds_do_not_end_the_deadline(self) -> None:
        with self.assertRaises(subprocess.TimeoutExpired):
            VERIFY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.close(1); os.close(2); time.sleep(5)",
                ],
                stdout_max=1024,
                stderr_max=1024,
                timeout=0.1,
            )

    def test_closed_stdin_pipe_does_not_hang(self) -> None:
        result = VERIFY.run_bounded(
            [sys.executable, "-I", "-c", "import sys; sys.exit(0)"],
            input_bytes=b"x" * 1024 * 1024,
            stdout_max=1024,
            stderr_max=1024,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)

    def test_failed_checked_command_hides_raw_tool_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "command failed") as failure:
            VERIFY.run_bounded(
                [sys.executable, "-I", "-c", "import sys; sys.stderr.write('SECRET'); sys.exit(7)"],
                stdout_max=1024,
                stderr_max=1024,
                timeout=5,
                check=True,
            )
        self.assertNotIn("SECRET", str(failure.exception))


class ServiceDiagnosticDrainTests(unittest.TestCase):
    def test_service_stderr_overflow_fails_without_blocking_cleanup(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                "import os,time; os.write(2, b'x' * 8192); time.sleep(5)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        assert process.stderr is not None
        drain = VERIFY.ServiceStderrDrain(process)
        drain.start()
        try:
            process.wait(timeout=5)
            drain.finish()
            self.assertTrue(drain.overflow)
            self.assertNotEqual(process.returncode, 0)
            self.assertTrue(drain.failed())
            self.assertLessEqual(len(drain.diagnostic), VERIFY.SERVICE_DIAGNOSTIC_BYTES_MAX)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            drain.finish()

    def test_service_stderr_graceful_cleanup_preserves_bounded_evidence(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", "import os; os.write(2, b'bounded diagnostic')"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        assert process.stderr is not None
        drain = VERIFY.ServiceStderrDrain(process)
        drain.start()
        process.wait(timeout=5)
        drain.finish()
        self.assertEqual(process.returncode, 0)
        self.assertFalse(drain.failed())
        self.assertEqual(bytes(drain.diagnostic), b"bounded diagnostic")

    def test_finish_closes_the_reader_even_if_another_writer_keeps_the_pipe_open(self) -> None:
        reader, writer = os.pipe()
        source = os.fdopen(reader, "rb")
        process = mock.Mock(stderr=source)
        drain = VERIFY.ServiceStderrDrain(process)
        drain.start()
        started = time.monotonic()
        try:
            drain.finish()
            self.assertLess(time.monotonic() - started, 3)
            self.assertFalse(drain.thread.is_alive())
            self.assertTrue(source.closed)
            self.assertTrue(drain.failed())
        finally:
            os.close(writer)
            drain.finish()


class CompleteArtifactTests(unittest.TestCase):
    def test_complete_artifact_sidecars_are_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-complete-artifact-") as temporary:
            archive = write_complete_artifact(pathlib.Path(temporary))
            archive_bytes, metadata = VERIFY.verified_release(
                archive, archive.with_name(archive.name + ".sha256"), "1" * 40
            )
            self.assertEqual(digest(archive_bytes), digest(archive.read_bytes()))
        self.assertEqual(metadata["source_revision"], "1" * 40)

    def test_companion_extracts_in_an_isolated_process_without_checkout_imports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-independent-companion-") as temporary:
            root = pathlib.Path(temporary)
            archive = write_complete_artifact(root)
            companion = archive.with_name(archive.name + ".verify.py")
            destination = root / "extracted"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(companion),
                    "--archive",
                    str(archive),
                    "--expected-revision",
                    "1" * 40,
                    "--extract-to",
                    str(destination),
                ],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=True,
            )
            extracted = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout.decode().strip(), str(extracted))
            self.assertEqual((extracted / "bin/kapsel").read_bytes(), b"ordinary")
            self.assertEqual((extracted / "bin/kapsel").stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
