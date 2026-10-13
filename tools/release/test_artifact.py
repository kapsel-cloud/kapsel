#!/usr/bin/env python3
"""Source correspondence and explicit extracted smoke/installed profiles for clean artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

import assemble_artifact as ASSEMBLY
import verify_artifact as VERIFY

ROOT = pathlib.Path(__file__).resolve().parents[2]
ASSEMBLER = pathlib.Path(__file__).with_name("assemble_artifact.py")
TARGET = "x86_64-unknown-linux-gnu"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
RELEASE_ARCHIVE: pathlib.Path | None = None


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


class SourceCorrespondenceTests(unittest.TestCase):
    def test_cargo_records_reject_malformed_shapes(self) -> None:
        for document in (
            None,
            {"packages": {}, "resolve": {"nodes": []}},
            {"packages": [7], "resolve": {"nodes": []}},
            {"packages": [], "resolve": {"nodes": [{"id": "x", "deps": [7]}]}},
            {
                "packages": [],
                "resolve": {"nodes": [{"id": "x", "deps": [{"pkg": "y", "dep_kinds": [{}]}]}]},
            },
            {
                "packages": [{"id": "x", "name": "x", "version": "1", "manifest_path": "x"}],
                "resolve": {"nodes": []},
            },
            {
                "packages": [],
                "resolve": {
                    "nodes": [{"id": "x", "deps": [{"pkg": "y", "dep_kinds": [{"kind": 7}]}]}]
                },
            },
        ):
            with self.subTest(document=document), self.assertRaises(RuntimeError):
                ASSEMBLY.cargo_graph_records(document)

    def test_staged_document_names_and_links_survive_source_reorganisation(self) -> None:
        """Exercise real assembly mappings without compiling or running product binaries."""
        sources = {
            "COMMANDS.md": "docs/reference/commands.md",
            "KAPSEL_SERVICE_OPERATOR.md": "docs/guides/operator.md",
            "KAPSEL_SERVICE.md": "docs/reference/service.md",
            "PRIVACY.md": "docs/reference/privacy.md",
            "RELEASE.md": "docs/reference/release.md",
            "SECURITY.md": "SECURITY.md",
            "UPGRADE.md": "docs/guides/journal_retention.md",
        }

        def fake_build(directory: pathlib.Path):
            binaries = {}
            for name in ("ordinary", "service", "client", "mcp_bridge"):
                binary = directory / name
                binary.write_bytes(b"not an executable")
                binaries[name] = binary
            metadata = directory / "metadata.json"
            metadata.write_text("{}")
            return binaries, metadata

        revision = "1" * 40
        with (
            tempfile.TemporaryDirectory(prefix="kapsel-doc-staging-") as temporary,
            mock.patch.object(ASSEMBLY, "build_binaries", side_effect=fake_build),
            mock.patch.object(ASSEMBLY, "cargo_graph", return_value=([], [], "unused")),
        ):
            staging = pathlib.Path(temporary)
            ASSEMBLY.stage_release(staging, revision, "2" * 40, False)
            documents = staging / "share/doc/kapsel"
            self.assertEqual({path.name for path in documents.iterdir()}, set(sources))
            for name, source in sources.items():
                with self.subTest(document=name):
                    text = (documents / name).read_text()
                    self.assertEqual(
                        text.splitlines()[0], ROOT.joinpath(source).read_text().splitlines()[0]
                    )
                    for target in re.findall(r"]\(([^)\s]+[.]md(?:#[^)]+)?)\)", text):
                        if target.startswith(("https://", "http://")):
                            continue
                        self.assertTrue((documents / target.split("#", 1)[0]).is_file(), target)
            operator = documents.joinpath("KAPSEL_SERVICE_OPERATOR.md").read_text()
            self.assertIn("](RELEASE.md#authenticate-and-extract-the-release)", operator)
            self.assertIn("](KAPSEL_SERVICE.md#action-independence)", operator)
            self.assertIn(
                f"](https://github.com/kapsel-cloud/kapsel/blob/{revision}/"
                "docs/contributing/qualification.md#documented-operator-example)",
                operator,
            )
            self.assertIn(
                f"](https://github.com/kapsel-cloud/kapsel/blob/{revision}/"
                "docs/getting_started.md)",
                operator,
            )
            release = documents.joinpath("RELEASE.md").read_text()
            self.assertIn(
                "](KAPSEL_SERVICE_OPERATOR.md#prepare-your-own-extracted-artifact)", release
            )

    def test_documented_bootstrap_never_executes_after_authentication_failure(self) -> None:
        document = ROOT.joinpath("docs/reference/release.md").read_text()
        _, heading, section = document.partition("## Authenticate and extract the release\n")
        self.assertTrue(heading, "release authentication section is missing")
        section = section.split("\n## ", 1)[0]
        _, fence, commands = section.partition("```sh\n")
        self.assertTrue(fence, "release authentication command block is missing")
        block, closing_fence, _ = commands.partition("```")
        self.assertTrue(closing_fence, "release authentication command block is unterminated")
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
                ("kapsel-daemon", "/workspace/crates/kapsel-daemon/Cargo.toml"),
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
            {package["name"] for package in graph}, {"kapsel", "kapsel-daemon", "service-only"}
        )
        self.assertEqual(len(edges), 2)
        self.assertEqual(root, "SPDXRef-Package-kapsel-source")

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


class ReleaseArtifactTests(unittest.TestCase):
    def test_source_and_extracted_identity(self) -> None:
        archive = release_archive()
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        _, metadata = VERIFY.verified_release(
            archive, archive.with_name(archive.name + ".sha256"), revision
        )
        package = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())["workspace"]["package"]
        self.assertEqual(archive.name, f"kapsel-{package['version']}-{TARGET}.tar.gz")
        self.assertFalse(metadata["source_dirty"], "artifact qualification needs clean source")
        self.assertEqual(
            metadata["source_tree"],
            subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
            ).strip(),
        )
        self.assertEqual(metadata["cargo_lock_sha256"], sha256(ROOT / "Cargo.lock"))
        self.assertEqual(metadata["license"], package["license"])
        verifier = archive.with_name(archive.name + ".verify.py")
        self.assertEqual(
            VERIFY.read_bounded_regular(verifier, 64 * 1024),
            ROOT.joinpath("tools/release/verify_artifact.py").read_bytes(),
        )

        # The verifier's independent hostile vectors own format, layout and digest rules.
        # This artifact adds source correspondence and actual executable/installed observations.
        with tempfile.TemporaryDirectory() as temporary:
            destination = pathlib.Path(temporary) / "extracted"
            extracted = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(verifier),
                    "--archive",
                    str(archive),
                    "--expected-revision",
                    revision,
                    "--extract-to",
                    str(destination),
                ],
                cwd=temporary,
                capture_output=True,
                timeout=30,
                check=True,
            )
            root = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(extracted.stdout.decode().strip(), str(root))
            self.assertEqual(extracted.stderr, b"")
            self.assertEqual((root / "LICENSE").read_bytes(), ROOT.joinpath("LICENSE").read_bytes())
            for asset in ("kapseld.service", "kapseld.conf", "kapseld-rbac.yaml"):
                self.assertEqual(
                    root.joinpath("share/kapsel", asset).read_bytes(),
                    ROOT.joinpath("crates/kapsel-daemon/deploy", asset).read_bytes(),
                )
            for document in root.joinpath("share/doc/kapsel").glob("*.md"):
                for link in re.findall(
                    r"]\((?!https?://|#|mailto:)([^)\s]+[.]md)(?:#[^)]+)?\)", document.read_text()
                ):
                    target = (document.parent / link).resolve()
                    self.assertTrue(target.is_relative_to(root.resolve()))
                    self.assertTrue(target.is_file(), link)
            for relative in (
                "bin/kapsel",
                "libexec/kapsel/kapseld",
                "bin/kapsel-service-client",
                "bin/kapsel-service-mcp",
            ):
                with root.joinpath(relative).open("rb") as source:
                    header = source.read(20)
                self.assertEqual(header[:6], b"\x7fELF\x02\x01")
                self.assertEqual(int.from_bytes(header[18:20], "little"), 62)

            self.assertEqual(
                (root / "share/kapsel/qualification.py").read_bytes(),
                ROOT.joinpath("tools/release/qualification.py").read_bytes(),
            )
            for relative in VERIFY.ASSETS:
                self.assertEqual(
                    metadata["asset_files"][relative]["sha256"], sha256(root / relative)
                )

    def run_profile(self, profile: str) -> None:
        archive = release_archive()
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with tempfile.TemporaryDirectory(prefix="kapsel-selected-profile-") as temporary:
            destination = pathlib.Path(temporary) / "extracted"
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(archive) + ".verify.py",
                    "--archive",
                    str(archive),
                    "--expected-revision",
                    revision,
                    "--extract-to",
                    str(destination),
                ],
                cwd=temporary,
                check=True,
                timeout=30,
            )
            root = destination / archive.name.removesuffix(".tar.gz")
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "none",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=128",
                    "--memory=512m",
                    "--volume",
                    f"{root}:/artifact:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "-I",
                    "/artifact/share/kapsel/qualification.py",
                    "--artifact",
                    "/artifact",
                    "--expected-revision",
                    revision,
                    "--profile",
                    profile,
                ],
                check=True,
                timeout=180,
            )

    def test_extracted_executable_smoke(self) -> None:
        self.run_profile("smoke")

    def test_installed_guide(self) -> None:
        self.run_profile("direct")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    arguments, unittest_arguments = parser.parse_known_args()
    RELEASE_ARCHIVE = pathlib.Path(os.path.abspath(arguments.archive))
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
