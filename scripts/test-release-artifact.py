#!/usr/bin/env python3
"""Black-box smoke tests for the assembled Kapsel release artifact."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "assemble-release-artifact.py"
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663"
)
SMOKE_IMAGE = (
    "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ReleaseArtifactTests(unittest.TestCase):
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

    def test_assembly_produces_verified_exact_layout(self) -> None:
        expected_dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        )
        with tempfile.TemporaryDirectory(prefix="kapsel-release-artifact-") as temporary:
            output = pathlib.Path(temporary)
            subprocess.run(
                [
                    "python3",
                    str(ASSEMBLER),
                    "--output-directory",
                    str(output),
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                timeout=900,
            )
            version = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())["workspace"][
                "package"
            ]["version"]
            basename = f"kapsel-{version}-{TARGET}"
            archive = output / f"{basename}.tar.gz"
            checksum = output / f"{archive.name}.sha256"
            self.assertTrue(archive.is_file())
            self.assertEqual(checksum.read_text(), f"{sha256(archive)}  {archive.name}\n")

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
                        ("/kapsel", "/kapsel-demo-harness", ".sh")
                    )
                    expected_mode = 0o755 if executable else 0o644
                    self.assertEqual(member.mode, expected_mode, member.name)

                metadata_file = release.extractfile(f"{basename}/RELEASE-METADATA.json")
                self.assertIsNotNone(metadata_file)
                metadata_bytes = metadata_file.read()
                self.assertTrue(metadata_bytes.endswith(b"\n"))
                metadata = json.loads(metadata_bytes)
                self.assertEqual(metadata["artifact_schema"], "kapsel.release-artifact.v1")
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
                self.assertEqual(metadata["source_dirty"], expected_dirty)
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
                    "not-production;no-stable-cli;no-stable-receipt;no-other-targets",
                )
                self.assertEqual(
                    list(metadata),
                    [
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
                    ],
                )

                ordinary = release.extractfile(f"{basename}/bin/kapsel")
                demonstration = release.extractfile(f"{basename}/libexec/kapsel-demo-harness")
                self.assertIsNotNone(ordinary)
                self.assertIsNotNone(demonstration)
                ordinary_bytes = ordinary.read()
                demonstration_bytes = demonstration.read()
                self.assertEqual(
                    hashlib.sha256(ordinary_bytes).hexdigest(),
                    metadata["ordinary_binary_sha256"],
                )
                self.assertEqual(
                    hashlib.sha256(demonstration_bytes).hexdigest(),
                    metadata["demo_binary_sha256"],
                )
                for binary in [ordinary_bytes, demonstration_bytes]:
                    self.assertEqual(binary[:4], b"\x7fELF")
                    self.assertEqual(binary[4:6], b"\x02\x01")
                    self.assertEqual(int.from_bytes(binary[18:20], "little"), 62)

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
                ],
                cwd=ROOT,
                check=True,
                timeout=180,
            )


if __name__ == "__main__":
    unittest.main()
