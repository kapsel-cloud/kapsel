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
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "assemble-release-artifact.py"
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
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
            checksum_bytes = SMOKE.read_bounded_regular(checksum, 1024)
            sbom_bytes = SMOKE.read_bounded_regular(sbom, 2 * 1024 * 1024)
            manifest_bytes = SMOKE.read_bounded_regular(manifest, 1024)
            self.assertEqual(checksum_bytes.decode(), f"{sha256(archive)}  {archive.name}\n")
            expected_manifest = "".join(
                f"{sha256(path)}  {path.name}\n"
                for path in sorted([archive, checksum, sbom], key=lambda path: path.name)
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
    arguments, unittest_arguments = parser.parse_known_args()
    RELEASE_ARCHIVE = pathlib.Path(os.path.abspath(arguments.archive))
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
