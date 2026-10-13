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
import unittest
from unittest import mock

import verify_artifact as VERIFY

# Pin published values independently of both producer and verifier.
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
NON_CLAIMS = "service-preview;not-production;no-public-rust-api;no-other-targets"
ASSETS = {
    "share/kapsel/qualification.py": b"raise SystemExit('qualification must not execute')\n",
    "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md": b"operator\n",
    "share/kapsel/kapseld.service": b"unit\n",
    "share/kapsel/kapseld.conf": b"sysusers\n",
    "share/kapsel/kapseld-rbac.yaml": b"rbac\n",
}
BINARIES = {
    "ordinary": "bin/kapsel",
    "service": "libexec/kapsel/kapseld",
    "client": "bin/kapsel-service-client",
    "mcp_bridge": "bin/kapsel-service-mcp",
}


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
    information.mode = 0o755 if name.endswith(tuple(BINARIES.values())) else 0o644
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
        "artifact_schema": "kapsel.release-artifact.v4",
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
        "builder_image": BUILDER_IMAGE,
        "smoke_image": SMOKE_IMAGE,
    }
    for name, value in binaries.items():
        metadata[f"{name}_binary_bytes"] = len(value)
        metadata[f"{name}_binary_sha256"] = digest(value)
    metadata["asset_files"] = {
        path: {"bytes": len(value), "sha256": digest(value)} for path, value in ASSETS.items()
    }
    metadata["non_claims"] = NON_CLAIMS
    files = {
        f"{basename}/bin/kapsel": binaries["ordinary"],
        f"{basename}/libexec/kapsel/kapseld": binaries["service"],
        f"{basename}/bin/kapsel-service-client": binaries["client"],
        f"{basename}/bin/kapsel-service-mcp": binaries["mcp_bridge"],
        f"{basename}/share/doc/kapsel/COMMANDS.md": b"commands\n",
        **{f"{basename}/{path}": value for path, value in ASSETS.items()},
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
                f"builder_image={BUILDER_IMAGE}",
                f"cargo_lock_sha256={'3' * 64}",
                f"cargo_graph_sha256={metadata['cargo_graph_sha256']}",
            ]
        ),
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z",
            "creators": ["Tool: kapsel-release-sbom/1"],
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
                "checksums": [{"algorithm": "SHA256", "checksumValue": file_digest}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            for path, file_digest in [
                *((path, digest(binaries[name])) for name, path in BINARIES.items()),
                *((path, digest(value)) for path, value in ASSETS.items()),
            ]
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
                for path in (*BINARIES.values(), *ASSETS)
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


def hostile_archive(archive: pathlib.Path, mutation: str) -> bytes:
    """Change one independently authored archive fact, leaving the canonical source untouched."""
    with tarfile.open(archive, "r:gz") as release:
        entries = []
        for member in release:
            source = release.extractfile(member) if member.isfile() else None
            entries.append((member, source.read() if source is not None else b""))
    basename = archive.name.removesuffix(".tar.gz")
    selected = f"{basename}/CHANGELOG.md"
    if mutation.endswith("-digest"):
        relative = {
            **BINARIES,
            "qualification": "share/kapsel/qualification.py",
            "guide": "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        }[mutation.removesuffix("-digest")]
        selected = f"{basename}/{relative}"
    if mutation == "executable-unit":
        selected = f"{basename}/share/kapsel/kapseld.service"
    if mutation == "old-schema" or mutation.startswith("metadata-"):
        selected = f"{basename}/RELEASE-METADATA.json"
    if mutation in {"extra", "traversal", "absolute", "duplicate"}:
        name = {
            "extra": f"{basename}/EXTRA",
            "traversal": f"{basename}/../escape",
            "absolute": "/escape",
            "duplicate": selected,
        }[mutation]
        entries.append((tarfile.TarInfo(name), b"extra"))
        entries.sort(key=lambda entry: entry[0].name)
    if mutation == "missing":
        entries = [entry for entry in entries if entry[0].name != selected]
    if mutation == "ordering":
        entries.reverse()

    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        archive_format = {"gnu": tarfile.GNU_FORMAT, "pax": tarfile.PAX_FORMAT}.get(
            mutation, tarfile.USTAR_FORMAT
        )
        with tarfile.open(fileobj=compressed, mode="w", format=archive_format) as release:
            for member, value in entries:
                if mutation == "oversized-expanded" and member.name.endswith(
                    ("/COMMANDS.md", "/KAPSEL_SERVICE_OPERATOR.md", "/KAPSEL_SERVICE.md")
                ):
                    value = bytes(22 * 1024 * 1024)
                if member.name == selected:
                    if mutation.endswith("-digest"):
                        value = b"x" + value[1:]
                    elif mutation == "old-schema":
                        value = value.replace(
                            b"kapsel.release-artifact.v4", b"kapsel.release-artifact.v3"
                        )
                    elif mutation.startswith("metadata-"):
                        metadata = json.loads(value)
                        if mutation == "metadata-order":
                            metadata = dict(reversed(list(metadata.items())))
                        else:
                            field = mutation.removeprefix("metadata-")
                            metadata[field] = "wrong"
                        value = (json.dumps(metadata) + "\n").encode()
                    elif mutation == "oversized-file":
                        value = bytes(32 * 1024 * 1024 + 1)
                    elif mutation in {"symlink", "hardlink", "special"}:
                        member.type = {
                            "symlink": tarfile.SYMTYPE,
                            "hardlink": tarfile.LNKTYPE,
                            "special": tarfile.CHRTYPE,
                        }[mutation]
                        member.linkname = "LICENSE"
                    elif mutation in {"unsafe-mode", "executable-unit"}:
                        member.mode = 0o666 if mutation == "unsafe-mode" else 0o755
                    elif mutation == "owner":
                        member.uid = 1
                    elif mutation == "timestamp":
                        member.mtime = 1
                    elif mutation == "pax":
                        member.pax_headers = {"comment": "hidden extension"}
                member.size = len(value) if member.isfile() else 0
                release.addfile(member, io.BytesIO(value) if member.isfile() else None)
    return output.getvalue()


class CompleteArtifactTests(unittest.TestCase):
    def test_complete_artifact_sidecars_are_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-complete-artifact-") as temporary:
            archive = write_complete_artifact(pathlib.Path(temporary))
            archive_bytes, metadata = VERIFY.verified_release(
                archive, archive.with_name(archive.name + ".sha256"), "1" * 40
            )
            self.assertEqual(digest(archive_bytes), digest(archive.read_bytes()))
        self.assertEqual(metadata["source_revision"], "1" * 40)

    def test_companion_extracts_exclusively_without_checkout_imports_or_executing_binaries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-independent-companion-") as temporary:
            root = pathlib.Path(temporary)
            archive = write_complete_artifact(root)
            (root / "pathlib.py").write_text("raise SystemExit(99)\n")
            destination = root / "extracted"
            command = [
                sys.executable,
                "-I",
                str(archive) + ".verify.py",
                "--archive",
                str(archive),
                "--expected-revision",
                "1" * 40,
                "--extract-to",
                str(destination),
            ]
            validated = subprocess.run(
                command[:-2] + ["--verify-only"],
                cwd=root,
                capture_output=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(validated.stdout, b"Kapsel release artifact validation: ok\n")
            self.assertFalse(destination.exists())
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=10, check=True)
            extracted = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout.decode().strip(), str(extracted))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((extracted / "bin/kapsel").read_bytes(), b"ordinary")
            self.assertEqual((extracted / "bin/kapsel").stat().st_mode & 0o777, 0o755)
            original = {
                path.relative_to(destination): path.read_bytes()
                for path in destination.rglob("*")
                if path.is_file()
            }
            refused = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(
                original,
                {
                    path.relative_to(destination): path.read_bytes()
                    for path in destination.rglob("*")
                    if path.is_file()
                },
            )
            link = root / "link"
            link.symlink_to(root / "absent")
            command[-1] = str(link)
            refused = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "absent").exists())
            command[-1] = str(root / "wrong")
            command[command.index("--expected-revision") + 1] = "0" * 40
            refused = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b"expected revision", refused.stderr)
            self.assertFalse((root / "wrong").exists())

    def test_hostile_layouts_and_binary_changes_fail_their_own_validation(self) -> None:
        cases = {
            **{name + "-digest": "binary digest disagrees" for name in BINARIES},
            "qualification-digest": "asset digest",
            "guide-digest": "asset digest",
            "old-schema": "metadata schema changed",
            "metadata-extra": "metadata fields or order",
            "metadata-order": "metadata fields or order",
            "metadata-package_version": "archive identity",
            "metadata-rust_target": "archive identity",
            "metadata-license": "license provenance",
            "metadata-builder_image": "container provenance",
            "metadata-smoke_image": "container provenance",
            "metadata-non_claims": "non-claims changed",
            "metadata-ordinary_binary_bytes": "binary size disagrees",
            "executable-unit": "mode is not canonical",
            "unsafe-mode": "mode is not canonical",
            "extra": "too many raw entries",
            "duplicate": "too many raw entries",
            "missing": "framing or padding",
            "ordering": "layout or ordering",
            "traversal": "too many raw entries",
            "absolute": "too many raw entries",
            "symlink": "extension, link, or special header",
            "hardlink": "extension, link, or special header",
            "special": "extension, link, or special header",
            "owner": "metadata is not normalized",
            "timestamp": "metadata is not normalized",
            "oversized-file": "file bound",
            "oversized-expanded": "decompressed bound",
            "pax": "extension, link, or special header",
            "gnu": "not exact USTAR",
        }
        with tempfile.TemporaryDirectory() as temporary:
            archive = write_complete_artifact(pathlib.Path(temporary))
            VERIFY.validate_archive(archive, archive.read_bytes())
            for mutation, diagnostic in cases.items():
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaisesRegex(RuntimeError, diagnostic),
                ):
                    VERIFY.validate_archive(archive, hostile_archive(archive, mutation))

    def test_sbom_identity_and_inventory_are_bound_to_the_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = write_complete_artifact(pathlib.Path(temporary))
            archive_bytes, metadata = VERIFY.verified_release(
                archive, archive.with_name(archive.name + ".sha256"), "1" * 40
            )
            sbom_bytes = archive.with_name(archive.name + ".spdx.json").read_bytes()
            for field, value, diagnostic in (
                ("spdxVersion", "SPDX-2.2", "SPDX identity"),
                ("documentNamespace", "wrong", "namespace"),
                ("creationInfo", {"creators": ["wrong"]}, "generator identity"),
                ("comment", "wrong", "source or builder binding"),
                ("packages", [], "package inventory"),
                ("relationships", [], "Cargo graph"),
                ("files", [], "file inventory"),
            ):
                changed = json.loads(sbom_bytes)
                changed[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, diagnostic):
                    VERIFY.validate_sbom(
                        archive, archive_bytes, (json.dumps(changed) + "\n").encode(), metadata
                    )

    def test_sbom_file_identifiers_and_digest_algorithms_are_not_interchangeable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = write_complete_artifact(pathlib.Path(temporary))
            archive_bytes, metadata = VERIFY.verified_release(
                archive, pathlib.Path(str(archive) + ".sha256"), "1" * 40
            )
            original = pathlib.Path(str(archive) + ".spdx.json").read_bytes()
            for field in ("SPDXID", "algorithm", "digest"):
                changed = json.loads(original)
                entry = changed["files"][-1]
                if field == "SPDXID":
                    entry[field] = "SPDXRef-File-unrelated"
                else:
                    entry["checksums"][0][
                        "algorithm" if field == "algorithm" else "checksumValue"
                    ] = "SHA1" if field == "algorithm" else "0" * 64
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(RuntimeError, "file identity"),
                ):
                    VERIFY.validate_sbom(
                        archive, archive_bytes, (json.dumps(changed) + "\n").encode(), metadata
                    )

    def test_tampered_archive_or_sidecar_is_refused_before_destination_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = write_complete_artifact(root)
            for suffix in ("", ".sha256", ".spdx.json", ".SHA256SUMS", ".verify.py"):
                path = archive.with_name(archive.name + suffix)
                original = path.read_bytes()
                path.write_bytes(original + b"\n# altered\n")
                destination = root / "extracted"
                with self.subTest(suffix=suffix), self.assertRaisesRegex(RuntimeError, "mismatch"):
                    VERIFY.extract_release(
                        archive, archive.with_name(archive.name + ".sha256"), "1" * 40, destination
                    )
                self.assertFalse(destination.exists())
                path.write_bytes(original)


class DescriptorAndSnapshotTests(unittest.TestCase):
    def test_regular_descriptor_bounds_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            regular = root / "regular"
            regular.write_bytes(b"bounded")
            self.assertEqual(VERIFY.read_bounded_regular(regular, 7), b"bounded")
            with self.assertRaisesRegex(RuntimeError, "bounded regular"):
                VERIFY.read_bounded_regular(regular, 6)
            link = root / "link"
            link.symlink_to(regular)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (link, fifo, root):
                with self.subTest(path=path.name):
                    code = (
                        "import runpy, pathlib, sys; "
                        "owner=runpy.run_path(sys.argv[1]); "
                        "owner['read_bounded_regular'](pathlib.Path(sys.argv[2]), 256)"
                    )
                    result = subprocess.run(
                        [sys.executable, "-I", "-c", code, VERIFY.__file__, str(path)],
                        capture_output=True,
                        timeout=5,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_extraction_keeps_the_validated_archive_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = write_complete_artifact(root)
            create = pathlib.Path.mkdir

            def replace_after_validation(path, *args, **kwargs):
                if path == root / "extracted":
                    archive.write_bytes(b"changed after validation")
                return create(path, *args, **kwargs)

            with mock.patch.object(pathlib.Path, "mkdir", replace_after_validation):
                extracted = VERIFY.extract_release(
                    archive, pathlib.Path(str(archive) + ".sha256"), "1" * 40, root / "extracted"
                )
            self.assertEqual((extracted / "bin/kapsel").read_bytes(), b"ordinary")


if __name__ == "__main__":
    unittest.main()
