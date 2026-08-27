#!/usr/bin/env python3
"""Test hostile handling and one assembled Kapsel service artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
SMOKE_IMAGE = (
    "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
)
ARCHIVE: pathlib.Path | None = None

SPEC = importlib.util.spec_from_file_location(
    "verify_kapsel_service", ROOT / "scripts" / "verify-kapsel-service-artifact.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Kapsel service artifact verifier")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def fake_elf(label: bytes) -> bytes:
    value = bytearray(64 + len(label))
    value[:6] = b"\x7fELF\x02\x01"
    value[18:20] = (62).to_bytes(2, "little")
    value[64:] = label
    return bytes(value)


def synthetic_archive(path: pathlib.Path, mutation: str | None = None) -> bytes:
    revision = "1" * 40
    basename = f"kapsel-service-{revision}-{TARGET}"
    files = {
        "bin/kapsel": fake_elf(b"kapsel"),
        "bin/kapsel-service-client": fake_elf(b"client"),
        "libexec/kapsel/kapseld": fake_elf(b"daemon"),
        "lib/systemd/system/kapseld.service": b"unit\n",
        "lib/sysusers.d/kapseld.conf": b"sysusers\n",
        "share/kapsel/kapseld-rbac.yaml": b"rbac\n",
        "share/kapsel/verify-kapsel-service-artifact.py": b"#!/usr/bin/env python3\n",
        "share/kapsel/smoke-kapsel-service-artifact.py": b"#!/usr/bin/env python3\n",
        "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md": b"guide\n",
        "LICENSE": b"license\n",
    }
    metadata: dict[str, object] = {
        "artifact_schema": "kapsel.service-artifact.v1",
        "package_version": "0.2.0",
        "source_revision": revision,
        "source_tree": "2" * 40,
        "source_dirty": False,
        "rust_target": TARGET,
        "builder_image": VERIFY.BUILDER_IMAGE,
        "cargo_lock_sha256": "3" * 64,
        "license": "Apache-2.0",
        "license_sha256": hashlib.sha256(files["LICENSE"]).hexdigest(),
    }
    for name, file_name in [
        ("kapsel", "bin/kapsel"),
        ("client", "bin/kapsel-service-client"),
        ("daemon", "libexec/kapsel/kapseld"),
    ]:
        metadata[f"{name}_bytes"] = len(files[file_name])
        metadata[f"{name}_sha256"] = hashlib.sha256(files[file_name]).hexdigest()
    metadata["non_claims"] = VERIFY.NON_CLAIMS
    files["SERVICE-METADATA.json"] = (
        json.dumps(metadata, indent=2, separators=(",", ": ")) + "\n"
    ).encode()

    names = sorted(VERIFY.expected_names(basename))
    added = {
        "extra": f"{basename}/EXTRA",
        "traversal": f"{basename}/../escape",
        "absolute": "/escape",
        "duplicate": f"{basename}/LICENSE",
    }.get(mutation)
    if added is not None:
        names.append(added)
        names.sort()
    output = io.BytesIO()
    archive_format = {
        "gnu": tarfile.GNU_FORMAT,
        "pax": tarfile.PAX_FORMAT,
    }.get(mutation, tarfile.USTAR_FORMAT)
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=archive_format) as release:
            for name in names:
                member = tarfile.TarInfo(name)
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ""
                is_directory = name.endswith("/")
                executable = is_directory or name.endswith(
                    ("/kapsel", "/kapsel-service-client", "/kapseld", ".py")
                )
                member.mode = 0o755 if executable else 0o644
                if mutation == "unsafe-mode" and name.endswith("/LICENSE"):
                    member.mode = 0o666
                if is_directory:
                    member.type = tarfile.DIRTYPE
                    release.addfile(member)
                    continue
                if mutation in {"symlink", "hardlink", "special"} and name.endswith("/LICENSE"):
                    member.type = {
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "special": tarfile.CHRTYPE,
                    }[mutation]
                    member.linkname = "SERVICE-METADATA.json"
                    release.addfile(member)
                    continue
                value = files.get(name.removeprefix(f"{basename}/"), b"extra\n")
                member.size = len(value)
                release.addfile(member, io.BytesIO(value))
    result = output.getvalue()
    if mutation == "gzip-mtime":
        changed = bytearray(result)
        changed[4] = 1
        return bytes(changed)
    if mutation == "second-gzip-member":
        second = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=second, mtime=0):
            pass
        return result + second.getvalue()
    if mutation in {"ustar-version", "entry-padding", "extra-zero-tail"}:
        raw = bytearray(gzip.decompress(result))
        if mutation == "ustar-version":
            raw[263:265] = b" \x00"
            raw[148:156] = b"        "
            raw[148:156] = f"{sum(raw[:512]):06o}\0 ".encode()
        elif mutation == "entry-padding":
            offset = 0
            while raw[offset : offset + 512] != bytes(512):
                size = int(raw[offset + 124 : offset + 136].rstrip(b"\0 ") or b"0", 8)
                if size and size % 512 != 0:
                    raw[offset + 512 + size] = 1
                    break
                offset += 512 + ((size + 511) // 512) * 512
            else:
                raise RuntimeError("synthetic archive has no entry padding")
        else:
            raw.extend(bytes(10_240))
        rewritten = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=rewritten, mtime=0) as compressed:
            compressed.write(raw)
        return rewritten.getvalue()
    return result


class KapselServiceVerifierTests(unittest.TestCase):
    def test_canonical_archive_validates_and_extracts_exclusively(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive = parent / f"kapsel-service-{'1' * 40}-{TARGET}.tar.gz"
            value = synthetic_archive(archive)
            tar_bytes, metadata = VERIFY.validate_archive(archive, value, "1" * 40)
            self.assertEqual(metadata["artifact_schema"], "kapsel.service-artifact.v1")
            previous_umask = os.umask(0o777)
            try:
                root = VERIFY.extract(tar_bytes, parent / "extracted")
            finally:
                os.umask(previous_umask)
            self.assertTrue(root.joinpath("bin/kapsel-service-client").is_file())
            self.assertEqual(root.joinpath("bin/kapsel-service-client").stat().st_mode & 0o777, 0o755)
            self.assertEqual(root.joinpath("LICENSE").stat().st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                VERIFY.extract(tar_bytes, parent / "extracted")

    def test_hostile_archive_matrix_fails_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / (
                f"kapsel-service-{'1' * 40}-{TARGET}.tar.gz"
            )
            for mutation in [
                "extra",
                "traversal",
                "absolute",
                "duplicate",
                "symlink",
                "hardlink",
                "special",
                "unsafe-mode",
                "pax",
                "gnu",
                "gzip-mtime",
                "second-gzip-member",
                "ustar-version",
                "entry-padding",
                "extra-zero-tail",
            ]:
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    VERIFY.validate_archive(archive, synthetic_archive(archive, mutation), "1" * 40)

    def test_oversized_input_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "oversized"
            with path.open("wb") as output:
                output.truncate(VERIFY.ARCHIVE_BYTES_MAX + 1)
            with self.assertRaises(RuntimeError):
                VERIFY.read_regular(path, VERIFY.ARCHIVE_BYTES_MAX)

    def test_sidecar_symlink_and_digest_changes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / f"kapsel-service-{'1' * 40}-{TARGET}.tar.gz"
            archive_bytes = synthetic_archive(archive)
            archive.write_bytes(archive_bytes)
            checksum = archive.with_name(archive.name + ".sha256")
            checksum.write_text(f"{'0' * 64}  {archive.name}\n")
            manifest = archive.with_name(archive.name + ".SHA256SUMS")
            manifest.write_text("changed\n")
            with self.assertRaises(RuntimeError):
                VERIFY.verify_sidecars(archive, archive_bytes)
            checksum.unlink()
            target = root / "target"
            target.write_text("value")
            checksum.symlink_to(target)
            with self.assertRaises(OSError):
                VERIFY.verify_sidecars(archive, archive_bytes)


class AssembledKapselServiceTests(unittest.TestCase):
    def test_strict_artifact_validates_and_matches_bundled_verifier(self) -> None:
        if ARCHIVE is None:
            self.skipTest("--archive was not supplied")
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        archive_bytes = VERIFY.read_regular(ARCHIVE, VERIFY.ARCHIVE_BYTES_MAX)
        VERIFY.verify_sidecars(ARCHIVE, archive_bytes)
        tar_bytes, metadata = VERIFY.validate_archive(ARCHIVE, archive_bytes, revision)
        with tempfile.TemporaryDirectory() as temporary:
            root = VERIFY.extract(tar_bytes, pathlib.Path(temporary) / "extracted")
            for source, packaged in [
                ("scripts/verify-kapsel-service-artifact.py", "share/kapsel/verify-kapsel-service-artifact.py"),
                (
                    "scripts/smoke-kapsel-service-artifact.py",
                    "share/kapsel/smoke-kapsel-service-artifact.py",
                ),
            ]:
                self.assertEqual(root.joinpath(packaged).read_bytes(), ROOT.joinpath(source).read_bytes())
            for source, packaged in [
                ("crates/kapseld/deploy/kapseld.service", "lib/systemd/system/kapseld.service"),
                ("crates/kapseld/deploy/kapseld.conf", "lib/sysusers.d/kapseld.conf"),
                ("crates/kapseld/deploy/kapseld-rbac.yaml", "share/kapsel/kapseld-rbac.yaml"),
            ]:
                self.assertEqual(root.joinpath(packaged).read_bytes(), ROOT.joinpath(source).read_bytes())
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--volume",
                    f"{root}:/artifact:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "/artifact/share/kapsel/smoke-kapsel-service-artifact.py",
                    "--extracted-root",
                    "/artifact",
                    "--expected-kapsel-version",
                    str(metadata["package_version"]),
                ],
                check=True,
                timeout=120,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=pathlib.Path)
    arguments, unittest_arguments = parser.parse_known_args()
    if arguments.archive is not None:
        ARCHIVE = pathlib.Path(os.path.abspath(arguments.archive))
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
