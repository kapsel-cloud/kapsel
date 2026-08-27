#!/usr/bin/env python3
"""Validate and safely extract one Kapsel service artifact archive."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import tarfile
import zlib

TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663"
)
NON_CLAIMS = "unpublished-preview;not-production;no-compatibility;one-capability;one-target"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024
FILE_BYTES_MAX = 32 * 1024 * 1024
TAR_STREAM_BYTES_MAX = EXPANDED_BYTES_MAX + 64 * 1024


def read_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"input is not one regular file: {path}")
        if metadata.st_size > maximum:
            raise RuntimeError(f"input exceeds its byte bound: {path}")
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise RuntimeError(f"input exceeds its byte bound: {path}")
    return value


def verify_sidecars(archive: pathlib.Path, archive_bytes: bytes) -> None:
    checksum = archive.with_name(archive.name + ".sha256")
    manifest = archive.with_name(archive.name + ".SHA256SUMS")
    checksum_bytes = read_regular(checksum, 256)
    expected_checksum = f"{hashlib.sha256(archive_bytes).hexdigest()}  {archive.name}\n".encode()
    if checksum_bytes != expected_checksum:
        raise RuntimeError("Kapsel service artifact checksum mismatch")
    manifest_bytes = read_regular(manifest, 1024)
    expected_manifest = "".join(
        f"{hashlib.sha256(value).hexdigest()}  {name}\n"
        for name, value in sorted(
            [(archive.name, archive_bytes), (checksum.name, checksum_bytes)]
        )
    ).encode()
    if manifest_bytes != expected_manifest:
        raise RuntimeError("Kapsel service artifact digest manifest mismatch")


def bounded_ustar(archive_bytes: bytes, entries_expected: int) -> bytes:
    if archive_bytes[:10] != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff":
        raise RuntimeError("Kapsel service artifact gzip header is not canonical")
    decompressor = zlib.decompressobj(wbits=31)
    value = decompressor.decompress(archive_bytes, TAR_STREAM_BYTES_MAX + 1)
    if len(value) > TAR_STREAM_BYTES_MAX or decompressor.unconsumed_tail:
        raise RuntimeError("Kapsel service artifact tar stream exceeds its bound")
    value += decompressor.flush(TAR_STREAM_BYTES_MAX + 1 - len(value))
    if (
        len(value) > TAR_STREAM_BYTES_MAX
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise RuntimeError("Kapsel service artifact must contain one bounded gzip member")
    offset = entries = zero_blocks = 0
    while offset + 512 <= len(value):
        header = value[offset : offset + 512]
        if header == bytes(512):
            zero_blocks += 1
            offset += 512
            if zero_blocks == 2:
                break
            continue
        if zero_blocks:
            raise RuntimeError("Kapsel service artifact has data after an end marker")
        entries += 1
        if entries > entries_expected:
            raise RuntimeError("Kapsel service artifact has too many raw entries")
        try:
            canonical_header = tarfile.TarInfo.frombuf(header, "utf-8", "strict").tobuf(
                tarfile.USTAR_FORMAT, "utf-8", "strict"
            )
        except (tarfile.HeaderError, ValueError) as error:
            raise RuntimeError("Kapsel service artifact USTAR header is invalid") from error
        if canonical_header != header:
            raise RuntimeError("Kapsel service artifact USTAR header is not canonical")
        if header[257:263] != b"ustar\0":
            raise RuntimeError("Kapsel service artifact is not exact USTAR")
        if header[156:157] not in {b"\0", b"0", b"5"}:
            raise RuntimeError("Kapsel service artifact has a link, special file, or extension")
        size_field = header[124:136].rstrip(b"\0 ")
        if any(character not in b"01234567" for character in size_field):
            raise RuntimeError("Kapsel service artifact has a noncanonical size")
        size = int(size_field or b"0", 8)
        data_start = offset + 512
        data_end = data_start + size
        next_offset = data_start + ((size + 511) // 512) * 512
        if next_offset > len(value):
            raise RuntimeError("Kapsel service artifact entry exceeds its stream")
        if any(value[data_end:next_offset]):
            raise RuntimeError("Kapsel service artifact entry padding is not zero")
        offset = next_offset
    canonical_length = ((offset + 10_239) // 10_240) * 10_240
    if (
        entries != entries_expected
        or zero_blocks != 2
        or len(value) != canonical_length
        or any(value[offset:])
    ):
        raise RuntimeError("Kapsel service artifact tar framing is not canonical")
    return value


def expected_names(basename: str) -> set[str]:
    files = {
        "bin/kapsel",
        "bin/kapsel-service-client",
        "libexec/kapsel/kapseld",
        "lib/systemd/system/kapseld.service",
        "lib/sysusers.d/kapseld.conf",
        "share/kapsel/kapseld-rbac.yaml",
        "share/kapsel/verify-kapsel-service-artifact.py",
        "share/kapsel/smoke-kapsel-service-artifact.py",
        "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        "LICENSE",
        "SERVICE-METADATA.json",
    }
    directories: set[str] = {f"{basename}/"}
    for name in files:
        parts = pathlib.PurePosixPath(name).parts[:-1]
        for index in range(1, len(parts) + 1):
            directories.add(f"{basename}/{'/'.join(parts[:index])}/")
    return directories | {f"{basename}/{name}" for name in files}


def validate_archive(
    archive: pathlib.Path, archive_bytes: bytes, expected_revision: str
) -> tuple[bytes, dict[str, object]]:
    if len(expected_revision) != 40 or any(
        character not in "0123456789abcdef" for character in expected_revision
    ):
        raise RuntimeError("expected revision is not canonical lowercase SHA-1")
    basename = f"kapsel-service-{expected_revision}-{TARGET}"
    if archive.name != f"{basename}.tar.gz":
        raise RuntimeError("Kapsel service artifact name disagrees with expected identity")
    expected = sorted(expected_names(basename))
    tar_bytes = bounded_ustar(archive_bytes, len(expected))
    evidence_names = {
        f"{basename}/SERVICE-METADATA.json": "metadata",
        f"{basename}/LICENSE": "license",
        f"{basename}/bin/kapsel": "kapsel",
        f"{basename}/bin/kapsel-service-client": "client",
        f"{basename}/libexec/kapsel/kapseld": "daemon",
    }
    evidence: dict[str, bytes] = {}
    expanded = count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r|") as release:
        for member in release:
            count += 1
            canonical = member.name + ("/" if member.isdir() else "")
            if count > len(expected) or canonical != expected[count - 1]:
                raise RuntimeError("Kapsel service artifact layout or ordering changed")
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Kapsel service artifact path is unsafe")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError("Kapsel service artifact contains a link or special file")
            if member.isfile():
                if member.size > FILE_BYTES_MAX:
                    raise RuntimeError("Kapsel service artifact file exceeds its bound")
                expanded += member.size
                if expanded > EXPANDED_BYTES_MAX:
                    raise RuntimeError("Kapsel service artifact expanded size exceeds its bound")
            if (member.uid, member.gid, member.uname, member.gname, member.mtime) != (
                0,
                0,
                "",
                "",
                0,
            ):
                raise RuntimeError("Kapsel service artifact metadata is not normalized")
            executable = member.isdir() or member.name.endswith(
                ("/kapsel", "/kapsel-service-client", "/kapseld", ".py")
            )
            if member.mode != (0o755 if executable else 0o644):
                raise RuntimeError("Kapsel service artifact mode is not canonical")
            key = evidence_names.get(member.name)
            if key is not None:
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("Kapsel service artifact evidence is unreadable")
                evidence[key] = source.read(member.size + 1)
    if count != len(expected) or len(evidence) != len(evidence_names):
        raise RuntimeError("Kapsel service artifact evidence is incomplete")
    metadata = json.loads(evidence["metadata"])
    keys = [
        "artifact_schema",
        "package_version",
        "source_revision",
        "source_tree",
        "source_dirty",
        "rust_target",
        "builder_image",
        "cargo_lock_sha256",
        "license",
        "license_sha256",
        "kapsel_bytes",
        "kapsel_sha256",
        "client_bytes",
        "client_sha256",
        "daemon_bytes",
        "daemon_sha256",
        "non_claims",
    ]
    if list(metadata) != keys:
        raise RuntimeError("Kapsel service artifact metadata fields or order changed")
    if (
        metadata["artifact_schema"] != "kapsel.service-artifact.v1"
        or not isinstance(metadata["package_version"], str)
        or not metadata["package_version"]
        or metadata["source_revision"] != expected_revision
        or metadata["source_dirty"] is not False
        or metadata["rust_target"] != TARGET
        or metadata["builder_image"] != BUILDER_IMAGE
        or metadata["license"] != "Apache-2.0"
        or metadata["non_claims"] != NON_CLAIMS
    ):
        raise RuntimeError("Kapsel service artifact metadata identity changed")
    for field in ["source_tree"]:
        value = metadata[field]
        if not isinstance(value, str) or len(value) != 40 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise RuntimeError(f"Kapsel service artifact {field} is invalid")
    for name in ["cargo_lock", "license", "kapsel", "client", "daemon"]:
        digest = metadata[f"{name}_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise RuntimeError(f"Kapsel service artifact {name} digest is invalid")
    if hashlib.sha256(evidence["license"]).hexdigest() != metadata["license_sha256"]:
        raise RuntimeError("Kapsel service artifact license digest disagrees")
    for name in ["kapsel", "client", "daemon"]:
        value = evidence[name]
        if len(value) != metadata[f"{name}_bytes"] or hashlib.sha256(value).hexdigest() != metadata[
            f"{name}_sha256"
        ]:
            raise RuntimeError(f"Kapsel service artifact {name} identity disagrees")
        if value[:4] != b"\x7fELF" or value[4:6] != b"\x02\x01" or int.from_bytes(
            value[18:20], "little"
        ) != 62:
            raise RuntimeError(f"Kapsel service artifact {name} is not x86-64 ELF")
    return tar_bytes, metadata


def extract(tar_bytes: bytes, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700, follow_symlinks=False)
    top_level: pathlib.Path | None = None
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as release:
        for member in release:
            parts = pathlib.PurePosixPath(member.name).parts
            if top_level is None:
                top_level = destination / parts[0]
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(mode=member.mode)
                os.chmod(target, member.mode, follow_symlinks=False)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("Kapsel service artifact file is unreadable")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    member.mode,
                )
                with os.fdopen(descriptor, "wb") as output:
                    os.fchmod(output.fileno(), member.mode)
                    shutil.copyfileobj(source, output)
            metadata = os.lstat(target)
            if stat.S_IMODE(metadata.st_mode) != member.mode:
                raise RuntimeError("Kapsel service artifact extracted mode changed")
    if top_level is None:
        raise RuntimeError("Kapsel service artifact is empty")
    return top_level


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--extract-directory", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    archive = pathlib.Path(os.path.abspath(arguments.archive))
    archive_bytes = read_regular(archive, ARCHIVE_BYTES_MAX)
    verify_sidecars(archive, archive_bytes)
    tar_bytes, _ = validate_archive(archive, archive_bytes, arguments.expected_revision)
    root = extract(tar_bytes, pathlib.Path(os.path.abspath(arguments.extract_directory)))
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
