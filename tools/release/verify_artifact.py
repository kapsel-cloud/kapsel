#!/usr/bin/env python3
"""Validate or exclusively extract Kapsel artifacts; never execute bundled code."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import tarfile
from typing import TypedDict, cast


class ReleaseMetadata(TypedDict):
    artifact_schema: str
    package_version: str
    rust_target: str
    source_revision: str
    source_tree: str
    source_dirty: bool
    cargo_lock_sha256: str
    cargo_graph_sha256: str
    cargo_package_count: int
    cargo_relationship_count: int
    license: str
    license_sha256: str
    builder_image: str
    smoke_image: str
    ordinary_binary_bytes: int
    ordinary_binary_sha256: str
    service_binary_bytes: int
    service_binary_sha256: str
    client_binary_bytes: int
    client_binary_sha256: str
    mcp_bridge_binary_bytes: int
    mcp_bridge_binary_sha256: str
    asset_files: dict[str, dict[str, int | str]]
    non_claims: str


TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
NON_CLAIMS = "service-preview;not-production;no-public-rust-api;no-other-targets"
BINARIES = {
    "ordinary": "bin/kapsel",
    "service": "libexec/kapsel/kapseld",
    "client": "bin/kapsel-service-client",
    "mcp_bridge": "bin/kapsel-service-mcp",
}
SBOM_GENERATOR = "kapsel-release-sbom/1"
ASSETS = (
    "share/kapsel/qualification.py",
    "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
    "share/kapsel/kapseld.service",
    "share/kapsel/kapseld.conf",
    "share/kapsel/kapseld-rbac.yaml",
)
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024
FILE_BYTES_MAX = 32 * 1024 * 1024
SBOM_BYTES_MAX = 2 * 1024 * 1024
MANIFEST_BYTES_MAX = 1024
VERIFIER_BYTES_MAX = 64 * 1024
TAR_STREAM_BYTES_MAX = EXPANDED_BYTES_MAX + 64 * 1024


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


def verify_checksum(archive: pathlib.Path, checksum: pathlib.Path) -> tuple[bytes, bytes]:
    checksum_bytes = read_bounded_regular(checksum, 256)
    archive_bytes = read_bounded_regular(archive, ARCHIVE_BYTES_MAX)
    expected = f"{hashlib.sha256(archive_bytes).hexdigest()}  {archive.name}\n".encode()
    if checksum_bytes != expected:
        raise RuntimeError("release archive checksum mismatch")
    return archive_bytes, checksum_bytes


def verify_digest_manifest(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    sbom: pathlib.Path,
    manifest: pathlib.Path,
    archive_bytes: bytes,
    checksum_bytes: bytes,
) -> bytes:
    sbom_bytes = read_bounded_regular(sbom, SBOM_BYTES_MAX)
    verifier = archive.with_name(archive.name + ".verify.py")
    verifier_bytes = read_bounded_regular(verifier, VERIFIER_BYTES_MAX)
    manifest_bytes = read_bounded_regular(manifest, MANIFEST_BYTES_MAX)
    entries = sorted(
        [
            (archive.name, hashlib.sha256(archive_bytes).hexdigest()),
            (checksum.name, hashlib.sha256(checksum_bytes).hexdigest()),
            (sbom.name, hashlib.sha256(sbom_bytes).hexdigest()),
            (verifier.name, hashlib.sha256(verifier_bytes).hexdigest()),
        ]
    )
    expected = "".join(f"{digest}  {name}\n" for name, digest in entries).encode()
    if manifest_bytes != expected:
        raise RuntimeError("release digest manifest mismatch")
    return sbom_bytes


def validate_sbom(
    archive: pathlib.Path,
    archive_bytes: bytes,
    sbom_bytes: bytes,
    metadata: ReleaseMetadata,
) -> None:
    if not sbom_bytes.endswith(b"\n"):
        raise RuntimeError("release SBOM has no trailing newline")
    sbom = json.loads(sbom_bytes)
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("dataLicense") != "CC0-1.0":
        raise RuntimeError("release SBOM SPDX identity changed")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise RuntimeError("release SBOM document identity changed")
    creation = sbom.get("creationInfo")
    if not isinstance(creation, dict) or creation.get("creators") != [f"Tool: {SBOM_GENERATOR}"]:
        raise RuntimeError("release SBOM generator identity changed")
    created = creation.get("created")
    if not isinstance(created, str) or not created.endswith("Z"):
        raise RuntimeError("release SBOM normalized creation time is invalid")

    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    expected_namespace = (
        "https://github.com/kapsel-cloud/kapsel/sbom/"
        f"{metadata['source_revision']}/{archive_digest}"
    )
    if sbom.get("documentNamespace") != expected_namespace:
        raise RuntimeError("release SBOM namespace disagrees with archive identity")
    comment = sbom.get("comment")
    required_comment_facts = [
        f"source_revision={metadata['source_revision']}",
        f"source_tree={metadata['source_tree']}",
        f"rust_target={TARGET}",
        f"builder_image={BUILDER_IMAGE}",
        f"cargo_lock_sha256={metadata['cargo_lock_sha256']}",
        f"cargo_graph_sha256={metadata['cargo_graph_sha256']}",
    ]
    if not isinstance(comment, str) or any(fact not in comment for fact in required_comment_facts):
        raise RuntimeError("release SBOM source or builder binding changed")

    packages = sbom.get("packages")
    if not isinstance(packages, list) or len(packages) < 2:
        raise RuntimeError("release SBOM package inventory is incomplete")
    package_ids = [package.get("SPDXID") for package in packages if isinstance(package, dict)]
    if len(package_ids) != len(packages) or len(set(package_ids)) != len(package_ids):
        raise RuntimeError("release SBOM package identities are invalid")
    archive_packages = [
        package for package in packages if package.get("SPDXID") == "SPDXRef-Package-kapsel-archive"
    ]
    root_packages = [
        package for package in packages if package.get("SPDXID") == "SPDXRef-Package-kapsel-source"
    ]
    if len(archive_packages) != 1 or len(root_packages) != 1:
        raise RuntimeError("release SBOM root package identities changed")

    cargo_packages = [
        package for package in packages if package.get("SPDXID") != "SPDXRef-Package-kapsel-archive"
    ]
    relationships = sbom.get("relationships")
    if not isinstance(relationships, list):
        raise RuntimeError("release SBOM relationships are invalid")
    cargo_relationships = [
        relationship
        for relationship in relationships
        if isinstance(relationship, dict) and relationship.get("relationshipType") == "DEPENDS_ON"
    ]
    graph = {
        "packages": cargo_packages,
        "relationships": cargo_relationships,
        "root_package_id": "SPDXRef-Package-kapsel-source",
    }
    canonical_graph = json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    graph_digest = hashlib.sha256(canonical_graph).hexdigest()
    if (
        len(cargo_packages) != metadata["cargo_package_count"]
        or len(cargo_relationships) != metadata["cargo_relationship_count"]
        or graph_digest != metadata["cargo_graph_sha256"]
    ):
        raise RuntimeError("release SBOM Cargo graph is incomplete")

    archive_package = archive_packages[0]
    if (
        archive_package.get("name") != archive.name
        or archive_package.get("filesAnalyzed") is not False
        or archive_package.get("versionInfo") != metadata["package_version"]
        or archive_package.get("checksums")
        != [{"algorithm": "SHA256", "checksumValue": archive_digest}]
    ):
        raise RuntimeError("release SBOM archive package disagrees")
    if root_packages[0].get("versionInfo") != metadata["package_version"]:
        raise RuntimeError("release SBOM root package version disagrees")
    service_packages = [
        package for package in cargo_packages if package.get("name") == "kapsel-daemon"
    ]
    if (
        len(service_packages) != 1
        or service_packages[0].get("versionInfo") != metadata["package_version"]
    ):
        raise RuntimeError("release SBOM service package identity disagrees")

    files = sbom.get("files")
    expected_files = {
        f"./{path}": metadata[f"{name}_binary_sha256"] for name, path in BINARIES.items()
    }
    expected_files.update({f"./{path}": metadata["asset_files"][path]["sha256"] for path in ASSETS})
    actual_files = {}
    if isinstance(files, list):
        for entry in files:
            if not isinstance(entry, dict):
                raise RuntimeError("release SBOM file record is invalid")
            path = entry.get("fileName")
            if not isinstance(path, str) or path not in expected_files:
                raise RuntimeError("release SBOM file path is invalid")
            identifier = "SPDXRef-File-" + path.removeprefix("./").replace("/", "-")
            if entry.get("SPDXID") != identifier or entry.get("checksums") != [
                {"algorithm": "SHA256", "checksumValue": expected_files[path]}
            ]:
                raise RuntimeError("release SBOM file identity or checksum disagrees")
            actual_files[path] = expected_files[path]
    if (
        not isinstance(files, list)
        or len(files) != len(expected_files)
        or actual_files != expected_files
    ):
        raise RuntimeError("release SBOM file inventory disagrees")

    contains = {
        relationship.get("relatedSpdxElement")
        for relationship in relationships
        if isinstance(relationship, dict)
        and relationship.get("spdxElementId") == "SPDXRef-Package-kapsel-archive"
        and relationship.get("relationshipType") == "CONTAINS"
    }
    if contains != {
        "SPDXRef-File-" + path.replace("/", "-") for path in (*BINARIES.values(), *ASSETS)
    }:
        raise RuntimeError("release SBOM file containment relationships changed")
    if not any(
        relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and relationship.get("relationshipType") == "DESCRIBES"
        and relationship.get("relatedSpdxElement") == "SPDXRef-Package-kapsel-archive"
        for relationship in relationships
        if isinstance(relationship, dict)
    ):
        raise RuntimeError("release SBOM document relationship changed")


def bounded_ustar_bytes(archive_bytes: bytes, expected_entries: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as compressed:
        value = compressed.read(TAR_STREAM_BYTES_MAX + 1)
    if len(value) > TAR_STREAM_BYTES_MAX:
        raise RuntimeError("release tar stream exceeds its decompressed bound")

    offset = 0
    entries = 0
    zero_blocks = 0
    while offset + 512 <= len(value):
        header = value[offset : offset + 512]
        if header == bytes(512):
            zero_blocks += 1
            offset += 512
            if zero_blocks == 2:
                break
            continue
        if zero_blocks:
            raise RuntimeError("release tar has data after an end marker")

        entries += 1
        if entries > expected_entries:
            raise RuntimeError("release tar has too many raw entries")
        if header[257:263] != b"ustar\0":
            raise RuntimeError("release tar is not exact USTAR")
        if header[156:157] not in {b"\0", b"0", b"5"}:
            raise RuntimeError("release tar contains an extension, link, or special header")

        size_field = header[124:136].rstrip(b"\0 ")
        if any(character not in b"01234567" for character in size_field):
            raise RuntimeError("release tar size is not canonical octal")
        size = int(size_field or b"0", 8)
        offset += 512 + ((size + 511) // 512) * 512
        if offset > len(value):
            raise RuntimeError("release tar entry exceeds the decompressed stream")
    if entries != expected_entries or zero_blocks != 2 or any(value[offset:]):
        raise RuntimeError("release tar framing or padding is not canonical")
    return value


def validate_archive(archive: pathlib.Path, archive_bytes: bytes) -> ReleaseMetadata:
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
        f"{basename}/libexec/kapsel/",
        f"{basename}/libexec/kapsel/kapseld",
        f"{basename}/bin/kapsel-service-client",
        f"{basename}/bin/kapsel-service-mcp",
        f"{basename}/share/",
        f"{basename}/share/kapsel/",
        f"{basename}/share/kapsel/kapseld.service",
        f"{basename}/share/kapsel/kapseld.conf",
        f"{basename}/share/kapsel/kapseld-rbac.yaml",
        f"{basename}/share/kapsel/qualification.py",
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
    expected_order = sorted(expected)
    tar_bytes = bounded_ustar_bytes(archive_bytes, len(expected_order))
    evidence_names = {
        f"{basename}/RELEASE-METADATA.json": "metadata",
        f"{basename}/LICENSE": "license",
        **{f"{basename}/{path}": name for name, path in BINARIES.items()},
        **{f"{basename}/{path}": path for path in ASSETS},
    }
    executable_paths = {f"{basename}/{path}" for path in BINARIES.values()}
    evidence: dict[str, bytes] = {}
    expanded_size = 0
    entry_count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r|") as release:
        for member in release:
            entry_count += 1
            if entry_count > len(expected_order):
                raise RuntimeError("release archive has too many entries")
            canonical_name = member.name + ("/" if member.isdir() else "")
            if canonical_name != expected_order[entry_count - 1]:
                raise RuntimeError("release archive layout or ordering is not canonical")
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("release archive path is unsafe")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError("release archive contains a link or special entry")
            if member.isfile():
                if member.size > FILE_BYTES_MAX:
                    raise RuntimeError("release archive entry exceeds its file bound")
                expanded_size += member.size
                if expanded_size > EXPANDED_BYTES_MAX:
                    raise RuntimeError("release archive exceeds its expanded bound")
            identity = (member.uid, member.gid, member.uname, member.gname, member.mtime)
            if identity != (0, 0, "", "", 0):
                raise RuntimeError("release archive metadata is not normalized")
            executable = member.isdir() or member.name in executable_paths
            expected_mode = 0o755 if executable else 0o644
            if member.mode != expected_mode:
                raise RuntimeError("release archive mode is not canonical")
            evidence_key = evidence_names.get(member.name)
            if evidence_key is not None:
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("release archive evidence could not be read")
                value = source.read(member.size + 1)
                if len(value) != member.size:
                    raise RuntimeError("release archive evidence size changed while reading")
                evidence[evidence_key] = value
    if entry_count != len(expected_order) or len(evidence) != len(evidence_names):
        raise RuntimeError("release archive layout or evidence is incomplete")

    return validate_metadata(version, evidence)


def validate_metadata(version: str, evidence: dict[str, bytes]) -> ReleaseMetadata:
    metadata_bytes = evidence["metadata"]
    license_bytes = evidence["license"]
    if not metadata_bytes.endswith(b"\n"):
        raise RuntimeError("release metadata has no trailing newline")
    metadata = json.loads(metadata_bytes)
    expected_keys = [
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
        "mcp_bridge_binary_bytes",
        "mcp_bridge_binary_sha256",
        "asset_files",
        "non_claims",
    ]
    if list(metadata) != expected_keys:
        raise RuntimeError("release metadata fields or order changed")
    if metadata["artifact_schema"] != "kapsel.release-artifact.v4":
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
    tree = metadata["source_tree"]
    if (
        not isinstance(tree, str)
        or len(tree) != 40
        or any(character not in "0123456789abcdef" for character in tree)
    ):
        raise RuntimeError("release source tree is not canonical")
    lock_digest = metadata["cargo_lock_sha256"]
    if (
        not isinstance(lock_digest, str)
        or len(lock_digest) != 64
        or any(character not in "0123456789abcdef" for character in lock_digest)
    ):
        raise RuntimeError("release lockfile digest is not canonical")
    graph_digest = metadata["cargo_graph_sha256"]
    if (
        not isinstance(graph_digest, str)
        or len(graph_digest) != 64
        or any(character not in "0123456789abcdef" for character in graph_digest)
    ):
        raise RuntimeError("release Cargo graph digest is not canonical")
    if (
        not isinstance(metadata["cargo_package_count"], int)
        or metadata["cargo_package_count"] < 1
        or not isinstance(metadata["cargo_relationship_count"], int)
        or metadata["cargo_relationship_count"] < 1
    ):
        raise RuntimeError("release Cargo graph counts are invalid")
    if not isinstance(metadata["source_dirty"], bool):
        raise RuntimeError("release dirty state is not boolean")

    license_digest = hashlib.sha256(license_bytes).hexdigest()
    if metadata["license"] != "Apache-2.0" or metadata["license_sha256"] != license_digest:
        raise RuntimeError("release license provenance disagrees")
    if metadata["builder_image"] != BUILDER_IMAGE or metadata["smoke_image"] != SMOKE_IMAGE:
        raise RuntimeError("release container provenance disagrees")
    if metadata["non_claims"] != NON_CLAIMS:
        raise RuntimeError("release non-claims changed")

    for name in BINARIES:
        declared_size = metadata[f"{name}_binary_bytes"]
        declared_digest = metadata[f"{name}_binary_sha256"]
        binary_bytes = evidence[name]
        if type(declared_size) is not int or declared_size != len(binary_bytes):
            raise RuntimeError("release binary size disagrees")
        if declared_digest != hashlib.sha256(binary_bytes).hexdigest():
            raise RuntimeError("release binary digest disagrees")
    assets = metadata["asset_files"]
    if not isinstance(assets, dict) or list(assets) != list(ASSETS):
        raise RuntimeError("release asset inventory disagrees")
    for path in ASSETS:
        identity = assets[path]
        value = evidence[path]
        if (
            not isinstance(identity, dict)
            or list(identity) != ["bytes", "sha256"]
            or type(identity["bytes"]) is not int
            or identity["bytes"] != len(value)
            or identity["sha256"] != hashlib.sha256(value).hexdigest()
        ):
            raise RuntimeError("release asset digest or size disagrees")
    # Every field above has its independent shape and artifact binding checked before exposure.
    return cast(ReleaseMetadata, metadata)


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


def verified_release(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    expected_revision: str | None,
) -> tuple[bytes, ReleaseMetadata]:
    archive_bytes, checksum_bytes = verify_checksum(archive, checksum)
    sbom = archive.with_name(archive.name + ".spdx.json")
    manifest = archive.with_name(archive.name + ".SHA256SUMS")
    sbom_bytes = verify_digest_manifest(
        archive, checksum, sbom, manifest, archive_bytes, checksum_bytes
    )
    metadata = validate_archive(archive, archive_bytes)
    validate_sbom(archive, archive_bytes, sbom_bytes, metadata)
    if expected_revision is not None and metadata["source_revision"] != expected_revision:
        raise RuntimeError("release source revision disagrees with the expected revision")
    return archive_bytes, metadata


def extract_release(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    expected_revision: str,
    destination: pathlib.Path,
) -> pathlib.Path:
    archive_bytes, _ = verified_release(archive, checksum, expected_revision)
    # Exclusive creation also refuses dangling symlinks. The caller owns the parent.
    destination.mkdir(mode=0o700)
    return extract_exact_archive(archive, archive_bytes, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--extract-to", type=pathlib.Path)
    arguments = parser.parse_args()
    archive = pathlib.Path(os.path.abspath(arguments.archive))
    checksum = archive.with_name(archive.name + ".sha256")
    if arguments.extract_to is not None:
        if arguments.expected_revision is None:
            parser.error("--extract-to requires --expected-revision")
        destination = pathlib.Path(os.path.abspath(arguments.extract_to))
        print(extract_release(archive, checksum, arguments.expected_revision, destination))
    else:
        verified_release(archive, checksum, arguments.expected_revision)
        print("Kapsel release artifact validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
