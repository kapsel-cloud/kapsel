#!/usr/bin/env python3
"""Execute the extracted Kapsel release artifact in a clean Linux environment."""

from __future__ import annotations

import argparse
import grp
import gzip
import hashlib
import http.server
import io
import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import sys
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
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
NON_CLAIMS = "service-preview;not-production;no-public-rust-api;no-other-targets"
BINARIES = {
    "ordinary": "bin/kapsel",
    "service": "libexec/kapsel/kapseld",
    "client": "bin/kapsel-service-client",
}
SBOM_GENERATOR = "kapsel-release-sbom/1"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024
FILE_BYTES_MAX = 32 * 1024 * 1024
SBOM_BYTES_MAX = 2 * 1024 * 1024
MANIFEST_BYTES_MAX = 1024
VERIFIER_BYTES_MAX = 64 * 1024
TAR_STREAM_BYTES_MAX = EXPANDED_BYTES_MAX + 64 * 1024
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
    metadata: dict[str, object],
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
    graph_digest = hashlib.sha256(
        json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
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
    service_packages = [package for package in cargo_packages if package.get("name") == "kapseld"]
    if (
        len(service_packages) != 1
        or service_packages[0].get("versionInfo") != metadata["package_version"]
    ):
        raise RuntimeError("release SBOM service package identity disagrees")
    files = sbom.get("files")
    expected_files = {
        f"./{path}": metadata[f"{name}_binary_sha256"] for name, path in BINARIES.items()
    }
    actual_files = {}
    if isinstance(files, list):
        for entry in files:
            if isinstance(entry, dict):
                checksums = entry.get("checksums")
                if isinstance(checksums, list) and len(checksums) == 1:
                    actual_files[entry.get("fileName")] = checksums[0].get("checksumValue")
    if (
        not isinstance(files, list)
        or len(files) != len(expected_files)
        or actual_files != expected_files
    ):
        raise RuntimeError("release SBOM binary inventory disagrees")
    contains = {
        relationship.get("relatedSpdxElement")
        for relationship in relationships
        if isinstance(relationship, dict)
        and relationship.get("spdxElementId") == "SPDXRef-Package-kapsel-archive"
        and relationship.get("relationshipType") == "CONTAINS"
    }
    if contains != {"SPDXRef-File-" + path.replace("/", "-") for path in BINARIES.values()}:
        raise RuntimeError("release SBOM binary containment relationships changed")
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
    expected_order = sorted(expected)
    tar_bytes = bounded_ustar_bytes(archive_bytes, len(expected_order))
    evidence_names = {
        f"{basename}/RELEASE-METADATA.json": "metadata",
        f"{basename}/LICENSE": "license",
        **{f"{basename}/{path}": name for name, path in BINARIES.items()},
    }
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
            executable = member.isdir() or member.name in {
                f"{basename}/{path}" for path in BINARIES.values()
            }
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
        "non_claims",
    ]
    if list(metadata) != expected_keys:
        raise RuntimeError("release metadata fields or order changed")
    if metadata["artifact_schema"] != "kapsel.release-artifact.v3":
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
        if type(metadata[f"{name}_binary_bytes"]) is not int or metadata[
            f"{name}_binary_bytes"
        ] != len(evidence[name]):
            raise RuntimeError("release binary size disagrees")
        if metadata[f"{name}_binary_sha256"] != hashlib.sha256(evidence[name]).hexdigest():
            raise RuntimeError("release binary digest disagrees")
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
    mutations = 0

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

    def do_PATCH(self) -> None:
        type(self).mutations += 1
        self.rfile.read(int(self.headers.get("content-length", "0")))
        self.respond()


def reset_kubernetes_fixture() -> None:
    KubernetesFixture.responses = [
        deployment("1", 1, False),
        deployment("2", 2, False),
        deployment("3", 2, True),
    ]
    KubernetesFixture.requests = 0
    KubernetesFixture.mutations = 0


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


def exercise_version(binary: pathlib.Path, expected_version: object) -> None:
    if not isinstance(expected_version, str):
        raise RuntimeError("release metadata package version is invalid")
    result = subprocess.run(
        [str(binary), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    if result.stdout != f"kapsel {expected_version}\n".encode() or result.stderr:
        raise RuntimeError("installed executable version identity disagrees")


def verified_release(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    expected_revision: str | None,
) -> tuple[bytes, dict[str, object]]:
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


def smoke(
    archive: pathlib.Path,
    checksum: pathlib.Path,
    expected_revision: str | None = None,
    service_container: bool = False,
    service_systemd: bool = False,
) -> None:
    archive_bytes, metadata = verified_release(archive, checksum, expected_revision)
    if service_systemd and metadata["source_dirty"]:
        raise RuntimeError("native qualification requires a clean committed-source artifact")
    with tempfile.TemporaryDirectory(prefix="kapsel-clean-smoke-") as temporary:
        root = extract_exact_archive(archive, archive_bytes, pathlib.Path(temporary))
        extracted_binary = root / "bin" / "kapsel"
        installation = pathlib.Path(temporary) / "installation"
        installation.mkdir(mode=0o755)
        binary = installation / "kapsel"
        shutil.copyfile(extracted_binary, binary)
        binary.chmod(0o755)
        if sha256(binary) != metadata["ordinary_binary_sha256"]:
            raise RuntimeError("installed ordinary binary digest mismatch")
        for name, relative in BINARIES.items():
            if sha256(root / relative) != metadata[f"{name}_binary_sha256"]:
                raise RuntimeError("extracted binary digest mismatch")
        exercise_version(binary, metadata["package_version"])

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
            write_private(trust, fixture_receipt_trust())
            inspect_receipt(binary, receipt, trust)
            exercise_mcp(binary, paths["operator"], metadata["package_version"])
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=5)
        shutil.rmtree(evaluation)
        if evaluation.exists():
            raise RuntimeError("artifact smoke did not clean its evaluation directory")

        if service_container or service_systemd:
            exercise_service(root, pathlib.Path(temporary), service_systemd)
        binary.unlink()
        installation.rmdir()
        if installation.exists():
            raise RuntimeError("artifact smoke did not uninstall the ordinary binary")


def systemctl(*arguments: str) -> str:
    return subprocess.run(
        ["systemctl", *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


def refuse_systemd_references(parent: pathlib.Path) -> None:
    # Include dangling enablement links and aliases, without adopting or deleting them.
    for name in ("kapseld.service", "kapseld.service.d"):
        if os.path.lexists(parent / name):
            raise RuntimeError("native qualification refuses an existing unit or override")
    for path in [*parent.glob("*"), *parent.glob("*/*")]:
        if path.name == "kapseld.service" or (
            path.is_symlink() and path.resolve().name == "kapseld.service"
        ):
            raise RuntimeError("native qualification refuses existing service references")


def require_disabled_unit() -> None:
    result = subprocess.run(
        ["systemctl", "is-enabled", "kapseld.service"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 1 or result.stdout.strip() != "disabled":
        raise RuntimeError("qualification unit is not disabled")


def install_systemd_assets(root: pathlib.Path) -> tuple[int, int, int]:
    if (
        os.uname().machine != "x86_64"
        or pathlib.Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise RuntimeError("native qualification requires x86-64 Linux with systemd as PID 1")
    if pathlib.Path("/.dockerenv").exists():
        raise RuntimeError("native qualification refuses a Docker container")
    print("native architecture:", os.uname().machine)
    print(pathlib.Path("/etc/os-release").read_text().strip())
    print(systemctl("--version"))
    for name in ("kapsel", "kapsel-service-caller"):
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("native qualification refuses existing identities")
    for name in ("kapsel", "kapsel-service-callers"):
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("native qualification refuses existing groups")
    unit_paths = subprocess.run(
        ["systemd-analyze", "--system", "unit-paths"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()
    if not unit_paths or any(not pathlib.Path(path).is_absolute() for path in unit_paths):
        raise RuntimeError("systemd unit search paths are unavailable")
    for parent in unit_paths:
        refuse_systemd_references(pathlib.Path(parent))
    if systemctl("show", "kapseld.service", "-p", "LoadState", "--value") != "not-found":
        raise RuntimeError("native qualification refuses a loaded service")
    subprocess.run(
        ["install", "-d", "-m", "0755", "/usr/share/kapsel", "/usr/share/doc/kapsel"],
        check=True,
        timeout=10,
    )
    for document in (root / "share/doc/kapsel").iterdir():
        destination = pathlib.Path("/usr/share/doc/kapsel") / document.name
        with destination.open("xb") as output:
            output.write(document.read_bytes())
        destination.chmod(0o644)
    for asset, destination in (
        ("kapseld.service", "/usr/lib/systemd/system/kapseld.service"),
        ("kapseld.conf", "/usr/lib/sysusers.d/kapseld.conf"),
        ("kapseld-rbac.yaml", "/usr/share/kapsel/kapseld-rbac.yaml"),
    ):
        path = pathlib.Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write((root / "share/kapsel" / asset).read_bytes())
        path.chmod(0o644)
    subprocess.run(["systemd-sysusers", "/usr/lib/sysusers.d/kapseld.conf"], check=True, timeout=30)
    subprocess.run(
        [
            "useradd",
            "--system",
            "--no-create-home",
            "--gid",
            "kapsel-service-callers",
            "--shell",
            "/usr/sbin/nologin",
            "kapsel-service-caller",
        ],
        check=True,
        timeout=30,
    )
    systemctl("daemon-reload")
    require_disabled_unit()
    return (
        pwd.getpwnam("kapsel").pw_uid,
        pwd.getpwnam("kapsel-service-caller").pw_uid,
        grp.getgrnam("kapsel-service-callers").gr_gid,
    )


def exercise_journald_failure() -> None:
    # No operator document exists yet. This must fail closed and emit only the fixed category.
    subprocess.run(
        ["systemctl", "start", "kapseld.service"], capture_output=True, check=False, timeout=30
    )
    deadline = time.monotonic() + 10
    while systemctl("show", "kapseld.service", "-p", "ActiveState", "--value") != "failed":
        if time.monotonic() >= deadline:
            raise RuntimeError("unprovisioned native service did not fail closed")
        time.sleep(0.05)
    invocation = systemctl("show", "kapseld.service", "-p", "InvocationID", "--value")
    if len(invocation) != 32 or any(value not in "0123456789abcdef" for value in invocation):
        raise RuntimeError("native service invocation identity is unavailable")
    subprocess.run(["journalctl", "--sync"], check=True, timeout=30)
    diagnostic = subprocess.run(
        ["journalctl", f"_SYSTEMD_INVOCATION_ID={invocation}", "--output=cat", "--no-pager"],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    if b"provisioning_unavailable" not in diagnostic or any(
        value in diagnostic for value in FORBIDDEN
    ):
        raise RuntimeError("native journald provisioning diagnostic missing or unsafe")
    systemctl("stop", "kapseld.service")
    print("Broken setup: startup failed with provisioning_unavailable (operator document absent).")
    print("Diagnosis: systemctl status kapseld.service; journalctl -u kapseld.service")
    print("Next: prepare and publish the explicit approval, then start the service.")


def exercise_service(root: pathlib.Path, temporary: pathlib.Path, native: bool = False) -> None:
    """Explicit fresh-host qualification only. Never adopts or removes retained state."""
    if os.geteuid() != 0 or (not native and not pathlib.Path("/.dockerenv").is_file()):
        raise RuntimeError("service smoke requires root and an explicit disposable-host mode")
    private_roots = [
        pathlib.Path(path) for path in ("/etc/kapsel", "/var/lib/kapsel", "/run/kapsel")
    ]
    destinations = {
        "ordinary": pathlib.Path("/usr/bin/kapsel"),
        "service": pathlib.Path("/usr/libexec/kapsel/kapseld"),
        "client": pathlib.Path("/usr/bin/kapsel-service-client"),
    }
    fresh_paths = [
        *private_roots,
        *destinations.values(),
        "/usr/libexec/kapsel",
        "/usr/share/kapsel",
        "/usr/share/doc/kapsel",
        "/usr/lib/sysusers.d/kapseld.conf",
        "/var/lib/kapsel-installer",
        "/run/lock/kapsel-installer.lock",
        "/tmp/kapsel-artifact-receipt-0",
        "/tmp/kapsel-artifact-receipt-1",
    ]
    if any(os.path.lexists(path) for path in fresh_paths):
        raise RuntimeError("service smoke refuses existing installation or state")
    service_uid, caller_uid, caller_gid = (
        install_systemd_assets(root) if native else (61000, 61001, 61000)
    )
    if service_uid == caller_uid or service_uid == 0 or caller_uid == 0:
        raise RuntimeError("qualification requires distinct unprivileged identities")
    subprocess.run(["install", "-d", "-m", "0755", "/usr/libexec/kapsel"], check=True, timeout=10)
    for name, destination in destinations.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write((root / BINARIES[name]).read_bytes())
        destination.chmod(0o755)
    for directory in private_roots:
        mode = 0o750 if directory == private_roots[2] else 0o700
        directory.mkdir(mode=mode)
        directory.chmod(mode)
        os.chown(directory, service_uid, caller_gid)
    if native:
        print(
            "Disposable service example: production binaries and systemd; loopback receiver only."
        )
        print("Installed the extracted assets with separate service and caller identities.")
        exercise_journald_failure()
    # The temporary fixture remains operator-only. Neither service nor caller traverses it.
    evaluation = temporary / "service-evaluation"
    evaluation.mkdir(mode=0o700)
    reset_kubernetes_fixture()
    KubernetesFixture.responses.insert(0, deployment("1", 1, False))
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KubernetesFixture)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        paths = prepare_inputs(evaluation, fixture.server_address)
        grant = evaluation / "snapshot.grant"
        provision = run_binary(
            destinations["ordinary"],
            [
                "provision-snapshot-grant",
                "--authorization",
                str(paths["authorization"]),
                "--kubeconfig",
                str(evaluation / "kubeconfig.yaml"),
                "--signing-seed",
                str(evaluation / "authorization.seed"),
                "--signing-key-id",
                "artifact-authorization-key",
                "--output",
                str(grant),
            ],
        )
        if provision.returncode != 0 or KubernetesFixture.requests != 1:
            raise RuntimeError("artifact snapshot provisioning failed")
        print("Snapshot approval:", paths["authorization"].read_text())
        candidate = evaluation / "operator.candidate.json"
        prepared = run_binary(
            destinations["ordinary"],
            [
                "prepare-service-config",
                "--authorization-key",
                "artifact-authorization-key",
                str(evaluation / "authorization.pub"),
                "--approval",
                "Artifact smoke",
                str(grant),
                "--receipt-signing-key-id",
                "kap0038-test-key",
                "--output",
                str(candidate),
            ],
        )
        if prepared.returncode != 0:
            raise RuntimeError("artifact configuration preparation failed")
        document = read_bounded_regular(candidate, 160 * 1024)
        validated = run_binary(
            destinations["ordinary"],
            ["validate-service-config", "--operator-config", str(candidate)],
        )
        if (
            validated.returncode != 0
            or json.loads(validated.stdout).get("status") != "VALIDATED_STATIC"
            or candidate.read_bytes() != document
            or KubernetesFixture.requests != 1
        ):
            raise RuntimeError("artifact static configuration validation failed")
        for name in ("kubeconfig.yaml", "receipt.seed"):
            destination = private_roots[0] / name
            write_private(destination, (evaluation / name).read_bytes())
            os.chown(destination, service_uid, caller_gid)
        publication = subprocess.run(
            [str(destinations["service"]), "--replace-operator-config"],
            input=document,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            user=service_uid,
            group=caller_gid,
            extra_groups=[],
            timeout=30,
            check=False,
        )
        if (
            publication.returncode != 0
            or publication.stdout != b"PUBLISHED\n"
            or publication.stderr
        ):
            raise RuntimeError("artifact initial cold publication failed")
        print("Configuration: PREPARED, then PUBLISHED. Static checks are not execution readiness.")
        trust = private_roots[0] / "example-receipt.trust"
        write_private(trust, fixture_receipt_trust(snapshot=True))
        os.chown(trust, service_uid, caller_gid)
        for restart in range(2):
            before = KubernetesFixture.requests
            if native:
                print(
                    "Start:" if restart == 0 else "Read-first restart:",
                    "systemctl start kapseld.service",
                )
                systemctl("start", "kapseld.service")
            else:
                process = subprocess.Popen(
                    [
                        str(destinations["service"]),
                        "--operator-config",
                        "/etc/kapsel/operator.json",
                        "--socket",
                        "/run/kapsel/kapseld.sock",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    user=service_uid,
                    group=caller_gid,
                    extra_groups=[],
                    umask=0o077,
                )
            deadline = time.monotonic() + 20
            # A stale socket pathname is not readiness. Retry only the offline read.
            while True:
                if (
                    process is not None and process.poll() is not None
                ) or time.monotonic() >= deadline:
                    raise RuntimeError("artifact service startup failed")
                try:
                    catalog = service_client(
                        destinations["client"], ["list"], caller_uid, caller_gid
                    )
                    if (
                        native
                        and restart == 1
                        and "After cold replacement" not in json.dumps(catalog)
                    ):
                        raise RuntimeError("native restart did not load the replaced catalog")
                    break
                except RuntimeError:
                    time.sleep(0.02)
            socket = pathlib.Path("/run/kapsel/kapseld.sock").stat()
            if (socket.st_mode & 0o777, socket.st_uid, socket.st_gid) != (
                0o660,
                service_uid,
                caller_gid,
            ):
                raise RuntimeError("installed service socket custody differs")
            denied = subprocess.run(
                [sys.executable, "-c", "open('/etc/kapsel/operator.json', 'rb')"],
                user=caller_uid,
                group=caller_gid,
                extra_groups=[],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if denied.returncode == 0 or b"PermissionError" not in denied.stderr:
                raise RuntimeError("caller private-file confinement not established")
            # Read first after every start. Startup and reads must not contact the receiver.
            service_client(destinations["client"], ["history"], caller_uid, caller_gid)
            if KubernetesFixture.requests != before:
                raise RuntimeError("artifact startup or reads contacted the receiver")
            if restart == 0:
                admitted = service_client(
                    destinations["client"], ["submit", OPERATION], caller_uid, caller_gid
                )
                if admitted.get("status") != "ADMITTED":
                    raise RuntimeError("artifact did not admit the selected approval")
                print("Submit:", json.dumps(admitted, sort_keys=True))
            while True:
                status = service_client(
                    destinations["client"], ["status", OPERATION], caller_uid, caller_gid
                )
                if status.get("status") == "SUCCEEDED":
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("artifact selection failed to complete")
                time.sleep(0.02)
            print("Stored status:", json.dumps(status, sort_keys=True))
            receipt = pathlib.Path(f"/tmp/kapsel-artifact-receipt-{restart}")
            exported = service_client(
                destinations["client"], ["receipt", OPERATION, str(receipt)], caller_uid, caller_gid
            )
            print("Receipt:", json.dumps(exported, sort_keys=True))
            inspect_receipt(destinations["ordinary"], receipt, trust)
            print(
                "Offline inspection: INSPECTED under separately appointed disposable fixture trust."
            )
            if restart == 0:
                frozen = receipt.read_bytes()
            elif receipt.read_bytes() != frozen:
                raise RuntimeError("artifact restart changed receipt bytes")
            if native:
                systemctl("stop", "kapseld.service")
                print("Stop: systemctl stop kapseld.service")
                if (
                    systemctl("show", "kapseld.service", "-p", "MainPID", "--value") != "0"
                    or systemctl("show", "kapseld.service", "-p", "ActiveState", "--value")
                    != "inactive"
                ):
                    raise RuntimeError("native service did not retire")
                changed = json.loads(document)
                changed["approvals"][0]["label"] = "After cold replacement"
                document = json.dumps(changed).encode()
                replacement = subprocess.run(
                    [str(destinations["service"]), "--replace-operator-config"],
                    input=document,
                    capture_output=True,
                    user=service_uid,
                    group=caller_gid,
                    extra_groups=[],
                    timeout=30,
                    check=False,
                )
                if pathlib.Path("/etc/kapsel/operator.json").read_bytes() != document:
                    raise RuntimeError("native configuration replacement bytes differ")
                if (
                    replacement.returncode != 0
                    or replacement.stdout != b"PUBLISHED\n"
                    or replacement.stderr
                ):
                    raise RuntimeError("native cold replacement against retained history failed")
            else:
                process.terminate()
                _, diagnostic = process.communicate(timeout=30)
                if process.returncode != 0 or len(diagnostic) > 4096:
                    raise RuntimeError("artifact graceful retirement failed")
                process = None
            if KubernetesFixture.mutations != 1 or KubernetesFixture.requests != 4:
                raise RuntimeError("artifact repeated receiver work")
        if native:
            require_disabled_unit()
        # Native hosts retain installation, identities, fixture authority and history, stopped.
        print(
            "service qualification: one PATCH, read-first restart, identical receipt; retained state preserved"
        )
    finally:
        if native:
            systemctl("stop", "kapseld.service")
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)


def service_client(binary: pathlib.Path, arguments: list[str], uid: int, gid: int) -> dict:
    result = subprocess.run(
        [str(binary), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        user=uid,
        group=gid,
        extra_groups=[],
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > 64 * 1024:
        raise RuntimeError("artifact service client failed")
    if any(canary in result.stdout for canary in FORBIDDEN):
        raise RuntimeError("artifact service client disclosed private material")
    response = json.loads(result.stdout)
    if response.get("version") != 1:
        raise RuntimeError("artifact service protocol identity changed")
    return response


def fixture_receipt_trust(*, snapshot: bool = False) -> bytes:
    """Public smoke fixture only. Never included as operator trust in the archive."""
    purpose = (
        b"kapsel.kap0038.kubernetes-effect-receipt.v3"
        if snapshot
        else b"kapsel.kap0038.kubernetes-effect-receipt.v2"
    )
    fields = [
        b"kap0038-test-key",
        AUTHORIZATION_PUBLIC_KEY,
        purpose,
        (100).to_bytes(8, "big"),
        (200).to_bytes(8, "big"),
    ]
    return b"KAPSEL-KAP0038-K8S-TRUST-V2\0" + b"".join(
        bytes([index]) + len(value).to_bytes(4, "big") + value
        for index, value in enumerate(fields, 1)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--service-container", action="store_true")
    mode.add_argument(
        "--service-systemd",
        action="store_true",
        help="root-only fresh native host qualification with loopback fixture; leaves stopped test installation/state",
    )
    mode.add_argument("--extract-to", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.service_systemd and arguments.expected_revision is None:
        parser.error("--service-systemd requires --expected-revision")
    archive = pathlib.Path(os.path.abspath(arguments.archive))
    checksum = archive.with_name(archive.name + ".sha256")
    if arguments.extract_to is not None:
        if arguments.expected_revision is None:
            parser.error("--extract-to requires --expected-revision")
        destination = pathlib.Path(os.path.abspath(arguments.extract_to))
        print(extract_release(archive, checksum, arguments.expected_revision, destination))
    else:
        smoke(
            archive,
            checksum,
            arguments.expected_revision,
            arguments.service_container,
            arguments.service_systemd,
        )
        print("Kapsel release artifact smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
