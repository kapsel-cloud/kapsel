#!/usr/bin/env python3
"""Assemble the unpublished source-independent Kapsel service artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
NON_CLAIMS = "unpublished-preview;not-production;no-compatibility;one-capability;one-target"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024
MANIFEST_BYTES_MAX = 1024

RELEASE_SPEC = importlib.util.spec_from_file_location(
    "assemble_release_artifact", ROOT / "scripts" / "assemble-release-artifact.py"
)
if RELEASE_SPEC is None or RELEASE_SPEC.loader is None:
    raise RuntimeError("could not load release assembly primitives")
RELEASE = importlib.util.module_from_spec(RELEASE_SPEC)
RELEASE_SPEC.loader.exec_module(RELEASE)


def build_binaries(target_directory: pathlib.Path) -> dict[str, pathlib.Path]:
    script = f"""
        set -eu
        restore_target_ownership() {{ chown -R "$HOST_UID:$HOST_GID" /target; }}
        trap restore_target_ownership EXIT
        cargo build --release --locked --target {TARGET} -p kapsel --bin kapsel
        cp /target/{TARGET}/release/kapsel /target/service-kapsel
        cargo build --release --locked --target {TARGET} -p kapseld --bins
        cp /target/{TARGET}/release/kapseld /target/service-kapseld
        cp /target/{TARGET}/release/kapsel-service-client /target/service-kapsel-service-client
    """
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--volume",
            f"{ROOT}:/workspace:ro",
            "--volume",
            f"{target_directory}:/target",
            "--workdir",
            "/workspace",
            "--env",
            "CARGO_TARGET_DIR=/target",
            "--env",
            "RUSTFLAGS=--remap-path-prefix=/workspace=.",
            "--env",
            f"HOST_UID={os.getuid()}",
            "--env",
            f"HOST_GID={os.getgid()}",
            RELEASE.BUILDER_IMAGE,
            "sh",
            "-eu",
            "-c",
            script,
        ],
        cwd=ROOT,
        check=True,
    )
    outputs = {
        "kapsel": target_directory / "service-kapsel",
        "kapsel-service-client": target_directory / "service-kapsel-service-client",
        "kapseld": target_directory / "service-kapseld",
    }
    if not all(path.is_file() for path in outputs.values()):
        raise RuntimeError("Cargo did not produce every Kapsel service artifact executable")
    return outputs


def stage(staging: pathlib.Path, revision: str, tree: str, dirty: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="kapsel-service-target-") as temporary:
        binaries = build_binaries(pathlib.Path(temporary))
        destinations = {
            "kapsel": staging / "bin" / "kapsel",
            "kapsel-service-client": staging / "bin" / "kapsel-service-client",
            "kapseld": staging / "libexec" / "kapsel" / "kapseld",
        }
        for name, destination in destinations.items():
            RELEASE.copy_file(binaries[name], destination, 0o755)

    assets = {
        ROOT / "crates/kapseld/deploy/kapseld.service": (
            staging / "lib/systemd/system/kapseld.service",
            0o644,
        ),
        ROOT / "crates/kapseld/deploy/kapseld.conf": (
            staging / "lib/sysusers.d/kapseld.conf",
            0o644,
        ),
        ROOT / "crates/kapseld/deploy/kapseld-rbac.yaml": (
            staging / "share/kapsel/kapseld-rbac.yaml",
            0o644,
        ),
        ROOT / "scripts/verify-kapsel-service-artifact.py": (
            staging / "share/kapsel/verify-kapsel-service-artifact.py",
            0o755,
        ),
        ROOT / "scripts/smoke-kapsel-service-artifact.py": (
            staging / "share/kapsel/smoke-kapsel-service-artifact.py",
            0o755,
        ),
        ROOT / "LICENSE": (staging / "LICENSE", 0o644),
    }
    for source, (destination, mode) in assets.items():
        RELEASE.copy_file(source, destination, mode)
    RELEASE.copy_document(
        ROOT / "docs/KAPSEL_SERVICE_OPERATOR.md",
        staging / "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        revision,
    )

    metadata: dict[str, object] = {
        "artifact_schema": "kapsel.service-artifact.v1",
        "package_version": RELEASE.package_version(),
        "source_revision": revision,
        "source_tree": tree,
        "source_dirty": dirty,
        "rust_target": TARGET,
        "builder_image": RELEASE.BUILDER_IMAGE,
        "cargo_lock_sha256": RELEASE.file_sha256(ROOT / "Cargo.lock"),
        "license": "Apache-2.0",
        "license_sha256": RELEASE.file_sha256(staging / "LICENSE"),
    }
    for name, path in [
        ("kapsel", staging / "bin/kapsel"),
        ("client", staging / "bin/kapsel-service-client"),
        ("daemon", staging / "libexec/kapsel/kapseld"),
    ]:
        metadata[f"{name}_bytes"] = path.stat().st_size
        metadata[f"{name}_sha256"] = RELEASE.file_sha256(path)
    metadata["non_claims"] = NON_CLAIMS
    encoded = (json.dumps(metadata, indent=2, separators=(",", ": ")) + "\n").encode()
    RELEASE.write_exclusive(staging / "SERVICE-METADATA.json", encoded)


def assemble(output_directory: pathlib.Path, allow_dirty: bool) -> pathlib.Path:
    revision, tree, _, dirty = RELEASE.git_provenance(allow_dirty)
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for Kapsel service artifact assembly")
    RELEASE.run("docker", "info")
    basename = f"kapsel-service-{revision}-{TARGET}"
    output_directory.mkdir(parents=True, exist_ok=True)
    archive = output_directory / f"{basename}.tar.gz"
    checksum = archive.with_name(archive.name + ".sha256")
    manifest = archive.with_name(archive.name + ".SHA256SUMS")
    if any(os.path.lexists(path) for path in [archive, checksum, manifest]):
        raise RuntimeError("Kapsel service artifact output already exists")

    with tempfile.TemporaryDirectory(prefix="kapsel-service-stage-") as temporary:
        staging = pathlib.Path(temporary) / basename
        staging.mkdir(mode=0o755)
        stage(staging, revision, tree, dirty)
        expanded = sum(path.stat().st_size for path in staging.rglob("*") if path.is_file())
        if expanded > EXPANDED_BYTES_MAX:
            raise RuntimeError("Kapsel service artifact exceeded its expanded bound")
        RELEASE.create_archive(staging, archive)
    if archive.stat().st_size > ARCHIVE_BYTES_MAX:
        archive.unlink()
        raise RuntimeError("Kapsel service artifact exceeded its compressed bound")

    checksum_bytes = f"{RELEASE.file_sha256(archive)}  {archive.name}\n".encode()
    RELEASE.write_exclusive(checksum, checksum_bytes)
    manifest_bytes = "".join(
        f"{RELEASE.file_sha256(path)}  {path.name}\n"
        for path in sorted([archive, checksum], key=lambda path: path.name)
    ).encode()
    if len(manifest_bytes) > MANIFEST_BYTES_MAX:
        raise RuntimeError("Kapsel service artifact digest manifest exceeded its bound")
    RELEASE.write_exclusive(manifest, manifest_bytes)
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=pathlib.Path)
    parser.add_argument("--allow-dirty", action="store_true")
    arguments = parser.parse_args()
    try:
        archive = assemble(arguments.output_directory.resolve(), arguments.allow_dirty)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Kapsel service artifact assembly failed: {error}", file=sys.stderr)
        return 1
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
