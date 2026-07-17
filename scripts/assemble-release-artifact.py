#!/usr/bin/env python3
"""Assemble the fixed Kapsel x86-64 GNU/Linux release artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663"
)
SMOKE_IMAGE = (
    "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
)
NON_CLAIMS = "not-production;no-stable-cli;no-stable-receipt;no-other-targets"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
EXPANDED_BYTES_MAX = 64 * 1024 * 1024


def run(*arguments: str, cwd: pathlib.Path = ROOT) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_version() -> str:
    manifest = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())
    return str(manifest["workspace"]["package"]["version"])


def git_provenance(allow_dirty: bool) -> tuple[str, bool]:
    revision = run("git", "rev-parse", "HEAD")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("source revision is not canonical lowercase SHA-1")
    dirty = bool(run("git", "status", "--porcelain=v1", "--untracked-files=all"))
    if dirty and not allow_dirty:
        raise RuntimeError("release assembly requires a clean worktree")
    return revision, dirty


def build_binaries(target_directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    build_script = f"""
        set -eu
        cargo build --release --locked --target {TARGET} --bin kapsel
        cp /target/{TARGET}/release/kapsel /target/ordinary-kapsel
        cargo build --release --locked --target {TARGET} --bin kapsel --features demo-harness
        cp /target/{TARGET}/release/kapsel /target/demo-kapsel
    """
    command = [
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
        BUILDER_IMAGE,
        "sh",
        "-eu",
        "-c",
        build_script,
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    ordinary = target_directory / "ordinary-kapsel"
    demonstration = target_directory / "demo-kapsel"
    if not ordinary.is_file() or not demonstration.is_file():
        raise RuntimeError("Cargo did not produce both expected release binaries")
    return ordinary, demonstration


def copy_file(source: pathlib.Path, destination: pathlib.Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage_release(staging: pathlib.Path, revision: str, dirty: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="kapsel-release-target-") as temporary:
        ordinary, demonstration = build_binaries(pathlib.Path(temporary))
        copy_file(ordinary, staging / "bin" / "kapsel", 0o755)
        copy_file(demonstration, staging / "libexec" / "kapsel-demo-harness", 0o755)

    assets = {
        ROOT / "scripts" / "demo-kind-crash-recovery.sh": (
            staging / "share" / "kapsel" / "demo-kind-crash-recovery.sh",
            0o755,
        ),
        ROOT / "vectors" / "kap0038-trust.hex": (
            staging / "share" / "kapsel" / "kap0038-trust.hex",
            0o644,
        ),
        ROOT / "docs" / "EVALUATOR.md": (
            staging / "share" / "doc" / "kapsel" / "EVALUATOR.md",
            0o644,
        ),
        ROOT / "CHANGELOG.md": (staging / "CHANGELOG.md", 0o644),
        ROOT / "LICENSE": (staging / "LICENSE", 0o644),
    }
    for source, (destination, mode) in assets.items():
        if not source.is_file():
            raise RuntimeError(f"required release input is missing: {source.relative_to(ROOT)}")
        copy_file(source, destination, mode)

    metadata = {
        "artifact_schema": "kapsel.release-artifact.v1",
        "package_version": package_version(),
        "rust_target": TARGET,
        "source_revision": revision,
        "source_dirty": dirty,
        "license": "Apache-2.0",
        "license_sha256": file_sha256(staging / "LICENSE"),
        "builder_image": BUILDER_IMAGE,
        "smoke_image": SMOKE_IMAGE,
        "ordinary_binary_sha256": file_sha256(staging / "bin" / "kapsel"),
        "demo_binary_sha256": file_sha256(staging / "libexec" / "kapsel-demo-harness"),
        "non_claims": NON_CLAIMS,
    }
    staging.joinpath("RELEASE-METADATA.json").write_text(
        json.dumps(metadata, indent=2, separators=(",", ": ")) + "\n"
    )
    staging.joinpath("RELEASE-METADATA.json").chmod(0o644)


def tar_info(path: pathlib.Path, arcname: str) -> tarfile.TarInfo:
    information = tarfile.TarInfo(arcname + ("/" if path.is_dir() else ""))
    information.uid = 0
    information.gid = 0
    information.uname = ""
    information.gname = ""
    information.mtime = 0
    if path.is_dir():
        information.type = tarfile.DIRTYPE
        information.mode = 0o755
    else:
        information.type = tarfile.REGTYPE
        information.mode = path.stat().st_mode & 0o777
        information.size = path.stat().st_size
    return information


def create_archive(staging: pathlib.Path, archive: pathlib.Path) -> None:
    paths = [staging, *staging.rglob("*")]
    paths.sort(key=lambda path: path.relative_to(staging.parent).as_posix())
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as release:
                for path in paths:
                    arcname = path.relative_to(staging.parent).as_posix()
                    information = tar_info(path, arcname)
                    if path.is_dir():
                        release.addfile(information)
                    else:
                        with path.open("rb") as source:
                            release.addfile(information, source)


def assemble(output_directory: pathlib.Path, allow_dirty: bool) -> pathlib.Path:
    revision, dirty = git_provenance(allow_dirty)
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for release assembly")
    run("docker", "info")
    version = package_version()
    basename = f"kapsel-{version}-{TARGET}"
    output_directory.mkdir(parents=True, exist_ok=True)
    archive = output_directory / f"{basename}.tar.gz"
    checksum = output_directory / f"{archive.name}.sha256"
    if archive.exists() or checksum.exists():
        raise RuntimeError("release output already exists")

    with tempfile.TemporaryDirectory(prefix="kapsel-release-stage-") as temporary:
        staging = pathlib.Path(temporary) / basename
        staging.mkdir(mode=0o755)
        stage_release(staging, revision, dirty)
        expanded_size = sum(path.stat().st_size for path in staging.rglob("*") if path.is_file())
        if expanded_size > EXPANDED_BYTES_MAX:
            raise RuntimeError("release staging tree exceeded its expanded bound")
        create_archive(staging, archive)

    if archive.stat().st_size > ARCHIVE_BYTES_MAX:
        archive.unlink()
        raise RuntimeError("release archive exceeded its compressed bound")
    checksum.write_text(f"{file_sha256(archive)}  {archive.name}\n")
    checksum.chmod(0o644)
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=pathlib.Path)
    parser.add_argument("--allow-dirty", action="store_true")
    arguments = parser.parse_args()
    try:
        archive = assemble(arguments.output_directory.resolve(), arguments.allow_dirty)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Kapsel release assembly failed: {error}", file=sys.stderr)
        return 1
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
