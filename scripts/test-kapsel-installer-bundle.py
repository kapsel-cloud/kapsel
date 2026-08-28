#!/usr/bin/env python3
"""Smoke the release-only installer bundle seam with test-only ELF fixtures."""

from __future__ import annotations

import os
import pathlib
import secrets
import shutil
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663"
)


def test_elf() -> bytes:
    """Return a minimal structurally valid ELF64 fixture; it is never executed."""
    value = bytearray(120)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", value, 16, 3, 62, 1)
    struct.pack_into("<Q", value, 32, 64)
    struct.pack_into("<HHH", value, 52, 64, 56, 1)
    struct.pack_into("<II", value, 64, 1, 1)
    struct.pack_into("<QQQ", value, 72, 0, 0, 0)
    struct.pack_into("<QQ", value, 96, len(value), len(value))
    struct.pack_into("<Q", value, 112, 4096)
    return bytes(value)


def copy(source: pathlib.Path, destination: pathlib.Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage_bundle(stage: pathlib.Path) -> None:
    stage.chmod(0o755)
    for path in [
        "usr/bin/kapsel",
        "usr/bin/kapsel-service-client",
        "usr/libexec/kapsel/kapseld",
    ]:
        destination = stage / path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.write_bytes(test_elf())
        destination.chmod(0o755)
    for source, destination in [
        ("crates/kapseld/deploy/kapseld.service", "usr/lib/systemd/system/kapseld.service"),
        ("crates/kapseld/deploy/kapseld.conf", "usr/lib/sysusers.d/kapseld.conf"),
        ("crates/kapseld/deploy/kapseld-rbac.yaml", "usr/share/kapsel/kapseld-rbac.yaml"),
        (
            "docs/KAPSEL_SERVICE_OPERATOR.md",
            "usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        ),
        ("LICENSE", "LICENSE"),
    ]:
        copy(ROOT / source, stage / destination, 0o644)
    metadata = stage / "KAPSEL-SERVICE-METADATA.json"
    metadata.write_text('{"fixture":"test-only;not-candidate-metadata"}\n')
    metadata.chmod(0o644)
    for directory in [stage, *[path for path in stage.rglob("*") if path.is_dir()]]:
        directory.chmod(0o755)


def main() -> int:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for the installer bundle smoke")
    subprocess.run(
        ["docker", "info"], check=True, stdout=subprocess.DEVNULL, timeout=30
    )
    with tempfile.TemporaryDirectory(prefix="kapsel-installer-stage-") as stage_text:
        with tempfile.TemporaryDirectory(prefix="kapsel-installer-target-") as target_text:
            stage = pathlib.Path(stage_text)
            target = pathlib.Path(target_text)
            stage_bundle(stage)
            script = f"""
                set -eu
                restore_target_ownership() {{
                    chown -R "$HOST_UID:$HOST_GID" /target
                }}
                trap restore_target_ownership EXIT
                cargo build --release --locked --target {TARGET} \\
                    -p kapsel-installer
                installer=/target/{TARGET}/release/kapsel-installer
                set +e
                "$installer" install --operator-input /secure/kapsel \\
                    --kube-context nonprod >/target/stdout 2>/target/stderr
                status=$?
                set -e
                test "$status" = 1
                test ! -s /target/stdout
                test "$(cat /target/stderr)" = \\
                    "Kapsel installer failure: implementation_incomplete"
            """
            container = f"kapsel-installer-bundle-{os.getpid()}-{secrets.token_hex(4)}"
            command = [
                "docker",
                "run",
                "--rm",
                "--name",
                container,
                "--platform",
                "linux/amd64",
                "--volume",
                f"{ROOT}:/workspace:ro",
                "--volume",
                f"{stage}:/stage:ro",
                "--volume",
                f"{target}:/target",
                "--workdir",
                "/workspace",
                "--env",
                "CARGO_TARGET_DIR=/target",
                "--env",
                "KAPSEL_INSTALLER_STAGE=/stage",
                "--env",
                f"HOST_UID={os.getuid()}",
                "--env",
                f"HOST_GID={os.getgid()}",
                BUILDER_IMAGE,
                "sh",
                "-eu",
                "-c",
                script,
            ]
            try:
                subprocess.run(command, cwd=ROOT, check=True, timeout=300)
            finally:
                subprocess.run(
                    ["docker", "rm", "--force", container],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
    print("installer release-bundle smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
