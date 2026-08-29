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


def operator_input(directory: pathlib.Path) -> None:
    directory.chmod(0o700)
    files = {
        "grant.bin": bytes.fromhex(
            (ROOT / "vectors/effect-gateway-grant.hex").read_text().strip()
        ),
        "authorization.pub": bytes.fromhex(
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        ),
        "receipt.seed": bytes([9]) * 32,
        "receipt.trust": bytes.fromhex(
            (ROOT / "vectors/effect-gateway-trust.hex").read_text().strip()
        ),
        "bootstrap-kubeconfig.yaml": b"""apiVersion: v1
kind: Config
clusters:
- name: fixture
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: Y2E=
users:
- name: fixture
  user:
    token: fixture-token
contexts:
- name: nonprod
  context:
    cluster: fixture
    user: fixture
    namespace: demo
current-context: nonprod
""",
    }
    for name, contents in files.items():
        path = directory / name
        path.write_bytes(contents)
        path.chmod(0o600)


def main() -> int:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for the installer bundle smoke")
    subprocess.run(
        ["docker", "info"], check=True, stdout=subprocess.DEVNULL, timeout=30
    )
    with (
        tempfile.TemporaryDirectory(prefix="kapsel-installer-stage-") as stage_text,
        tempfile.TemporaryDirectory(prefix="kapsel-installer-target-") as target_text,
        tempfile.TemporaryDirectory(prefix="kapsel-installer-input-") as input_text,
    ):
        stage = pathlib.Path(stage_text)
        target = pathlib.Path(target_text)
        operator = pathlib.Path(input_text)
        stage_bundle(stage)
        operator_input(operator)
        script = f"""
            set -eu
            restore_target_ownership() {{
                chown -R "$HOST_UID:$HOST_GID" /target
            }}
            trap restore_target_ownership EXIT
            cargo build --release --locked --target {TARGET} \\
                -p kapsel-installer
            cargo test --release --locked --target {TARGET} -p kapsel-installer \\
                'tests::initial_publication_has_no_named_partial_before_link' -- --exact
            installer=/target/{TARGET}/release/kapsel-installer
            mkdir -p /secure
            cp -a /operator-fixture /secure/kapsel
            chown -R 0:0 /secure/kapsel
            run_failure() {{
                expected=$1
                : >/target/stdout
                : >/target/stderr
                chmod 0600 /target/stdout /target/stderr
                set +e
                "$installer" install --operator-input /secure/kapsel \\
                    --kube-context nonprod >/target/stdout 2>/target/stderr
                status=$?
                set -e
                test "$status" = 1
                test ! -s /target/stdout
                test "$(cat /target/stderr)" = \\
                    "Kapsel installer failure: $expected"
            }}
            test ! -e /var/lib/kapsel-installer
            old_umask=$(umask)
            umask 0777
            run_failure implementation_incomplete
            umask "$old_umask"
            installer_state=/var/lib/kapsel-installer
            transaction=$installer_state/transaction.json
            test "$(stat -c '%u:%a' "$installer_state")" = "0:700"
            test -f "$transaction"
            test "$(stat -c '%u:%a:%h' "$transaction")" = "0:600:1"
            test "$(stat -c '%s' "$transaction")" -le 65536
            cp "$transaction" /target/valid-transaction.json
            ! grep -F 'fixture-token' "$transaction"
            ! grep -F 'Y2E=' "$transaction"
            run_failure implementation_incomplete
            cmp "$transaction" /target/valid-transaction.json
            : >"$installer_state/unknown"
            chmod 0600 "$installer_state/unknown"
            run_failure transaction_failure
            test -f "$installer_state/unknown"
            rm "$installer_state/unknown"
            chmod 0644 "$transaction"
            run_failure transaction_failure
            test "$(stat -c '%a' "$transaction")" = "644"
            chmod 0600 "$transaction"
            printf '{{}}' >"$transaction"
            run_failure transaction_failure
            test "$(cat "$transaction")" = '{{}}'
            cp /target/valid-transaction.json "$transaction"
            chmod 0600 "$transaction"
            sed 's#"path":"/secure/kapsel"#"path":"/secure/changed"#' \
                /target/valid-transaction.json >"$transaction"
            run_failure transaction_failure
            grep -F '"path":"/secure/changed"' "$transaction" >/dev/null
            cp /target/valid-transaction.json "$transaction"
            chmod 0600 "$transaction"
            ln "$transaction" "$installer_state/transaction-link"
            run_failure transaction_failure
            test "$(stat -c '%h' "$transaction")" = "2"
            rm "$installer_state/transaction-link"
            rm "$transaction"
            ln -s /target/valid-transaction.json "$transaction"
            run_failure transaction_failure
            test -L "$transaction"
            rm "$transaction"
            mkfifo -m 0600 "$transaction"
            run_failure transaction_failure
            test -p "$transaction"
            rm "$transaction"
            mkdir -m 0600 "$transaction"
            run_failure transaction_failure
            test -d "$transaction"
            rmdir "$transaction"
            rmdir "$installer_state"
            mkdir -m 0700 "$installer_state"
            run_failure implementation_incomplete
            test "$(stat -c '%u:%a' "$installer_state")" = "0:700"
            test "$(stat -c '%u:%a:%h' "$transaction")" = "0:600:1"
            test -f /run/lock/kapsel-installer.lock
            test "$(stat -c '%u:%a:%h' /run/lock/kapsel-installer.lock)" = "0:600:1"
            run_failure implementation_incomplete
            exec 9<>/run/lock/kapsel-installer.lock
            flock -n 9
            run_failure installer_lock_failure
            flock -u 9
            exec 9>&-
            chmod 0644 /run/lock/kapsel-installer.lock
            run_failure installer_lock_failure
            chmod 0600 /run/lock/kapsel-installer.lock
            chown 1:0 /run/lock/kapsel-installer.lock
            run_failure installer_lock_failure
            chown 0:0 /run/lock/kapsel-installer.lock
            ln /run/lock/kapsel-installer.lock /run/lock/kapsel-installer-link
            run_failure installer_lock_failure
            rm /run/lock/kapsel-installer-link
            rm /run/lock/kapsel-installer.lock
            ln -s /secure/kapsel/grant.bin /run/lock/kapsel-installer.lock
            run_failure installer_lock_failure
            rm /run/lock/kapsel-installer.lock
            mkdir /run/lock/kapsel-installer.lock
            run_failure installer_lock_failure
            rmdir /run/lock/kapsel-installer.lock
            mkfifo -m 0600 /run/lock/kapsel-installer.lock
            run_failure installer_lock_failure
            rm /run/lock/kapsel-installer.lock
            run_failure implementation_incomplete
            chmod 0644 /secure/kapsel/grant.bin
            run_failure invalid_operator_input
            chmod 0600 /secure/kapsel/grant.bin
            : >/secure/kapsel/unknown
            chmod 0600 /secure/kapsel/unknown
            run_failure invalid_operator_input
            rm /secure/kapsel/unknown
            ln /secure/kapsel/receipt.seed /secure/receipt-seed-link
            run_failure invalid_operator_input
            rm /secure/receipt-seed-link
            cp /secure/kapsel/authorization.pub /secure/kapsel/receipt.seed
            chmod 0600 /secure/kapsel/receipt.seed
            run_failure invalid_operator_input
            cp /operator-fixture/receipt.seed /secure/kapsel/receipt.seed
            rm /secure/kapsel/grant.bin
            mkfifo -m 0600 /secure/kapsel/grant.bin
            run_failure invalid_operator_input
            rm /secure/kapsel/grant.bin
            cp /operator-fixture/grant.bin /secure/kapsel/grant.bin
            rm /secure/kapsel/receipt.trust
            ln -s /operator-fixture/receipt.trust /secure/kapsel/receipt.trust
            run_failure invalid_operator_input
            rm /secure/kapsel/receipt.trust
            cp /operator-fixture/receipt.trust /secure/kapsel/receipt.trust
            rm /secure/kapsel/authorization.pub
            run_failure invalid_operator_input
            cp /operator-fixture/authorization.pub /secure/kapsel/authorization.pub
            chown 1 /secure/kapsel/grant.bin
            run_failure invalid_operator_input
            chown 0 /secure/kapsel/grant.bin
            chmod 0710 /secure/kapsel
            run_failure invalid_operator_input
            chmod 0700 /secure/kapsel
            head -c 65537 /dev/zero >/secure/kapsel/bootstrap-kubeconfig.yaml
            chmod 0600 /secure/kapsel/bootstrap-kubeconfig.yaml
            run_failure invalid_operator_input
            cp /operator-fixture/bootstrap-kubeconfig.yaml \
                /secure/kapsel/bootstrap-kubeconfig.yaml
            head -c 31 /operator-fixture/authorization.pub \
                >/secure/kapsel/authorization.pub
            chmod 0600 /secure/kapsel/authorization.pub
            run_failure invalid_operator_input
            cp /operator-fixture/authorization.pub /secure/kapsel/authorization.pub
            mv /secure/kapsel /secure/kapsel-real
            ln -s /secure/kapsel-real /secure/kapsel
            run_failure invalid_operator_input
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
            "--volume",
            f"{operator}:/operator-fixture:ro",
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
            subprocess.run(command, cwd=ROOT, check=True, timeout=900)
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
