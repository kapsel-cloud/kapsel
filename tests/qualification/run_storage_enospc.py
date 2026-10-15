#!/usr/bin/env python3
"""Qualify maximal completion and actual ENOSPC with one cached Linux test executable."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path

IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
TARGET = "x86_64-unknown-linux-gnu"
PREFIX = "gateway::tests::storage::"
CASES = {
    PREFIX + "full_identity_capacity_completes_maximal_mixed_phase_history": (
        "KAPSEL_MAXIMAL_COMPLETION_PASSED",
    ),
    PREFIX + "genuine_enospc_during_admission_and_receipt_recovers_without_resend": (
        "KAPSEL_ADMISSION_ENOSPC_PASSED",
        "KAPSEL_RECEIPT_SQL_ENOSPC_PASSED",
        "KAPSEL_RECEIPT_COMMIT_ENOSPC_PASSED",
    ),
}
OUTPUT_LIMIT = 8 * 1024 * 1024
CANCELLED: int | None = None


def check_interruption() -> None:
    if CANCELLED is not None:
        raise KeyboardInterrupt(f"storage qualification interrupted by signal {CANCELLED}")


def save_json(path: Path, value: object) -> None:
    primary = sys.exception()
    try:
        path.write_text(json.dumps(value, indent=2) + "\n")
    except BaseException as publication:
        if primary is not None:
            raise BaseExceptionGroup(
                "execution and evidence publication failed", [primary, publication]
            ) from None
        raise


def run(
    command: list[str], log: Path | None, timeout: float = 30, *, interruptible: bool = True
) -> bytes:
    """Bound all commands, including EOF-before-exit, and retire the owned client group."""
    if interruptible:
        check_interruption()
    deadline = time.monotonic() + timeout
    output = bytearray()
    with log.open("xb") if log is not None else contextlib.nullcontext() as retained:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert child.stdout is not None
        selector = None
        try:
            selector = selectors.DefaultSelector()
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if interruptible:
                    check_interruption()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(65536, OUTPUT_LIMIT - len(output) + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(chunk) > OUTPUT_LIMIT:
                        raise RuntimeError(f"command output exceeded {OUTPUT_LIMIT} bytes: {log}")
                    if retained is not None:
                        retained.write(chunk)
                    output.extend(chunk)
            while child.poll() is None:
                if interruptible:
                    check_interruption()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    child.wait(timeout=min(remaining, 0.1))
                except subprocess.TimeoutExpired:
                    continue
            code = child.returncode
            if code:
                raise RuntimeError(f"command failed ({code}): {shlex.join(command)}; see {log}")
        finally:
            primary = sys.exception()
            try:
                # Explicit ownership: Popen.__exit__ would reap without a timeout on failure.
                # Reap before signalling (macOS rejects zombie-only groups).
                child.poll()
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Reap a leader that became a zombie, then retry the group.
                    child.wait(timeout=10)
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=10)
            except BaseException as cleanup:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "command execution and bounded cleanup failed", [primary, cleanup]
                    ) from None
                raise
            finally:
                child.stdout.close()
                if selector is not None:
                    selector.close()
    return bytes(output)


class Commands:
    """Retain bounded logs and literal commands with elapsed time, including failures."""

    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self.records: list[dict[str, object]] = []
        self.publication_errors: list[BaseException] = []

    def execute(
        self, command: list[str], timeout: float = 30, *, retirement: bool = False
    ) -> bytes:
        log = self.evidence / f"command-{len(self.records):02}.log"
        record: dict[str, object] = {"command": command, "log": log.name, "outcome": "FAILED"}
        self.records.append(record)
        started = time.monotonic()
        try:
            # Retirement must remain possible after cancellation or evidence storage failure.
            output = run(
                command, None if retirement else log, timeout, interruptible=not retirement
            )
            record["outcome"] = "COMPLETED"
            if retirement:
                try:
                    log.write_bytes(output)
                except OSError as publication:
                    self.publication_errors.append(publication)
            return output
        finally:
            record["seconds"] = time.monotonic() - started
            if retirement:
                try:
                    save_json(self.evidence / "commands.json", self.records)
                except BaseException as publication:
                    self.publication_errors.append(publication)
            else:
                save_json(self.evidence / "commands.json", self.records)

    def require_evidence(self) -> None:
        if self.publication_errors:
            raise BaseExceptionGroup(
                "retirement evidence publication failed", self.publication_errors
            )


def cleanup_container(name: str, owner: str, commands: Commands) -> str:
    identity = (
        commands.execute(
            [
                "docker",
                "inspect",
                "--format",
                '{{.Id}}\t{{ index .Config.Labels "cloud.kapsel.storage-evidence" }}',
                name,
            ],
            retirement=True,
        )
        .decode()
        .strip()
        .split("\t")
    )
    if len(identity) != 2 or not re.fullmatch(r"[0-9a-f]{64}", identity[0]) or identity[1] != owner:
        raise RuntimeError("container cleanup unverified: ownership/identity mismatch")
    # Names can be replaced after inspection. Never remove by name or an unverified create result.
    commands.execute(["docker", "rm", "--force", identity[0]], retirement=True)
    inventory = commands.execute(
        ["docker", "container", "ls", "--all", "--no-trunc", "--quiet"], retirement=True
    )
    ids = inventory.decode().splitlines()
    if any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in ids) or identity[0] in ids:
        raise RuntimeError("container cleanup unverified: removed ID remains or invalid inventory")
    commands.require_evidence()
    return identity[0]


def container_command(root: Path, cache: Path, name: str, owner: str) -> list[str]:
    return [
        "docker",
        "create",
        "--name",
        name,
        "--platform",
        "linux/amd64",
        "--label",
        f"cloud.kapsel.storage-evidence={owner}",
        "--memory=2g",
        "--memory-swap=2g",
        "--cpus=2",
        "--pids-limit=256",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--log-driver=local",
        "--log-opt=max-size=8m",
        "--log-opt=max-file=2",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={root},dst=/workspace,readonly",
        "--mount",
        f"type=bind,src={cache},dst=/cache",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=67108864,mode=1777",
        "--tmpfs",
        "/kapsel-enospc:rw,nosuid,nodev,noexec,size=100663296,mode=0700,"
        f"uid={os.getuid()},gid={os.getgid()}",
        "--workdir",
        "/workspace",
        "--env",
        "CARGO_HOME=/cache/cargo",
        "--env",
        "CARGO_TARGET_DIR=/cache/target",
        "--env",
        "CARGO_BUILD_JOBS=2",
        "--env",
        "RUSTUP_TOOLCHAIN=1.98.0",
        "--env",
        "KAPSEL_ENOSPC_FIXTURE=dedicated-tmpfs-v1",
        IMAGE,
        "sleep",
        "1800",
    ]


def select_executable(output: bytes) -> tuple[str, dict[str, int]]:
    executables: list[str] = []
    counts = {"fresh": 0, "compiled": 0}
    for line in output.splitlines():
        # Cargo's progress diagnostics share the retained log, but artifacts are JSON objects.
        if not line.startswith(b"{"):
            continue
        record = json.loads(line)
        if record.get("reason") != "compiler-artifact":
            continue
        counts["fresh" if record["fresh"] else "compiled"] += 1
        if (
            record.get("target", {}).get("name") == "kapsel"
            and record.get("profile", {}).get("test") is True
            and record.get("target", {}).get("kind") == ["lib"]
            and isinstance(record.get("executable"), str)
        ):
            executables.append(record["executable"])
    if len(executables) != 1 or not executables[0].startswith(
        f"/cache/target/{TARGET}/debug/deps/"
    ):
        raise RuntimeError(
            "Cargo did not identify exactly one compatible kapsel libtest executable"
        )
    return executables[0], counts


def require_selection(output: bytes, case: str) -> None:
    if output.decode().splitlines() != [f"{case}: test", "", "1 test, 0 benchmarks"]:
        raise RuntimeError(f"nonempty exact selection not established: {case}")


def require_completion(output: bytes, case: str) -> None:
    lines = output.decode().splitlines()
    for marker in CASES[case]:
        if lines.count(marker) != 1:
            raise RuntimeError(f"missing or duplicated phase marker: {marker}")
    if not any(
        line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;") for line in lines
    ):
        raise RuntimeError(f"one executed passing test not established: {case}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def qualify(root: Path, cache: Path, evidence: Path, prepare_only: bool) -> None:
    started = time.monotonic()
    commands = Commands(evidence)
    owner = uuid.uuid4().hex
    name = f"kapsel-storage-{owner}"
    source = {
        "revision": commands.execute(["git", "-C", str(root), "rev-parse", "HEAD"])
        .decode()
        .strip(),
        "tree": commands.execute(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"])
        .decode()
        .strip(),
        "dirty": bool(commands.execute(["git", "-C", str(root), "status", "--porcelain=v1"])),
    }
    report: dict[str, object] = {
        "source": source,
        "runner_sha256": sha256(Path(__file__)),
        "image": IMAGE,
        "target": TARGET,
        "build_cache": str(cache),
        "cases": list(CASES),
        "outcome": "INCOMPLETE",
    }
    save_json(evidence / "result.json", report)
    # Once creation is submitted, even timeout/interruption must resolve ownership before cleanup.
    try:
        created = commands.execute(container_command(root, cache, name, owner), timeout=120)
        container_id = created.decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("invalid container creation identity")
        commands.execute(["docker", "start", container_id])
        execute = ["docker", "exec", container_id]
        report["installed_toolchains"] = commands.execute(
            [*execute, "rustup", "toolchain", "list"]
        ).decode()
        rustc = commands.execute([*execute, "rustc", "-vV"]).decode()
        toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"][
            "channel"
        ]
        if f"release: {toolchain}\n" not in rustc or f"host: {TARGET}\n" not in rustc:
            raise RuntimeError(
                "pinned container/toolchain is incompatible with the selected source"
            )
        report["rustc"] = rustc
        report["environment"] = commands.execute([*execute, "uname", "-a"]).decode().strip()
        report["setup_seconds"] = time.monotonic() - started

        build_started = time.monotonic()
        output = commands.execute(
            [
                *execute,
                "cargo",
                "test",
                "--locked",
                "-p",
                "kapsel",
                "--lib",
                "--no-run",
                "--target",
                TARGET,
                "--message-format=json",
            ],
            timeout=1200,
        )
        executable, artifacts = select_executable(output)
        report["build_seconds"] = time.monotonic() - build_started
        report["cargo_artifacts"] = artifacts
        report["executable"] = executable
        executable_digest = (
            commands.execute([*execute, "sha256sum", executable]).decode().split()[0]
        )
        if not re.fullmatch(r"[0-9a-f]{64}", executable_digest):
            raise RuntimeError("invalid test executable SHA256")
        report["executable_sha256"] = executable_digest

        execution_started = time.monotonic()
        executed: list[str] = []
        for case in CASES:
            selected = [*execute, executable, case, "--ignored", "--exact"]
            require_selection(commands.execute([*selected, "--list"]), case)
            if not prepare_only:
                require_completion(
                    commands.execute([*selected, "--nocapture", "--test-threads=1"], timeout=300),
                    case,
                )
                executed.append(case)
        report["executed_cases"] = executed
        report["execution_seconds"] = time.monotonic() - execution_started
        if (
            commands.execute([*execute, "sha256sum", executable]).decode().split()[0]
            != executable_digest
        ):
            raise RuntimeError("test executable changed during qualification")
    except BaseException as primary:
        try:
            report["removed_container_id"] = cleanup_container(name, owner, commands)
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "storage run failed and cleanup is unverified", [primary, cleanup]
            ) from None
        raise
    else:
        report["removed_container_id"] = cleanup_container(name, owner, commands)
        check_interruption()
        report["outcome"] = "PREPARED" if prepare_only else "QUALIFIED"
    finally:
        report["total_seconds"] = time.monotonic() - started
        save_json(evidence / "result.json", report)


def interrupted(signum: int, _frame: object) -> None:
    # Defer exceptions until the child is registered. Cleanup commands ignore cancellation,
    # but qualification checks it before selecting a terminal result. SIGKILL leaves INCOMPLETE.
    global CANCELLED
    CANCELLED = signum


def main() -> None:
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-cache", type=Path, default=root / "target/storage-linux-amd64")
    parser.add_argument("--output", type=Path, help="new evidence directory")
    parser.add_argument(
        "--prepare-only", action="store_true", help="build/list only; never qualification"
    )
    arguments = parser.parse_args()
    cache = arguments.build_cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    evidence = arguments.output
    if evidence is None:
        evidence = Path(tempfile.mkdtemp(prefix="kapsel-storage-"))
    else:
        evidence.mkdir(parents=True, exist_ok=False)
    print(f"Storage evidence: {evidence.resolve()}", flush=True)
    qualify(root, cache, evidence.resolve(), arguments.prepare_only)
    print(
        "KAPSEL_STORAGE_PREPARED" if arguments.prepare_only else "KAPSEL_STORAGE_QUALIFIED",
        flush=True,
    )


if __name__ == "__main__":
    main()
