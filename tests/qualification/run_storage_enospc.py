#!/usr/bin/env python3
"""Run only the optional bounded SQLite ENOSPC fixture in a disposable Linux tmpfs."""

from __future__ import annotations

import io
import os
import re
import select
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
TEST = (
    "gateway::tests::storage::genuine_enospc_during_admission_and_receipt_recovers_without_resend"
)

# The source snapshot is evidence, not an input transport. Current maintained checkouts are far below
# these fixed caps; they bound hostile untracked files before allocation or archive copy while allowing
# ordinary source additions to be preserved byte-for-byte.
SOURCE_FILE_BYTE_LIMIT = 8 * 1024 * 1024
SOURCE_TOTAL_BYTE_LIMIT = 64 * 1024 * 1024
SOURCE_READ_CHUNK = 1024 * 1024

# Git diff is the tracked-source evidence stream and can legitimately include binary patches. This
# cap is intentionally larger than source snapshot caps while still bounding memory before appending.
GIT_OUTPUT_BYTE_LIMIT = 128 * 1024 * 1024
GIT_OUTPUT_READ_CHUNK = 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 30.0


class SourceFile(NamedTuple):
    content: bytes
    mode: int


def bounded_command_output(command: list[str]) -> bytes:
    deadline = time.monotonic() + GIT_COMMAND_TIMEOUT_SECONDS
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise RuntimeError("bounded command stdout pipe was not created")

    chunks: list[bytes] = []
    bytes_read = 0
    failed = True
    try:
        output_descriptor = process.stdout.fileno()
        while True:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(command, GIT_COMMAND_TIMEOUT_SECONDS)
            readable, _, _ = select.select([output_descriptor], [], [], remaining_seconds)
            if not readable:
                raise subprocess.TimeoutExpired(command, GIT_COMMAND_TIMEOUT_SECONDS)
            chunk = os.read(output_descriptor, GIT_OUTPUT_READ_CHUNK)
            if not chunk:
                break
            if len(chunk) > GIT_OUTPUT_BYTE_LIMIT - bytes_read:
                raise RuntimeError(
                    f"command output exceeds {GIT_OUTPUT_BYTE_LIMIT} byte capture cap"
                )
            chunks.append(chunk)
            bytes_read += len(chunk)

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise subprocess.TimeoutExpired(command, GIT_COMMAND_TIMEOUT_SECONDS)
        return_code = process.wait(timeout=remaining_seconds)
        output = b"".join(chunks)
        if return_code:
            raise subprocess.CalledProcessError(return_code, command, output=output)
        failed = False
        return output
    finally:
        process.stdout.close()
        if failed and process.poll() is None:
            process.kill()
            process.wait()


def git(*arguments: str) -> bytes:
    return bounded_command_output(["git", "--no-optional-locks", *arguments])


def read_source_file(path: str, remaining_total_bytes: int) -> SourceFile:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"untracked source {path!r} could not be opened safely") from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"untracked source {path!r} is not a regular file")
        if metadata.st_size > SOURCE_FILE_BYTE_LIMIT:
            raise RuntimeError(
                f"untracked source {path!r} exceeds {SOURCE_FILE_BYTE_LIMIT} byte file cap"
            )
        if metadata.st_size > remaining_total_bytes:
            raise RuntimeError(
                f"untracked sources exceed {SOURCE_TOTAL_BYTE_LIMIT} byte aggregate cap"
            )

        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            if bytes_read >= metadata.st_size:
                chunk = os.read(descriptor, 1)
                if chunk:
                    raise RuntimeError(f"untracked source {path!r} grew during capture")
                break
            read_size = min(SOURCE_READ_CHUNK, metadata.st_size - bytes_read)
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            bytes_read += len(chunk)
            chunks.append(chunk)

        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_size != metadata.st_size
            or bytes_read != metadata.st_size
            or stat.S_IMODE(final_metadata.st_mode) != stat.S_IMODE(metadata.st_mode)
        ):
            raise RuntimeError(f"untracked source {path!r} changed during capture")
        return SourceFile(b"".join(chunks), stat.S_IMODE(metadata.st_mode))
    finally:
        os.close(descriptor)


def untracked_source_files() -> dict[str, SourceFile]:
    paths = git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    sources: dict[str, SourceFile] = {}
    remaining_total_bytes = SOURCE_TOTAL_BYTE_LIMIT
    for path_bytes in paths:
        if not path_bytes:
            continue
        path = os.fsdecode(path_bytes)
        source_file = read_source_file(path, remaining_total_bytes)
        remaining_total_bytes -= len(source_file.content)
        sources[path] = source_file
    return sources


def untracked_sources() -> dict[str, bytes]:
    return {path: source_file.content for path, source_file in untracked_source_files().items()}


def capture_source(evidence: Path) -> tuple[str, bytes, dict[str, SourceFile]]:
    base = git("rev-parse", "HEAD").decode().strip()
    source_diff = git("diff", "--binary", "--no-ext-diff", "--no-textconv", base, "--")
    source_files = untracked_source_files()
    (evidence / "base-revision.txt").write_text(base + "\n", encoding="utf-8")
    (evidence / "source.diff").write_bytes(source_diff)
    (evidence / "source-status.txt").write_bytes(git("status", "--porcelain=v1"))
    with tarfile.open(evidence / "new-source.tar", "w") as archive:
        for path, source_file in source_files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(source_file.content)
            entry.mode = source_file.mode
            archive.addfile(entry, io.BytesIO(source_file.content))
    return base, source_diff, source_files


def verify_source(snapshot: tuple[str, bytes, dict[str, SourceFile]]) -> None:
    base, source_diff, sources = snapshot
    tracked_source_changed = (
        git("diff", "--binary", "--no-ext-diff", "--no-textconv", base, "--") != source_diff
    )
    if tracked_source_changed or untracked_source_files() != sources:
        raise RuntimeError("source changed during read-only container gate")


def cleanup_container(name: str, expected_owner: str) -> str:
    owner = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            '{{.Id}}\t{{ index .Config.Labels "cloud.kapsel.storage-evidence" }}',
            name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if owner.returncode:
        # A failed inspect is not evidence of absence. Require a successful full inventory.
        inventory = subprocess.run(
            ["docker", "container", "ls", "--all", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        names = inventory.stdout.decode().splitlines()
        if inventory.returncode or any(
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", item) for item in names
        ):
            raise RuntimeError(
                f"container cleanup unverified: inspect failed {owner.stderr!r}; "
                f"inventory failed or invalid {inventory.stderr!r}"
            )
        if name in names:
            raise RuntimeError(
                f"container cleanup unverified: {name} exists but inspect failed {owner.stderr!r}"
            )
        return "Container absent in successful Docker inventory after failed inspection.\n"

    fields = owner.stdout.decode().strip().split("\t")
    if (
        len(fields) != 2
        or not re.fullmatch(r"[0-9a-f]{64}", fields[0])
        or fields[1] != expected_owner
    ):
        raise RuntimeError(f"container cleanup unverified: ownership/identity mismatch for {name}")

    # The name can be replaced after inspection; remove only the verified immutable ID.
    removed = subprocess.run(
        ["docker", "rm", "--force", fields[0]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if removed.returncode:
        raise RuntimeError(f"owned container cleanup failed: {removed.stderr!r}")
    return f"Removed verified owned container {fields[0]}.\n"


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    evidence = Path(tempfile.mkdtemp(prefix="kapsel-storage-enospc-"))
    name = f"kapsel-storage-{evidence.name.rsplit('-', 1)[-1]}"
    snapshot = capture_source(evidence)
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--platform",
        "linux/amd64",
        "--label",
        f"cloud.kapsel.storage-evidence={evidence.name}",
        "--memory=2g",
        "--memory-swap=2g",
        "--cpus=2",
        "--pids-limit=256",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={root},dst=/workspace,readonly",
        "--tmpfs",
        f"/kapsel-enospc:rw,nosuid,nodev,noexec,size=100663296,mode=0700,"
        f"uid={os.getuid()},gid={os.getgid()}",
        "--workdir",
        "/workspace",
        "--env",
        "CARGO_HOME=/tmp/kapsel-cargo",
        "--env",
        "CARGO_TARGET_DIR=/tmp/kapsel-target",
        "--env",
        "CARGO_BUILD_JOBS=2",
        "--env",
        "KAPSEL_ENOSPC_FIXTURE=dedicated-tmpfs-v1",
        IMAGE,
        "bash",
        "-euc",
        f"rustc --version; uname -a; cargo test --locked -p kapsel --lib {TEST} "
        "-- --ignored --exact --nocapture --test-threads=1",
    ]
    (evidence / "command.txt").write_text(repr(command) + "\n", encoding="utf-8")
    print(f"Storage ENOSPC evidence: {evidence}", flush=True)
    try:
        with (evidence / "enospc.log").open("wb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        if result.returncode:
            raise SystemExit(f"ENOSPC fixture failed ({result.returncode}); see {evidence}")

        output = (evidence / "enospc.log").read_bytes()
        if (
            b"KAPSEL_ADMISSION_ENOSPC_PASSED" not in output
            or (b"KAPSEL_REAL_ENOSPC_CASES_PASSED" not in output)
            or (b"test result: ok. 1 passed; 0 failed; 0 ignored" not in output)
        ):
            raise SystemExit("expected ENOSPC test did not execute both cases")
        verify_source(snapshot)
    except BaseException as run_error:
        try:
            (evidence / "cleanup.txt").write_text(
                cleanup_container(name, evidence.name), encoding="utf-8"
            )
        except BaseException as cleanup_error:
            raise BaseExceptionGroup(
                "ENOSPC run failed and container cleanup is unverified",
                [run_error, cleanup_error],
            ) from None
        raise
    else:
        (evidence / "cleanup.txt").write_text(
            cleanup_container(name, evidence.name), encoding="utf-8"
        )
    (evidence / "result.txt").write_text("KAPSEL_STORAGE_ENOSPC_PASSED\n", encoding="utf-8")
    print("KAPSEL_STORAGE_ENOSPC_PASSED", flush=True)


if __name__ == "__main__":
    main()
