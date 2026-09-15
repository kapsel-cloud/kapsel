#!/usr/bin/env python3
"""Run only the optional bounded SQLite ENOSPC fixture in a disposable Linux tmpfs."""

from __future__ import annotations

import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
TEST = (
    "gateway::tests::storage::genuine_enospc_during_receipt_sql_and_commit_recovers_without_resend"
)


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", "--no-optional-locks", *arguments], timeout=30)


def untracked_sources() -> dict[str, bytes]:
    paths = git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    return {os.fsdecode(path): Path(os.fsdecode(path)).read_bytes() for path in paths if path}


def capture_source(evidence: Path) -> tuple[str, bytes, dict[str, bytes]]:
    base = git("rev-parse", "HEAD").decode().strip()
    source_diff = git("diff", "--binary", "--no-ext-diff", "--no-textconv", base, "--")
    sources = untracked_sources()
    (evidence / "base-revision.txt").write_text(base + "\n", encoding="utf-8")
    (evidence / "source.diff").write_bytes(source_diff)
    (evidence / "source-status.txt").write_bytes(git("status", "--porcelain=v1"))
    with tarfile.open(evidence / "new-source.tar", "w") as archive:
        for path in sources:
            archive.add(path, arcname=path, recursive=False)
    return base, source_diff, sources


def verify_source(snapshot: tuple[str, bytes, dict[str, bytes]]) -> None:
    base, source_diff, sources = snapshot
    if git("diff", "--binary", "--no-ext-diff", "--no-textconv", base, "--") != source_diff or (
        untracked_sources() != sources
    ):
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
    # Delete the verified immutable ID, not a name that could have been replaced since inspection.
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
    root = Path(__file__).resolve().parent.parent
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
        "--mount",
        f"type=bind,src={root},dst=/workspace,readonly",
        "--tmpfs",
        "/kapsel-enospc:rw,nosuid,nodev,noexec,size=100663296,mode=0700",
        "--workdir",
        "/workspace",
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
        if b"KAPSEL_REAL_ENOSPC_CASES_PASSED" not in output or (
            b"test result: ok. 1 passed; 0 failed; 0 ignored" not in output
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
