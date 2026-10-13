#!/usr/bin/env python3
"""Qualify extracted production binaries against a disposable local Git receiver.

Uses one isolated Linux container per case, with distinct service and caller identities.
No system installation, source harness, product pause hook, or live repository is used.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
CASES = ("healthy", "pre-receive", "post-receive", "service-loss")
EXERCISE_SOURCE = Path(__file__).with_name("git_service_exercise.py")
CALLER_SOURCE = ROOT / "examples/fresh_session_caller.py"
HOOK_SOURCE = Path(__file__).with_name("git_receiver_hook.py")


def run(arguments: list[str]) -> bytes:
    return subprocess.run(arguments, check=True, capture_output=True, timeout=60).stdout


def exercise_case(
    case: str,
    extracted: Path,
    inputs: Path,
    evidence: Path,
    source: bytes,
) -> dict[str, object]:
    """Transfer the operator fixture into one owned, network-disabled environment."""
    name = "kapsel-git-" + uuid.uuid4().hex[:12]
    evidence.mkdir(mode=0o700)
    owned = False
    try:
        run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=1g",
                "--volume",
                f"{extracted}:/artifact:ro",
                "--env",
                f"GIT_CASE={case}",
                "-i",
                RUNNER,
                "python3",
                "-I",
                "-",
            ]
        )
        owned = True
        run(["docker", "cp", str(inputs), name + ":/inputs"])
        with (evidence / "exercise.log").open("wb") as log:
            result = subprocess.run(
                ["docker", "start", "--attach", "--interactive", name],
                input=source,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
        run(["docker", "cp", name + ":/evidence/.", str(evidence)])
        if result.returncode != 0:
            raise RuntimeError(f"{case} failed; inspect the private exercise.log")
        summary = json.loads((evidence / "summary.json").read_bytes())
        if (
            not isinstance(summary, dict)
            or summary.get("case") != case
            or summary.get("result") != ("SUCCEEDED" if case == "healthy" else "UNKNOWN")
            or summary.get("inspection") != "INSPECTED"
            or summary.get("identical_retained_receipt") is not True
            or summary.get("caller_private_access_denied") is not True
            or summary.get("cold_binary_replacement") is not True
            or summary.get("finalized_submission")
            != {"version": 1, "status": "ADMITTED", "phase": "finalized"}
            or (case == "healthy" and summary.get("signing_repair_without_receiver") is not True)
            or not isinstance(summary.get("receipt_sha256"), str)
            or len(summary["receipt_sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in summary["receipt_sha256"])
        ):
            raise RuntimeError("packaged Git exercise returned malformed or incomplete evidence")
        return summary
    finally:
        if owned:
            run(["docker", "rm", "-f", name])


def qualify(archive: Path, revision: str, git: Path, cases: tuple[str, ...] = CASES) -> Path:
    if not cases or any(case not in CASES for case in cases):
        raise ValueError("select at least one known Git case")
    selected = tuple(case for case in CASES if case in cases)
    os.umask(0o077)
    workspace = Path(tempfile.mkdtemp(prefix="kapsel-git-artifact-"))
    print(f"Private evidence workspace: {workspace}", flush=True)
    spec = importlib.util.spec_from_file_location(
        "artifact", ROOT / "tools/release/verify_artifact.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the artifact verifier")
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    archive = archive.resolve(strict=True)
    git = git.resolve(strict=True)
    extracted = artifact.extract_release(
        archive, Path(str(archive) + ".sha256"), revision, workspace / "extracted"
    )
    metadata = json.loads((extracted / "RELEASE-METADATA.json").read_bytes())
    if metadata["source_dirty"]:
        raise RuntimeError("packaged Git qualification requires a clean-source artifact")
    if not git.is_file() or not os.access(git, os.X_OK):
        raise RuntimeError("--git must select an executable regular file")
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
    shutil.copyfile(CALLER_SOURCE, inputs / CALLER_SOURCE.name)
    shutil.copyfile(git, inputs / "git")
    (inputs / "git").chmod(0o700)
    # Snapshot once: every case executes the same bytes, retained for independent replay.
    source = EXERCISE_SOURCE.read_bytes()
    (workspace / EXERCISE_SOURCE.name).write_bytes(source)
    hook_source = HOOK_SOURCE.read_bytes()
    (inputs / HOOK_SOURCE.name).write_bytes(hook_source)
    (workspace / HOOK_SOURCE.name).write_bytes(hook_source)
    hook_digest = hashlib.sha256(hook_source).hexdigest()
    (workspace / (HOOK_SOURCE.name + ".sha256")).write_text(hook_digest + "\n")

    summaries = [
        exercise_case(case, extracted, inputs, workspace / case, source) for case in selected
    ]
    summary = {
        "qualification_scope": "full" if selected == CASES else "focused",
        "requested_cases": selected,
        "prerequisite_cases": [],
        "executed_cases": [record["case"] for record in summaries],
        "source_revision": revision,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "git_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
        "exercise_sha256": hashlib.sha256(source).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "caller_sha256": hashlib.sha256((inputs / CALLER_SOURCE.name).read_bytes()).hexdigest(),
        "hook_sha256": hook_digest,
        "runner": RUNNER,
        "cases": summaries,
        "limits": "container process/socket and hook-input proof; not packet counts, native systemd, power loss or publication",
    }
    (workspace / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)
    return workspace


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--git", required=True, type=Path, help="accepted Linux Git 2.55.0 executable"
    )
    parser.add_argument(
        "--case", action="append", choices=CASES, help="Run only these cases; repeat to select more"
    )
    args = parser.parse_args()
    qualify(args.archive, args.revision, args.git, tuple(args.case) if args.case else CASES)


if __name__ == "__main__":
    main()
