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
EXERCISE_SOURCE = Path(__file__).with_name("git_artifact_exercise.py")
HOOK_SOURCE = Path(__file__).with_name("git_receiver_hook.py")


def run(arguments: list[str]) -> bytes:
    return subprocess.run(arguments, check=True, capture_output=True, timeout=60).stdout


def exercise_case(
    case: str,
    extracted: Path,
    inputs: Path,
    evidence: Path,
    source: bytes,
    retained: Path | None = None,
) -> dict[str, object]:
    """Transfer the operator fixture into one owned, network-disabled environment."""
    name = "kapsel-git-" + uuid.uuid4().hex[:12]
    evidence.mkdir(mode=0o700)
    owned = False
    retained_mount = [] if retained is None else ["--volume", f"{retained}:/retained-artifact:ro"]
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
                *retained_mount,
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
        if not isinstance(summary, dict) or summary.get("case") != case:
            raise RuntimeError("packaged Git exercise returned the wrong case evidence")
        return summary
    finally:
        if owned:
            run(["docker", "rm", "-f", name])


def qualify(
    archive: Path,
    revision: str,
    git: Path,
    retained_archive: Path | None = None,
    retained_revision: str | None = None,
) -> Path:
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
    retained = None
    if retained_archive is not None:
        if retained_revision is None:
            raise RuntimeError("retained archive requires its exact revision")
        retained_archive = retained_archive.resolve(strict=True)
        retained = artifact.extract_release(
            retained_archive,
            Path(str(retained_archive) + ".sha256"),
            retained_revision,
            workspace / "retained-extracted",
        )
        if json.loads((retained / "RELEASE-METADATA.json").read_bytes())["source_dirty"]:
            raise RuntimeError("retained history requires a clean-source producer")
    elif retained_revision is not None:
        raise RuntimeError("retained revision requires an archive")
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
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
        exercise_case(case, extracted, inputs, workspace / case, source, retained) for case in CASES
    ]
    summary = {
        "source_revision": revision,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "git_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
        "retained_source_revision": retained_revision,
        "retained_archive_sha256": (
            hashlib.sha256(retained_archive.read_bytes()).hexdigest()
            if retained_archive is not None
            else None
        ),
        "exercise_sha256": hashlib.sha256(source).hexdigest(),
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
    parser.add_argument("--retained-archive", type=Path)
    parser.add_argument("--retained-revision")
    args = parser.parse_args()
    qualify(args.archive, args.revision, args.git, args.retained_archive, args.retained_revision)


if __name__ == "__main__":
    main()
