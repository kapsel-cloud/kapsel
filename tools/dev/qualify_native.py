#!/usr/bin/env python3
"""Extract selected A, then route to its native owner on an authorized fresh Linux host."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--extract-to", required=True, type=Path)
    arguments = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error(
            "native qualification requires separately authorized root on a fresh Linux host"
        )
    extraction = subprocess.run(
        [
            sys.executable,
            "tools/release/verify_artifact.py",
            "--archive",
            str(arguments.archive),
            "--expected-revision",
            arguments.revision,
            "--extract-to",
            str(arguments.extract_to),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    lines = extraction.stdout.splitlines()
    if len(lines) != 1:
        raise RuntimeError("verifier did not report one extracted artifact root")
    artifact = Path(lines[0])
    owner = artifact / "share/kapsel/qualification.py"
    subprocess.run(
        [
            sys.executable,
            "-I",
            str(owner),
            "--artifact",
            str(artifact),
            "--expected-revision",
            arguments.revision,
            "--profile",
            "systemd",
        ],
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
