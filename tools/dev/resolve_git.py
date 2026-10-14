#!/usr/bin/env python3
"""Resolve the supported local Git prerequisite without installing anything."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def resolve_git(selected: str | None) -> Path:
    if selected is not None and not Path(selected).is_absolute():
        raise ValueError("KAPSEL_TEST_GIT must be an absolute executable path")
    candidate = selected or shutil.which("git")
    if candidate is None:
        raise ValueError("Git 2.55.0 is missing")
    path = Path(candidate).resolve(strict=True)
    if path.name != "git" or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("the supported executable must be an executable regular file named git")
    output = subprocess.run([str(path), "--version"], capture_output=True, timeout=15, check=True)
    if output.stdout != b"git version 2.55.0\n":
        raise ValueError(f"Git version mismatch at {path}; expected Git 2.55.0")
    return path


def main() -> int:
    try:
        print(resolve_git(os.environ.get("KAPSEL_TEST_GIT")))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            f"Local Git prerequisite: {error}. Install Git 2.55.0 explicitly, then set KAPSEL_TEST_GIT to its absolute path and rerun cargo xtask doctor.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
