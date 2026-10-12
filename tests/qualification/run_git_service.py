#!/usr/bin/env python3
"""Unprivileged Linux source launch profile for the shared Git service exercise."""

import argparse
import os
import tempfile
from pathlib import Path

from git_service_exercise import Launch, exercise

REPO = Path(__file__).resolve().parents[2]
CASES = (
    "healthy",
    "after_apply",
    "before_receipt_commit",
    "after_receipt_commit",
    "pre-receive",
    "post-receive",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git", required=True, type=Path, help="operator-selected Git 2.55.0")
    for binary in ("kapsel", "kapseld", "bridge"):
        name = "kapsel-service-mcp" if binary == "bridge" else binary
        parser.add_argument(f"--{binary}", type=Path, default=REPO / "target/debug" / name)
    args = parser.parse_args()
    os.umask(0o077)
    for case in CASES:
        with tempfile.TemporaryDirectory(prefix="kapsel-git-service-") as temporary:
            exercise(
                Launch(
                    Path(temporary).resolve(),
                    args.git.resolve(strict=True),
                    args.kapsel.resolve(strict=True),
                    args.kapseld.resolve(strict=True),
                    args.bridge.resolve(strict=True),
                    REPO / "examples/fresh_session_caller.py",
                    Path(__file__).with_name("git_receiver_hook.py"),
                ),
                case,
            )


if __name__ == "__main__":
    main()
