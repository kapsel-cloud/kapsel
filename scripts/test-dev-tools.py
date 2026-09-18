#!/usr/bin/env python3
"""Check read-only setup diagnosis and partial-commit behavior in disposable homes/repos."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ContributorToolsTests(unittest.TestCase):
    def test_diagnosis_does_not_install_into_empty_home(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-tools-test-") as temporary:
            home = Path(temporary)
            result = subprocess.run(
                [str(ROOT / "scripts/setup.sh"), "--check"],
                cwd=ROOT,
                env={**os.environ, "HOME": str(home)},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((home / ".local").exists())
            self.assertFalse((home / ".rustup").exists())
            self.assertFalse((home / ".cargo").exists())

    def test_hook_checks_index_despite_unrelated_or_partial_edits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-hook-test-") as temporary:
            root = Path(temporary)

            def git(*arguments: str) -> None:
                subprocess.run(
                    ["git", *arguments], cwd=root, check=True, capture_output=True, timeout=10
                )

            def hook() -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    ["sh", str(ROOT / ".githooks/pre-commit")],
                    cwd=root,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

            git("init", "-q")
            path = root / "partial.txt"
            path.write_text("staged clean line\n")
            git("add", "partial.txt")
            path.write_text("unstaged trailing whitespace  \n")
            (root / "unrelated.txt").write_text("untracked  \n")
            self.assertEqual(hook().returncode, 0)
            git("add", "partial.txt")
            path.write_text("worktree clean but index bad\n")
            self.assertNotEqual(hook().returncode, 0)


if __name__ == "__main__":
    unittest.main()
