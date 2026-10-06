#!/usr/bin/env python3
"""Exercise source-fixture preparation with local Git, not pinned-receiver qualification."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_git_service as JOURNEY


class GitServiceFixtureTests(unittest.TestCase):
    def test_preparation_creates_the_exact_receiver_and_hook_inputs(self) -> None:
        selected = shutil.which("git")
        self.assertIsNotNone(selected)
        assert selected is not None
        # Only Git's version response is mocked. Repository operations and hooks run through
        # the copied local Git. This test does not qualify the required Git 2.55.0 binary.
        original_run = JOURNEY.run

        def run(*arguments: str, **kwargs) -> bytes:
            if arguments[1:] == ("--version",):
                return b"git version 2.55.0\n"
            return original_run(*arguments, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(JOURNEY, "run", side_effect=run):
                prepared = JOURNEY.prepare_git_receiver(root, Path(selected), "healthy")
            self.assertEqual(prepared.executable.read_bytes(), Path(selected).read_bytes())
            self.assertEqual(
                prepared.command("--git-dir", prepared.receiver, "rev-parse", JOURNEY.REF),
                prepared.old_commit,
            )
            prepared.command(
                "--git-dir",
                prepared.sender,
                "push",
                prepared.receiver,
                f"{prepared.new_commit}:{JOURNEY.REF}",
            )
            expected = f"{prepared.old_commit} {prepared.new_commit} {JOURNEY.REF}\n"
            for hook in ("pre-receive", "post-receive"):
                self.assertEqual((root / hook).read_text(), expected)
            self.assertEqual(
                prepared.command("--git-dir", prepared.receiver, "rev-parse", JOURNEY.REF),
                prepared.new_commit,
            )

    def test_barrier_rejects_a_retired_process(self) -> None:
        with subprocess.Popen(["sh", "-c", "exit 0"]) as process:
            process.wait(timeout=5)
            with self.assertRaisesRegex(AssertionError, "service exited"):
                JOURNEY.wait_for(lambda: True, process)


if __name__ == "__main__":
    unittest.main()
