#!/usr/bin/env python3
"""Regress ENOSPC source evidence and cleanup without Docker or this checkout's index."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "storage_enospc", ROOT / "scripts/test-storage-enospc.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
CONTAINER_ID = "a" * 64


class SourceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="kapsel-storage-runner-test-")
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.root = self.temporary / "repo"
        self.root.mkdir()
        # Never let a hook's alternate Git index/worktree redirect fixture writes to this checkout.
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated_git = mock.patch.dict(os.environ, environment, clear=True)
        isolated_git.start()
        self.addCleanup(isolated_git.stop)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.git("init", "-q")
        for name in ("staged.txt", "unstaged.txt", "both.txt", "deleted.txt"):
            (self.root / name).write_text("original\n")
        self.git("add", ".")
        self.commit("base")
        self.evidence = self.temporary / "evidence"
        self.evidence.mkdir()

    def git(self, *arguments: str) -> bytes:
        return subprocess.check_output(["git", *arguments], cwd=self.root, timeout=10)

    def commit(self, message: str, *arguments: str) -> None:
        self.git(
            "-c",
            "user.name=Storage fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--no-gpg-sign",
            "-qm",
            message,
            *arguments,
        )

    def test_staged_unstaged_new_deleted_and_untracked_reconstruct_without_index_changes(
        self,
    ) -> None:
        (self.root / "staged.txt").write_text("staged change\n")
        (self.root / "new.bin").write_bytes(b"\0staged new\xff")
        (self.root / "both.txt").write_text("staged intermediate\n")
        self.git("add", "staged.txt", "new.bin", "both.txt")
        (self.root / "both.txt").write_text("working-tree final\n")
        self.git("rm", "-q", "deleted.txt")
        (self.root / "unstaged.txt").write_text("unstaged change\n")
        (self.root / "loose.txt").write_text("untracked\n")
        index = (self.root / ".git/index").read_bytes()
        snapshot = RUNNER.capture_source(self.evidence)
        RUNNER.verify_source(snapshot)
        self.assertEqual((self.root / ".git/index").read_bytes(), index)
        self.assertEqual(snapshot[2], {"loose.txt": b"untracked\n"})
        reconstructed = self.temporary / "reconstructed"
        reconstructed.mkdir()
        with tarfile.open(fileobj=io.BytesIO(self.git("archive", snapshot[0]))) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    (reconstructed / member.name).write_bytes(archive.extractfile(member).read())
        subprocess.run(
            ["git", "apply", str(self.evidence / "source.diff")],
            cwd=reconstructed,
            timeout=10,
            check=True,
        )
        with tarfile.open(self.evidence / "new-source.tar") as archive:
            for member in archive.getmembers():
                (reconstructed / member.name).write_bytes(archive.extractfile(member).read())
        expected = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        self.assertEqual({p.name: p.read_bytes() for p in reconstructed.iterdir()}, expected)
        self.assertEqual((self.root / ".git/index").read_bytes(), index)

    def test_verification_detects_staged_edits_and_untracked_inventory_and_bytes(self) -> None:
        (self.root / "loose.txt").write_text("first\n")
        for change in ("staged", "untracked-bytes", "untracked-added", "untracked-removed"):
            with self.subTest(change=change):
                snapshot = RUNNER.capture_source(self.evidence)
                if change == "staged":
                    (self.root / "staged.txt").write_text("changed during run\n")
                    self.git("add", "staged.txt")
                elif change == "untracked-bytes":
                    (self.root / "loose.txt").write_text("second\n")
                elif change == "untracked-added":
                    (self.root / "new-loose.txt").write_text("new\n")
                else:
                    (self.root / "new-loose.txt").unlink()
                with self.assertRaisesRegex(RuntimeError, "source changed"):
                    RUNNER.verify_source(snapshot)

    def test_head_is_captured_once_and_comparison_uses_that_exact_base(self) -> None:
        with mock.patch.object(RUNNER, "git", wraps=RUNNER.git) as commands:
            snapshot = RUNNER.capture_source(self.evidence)
            self.commit("later fixture head", "--allow-empty")
            self.assertNotEqual(self.git("rev-parse", "HEAD").decode().strip(), snapshot[0])
            RUNNER.verify_source(snapshot)
        self.assertEqual(
            sum(call.args == ("rev-parse", "HEAD") for call in commands.call_args_list), 1
        )
        diffs = [call.args for call in commands.call_args_list if call.args[0] == "diff"]
        self.assertEqual(len(diffs), 2)
        self.assertTrue(all(args[-2:] == (snapshot[0], "--") for args in diffs))


class CleanupTests(unittest.TestCase):
    @staticmethod
    def result(
        code: int = 0, output: bytes = b"", error: bytes = b""
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess([], code, output, error)

    def test_verified_owner_is_removed_by_immutable_id(self) -> None:
        with mock.patch.object(
            RUNNER.subprocess,
            "run",
            side_effect=[
                self.result(output=f"{CONTAINER_ID}\towner\n".encode()),
                self.result(),
            ],
        ) as calls:
            self.assertIn("Removed verified owned", RUNNER.cleanup_container("name", "owner"))
        self.assertEqual(calls.call_args_list[1].args[0], ["docker", "rm", "--force", CONTAINER_ID])

    def test_inspect_failure_requires_successful_inventory_proof_of_absence(self) -> None:
        with mock.patch.object(
            RUNNER.subprocess,
            "run",
            side_effect=[
                self.result(1, error=b"inspect unavailable"),
                self.result(output=b"unrelated\n"),
            ],
        ) as calls:
            self.assertIn(
                "absent in successful Docker inventory", RUNNER.cleanup_container("name", "owner")
            )
        self.assertFalse(any(call.args[0][1] == "rm" for call in calls.call_args_list))

    def test_inspect_inventory_and_ownership_failures_never_remove_unverified_container(
        self,
    ) -> None:
        cases = [
            [self.result(1), self.result(1, error=b"daemon unavailable")],
            [self.result(1), self.result(output=b"name\n")],
            [self.result(1), self.result(output=b"invalid inventory output\n")],
            [self.result(output=f"{CONTAINER_ID}\twrong-owner\n".encode())],
            [self.result(output=b"malformed identity\towner\n")],
            [subprocess.TimeoutExpired("docker inspect", 30)],
            [OSError("docker unavailable")],
        ]
        for responses in cases:
            with (
                self.subTest(responses=responses),
                mock.patch.object(RUNNER.subprocess, "run", side_effect=responses) as calls,
            ):
                with self.assertRaises((RuntimeError, subprocess.TimeoutExpired, OSError)):
                    RUNNER.cleanup_container("name", "owner")
                self.assertFalse(any(call.args[0][1] == "rm" for call in calls.call_args_list))

    def test_verified_removal_failure_is_explicit(self) -> None:
        for failure in (
            self.result(1, error=b"remove refused"),
            subprocess.TimeoutExpired("docker rm", 30),
        ):
            with (
                self.subTest(failure=failure),
                mock.patch.object(
                    RUNNER.subprocess,
                    "run",
                    side_effect=[
                        self.result(output=f"{CONTAINER_ID}\towner\n".encode()),
                        failure,
                    ],
                ),
            ):
                with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                    RUNNER.cleanup_container("name", "owner")


class RunnerOutcomeTests(unittest.TestCase):
    def test_primary_failure_survives_cleanup_failure_and_success_requires_cleanup(self) -> None:
        for outcome, cleanup_fails in (
            ("success", False),
            ("success", True),
            ("exit", False),
            ("exit", True),
            ("timeout", False),
            ("timeout", True),
        ):
            run_fails = outcome != "success"
            with self.subTest(outcome=outcome, cleanup_fails=cleanup_fails):
                with tempfile.TemporaryDirectory(prefix="kapsel-storage-outcome-") as temporary:
                    directory = Path(temporary)
                    (directory / "repo/scripts").mkdir(parents=True)
                    evidence = directory / "evidence"
                    evidence.mkdir()
                    previous = Path.cwd()

                    def run(
                        command: list[str], *, selected_outcome: str = outcome, **kwargs: object
                    ) -> subprocess.CompletedProcess:
                        kwargs["stdout"].write(
                            b"KAPSEL_REAL_ENOSPC_CASES_PASSED\n"
                            b"test result: ok. 1 passed; 0 failed; 0 ignored\n"
                        )
                        if selected_outcome == "timeout":
                            raise subprocess.TimeoutExpired(command, 1800)
                        return subprocess.CompletedProcess(
                            command, int(selected_outcome != "success")
                        )

                    output = io.StringIO()
                    try:
                        with (
                            mock.patch.object(
                                RUNNER, "__file__", str(directory / "repo/scripts/runner.py")
                            ),
                            mock.patch.object(
                                RUNNER.tempfile, "mkdtemp", return_value=str(evidence)
                            ),
                            mock.patch.object(
                                RUNNER, "capture_source", return_value=("base", b"", {})
                            ),
                            mock.patch.object(RUNNER, "verify_source"),
                            mock.patch.object(RUNNER.subprocess, "run", side_effect=run),
                            mock.patch.object(
                                RUNNER,
                                "cleanup_container",
                                side_effect=RuntimeError("cleanup uncertainty")
                                if cleanup_fails
                                else None,
                                return_value="verified cleanup\n",
                            ),
                            contextlib.redirect_stdout(output),
                        ):
                            if run_fails and cleanup_fails:
                                with self.assertRaises(BaseExceptionGroup) as caught:
                                    RUNNER.main()
                                self.assertIsInstance(
                                    caught.exception.exceptions[0],
                                    SystemExit if outcome == "exit" else subprocess.TimeoutExpired,
                                )
                                self.assertIn(
                                    "fixture failed" if outcome == "exit" else "timed out",
                                    str(caught.exception.exceptions[0]),
                                )
                                self.assertIn(
                                    "cleanup uncertainty", str(caught.exception.exceptions[1])
                                )
                            elif run_fails:
                                with self.assertRaises(
                                    SystemExit if outcome == "exit" else subprocess.TimeoutExpired
                                ):
                                    RUNNER.main()
                            elif cleanup_fails:
                                with self.assertRaisesRegex(RuntimeError, "cleanup uncertainty"):
                                    RUNNER.main()
                            else:
                                RUNNER.main()
                    finally:
                        os.chdir(previous)
                    succeeded = not run_fails and not cleanup_fails
                    self.assertEqual((evidence / "result.txt").exists(), succeeded)
                    self.assertEqual("KAPSEL_STORAGE_ENOSPC_PASSED" in output.getvalue(), succeeded)


if __name__ == "__main__":
    unittest.main()
