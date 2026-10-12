#!/usr/bin/env python3
"""Behavioral checks of the two fixed profiles and shared independent fixture premises."""

import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import git_service_exercise as EXERCISE
import run_git_service as SOURCE


class GitServiceFixtureTests(unittest.TestCase):
    def launch(self, root: Path, artifact: Path | None = None) -> EXERCISE.Launch:
        return EXERCISE.Launch(
            root,
            root / "selected-git",
            root / "kapsel",
            root / "kapseld",
            root / "bridge",
            SOURCE.REPO / "examples/fresh_session_caller.py",
            Path(__file__).with_name("git_receiver_hook.py"),
            artifact,
        )

    def test_profiles_keep_process_windows_out_of_installed_environment(self):
        root = Path("/private/fixture")
        source = self.launch(root)
        installed = self.launch(root, Path("/artifact"))
        for case in SOURCE.CASES:
            environment = source.service_environment(case)
            self.assertEqual(environment["KAPSELD_TEST_INSTALLATION_ROOT"], str(root))
            self.assertEqual(
                environment.get("KAPSEL_DEMO_PAUSE"),
                case if case.endswith(("apply", "commit")) else None,
            )
            self.assertFalse(
                any("TEST" in key or "DEMO" in key for key in installed.service_environment(case))
            )

    def test_selected_git_bytes_and_version_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "selected-git"
            selected.write_bytes(b"#!/bin/sh\nprintf 'git version wrong\\n'\n")
            selected.chmod(0o700)
            with self.assertRaises(AssertionError):
                EXERCISE.exercise(self.launch(root), "healthy")
            copied = root / "var/lib/kapsel/git-bin/git"
            self.assertEqual(copied.read_bytes(), selected.read_bytes())
            self.assertEqual(copied.stat().st_mode & 0o777, 0o700)

    def test_service_retirement_kills_and_reaps_after_shutdown_timeout(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("kapseld", 15), 0]
        EXERCISE.retire_service(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(
            process.wait.call_args_list, [mock.call(timeout=15), mock.call(timeout=10)]
        )

    def test_modes_survive_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = os.umask(0o077)
            try:
                EXERCISE.private_directories(root)
            finally:
                os.umask(previous)
            self.assertEqual((root / "run/kapsel").stat().st_mode & 0o777, 0o750)
            self.assertEqual((root / "var/lib/kapsel").stat().st_mode & 0o777, 0o700)

    def test_exact_helper_bytes_execute_isolated_and_record_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / "fixture-control"
            control.mkdir()
            (control / "hook-settings.json").write_text('{"case":"healthy"}')
            hook = root / "receiver.git/hooks/pre-receive.py"
            hook.parent.mkdir(parents=True)
            source = Path(__file__).with_name("git_receiver_hook.py").read_bytes()
            hook.write_bytes(source)
            subprocess.run(
                ["python3", "-I", str(hook)],
                input=b"A B refs/heads/approved\n",
                check=True,
                timeout=5,
            )
            self.assertEqual((control / "pre-receive").read_bytes(), b"A B refs/heads/approved\n")
            self.assertEqual(hook.read_bytes(), source)

    def test_retained_row_is_read_only_and_refuses_missing_or_invalid_evidence(self):
        for version, insert in ((5, True), (6, False), (6, True)):
            with (
                self.subTest(version=version, insert=insert),
                tempfile.TemporaryDirectory() as temporary,
            ):
                journal = Path(temporary) / "journal.sqlite3"
                with sqlite3.connect(journal) as connection:
                    connection.execute(f"PRAGMA user_version = {version}")
                    connection.execute(
                        "CREATE TABLE git_ref_operations (operation_id TEXT, grant BLOB)"
                    )
                    if insert:
                        connection.execute(
                            "INSERT INTO git_ref_operations VALUES ('git-example', ?)",
                            (b"original",),
                        )
                before = journal.read_bytes()
                if version == 6 and insert:
                    self.assertEqual(EXERCISE.retained_row(journal), ("git-example", b"original"))
                else:
                    with self.assertRaises(AssertionError):
                        EXERCISE.retained_row(journal)
                self.assertEqual(journal.read_bytes(), before)
        with mock.patch.object(EXERCISE.sqlite3, "connect", side_effect=sqlite3.DatabaseError):
            with tempfile.NamedTemporaryFile() as file, self.assertRaises(sqlite3.DatabaseError):
                EXERCISE.retained_row(Path(file.name))


if __name__ == "__main__":
    unittest.main()
