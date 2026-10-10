#!/usr/bin/env python3
"""Focused offline release assembler subprocess-bound regressions."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import assemble_artifact as ASSEMBLY


class AssemblerBoundedProcessTests(unittest.TestCase):
    def test_run_returns_stripped_success_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-assemble-run-") as temporary:
            root = pathlib.Path(temporary)
            result = ASSEMBLY.run(
                sys.executable,
                "-I",
                "-c",
                "print(' 0.2.0 ')",
                cwd=root,
            )
        self.assertEqual(result, "0.2.0")

    def test_output_overflow_is_rejected_before_completion(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "byte bound"):
            ASSEMBLY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.write(1, b'x' * 65536); time.sleep(5)",
                ],
                timeout=10,
                stdout_max=1024,
                stderr_max=1024,
            )

    def test_closed_output_fds_do_not_end_the_deadline(self) -> None:
        with self.assertRaises(subprocess.TimeoutExpired):
            ASSEMBLY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.close(1); os.close(2); time.sleep(5)",
                ],
                timeout=0.1,
                stdout_max=1024,
                stderr_max=1024,
            )

    def test_failed_command_hides_raw_tool_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "command failed") as failure:
            ASSEMBLY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,sys; os.write(2, b'SECRET'); sys.exit(7)",
                ],
                timeout=5,
                stdout_max=1024,
                stderr_max=1024,
            )
        self.assertNotIn("SECRET", str(failure.exception))


class BuildContainerCustodyTests(unittest.TestCase):
    container_id = "a" * 64

    def created(self) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, (self.container_id + "\n").encode(), b"")

    def test_start_timeout_retires_the_confirmed_container_not_only_the_client(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(ASSEMBLY, "run_bounded", return_value=self.created()) as create,
                mock.patch.object(
                    ASSEMBLY.subprocess,
                    "run",
                    side_effect=[
                        subprocess.TimeoutExpired("docker start", 1800),
                        subprocess.CompletedProcess([], 0),
                    ],
                ) as calls,
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    ASSEMBLY.build_binaries(pathlib.Path(temporary))
        self.assertEqual(create.call_args.args[0][1], "create")
        self.assertEqual(
            [call.args[0] for call in calls.call_args_list],
            [
                ["docker", "start", "--attach", self.container_id],
                ["docker", "rm", "--force", self.container_id],
            ],
        )

    def test_failed_creation_never_submits_start(self) -> None:
        with (
            mock.patch.object(ASSEMBLY, "run_bounded", side_effect=RuntimeError("create failed")),
            mock.patch.object(ASSEMBLY.subprocess, "run") as calls,
        ):
            with self.assertRaisesRegex(RuntimeError, "create failed"):
                ASSEMBLY.build_binaries(pathlib.Path("unused-target"))
        calls.assert_not_called()

    def test_failed_retirement_does_not_claim_cleanup(self) -> None:
        with (
            mock.patch.object(ASSEMBLY, "run_bounded", return_value=self.created()),
            mock.patch.object(
                ASSEMBLY.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.TimeoutExpired("docker rm", 30),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "retirement is unconfirmed"):
                ASSEMBLY.build_binaries(pathlib.Path("unused-target"))

    def test_failed_build_retains_the_mount_and_reports_its_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "target"
            target.mkdir()
            retained = target / "retained"
            retained.write_bytes(b"build evidence")
            with (
                mock.patch.object(ASSEMBLY.tempfile, "mkdtemp", return_value=str(target)),
                mock.patch.object(
                    ASSEMBLY,
                    "build_binaries",
                    side_effect=RuntimeError("retirement is unconfirmed"),
                ),
                mock.patch.object(ASSEMBLY.shutil, "rmtree") as cleanup,
            ):
                with self.assertRaisesRegex(RuntimeError, "target retained") as failure:
                    ASSEMBLY.stage_release(
                        pathlib.Path(temporary) / "stage", "1" * 40, "2" * 40, True
                    )
                self.assertIn(str(target), str(failure.exception))
                self.assertEqual(retained.read_bytes(), b"build evidence")
                cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
