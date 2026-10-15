#!/usr/bin/env python3
"""Regress exact selection, phase evidence, bounded execution and immutable-ID cleanup offline."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import run_storage_enospc as RUNNER

ROOT = Path(__file__).resolve().parents[2]
CONTAINER_ID = "a" * 64
EXECUTABLE = f"/cache/target/{RUNNER.TARGET}/debug/deps/kapsel-fixture"


def artifact_output(fresh: bool = True) -> bytes:
    return (
        json.dumps(
            {
                "reason": "compiler-artifact",
                "target": {"name": "kapsel", "kind": ["lib"]},
                "profile": {"test": True},
                "fresh": fresh,
                "executable": EXECUTABLE,
            }
        ).encode()
        + b"\n"
    )


def listing(case: str) -> bytes:
    return f"{case}: test\n\n1 test, 0 benchmarks\n".encode()


def completion(case: str) -> bytes:
    return (
        "\n".join(RUNNER.CASES[case])
        + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;\n"
    ).encode()


class SelectionTests(unittest.TestCase):
    def test_cargo_selects_one_exact_linux_executable_and_records_cache_reuse(self) -> None:
        for fresh in (False, True):
            executable, counts = RUNNER.select_executable(
                b"Finished test profile\n" + artifact_output(fresh)
            )
            self.assertEqual(executable, EXECUTABLE)
            self.assertEqual(counts, {"fresh": int(fresh), "compiled": int(not fresh)})
        for output in (
            b"",
            artifact_output() * 2,
            artifact_output().replace(b"/cache/target", b"/foreign"),
        ):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                RUNNER.select_executable(output)

    def test_every_exact_case_requires_nonzero_selection_and_every_phase_marker(self) -> None:
        for case in RUNNER.CASES:
            RUNNER.require_selection(listing(case), case)
            RUNNER.require_completion(completion(case), case)
            for bad in (
                b"\n0 tests, 0 benchmarks\n",
                listing(case).replace(b"1 test", b"2 tests"),
                listing("wrong"),
            ):
                with self.subTest(case=case, bad=bad), self.assertRaises(RuntimeError):
                    RUNNER.require_selection(bad, case)
            for marker in RUNNER.CASES[case]:
                for bad in (
                    completion(case).replace(marker.encode(), b""),
                    completion(case) + marker.encode() + b"\n",
                ):
                    with self.subTest(case=case, marker=marker), self.assertRaises(RuntimeError):
                        RUNNER.require_completion(bad, case)
            with self.assertRaises(RuntimeError):
                RUNNER.require_completion(completion(case).replace(b"1 passed", b"0 passed"), case)

    def test_container_bounds_and_readonly_source_are_explicit(self) -> None:
        command = RUNNER.container_command(ROOT, Path("/cache-on-host"), "name", "owner")
        for value in (
            "--memory=2g",
            "--memory-swap=2g",
            "--cpus=2",
            "--pids-limit=256",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "linux/amd64",
            "type=bind,src=/cache-on-host,dst=/cache",
            f"type=bind,src={ROOT},dst=/workspace,readonly",
        ):
            self.assertIn(value, command)
        self.assertIn(
            "size=100663296", command[command.index("--tmpfs", command.index("--tmpfs") + 1) + 1]
        )
        self.assertEqual(command[command.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        self.assertEqual(command[-3:], [RUNNER.IMAGE, "sleep", "1800"])


class CommandTests(unittest.TestCase):
    def test_real_exit_timeout_eof_and_output_ceiling_never_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.assertEqual(RUNNER.run(["sh", "-c", "printf exact"], directory / "ok"), b"exact")
            for name, program, exception in (
                ("exit", "printf primary; exit 7", RuntimeError),
                ("timeout", "sleep 3", subprocess.TimeoutExpired),
                ("eof", "exec 1>&- 2>&-; sleep 3", subprocess.TimeoutExpired),
            ):
                with self.subTest(name=name), self.assertRaises(exception):
                    RUNNER.run(["sh", "-c", program], directory / name, timeout=0.1)
            self.assertEqual((directory / "exit").read_bytes(), b"primary")
            with (
                mock.patch.object(RUNNER, "OUTPUT_LIMIT", 4),
                self.assertRaisesRegex(RuntimeError, "output exceeded"),
            ):
                RUNNER.run(["sh", "-c", "printf 12345"], directory / "overflow")
            self.assertLessEqual((directory / "overflow").stat().st_size, 4)

    def test_registration_interruption_retires_child_and_cancellation_defers_until_registered(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "log"
            started = time.monotonic()
            with mock.patch.object(
                RUNNER.selectors.DefaultSelector,
                "register",
                side_effect=KeyboardInterrupt("registration"),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    RUNNER.run(["sh", "-c", "sleep 30"], log)
            self.assertLess(time.monotonic() - started, 2)
            with mock.patch.object(RUNNER, "CANCELLED", None):
                RUNNER.interrupted(15, None)
                with self.assertRaises(KeyboardInterrupt):
                    RUNNER.run(["sh", "-c", "printf forbidden"], Path(temporary) / "cancelled")
                self.assertEqual(
                    RUNNER.run(["sh", "-c", "printf cleanup"], None, interruptible=False),
                    b"cleanup",
                )

    def test_publication_failure_retains_primary_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            commands = RUNNER.Commands(Path(temporary))
            with mock.patch.object(Path, "write_text", side_effect=OSError("evidence full")):
                with self.assertRaises(BaseExceptionGroup) as caught:
                    commands.execute(["sh", "-c", "exit 7"])
            self.assertIn("command failed (7)", str(caught.exception.exceptions[0]))
            self.assertIn("evidence full", str(caught.exception.exceptions[1]))

    def test_failed_bounded_reap_never_uses_context_manager_wait(self) -> None:
        for execution_fails in (False, True):
            with self.subTest(execution_fails=execution_fails):
                child = mock.MagicMock()
                child.__enter__.return_value = child
                child.stdout = mock.Mock()
                child.poll.return_value = 7 if execution_fails else 0
                child.returncode = child.poll.return_value
                cleanup = subprocess.TimeoutExpired(["fixture"], 10)
                child.wait.side_effect = cleanup
                selector = mock.Mock()
                selector.get_map.return_value = {}
                with (
                    mock.patch.object(RUNNER.subprocess, "Popen", return_value=child),
                    mock.patch.object(RUNNER.selectors, "DefaultSelector", return_value=selector),
                    mock.patch.object(RUNNER.os, "killpg"),
                    self.assertRaises(BaseException) as caught,
                ):
                    RUNNER.run(["fixture"], None)
                if execution_fails:
                    self.assertIsInstance(caught.exception, BaseExceptionGroup)
                    group = caught.exception
                    self.assertIn("command failed (7)", str(group.exceptions[0]))
                    self.assertIs(group.exceptions[1], cleanup)
                else:
                    self.assertIs(caught.exception, cleanup)
                child.wait.assert_called_once_with(timeout=10)
                child.__exit__.assert_not_called()
                child.stdout.close.assert_called_once_with()
                selector.close.assert_called_once_with()

    def test_timeout_retires_client_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "late-write"
            with self.assertRaises(subprocess.TimeoutExpired):
                RUNNER.run(
                    ["sh", "-c", '(sleep 1; touch "$1") & wait', "fixture", str(marker)],
                    Path(temporary) / "log",
                    timeout=0.1,
                )
            time.sleep(1.1)
            self.assertFalse(marker.exists())


class CleanupTests(unittest.TestCase):
    def test_verified_cleanup_removes_only_immutable_id_and_checks_retirement(self) -> None:
        commands = mock.Mock()
        commands.execute.side_effect = [f"{CONTAINER_ID}\towner\n".encode(), b"removed\n", b""]
        self.assertEqual(RUNNER.cleanup_container("name", "owner", commands), CONTAINER_ID)
        self.assertEqual(
            commands.execute.call_args_list[1].args[0], ["docker", "rm", "--force", CONTAINER_ID]
        )

    def test_full_evidence_filesystem_cannot_prevent_verified_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            commands = RUNNER.Commands(Path(temporary))
            with (
                mock.patch.object(
                    RUNNER,
                    "run",
                    side_effect=[f"{CONTAINER_ID}\towner\n".encode(), b"removed\n", b""],
                ) as run,
                mock.patch.object(Path, "write_bytes", side_effect=OSError("logs full")),
                mock.patch.object(Path, "write_text", side_effect=OSError("records full")),
                self.assertRaises(BaseExceptionGroup),
            ):
                RUNNER.cleanup_container("name", "owner", commands)
            self.assertEqual(
                run.call_args_list[1].args[0], ["docker", "rm", "--force", CONTAINER_ID]
            )
            self.assertEqual(run.call_count, 3)
            self.assertTrue(
                all(
                    call.args[1] is None and not call.kwargs["interruptible"]
                    for call in run.call_args_list
                )
            )

    def test_unverified_identity_inspection_removal_and_retirement_fail(self) -> None:
        for responses in (
            [f"{CONTAINER_ID}\tforeign\n".encode()],
            [b"malformed\towner\n"],
            [RuntimeError("inspect failed")],
            [f"{CONTAINER_ID}\towner\n".encode(), RuntimeError("remove failed")],
            [f"{CONTAINER_ID}\towner\n".encode(), b"", f"{CONTAINER_ID}\n".encode()],
            [f"{CONTAINER_ID}\towner\n".encode(), b"", b"invalid inventory\n"],
        ):
            with self.subTest(responses=responses):
                commands = mock.Mock()
                commands.execute.side_effect = responses
                with self.assertRaises(RuntimeError):
                    RUNNER.cleanup_container("name", "owner", commands)
                if len(responses) == 1:
                    self.assertEqual(commands.execute.call_count, 1)


class OutcomeTests(unittest.TestCase):
    def exercise(self, evidence: Path, outcome: str, prepare_only: bool = False) -> dict:
        commands: list[list[str]] = []

        def execute(
            _self: RUNNER.Commands,
            command: list[str],
            timeout: float = 30,
            *,
            retirement: bool = False,
        ) -> bytes:
            commands.append(command)
            if command[0] == "git":
                return b"dirty\n" if "status" in command else b"b" * 40 + b"\n"
            if command[1] == "create":
                return CONTAINER_ID.encode()
            if command[1] == "start":
                return b"started"
            if command[1] == "inspect":
                owner = next(
                    part.split("=", 1)[1]
                    for part in commands[3]
                    if part.startswith("cloud.kapsel.storage-evidence=")
                )
                return f"{CONTAINER_ID}\t{owner if outcome != 'owner' else 'foreign'}\n".encode()
            if command[1] == "rm":
                if outcome in ("cleanup", "exit-and-cleanup"):
                    raise RuntimeError("cleanup uncertainty")
                return b"removed"
            if command[1] == "container":
                return b""
            self.assertEqual(command[:3], ["docker", "exec", CONTAINER_ID])
            if command[3] == "rustup":
                return b"1.98.0-x86_64-unknown-linux-gnu (active, default)\n"
            if command[3] == "rustc":
                channel = "wrong" if outcome == "toolchain" else "1.98.0"
                return f"release: {channel}\nhost: {RUNNER.TARGET}\n".encode()
            if command[3] == "uname":
                return b"Linux fixture\n"
            if command[3] == "cargo":
                return artifact_output()
            if command[3] == "sha256sum":
                return b"c" * 64 + b"  executable\n"
            self.assertEqual(command[3], EXECUTABLE)
            case = command[4]
            self.assertIn("--exact", command)
            self.assertIn("--ignored", command)
            if "--list" in command:
                return b"0 tests, 0 benchmarks\n" if outcome == "zero" else listing(case)
            if outcome == "timeout":
                raise subprocess.TimeoutExpired(command, timeout)
            if outcome == "interrupt":
                raise KeyboardInterrupt("interrupted")
            if outcome in ("exit", "exit-and-cleanup"):
                raise RuntimeError("primary test failure")
            return (
                completion(case).replace(b"KAPSEL_MAXIMAL_COMPLETION_PASSED", b"")
                if outcome == "marker"
                else completion(case)
            )

        with mock.patch.object(RUNNER.Commands, "execute", autospec=True, side_effect=execute):
            RUNNER.qualify(ROOT, evidence / "cache", evidence, prepare_only)
        report = json.loads((evidence / "result.json").read_text())
        self.assertEqual(sum(command[3:4] == ["cargo"] for command in commands), 1)
        self.assertEqual(report["source"]["dirty"], True)
        self.assertEqual(report["cargo_artifacts"], {"fresh": 1, "compiled": 0})
        self.assertEqual(report["removed_container_id"], CONTAINER_ID)
        return report

    def test_success_and_preparation_have_distinct_evidence(self) -> None:
        for prepare_only in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                report = self.exercise(Path(temporary), "success", prepare_only)
                self.assertEqual(report["outcome"], "PREPARED" if prepare_only else "QUALIFIED")
                self.assertEqual(
                    report["executed_cases"], [] if prepare_only else list(RUNNER.CASES)
                )
                for timing in (
                    "setup_seconds",
                    "build_seconds",
                    "execution_seconds",
                    "total_seconds",
                ):
                    self.assertGreaterEqual(report[timing], 0)

    def test_all_execution_failures_leave_incomplete_and_preserve_primary_failure(self) -> None:
        for outcome in (
            "marker",
            "zero",
            "timeout",
            "interrupt",
            "exit",
            "owner",
            "cleanup",
            "toolchain",
            "exit-and-cleanup",
        ):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                evidence = Path(temporary)
                with self.assertRaises(BaseException) as caught:
                    self.exercise(evidence, outcome)
                if outcome == "exit-and-cleanup":
                    self.assertIsInstance(caught.exception, BaseExceptionGroup)
                    group = caught.exception
                    self.assertIn("primary test failure", str(group.exceptions[0]))
                    self.assertIn("cleanup uncertainty", str(group.exceptions[1]))
                self.assertEqual(
                    json.loads((evidence / "result.json").read_text())["outcome"], "INCOMPLETE"
                )


if __name__ == "__main__":
    unittest.main()
