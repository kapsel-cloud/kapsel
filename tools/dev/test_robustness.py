#!/usr/bin/env python3
"""Tiny process fixtures for the robustness supervisor; no exploration or host changes."""

import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import run_robustness as runner


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.scratch = self.root / "scratch"
        self.evidence = self.state / "run-fixture"
        for path in (self.state, self.scratch, self.evidence):
            path.mkdir(mode=0o700)
        self.lock = runner.acquire_lock(self.state)
        self.supervisor = runner.Supervisor(self.evidence, self.scratch, self.lock, 5)

    def tearDown(self):
        os.close(self.lock)
        self.temporary.cleanup()

    def command(self, source):
        return [sys.executable, "-c", source]

    def fixture_command(self, scenario, *arguments):
        return [
            sys.executable,
            str(Path(__file__).with_name("robustness_process_fixture.py")),
            scenario,
            *(str(argument) for argument in arguments),
        ]

    def test_retained_record_shapes_are_validated_before_use(self):
        path = self.evidence / "result.json"
        for field, value in (
            ("revision", []),
            ("cases", True),
            ("seeds", ["7"]),
            ("finished", "now"),
            ("prior_status", "SUCCESS"),
        ):
            with self.subTest(field=field):
                runner.atomic_json(
                    path, {"status": "INCOMPLETE", "lane": "simulation", field: value}
                )
                with self.assertRaises(runner.Incomplete):
                    runner.read_result(path)
        minimal = {"status": "INCOMPLETE", "lane": "unclassified"}
        runner.atomic_json(path, minimal)
        self.assertEqual(runner.read_result(path), minimal)

    def test_exit_status_and_empty_execution(self):
        with self.assertRaises(runner.Finding):
            self.supervisor.run([self.command("raise SystemExit(7)")], finding=True)
        records = json.loads((self.evidence / "commands.json").read_text())["commands"]
        self.assertEqual(records[0]["exit_status"], 7)
        with patch.object(self.supervisor, "run", return_value=[""]):
            with self.assertRaises(runner.Incomplete):
                runner.simulation(self.supervisor, [7], 2, 2)

    def test_clean_source_required(self):
        with patch.object(
            self.supervisor, "run", return_value=["a" * 40, " M source", "rustc", "cargo"]
        ):
            with self.assertRaises(runner.Incomplete):
                runner.source_identity(self.supervisor)

    def test_failure_log_is_drained(self):
        source = (
            "import sys; sys.stdout.write('x' * 200000); sys.stdout.flush(); raise SystemExit(9)"
        )
        with self.assertRaises(runner.Finding):
            self.supervisor.run([self.command(source)], finding=True)
        self.assertEqual((self.evidence / "command-001.log").stat().st_size, 200000)

    def test_empty_commands_fail(self):
        with self.assertRaises(runner.Incomplete):
            self.supervisor.run([])

    def test_setup_failure_is_not_invariant_finding(self):
        with self.assertRaises(runner.Incomplete):
            self.supervisor.run([self.command("raise SystemExit(8)")])

    def test_bounded_log(self):
        with patch.object(runner, "LOG_LIMIT", 1024):
            with self.assertRaises(runner.Incomplete):
                self.supervisor.run([self.command("print('x' * 100000)")])
        self.assertEqual((self.evidence / "command-001.log").stat().st_size, 1024)

    def test_atomic_exclusion_and_release(self):
        with self.assertRaises(runner.Incomplete):
            runner.acquire_lock(self.state)
        os.close(self.lock)
        self.lock = runner.acquire_lock(self.state)

    def test_command_retains_lock_after_supervisor_fd_closes(self):
        process = subprocess.Popen(
            self.command("import time; time.sleep(30)"),
            pass_fds=(self.lock,),
            start_new_session=True,
        )
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)
        try:
            with self.assertRaises(runner.Incomplete):
                runner.acquire_lock(self.state)
        finally:
            runner.retire(process)
        os.close(self.lock)
        self.lock = runner.acquire_lock(self.state)

    def test_interrupted_run_blocks_lane(self):
        runner.atomic_json(
            self.evidence / "result.json", {"lane": "simulation", "status": "RUNNING"}
        )
        self.assertEqual(runner.unresolved(self.state, "simulation"), [self.evidence])
        self.assertEqual(runner.unresolved(self.state, "fuzz"), [])
        (self.evidence / "result.json").unlink()
        self.assertEqual(runner.unresolved(self.state, "fuzz"), [self.evidence])

    def test_unsafe_roots_and_storage(self):
        link = self.root / "link"
        link.symlink_to(self.scratch, target_is_directory=True)
        for path in (link, link / "nested", Path("relative")):
            with self.assertRaises((runner.Incomplete, OSError)):
                runner.private_root(str(path))
        self.scratch.chmod(0o755)
        with self.assertRaises(runner.Incomplete):
            runner.private_root(str(self.scratch))
        self.scratch.chmod(0o700)
        (self.state / "bad").symlink_to(self.scratch)
        with self.assertRaises(runner.Incomplete):
            runner.check_storage(self.state)
        (self.state / "bad").unlink()
        with patch.object(runner, "STATE_LIMIT", 1):
            with self.assertRaises(runner.Incomplete):
                runner.check_storage(self.state)

    def test_timeout_retires_descendant(self):
        marker = self.scratch / "escaped-write"
        self.supervisor.deadline = time.monotonic() + 0.2
        with self.assertRaises(runner.Incomplete):
            self.supervisor.run([self.fixture_command("spawn-delayed-writer", marker)])
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_success_also_retires_leftover_descendant(self):
        # The descendant inherits stdout: leader success, not pipe EOF, must trigger retirement.
        self.supervisor.deadline = time.monotonic() + 2
        self.assertEqual(
            self.supervisor.run([self.fixture_command("spawn-sleeping-descendant")]), [""]
        )

    def test_fifo_result_is_rejected_without_blocking(self):
        path = self.evidence / "result.json"
        os.mkfifo(path, mode=0o600)
        process = subprocess.Popen(self.fixture_command("reject-fifo", path))
        try:
            self.assertEqual(process.wait(timeout=2), 0)
        finally:
            process.kill()
            process.wait()
        with self.assertRaises(runner.Incomplete):
            runner.check_storage(self.state)

    def cancellation_phase(self, phase):
        process = subprocess.Popen(
            self.fixture_command("cancel-during-" + phase, self.evidence, self.scratch, self.lock),
            pass_fds=(self.lock,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            _, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error.decode())
        finally:
            process.kill()
            process.wait()
        records = json.loads((self.evidence / "commands.json").read_text())["commands"]
        children = [record for record in records if "exit_status" in record]
        self.assertEqual(len(children), 1 if phase == "spawn" else 2)
        self.assertTrue(all(record["exit_status"] == -signal.SIGKILL for record in children))

    def test_cancellation_between_spawn_and_registration(self):
        self.cancellation_phase("spawn")

    def test_cancellation_during_retirement_retires_all_groups(self):
        self.cancellation_phase("retirement")

    def finalization_cancellation(self, phase):
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)
        self.evidence.rmdir()
        process = subprocess.Popen(
            self.fixture_command("finalization", self.state, self.scratch, phase),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            _, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0 if phase == "terminal" else 130, error.decode())
        finally:
            process.kill()
            process.wait()
        result = json.loads(next(self.state.glob("run-*/result.json")).read_text())
        self.assertEqual(result["status"], "PASSED" if phase == "terminal" else "CANCELLED")
        self.assertEqual(Path(result["scratch"]).exists(), phase == "validate")

    def test_cancellation_during_final_scratch_validation(self):
        self.finalization_cancellation("validate")

    def test_cancellation_during_scratch_removal(self):
        self.finalization_cancellation("remove")

    def test_signal_after_terminal_decision_preserves_completed_result(self):
        self.finalization_cancellation("terminal")

    def test_missing_shard_completion_is_incomplete(self):
        executable = self.scratch / "fake-test"
        executable.write_text("#!/bin/sh\necho 'test result: ok. 0 passed; 0 failed'\n")
        executable.chmod(0o700)
        message = {
            "reason": "compiler-artifact",
            "executable": str(executable),
            "target": {"name": "kapsel"},
            "profile": {"test": True},
        }
        with patch.object(self.supervisor, "run", side_effect=[[json.dumps(message)], ["empty"]]):
            with self.assertRaises(runner.Incomplete):
                runner.simulation(self.supervisor, [1], 2, 1)

    def test_wrong_shard_count_prefix_is_rejected(self):
        executable = self.scratch / "test-binary"
        executable.write_text("fixture")
        message = {
            "reason": "compiler-artifact",
            "executable": str(executable),
            "target": {"name": "kapsel"},
            "profile": {"test": True},
        }
        output = "KAPSEL_SIMULATION_COMPLETED seed=1 shard=0/1 cases=20\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
        with patch.object(self.supervisor, "run", side_effect=[[json.dumps(message)], [output]]):
            with self.assertRaises(runner.Incomplete):
                runner.simulation(self.supervisor, [1], 2, 1)

    def fuzz_binary(self):
        executable = self.scratch / "fuzz-build/fixture-host/debug/inspect_receipt"
        executable.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        executable.write_bytes(b"built fuzz fixture")
        return executable

    def test_persistent_corpus_and_smoke_contract(self):
        self.fuzz_binary()
        for smoke, directory in ((False, self.state), (True, self.scratch)):
            evidence = self.state / ("smoke" if smoke else "explore")
            evidence.mkdir(mode=0o700)
            supervisor = runner.Supervisor(evidence, self.scratch, self.lock, 5)
            with patch.object(
                supervisor,
                "run",
                side_effect=[
                    ["host: fixture-host", "fuzz", "metadata"],
                    ["built"],
                    ["Done 10 runs in 0 second(s)"],
                ],
            ) as run:
                runner.fuzz(supervisor, self.state, 17, 1, smoke)
            command = run.call_args.args[0][0]
            self.assertIn("--fuzz-dir", run.call_args_list[1].args[0][0])
            self.assertEqual(command[0], str(self.fuzz_binary()))
            self.assertIn("-runs=10000" if smoke else "-runs=-1", command)
            self.assertIn("-seed=17", command)
            original = runner.corpus_identity(directory / "corpus")
            self.assertEqual(runner.corpus_identity(evidence / "corpus-before"), original)
            self.assertEqual(json.loads((evidence / "corpus-after.json").read_text()), original)

    def test_fuzz_setup_failure_is_not_finding(self):
        with patch.object(
            self.supervisor,
            "run",
            side_effect=[
                ["host: fixture-host", "fuzz", "metadata"],
                runner.Incomplete("command exited 1"),
            ],
        ):
            with self.assertRaises(runner.Incomplete):
                runner.fuzz(self.supervisor, self.state, 17, 1, False)
        self.assertTrue((self.evidence / "corpus-before").is_dir())

    def test_fuzz_signal_finding_retains_replay_artifact(self):
        executable = self.fuzz_binary()
        fixture = Path(__file__).with_name("robustness_process_fixture.py").resolve()
        executable.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(fixture))} "
            'fuzz-signal -- "$@"\n'
        )
        executable.chmod(0o700)
        actual = self.supervisor.run

        def commands(selected, environments=None, finding=False):
            if selected[0][0] == "rustup":
                return (
                    ["host: fixture-host", "fuzz", "metadata"] if len(selected) == 3 else ["built"]
                )
            return actual(selected, environments, finding)

        with patch.object(self.supervisor, "run", side_effect=commands):
            with self.assertRaises(runner.Finding):
                runner.fuzz(self.supervisor, self.state, 17, 1, False)
        self.assertEqual((self.evidence / "artifacts/crash-fixture").read_bytes(), b"replay")
        self.assertEqual(
            runner.corpus_identity(self.evidence / "corpus-before"),
            runner.corpus_identity(self.state / "corpus"),
        )

    def test_zero_fuzz_runs_are_incomplete(self):
        self.fuzz_binary()
        with patch.object(
            self.supervisor,
            "run",
            side_effect=[
                ["host: fixture-host", "fuzz", "metadata"],
                ["built"],
                ["Done 0 runs in 0 second(s)"],
            ],
        ):
            with self.assertRaises(runner.Incomplete):
                runner.fuzz(self.supervisor, self.state, 17, 1, False)

    def test_main_failure_retains_first_and_requires_triage(self):
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)
        self.evidence.rmdir()
        arguments = [
            "runner",
            "simulation",
            "--state",
            str(self.state),
            "--scratch",
            str(self.scratch),
        ]
        with patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()):
            with patch.object(
                runner,
                "source_identity",
                return_value={
                    "revision": "a" * 40,
                    "rustc": "fixture rustc",
                    "cargo": "fixture cargo",
                },
            ):
                with patch.object(runner, "simulation", side_effect=runner.Finding("fixture")):
                    self.assertEqual(runner.main(), 1)
                    with self.assertRaises(runner.Incomplete):
                        runner.main()
        runs = list(self.state.glob("run-*"))
        self.assertEqual(len(runs), 1)
        result = json.loads((runs[0] / "result.json").read_text())
        self.assertEqual(result["status"], "FINDING")
        self.assertTrue(Path(result["scratch"]).is_dir())
        triage = [
            "runner",
            "triage",
            "--state",
            str(self.state),
            "--run",
            runs[0].name,
            "--regression",
            "revision:test; passing command",
        ]
        with patch.object(sys, "argv", triage), patch.object(runner, "STATE_LIMIT", 1):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(runner.unresolved(self.state, "simulation"), [])
        self.assertTrue(Path(result["scratch"]).is_dir())

    def test_pass_cleanup_and_timeout_status(self):
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)
        self.evidence.rmdir()
        arguments = [
            "runner",
            "simulation",
            "--state",
            str(self.state),
            "--scratch",
            str(self.scratch),
        ]
        for error, expected_code, status in (
            (None, 0, "PASSED"),
            (runner.Incomplete("overall timeout"), 2, "INCOMPLETE"),
        ):
            with patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()):
                with patch.object(
                    runner,
                    "source_identity",
                    return_value={
                        "revision": "b" * 40,
                        "rustc": "fixture rustc",
                        "cargo": "fixture cargo",
                    },
                ):
                    with patch.object(runner, "simulation", side_effect=error):
                        self.assertEqual(runner.main(), expected_code)
            results = [
                json.loads(path.read_text()) for path in self.state.glob("run-*/result.json")
            ]
            result = next(result for result in results if result["status"] == status)
            self.assertEqual(Path(result["scratch"]).exists(), status != "PASSED")

    def test_cancelled_result_is_not_finding(self):
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)
        self.evidence.rmdir()
        arguments = [
            "runner",
            "simulation",
            "--state",
            str(self.state),
            "--scratch",
            str(self.scratch),
        ]
        with patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()):
            with patch.object(
                runner,
                "source_identity",
                return_value={
                    "revision": "c" * 40,
                    "rustc": "fixture rustc",
                    "cargo": "fixture cargo",
                },
            ):
                with patch.object(runner, "simulation", side_effect=runner.Cancelled("signal")):
                    self.assertEqual(runner.main(), 130)
        result = json.loads(next(self.state.glob("run-*/result.json")).read_text())
        self.assertEqual(result["status"], "CANCELLED")
        self.assertTrue(Path(result["scratch"]).exists())

    def test_signal_cancellation(self):
        evidence = self.root / "cancel-evidence"
        evidence.mkdir(mode=0o700)
        marker = self.root / "ready"
        process = subprocess.Popen(
            self.fixture_command(
                "collect-until-cancelled", evidence, self.scratch, self.lock, marker
            ),
            pass_fds=(self.lock,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGTERM)
            self.assertNotEqual(process.wait(timeout=5), 0)
            records = json.loads((evidence / "commands.json").read_text())["commands"]
            self.assertEqual(records[0]["exit_status"], -signal.SIGKILL)
        finally:
            process.kill()
            process.wait()


if __name__ == "__main__":
    unittest.main()
