#!/usr/bin/env python3
"""Runner protocol cases and compact real process/custody witnesses; no exploration."""

import errno
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import run_robustness as runner

PASSED_TEST = "test result: ok. 1 passed; 0 failed; 0 ignored;"


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state, self.scratch = self.root / "state", self.root / "scratch"
        self.evidence = self.state / "run-fixture"
        for path in (self.state, self.scratch, self.evidence):
            path.mkdir(mode=0o700)
        self.lock = runner.acquire_lock(self.state)
        self.supervisor = runner.Supervisor(self.evidence, self.scratch, self.lock, 5)

    def tearDown(self):
        os.close(self.lock)
        self.temporary.cleanup()

    def fixture_command(self, scenario, *arguments):
        return [
            sys.executable,
            str(Path(__file__).with_name("robustness_process_fixture.py")),
            scenario,
            *(str(argument) for argument in arguments),
        ]

    @contextmanager
    def process_fixture(self, scenario, *arguments):
        process = subprocess.Popen(
            self.fixture_command(scenario, *arguments),
            pass_fds=(self.lock,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            yield process
        finally:
            process.kill()
            process.wait(timeout=10)
            if process.stderr is not None:
                process.stderr.close()

    def release_lock(self):
        os.close(self.lock)
        self.lock = os.open(os.devnull, os.O_RDONLY)

    def test_retained_envelope_is_bounded_and_metadata_is_not_authority(self):
        path = self.evidence / "result.json"
        for record in (
            {},
            [],
            {"status": "SUCCESS", "lane": "simulation"},
            {"status": "PASSED", "lane": []},
        ):
            path.write_text(json.dumps(record))
            with self.assertRaises(runner.Incomplete):
                runner.read_result(path)
        record = {"status": "INCOMPLETE", "lane": "unclassified", "scratch": [], "revision": {}}
        runner.atomic_json(path, record)
        self.assertEqual(runner.read_result(path), record)
        self.assertEqual(runner.unresolved(self.state, "fuzz"), [self.evidence])
        runner.triage_run(self.state, self.evidence.name, "committed regression; passed")
        self.assertEqual(runner.read_result(path)["scratch"], [])
        path.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(runner.Incomplete):
            runner.read_result(path)

    def test_process_failure_drains_bounded_output_and_never_invents_a_finding(self):
        for size, limit, failure in (
            (200000, runner.LOG_LIMIT, runner.CommandFailed),
            (100000, 1024, runner.Incomplete),
        ):
            with self.subTest(size=size), patch.object(runner, "LOG_LIMIT", limit):
                source = (
                    f"import sys; sys.stdout.write('x' * {size}); sys.stdout.flush(); sys.exit(9)"
                )
                with self.assertRaises(failure) as caught:
                    self.supervisor.run([[sys.executable, "-c", source]])
                record = self.supervisor.commands[-1]
                self.assertEqual((self.evidence / record["log"]).stat().st_size, min(size, limit))
                if isinstance(caught.exception, runner.CommandFailed):
                    self.assertEqual(
                        (caught.exception.status, len(caught.exception.output)), (9, size)
                    )
                    self.assertEqual(record.get("exit_status"), 9)
        with self.assertRaises(runner.Incomplete):
            self.supervisor.run([])

    def test_eof_before_late_nonzero_exit_cannot_pass(self):
        read, write = os.pipe()
        os.close(write)
        output = os.fdopen(read, "rb")
        child = Mock(pid=47, stdout=output, returncode=None)
        polls = iter((None, 7))

        def poll():
            child.returncode = next(polls)
            return child.returncode

        child.poll.side_effect = poll
        child.wait.return_value = 7
        with (
            patch.object(runner.subprocess, "Popen", return_value=child),
            patch.object(runner, "retire_all"),
        ):
            with self.assertRaises(runner.CommandFailed) as caught:
                self.supervisor.run([["late-failure"]])
        self.assertEqual(caught.exception.status, 7)
        self.assertEqual(self.supervisor.commands[0].get("exit_status"), 7)

    def test_clean_source_required(self):
        with patch.object(
            self.supervisor, "run", return_value=["a" * 40, " M source", "rustc", "cargo"]
        ):
            with self.assertRaises(runner.Incomplete):
                runner.source_identity(self.supervisor)

    def test_lock_excludes_peers_and_survives_supervisor_descriptor_closure(self):
        with self.assertRaises(runner.Incomplete):
            runner.acquire_lock(self.state)
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            pass_fds=(self.lock,),
            start_new_session=True,
        )
        self.release_lock()
        try:
            with self.assertRaises(runner.Incomplete):
                runner.acquire_lock(self.state)
        finally:
            runner.retire(process)
        os.close(self.lock)
        self.lock = runner.acquire_lock(self.state)

    def test_interrupted_run_blocks_only_its_lane_or_both_if_unclassified(self):
        runner.atomic_json(
            self.evidence / "result.json", {"lane": "simulation", "status": "RUNNING"}
        )
        self.assertEqual(runner.unresolved(self.state, "simulation"), [self.evidence])
        self.assertEqual(runner.unresolved(self.state, "fuzz"), [])
        (self.evidence / "result.json").unlink()
        self.assertEqual(runner.unresolved(self.state, "fuzz"), [self.evidence])

    def test_roots_and_storage_refuse_unsafe_entries_and_budget_exhaustion(self):
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

    def test_timeout_and_success_both_retire_descendants(self):
        marker = self.scratch / "escaped-write"
        self.supervisor.deadline = time.monotonic() + 0.2
        with self.assertRaises(runner.Incomplete):
            self.supervisor.run([self.fixture_command("spawn-delayed-writer", marker)])
        time.sleep(1.2)
        self.assertFalse(marker.exists())
        self.supervisor.deadline = time.monotonic() + 2
        self.assertEqual(
            self.supervisor.run([self.fixture_command("spawn-sleeping-descendant")]), [""]
        )

    def test_first_failed_peer_stops_groups_without_retiring_a_successful_group_twice(self):
        marker = self.scratch / "successful-group-retired"
        actual_killpg, actual_retire = os.killpg, runner.retire
        retired_groups = set()

        def killpg_once(pid, signum):
            if pid in retired_groups:
                raise PermissionError(errno.EPERM, "process group already retired")
            retired_groups.add(pid)
            actual_killpg(pid, signum)

        def retire_success(process):
            actual_retire(process)
            marker.touch()

        with (
            patch.object(runner.os, "killpg", side_effect=killpg_once),
            patch.object(runner, "retire", side_effect=retire_success),
        ):
            with self.assertRaises(runner.CommandFailed) as caught:
                self.supervisor.run(
                    [
                        [sys.executable, "-c", "pass"],
                        self.fixture_command("fail-after-marker", marker),
                    ]
                )
        self.assertEqual(caught.exception.status, 7)
        self.assertIn("peer failure after successful retirement", caught.exception.output)
        self.assertEqual(len(retired_groups), 2)
        self.assertEqual([record.get("exit_status") for record in self.supervisor.commands], [0, 7])

    def test_fifo_result_is_rejected_without_blocking(self):
        path = self.evidence / "result.json"
        os.mkfifo(path, mode=0o600)
        with self.process_fixture("reject-fifo", path) as process:
            self.assertEqual(process.wait(timeout=2), 0)
        with self.assertRaises(runner.Incomplete):
            runner.check_storage(self.state)

    def test_cancellation_registers_then_retires_every_spawned_group(self):
        for phase, count in (("spawn", 1), ("retirement", 2)):
            evidence = self.state / ("run-" + phase)
            evidence.mkdir(mode=0o700)
            with (
                self.subTest(phase=phase),
                self.process_fixture(
                    "cancel-during-" + phase, evidence, self.scratch, self.lock
                ) as process,
            ):
                _, error = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, error.decode())
            records = json.loads((evidence / "commands.json").read_bytes())["commands"]
            children = [record for record in records if "exit_status" in record]
            self.assertEqual(len(children), count)
            self.assertTrue(all(record["exit_status"] == -signal.SIGKILL for record in children))

    def test_cancellation_before_terminal_decision_and_late_signal_are_distinct(self):
        self.release_lock()
        for phase in ("validate", "remove", "terminal"):
            state = self.root / phase
            state.mkdir(mode=0o700)
            with (
                self.subTest(phase=phase),
                self.process_fixture("finalization", state, self.scratch, phase) as process,
            ):
                _, error = process.communicate(timeout=10)
                self.assertEqual(
                    process.returncode, 0 if phase == "terminal" else 130, error.decode()
                )
            result = json.loads(next(state.glob("run-*/result.json")).read_bytes())
            self.assertEqual(result["status"], "PASSED" if phase == "terminal" else "CANCELLED")
            self.assertEqual(Path(result["scratch"]).exists(), phase == "validate")

    def test_external_sigterm_retires_the_owned_command(self):
        marker = self.root / "ready"
        with self.process_fixture(
            "collect-until-cancelled", self.evidence, self.scratch, self.lock, marker
        ) as process:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGTERM)
            self.assertNotEqual(process.wait(timeout=5), 0)
            records = json.loads((self.evidence / "commands.json").read_bytes())["commands"]
            self.assertEqual(records[0]["exit_status"], -signal.SIGKILL)

    def test_build_protocol_selects_one_regular_owned_test_binary(self):
        root = self.scratch / "simulation-build"
        root.mkdir(mode=0o700)
        executable = root / "test-binary"
        executable.write_bytes(b"compiled fixture")
        artifact = {
            "reason": "compiler-artifact",
            "executable": str(executable),
            "target": {"name": "kapsel"},
            "profile": {"test": True},
        }
        valid = json.dumps(artifact)
        self.assertEqual(runner.simulation_executable("diagnostic\n[]\n" + valid, root), executable)
        for output in (
            "",
            valid + "\n" + valid,
            json.dumps({**artifact, "profile": {"test": "yes"}}),
            json.dumps({**artifact, "executable": str(self.root / "outside")}),
        ):
            with self.subTest(output=output), self.assertRaises(runner.Incomplete):
                runner.simulation_executable(output, root)
        executable.unlink()
        executable.symlink_to(self.root / "outside")
        with self.assertRaises(runner.Incomplete):
            runner.simulation_executable(valid, root)

    def test_completion_protocol_requires_exact_shard_or_replay_marker_and_one_test(self):
        for marker in (
            "KAPSEL_KERNEL_COMPLETED seed=7 shard=0/1 cases=2 steps=48",
            "KAPSEL_KERNEL_REPLAYED cases=2",
        ):
            runner.require_test_completion(marker + "\n" + PASSED_TEST, marker)
            for output in (
                "",
                PASSED_TEST,
                marker,
                marker + "0\n" + PASSED_TEST,
                marker + "\n" + marker + "\n" + PASSED_TEST,
                marker + "\ntest result: ok. 0 passed; 0 failed; 0 ignored;",
            ):
                with self.subTest(output=output), self.assertRaises(runner.Incomplete):
                    runner.require_test_completion(output, marker)

    def test_trace_custody_checks_names_identity_bounds_and_exact_bytes_not_actions(self):
        traces = self.evidence / "traces-7-0"
        traces.mkdir(mode=0o700)
        path = traces / "case-0.json"
        header = {"seed": 7, "executable_sha256": "a" * 64, "source_sha256": "b" * 64}
        for wrong in ({"seed": 8}, {"executable_sha256": "c" * 64}, {"source_sha256": "bad"}):
            runner.atomic_json(path, {**header, **wrong})
            with self.subTest(wrong=wrong), self.assertRaises(runner.Incomplete):
                runner.retained_exploration(traces, 7, 1, 1, 0, "a" * 64)
        runner.atomic_json(path, header)
        runner.retained_exploration(traces, 7, 1, 1, 0, "a" * 64)
        self.assertEqual(
            json.loads((self.evidence / "traces-7-0.json").read_bytes()),
            {path.name: hashlib.sha256(path.read_bytes()).hexdigest()},
        )
        path.unlink()
        with self.assertRaises(runner.Incomplete):
            runner.retained_exploration(traces, 7, 1, 1, 0, "a" * 64)

    def test_simulation_controller_retains_source_and_binary_then_replays_every_shard(self):
        replayed = []
        compiled = self.scratch / "simulation-build/test-binary"
        compiled.parent.mkdir(mode=0o700)
        compiled.write_bytes(b"compiled fixture")
        digest = hashlib.sha256(compiled.read_bytes()).hexdigest()

        def commands(selected, environments=None):
            if selected[0][0] == "git":
                Path(selected[0][selected[0].index("--output") + 1]).write_bytes(b"source archive")
                return [""]
            if selected[0][0] == "cargo":
                self.assertEqual(
                    selected[0][selected[0].index("--target-dir") + 1], str(compiled.parent)
                )
                return [
                    json.dumps(
                        {
                            "reason": "compiler-artifact",
                            "executable": str(compiled),
                            "target": {"name": "kapsel"},
                            "profile": {"test": True},
                        }
                    )
                ]
            outputs = []
            assert environments is not None
            for command, environment in zip(selected, environments, strict=True):
                self.assertEqual(
                    command,
                    [
                        str(self.evidence / "simulation-tests"),
                        runner.KERNEL_TEST,
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                )
                if "KAPSEL_KERNEL_REPLAY_DIRECTORY" in environment:
                    directory = Path(environment["KAPSEL_KERNEL_REPLAY_DIRECTORY"])
                    replayed.append(directory.name)
                    marker = f"KAPSEL_KERNEL_REPLAYED cases={len(list(directory.iterdir()))}"
                else:
                    directory = Path(environment["KAPSEL_KERNEL_EVIDENCE"])
                    index = int(environment["KAPSEL_KERNEL_SHARD_INDEX"])
                    for case in range(index, 3, 2):
                        runner.atomic_json(
                            directory / f"case-{case}.json",
                            {
                                "seed": 7 + case,
                                "executable_sha256": digest,
                                "source_sha256": "a" * 64,
                            },
                        )
                    marker = f"KAPSEL_KERNEL_COMPLETED seed=7 shard={index}/2 cases={len(range(index, 3, 2))} steps=48"
                outputs.append(marker + "\n" + PASSED_TEST)
            return outputs

        with (
            patch.dict(os.environ, {"CARGO_TARGET_DIR": str(runner.ROOT / "target")}),
            patch.object(self.supervisor, "run", side_effect=commands),
        ):
            runner.simulation(self.supervisor, [7], 3, 2, "a" * 40)
        self.assertEqual(replayed, ["traces-7-0", "traces-7-1"])
        manifest = json.loads((self.evidence / "exploration.json").read_bytes())
        self.assertEqual(
            manifest["source_archive"]["sha256"], hashlib.sha256(b"source archive").hexdigest()
        )
        self.assertEqual((self.evidence / "simulation-tests").read_bytes(), compiled.read_bytes())
        self.assertEqual(manifest["sha256"], digest)

    def test_command_and_fuzz_outcome_protocols_distinguish_completion_setup_and_findings(self):
        for status, output, failure in (
            (0, "Done 10 runs in 0 second(s)", None),
            (0, "", runner.Incomplete),
            (0, "Done 0 runs in 0 second(s)", runner.Incomplete),
            (0, "Done 1 runs in 0\nDone 2 runs in 0", runner.Incomplete),
            (1, "build error", runner.Incomplete),
            (-9, "", runner.Incomplete),
            (1, "panicked at fixture", runner.Finding),
            (-9, "ERROR: libFuzzer: deadly signal", runner.Finding),
            (1, "ERROR: AddressSanitizer: fixture", runner.Finding),
        ):
            with self.subTest(status=status, output=output):
                if failure is None:
                    runner.fuzz_completion(status, output)
                else:
                    with self.assertRaises(failure):
                        runner.fuzz_completion(status, output)
        for status, failure in ((1, runner.Finding), (-9, runner.Incomplete)):
            with patch.object(
                self.supervisor, "run", side_effect=runner.CommandFailed(status, "log")
            ):
                with self.assertRaises(failure):
                    runner.simulation_commands(self.supervisor, [["test"]], [{}])
        for target, maximum in runner.FUZZ_TARGETS.items():
            command = runner.fuzz_command(
                Path("binary"), Path("corpus"), Path("artifacts"), 17, 1, "10000", target
            )
            self.assertIn(f"-max_len={maximum}", command)
            self.assertIn("-timeout=10", command)
            self.assertIn("-rss_limit_mb=2048", command)

    def test_fuzz_controller_preserves_discoveries_and_selects_smoke_or_persistent_corpus(self):
        for smoke, target, setup_failure in (
            (False, "inspect_receipt", False),
            (True, "service_document", False),
            (False, "verify_git_grant", True),
        ):
            evidence = self.state / target
            evidence.mkdir(mode=0o700)
            supervisor = runner.Supervisor(evidence, self.scratch, self.lock, 5)
            name = "corpus" if target == "inspect_receipt" else "corpus-" + target
            corpus = (self.scratch if smoke else self.state) / name
            corpus.mkdir(mode=0o700)
            discovery = corpus / "retained-discovery"
            discovery.write_bytes(b"original discovery")
            calls = []

            def commands(
                selected,
                environments=None,
                *,
                target=target,
                setup_failure=setup_failure,
                calls=calls,
            ):
                calls.append(selected)
                if len(selected) == 3:
                    self.assertIn("--locked", selected[2])
                    return ["host: fixture-host", "cargo-fuzz fixture", "locked graph"]
                if selected[0][0] == "rustup":
                    if setup_failure:
                        raise runner.CommandFailed(1, "panicked at setup, not fuzz execution")
                    binary = self.scratch / "fuzz-build/fixture-host/debug" / target
                    binary.parent.mkdir(parents=True, exist_ok=True)
                    binary.write_bytes(b"built fixture")
                    return [""]
                return ["Done 10 runs in 0 second(s)"]

            with patch.object(supervisor, "run", side_effect=commands):
                if setup_failure:
                    with self.assertRaises(runner.CommandFailed):
                        runner.fuzz(supervisor, self.state, 17, 1, smoke, target)
                else:
                    runner.fuzz(supervisor, self.state, 17, 1, smoke, target)
                    command = calls[-1][0]
                    self.assertEqual(command[1], str(corpus))
                    self.assertIn("-runs=10000" if smoke else "-runs=-1", command)
                    self.assertIn("-seed=17", command)
                    self.assertEqual(
                        json.loads((evidence / "corpus-after.json").read_bytes()),
                        runner.corpus_identity(corpus),
                    )
            self.assertEqual(discovery.read_bytes(), b"original discovery")
            self.assertEqual(
                (evidence / "corpus-before" / discovery.name).read_bytes(), b"original discovery"
            )
            for digest in runner.corpus_identity(runner.ROOT / "fuzz/corpus" / target).values():
                self.assertIn(digest, runner.corpus_identity(corpus).values())
        with self.assertRaises(runner.Incomplete):
            runner.fuzz(self.supervisor, self.state, 17, 1, False, "../escape")

    def test_real_fuzz_signal_retains_diagnostic_and_replay_artifact(self):
        artifacts = self.evidence / "artifacts"
        artifacts.mkdir(mode=0o700)
        with self.assertRaises(runner.CommandFailed) as caught:
            self.supervisor.run(
                [self.fixture_command("fuzz-signal", "--", f"-artifact_prefix={artifacts}/")]
            )
        with self.assertRaises(runner.Finding):
            runner.fuzz_completion(caught.exception.status, caught.exception.output)
        self.assertEqual((artifacts / "crash-fixture").read_bytes(), b"replay")

    def test_terminal_outcomes_preserve_evidence_and_block_until_explicit_triage(self):
        self.release_lock()
        for failure, code, status in (
            (None, 0, "PASSED"),
            (runner.Finding("law"), 1, "FINDING"),
            (runner.Incomplete("timeout"), 2, "INCOMPLETE"),
            (runner.Cancelled("signal"), 130, "CANCELLED"),
        ):
            state = self.root / status
            state.mkdir(mode=0o700)
            arguments = [
                "runner",
                "simulation",
                "--state",
                str(state),
                "--scratch",
                str(self.scratch),
                "--seed",
                "7",
            ]
            with (
                self.subTest(status=status),
                patch.object(sys, "argv", arguments),
                redirect_stdout(io.StringIO()),
                patch.object(
                    runner,
                    "source_identity",
                    return_value={"revision": "a" * 40, "rustc": "fixture", "cargo": "fixture"},
                ),
                patch.object(runner, "simulation", side_effect=failure),
            ):
                self.assertEqual(runner.main(), code)
                result_path = next(state.glob("run-*/result.json"))
                result = json.loads(result_path.read_bytes())
                self.assertEqual(result["status"], status)
                self.assertEqual(Path(result["scratch"]).exists(), failure is not None)
                if failure is not None:
                    with self.assertRaises(runner.Incomplete):
                        runner.main()
                    self.assertEqual(len(list(state.glob("run-*"))), 1)
                    triage = [
                        "runner",
                        "triage",
                        "--state",
                        str(state),
                        "--run",
                        result_path.parent.name,
                        "--regression",
                        "committed regression; passed",
                    ]
                    with patch.object(sys, "argv", triage), patch.object(runner, "STATE_LIMIT", 1):
                        self.assertEqual(runner.main(), 0)
                    self.assertEqual(runner.unresolved(state, "simulation"), [])
                    self.assertTrue(Path(result["scratch"]).is_dir())


if __name__ == "__main__":
    unittest.main()
