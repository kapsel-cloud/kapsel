#!/usr/bin/env python3
"""Job protocol regressions and real owned-process witnesses; no exploration."""

import argparse
import errno
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
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
        self.evidence = self.root / "job"
        self.evidence.mkdir(mode=0o700)
        self.job = runner.Job(self.evidence, 10)

    def tearDown(self):
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
                    self.job.run([[sys.executable, "-c", source]])
                record = self.job.commands[-1]
                self.assertEqual((self.evidence / record["log"]).stat().st_size, min(size, limit))
                if isinstance(caught.exception, runner.CommandFailed):
                    self.assertEqual(
                        (caught.exception.status, len(caught.exception.output)), (9, size)
                    )
                    self.assertEqual(record.get("exit_status"), 9)
        with self.assertRaises(runner.Incomplete):
            self.job.run([])

    def test_command_records_build_environment_without_inheriting_ambient_replay(self):
        with patch.dict(
            os.environ,
            {
                "CARGO_TARGET_DIR": str(self.root / "build"),
                "KAPSEL_KERNEL_REPLAY": "/not/the/selected/input",
            },
        ):
            output = self.job.run(
                [
                    [
                        sys.executable,
                        "-c",
                        "import os; print(os.environ.get('KAPSEL_KERNEL_REPLAY', 'unset'))",
                    ]
                ]
            )
        self.assertEqual(output, ["unset\n"])
        self.assertEqual(
            self.job.commands[0]["environment"]["CARGO_TARGET_DIR"], str(self.root / "build")
        )

    def test_eof_before_late_nonzero_exit_cannot_pass(self):
        read, write = os.pipe()
        os.close(write)
        child = Mock(pid=47, stdout=os.fdopen(read, "rb"), returncode=None)
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
                self.job.run([["late-failure"]])
        self.assertEqual(caught.exception.status, 7)

    def test_timeout_and_success_both_retire_descendants(self):
        marker = self.root / "escaped-write"
        self.job.deadline = time.monotonic() + 0.2
        with self.assertRaises(runner.Incomplete):
            self.job.run([self.fixture_command("spawn-delayed-writer", marker)])
        time.sleep(1.2)
        self.assertFalse(marker.exists())
        self.job.deadline = time.monotonic() + 2
        self.assertEqual(self.job.run([self.fixture_command("spawn-sleeping-descendant")]), [""])

    def test_first_failed_peer_retires_successful_groups_only_once(self):
        marker = self.root / "successful-group-retired"
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
                self.job.run(
                    [
                        [sys.executable, "-c", "pass"],
                        self.fixture_command("fail-after-marker", marker),
                    ]
                )
        self.assertEqual(caught.exception.status, 7)
        self.assertIn("peer failure after successful retirement", caught.exception.output)
        self.assertEqual(len(retired_groups), 2)
        self.assertEqual([record.get("exit_status") for record in self.job.commands], [0, 7])

    def test_fifo_symlink_and_oversize_inputs_are_refused(self):
        path = self.root / "input"
        os.mkfifo(path, mode=0o600)
        with self.process_fixture("reject-fifo", path) as process:
            self.assertEqual(process.wait(timeout=2), 0)
        path.unlink()
        path.symlink_to(self.root / "absent")
        with self.assertRaises(OSError):
            runner.bounded_bytes(path, 10)
        path.unlink()
        path.write_bytes(b"x" * 11)
        with self.assertRaises(runner.Incomplete):
            runner.bounded_bytes(path, 10)

    def test_cancellation_registers_then_retires_every_spawned_group(self):
        for phase, count in (("spawn", 1), ("retirement", 2)):
            evidence = self.root / phase
            evidence.mkdir(mode=0o700)
            with (
                self.subTest(phase=phase),
                self.process_fixture("cancellation", evidence, phase) as process,
            ):
                _, error = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, error.decode())
            records = runner.read_json(evidence / "commands.json")["commands"]
            children = [record for record in records if "exit_status" in record]
            self.assertEqual(len(children), count)
            self.assertTrue(all(record["exit_status"] == -signal.SIGKILL for record in children))

    def test_cancellation_before_terminal_decision_and_late_signal_are_distinct(self):
        for phase in ("execution", "terminal"):
            output = self.root / phase
            with self.process_fixture("finalization", output, phase) as process:
                _, error = process.communicate(timeout=10)
                self.assertEqual(
                    process.returncode, 0 if phase == "terminal" else 130, error.decode()
                )
            self.assertEqual(
                runner.read_json(output / "result.json")["status"],
                "PASSED" if phase == "terminal" else "CANCELLED",
            )

    def test_external_sigterm_retires_the_owned_command(self):
        marker = self.root / "ready"
        output = self.root / "external"
        output.mkdir(mode=0o700)
        with self.process_fixture("collect-until-cancelled", output, marker) as process:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGTERM)
            self.assertNotEqual(process.wait(timeout=5), 0)
        records = runner.read_json(output / "commands.json")["commands"]
        self.assertEqual(records[0]["exit_status"], -signal.SIGKILL)

    def test_dirty_source_snapshot_includes_untracked_bytes_and_excludes_deleted_inputs(self):
        source = self.root / "source"
        source.mkdir()
        (source / "tracked").write_bytes(b"original")
        with patch.object(runner, "ROOT", source):
            self.job.run([["git", "init", "--quiet"]])
            self.job.run([["git", "add", "tracked"]])
            (source / "tracked").unlink()
            (source / "research").write_bytes(b"dirty research")
            digest = runner.source_snapshot(self.job, retain=True)
            expected = hashlib.sha256(
                (8).to_bytes(8, "little")
                + b"research"
                + (14).to_bytes(8, "little")
                + b"dirty research"
            ).hexdigest()
            self.assertEqual(digest, expected)
            with tarfile.open(self.evidence / "source.tar") as archive:
                self.assertEqual(archive.getnames(), ["research"])
                retained = archive.extractfile("research")
                assert retained is not None
                self.assertEqual(retained.read(), b"dirty research")
            (source / "research").write_bytes(b"changed")
            self.assertNotEqual(runner.source_snapshot(self.job, retain=False), digest)

    def test_build_and_completion_protocols_require_one_selected_test_and_exact_count(self):
        artifact = {
            "reason": "compiler-artifact",
            "executable": str(self.root / "binary"),
            "target": {"name": "kapsel"},
            "profile": {"test": True},
        }
        valid = json.dumps(artifact)
        self.assertEqual(
            runner.simulation_executable("diagnostic\n[]\n" + valid), self.root / "binary"
        )
        for output in (
            "",
            valid + "\n" + valid,
            json.dumps({**artifact, "profile": {"test": "yes"}}),
        ):
            with self.assertRaises(runner.Incomplete):
                runner.simulation_executable(output)
        marker = "KAPSEL_KERNEL_COMPLETED seed=7 shard=0/1 cases=2 steps=48"
        runner.require_test_completion(marker + "\n" + PASSED_TEST, marker)
        for output in (
            "",
            PASSED_TEST,
            marker,
            marker + "0\n" + PASSED_TEST,
            marker + "\n" + marker + "\n" + PASSED_TEST,
            marker + "\ntest result: ok. 0 passed; 0 failed; 0 ignored;",
        ):
            with self.assertRaises(runner.Incomplete):
                runner.require_test_completion(output, marker)

    def test_trace_accounting_binds_source_binary_seed_and_exact_bytes(self):
        traces = self.evidence / "traces-7-0"
        traces.mkdir(mode=0o700)
        path = traces / "case-0.json"
        header = {"seed": 7, "executable_sha256": "a" * 64, "source_sha256": "b" * 64}
        for wrong in ({"seed": 8}, {"executable_sha256": "c" * 64}, {"source_sha256": "c" * 64}):
            runner.atomic_json(path, {**header, **wrong})
            with self.assertRaises(runner.Incomplete):
                runner.retained_traces(traces, 7, 1, 1, 0, "a" * 64, "b" * 64)
        runner.atomic_json(path, header)
        runner.retained_traces(traces, 7, 1, 1, 0, "a" * 64, "b" * 64)
        self.assertEqual(
            runner.read_json(traces.with_suffix(".json")),
            {path.name: hashlib.sha256(path.read_bytes()).hexdigest()},
        )
        path.unlink()
        with self.assertRaises(runner.Incomplete):
            runner.retained_traces(traces, 7, 1, 1, 0, "a" * 64, "b" * 64)

    def test_simulation_reuses_build_output_and_does_not_replay_passing_cases(self):
        compiled = self.root / "binary"
        compiled.write_bytes(b"compiled fixture")
        digest = hashlib.sha256(compiled.read_bytes()).hexdigest()
        calls = []

        def commands(selected, environments=None):
            calls.append(selected)
            if selected[0][0] == "cargo":
                self.assertNotIn("--target-dir", selected[0])
                self.assertNotIn("--release", selected[0])
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
            assert environments is not None
            outputs = []
            for environment in environments:
                self.assertNotIn("KAPSEL_KERNEL_REPLAY_DIRECTORY", environment)
                directory = Path(environment["KAPSEL_KERNEL_EVIDENCE"])
                index = int(environment["KAPSEL_KERNEL_SHARD_INDEX"])
                for case in range(index, 3, 2):
                    runner.atomic_json(
                        directory / f"case-{case}.json",
                        {"seed": 7 + case, "executable_sha256": digest, "source_sha256": "a" * 64},
                    )
                outputs.append(
                    f"KAPSEL_KERNEL_COMPLETED seed=7 shard={index}/2 cases={len(range(index, 3, 2))} steps=8\n"
                    + PASSED_TEST
                )
            return outputs

        args = argparse.Namespace(
            executable=None, replay=None, seed=[7], cases=3, shards=2, steps=8
        )
        with patch.object(self.job, "run", side_effect=commands):
            runner.simulation(self.job, args, "a" * 64)
        self.assertEqual(len(calls), 2)
        self.assertEqual((self.evidence / "executable").read_bytes(), compiled.read_bytes())
        self.assertTrue(
            runner.read_json(self.evidence / "simulation.json")["cargo_build_requested"]
        )

    def test_simulation_panics_without_reached_law_evidence_are_incomplete(self):
        for error in (
            runner.CommandFailed(101, "panicked at setup"),
            runner.CommandFailed(-9, 'KAPSEL_KERNEL_FINDING {"law":"x"}'),
        ):
            with self.assertRaises(runner.Incomplete):
                runner.finding_marker(error)
        finding = {"law": "dispatch_provenance", "event": 3, "defect_reached": ["Remint"]}
        self.assertEqual(
            runner.finding_marker(
                runner.CommandFailed(101, "KAPSEL_KERNEL_FINDING " + json.dumps(finding))
            ),
            finding,
        )

    def test_original_replay_rejects_wrong_binary_but_candidate_comparison_is_explicit(self):
        binary = self.root / "original"
        binary.write_bytes(b"binary")
        trace = self.root / "trace.json"
        runner.atomic_json(trace, {"executable_sha256": "0" * 64})
        args = argparse.Namespace(executable=binary, replay=trace)
        with patch.object(runner, "replay_trace") as replay:
            with self.assertRaisesRegex(runner.Incomplete, "does not match"):
                runner.simulation(self.job, args, "a" * 64)
            replay.assert_not_called()
        self.assertFalse(
            runner.read_json(self.evidence / "simulation.json")["cargo_build_requested"]
        )

    def test_corpus_empty_files_are_bounded_and_check_deadlines(self):
        corpus = self.root / "corpus"
        corpus.mkdir()
        for index in range(3):
            (corpus / str(index)).touch()
        # Python 3.11's Path.iterdir materializes os.listdir before the first budget check.
        with patch.object(Path, "iterdir", side_effect=AssertionError("eager enumeration")):
            self.assertEqual(len(runner.corpus_identity(corpus, self.job)), 3)
            with patch.object(runner, "CORPUS_FILES", 2):
                with self.assertRaisesRegex(runner.Incomplete, "entry limit"):
                    runner.corpus_identity(corpus, self.job)
        self.job.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(runner.Incomplete, "timeout"):
            runner.corpus_identity(corpus, self.job)

    def test_fuzz_protocol_requires_exact_runs_and_retained_crash_input(self):
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        for status, output in (
            (0, ""),
            (0, "Done 9 runs in 0 second(s)"),
            (0, "Done 11 runs in 0 second(s)"),
            (1, "build error"),
            (-9, ""),
            (1, "panicked at fixture"),
        ):
            with self.assertRaises(runner.Incomplete):
                runner.fuzz_completion(status, output, 10, artifacts)
        runner.fuzz_completion(0, "Done 10 runs in 0 second(s)", 10, artifacts)
        with self.assertRaises(runner.CommandFailed) as caught:
            self.job.run([self.fixture_command("fuzz-signal", artifacts)])
        with self.assertRaises(runner.Finding):
            runner.fuzz_completion(caught.exception.status, caught.exception.output, 10, artifacts)
        self.assertEqual((artifacts / "crash-fixture").read_bytes(), b"replay")
        for diagnostic in ("timeout after 10 seconds", "out-of-memory", "file size exceeded"):
            with self.assertRaisesRegex(runner.Incomplete, "resource limit"):
                runner.fuzz_completion(70, "ERROR: libFuzzer: " + diagnostic, 10, artifacts)

    def test_all_fuzz_targets_keep_input_snapshots_and_separate_discoveries(self):
        for target in runner.FUZZ_TARGETS:
            evidence = self.root / target
            evidence.mkdir()
            job = runner.Job(evidence, 5)
            corpus = self.root / ("input-" + target)
            corpus.mkdir()
            (corpus / "prior-discovery").write_bytes(b"old input")
            build = self.root / "build"
            calls = []

            def commands(
                selected,
                environments=None,
                *,
                calls=calls,
                build=build,
                target=target,
                evidence=evidence,
            ):
                calls.append(selected)
                if len(selected) == 3:
                    return [
                        "host: fixture-host",
                        "cargo-fuzz fixture",
                        json.dumps({"target_directory": str(build)}),
                    ]
                if selected[0][0] == "rustup":
                    binary = build / "fixture-host/debug" / target
                    binary.parent.mkdir(parents=True, exist_ok=True)
                    binary.write_bytes(b"built fixture")
                    return [""]
                command = selected[0]
                self.assertEqual(Path(command[1]), evidence / "discoveries" / target)
                self.assertEqual(Path(command[2]), evidence / "corpus-before")
                self.assertIn(f"-max_len={runner.FUZZ_TARGETS[target]}", command)
                (Path(command[1]) / "new-discovery").write_bytes(b"new input")
                return ["Done 10 runs in 0 second(s)"]

            args = argparse.Namespace(corpus=[corpus], seed=[17], runs=10, fuzz_target=target)
            with patch.object(job, "run", side_effect=commands):
                runner.fuzz(job, args, "a" * 64)
            self.assertEqual(
                (evidence / "corpus-before/0-prior-discovery").read_bytes(), b"old input"
            )
            self.assertEqual(list(corpus.iterdir()), [corpus / "prior-discovery"])
            self.assertEqual((evidence / "executable").read_bytes(), b"built fixture")
            self.assertEqual(
                runner.read_json(evidence / "discoveries.json"),
                {"new-discovery": hashlib.sha256(b"new input").hexdigest()},
            )

    def test_independent_jobs_preserve_old_evidence_and_never_require_triage(self):
        for failure, code, status in (
            (None, 0, "PASSED"),
            (runner.Finding("law"), 1, "FINDING"),
            (runner.Incomplete("timeout"), 2, "INCOMPLETE"),
            (runner.Cancelled("signal"), 130, "CANCELLED"),
        ):
            for repeat in range(2):
                output = self.root / f"{status}-{repeat}"
                with (
                    patch.object(
                        sys,
                        "argv",
                        ["runner", "simulation", "--output", str(output), "--seed", "7"],
                    ),
                    redirect_stdout(io.StringIO()),
                    patch.object(runner.Job, "run", return_value=["revision", "rustc", "cargo"]),
                    patch.object(runner, "source_snapshot", return_value="a" * 64),
                    patch.object(runner, "bounded_bytes", return_value=b"archive"),
                    patch.object(runner, "simulation", side_effect=failure),
                    patch.object(runner, "seal_evidence"),
                ):
                    self.assertEqual(runner.main(), code)
                    result = (output / "result.json").read_bytes()
                    self.assertEqual(json.loads(result)["status"], status)
                    with self.assertRaises(FileExistsError):
                        runner.main()
                    self.assertEqual((output / "result.json").read_bytes(), result)

    def test_failed_terminal_publication_never_leaves_a_pass(self):
        output = self.root / "terminal-failure"
        publish = runner.atomic_json

        def fail_terminal(path, value):
            if path.name == "result.json" and value.get("status") == "PASSED":
                raise OSError("disk full")
            publish(path, value)

        with (
            patch.object(
                sys, "argv", ["runner", "simulation", "--output", str(output), "--seed", "7"]
            ),
            redirect_stdout(io.StringIO()),
            patch.object(runner.Job, "run", return_value=["revision", "rustc", "cargo"]),
            patch.object(runner, "source_snapshot", return_value="a" * 64),
            patch.object(runner, "bounded_bytes", return_value=b"archive"),
            patch.object(runner, "simulation"),
            patch.object(runner, "seal_evidence"),
            patch.object(runner, "atomic_json", side_effect=fail_terminal),
        ):
            with self.assertRaises(OSError):
                runner.main()
        self.assertEqual(runner.read_json(output / "result.json")["status"], "RUNNING")

    def test_sealing_requires_unchanged_source_and_executable(self):
        (self.evidence / "source.tar").write_bytes(b"source")
        runner.atomic_json(
            self.evidence / "source.json", {"archive_sha256": hashlib.sha256(b"source").hexdigest()}
        )
        runner.atomic_json(
            self.evidence / "simulation.json",
            {"executable_sha256": hashlib.sha256(b"binary").hexdigest()},
        )
        binary = self.evidence / "executable"
        binary.write_bytes(b"binary")
        runner.seal_evidence(self.job)
        for changed in (b"changed", None):
            if changed is None:
                binary.unlink()
            else:
                binary.write_bytes(changed)
            with self.assertRaises(runner.Incomplete):
                runner.seal_evidence(self.job)

    def test_retention_failure_and_changed_source_cannot_pass(self):
        for changed in (False, True):
            output = self.root / str(changed)
            with (
                patch.object(
                    sys, "argv", ["runner", "simulation", "--output", str(output), "--seed", "7"]
                ),
                redirect_stdout(io.StringIO()),
                patch.object(runner.Job, "run", return_value=["revision", "rustc", "cargo"]),
                patch.object(runner, "source_snapshot", side_effect=["a" * 64, "b" * 64]),
                patch.object(runner, "bounded_bytes", return_value=b"archive"),
                patch.object(
                    runner, "simulation", side_effect=None if changed else OSError("disk full")
                ),
            ):
                self.assertEqual(runner.main(), 2)
                self.assertEqual(
                    json.loads((output / "result.json").read_bytes())["status"], "INCOMPLETE"
                )


if __name__ == "__main__":
    unittest.main()
