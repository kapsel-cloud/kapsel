#!/usr/bin/env python3
"""Isolated process fixtures for bounded-job regressions, not exploration commands."""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import run_robustness as runner


def sleeping_command() -> list[str]:
    return [sys.executable, "-c", "import time; time.sleep(30)"]


def request_cancellation() -> None:
    os.kill(os.getpid(), signal.SIGTERM)


def cancellation(evidence: str, phase: str) -> int:
    job = runner.Job(Path(evidence), 5)
    actual_spawn, actual_retire = subprocess.Popen, runner.retire_all

    def spawn(*args, **kwargs):
        child = actual_spawn(*args, **kwargs)
        if phase == "spawn":
            request_cancellation()
        return child

    def retire(children):
        if phase == "retirement":
            request_cancellation()
        actual_retire(children)

    with (
        patch.object(runner.subprocess, "Popen", side_effect=spawn),
        patch.object(runner, "retire_all", side_effect=retire),
    ):
        try:
            job.run([sleeping_command(), sleeping_command(), [str(Path(evidence) / "missing")]])
        except runner.Cancelled:
            return 0
    return 99


def finalization(output: str, phase: str) -> int:
    actual_publish = runner.atomic_json

    def publish(path, value):
        if phase == "terminal" and value.get("status") == "COMPLETED":
            request_cancellation()
        actual_publish(path, value)

    def execute(*_args):
        if phase == "execution":
            request_cancellation()

    with (
        patch.object(sys, "argv", ["runner", "simulation", "--output", output, "--seed", "1"]),
        patch.object(runner.Job, "run", return_value=["revision", "rustc", "cargo"]),
        patch.object(runner, "source_snapshot", return_value="a" * 64),
        patch.object(runner, "bounded_bytes", return_value=b"archive"),
        patch.object(runner, "simulation", side_effect=execute),
        patch.object(runner, "seal_evidence"),
        patch.object(runner, "atomic_json", side_effect=publish),
    ):
        return runner.main()


def reject_fifo(path: str) -> int:
    try:
        runner.bounded_bytes(Path(path), 100)
    except runner.Incomplete:
        return 0
    return 99


def collect_until_cancelled(evidence: str, marker: str) -> int:
    runner.Job(Path(evidence), 30).run([[sys.executable, __file__, "ready-and-sleep", marker]])
    return 99


def ready_and_sleep(marker: str) -> int:
    Path(marker).touch()
    time.sleep(30)
    return 0


def delayed_write(marker: str) -> int:
    time.sleep(1)
    Path(marker).write_text("alive")
    return 0


def spawn_delayed_writer(marker: str) -> int:
    subprocess.Popen([sys.executable, __file__, "delayed-write", marker])
    time.sleep(30)
    return 0


def fail_after_marker(marker: str) -> int:
    deadline = time.monotonic() + 5
    while not Path(marker).exists():
        if time.monotonic() >= deadline:
            return 99
        time.sleep(0.01)
    print("peer failure after successful retirement", flush=True)
    return 7


def spawn_sleeping_descendant() -> int:
    subprocess.Popen(sleeping_command())
    return 0


def fuzz_signal(artifacts: str) -> int:
    Path(artifacts, "crash-fixture").write_bytes(b"replay")
    print("ERROR: libFuzzer: deadly signal", flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
    return 99


def duration_marker_then_hang() -> int:
    print(
        "KAPSEL_KERNEL_DURATION_COMPLETED seed=7 shard=0/1 "
        "cases=1 steps=32 duration_ms=1 elapsed_ms=1",
        flush=True,
    )
    print("test result: ok. 1 passed; 0 failed; 0 ignored;", flush=True)
    time.sleep(30)
    return 0


SCENARIOS = {
    "cancellation": cancellation,
    "finalization": finalization,
    "reject-fifo": reject_fifo,
    "collect-until-cancelled": collect_until_cancelled,
    "ready-and-sleep": ready_and_sleep,
    "delayed-write": delayed_write,
    "spawn-delayed-writer": spawn_delayed_writer,
    "spawn-sleeping-descendant": spawn_sleeping_descendant,
    "fail-after-marker": fail_after_marker,
    "fuzz-signal": fuzz_signal,
    "duration-marker-then-hang": duration_marker_then_hang,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, runner.cancel)
    return SCENARIOS[args.scenario](*args.arguments)


if __name__ == "__main__":
    sys.exit(main())
