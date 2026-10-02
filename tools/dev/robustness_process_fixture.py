#!/usr/bin/env python3
"""Small, isolated process fixtures for robustness regressions, not exploration commands."""

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


def cancel_during_spawn(evidence: str, scratch: str, lock: str) -> int:
    supervisor = runner.Supervisor(Path(evidence), Path(scratch), int(lock), 5)
    actual = subprocess.Popen

    def spawn(*args, **kwargs):
        child = actual(*args, **kwargs)
        request_cancellation()
        return child

    with patch.object(runner.subprocess, "Popen", side_effect=spawn):
        try:
            supervisor.run([sleeping_command()])
        except runner.Cancelled:
            return 0
    return 99


def cancel_during_retirement(evidence: str, scratch: str, lock: str) -> int:
    supervisor = runner.Supervisor(Path(evidence), Path(scratch), int(lock), 5)
    actual = runner.retire_all

    def retire(children):
        request_cancellation()
        actual(children)

    with patch.object(runner, "retire_all", side_effect=retire):
        try:
            supervisor.run(
                [sleeping_command(), sleeping_command(), [str(Path(scratch) / "missing-command")]]
            )
        except runner.Cancelled:
            return 0
    return 99


def cancellation_at_finalization(state: str, scratch: str, phase: str) -> int:
    actual_root = runner.private_root
    actual_remove = runner.shutil.rmtree
    actual_publish = runner.atomic_json
    root_calls = 0

    def validate_root(value):
        nonlocal root_calls
        if value == scratch:
            root_calls += 1
            if phase == "validate" and root_calls == 2:
                request_cancellation()
        return actual_root(value)

    def remove(path):
        if phase == "remove":
            request_cancellation()
        actual_remove(path)

    def publish(path, value):
        if phase == "terminal" and path.name == "result.json" and value.get("status") == "PASSED":
            request_cancellation()
        actual_publish(path, value)

    arguments = ["runner", "simulation", "--state", state, "--scratch", scratch, "--seed", "1"]
    with (
        patch.object(sys, "argv", arguments),
        patch.object(runner, "source_identity", return_value={"revision": "a" * 40}),
        patch.object(runner, "simulation"),
        patch.object(runner, "private_root", side_effect=validate_root),
        patch.object(runner.shutil, "rmtree", side_effect=remove),
        patch.object(runner, "atomic_json", side_effect=publish),
    ):
        return runner.main()


def reject_fifo(path: str) -> int:
    try:
        runner.read_result(Path(path))
    except runner.Incomplete:
        return 0
    return 99


def collect_until_cancelled(evidence: str, scratch: str, lock: str, marker: str) -> int:
    supervisor = runner.Supervisor(Path(evidence), Path(scratch), int(lock), 30)
    supervisor.run([[sys.executable, __file__, "ready-and-sleep", marker]])
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


def spawn_sleeping_descendant() -> int:
    subprocess.Popen(sleeping_command())
    return 0


def fuzz_signal(*arguments: str) -> int:
    prefix = next(
        argument.split("=", 1)[1]
        for argument in arguments
        if argument.startswith("-artifact_prefix=")
    )
    Path(prefix, "crash-fixture").write_bytes(b"replay")
    print("ERROR: libFuzzer: deadly signal", flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
    return 99


SCENARIOS = {
    "cancel-during-spawn": cancel_during_spawn,
    "cancel-during-retirement": cancel_during_retirement,
    "finalization": cancellation_at_finalization,
    "reject-fifo": reject_fifo,
    "collect-until-cancelled": collect_until_cancelled,
    "ready-and-sleep": ready_and_sleep,
    "delayed-write": delayed_write,
    "spawn-delayed-writer": spawn_delayed_writer,
    "spawn-sleeping-descendant": spawn_sleeping_descendant,
    "fuzz-signal": fuzz_signal,
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
