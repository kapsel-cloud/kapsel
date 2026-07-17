#!/usr/bin/env python3
"""Deterministic prerequisite refusal tests for the live KAP-0042 harness."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "demo-kind-crash-recovery.sh"


class HarnessPrerequisiteTests(unittest.TestCase):
    def run_case(self, commands: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory(prefix="kapsel-demo-prerequisites-") as temporary:
            directory = pathlib.Path(temporary)
            log = directory / "calls.log"
            for name, body in commands.items():
                path = directory / name
                path.write_text(f"#!/bin/sh\nprintf '%s\\n' \"{name} $*\" >>\"$FAKE_LOG\"\n{body}\n")
                path.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{directory}:{environment['PATH']}"
            environment["FAKE_LOG"] = str(log)
            result = subprocess.run(
                [str(HARNESS)],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            calls = log.read_text() if log.exists() else ""
            return result, calls

    def test_unavailable_docker_stops_before_cluster_inspection(self) -> None:
        result, calls = self.run_case({"docker": "exit 1", "kind": "exit 99"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "docker info\n")

    def test_old_kind_stops_before_cluster_creation(self) -> None:
        result, calls = self.run_case(
            {
                "docker": "exit 0",
                "kind": "[ \"$1\" = version ] && echo 'kind v0.31.0'; exit 0",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kind version", calls)
        self.assertNotIn("kind create", calls)

    def test_preexisting_cluster_stops_before_creation(self) -> None:
        result, calls = self.run_case(
            {
                "docker": "exit 0",
                "kind": "if [ \"$1\" = version ]; then echo 'kind v0.32.0'; else echo occupied; fi",
                "kubectl": (
                    "echo '{\"clientVersion\":{\"major\":\"1\",\"minor\":\"34\"}}'"
                ),
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to run while kind clusters already exist", result.stderr)
        self.assertNotIn("kind create", calls)


if __name__ == "__main__":
    unittest.main()
