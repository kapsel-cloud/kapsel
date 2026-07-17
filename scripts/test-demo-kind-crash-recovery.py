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
    def run_case(
        self,
        commands: dict[str, str],
        artifact_state: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
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
            if artifact_state is not None:
                executable = directory / "kapsel-demo-harness"
                assets = directory / "assets"
                assets.mkdir()
                if artifact_state != "missing-executable":
                    executable.write_text("#!/bin/sh\nexit 0\n")
                    executable.chmod(0o755)
                if artifact_state != "missing-vector":
                    assets.joinpath("kap0038-trust.hex").write_text("00")
                environment["KAPSEL_DEMO_EXECUTABLE"] = str(executable)
                environment["KAPSEL_DEMO_ASSET_DIRECTORY"] = str(assets)
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

    def test_missing_artifact_executable_stops_before_docker(self) -> None:
        result, calls = self.run_case(
            {"docker": "exit 99"},
            artifact_state="missing-executable",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")
        self.assertIn("artifact demo executable is unsafe or unavailable", result.stderr)

    def test_missing_artifact_vector_stops_before_docker(self) -> None:
        result, calls = self.run_case(
            {"docker": "exit 99"},
            artifact_state="missing-vector",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, "")
        self.assertIn("artifact demo trust vector is unsafe or unavailable", result.stderr)

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

    def test_failed_cluster_creation_deletes_the_unique_owned_name(self) -> None:
        result, calls = self.run_case(
            {
                "docker": "exit 0",
                "kind": (
                    "if [ \"$1\" = version ]; then echo 'kind v0.32.0'; "
                    "elif [ \"$1 $2\" = 'get clusters' ]; then echo 'No kind clusters found.'; "
                    "elif [ \"$1\" = create ]; then exit 1; fi; exit 0"
                ),
                "kubectl": "echo '{\"clientVersion\":{\"major\":\"1\",\"minor\":\"34\"}}'",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kind create cluster", calls)
        self.assertIn("kind delete cluster", calls)

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
