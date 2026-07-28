#!/usr/bin/env python3
"""Regression tests for the KAP-0061 qualification orchestrator."""

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATOR = runpy.run_path(str(ROOT / "scripts/run-kap0061-qualification.py"))


class QualificationOrchestratorTests(unittest.TestCase):
    def test_bounded_output_placeholder_is_replaced_only_for_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bounded.json"
            command = [
                "python3",
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('bounded')",
                "BOUNDED_OUTPUT",
            ]
            result = ORCHESTRATOR["run_lane"](
                "placeholder regression", command, ROOT, 30, output
            )
            self.assertEqual(result["command"], command)
            self.assertEqual(output.read_text(), "bounded")
            self.assertEqual(
                result["bounded_output_sha256"],
                hashlib.sha256(b"bounded").hexdigest(),
            )

    def test_kind_version_selects_semver_not_platform(self) -> None:
        self.assertEqual(
            ORCHESTRATOR["parse_kind_version"]("kind v0.32.0 go1.26.3 darwin/arm64"),
            "0.32.0",
        )
        with self.assertRaises(RuntimeError):
            ORCHESTRATOR["parse_kind_version"]("darwin/arm64")

    def test_lower_security_findings_are_retained(self) -> None:
        self.assertEqual(
            ORCHESTRATOR["retained_security_findings"](
                {"trivy": {"vulnerability_counts": {}}}
            ),
            [],
        )
        findings = ORCHESTRATOR["retained_security_findings"](
            {"trivy": {"vulnerability_counts": {"LOW": 2}}}
        )
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertEqual(findings[0]["count"], 2)
        with self.assertRaises(RuntimeError):
            ORCHESTRATOR["retained_security_findings"](
                {"trivy": {"vulnerability_counts": {"HIGH": 1}}}
            )

    def test_live_timings_are_closed_and_complete(self) -> None:
        output = b"\n".join(
            [
                b"[kind timing] healthy_ms=1",
                b"[kind timing] failed_ms=2",
                b"[kind timing] unknown_ms=3",
                b"[kind timing] cleanup_ms=4",
            ]
        )
        self.assertEqual(
            ORCHESTRATOR["parse_live"](output),
            {"healthy": 1, "failed": 2, "unknown": 3, "cleanup": 4},
        )
        with self.assertRaises(RuntimeError):
            ORCHESTRATOR["parse_live"](b"[kind timing] healthy_ms=1")


if __name__ == "__main__":
    unittest.main()
