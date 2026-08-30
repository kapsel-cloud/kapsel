#!/usr/bin/env python3
"""Regression tests for the beta qualification orchestrator."""

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATOR = runpy.run_path(str(ROOT / "scripts/run-beta-qualification.py"))
VALIDATOR = runpy.run_path(str(ROOT / "scripts/validate-beta-qualification-baseline.py"))


class QualificationOrchestratorTests(unittest.TestCase):
    def test_source_identity_covers_extracted_inputs_and_replacement_scripts(self) -> None:
        paths = [
            "Cargo.lock",
            "crates/kapsel-authority/src/lib.rs",
            "scripts/format.sh",
            "scripts/test-demo-harness.sh",
            "scripts/test-fuzz.sh",
            "scripts/test-simulation.sh",
            "unrelated",
        ]
        selected = ORCHESTRATOR["selected_source_paths"](paths)
        mirrored = VALIDATOR["selected_baseline_source_paths"](paths)
        self.assertNotIn("unrelated", selected)
        self.assertEqual(selected, mirrored)
        self.assertEqual(len(selected), len(paths) - 1)

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
                {"trivy": {"findings": []}}
            ),
            [],
        )
        low = {
            "vulnerability_id": "CVE-TEST",
            "package": "example",
            "installed_version": "1.0",
            "fixed_version": "unavailable",
            "severity": "LOW",
        }
        findings = ORCHESTRATOR["retained_security_findings"](
            {"trivy": {"findings": [low]}}
        )
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertEqual(findings[0]["vulnerability_id"], "CVE-TEST")
        with self.assertRaises(RuntimeError):
            ORCHESTRATOR["retained_security_findings"](
                {"trivy": {"findings": [{**low, "severity": "HIGH"}]}}
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
