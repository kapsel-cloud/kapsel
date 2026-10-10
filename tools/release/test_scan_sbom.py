#!/usr/bin/env python3
"""Regression tests for the release SBOM vulnerability scanner."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scan_sbom as SCANNER

ROOT = pathlib.Path(__file__).resolve().parents[2]

TRIVY_FIXTURE = pathlib.Path(__file__).with_name("trivy_fixture.py")


class ReleaseSbomScannerTests(unittest.TestCase):
    def test_fifo_sbom_is_rejected_without_waiting_for_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "fifo"
            os.mkfifo(path)
            code = (
                "import importlib.util,pathlib\n"
                f"s=importlib.util.spec_from_file_location('scanner', {str(ROOT / 'tools/release/scan_sbom.py')!r})\n"
                "m=importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\n"
                f"m.read_bounded_regular(pathlib.Path({str(path)!r}),256)\n"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", code], capture_output=True, timeout=5
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"not a bounded regular file", result.stderr)

    def fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], pathlib.Path, pathlib.Path, dict[str, str]]:
        temporary = tempfile.TemporaryDirectory(prefix="kapsel-sbom-scan-test-")
        root = pathlib.Path(temporary.name)
        binary_directory = root / "bin"
        binary_directory.mkdir()
        trivy = binary_directory / "trivy"
        trivy.write_bytes(TRIVY_FIXTURE.read_bytes())
        trivy.chmod(0o755)
        sbom = root / "candidate.spdx.json"
        sbom.write_text("{}\n")
        output = root / "summary.json"
        environment = {
            "HOME": str(root / "home"),
            "PATH": f"{binary_directory}:{os.environ.get('PATH', '')}",
        }
        return temporary, sbom, output, environment

    def test_fresh_atomic_scan_records_database_and_sbom_identity(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            SCANNER.scan(sbom, output)
            summary = json.loads(output.read_text())
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["finding_count"], 0)
        self.assertEqual(len(summary["database_sha256"]), 64)
        self.assertEqual(len(summary["sbom_sha256"]), 64)

    def test_high_finding_is_retained_and_rejected(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_SEVERITY"] = "HIGH"
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(RuntimeError):
                SCANNER.scan(sbom, output)
            summary = json.loads(output.read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["findings"][0]["id"], "CVE-TEST-1")

    def test_unknown_finding_is_retained_without_blocking(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_SEVERITY"] = "UNKNOWN"
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            SCANNER.scan(sbom, output)
            summary = json.loads(output.read_text())
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["findings"][0]["severity"], "UNKNOWN")

    def test_omitted_optional_finding_fields_are_reported_as_null(self) -> None:
        finding = {
            "VulnerabilityID": "CVE-TEST-1",
            "Severity": "LOW",
        }
        summary_finding = SCANNER.validated_findings({"Results": [{"Vulnerabilities": [finding]}]})[
            0
        ]
        self.assertEqual(summary_finding["id"], "CVE-TEST-1")
        self.assertIsNone(summary_finding["package"])
        self.assertIsNone(summary_finding["installed_version"])
        self.assertIsNone(summary_finding["fixed_version"])

    def test_noncanonical_severity_is_rejected(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_SEVERITY"] = "IMPORTANT"
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "unsupported vulnerability severity"):
                SCANNER.scan(sbom, output)
        self.assertFalse(output.exists())

    def test_omitted_report_collections_are_empty_results(self) -> None:
        for report_kind in ["omitted-results", "omitted-vulnerabilities"]:
            with self.subTest(report_kind=report_kind):
                temporary, sbom, output, environment = self.fixture()
                environment["FAKE_TRIVY_REPORT_KIND"] = report_kind
                with temporary, mock.patch.dict(os.environ, environment, clear=True):
                    SCANNER.scan(sbom, output)
                    summary = json.loads(output.read_text())
                self.assertEqual(summary["finding_count"], 0)
                self.assertEqual(summary["status"], "passed")

    def test_malformed_report_shapes_are_rejected(self) -> None:
        for report_kind in [
            "top-list",
            "results-object",
            "vulnerabilities-object",
            "vulnerability-string",
        ]:
            with self.subTest(report_kind=report_kind):
                temporary, sbom, output, environment = self.fixture()
                environment["FAKE_TRIVY_REPORT_KIND"] = report_kind
                with temporary, mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(RuntimeError, "Trivy report has an invalid"):
                        SCANNER.scan(sbom, output)
                self.assertFalse(output.exists())

    def test_database_change_during_no_update_scan_is_rejected(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_MUTATE"] = "1"
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "database identity changed"):
                SCANNER.scan(sbom, output)
        self.assertFalse(output.exists())

    def test_oversized_sbom_is_rejected_before_trivy_refresh(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with sbom.open("wb") as document:
                document.truncate(2 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
                SCANNER.scan(sbom, output)
            self.assertFalse(pathlib.Path(environment["HOME"]).exists())

    def test_sbom_symlink_is_rejected_without_resolving_final_component(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            target = sbom.with_name("target.spdx.json")
            sbom.replace(target)
            sbom.symlink_to(target)
            with self.assertRaises(OSError):
                SCANNER.scan(sbom, output)

    def test_trivy_report_must_be_bounded_regular_json(self) -> None:
        for report_kind in ["oversized", "symlink", "fifo"]:
            with self.subTest(report_kind=report_kind):
                temporary, sbom, output, environment = self.fixture()
                environment["FAKE_TRIVY_REPORT_KIND"] = report_kind
                with temporary, mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises((OSError, RuntimeError)):
                        SCANNER.scan(sbom, output)
                self.assertFalse(output.exists())

    def test_trivy_metadata_stdout_overflow_is_rejected(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_VERSION_STDOUT_BYTES"] = str(SCANNER.METADATA_BYTES_MAX + 1)
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "stdout exceeded its byte bound"):
                SCANNER.scan(sbom, output)
        self.assertFalse(output.exists())

    def test_trivy_metadata_stderr_overflow_is_rejected_without_sensitive_output(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_VERSION_STDERR_BYTES"] = str(SCANNER.METADATA_BYTES_MAX + 1)
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "stderr exceeded its byte bound") as raised:
                SCANNER.scan(sbom, output)
        self.assertNotIn("SECRET", str(raised.exception))
        self.assertFalse(output.exists())

    def test_trivy_metadata_wait_after_pipe_eof_keeps_deadline(self) -> None:
        temporary, _sbom, _output, environment = self.fixture()
        environment["FAKE_TRIVY_CLOSE_PIPES_THEN_SLEEP"] = "5"
        command = ["trivy", "--version", "--format", "json"]
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                SCANNER.run_bounded_capture(
                    command,
                    timeout_seconds=1,
                    output_bytes_maximum=SCANNER.METADATA_BYTES_MAX,
                )

    def test_trivy_metadata_eof_success_returns_stdout(self) -> None:
        temporary, _sbom, _output, environment = self.fixture()
        command = ["trivy", "--version", "--format", "json"]
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            metadata = SCANNER.run_json_metadata(command, timeout_seconds=1)
        self.assertEqual(metadata["Version"], SCANNER.TRIVY_VERSION)

    def test_trivy_timeout_cleans_invocation_owned_temporary_directory(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_SLEEP_SBOM"] = "5"
        with (
            temporary,
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(SCANNER, "SCAN_TIMEOUT_SECONDS", 1),
            mock.patch.object(tempfile, "tempdir", temporary.name),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                SCANNER.scan(sbom, output)
            leftovers = list(pathlib.Path(temporary.name).glob("kapsel-release-sbom-scan-*"))
        self.assertEqual(leftovers, [])
        self.assertFalse(output.exists())

    def test_failed_trivy_diagnostic_does_not_expose_tool_stderr(self) -> None:
        temporary, sbom, output, environment = self.fixture()
        environment["FAKE_TRIVY_FAIL_VERSION"] = "1"
        with temporary, mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Trivy command failed") as raised:
                SCANNER.scan(sbom, output)
        self.assertNotIn("SECRET", str(raised.exception))
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
