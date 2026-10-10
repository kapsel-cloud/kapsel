#!/usr/bin/env python3
"""Independent regressions for source privacy and dependency/secret scans."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import check_source_privacy as PRIVACY
import scan_source_security as SECURITY

ROOT = Path(__file__).resolve().parents[2]


class SourcePrivacyTests(unittest.TestCase):
    def test_scope_includes_retained_service_and_excludes_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            names = [
                "README.md",
                "CONTRIBUTING.md",
                "AGENTS.md",
                ".github/workflows/ci.yml",
                "crates/kapsel-daemon/src/main.rs",
                "crates/kapsel-authority/src/lib.rs",
                "scripts/setup.sh",
                "tools/checks/check.py",
                "tools/release/verify.py",
                "tools/dev/setup.py",
                "examples/caller.py",
                "xtask/src/main.rs",
                ".cargo/config.toml",
                "src/lib.rs",
                "tests/test.rs",
                "vectors/example.hex",
                "docs/reference/privacy.md",
                "fuzz/fuzz_targets/inspect_receipt.rs",
            ]
            for name in [*names, "target/generated", "dist/generated"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic\n")
            self.assertEqual(PRIVACY.tracked_paths(root), sorted(names))

    def test_private_inputs_and_overclaims_fail_without_disclosing_contents(self) -> None:
        cases = {
            "private-path.md": b"path: /Users/operator/private\n",
            "temporary-path.md": b"path: /private/var/private\n",
            "credential.md": b"-----BEGIN PRIVATE KEY-----\n",
            "aws.md": b"AKIA0123456789ABCDEF\n",
            "token.md": b"ghp_" + b"x" * 30,
            "claim.md": b"Kapsel is production-ready.\n",
            "once.md": b"Kapsel guarantees exactly-once.\n",
            "sla.md": b"Kapsel provides a production-support SLA.\n",
            "platform.md": b"Kapsel supports every Kubernetes distribution.\n",
            "performance.md": b"This establishes native-host performance.\n",
            "journal.sqlite3": b"SQLite format 3\0",
        }
        for name, contents in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / name).write_bytes(contents)

                with self.assertRaises(RuntimeError) as caught:
                    PRIVACY.validate(root, [name])

                self.assertIn(name, str(caught.exception))
                self.assertNotIn(contents.decode(errors="replace").strip(), str(caught.exception))

    def test_nonclaims_and_synthetic_vectors_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("Kapsel is not production-ready.\n")
            (root / "vector.hex").write_text("00010203\n")
            self.assertEqual(len(PRIVACY.validate(root, ["README.md", "vector.hex"])), 64)

    def test_source_reader_rejects_symlink_fifo_and_oversize_without_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "AKIA0123456789ABCDEF"
            oversized = root / "oversized.md"
            oversized.write_bytes(secret.encode() + b"x" * PRIVACY.MAX_SOURCE_FILE_BYTES)
            symlink = root / "symlink.md"
            symlink.symlink_to(oversized)
            fifo = root / "fifo.md"
            os.mkfifo(fifo)

            for name in ("oversized.md", "symlink.md", "fifo.md"):
                with self.subTest(name=name), self.assertRaises(RuntimeError) as caught:
                    PRIVACY.validate(root, [name])
                self.assertIn(name, str(caught.exception))
                self.assertNotIn(secret, str(caught.exception))


class SourceSecurityTests(unittest.TestCase):
    def test_database_freshness_rejects_old_and_future_timestamps(self) -> None:
        now = datetime.now(timezone.utc)
        self.assertTrue(SECURITY.utc_timestamp(now.isoformat()).endswith("Z"))
        for delta in (timedelta(days=-2), timedelta(days=1)):
            with self.assertRaises(RuntimeError):
                SECURITY.utc_timestamp((now + delta).isoformat())

    def test_bounded_run_handles_eof_and_rejects_large_streams_and_timeouts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            ok = SECURITY._bounded_completed_process(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ok')"],
                cwd,
                SECURITY.CommandLimits(deadline_seconds=5, stream_bytes=16),
                check=True,
            )
            self.assertEqual(ok.stdout, b"ok")

            with self.assertRaises(RuntimeError):
                SECURITY._bounded_completed_process(
                    [sys.executable, "-c", "import sys; sys.stdout.write('x' * 64)"],
                    cwd,
                    SECURITY.CommandLimits(deadline_seconds=5, stream_bytes=8),
                    check=True,
                )
            with self.assertRaises(RuntimeError):
                SECURITY._bounded_completed_process(
                    [sys.executable, "-c", "import sys; sys.stderr.write('x' * 64)"],
                    cwd,
                    SECURITY.CommandLimits(deadline_seconds=5, stream_bytes=8),
                    check=True,
                )
            with self.assertRaises(RuntimeError):
                SECURITY._bounded_completed_process(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    cwd,
                    SECURITY.CommandLimits(deadline_seconds=0.1, stream_bytes=8),
                    check=True,
                )
            with self.assertRaises(RuntimeError):
                SECURITY._bounded_completed_process(
                    [
                        sys.executable,
                        "-c",
                        "import os, time; os.close(1); os.close(2); time.sleep(5)",
                    ],
                    cwd,
                    SECURITY.CommandLimits(deadline_seconds=0.1, stream_bytes=8),
                    check=True,
                )

    def test_bounded_json_file_rejects_unsafe_or_oversize_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            report.write_text("{}")
            self.assertEqual(SECURITY.bounded_json_file(report, 2), {})
            report.write_text('{"Results":[]}' + "x")
            with self.assertRaises(RuntimeError):
                SECURITY.bounded_json_file(report, 2)

            symlink = root / "symlink.json"
            symlink.symlink_to(report)
            with self.assertRaises(RuntimeError):
                SECURITY.bounded_json_file(symlink, 1024)

            fifo = root / "fifo.json"
            os.mkfifo(fifo)
            with self.assertRaises(RuntimeError):
                SECURITY.bounded_json_file(fifo, 1024)

    def test_cargo_audit_rejects_vulnerabilities_warnings_and_database_changes(self) -> None:
        for count, warnings, digests, rejected in (
            (0, {}, ["same", "same"], False),
            (1, {}, ["same"], True),
            (0, {"unmaintained": [{}]}, ["same"], True),
            (0, {}, ["before", "after"], True),
        ):
            document = {"vulnerabilities": {"count": count}, "warnings": warnings}

            def run_scanner(command, _root, document=document):
                if "--version" in command:
                    output = b"cargo-audit 0.22.2"
                else:
                    output = json.dumps(document).encode()
                return subprocess.CompletedProcess(command, 0, output)

            def run_git(command, _root):
                return subprocess.CompletedProcess(command, 0, b"commit")

            with (
                self.subTest(count=count, warnings=warnings, digests=digests),
                mock.patch.object(SECURITY, "run_scanner", side_effect=run_scanner),
                mock.patch.object(SECURITY, "run_git", side_effect=run_git),
                mock.patch.object(SECURITY, "git_tree_sha256", side_effect=digests),
            ):
                if rejected:
                    with self.assertRaises(RuntimeError):
                        SECURITY.cargo_audit_result(ROOT)
                else:
                    result, tool = SECURITY.cargo_audit_result(ROOT)
                    self.assertEqual(result["vulnerabilities"], 0)
                    self.assertEqual(tool["database_sha256"], "same")

    def test_trivy_policy_and_database_identity(self) -> None:
        for severity, secrets, changed, rejected in (
            ("LOW", [], False, False),
            ("MEDIUM", [], False, False),
            ("UNKNOWN", [], False, False),
            ("HIGH", [], False, True),
            ("CRITICAL", [], False, True),
            ("LOW", [{}], False, True),
            ("LOW", [], True, True),
        ):
            with (
                self.subTest(severity=severity, secrets=secrets, changed=changed),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                database = root / "trivy.db"
                database.write_bytes(b"database")
                finding = {"VulnerabilityID": "CVE-TEST", "Severity": severity}

                def run_git(command, cwd):
                    return SECURITY.subprocess.run(
                        command, cwd=cwd, capture_output=True, check=True
                    )

                def run_scanner(
                    command,
                    cwd,
                    changed=changed,
                    database=database,
                    finding=finding,
                    secrets=secrets,
                ):
                    if command[1] == "version":
                        document = {
                            "Version": "0.72.0",
                            "VulnerabilityDB": {
                                "Version": 2,
                                "UpdatedAt": datetime.now(timezone.utc).isoformat(),
                            },
                        }
                        return subprocess.CompletedProcess(
                            command, 0, json.dumps(document).encode()
                        )
                    if "--skip-db-update" in command:
                        if changed:
                            database.write_bytes(b"changed")
                        document = {"Results": [{"Vulnerabilities": [finding], "Secrets": secrets}]}
                        report = Path(command[command.index("--output") + 1])
                        report.write_text(json.dumps(document))
                    return subprocess.CompletedProcess(command, 0, b"{}")

                subprocess.run(["git", "init", "--quiet", str(root)], check=True)
                (root / "source").write_text("synthetic\n")
                subprocess.run(["git", "add", "source"], cwd=root, check=True)
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@example.invalid",
                        "commit",
                        "--quiet",
                        "-m",
                        "fixture",
                    ],
                    cwd=root,
                    check=True,
                )

                with (
                    mock.patch.object(SECURITY, "run_git", side_effect=run_git),
                    mock.patch.object(SECURITY, "run_scanner", side_effect=run_scanner),
                    mock.patch.object(SECURITY, "trivy_database", return_value=database),
                ):
                    if rejected:
                        with self.assertRaises(RuntimeError):
                            SECURITY.trivy_result(root, "HEAD")
                    else:
                        result, tool = SECURITY.trivy_result(root, "HEAD")
                        self.assertEqual(result["findings"][0]["severity"], severity)
                        self.assertEqual(result["secrets"], 0)
                        self.assertEqual(len(tool["database_sha256"]), 64)

    def test_trivy_rejects_malformed_report_shape_and_noncanonical_severity(self) -> None:
        malformed_reports = [
            {"Results": {}},
            {"Results": [None]},
            {"Results": [{"Vulnerabilities": None}]},
            {"Results": [{"Vulnerabilities": {}}]},
            {"Results": [{"Vulnerabilities": [None]}]},
            {"Results": [{"Vulnerabilities": [{"Severity": "high"}]}]},
            {"Results": [{"Vulnerabilities": [{"Severity": "IMPORTANT"}]}]},
            {"Results": [{"Vulnerabilities": [{}]}]},
            {"Results": [{"Secrets": None}]},
            {"Results": [{"Secrets": "secret"}]},
            {"Results": [{"Secrets": [None]}]},
        ]
        for report in malformed_reports:
            with self.subTest(report=report), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._write_git_fixture(root)
                database = root / "trivy.db"
                database.write_bytes(b"database")

                with self._mock_trivy(root, database, report):
                    with self.assertRaises(RuntimeError):
                        SECURITY.trivy_result(root, "HEAD")

    def test_trivy_accepts_omitted_and_empty_collections(self) -> None:
        reports = [
            {},
            {"Results": []},
            {"Results": [{}]},
            {"Results": [{"Vulnerabilities": [], "Secrets": []}]},
        ]
        for report in reports:
            with self.subTest(report=report), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._write_git_fixture(root)
                database = root / "trivy.db"
                database.write_bytes(b"database")

                with self._mock_trivy(root, database, report):
                    result, _tool = SECURITY.trivy_result(root, "HEAD")
                    self.assertEqual(result["findings"], [])
                    self.assertEqual(result["secrets"], 0)

    def _write_git_fixture(self, root: Path) -> None:
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        (root / "source").write_text("synthetic\n")
        subprocess.run(["git", "add", "source"], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            cwd=root,
            check=True,
        )

    def _mock_trivy(self, root: Path, database: Path, report: object):
        def run_git(command, cwd):
            return SECURITY.subprocess.run(command, cwd=cwd, capture_output=True, check=True)

        def run_scanner(command, cwd):
            if command[1] == "version":
                document = {
                    "Version": "0.72.0",
                    "VulnerabilityDB": {
                        "Version": 2,
                        "UpdatedAt": datetime.now(timezone.utc).isoformat(),
                    },
                }
                return subprocess.CompletedProcess(command, 0, json.dumps(document).encode())
            if "--skip-db-update" in command:
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps(report))
            return subprocess.CompletedProcess(command, 0, b"{}")

        return mock.patch.multiple(
            SECURITY,
            run_git=mock.Mock(side_effect=run_git),
            run_scanner=mock.Mock(side_effect=run_scanner),
            trivy_database=mock.Mock(return_value=database),
        )


if __name__ == "__main__":
    unittest.main()
