#!/usr/bin/env python3
"""Independent regressions for source privacy and dependency/secret scans."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PRIVACY = load("check-source-privacy")
SECURITY = load("scan-source-security")


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
                "crates/kapseld/src/main.rs",
                "crates/kapsel-authority/src/lib.rs",
                "scripts/check.py",
                "src/lib.rs",
                "tests/test.rs",
                "vectors/example.hex",
                "docs/PRIVACY.md",
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


class SourceSecurityTests(unittest.TestCase):
    def test_database_freshness_rejects_old_and_future_timestamps(self) -> None:
        now = datetime.now(timezone.utc)
        self.assertTrue(SECURITY.utc_timestamp(now.isoformat()).endswith("Z"))
        for delta in (timedelta(days=-2), timedelta(days=1)):
            with self.assertRaises(RuntimeError):
                SECURITY.utc_timestamp((now + delta).isoformat())

    def test_cargo_audit_rejects_vulnerabilities_warnings_and_database_changes(self) -> None:
        for count, warnings, digests, rejected in (
            (0, {}, ["same", "same"], False),
            (1, {}, ["same"], True),
            (0, {"unmaintained": [{}]}, ["same"], True),
            (0, {}, ["before", "after"], True),
        ):
            document = {"vulnerabilities": {"count": count}, "warnings": warnings}

            def run(command, _root, document=document):
                if command[0] == "git":
                    output = b"commit"
                elif "--version" in command:
                    output = b"cargo-audit 0.22.2"
                else:
                    output = json.dumps(document).encode()
                return subprocess.CompletedProcess(command, 0, output)

            with (
                self.subTest(count=count, warnings=warnings, digests=digests),
                mock.patch.object(SECURITY, "run", side_effect=run),
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

                def run(
                    command,
                    cwd,
                    changed=changed,
                    database=database,
                    finding=finding,
                    secrets=secrets,
                ):
                    if command[0] == "git":
                        # Real git archive/extraction, with scanner output isolated below.
                        return SECURITY.subprocess.run(
                            command, cwd=cwd, capture_output=True, check=True
                        )
                    if command[1] == "version":
                        document = {
                            "Version": "0.72.0",
                            "VulnerabilityDB": {
                                "Version": 2,
                                "UpdatedAt": datetime.now(timezone.utc).isoformat(),
                            },
                        }
                    elif "--skip-db-update" in command:
                        if changed:
                            database.write_bytes(b"changed")
                        document = {"Results": [{"Vulnerabilities": [finding], "Secrets": secrets}]}
                    else:
                        document = {}
                    return subprocess.CompletedProcess(command, 0, json.dumps(document).encode())

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
                    mock.patch.object(SECURITY, "run", side_effect=run),
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


if __name__ == "__main__":
    unittest.main()
