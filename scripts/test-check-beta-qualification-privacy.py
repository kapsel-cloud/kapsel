#!/usr/bin/env python3
"""Regression tests for the closed beta qualification privacy review."""

from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check-beta-qualification-privacy.py"
CHECK = runpy.run_path(str(CHECKER))
VALIDATOR = runpy.run_path(str(ROOT / "scripts/validate-beta-qualification-baseline.py"))


class PrivacyReviewTests(unittest.TestCase):
    def test_scope_covers_extracted_product_source(self) -> None:
        prefix = "crates/kapsel-authority/"
        self.assertIn(prefix, CHECK["ROOT_PREFIXES"])
        self.assertIn(prefix, VALIDATOR["PRIVACY_ROOT_PREFIXES"])
        self.assertIn(f"{prefix}src/lib.rs", CHECK["tracked_paths"](ROOT))

    def test_current_root_scope_passes(self) -> None:
        with tempfile.NamedTemporaryFile() as output:
            result = subprocess.run(
                ["python3", str(CHECKER), "--output", output.name],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_paths_credentials_artifacts_and_overclaims_fail(self) -> None:
        cases = {
            "private-path.md": b"path: /Users/operator/private\n",
            "credential.md": b"-----BEGIN PRIVATE KEY-----\n",
            "claim.md": b"Kapsel is production-ready.\n",
            "journal.sqlite3": b"SQLite format 3\0",
        }
        for name, contents in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / name).write_bytes(contents)
                with self.assertRaises(RuntimeError):
                    CHECK["validate"](root, [name])


if __name__ == "__main__":
    unittest.main()
