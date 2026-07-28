#!/usr/bin/env python3
"""Regression tests for the closed KAP-0061 baseline validator."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "scripts/validate-kap0061-baseline.py"
MANIFEST = ROOT / "qualification/kap0061-baseline.json"


class BaselineValidatorTests(unittest.TestCase):
    def run_document(self, document: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as output:
            json.dump(document, output)
            output.flush()
            return subprocess.run(
                ["python3", str(VALIDATOR), output.name],
                capture_output=True,
                text=True,
                check=False,
            )

    def document(self) -> dict:
        return json.loads(MANIFEST.read_text())

    def test_canonical_manifest_passes(self) -> None:
        result = subprocess.run(
            ["python3", str(VALIDATOR), str(MANIFEST)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_null_duplicate_float_and_absolute_path_fail(self) -> None:
        mutations = []
        unknown = self.document()
        unknown["unknown"] = True
        mutations.append(unknown)
        null = self.document()
        null["baseline"]["source_sha256"] = None
        mutations.append(null)
        duplicate = self.document()
        duplicate["budgets"].append(copy.deepcopy(duplicate["budgets"][0]))
        mutations.append(duplicate)
        floating = self.document()
        floating["results"][0]["duration_ms"] = 1.5
        mutations.append(floating)
        absolute = self.document()
        absolute["results"][0]["command"][0] = "/private/var/secret"
        mutations.append(absolute)
        missing = self.document()
        missing["results"].pop()
        mutations.append(missing)

        for document in mutations:
            with self.subTest():
                self.assertNotEqual(self.run_document(document).returncode, 0)


if __name__ == "__main__":
    unittest.main()
