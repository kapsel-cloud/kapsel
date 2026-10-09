#!/usr/bin/env python3
"""Check source/range accounting, including additions and policy relocation."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import assurance_census as census


class AssuranceCensusTests(unittest.TestCase):
    def test_literals_comments_and_nested_ranges(self) -> None:
        source = """// #[cfg(test)] mod fake { }
const TEXT: &str = r###"#[cfg(test)] { /* } */"###;
/* outer /* #[cfg(test)] { */ comment */
#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn nested() { let character = '}'; }
    const SQL: &str = "continued \\
        { string }";
}
fn product<'a>(value: &'a str) -> &'a str { value }
"""
        self.assertEqual(census.gated_ranges(source), [[4, 10]])

    def test_gated_fields_parameters_and_generic_return(self) -> None:
        source = """struct Product {
    #[cfg(test)]
    fault: Option<Fault>,
    real: bool,
}
#[cfg(test)]
fn helper() -> Result<(), Error> {
    Ok(())
}
fn argument(real: bool, #[cfg(test)] fault: Fault) {}
"""
        self.assertEqual(census.gated_ranges(source), [[2, 3], [6, 10]])

    def test_nonexclusive_gates_stay_product(self) -> None:
        source = """#[cfg(not(test))]
fn product() {}
#[cfg(any(not(target_os = "linux"), test, feature = "test-harness"))]
fn shared() {}
#[cfg(all(test, target_os = "linux"))]
fn test_only() {}
#[cfg(feature = "demo-harness")]
fn harness_only() {}
"""
        self.assertEqual(census.gated_ranges(source), [[5, 8]])

    def test_file_classification(self) -> None:
        for path in (
            "src/kernel_simulation_tests.rs",
            "tests/qualification/run_git_service.py",
            "src/gateway/tests/format5-before-direct-create.sql",
            "fuzz/examples/replay.rs",
            "tools/dev/assurance_census.py",
        ):
            self.assertTrue(census.whole_support(path), path)
        for path in (
            "tools/release/verify_artifact.py",
            "scripts/ci.sh",
            "examples/fresh_session_caller.py",
            "src/gateway/journal/records.rs",
        ):
            self.assertFalse(census.whole_support(path), path)

    def test_git_snapshots_worktree_additions_and_conservation(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(census, "ROOT", Path(temporary)),
        ):
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", temporary], check=True, timeout=10)
            (root / "product.rs").write_text("fn product() {}\n", encoding="utf-8")
            (root / "test_sample.py").write_text("# fixture\n\n", encoding="utf-8")
            (root / ".gitignore").write_text("generated.rs\n", encoding="utf-8")
            census.git("add", ".")
            census.git(
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "baseline",
            )
            before = census.census("HEAD")
            (root / "product.rs").write_text("fn product() {}\nfn added() {}\n", encoding="utf-8")
            (root / "new_tests.rs").write_text("// new support\n", encoding="utf-8")
            (root / "generated.rs").write_text("// ignored\n", encoding="utf-8")
            (root / "test_sample.py").unlink()
            after = census.census("WORKTREE")
            self.assertEqual(before["totals"], {"assurance": 2, "product": 1, "tooling": 0})
            self.assertEqual(after["totals"], {"assurance": 1, "product": 2, "tooling": 0})
            # Report survives a round trip and accounts for every physical line once.
            report = json.loads(json.dumps(after))
            self.assertEqual(
                sum(report["totals"].values()), sum(f["lines"] for f in report["files"])
            )
            self.assertEqual([f["path"] for f in report["files"]], ["new_tests.rs", "product.rs"])


if __name__ == "__main__":
    unittest.main()
