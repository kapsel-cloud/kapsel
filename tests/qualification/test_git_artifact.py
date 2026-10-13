#!/usr/bin/env python3
"""Offline artifact custody, evidence and owned-container retirement checks."""

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import run_git_artifact as JOURNEY


def summary(case: str) -> dict[str, object]:
    return {
        "case": case,
        "result": "SUCCEEDED" if case == "healthy" else "UNKNOWN",
        "inspection": "INSPECTED",
        "receipt_sha256": "a" * 64,
        "identical_retained_receipt": True,
        "finalized_submission": {"version": 1, "status": "ADMITTED", "phase": "finalized"},
        "caller_private_access_denied": True,
        "cold_binary_replacement": True,
        "signing_repair_without_receiver": case == "healthy",
    }


class GitArtifactTests(unittest.TestCase):
    def fixture(self, root: Path, *, dirty: bool = False):
        workspace = root / "workspace"
        workspace.mkdir()
        extracted = workspace / "extracted"
        extracted.mkdir()
        (extracted / "RELEASE-METADATA.json").write_text(json.dumps({"source_dirty": dirty}))
        archive = root / "archive.tar.gz"
        archive.write_bytes(b"archive identity")
        git = root / "git"
        git.write_bytes(b"selected Git identity")
        git.chmod(0o700)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        module = SimpleNamespace(extract_release=mock.Mock(return_value=extracted))
        return workspace, extracted, archive, git, spec, module

    def test_cli_rejects_retired_inputs_before_qualification(self):
        arguments = ["runner", "--archive", "/selected", "--revision", "a" * 40, "--git", "/git"]
        for extra in ([], ["--retained-archive", "/other"], ["--retained-revision", "b" * 40]):
            with (
                self.subTest(extra=extra),
                mock.patch("sys.argv", arguments + extra),
                mock.patch.object(JOURNEY, "qualify") as qualify,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                if extra:
                    with self.assertRaises(SystemExit) as failure:
                        JOURNEY.main()
                    self.assertEqual(failure.exception.code, 2)
                    qualify.assert_not_called()
                else:
                    JOURNEY.main()
                    qualify.assert_called_once_with(Path("/selected"), "a" * 40, Path("/git"))

    def test_dirty_source_refuses_before_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _, archive, git, spec, module = self.fixture(Path(temporary), dirty=True)
            with (
                mock.patch.object(JOURNEY.tempfile, "mkdtemp", return_value=str(workspace)),
                mock.patch.object(
                    JOURNEY.importlib.util, "spec_from_file_location", return_value=spec
                ),
                mock.patch.object(JOURNEY.importlib.util, "module_from_spec", return_value=module),
                mock.patch.object(JOURNEY, "run") as transport,
            ):
                with self.assertRaisesRegex(RuntimeError, "clean-source"):
                    JOURNEY.qualify(archive, "a" * 40, git)
                transport.assert_not_called()
                self.assertEqual(module.extract_release.call_args.args[2], "a" * 40)

    def test_owned_container_is_removed_after_timeout_and_reports_cleanup_failure(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup=cleanup_fails), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                arguments = []

                def transport(argv, arguments=arguments, cleanup_fails=cleanup_fails):
                    arguments.append(argv)
                    if cleanup_fails and argv[1] == "rm":
                        raise RuntimeError("owned cleanup failed")
                    return b""

                with (
                    mock.patch.object(JOURNEY, "run", side_effect=transport),
                    mock.patch.object(
                        JOURNEY.subprocess,
                        "run",
                        side_effect=subprocess.TimeoutExpired("docker", 180),
                    ),
                ):
                    expected = RuntimeError if cleanup_fails else subprocess.TimeoutExpired
                    with self.assertRaises(expected):
                        JOURNEY.exercise_case("healthy", root, root, root / "evidence", b"source")
                create = arguments[0]
                name = create[create.index("--name") + 1]
                self.assertIn("none", create)
                self.assertIn("--security-opt=no-new-privileges", create)
                self.assertIn(f"{root}:/artifact:ro", create)
                self.assertEqual(arguments[-1], ["docker", "rm", "-f", name])

    def test_success_binds_all_cases_and_exact_transferred_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, extracted, archive, git, spec, module = self.fixture(Path(temporary))

            def transport(arguments):
                if arguments[:2] == ["docker", "cp"] and ":/evidence/." in arguments[2]:
                    destination = Path(arguments[3])
                    (destination / "summary.json").write_text(json.dumps(summary(destination.name)))
                return b""

            with (
                mock.patch.object(JOURNEY.tempfile, "mkdtemp", return_value=str(workspace)),
                mock.patch.object(
                    JOURNEY.importlib.util, "spec_from_file_location", return_value=spec
                ),
                mock.patch.object(JOURNEY.importlib.util, "module_from_spec", return_value=module),
                mock.patch.object(JOURNEY, "run", side_effect=transport) as docker,
                mock.patch.object(
                    JOURNEY.subprocess, "run", return_value=SimpleNamespace(returncode=0)
                ) as execution,
            ):
                self.assertEqual(JOURNEY.qualify(archive, "a" * 40, git), workspace)
                result = json.loads((workspace / "summary.json").read_bytes())
                self.assertEqual(result["source_revision"], "a" * 40)
                module.extract_release.assert_called_once_with(
                    archive.resolve(),
                    Path(str(archive.resolve()) + ".sha256"),
                    "a" * 40,
                    workspace / "extracted",
                )
                self.assertNotIn("retained_source_revision", result)
                self.assertNotIn("retained_archive_sha256", result)
                for call in docker.call_args_list:
                    if call.args[0][:2] == ["docker", "create"]:
                        volumes = [arg for arg in call.args[0] if arg.endswith(":ro")]
                        self.assertEqual(volumes, [f"{extracted}:/artifact:ro"])
                for key, path in (
                    ("archive", archive),
                    ("git", git),
                    ("exercise", JOURNEY.EXERCISE_SOURCE),
                    ("caller", JOURNEY.CALLER_SOURCE),
                    ("hook", JOURNEY.HOOK_SOURCE),
                ):
                    self.assertEqual(
                        result[key + "_sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
                    )
                self.assertEqual(
                    (workspace / JOURNEY.EXERCISE_SOURCE.name).read_bytes(),
                    JOURNEY.EXERCISE_SOURCE.read_bytes(),
                )
                self.assertEqual(
                    (workspace / "inputs" / JOURNEY.HOOK_SOURCE.name).read_bytes(),
                    JOURNEY.HOOK_SOURCE.read_bytes(),
                )
                self.assertEqual(
                    (workspace / "inputs" / JOURNEY.CALLER_SOURCE.name).read_bytes(),
                    JOURNEY.CALLER_SOURCE.read_bytes(),
                )
                self.assertEqual(len(execution.call_args_list), len(JOURNEY.CASES))
                for call in execution.call_args_list:
                    self.assertEqual(call.kwargs["input"], JOURNEY.EXERCISE_SOURCE.read_bytes())
                self.assertEqual(tuple(case["case"] for case in result["cases"]), JOURNEY.CASES)
                self.assertEqual(
                    sum(call.args[0][1] == "rm" for call in docker.call_args_list),
                    len(JOURNEY.CASES),
                )

    def test_empty_malformed_or_false_completion_evidence_never_passes(self):
        for record in (
            {},
            [],
            {**summary("healthy"), "receipt_sha256": ""},
            {**summary("healthy"), "identical_retained_receipt": False},
            {**summary("healthy"), "cold_binary_replacement": False},
            {**summary("healthy"), "finalized_submission": {"status": "NO_SELECTION"}},
            {
                **summary("healthy"),
                "finalized_submission": {"status": "ADMITTED", "phase": "authorized"},
            },
        ):
            with self.subTest(record=record), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)

                def transport(arguments, root=root, record=record):
                    if arguments[:2] == ["docker", "cp"] and ":/evidence/." in arguments[2]:
                        (root / "evidence/summary.json").write_text(json.dumps(record))
                    return b""

                with (
                    mock.patch.object(JOURNEY, "run", side_effect=transport),
                    mock.patch.object(
                        JOURNEY.subprocess, "run", return_value=SimpleNamespace(returncode=0)
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "incomplete evidence"):
                        JOURNEY.exercise_case("healthy", root, root, root / "evidence", b"source")


if __name__ == "__main__":
    unittest.main()
