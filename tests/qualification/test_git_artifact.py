#!/usr/bin/env python3
"""Offline checks for packaged Git qualification orchestration and failure handling."""

import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import run_git_artifact as JOURNEY


class GitArtifactTests(unittest.TestCase):
    def test_exercise_is_valid_python_without_product_test_hooks(self):
        source = JOURNEY.EXERCISE_SOURCE.read_bytes()
        ast.parse(source)
        self.assertNotIn(b"KAPSELD_TEST", source)
        self.assertNotIn(b"KAPSEL_DEMO", source)
        self.assertEqual(JOURNEY.CASES, ("healthy", "pre-receive", "post-receive", "service-loss"))

    def test_fixture_subcommands_use_the_selected_git(self):
        tree = ast.parse(JOURNEY.EXERCISE_SOURCE.read_bytes())
        helper = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "git"
        )
        command = mock.Mock(return_value=b"selected\n")
        namespace = {
            "git_binary": Path("/private/git"),
            "command": command,
            "environment": {},
            "Path": Path,
        }
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "fixture", "exec"), namespace)
        self.assertEqual(namespace["git"]("--version"), "selected")
        self.assertEqual(
            command.call_args.args[0], ["/private/git", "--exec-path=/private", "--version"]
        )
        bootstrap = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and any(
                isinstance(arg, ast.Constant) and arg.value == "push" for arg in node.value.args
            )
        )
        invoke = mock.Mock()
        exec(
            compile(ast.Module(body=[bootstrap], type_ignores=[]), "fixture", "exec"),
            {
                "git": invoke,
                "git_binary": Path("/private/git"),
                "sender": "sender",
                "receiver": "receiver",
                "old": "a" * 40,
                "reference": "refs/heads/approved",
            },
        )
        self.assertIn("--receive-pack=/private/git receive-pack", invoke.call_args.args)

    def test_runtime_custody_mode_survives_private_umask(self):
        tree = ast.parse(JOURNEY.EXERCISE_SOURCE.read_bytes())
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        setup = next(node for node in main.body if isinstance(node, ast.For))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            namespace = {
                "state": root / "state",
                "config": root / "config",
                "Path": lambda path: root / "runtime",
                "service_uid": 61000,
                "os": SimpleNamespace(chown=lambda *args: None),
            }
            previous = os.umask(0o077)
            try:
                exec(
                    compile(ast.Module(body=[setup], type_ignores=[]), "fixture", "exec"), namespace
                )
            finally:
                os.umask(previous)
            self.assertEqual((root / "runtime").stat().st_mode & 0o777, 0o750)
            self.assertEqual((root / "state").stat().st_mode & 0o777, 0o700)

    def fixture(self, root, *, dirty=False):
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

    def test_owned_container_is_removed_after_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, extracted, archive, git, spec, module = self.fixture(Path(temporary))
            with (
                mock.patch.object(JOURNEY.tempfile, "mkdtemp", return_value=str(workspace)),
                mock.patch.object(
                    JOURNEY.importlib.util, "spec_from_file_location", return_value=spec
                ),
                mock.patch.object(JOURNEY.importlib.util, "module_from_spec", return_value=module),
                mock.patch.object(JOURNEY, "run", return_value=b"") as transport,
                mock.patch.object(
                    JOURNEY.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 180)
                ),
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    JOURNEY.qualify(archive, "a" * 40, git)
                create = transport.call_args_list[0].args[0]
                name = create[create.index("--name") + 1]
                self.assertIn(f"{extracted}:/artifact:ro", create)
                self.assertIn("--network", create)
                self.assertIn("none", create)
                self.assertIn("--security-opt=no-new-privileges", create)
                self.assertEqual(transport.call_args_list[-1].args[0], ["docker", "rm", "-f", name])

    def test_success_binds_all_cases_and_selected_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _, archive, git, spec, module = self.fixture(Path(temporary))

            def transport(arguments):
                if arguments[:2] == ["docker", "cp"] and ":/evidence/." in arguments[2]:
                    destination = Path(arguments[3])
                    (destination / "summary.json").write_text(
                        json.dumps({"case": destination.name})
                    )
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
                summary = json.loads((workspace / "summary.json").read_bytes())
                self.assertEqual(summary["source_revision"], "a" * 40)
                self.assertEqual(
                    summary["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest()
                )
                self.assertEqual(
                    summary["git_sha256"], hashlib.sha256(git.read_bytes()).hexdigest()
                )
                source = JOURNEY.EXERCISE_SOURCE.read_bytes()
                self.assertEqual(summary["exercise_sha256"], hashlib.sha256(source).hexdigest())
                self.assertEqual((workspace / JOURNEY.EXERCISE_SOURCE.name).read_bytes(), source)
                self.assertEqual(len(execution.call_args_list), len(JOURNEY.CASES))
                for call in execution.call_args_list:
                    self.assertEqual(call.kwargs["input"], source)
                self.assertEqual(tuple(case["case"] for case in summary["cases"]), JOURNEY.CASES)
                removals = [
                    call.args[0] for call in docker.call_args_list if call.args[0][1] == "rm"
                ]
                self.assertEqual(len(removals), len(JOURNEY.CASES))


if __name__ == "__main__":
    unittest.main()
