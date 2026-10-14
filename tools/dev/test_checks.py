#!/usr/bin/env python3
"""Recording-fixture evidence for the fixed six scopes and honest gate failures."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import qualify_native
import resolve_git
import run_checks

ROOT = Path(__file__).resolve().parents[2]
TOOLS = {name: name.lower() for name in ("PRETTIER", "RUFF", "PYRIGHT")}


class SelectionTests(unittest.TestCase):
    def plan(self, mode: str, area: str | None, linux: bool = True) -> list[run_checks.Step]:
        with mock.patch.dict(os.environ, TOOLS):
            return run_checks.plan(mode, area, linux)

    def test_six_scopes_run_recorded_owners_without_qualification(self) -> None:
        expected = {
            "authority": "authenticated corpus",
            "core": "local Git 2.55.0 adapters",
            "service": "Linux source linux_process",
            "tools": "tools/dev/test_robustness.py",
            "release": "tools/release/test_qualification.py",
            "docs": "tools/checks/check_markdown_links.py",
        }
        for area, owner in expected.items():
            with self.subTest(area=area):
                steps = self.plan("check", area)

                def recording(command: tuple[str, ...], *_args: object, **_kwargs: object) -> str:
                    if "--message-format=json" in command:
                        return '{"reason":"compiler-artifact","executable":"/built/executable"}\n'
                    if "--ignored" in command and "gateway::git::tests::real_git_" not in command:
                        return ""
                    return "witness: test\n"

                with mock.patch.object(run_checks, "execute", side_effect=recording) as execute:
                    run_checks.run_steps(steps, ROOT, {}, 5)
                commands = [call.args[0] for call in execute.call_args_list]
                self.assertIn(owner, [step.owner for step in steps])
                self.assertEqual(commands[-1], ("git", "diff", "--check"))
                for command in commands:
                    self.assertFalse(set(command) & {"docker", "kind", "systemctl", "llvm-cov"})
                    self.assertNotIn("--include-ignored", command)
                    self.assertFalse(any("assemble_artifact.py" == part for part in command))
                if area == "docs":
                    self.assertFalse(any(command[0] == "cargo" for command in commands))

    def test_aggregate_runs_each_default_owner_once_and_explicit_linux_targets(self) -> None:
        steps = self.plan("check", None)
        commands = [step.command for step in steps]
        workspace = ("cargo", "test", "--locked", "--workspace", "--lib", "--bins", "--tests")
        self.assertEqual(commands.count(workspace), 1)
        for target in ("linux_process", "service_mcp"):
            matching = [step for step in steps if step.owner == f"Linux source {target}"]
            self.assertEqual(len(matching), 1)
            self.assertIn("test-harness", matching[0].command)
            self.assertTrue(matching[0].tests)
        client = next(step for step in steps if step.owner == "feature-enabled client failures")
        self.assertIn("client_failures::", client.command)
        git = next(step for step in steps if step.owner == "local Git 2.55.0 adapters")
        self.assertIn("gateway::git::tests::real_git_", git.command)
        self.assertIn("--ignored", git.command)
        qualification = next(
            step for step in steps if step.owner == "tools/release/test_qualification.py"
        )
        self.assertEqual(qualification.command, ("python3", "tools/release/test_qualification.py"))
        self.assertNotIn("CallerContainerTests", qualification.command)
        self.assertFalse(any("rust_imports" in command for command in commands))
        self.assertIn(("cargo", "test", "--locked", "--workspace", "--doc"), commands)

    def test_bin_only_tools_selection_is_accepted_by_real_cargo(self) -> None:
        steps = self.plan("check", "tools")
        tests = next(step for step in steps if step.owner == "tools")
        self.assertFalse(any("--doc" in step.command for step in steps))
        output = run_checks.execute(
            (*tests.command, "--", "--list", "--format", "terse"),
            ROOT,
            dict(os.environ),
            60,
            capture=True,
        )
        self.assertIn("commands_preserve_modes_and_reject_extra_arguments: test", output)

    def test_ci_aliases_partition_the_same_mapping_without_dropping_linux_owners(self) -> None:
        steps = self.plan("check", None)
        lanes = {
            name: [step for step in steps if step.lane == name]
            for name in ("static", "rust", "doc")
        }
        self.assertEqual(sum(map(len, lanes.values())), len(steps))
        rust_owners = {step.owner for step in lanes["rust"]}
        self.assertTrue(
            {
                "local Git 2.55.0 adapters",
                "Linux source linux_process",
                "Linux source service_mcp",
                "feature-enabled client failures",
                "examples/test_fresh_session_caller.py",
            }
            <= rust_owners
        )
        static_owners = {step.owner for step in lanes["static"]}
        self.assertIn("tools/release/test_qualification.py", static_owners)
        self.assertNotIn("default workspace", static_owners)
        self.assertEqual([step.owner for step in lanes["doc"]], ["workspace doctests"])

    def test_caller_paths_come_from_cargo_and_are_ready_before_caller(self) -> None:
        steps = self.plan("test", "service")
        builds = [step for step in steps if step.executable_environment]
        self.assertEqual(
            {step.executable_environment for step in builds},
            {"KAPSEL_TEST_INSPECT", "KAPSEL_TEST_BRIDGE"},
        )
        caller_position = next(
            index
            for index, step in enumerate(steps)
            if step.owner == "examples/test_fresh_session_caller.py"
        )
        self.assertTrue(all(steps.index(step) < caller_position for step in builds))
        environment: dict[str, str] = {}
        with mock.patch.object(
            run_checks,
            "execute",
            return_value='{"reason":"compiler-artifact","executable":"/configured-target/a-binary"}\n',
        ):
            run_checks.run_steps(builds, ROOT, environment, 5)
        self.assertEqual(environment["KAPSEL_TEST_BRIDGE"], "/configured-target/a-binary")

    def test_missing_or_empty_cargo_executable_cannot_skip_real_caller(self) -> None:
        build = next(
            step
            for step in self.plan("test", "service")
            if step.executable_environment == "KAPSEL_TEST_BRIDGE"
        )
        for output in ("", "{}\n", '{"reason":"compiler-artifact","executable":""}\n'):
            with (
                self.subTest(output=output),
                mock.patch.object(run_checks, "execute", return_value=output),
            ):
                with self.assertRaisesRegex(RuntimeError, "did not identify one executable"):
                    run_checks.run_steps([build], ROOT, {}, 5)

    def test_shell_enumeration_failure_cannot_be_hidden_by_successful_linter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tools/dev").mkdir(parents=True)
            enumerator = root / "enumerator"
            linter = root / "linter"
            enumerator.write_text("#!/bin/sh\nprintf 'some-file.sh\\0'\nexit 7\n")
            linter.write_text("#!/bin/sh\ntouch lint-ran\nexit 0\n")
            enumerator.chmod(0o755)
            linter.chmod(0o755)
            (root / "tools/dev/dev-tools.sh").write_text(
                f'SHFMT="{enumerator}"\nSHELLCHECK="{linter}"\n'
            )
            result = subprocess.run(
                ["sh", str(ROOT / "tools/checks/check-shell.sh")], cwd=root, timeout=5, check=False
            )
            self.assertEqual(result.returncode, 7)
            self.assertFalse((root / "lint-ran").exists())

    def test_non_linux_omits_only_linux_execution_and_iteration_omits_lints(self) -> None:
        steps = self.plan("test", "service", linux=False)
        self.assertFalse(any("Linux source" in step.owner for step in steps))
        self.assertFalse(any("clippy" in step.command for step in steps))
        self.assertIn("service", [step.owner for step in steps])

    def test_empty_selection_is_not_success_and_listing_uses_identical_arguments(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "empty owner"):
            run_checks.run_steps([], ROOT, {}, 5)
        step = run_checks.cargo_tests(
            "filtered", "-p", "kapsel", "--lib", "real_git_", "--", "--ignored"
        )
        with mock.patch.object(run_checks, "execute", return_value="") as execute:
            with self.assertRaisesRegex(RuntimeError, "empty runnable test selection"):
                run_checks.run_steps([step], ROOT, {}, 5)
        self.assertEqual(execute.call_args.args[0], (*step.command, "--list", "--format", "terse"))
        self.assertEqual(execute.call_count, 1)

    def test_ignored_only_listing_cannot_count_as_runnable_coverage(self) -> None:
        step = run_checks.cargo_tests("ignored-only target", "-p", "kapsel", "--lib")
        with mock.patch.object(
            run_checks, "execute", return_value="ignored_witness: test\n"
        ) as execute:
            with self.assertRaisesRegex(RuntimeError, "empty runnable test selection"):
                run_checks.run_steps([step], ROOT, {}, 5)
        self.assertEqual(execute.call_count, 2)
        self.assertIn("--ignored", execute.call_args.args[0])

    def test_missing_executable_nonzero_and_timeout_cannot_pass(self) -> None:
        environment = dict(os.environ)
        for command, exception in (
            (("/nonexistent-kapsel-gate-tool",), FileNotFoundError),
            (("sh", "-c", "exit 9"), RuntimeError),
            (("sh", "-c", "sleep 5"), subprocess.TimeoutExpired),
        ):
            with self.subTest(command=command), self.assertRaises(exception):
                run_checks.execute(command, ROOT, environment, 1)


class QualificationRoutingTests(unittest.TestCase):
    def test_archive_qualifiers_refuse_missing_archive_before_running_owner(self) -> None:
        for boundary in ("artifact", "reproducibility", "kubernetes", "git", "native"):
            result = subprocess.run(
                ["sh", "scripts/qualify.sh", boundary],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires --archive A", result.stderr)

    def test_native_uses_verifier_returned_top_level_not_extraction_parent(self) -> None:
        artifact = "/new-extraction/kapsel-release"
        with (
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.object(qualify_native.sys, "platform", "linux"),
            mock.patch.object(
                qualify_native.sys,
                "argv",
                [
                    "qualify_native",
                    "--archive",
                    "A",
                    "--revision",
                    "R",
                    "--extract-to",
                    "/new-extraction",
                ],
            ),
            mock.patch.object(
                qualify_native.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout=artifact + "\n"),
            ) as run,
        ):
            self.assertEqual(qualify_native.main(), 0)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("--extract-to", calls[0])
        self.assertIn(artifact + "/share/kapsel/qualification.py", calls[1])
        self.assertEqual(calls[1][calls[1].index("--artifact") + 1], artifact)
        self.assertNotIn("assemble_artifact.py", calls[0])


class GitPrerequisiteTests(unittest.TestCase):
    def test_absolute_supported_executable_and_wrong_missing_relative_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            git = Path(temporary) / "git"
            with self.assertRaises(FileNotFoundError):
                resolve_git.resolve_git(str(git))
            with self.assertRaisesRegex(ValueError, "absolute"):
                resolve_git.resolve_git("relative/git")
            git.write_text("#!/bin/sh\nprintf 'git version 2.54.0\\n'\n")
            git.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "version mismatch"):
                resolve_git.resolve_git(str(git))
            git.write_text("#!/bin/sh\nprintf 'git version 2.55.0\\n'\n")
            self.assertEqual(resolve_git.resolve_git(str(git)), git.resolve())


if __name__ == "__main__":
    unittest.main()
