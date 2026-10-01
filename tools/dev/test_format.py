#!/usr/bin/env python3
"""Prove formatter ordering and failure behavior without rewriting repository files."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = """#!/bin/sh
set -eu
name=${0##*/}
phase=format
case "$*" in
  *--version*|*--show-settings*|*which*) phase=preflight ;;
esac
printf '%s|%s|%s|%s\\n' "$name" "$phase" "$PWD" "$*" >> "$FORMAT_LOG"
if [ "$name:$phase" = "${FAIL_AT:-}" ]; then
  exit 1
fi
if [ "$name" = rustup ]; then
  printf '%s\\n' "$TEST_RUSTFMT"
fi
if [ "$name" = cargo ] && [ "$RUSTFMT" != "$TEST_RUSTFMT" ]; then
  exit 88
fi
if [ "$name" = prettier ] && [ "$phase" = preflight ]; then
  printf '%s\\n' "${TEST_PRETTIER_VERSION}"
fi
if [ "$name" = ruff ] && [ "$*" = --version ]; then
  printf 'ruff %s\\n' "${TEST_RUFF_VERSION}"
fi
if [ "$name" = taplo ] && [ "$phase" = preflight ]; then
  printf 'taplo %s\\n' "${TEST_TAPLO_VERSION}"
fi
if [ "$name" = shfmt ] && [ "$phase" = preflight ]; then
  printf '3.14.1\\n'
fi
if [ "$name" = shellcheck ] && [ "$phase" = preflight ]; then
  printf 'version: 0.11.0\\n'
fi
"""


class FormattingPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="kapsel-format-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, timeout=10)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/fmt.sh", self.root / "scripts/fmt.sh")
        (self.root / "tools/dev").mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/dev/dev-tools.sh", self.root / "tools/dev/dev-tools.sh")
        (self.root / "fuzz").mkdir()
        (self.root / "fuzz/Cargo.toml").touch()
        tools = self.root / "bin"
        tools.mkdir()
        for name in (
            "prettier",
            "cargo",
            "ruff",
            "shfmt",
            "shellcheck",
            "taplo",
            "rustup",
            "rustfmt",
        ):
            path = tools / name
            path.write_text(TOOL)
            path.chmod(0o755)
        pins = subprocess.run(
            [
                "sh",
                "-c",
                '. ./tools/dev/dev-tools.sh; printf "%s\\n%s\\n%s\\n%s\\n%s\\n%s\\n%s" '
                '"$PRETTIER" "$RUFF" "$PRETTIER_VERSION" "$RUFF_VERSION" '
                '"$FORMAT_TOOLCHAIN" "$TAPLO" "$TAPLO_VERSION"',
            ],
            cwd=self.root,
            env={**os.environ, "HOME": str(self.root)},
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.splitlines()
        for name, destination in zip(("prettier", "ruff"), pins[:2], strict=True):
            path = Path(destination)
            path.parent.mkdir(parents=True)
            path.symlink_to(tools / name)
        for name in ("shfmt", "shellcheck"):
            (Path(pins[1]).parent / name).symlink_to(tools / name)
        taplo = Path(pins[5])
        taplo.parent.mkdir(parents=True)
        taplo.symlink_to(tools / "taplo")
        self.format_toolchain = pins[4]
        self.log = self.root / "commands.log"
        self.env = {
            **os.environ,
            "PATH": f"{tools}:/usr/bin:/bin",
            "FORMAT_LOG": str(self.log),
            "FAIL_AT": "",
            "HOME": str(self.root),
            "TEST_PRETTIER_VERSION": pins[2],
            "TEST_RUFF_VERSION": pins[3],
            "TEST_TAPLO_VERSION": pins[6],
            "TEST_RUSTFMT": str(tools / "rustfmt"),
            "RUSTFMT": str(tools / "ambient-override"),
        }

    def run_format(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(self.root / "scripts/fmt.sh"), *arguments],
            cwd=self.root / "tools",
            env=self.env,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def commands(self) -> list[list[str]]:
        return [line.split("|", 3) for line in self.log.read_text().splitlines()]

    def test_modes_preserve_order_and_resolve_root(self) -> None:
        for arguments in ((), ("write",), ("check",), ("--check",)):
            with self.subTest(arguments=arguments):
                self.log.unlink(missing_ok=True)
                result = self.run_format(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = self.commands()
                self.assertEqual(
                    [(name, phase) for name, phase, _, _ in commands],
                    [
                        ("prettier", "preflight"),
                        ("ruff", "preflight"),
                        ("taplo", "preflight"),
                        ("shfmt", "preflight"),
                        ("shellcheck", "preflight"),
                        ("rustup", "preflight"),
                        ("cargo", "preflight"),
                        ("ruff", "preflight"),
                        ("prettier", "format"),
                        ("cargo", "format"),
                        ("cargo", "format"),
                        ("ruff", "format"),
                        ("ruff", "format"),
                        ("taplo", "format"),
                        ("shfmt", "format"),
                    ],
                )
                checking = arguments in (("check",), ("--check",))
                for name, phase, cwd, argv in commands:
                    self.assertEqual(cwd, str(self.root))
                    if phase == "format" and name == "shfmt":
                        self.assertIn("-d" if checking else "-w", argv.split())
                        self.assertIn("-i 2", argv)
                    elif phase == "format" and not argv.startswith("check "):
                        self.assertEqual("--check" in argv.split(), checking)
                self.assertIn("--select I", commands[-4][3])
                self.assertEqual("--fix" in commands[-4][3].split(), not checking)
                self.assertIn("--manifest-path fuzz/Cargo.toml", commands[-5][3])
                for name, phase, _, argv in commands:
                    if name == "cargo":
                        self.assertIn(f"+{self.format_toolchain}", argv.split())
                        if phase == "format":
                            self.assertIn("--config-path rustfmt-nightly.toml", argv)

    def test_missing_formatter_stops_before_writes(self) -> None:
        for name in ("prettier", "cargo", "ruff", "taplo", "shfmt", "shellcheck", "rustup"):
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.env["FAIL_AT"] = f"{name}:preflight"
                self.assertNotEqual(self.run_format().returncode, 0)
                self.assertTrue(all(command[1] == "preflight" for command in self.commands()))

    def test_wrong_version_stops_before_writes(self) -> None:
        for variable in ("TEST_PRETTIER_VERSION", "TEST_RUFF_VERSION", "TEST_TAPLO_VERSION"):
            with self.subTest(variable=variable):
                original = self.env[variable]
                self.env[variable] = "0.0.0"
                result = self.run_format()
                self.assertNotEqual(result.returncode, 0)
                name = {
                    "TEST_PRETTIER_VERSION": "Prettier",
                    "TEST_RUFF_VERSION": "Ruff",
                    "TEST_TAPLO_VERSION": "Taplo",
                }[variable]
                self.assertIn(f"{name} unavailable or mismatched: expected", result.stderr)
                self.assertTrue(all(command[1] == "preflight" for command in self.commands()))
                self.env[variable] = original

    def test_format_failure_stops_later_stages(self) -> None:
        self.env["FAIL_AT"] = "prettier:format"
        self.assertNotEqual(self.run_format().returncode, 0)
        self.assertEqual(self.commands()[-1][:2], ["prettier", "format"])

    def test_invalid_mode_runs_no_tools(self) -> None:
        self.assertEqual(self.run_format("invalid").returncode, 2)
        self.assertFalse(self.log.exists())


class RustWidthTests(unittest.TestCase):
    def test_checks_tracked_and_untracked_source_but_not_ignored_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-width-test-") as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, timeout=10)
            (root / ".gitignore").write_text("ignored.rs\n")
            (root / "ignored.rs").write_text("x" * 101 + "\n")
            tracked = root / "tracked.rs"
            untracked = root / "untracked.rs"
            tracked.write_text("x" * 100 + "\n")
            untracked.write_text("x" * 101 + "\n")
            subprocess.run(["git", "add", "tracked.rs"], cwd=root, check=True, timeout=10)

            def check_width() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["sh", str(ROOT / "tools/checks/check-rust-width.sh")],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

            result = check_width()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("untracked.rs:1: line is 101 bytes", result.stdout)
            self.assertNotIn("ignored.rs", result.stdout)
            untracked.write_text("x" * 100 + "\n")
            self.assertEqual(check_width().returncode, 0)
            tracked.write_text("x" * 101 + "\n")
            result = check_width()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("tracked.rs:1: line is 101 bytes", result.stdout)


if __name__ == "__main__":
    unittest.main()
