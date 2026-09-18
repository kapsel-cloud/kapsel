#!/usr/bin/env python3
"""Prove formatter ordering and failure behavior without rewriting repository files."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = """#!/bin/sh
set -eu
name=${0##*/}
phase=format
case "$*" in
  *--version*|*--show-settings*) phase=preflight ;;
esac
printf '%s|%s|%s|%s\\n' "$name" "$phase" "$PWD" "$*" >> "$FORMAT_LOG"
if [ "$name:$phase" = "${FAIL_AT:-}" ]; then
  exit 1
fi
if [ "$name" = prettier ] && [ "$phase" = preflight ]; then
  printf '%s\\n' "${TEST_PRETTIER_VERSION}"
fi
if [ "$name" = ruff ] && [ "$*" = --version ]; then
  printf 'ruff %s\\n' "${TEST_RUFF_VERSION}"
fi
"""


class FormattingPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="kapsel-format-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "scripts").mkdir()
        for name in ("format.sh", "dev-tools.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        (self.root / "fuzz").mkdir()
        (self.root / "fuzz/Cargo.toml").touch()
        tools = self.root / "tools"
        tools.mkdir()
        for name in ("prettier", "cargo", "ruff"):
            path = tools / name
            path.write_text(TOOL)
            path.chmod(0o755)
        pins = subprocess.run(
            [
                "sh",
                "-c",
                '. ./scripts/dev-tools.sh; printf "%s\\n%s\\n%s\\n%s\\n%s" '
                '"$PRETTIER" "$RUFF" "$PRETTIER_VERSION" "$RUFF_VERSION" "$FORMAT_TOOLCHAIN"',
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
        }

    def run_format(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(self.root / "scripts/format.sh"), *arguments],
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
                        ("cargo", "preflight"),
                        ("ruff", "preflight"),
                        ("prettier", "format"),
                        ("cargo", "format"),
                        ("cargo", "format"),
                        ("ruff", "format"),
                    ],
                )
                checking = arguments in (("check",), ("--check",))
                for _, phase, cwd, argv in commands:
                    self.assertEqual(cwd, str(self.root))
                    if phase == "format":
                        self.assertEqual("--check" in argv.split(), checking)
                self.assertIn("--manifest-path fuzz/Cargo.toml", commands[-2][3])
                for name, phase, _, argv in commands:
                    if name == "cargo":
                        self.assertIn(f"+{self.format_toolchain}", argv.split())
                        if phase == "format":
                            self.assertIn("--config-path rustfmt-nightly.toml", argv)

    def test_missing_formatter_stops_before_writes(self) -> None:
        for name in ("prettier", "cargo", "ruff"):
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.env["FAIL_AT"] = f"{name}:preflight"
                self.assertNotEqual(self.run_format().returncode, 0)
                self.assertTrue(all(command[1] == "preflight" for command in self.commands()))

    def test_wrong_version_stops_before_writes(self) -> None:
        for variable in ("TEST_PRETTIER_VERSION", "TEST_RUFF_VERSION"):
            with self.subTest(variable=variable):
                original = self.env[variable]
                self.env[variable] = "0.0.0"
                self.assertNotEqual(self.run_format().returncode, 0)
                self.assertTrue(all(command[1] == "preflight" for command in self.commands()))
                self.env[variable] = original

    def test_format_failure_stops_later_stages(self) -> None:
        self.env["FAIL_AT"] = "prettier:format"
        self.assertNotEqual(self.run_format().returncode, 0)
        self.assertEqual(self.commands()[-1][:2], ["prettier", "format"])
        self.assertEqual(len(self.commands()), 5)

    def test_invalid_mode_runs_no_tools(self) -> None:
        self.assertEqual(self.run_format("invalid").returncode, 2)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
