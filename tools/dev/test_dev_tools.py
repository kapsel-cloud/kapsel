#!/usr/bin/env python3
"""Check read-only setup diagnosis and partial-commit behavior in disposable homes/repos."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ContributorToolsTests(unittest.TestCase):
    def test_diagnosis_does_not_install_into_empty_home(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-tools-test-") as temporary:
            home = Path(temporary)
            result = subprocess.run(
                [str(ROOT / "scripts/setup.sh"), "--check"],
                cwd=ROOT,
                env={**os.environ, "HOME": str(home)},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Prettier missing:", result.stderr)
            self.assertIn("Ruff missing:", result.stderr)
            self.assertFalse((home / ".local").exists())
            self.assertFalse((home / ".rustup").exists())
            self.assertFalse((home / ".cargo").exists())

    def test_pip_installation_ignores_ambient_destinations_and_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-setup-test-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "tools/dev").mkdir(parents=True)
            shutil.copyfile(ROOT / "scripts/setup.sh", root / "scripts/setup.sh")
            shutil.copyfile(ROOT / "tools/dev/dev-tools.sh", root / "tools/dev/dev-tools.sh")
            shutil.copyfile(ROOT / "rust-toolchain.toml", root / "rust-toolchain.toml")
            (root / ".rustup/toolchains").mkdir(parents=True)
            host = root / "bin"
            host.mkdir()
            environment = {
                **os.environ,
                "HOME": str(root),
                "RUSTUP_HOME": str(root / ".rustup"),
                "PATH": f"{host}:/usr/bin:/bin",
                "PIP_TARGET": str(root / "foreign-target"),
                "PIP_PREFIX": str(root / "foreign-prefix"),
                "PIP_CONFIG_FILE": str(root / "foreign-pip.conf"),
                "MOCK_PIP": str(root / "pip"),
                "MOCK_LOG": str(root / "pip.log"),
            }
            pins = subprocess.run(
                [
                    "sh",
                    "-c",
                    '. ./tools/dev/dev-tools.sh; printf "%s\\n" '
                    '"$PRETTIER" "$RUFF" "$SHFMT" "$SHELLCHECK" "$TAPLO" '
                    '"$PRETTIER_VERSION" "$RUFF_VERSION" "$TAPLO_VERSION"',
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            ).stdout.splitlines()

            def executable(path: Path, body: str) -> None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
                path.chmod(0o755)

            for name in ("git", "cc", "node", "npm", "rustup"):
                executable(host / name, "exit 0")
            for path, version in (
                (pins[0], pins[5]),
                (pins[2], "3.14.1"),
                (pins[3], "version: 0.11.0"),
                (pins[4], f"taplo {pins[7]}"),
            ):
                executable(Path(path), f"printf '%s\\n' {shlex.quote(version)}")
            environment["TEST_RUFF_VERSION"] = pins[6]
            executable(
                root / "pip",
                r'''[ "$PIP_CONFIG_FILE" = /dev/null ] || exit 90
[ "$1 $2 $3 $4 $5" = '-I -m pip --isolated install' ] || exit 91
printf '%s\n' "$PIP_CONFIG_FILE|$*" >> "$MOCK_LOG"
printf '%s\n' '#!/bin/sh' "printf 'ruff %s\\n' '$TEST_RUFF_VERSION'" > "${0%/*}/ruff"
chmod +x "${0%/*}/ruff"''',
            )
            executable(
                host / "python3",
                f"""if [ "$1 $2" = '-m venv' ]; then
  mkdir -p "$3/bin"
  cp "$MOCK_PIP" "$3/bin/python"
else
  exec {shlex.quote(sys.executable)} "$@"
fi""",
            )
            result = subprocess.run(
                ["sh", str(root / "scripts/setup.sh")],
                cwd=host,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(Path(pins[1]).is_file())
            self.assertIn("/dev/null|-I -m pip --isolated install", (root / "pip.log").read_text())
            self.assertFalse((root / "foreign-target").exists())
            self.assertFalse((root / "foreign-prefix").exists())

    def test_hook_checks_index_despite_unrelated_or_partial_edits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-hook-test-") as temporary:
            root = Path(temporary)

            def git(*arguments: str) -> None:
                subprocess.run(
                    ["git", *arguments], cwd=root, check=True, capture_output=True, timeout=10
                )

            def hook() -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    ["sh", str(ROOT / ".githooks/pre-commit")],
                    cwd=root,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

            git("init", "-q")
            path = root / "partial.txt"
            path.write_text("staged clean line\n")
            git("add", "partial.txt")
            path.write_text("unstaged trailing whitespace  \n")
            (root / "unrelated.txt").write_text("untracked  \n")
            self.assertEqual(hook().returncode, 0)
            git("add", "partial.txt")
            path.write_text("worktree clean but index bad\n")
            self.assertNotEqual(hook().returncode, 0)


if __name__ == "__main__":
    unittest.main()
