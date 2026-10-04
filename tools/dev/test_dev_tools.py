#!/usr/bin/env python3
"""Check read-only setup diagnosis and partial-commit behavior in disposable homes/repos."""

from __future__ import annotations

import json
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
            (
                prettier_path,
                ruff_path,
                shfmt_path,
                shellcheck_path,
                taplo_path,
                prettier_version,
                ruff_version,
                taplo_version,
                pyright_path,
                pyright_version,
            ) = subprocess.run(
                [
                    "sh",
                    "-c",
                    '. ./tools/dev/dev-tools.sh; printf "%s\\n" '
                    '"$PRETTIER" "$RUFF" "$SHFMT" "$SHELLCHECK" "$TAPLO" '
                    '"$PRETTIER_VERSION" "$RUFF_VERSION" "$TAPLO_VERSION" '
                    '"$PYRIGHT" "$PYRIGHT_VERSION"',
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

            for name in ("git", "cc", "node", "rustup"):
                executable(host / name, "exit 0")
            for path, version in (
                (prettier_path, prettier_version),
                (shfmt_path, "3.14.1"),
                (shellcheck_path, "version: 0.11.0"),
                (taplo_path, f"taplo {taplo_version}"),
            ):
                executable(Path(path), f"printf '%s\\n' {shlex.quote(version)}")

            environment["TEST_PYRIGHT_PATH"] = pyright_path
            environment["TEST_PYRIGHT_VERSION"] = pyright_version
            executable(
                host / "npm",
                r'''[ "$1" = install ] || exit 92
printf '%s\n' "$*" >> "$HOME/npm.log"
mkdir -p "${TEST_PYRIGHT_PATH%/*}"
printf '%s\n' '#!/bin/sh' "printf 'pyright %s\\n' '$TEST_PYRIGHT_VERSION'" > "$TEST_PYRIGHT_PATH"
chmod +x "$TEST_PYRIGHT_PATH"''',
            )

            environment["TEST_RUFF_VERSION"] = ruff_version
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
            self.assertTrue(Path(ruff_path).is_file())
            installed = (root / "npm.log").read_text()
            self.assertIn(f"pyright@{pyright_version}", installed)
            self.assertIn("--ignore-scripts --no-audit --no-fund", installed)
            self.assertIn("--no-save --package-lock=false", installed)
            self.assertIn("/dev/null|-I -m pip --isolated install", (root / "pip.log").read_text())
            self.assertFalse((root / "foreign-target").exists())
            self.assertFalse((root / "foreign-prefix").exists())

    def test_type_checker_refuses_missing_and_mismatched_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-type-tool-test-") as temporary:
            checker = Path(temporary) / "pyright"

            def check() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "sh",
                        "-c",
                        '. ./tools/dev/dev-tools.sh; PYRIGHT="$1"; check_type_checker',
                        "sh",
                        str(checker),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

            self.assertNotEqual(check().returncode, 0)
            checker.write_text("#!/bin/sh\nprintf 'pyright wrong\\n'\n")
            checker.chmod(0o755)
            self.assertNotEqual(check().returncode, 0)
            # The shared pin is not exported; the executable reads it independently.
            checker.write_text(
                f'#!/bin/sh\n. "{ROOT}/tools/dev/dev-tools.sh"\n'
                'printf "pyright %s\\n" "$PYRIGHT_VERSION"\n'
            )
            self.assertEqual(check().returncode, 0)

    def test_type_gate_rejects_standard_and_strict_regressions(self) -> None:
        checker = subprocess.run(
            ["sh", "-c", '. ./tools/dev/dev-tools.sh; printf "%s" "$PYRIGHT"'],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout
        with tempfile.TemporaryDirectory(prefix="kapsel-type-gate-test-") as temporary:
            root = Path(temporary)
            config = root / "pyrightconfig.json"
            config.write_bytes((ROOT / "pyrightconfig.json").read_bytes())
            strict = root / "tools/checks/check_source_privacy.py"
            standard = root / "examples/fresh_session_caller.py"
            strict.parent.mkdir(parents=True)
            standard.parent.mkdir(parents=True)
            strict.write_text("def identity(value):\n    return value\n")
            standard.write_text("def text() -> str:\n    return 7\n")
            result = subprocess.run(
                [checker, "--project", str(config), "--outputjson"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            diagnostics = json.loads(result.stdout)["generalDiagnostics"]
            rules = {item["rule"] for item in diagnostics}
            self.assertIn("reportReturnType", rules)
            self.assertIn("reportUnknownParameterType", rules)
            self.assertIn("reportMissingParameterType", rules)

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
