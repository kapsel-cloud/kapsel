"""Positive executable-custody checks for the confined caller probe."""

import importlib.util
import os
import pathlib
import stat
import unittest
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "caller_custody_probe", pathlib.Path(__file__).with_name("caller_custody_probe.py")
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
ROOT_DIRECTORY = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)


class ExecutableCustodyTests(unittest.TestCase):
    def test_root_owned_runnable_executable_in_protected_directory_passes(self) -> None:
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with (
            mock.patch.object(PROBE.os, "stat", side_effect=[metadata, ROOT_DIRECTORY]),
            mock.patch.object(PROBE.os, "access", side_effect=lambda _path, mode: mode == os.X_OK),
        ):
            PROBE.check_executable("/usr/bin/kapsel-service-mcp")

    def test_missing_executable_does_not_count_as_custody(self) -> None:
        with mock.patch.object(PROBE.os, "stat", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                PROBE.check_executable("/usr/bin/kapsel-service-mcp")

    def test_caller_owned_or_nonregular_executable_fails(self) -> None:
        for mode, owner in [(stat.S_IFDIR | 0o755, 0), (stat.S_IFREG | 0o555, 10001)]:
            with self.subTest(mode=mode, owner=owner):
                metadata = SimpleNamespace(st_mode=mode, st_uid=owner)
                with mock.patch.object(PROBE.os, "stat", side_effect=[metadata, ROOT_DIRECTORY]):
                    with self.assertRaises(AssertionError):
                        PROBE.check_executable("/usr/bin/kapsel-service-mcp")

    def test_caller_can_neither_modify_nor_replace_executable(self) -> None:
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        for writable in ["/usr/bin", "/usr/bin/kapsel-service-mcp"]:
            with self.subTest(writable=writable):
                with (
                    mock.patch.object(PROBE.os, "stat", side_effect=[metadata, ROOT_DIRECTORY]),
                    mock.patch.object(
                        PROBE.os,
                        "access",
                        side_effect=lambda path, mode, writable_path=writable: (
                            mode == os.X_OK or path == writable_path
                        ),
                    ),
                ):
                    with self.assertRaises(AssertionError):
                        PROBE.check_executable("/usr/bin/kapsel-service-mcp")

    def test_caller_owned_executable_directory_fails(self) -> None:
        executable = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=10001)
        with mock.patch.object(PROBE.os, "stat", side_effect=[executable, directory]):
            with self.assertRaisesRegex(AssertionError, "directory is not root-owned"):
                PROBE.check_executable("/usr/bin/kapsel-service-mcp")

    def test_nonexecutable_installed_file_fails(self) -> None:
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with (
            mock.patch.object(PROBE.os, "stat", side_effect=[metadata, ROOT_DIRECTORY]),
            mock.patch.object(PROBE.os, "access", return_value=False),
        ):
            with self.assertRaises(AssertionError):
                PROBE.check_executable("/usr/bin/kapsel-service-mcp")


if __name__ == "__main__":
    unittest.main()
