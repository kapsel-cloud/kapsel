#!/usr/bin/env python3
"""Focused backup/restore tests for artifact-only release upgrade smoke."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "smoke_release_upgrade",
    ROOT / "scripts" / "smoke-release-upgrade.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the release upgrade smoke")
UPGRADE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPGRADE)


class ReleaseUpgradeBackupTests(unittest.TestCase):
    def test_verified_backup_restores_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-upgrade-backup-") as temporary:
            journal = pathlib.Path(temporary) / "journal.sqlite3"
            journal.write_bytes(b"old-generation")
            journal.chmod(0o600)
            backup, checksum = UPGRADE.private_backup(journal)
            journal.write_bytes(b"candidate-generation")
            UPGRADE.restore_backup(journal, backup, checksum)
            self.assertEqual(journal.read_bytes(), b"old-generation")

    def test_corrupt_checksum_refuses_before_active_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-upgrade-corrupt-") as temporary:
            journal = pathlib.Path(temporary) / "journal.sqlite3"
            journal.write_bytes(b"old-generation")
            journal.chmod(0o600)
            backup, checksum = UPGRADE.private_backup(journal)
            journal.write_bytes(b"candidate-generation")
            checksum.write_text("0" * 64 + "\n")
            with self.assertRaisesRegex(RuntimeError, "backup checksum mismatch"):
                UPGRADE.restore_backup(journal, backup, checksum)
            self.assertEqual(journal.read_bytes(), b"candidate-generation")

    def test_symlinked_backup_refuses_before_active_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-upgrade-link-") as temporary:
            root = pathlib.Path(temporary)
            journal = root / "journal.sqlite3"
            journal.write_bytes(b"old-generation")
            journal.chmod(0o600)
            backup, checksum = UPGRADE.private_backup(journal)
            original = root / "original.backup"
            backup.replace(original)
            backup.symlink_to(original)
            journal.write_bytes(b"candidate-generation")
            with self.assertRaises(OSError):
                UPGRADE.restore_backup(journal, backup, checksum)
            self.assertEqual(journal.read_bytes(), b"candidate-generation")


if __name__ == "__main__":
    unittest.main()
