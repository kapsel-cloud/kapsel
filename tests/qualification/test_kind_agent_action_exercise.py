"""Offline checks for the packaged journey's independent retained-evidence reader."""

import pathlib
import sqlite3
import tempfile
import unittest

from kind_agent_action_exercise import finalized_evidence, retained_row


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.journal = pathlib.Path(self.temporary.name) / "journal.sqlite3"
        with sqlite3.connect(self.journal) as connection:
            connection.executescript(
                """
                PRAGMA user_version = 6;
                CREATE TABLE kubernetes_image_operations (
                    operation_id TEXT PRIMARY KEY, state TEXT,
                    signed_authorization_grant BLOB, receipt_bytes BLOB, receipt_key_id TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO kubernetes_image_operations VALUES (?, ?, ?, ?, ?)",
                ("original", "finalized", b"original grant", b"original receipt", "original-key"),
            )
        self.original_bytes = self.journal.read_bytes()

    def test_exact_original_bytes_are_read_without_modifying_history(self) -> None:
        self.assertEqual(
            finalized_evidence(self.journal, "original"),
            (b"original grant", b"original receipt", "original-key"),
        )
        self.assertEqual(
            retained_row(self.journal, "original"),
            ("original", "finalized", b"original grant", b"original receipt", "original-key"),
        )
        self.assertEqual(self.journal.read_bytes(), self.original_bytes)

    def test_missing_identity_and_unfinalized_history_are_not_evidence(self) -> None:
        with self.assertRaises(AssertionError):
            finalized_evidence(self.journal, "other")
        with self.assertRaises(AssertionError):
            retained_row(self.journal, "other")
        with sqlite3.connect(self.journal) as connection:
            connection.execute("UPDATE kubernetes_image_operations SET state = 'receiver_observed'")
        with self.assertRaises(AssertionError):
            finalized_evidence(self.journal, "original")
        self.assertEqual(retained_row(self.journal, "original")[1], "receiver_observed")

    def test_old_format_is_rejected_unchanged(self) -> None:
        with sqlite3.connect(self.journal) as connection:
            connection.execute("PRAGMA user_version = 5")
        original = self.journal.read_bytes()
        with self.assertRaises(AssertionError):
            finalized_evidence(self.journal, "original")
        with self.assertRaises(AssertionError):
            retained_row(self.journal, "original")
        self.assertEqual(self.journal.read_bytes(), original)

    def test_oversized_or_wrong_type_evidence_is_rejected(self) -> None:
        for column, value in (
            ("signed_authorization_grant", b"g" * 4097),
            ("receipt_bytes", b"r" * 16385),
            ("receipt_key_id", "k" * 129),
            ("receipt_key_id", "é" * 128),
            ("receipt_bytes", "not a blob"),
        ):
            with self.subTest(column=column, value_type=type(value).__name__):
                with sqlite3.connect(self.journal) as connection:
                    connection.execute(
                        f"UPDATE kubernetes_image_operations SET {column} = ?", (value,)
                    )
                with self.assertRaises(AssertionError):
                    finalized_evidence(self.journal, "original")
                with sqlite3.connect(self.journal) as connection:
                    connection.execute(
                        """UPDATE kubernetes_image_operations
                        SET signed_authorization_grant = ?, receipt_bytes = ?, receipt_key_id = ?""",
                        (b"original grant", b"original receipt", "original-key"),
                    )

    def test_missing_journal_is_not_created(self) -> None:
        missing = self.journal.with_name("missing.sqlite3")
        with self.assertRaises(AssertionError):
            finalized_evidence(missing, "original")
        self.assertFalse(missing.exists())

    def test_symlink_journal_is_rejected(self) -> None:
        link = self.journal.with_name("linked.sqlite3")
        link.symlink_to(self.journal)
        with self.assertRaises(AssertionError):
            finalized_evidence(link, "original")


if __name__ == "__main__":
    unittest.main()
