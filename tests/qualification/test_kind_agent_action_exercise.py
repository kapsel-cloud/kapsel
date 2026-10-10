"""Offline checks for the packaged journey's independent retained-evidence reader."""

import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from kind_agent_action_exercise import finalized_evidence, retained_row
from run_kind_agent_action_workflow import CODEX_OUTPUT_LIMIT, run, run_bounded_process


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


class BoundedSubprocessTests(unittest.TestCase):
    def test_valid_stdin_stdout_and_stderr_are_captured_as_bytes(self) -> None:
        script = (
            "import sys\n"
            "data = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(data[::-1])\n"
            "sys.stderr.buffer.write(b'diagnostic')\n"
        )
        result = run_bounded_process([sys.executable, "-c", script], data=b"abc", timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"cba")
        self.assertEqual(result.stderr, b"diagnostic")

    def test_output_overflow_is_rejected_before_accumulating_more_bytes(self) -> None:
        for stream in ["stdout", "stderr"]:
            script = f"import sys; sys.{stream}.buffer.write(b'x' * 17); sys.{stream}.flush()"
            with self.subTest(stream=stream):
                with self.assertRaisesRegex(RuntimeError, "confined Codex output exceeded"):
                    run_bounded_process(
                        [sys.executable, "-c", script],
                        timeout=5,
                        output_limit=16,
                        overflow_message="confined Codex output exceeded its byte bound",
                    )

    def test_codex_capture_keeps_256_kib_limit(self) -> None:
        script = f"import sys; sys.stdout.buffer.write(b'x' * {CODEX_OUTPUT_LIMIT + 1})"
        with self.assertRaisesRegex(RuntimeError, "confined Codex output exceeded"):
            run_bounded_process(
                [sys.executable, "-c", script],
                timeout=5,
                output_limit=CODEX_OUTPUT_LIMIT,
                overflow_message="confined Codex output exceeded its byte bound",
            )

    def test_deadline_includes_eof_then_child_wait_and_reaps_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = pathlib.Path(temporary) / "pid"
            script = (
                "import os, pathlib, sys, time\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                "os.close(1)\n"
                "os.close(2)\n"
                "time.sleep(30)\n"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                run_bounded_process([sys.executable, "-c", script], timeout=0.2)
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            pid = int(pid_file.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_long_stdin_write_does_not_block_pipe_draining(self) -> None:
        payload = b"a" * (512 * 1024)
        script = (
            "import sys\n"
            "sys.stdout.buffer.write(b'x' * (512 * 1024))\n"
            "sys.stdout.flush()\n"
            "data = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(str(len(data)).encode())\n"
        )
        result = run_bounded_process([sys.executable, "-c", script], data=payload, timeout=5)
        self.assertEqual(result.stdout, b"x" * len(payload) + str(len(payload)).encode())

    def test_run_failure_diagnostic_omits_secret_argv_and_stderr(self) -> None:
        script = "import sys; sys.stderr.write('SECRET_STDERR'); raise SystemExit(7)"
        with self.assertRaises(RuntimeError) as raised:
            run([sys.executable, "-c", script, "SECRET_ARGV"], timeout=5)
        message = str(raised.exception)
        self.assertEqual(message, "command exited 7")
        self.assertNotIn("SECRET_ARGV", message)
        self.assertNotIn("SECRET_STDERR", message)


if __name__ == "__main__":
    unittest.main()
