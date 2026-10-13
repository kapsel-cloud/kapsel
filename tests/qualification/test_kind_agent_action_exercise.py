"""Offline checks for the packaged journey's independent retained-evidence reader."""

import ast
import hashlib
import http.server
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import run_kind_agent_action_workflow as JOURNEY
from kind_agent_action_exercise import finalized_evidence, retained_row
from kind_receiver_barrier import LIMIT, send_reply, upstream
from run_kind_agent_action_workflow import (
    CODEX_OUTPUT_LIMIT,
    observation_read_counts,
    run,
    run_agent_process,
    run_bounded_process,
)


class ReceiverBarrierTests(unittest.TestCase):
    def test_service_loss_can_close_headers_or_body_without_fixture_failure(self) -> None:
        for exception in (BrokenPipeError, ConnectionResetError):
            for closed_at in ("headers", "body"):
                with self.subTest(exception=exception, closed_at=closed_at):
                    handler = mock.Mock()
                    write = handler.end_headers if closed_at == "headers" else handler.wfile.write
                    write.side_effect = exception()
                    send_reply(handler, 200, b"{}")
                    handler.send_response.assert_called_once_with(200)
        handler = mock.Mock()
        handler.end_headers.side_effect = ValueError("invalid header")
        with self.assertRaises(ValueError):
            send_reply(handler, 200, b"{}")

    def test_real_forwarding_keeps_conditional_patch_authentication_and_conflict(self) -> None:
        requests = []

        class Api(http.server.BaseHTTPRequestHandler):
            def do_PATCH(self):  # noqa: N802 - stdlib handler API
                body = self.rfile.read(int(self.headers["Content-Length"]))
                requests.append(
                    (self.headers["Authorization"], self.headers["User-Agent"], json.loads(body))
                )
                response = b'{"kind":"Status","code":409}'
                self.send_response(
                    200 if self.headers["Authorization"] == "Bearer fixture" else 409
                )
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format, *args):
                return

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "kubeconfig.json").write_text(
                json.dumps(
                    {
                        "clusters": [{"cluster": {"server": "unused"}}],
                        "users": [{"user": {"token": "product"}}],
                    }
                )
            )
            (root / "fixture-token").write_text("fixture")
            (root / "settings.json").write_text(json.dumps({"cases": {"race": 0}}))
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                config = json.loads((root / "kubeconfig.json").read_text())
                config["clusters"][0]["cluster"]["server"] = (
                    f"http://127.0.0.1:{server.server_port}"
                )
                (root / "kubeconfig.json").write_text(json.dumps(config))
                script = pathlib.Path(__file__).with_name("kind_receiver_barrier.py")
                with subprocess.Popen(
                    [sys.executable, "-I", str(script), str(root), str(root), str(root)],
                    stderr=subprocess.DEVNULL,
                ) as process:
                    try:
                        deadline = time.monotonic() + 5
                        while not (root / "barrier.ready").exists():
                            self.assertIsNone(process.poll())
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.01)
                        port = int((root / "barrier.ready").read_text())
                        patch = {"metadata": {"uid": "original", "resourceVersion": "opaque"}}
                        request = urllib.request.Request(
                            f"http://127.0.0.1:{port}/apis/apps/v1/namespaces/demo/deployments/agent-race?fieldManager=kapsel",
                            data=json.dumps(patch).encode(),
                            method="PATCH",
                            headers={
                                "Authorization": "Bearer product",
                                "User-Agent": "original-client",
                                "Content-Type": "application/strategic-merge-patch+json",
                            },
                        )
                        with self.assertRaises(urllib.error.HTTPError) as conflict:
                            urllib.request.urlopen(request, timeout=5)
                        self.assertEqual(conflict.exception.code, 409)
                        conflict.exception.close()
                        self.assertEqual(
                            requests,
                            [
                                (
                                    "Bearer fixture",
                                    "kapsel-journey-fixture",
                                    {"metadata": {"annotations": {"journey-fixture/race": "true"}}},
                                ),
                                ("Bearer product", "original-client", patch),
                            ],
                        )
                        record = json.loads((root / "race.patch.json").read_text())
                        self.assertEqual(record["request"], patch)
                        self.assertEqual(record["status"], 409)
                        self.assertNotIn("Bearer", (root / "race.patch.json").read_text())
                        with self.assertRaises(urllib.error.HTTPError) as repeated:
                            urllib.request.urlopen(request, timeout=5)
                        repeated.exception.close()
                        self.assertEqual(len(requests), 3)
                        self.assertEqual(requests[-1], ("Bearer product", "original-client", patch))
                        self.assertEqual(
                            (root / "barrier.violation").read_text(),
                            "duplicate product PATCH: race",
                        )
                        (root / "race.patch.request.json").unlink()
                        (root / "barrier.violation").unlink()

                        def concurrent_send():
                            try:
                                urllib.request.urlopen(request, timeout=5)
                            except urllib.error.HTTPError as error:
                                with error:
                                    return error.code
                            self.fail("conditional request unexpectedly accepted")

                        with ThreadPoolExecutor(max_workers=2) as callers:
                            results = list(callers.map(lambda _: concurrent_send(), range(2)))
                        self.assertEqual(results, [409, 409])
                        self.assertEqual(len(requests), 6)
                        self.assertEqual(
                            sum(auth == "Bearer product" for auth, _, _ in requests), 4
                        )
                        self.assertTrue((root / "barrier.violation").exists())
                    finally:
                        process.terminate()
                        process.wait(timeout=5)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_upstream_bounds_actual_response_reads(self) -> None:
        class Api(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler API
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * (LIMIT + 1))

            def log_message(self, format, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(AssertionError, "response bound"):
                upstream(f"http://127.0.0.1:{server.server_port}", None, "fixture", "/")
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


class ObservationAuditTests(unittest.TestCase):
    def test_terminal_timing_and_each_recovery_pass_have_independent_bounds(self) -> None:
        slow = {"case": "caller-loss", "started_unix_s": 0, "finished_unix_s": 179}
        self.assertEqual(
            observation_read_counts([slow], {"caller-loss": [("get", 1), ("get", 2)]}),
            {"caller-loss": 2},
        )
        for stopped_at in (100, 210):
            with self.subTest(stopped_at=stopped_at), self.assertRaises(AssertionError):
                observation_read_counts(
                    [dict(slow, finished_unix_s=stopped_at)],
                    {"caller-loss": [("get", 1), ("get", 2)]},
                )
        interrupted = {
            "case": "service-loss",
            "started_unix_s": 0,
            "finished_unix_s": 60,
            "interrupted_unix_s": 5,
            "resumed_unix_s": 10,
        }
        original = [("get", 1.0), ("patch", 2.0), ("get", 3.0), ("get", 11.0)]
        self.assertEqual(
            observation_read_counts([interrupted], {"service-loss": original}), {"service-loss": 3}
        )
        # Read counts alone must not admit a recovery lasting 390 seconds.
        with self.assertRaises(AssertionError):
            observation_read_counts(
                [dict(interrupted, finished_unix_s=400)], {"service-loss": original}
            )
        self.assertEqual(
            observation_read_counts(
                [dict(interrupted, finished_unix_s=215)], {"service-loss": original}
            ),
            {"service-loss": 3},
        )
        with self.assertRaises(AssertionError):
            observation_read_counts([interrupted], {"service-loss": original + [("get", 61.0)]})
        # Aggregate reads still fit 361, but the recovery pass has exceeded its own 180 ceiling.
        excessive = original + [("get", 12 + index / 1000) for index in range(180)]
        with self.assertRaises(AssertionError):
            observation_read_counts([interrupted], {"service-loss": excessive})
        with self.assertRaises(AssertionError):
            observation_read_counts(
                [dict(interrupted, interrupted_unix_s=2.5)], {"service-loss": original}
            )


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
        for stream in (1, 2):
            script = f"import os; os.write({stream}, b'x' * {CODEX_OUTPUT_LIMIT + 1})"
            with (
                self.subTest(stream=stream),
                self.assertRaisesRegex(RuntimeError, "confined Codex output exceeded"),
            ):
                run_agent_process([sys.executable, "-I", "-c", script], timeout=5)

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


class PackagedRunnerTests(unittest.TestCase):
    def test_journey_streams_exact_fixture_bytes_through_a_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            docker = root / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import hashlib, sys\n"
                "assert sys.argv[1:] == ['start', '--attach', '--interactive', 'fixture']\n"
                "source = sys.stdin.buffer.read()\n"
                "compile(source, '<transferred-fixture>', 'exec')\n"
                "print(hashlib.sha256(source).hexdigest())\n"
            )
            docker.chmod(0o700)
            source = JOURNEY.EXERCISE_SOURCE.read_bytes()
            with mock.patch.dict(os.environ, PATH=str(root)):
                code, agent = JOURNEY.execute_journey_container(
                    "fixture", root, source, root, None, root / "unused-auth"
                )
            self.assertEqual(code, 0)
            self.assertIsNone(agent)
            self.assertEqual(
                (root / "exercise.log").read_text().strip(), hashlib.sha256(source).hexdigest()
            )

    def test_audit_collection_distinguishes_fixture_writes_and_duplicate_observations(self) -> None:
        event = {
            "verb": "patch",
            "userAgent": "kapsel",
            "auditID": "first",
            "user": {"username": "system:serviceaccount:demo:journey"},
            "objectRef": {"name": "agent-healthy"},
            "requestReceivedTimestamp": "2026-10-11T00:00:00Z",
        }
        fixture_write = dict(event, auditID="fixture", userAgent="kapsel-journey-fixture")
        audit = b"\n".join(json.dumps(item).encode() for item in (fixture_write, event))
        with mock.patch.object(JOURNEY, "run", return_value=audit):
            counts, events = JOURNEY.collect_receiver_counts("fixture")
        self.assertEqual(counts, {case: int(case == "healthy") for case in JOURNEY.CASES})
        self.assertEqual(events["healthy"], [("patch", 1791676800.0)])
        duplicate = b"\n".join([json.dumps(event).encode()] * 2)
        with (
            mock.patch.object(JOURNEY, "run", return_value=duplicate),
            self.assertRaises(AssertionError),
        ):
            JOURNEY.collect_receiver_counts("fixture")

    def test_journey_python_calls_exclude_caller_writable_imports(self) -> None:
        tree = ast.parse(JOURNEY.EXERCISE_SOURCE.read_bytes())
        invocations = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.List)
            and node.elts
            and ast.unparse(node.elts[0]) == "sys.executable"
        ]
        self.assertEqual(len(invocations), 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "socket.py").write_text("raise SystemExit(99)\n")
            for invocation in invocations:
                prefix = eval(
                    compile(
                        ast.fix_missing_locations(
                            ast.Expression(ast.List(elts=invocation.elts[:3], ctx=ast.Load()))
                        ),
                        "<caller-prefix>",
                        "eval",
                    ),
                    {"sys": sys},
                )
                self.assertEqual(prefix[:2], [sys.executable, "-I"])
                self.assertIn(prefix[2], ("-", "/inputs/kind_receiver_barrier.py"))
                subprocess.run(
                    prefix[:2] + ["-c", "import socket"], cwd=root, check=True, timeout=5
                )

    def test_journey_receipt_binds_action_and_result(self) -> None:
        function = next(
            node
            for node in ast.walk(ast.parse(JOURNEY.EXERCISE_SOURCE.read_bytes()))
            if isinstance(node, ast.FunctionDef) and node.name == "receipt"
        )
        for operation, result in (
            ("caller-loss", "UNKNOWN"),
            ("healthy", "UNKNOWN"),
            ("caller-loss", "SUCCEEDED"),
        ):
            with self.subTest(operation=operation, result=result):
                report = {
                    "status": "INSPECTED",
                    "operation_id": operation,
                    "result": result,
                    "target_uid": "original",
                    "target_resource_version": "opaque",
                }
                path = mock.Mock()
                path.read_text.return_value = "1"
                path.read_bytes.return_value = b"frozen"
                scope = {
                    "pathlib": SimpleNamespace(Path=lambda _, path=path: path),
                    "json": json,
                    "EXPECTED": {"caller-loss": "UNKNOWN"},
                    "targets": {"caller-loss": {"uid": "original", "resourceVersion": "opaque"}},
                    "read": lambda *args: {"status": "READY"},
                    "command": lambda *args, report=report: json.dumps(report),
                }
                exec(
                    compile(ast.Module(body=[function], type_ignores=[]), "<receipt>", "exec"),
                    scope,
                )
                if operation == "caller-loss" and result == "UNKNOWN":
                    self.assertEqual(scope["receipt"]("caller-loss", "restart"), b"frozen")
                else:
                    with self.assertRaises(AssertionError):
                        scope["receipt"]("caller-loss", "restart")

    def test_agent_execution_is_unprivileged_and_completion_requires_product_evidence(self) -> None:
        for case in (
            "valid",
            "model-failure",
            "model-prose-only",
            "unintended-action",
            "receipt-mismatch",
            "retirement-incomplete",
            "runtime-error",
            "timeout",
            "output-overflow",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                workspace = pathlib.Path(temporary)
                binary = workspace / "codex"
                binary.write_bytes(b"fixture binary")
                binary.with_name("codex-code-mode-host").write_bytes(b"fixture helper")
                responses: list[subprocess.CompletedProcess[bytes] | Exception] = [
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess(
                        [],
                        int(case == "model-failure"),
                        b'{"type":"turn.completed","usage":{}}\n',
                        b"",
                    ),
                ]

                if case == "runtime-error":
                    response = responses[1]
                    assert isinstance(response, subprocess.CompletedProcess)
                    response.stdout += b'{"type":"item.completed","item":{"type":"error"}}\n'
                if case == "timeout":
                    responses[1] = subprocess.TimeoutExpired("docker exec", 120)
                if case == "output-overflow":
                    responses[1] = RuntimeError("confined Codex output exceeded its byte bound")

                def product(arguments, case=case, **_kwargs):
                    if JOURNEY.RETIRE_CALLERS in arguments:
                        return b"" if case == "retirement-incomplete" else b"CALLERS_RETIRED\n"
                    if JOURNEY.RECEIPT_SNAPSHOT in arguments:
                        return (
                            b"wrong"
                            if case == "receipt-mismatch"
                            and arguments[-1].endswith("repeated.receipt")
                            else b"frozen receipt"
                        )
                    if arguments[-1] == "--version":
                        return b"codex fixture\n"
                    if "/usr/bin/kapsel-service-client" in arguments:
                        if "receipt" in arguments:
                            return json.dumps(
                                {"version": 1, "status": "READY", "receipt_sha256": "1" * 64}
                            ).encode()
                        state = "NOT_FOUND"
                        if arguments[-1] == "healthy" and case != "model-prose-only":
                            state = "SUCCEEDED"
                        if arguments[-1] == "stale" and case == "unintended-action":
                            state = "IN_PROGRESS"
                        return json.dumps({"version": 1, "status": state}).encode()
                    return b""

                with (
                    mock.patch.object(
                        JOURNEY.subprocess, "run", return_value=responses[0]
                    ) as direct,
                    mock.patch.object(
                        JOURNEY, "run_agent_process", side_effect=responses[1:]
                    ) as cli,
                    mock.patch.object(JOURNEY, "run", side_effect=product) as transport,
                ):
                    if case == "valid":
                        evidence = JOURNEY.run_agent(
                            "owned-container", workspace, binary, workspace / "auth.json"
                        )
                        self.assertEqual(evidence["uid"], 61001)
                        self.assertEqual(evidence["status"], "SUCCEEDED")
                        self.assertEqual(
                            json.loads((workspace / "selection.json").read_text()),
                            {"operation_id": "healthy"},
                        )
                    else:
                        with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                            JOURNEY.run_agent(
                                "owned-container", workspace, binary, workspace / "auth.json"
                            )
                        self.assertFalse((workspace / "selection.json").exists())
                    for invocation in transport.call_args_list:
                        argv = invocation.args[0]
                        if "/usr/bin/kapsel-service-client" in argv:
                            self.assertEqual(
                                argv[argv.index("owned-container") + 1],
                                "/usr/bin/kapsel-service-client",
                            )
                    arguments = cli.call_args.args[0]
                    self.assertEqual(
                        arguments[:5], ["docker", "exec", "--user", "61001:61000", "--workdir"]
                    )
                    self.assertNotIn("--ignore-user-config", arguments)
                    config_calls = [call for call in direct.call_args_list if "tee" in call.args[0]]
                    self.assertEqual(len(config_calls), 1)
                    self.assertIn(
                        b'command = "/usr/bin/kapsel-service-mcp"', config_calls[0].kwargs["input"]
                    )
                    self.assertIn("--ignore-rules", arguments)
                    self.assertIn("--ephemeral", arguments)
                    self.assertEqual(
                        transport.call_args.args[0],
                        [
                            "docker",
                            "exec",
                            "owned-container",
                            "rm",
                            "-f",
                            "/home/caller/.codex/auth.json",
                        ],
                    )


if __name__ == "__main__":
    unittest.main()
