#!/usr/bin/env python3
"""Caller decisions, reference custody, pipe retirement and one real MCP binding."""

import copy
import hashlib
import io
import itertools
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import fresh_session_caller as caller

SCRIPT = Path(caller.__file__)
PIPE_FIXTURE = SCRIPT.with_name("mcp_bridge_fixture.py")
ELIGIBLE = {
    "version": 1,
    "status": "IN_PROGRESS",
    "execution": {
        "disposition": "resume_required",
        "action_owner": "caller",
        "next_action": "select_same_id",
        "condition": None,
    },
}


def transcript(service, operation_id="op-1"):
    initialization = {"id": 1, "result": {"protocolVersion": caller.PROTOCOL}}
    reply = {
        "id": 2,
        "result": {
            "content": [{"text": json.dumps({"operation_id": operation_id, "service": service})}]
        },
    }
    return b"\n".join(json.dumps(item).encode() for item in (initialization, reply)) + b"\n"


class CallerPolicy(unittest.TestCase):
    def test_resume_requires_every_explicit_fact(self):
        for status, disposition, owner, action in itertools.product(
            (
                "IN_PROGRESS",
                "NOT_FOUND",
                "NOT_ATTEMPTED",
                "SUCCEEDED",
                "FAILED",
                "UNKNOWN",
                "ERROR",
            ),
            ("resume_required", "active", "waiting_for_worker", "operator_required", "complete"),
            ("caller", "operator"),
            ("select_same_id", "wait", "read_same_id", "contact_operator", "inspect_result"),
        ):
            response = {
                "version": 1,
                "status": status,
                "execution": {
                    "disposition": disposition,
                    "action_owner": owner,
                    "next_action": action,
                },
            }
            expected = (status, disposition, owner, action) == (
                "IN_PROGRESS",
                "resume_required",
                "caller",
                "select_same_id",
            )
            self.assertEqual(caller.requires_resume(response), expected, response)

    def test_malformed_or_incomplete_facts_cannot_select(self):
        for value in (None, 7, [], "IN_PROGRESS", {"status": "IN_PROGRESS"}):
            self.assertFalse(caller.requires_resume(value))
        for field in ("version", "status", "execution"):
            for replacement in (None, True, [], 7, "1"):
                value = {**ELIGIBLE, field: replacement}
                self.assertFalse(caller.requires_resume(value), value)
            value = copy.deepcopy(ELIGIBLE)
            del value[field]
            self.assertFalse(caller.requires_resume(value), value)
        for field in ("disposition", "action_owner", "next_action"):
            for replacement in (None, [], 7, "wrong"):
                value = copy.deepcopy(ELIGIBLE)
                value["execution"][field] = replacement
                self.assertFalse(caller.requires_resume(value), value)
            value = copy.deepcopy(ELIGIBLE)
            del value["execution"][field]
            self.assertFalse(caller.requires_resume(value), value)
        for effect in ("kubernetes.set_deployment_image", "git.transition_ref"):
            self.assertTrue(caller.requires_resume({**ELIGIBLE, "effect": effect}))

    def test_decoder_and_exchange_fail_closed_without_a_process_world(self):
        self.assertEqual(caller.decode_exchange(transcript(ELIGIBLE), "op-1"), ELIGIBLE)
        malformed = [b"", b"{}\n", b"7\n7\n", transcript(ELIGIBLE, "other")]
        for service in (
            7,
            {"status": 7},
            {**ELIGIBLE, "version": True},
            {**ELIGIBLE, "execution": "resume_required"},
            {**ELIGIBLE, "execution": {"next_action": []}},
        ):
            malformed.append(transcript(service))
        initialization, reply = transcript(ELIGIBLE).splitlines()
        for init in (7, {"id": 1, "result": None}, {"id": 9, "result": {}}):
            malformed.append(json.dumps(init).encode() + b"\n" + reply)
        malformed.append(initialization + b"\n7\n")
        for output in malformed:
            with (
                self.subTest(output=output),
                mock.patch.object(caller, "run_bridge", return_value=output),
            ):
                self.assertEqual(
                    caller.exchange("kapsel.get_status", {"operation_id": "op-1"}),
                    {"status": "ERROR", "error_class": "exchange_uncertain"},
                )


class CallerCustody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ref = self.root / "operation.ref"

    def pin(self):
        return caller.reference(str(self.ref), "history-a", "op-1")

    def invoke(self, command, *extra, response=None):
        argv = ["caller", "--service", "history-a", "--reference", str(self.ref), command, *extra]
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(caller, "exchange", return_value=response) as exchange,
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            code = caller.main()
        return code, output.getvalue(), exchange.call_args_list

    def test_initial_reference_is_synced_before_first_exchange_and_never_replaced(self):
        argv = ["caller", "--service", "history-a", "--reference", str(self.ref), "start", "op-1"]
        real_sync = os.fsync
        synced = []

        def sync(descriptor):
            synced.append(os.fstat(descriptor).st_mode)
            real_sync(descriptor)

        def lost_ack(tool, arguments):
            self.assertEqual(tool, "kapsel.submit")
            self.assertEqual(arguments, {"operation_id": "op-1"})
            self.assertEqual(len(synced), 2)
            self.assertEqual(json.loads(self.ref.read_bytes())["operation_id"], "op-1")
            self.assertEqual(self.ref.stat().st_mode & 0o777, 0o600)
            return {"status": "ERROR", "error_class": "exchange_uncertain"}

        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(caller, "exchange", side_effect=lost_ack),
            mock.patch("os.fsync", side_effect=sync),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(caller.main(), 4)
        original = self.ref.read_bytes()
        for identity in ("op-1", "another-id"):
            self.assertEqual(self.invoke("start", identity)[2], [])
            self.assertEqual(self.ref.read_bytes(), original)

    def test_reference_persistence_failures_prevent_every_exchange_and_preserve_partial_files(self):
        for failure in ("create", "write", "file_sync", "directory_sync"):
            with self.subTest(failure=failure):
                self.assert_reference_failure_prevents_exchange(failure)

    def assert_reference_failure_prevents_exchange(self, failure):
        self.ref = self.root / f"{failure}.ref"
        operations = []
        real_open = os.open
        real_fdopen = os.fdopen
        real_sync = os.fsync

        def open_reference(path, flags, *args):
            if flags & os.O_CREAT:
                operations.append("create")
                if failure == "create":
                    raise OSError("injected exclusive create failure")
            return real_open(path, flags, *args)

        @contextmanager
        def output_file(descriptor, mode):
            with real_fdopen(descriptor, mode) as output:
                observed = mock.Mock(wraps=output)

                def write(text):
                    operations.append("write")
                    if failure == "write":
                        output.write(text[:1])
                        output.flush()
                        raise OSError("injected write failure after partial bytes")
                    return output.write(text)

                observed.write.side_effect = write
                yield observed

        def sync(descriptor):
            kind = "directory_sync" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file_sync"
            operations.append(kind)
            if failure == kind:
                raise OSError(f"injected {kind} failure")
            real_sync(descriptor)

        with (
            mock.patch("os.open", side_effect=open_reference),
            mock.patch("os.fdopen", side_effect=output_file),
            mock.patch("os.fsync", side_effect=sync),
        ):
            code, _, calls = self.invoke("start", "op-1")

        self.assertEqual(code, 4)
        self.assertEqual(calls, [])
        self.assertEqual(operations[0], "create")
        self.assertIn(failure, operations)
        if failure == "create":
            self.assertFalse(self.ref.exists())
            return

        retained = self.ref.read_bytes()
        inode = self.ref.stat().st_ino
        self.assertTrue(retained)
        self.assertEqual(self.ref.stat().st_mode & 0o777, 0o600)
        if failure == "write":
            self.assertEqual(retained, b"{")
        else:
            self.assertEqual(json.loads(retained)["operation_id"], "op-1")
        for identity in ("op-1", "another-id"):
            code, _, calls = self.invoke("start", identity)
            self.assertEqual(code, 4)
            self.assertEqual(calls, [])
            self.assertEqual(self.ref.read_bytes(), retained)
            self.assertEqual(self.ref.stat().st_ino, inode)

    def test_commands_bind_the_policy_without_repeated_resume_journeys(self):
        self.pin()
        for command, response, tools in (
            ("read", ELIGIBLE, ["kapsel.get_status"]),
            ("resume", ELIGIBLE, ["kapsel.get_status", "kapsel.submit"]),
            ("resume", {**ELIGIBLE, "status": "UNKNOWN"}, ["kapsel.get_status"]),
            ("history", {"status": "READY", "entries": []}, ["kapsel.list_operation_history"]),
            ("approved", {"status": "READY", "entries": []}, ["kapsel.list_approved_actions"]),
        ):
            _, _, calls = self.invoke(command, response=response)
            self.assertEqual([call.args[0] for call in calls], tools)
            for call in calls:
                if call.args[0] not in (
                    "kapsel.list_operation_history",
                    "kapsel.list_approved_actions",
                ):
                    self.assertEqual(call.args[1], {"operation_id": "op-1"})

    def test_receipt_encoding_and_digest_are_checked_not_reconstructed(self):
        self.pin()
        receipt = b"original bytes"
        valid = {
            "version": 1,
            "status": "READY",
            "receipt_hex": receipt.hex(),
            "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        }
        self.assertEqual(self.invoke("receipt", response=valid)[0], 0)
        for fields in (
            {"receipt_hex": "A0"},
            {"receipt_hex": "0"},
            {"receipt_hex": "zz"},
            {"receipt_hex": "0" * 80_002},
            {"receipt_sha256": "0" * 64},
        ):
            self.assertEqual(self.invoke("receipt", response={**valid, **fields})[0], 4)

    def test_reference_rejects_unsafe_custody_and_wrong_records(self):
        valid = self.pin()
        link = self.root / "link"
        link.symlink_to(self.ref)
        with self.assertRaises(OSError):
            caller.reference(str(link), "history-a")
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            caller.reference(str(fifo), "history-a")
        with mock.patch("os.getuid", return_value=os.getuid() + 1), self.assertRaises(ValueError):
            caller.reference(str(self.ref), "history-a")
        alias = self.root / "alias"
        os.link(self.ref, alias)
        with self.assertRaises(ValueError):
            caller.reference(str(self.ref), "history-a")
        alias.unlink()
        for fields in ({"version": True}, {"service": "other"}, {"operation_id": "bad\n"}):
            self.ref.write_text(json.dumps({**valid, **fields}))
            with self.assertRaises(ValueError):
                caller.reference(str(self.ref), "history-a")
        self.ref.write_text(json.dumps({**valid, "caller_note": "keep"}))
        self.assertEqual(caller.reference(str(self.ref), "history-a").get("caller_note"), "keep")
        self.ref.chmod(0o640)
        with self.assertRaises(ValueError):
            caller.reference(str(self.ref), "history-a")

    def test_reference_rejects_truncate_and_grow_during_read(self):
        self.pin()
        original = self.ref.read_bytes()
        real_read = os.read
        for replacement in (b"", b"x" * 600):
            self.ref.write_bytes(original)

            def changed_read(descriptor, maximum, changed_bytes=replacement):
                self.ref.write_bytes(changed_bytes)
                return real_read(descriptor, maximum)

            with mock.patch("os.read", side_effect=changed_read), self.assertRaises(ValueError):
                caller.reference(str(self.ref), "history-a")

    def test_actual_pipe_bounds_and_child_retirement(self):
        bridge = self.root / "bridge"
        bridge.write_bytes(PIPE_FIXTURE.read_bytes())
        bridge.chmod(0o700)
        pid = self.root / "bridge.pid"
        for mode in ("oversized", "partial", "eof_then_wait"):
            with (
                mock.patch.object(caller, "BRIDGE", str(bridge)),
                mock.patch.object(caller, "EXCHANGE_DEADLINE_SECONDS", 0.5),
                mock.patch.dict(os.environ, {"FIXTURE_MODE": mode, "FIXTURE_PID": str(pid)}),
            ):
                self.assertEqual(
                    caller.exchange("kapsel.get_status", {"operation_id": "op-1"}),
                    {"status": "ERROR", "error_class": "exchange_uncertain"},
                )
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid.read_text()), 0)

    def test_real_bridge_reference_loss_and_resume_binding(self):
        binary = os.environ.get("KAPSEL_TEST_BRIDGE")
        if not binary:
            self.skipTest("set KAPSEL_TEST_BRIDGE to a test-harness bridge binary")
        script = self.root / "caller.py"
        script.write_text(SCRIPT.read_text().replace(caller.BRIDGE, binary))
        address = str(self.root / "service.sock")
        requests = []
        failures = []
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(address)
        listener.listen(4)
        listener.settimeout(10)
        replies = [None, ELIGIBLE, {"version": 1, "status": "ADMITTED", "phase": "requested"}]

        def serve():
            try:
                for response in replies:
                    connection, _ = listener.accept()
                    with connection, connection.makefile("rb") as input_stream:
                        size = struct.unpack(">I", input_stream.read(4))[0]
                        self.assertLessEqual(size, 16 * 1024)
                        requests.append(json.loads(input_stream.read(size)))
                        self.assertEqual(input_stream.read(1), b"")
                        if response is not None:
                            body = dict(response)
                            if body["status"] == "IN_PROGRESS":
                                body.update(
                                    effect="kubernetes.set_deployment_image",
                                    approved_target=None,
                                    attempt_target=None,
                                    observed_target=None,
                                )
                            raw = json.dumps(body).encode()
                            connection.sendall(struct.pack(">I", len(raw)) + raw)
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def call(command, *extra):
            return subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--service",
                    "history-a",
                    "--reference",
                    str(self.ref),
                    command,
                    *extra,
                ],
                env={**os.environ, "KAPSELD_TEST_CLIENT_SOCKET": address},
                capture_output=True,
                timeout=15,
            )

        first = call("start", "op-1")
        self.assertEqual(first.returncode, 4)
        self.assertEqual(json.loads(first.stdout)["service"]["status"], "ERROR")
        reference = self.ref.read_bytes()
        self.assertEqual(call("start", "another-id").returncode, 4)
        resumed = call("resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout)["service"]["status"], "ADMITTED")
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(self.ref.read_bytes(), reference)
        self.assertEqual(
            requests,
            [
                {"version": 1, "request": "submit_set_deployment_image", "operation_id": "op-1"},
                {
                    "version": 1,
                    "request": "get_set_deployment_image_status",
                    "operation_id": "op-1",
                },
                {"version": 1, "request": "submit_set_deployment_image", "operation_id": "op-1"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
