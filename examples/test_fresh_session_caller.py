#!/usr/bin/env python3
"""Independent-process transcripts for the read-first caller. The bridge itself has Rust tests."""

import hashlib
import json
import os
import runpy
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("fresh_session_caller.py")

BRIDGE_FIXTURE = Path(__file__).with_name("mcp_bridge_fixture.py")


class FreshSession(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.bridge = root / "bridge"
        self.bridge.write_bytes(BRIDGE_FIXTURE.read_bytes())
        self.bridge.chmod(0o700)
        self.script = root / "caller.py"
        self.script.write_text(
            SCRIPT.read_text().replace(
                'BRIDGE = "/usr/bin/kapsel-service-mcp"', f'BRIDGE = "{self.bridge}"'
            )
        )
        self.state = root / "state.json"
        self.ref = root / "reference.json"

    def run_caller_raw(self, command, *extra):
        return subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--service",
                "host-a-journal-a",
                "--reference",
                str(self.ref),
                command,
                *extra,
            ],
            env={**os.environ, "FIXTURE_STATE": str(self.state)},
            capture_output=True,
            text=True,
            timeout=10,
        )

    def run_caller(self, command, *extra):
        process = self.run_caller_raw(command, *extra)
        return process.returncode, json.loads(process.stdout)["service"]

    def pin(self):
        self.ref.write_text(
            json.dumps({"version": 1, "service": "host-a-journal-a", "operation_id": "op-1"})
        )
        self.ref.chmod(0o600)

    def fixture(self, status):
        self.state.write_text(
            json.dumps(
                {
                    "calls": [],
                    "responses": {
                        "kapsel.get_status": status,
                        "kapsel.list_approved_actions": {
                            "version": 1,
                            "status": "READY",
                            "entries": [{"operation_id": "op-1"}],
                            "next_cursor": None,
                        },
                        "kapsel.submit": {
                            "version": 1,
                            "status": "ADMITTED",
                            "phase": "apply_started",
                        },
                        "kapsel.get_receipt": {"version": 1, "status": "NOT_READY"},
                    },
                }
            )
        )

    def calls(self):
        return json.loads(self.state.read_text())["calls"]

    def test_reference_descriptor_rejects_unsafe_files_and_records(self):
        namespace = runpy.run_path(str(SCRIPT), run_name="caller_import")
        reference = namespace["reference"]
        valid = {"version": 1, "service": "host-a-journal-a", "operation_id": "op-1"}

        self.ref.write_text(json.dumps(valid))
        self.ref.chmod(0o600)
        link = Path(self.temp.name) / "reference-link.json"
        link.symlink_to(self.ref)
        with self.assertRaises(OSError):
            reference(str(link), "host-a-journal-a")

        fifo = Path(self.temp.name) / "reference.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            reference(str(fifo), "host-a-journal-a")

        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                reference(str(self.ref), "host-a-journal-a")

        for invalid in [{**valid, "operation_id": "bad\n"}, {**valid, "version": True}]:
            self.ref.write_text(json.dumps(invalid))
            self.ref.chmod(0o600)
            with self.assertRaises(ValueError):
                reference(str(self.ref), "host-a-journal-a")

    def test_reference_descriptor_rejects_truncate_and_grow_during_read(self):
        namespace = runpy.run_path(str(SCRIPT), run_name="caller_import")
        reference = namespace["reference"]
        saved = {"version": 1, "service": "host-a-journal-a", "operation_id": "op-1"}
        self.ref.write_text(json.dumps(saved))
        self.ref.chmod(0o600)
        real_read = os.read

        def truncate_before_read(descriptor, size):
            self.ref.write_text("")
            return real_read(descriptor, size)

        with mock.patch("os.read", side_effect=truncate_before_read):
            with self.assertRaises(ValueError):
                reference(str(self.ref), "host-a-journal-a")

        self.ref.write_text(json.dumps(saved))
        self.ref.chmod(0o600)

        def grow_before_read(descriptor, size):
            self.ref.write_text("{" + " ".join(["0"] * 600))
            return real_read(descriptor, size)

        with mock.patch("os.read", side_effect=grow_before_read):
            with self.assertRaises(ValueError):
                reference(str(self.ref), "host-a-journal-a")

    def test_reference_validation_preserves_accepted_fields(self):
        saved = {
            "version": 1,
            "service": "host-a-journal-a",
            "operation_id": "op-1",
            "caller_note": "keep",
        }
        self.ref.write_text(json.dumps(saved))
        self.ref.chmod(0o600)
        namespace = runpy.run_path(str(SCRIPT), run_name="caller_import")
        self.assertEqual(namespace["reference"](str(self.ref), "host-a-journal-a"), saved)
        self.assertEqual(json.loads(self.ref.read_text()), saved)

    def test_oversized_mcp_response_is_bounded_before_json_parsing(self):
        self.fixture({"version": 1, "status": "NOT_FOUND"})
        self.pin()
        self.bridge.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.read()\n"
            "sys.stdout.buffer.write(b'{\\\"jsonrpc\\\":' + b'0' * 100001)\n"
            "sys.stdout.flush()\n"
        )
        process = self.run_caller_raw("read")
        self.assertEqual(process.returncode, 4)
        self.assertEqual(
            json.loads(process.stdout)["service"],
            {"status": "ERROR", "error_class": "exchange_uncertain"},
        )
        self.assertNotIn("0" * 1000, process.stderr)
        self.assertEqual(self.calls(), [])

    def test_partial_mcp_response_remains_uncertain(self):
        self.fixture({"version": 1, "status": "NOT_FOUND"})
        self.pin()
        self.bridge.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "sys.stdin.read()\n"
            'print(json.dumps({"jsonrpc": "2.0", "id": 1, '
            '"result": {"protocolVersion": "2025-11-25"}}))\n'
        )
        self.assertEqual(
            self.run_caller("read"),
            (4, {"status": "ERROR", "error_class": "exchange_uncertain"}),
        )
        self.assertEqual(self.calls(), [])

    def test_deadline_spans_eof_and_child_wait_with_cleanup(self):
        self.fixture({"version": 1, "status": "NOT_FOUND"})
        self.pin()
        pid_file = Path(self.temp.name) / "bridge.pid"
        self.bridge.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys, time\n"
            "sys.stdin.read()\n"
            f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
            'print(json.dumps({"jsonrpc": "2.0", "id": 1, '
            '"result": {"protocolVersion": "2025-11-25"}}))\n'
            'print(json.dumps({"jsonrpc": "2.0", "id": 2, "result": '
            '{"content": [{"type": "text", "text": "{}"}]}}))\n'
            "sys.stdout.flush()\n"
            "os.close(1)\n"
            "os.close(2)\n"
            "time.sleep(30)\n"
        )
        process = self.run_caller_raw("read")
        self.assertEqual(process.returncode, 4)
        self.assertEqual(
            json.loads(process.stdout)["service"],
            {"status": "ERROR", "error_class": "exchange_uncertain"},
        )
        pid = int(pid_file.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(self.calls(), [])

    def test_malformed_mcp_envelopes_remain_uncertain(self):
        ready = {"id": 1, "result": {"protocolVersion": "2025-11-25"}}
        for initialization, reply in ((7, {}), ({"id": 1, "result": None}, {}), (ready, 7)):
            with self.subTest(initialization=initialization, reply=reply):
                self.fixture({"version": 1, "status": "NOT_FOUND"})
                self.pin()
                self.bridge.write_text(
                    "#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\n"
                    f"print({json.dumps(initialization)!r})\nprint({json.dumps(reply)!r})\n"
                )
                self.assertEqual(
                    self.run_caller("read"),
                    (4, {"status": "ERROR", "error_class": "exchange_uncertain"}),
                )
                self.assertEqual(self.calls(), [])

    def test_malformed_response_remains_uncertain_and_cannot_select(self):
        for response in (
            7,
            {"version": 1, "status": 7},
            {"version": "1", "status": "IN_PROGRESS"},
            {"version": 1, "status": "IN_PROGRESS", "execution": "resume_required"},
            {"version": 1, "status": "IN_PROGRESS", "execution": {"next_action": []}},
        ):
            with self.subTest(response=response):
                self.fixture(response)
                self.pin()
                code, result = self.run_caller("read")
                self.assertEqual(code, 4)
                self.assertEqual(result, {"status": "ERROR", "error_class": "exchange_uncertain"})
                self.assertEqual(self.calls(), ["kapsel.get_status"])

    def test_history_is_read_only_and_preserves_both_effects_and_access_errors(self):
        self.fixture({"version": 1, "status": "NOT_FOUND"})
        entries = [
            {"operation_id": "git-op", "effect": "git.transition_ref", "status": "UNKNOWN"},
            {
                "operation_id": "k8s-op",
                "effect": "kubernetes.set_deployment_image",
                "status": "SUCCEEDED",
            },
            {
                "operation_id": "unavailable",
                "status": "ERROR",
                "error_class": "authority_unavailable",
            },
        ]
        page = {"version": 1, "status": "READY", "entries": entries, "next_cursor": "unavailable"}
        data = json.loads(self.state.read_text())
        data["responses"]["kapsel.list_operation_history"] = page
        self.state.write_text(json.dumps(data))
        self.assertEqual(self.run_caller("history")[1], page)
        self.assertEqual(self.run_caller("history", "unavailable")[1], page)
        self.assertFalse(self.ref.exists())
        self.assertEqual(self.calls(), ["kapsel.list_operation_history"] * 2)

    def test_first_selection_is_explicit_and_cannot_repeat_after_loss(self):
        self.fixture(
            {
                "version": 1,
                "status": "NOT_FOUND",
                "execution": {
                    "disposition": "admission_unconfirmed",
                    "next_action": "read_same_id",
                    "action_owner": "caller",
                    "condition": None,
                },
            }
        )
        self.assertEqual(self.run_caller("approved")[1]["status"], "READY")
        self.assertFalse(self.ref.exists())
        self.assertEqual(self.run_caller("start", "op-1")[1]["status"], "ADMITTED")
        self.assertTrue(self.ref.exists())
        self.assertEqual(self.ref.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_caller("read")[1]["status"], "NOT_FOUND")
        self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
        retry = subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--service",
                "host-a-journal-a",
                "--reference",
                str(self.ref),
                "start",
                "op-1",
            ],
            env={**os.environ, "FIXTURE_STATE": str(self.state)},
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(retry.returncode, 4)
        self.assertEqual(
            self.calls(),
            [
                "kapsel.list_approved_actions",
                "kapsel.submit",
                "kapsel.get_status",
                "kapsel.get_status",
            ],
        )

    def test_definite_refusal_and_local_rejection_stay_distinct(self):
        self.fixture(
            {
                "version": 1,
                "status": "NOT_FOUND",
                "execution": {
                    "disposition": "admission_unconfirmed",
                    "next_action": "read_same_id",
                    "action_owner": "caller",
                    "condition": None,
                },
            }
        )
        data = json.loads(self.state.read_text())
        data["responses"]["kapsel.submit"] = {
            "version": 1,
            "status": "NOT_ADMITTED",
            "reason": "BUSY",
        }
        self.state.write_text(json.dumps(data))
        self.assertEqual(self.run_caller("start", "op-1")[1]["status"], "NOT_ADMITTED")
        self.assertEqual(self.run_caller("read")[1]["status"], "NOT_FOUND")
        self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
        self.assertEqual(self.calls().count("kapsel.submit"), 1)
        self.assertTrue(self.ref.exists())
        self.fixture(
            {
                "version": 1,
                "status": "NOT_ATTEMPTED",
                "target_rejection": "STALE_APPROVAL",
                "execution": {
                    "disposition": "complete",
                    "next_action": "inspect_result",
                    "action_owner": "caller",
                    "condition": None,
                },
            }
        )
        self.assertEqual(self.run_caller("read")[1]["target_rejection"], "STALE_APPROVAL")
        self.assertNotIn("kapsel.submit", self.calls())

    def test_lost_ack_and_restart_read_only_then_explicit_same_id(self):
        self.fixture(
            {
                "version": 1,
                "status": "IN_PROGRESS",
                "execution": {
                    "disposition": "resume_required",
                    "next_action": "select_same_id",
                    "action_owner": "caller",
                    "condition": None,
                },
            }
        )
        self.pin()
        self.assertEqual(self.run_caller("read")[1]["status"], "IN_PROGRESS")
        self.assertEqual(self.calls(), ["kapsel.get_status"])
        self.assertEqual(self.run_caller("resume")[1]["status"], "ADMITTED")
        self.assertEqual(self.calls().count("kapsel.submit"), 1)
        self.assertEqual(self.run_caller("read")[1]["status"], "IN_PROGRESS")
        self.assertEqual(self.calls().count("kapsel.submit"), 1)

    def test_terminal_and_inaccessible_never_submit(self):
        for status in ("NOT_FOUND", "NOT_ATTEMPTED", "SUCCEEDED", "FAILED", "UNKNOWN", "ERROR"):
            with self.subTest(status=status):
                self.fixture(
                    {
                        "version": 1,
                        "status": status,
                        "execution": {
                            "disposition": "complete",
                            "next_action": "inspect_result",
                            "action_owner": "caller",
                        },
                    }
                )
                if not self.ref.exists():
                    self.pin()
                self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
                self.assertEqual(self.calls(), ["kapsel.get_status"])

    def test_both_effects_use_same_identity_and_stop_at_unknown(self):
        for effect in ("kubernetes.set_deployment_image", "git.transition_ref"):
            with self.subTest(effect=effect):
                self.fixture(
                    {
                        "version": 1,
                        "effect": effect,
                        "status": "IN_PROGRESS",
                        "execution": {
                            "disposition": "resume_required",
                            "next_action": "select_same_id",
                            "action_owner": "caller",
                            "condition": None,
                        },
                    }
                )
                if not self.ref.exists():
                    self.pin()
                self.assertEqual(self.run_caller("read")[1]["effect"], effect)
                self.assertEqual(self.run_caller("resume")[1]["status"], "ADMITTED")
                data = json.loads(self.state.read_text())
                data["responses"]["kapsel.get_status"]["status"] = "UNKNOWN"
                self.state.write_text(json.dumps(data))
                self.assertEqual(self.run_caller("read")[0], 4)
                self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
                self.assertEqual(self.calls().count("kapsel.submit"), 1)
                self.assertEqual(json.loads(self.ref.read_text())["operation_id"], "op-1")

    def test_contradictory_execution_cannot_select(self):
        self.fixture(
            {
                "version": 1,
                "status": "IN_PROGRESS",
                "execution": {
                    "disposition": "operator_required",
                    "next_action": "select_same_id",
                    "action_owner": "caller",
                    "condition": "receiver_unavailable",
                },
            }
        )
        self.pin()
        self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
        self.assertEqual(self.calls(), ["kapsel.get_status"])

    def test_fresh_process_retrieves_same_frozen_receipt(self):
        receipt = b"frozen receipt fixture"
        digest = hashlib.sha256(receipt).hexdigest()
        self.fixture({"version": 1, "status": "UNKNOWN"})
        data = json.loads(self.state.read_text())
        data["responses"]["kapsel.get_receipt"] = {
            "version": 1,
            "status": "READY",
            "receipt_hex": receipt.hex(),
            "receipt_sha256": digest,
        }
        self.state.write_text(json.dumps(data))
        self.pin()
        first = self.run_caller("receipt")[1]
        second = self.run_caller("receipt")[1]
        self.assertEqual(bytes.fromhex(first["receipt_hex"]), receipt)
        self.assertEqual(first, second)
        self.assertEqual(self.calls(), ["kapsel.get_receipt", "kapsel.get_receipt"])
        self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
        self.assertNotIn("kapsel.submit", self.calls())

    def test_real_bridge_lost_ack_and_read_only_reconnect(self):
        binary = os.environ.get("KAPSEL_TEST_BRIDGE")
        if not binary:
            self.skipTest("set KAPSEL_TEST_BRIDGE to a test-harness bridge binary")
        self.script.write_text(
            SCRIPT.read_text().replace(
                'BRIDGE = "/usr/bin/kapsel-service-mcp"', f'BRIDGE = "{binary}"'
            )
        )
        address = str(Path(self.temp.name) / "service.sock")
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(address)
        listener.listen(4)
        listener.settimeout(10)
        requests = []
        replies = [
            None,  # Lost first-selection acknowledgement. The service may already have admitted it.
            {
                "version": 1,
                "status": "IN_PROGRESS",
                "execution": {
                    "disposition": "active",
                    "next_action": "wait",
                    "action_owner": "caller",
                    "condition": None,
                },
            },
            {
                "version": 1,
                "status": "UNKNOWN",
                "execution": {
                    "disposition": "complete",
                    "next_action": "inspect_result",
                    "action_owner": "caller",
                    "condition": None,
                },
            },
            {
                "version": 1,
                "status": "UNKNOWN",
                "execution": {
                    "disposition": "complete",
                    "next_action": "inspect_result",
                    "action_owner": "caller",
                    "condition": None,
                },
            },
        ]

        for response in replies:
            if response is not None:
                response.update(
                    {
                        "effect": "kubernetes.set_deployment_image",
                        "approved_target": None,
                        "attempt_target": None,
                        "observed_target": None,
                    }
                )

        def serve():
            for response in replies:
                connection, _ = listener.accept()
                with connection:
                    size = struct.unpack(">I", connection.recv(4))[0]
                    body = bytearray()
                    while len(body) < size:
                        body.extend(connection.recv(size - len(body)))
                    requests.append(json.loads(body))
                    if response is not None:
                        raw = json.dumps(response).encode()
                        connection.sendall(struct.pack(">I", len(raw)) + raw)
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = {**os.environ, "KAPSELD_TEST_CLIENT_SOCKET": address}

        def call(command, *extra):
            output = subprocess.run(
                [
                    sys.executable,
                    str(self.script),
                    "--service",
                    "host-a-journal-a",
                    "--reference",
                    str(self.ref),
                    command,
                    *extra,
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return output.returncode, json.loads(output.stdout)["service"]

        # The first process exits without an admission answer. A new process reads the old ID.
        first = call("start", "op-1")[1]
        self.assertEqual(first["status"], "ERROR", first)
        self.assertTrue(self.ref.exists())
        second_start = subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--service",
                "host-a-journal-a",
                "--reference",
                str(self.ref),
                "start",
                "op-1",
            ],
            env=env,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(second_start.returncode, 4)
        self.assertEqual(call("read")[1]["status"], "IN_PROGRESS")
        self.assertEqual(call("read")[1]["status"], "UNKNOWN")
        self.assertEqual(call("resume")[1]["status"], "NO_SELECTION")
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            [item["request"] for item in requests],
            [
                "submit_set_deployment_image",
                "get_set_deployment_image_status",
                "get_set_deployment_image_status",
                "get_set_deployment_image_status",
            ],
        )
        self.assertEqual(
            sum(item["request"] == "submit_set_deployment_image" for item in requests), 1
        )

    def test_detached_inspection_of_retrieved_original_bytes(self):
        inspector = os.environ.get("KAPSEL_TEST_INSPECT")
        if not inspector:
            self.skipTest("set KAPSEL_TEST_INSPECT to the built kapsel executable")
        root = Path(__file__).resolve().parent.parent
        receipt = bytes.fromhex((root / "vectors/effect-gateway-receipt.hex").read_text().strip())
        self.fixture({"version": 1, "status": "FAILED"})
        data = json.loads(self.state.read_text())
        data["responses"]["kapsel.get_receipt"] = {
            "version": 1,
            "status": "READY",
            "receipt_hex": receipt.hex(),
            "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        }
        self.state.write_text(json.dumps(data))
        self.pin()
        first = self.run_caller("receipt")[1]
        second = self.run_caller("receipt")[1]
        self.assertEqual(first, second)
        target = Path(self.temp.name) / "export.receipt"
        target.write_bytes(bytes.fromhex(second["receipt_hex"]))
        trust = Path(self.temp.name) / "trust.bin"
        trust.write_bytes(
            bytes.fromhex((root / "vectors/effect-gateway-trust.hex").read_text().strip())
        )
        report = subprocess.run(
            [
                inspector,
                "inspect",
                "--receipt",
                str(target),
                "--trust",
                str(trust),
                "--evaluation-time-unix-s",
                "150",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(json.loads(report.stdout)["status"], "INSPECTED")
        self.assertEqual(self.calls(), ["kapsel.get_receipt", "kapsel.get_receipt"])

    def test_active_work_and_wrong_history_label(self):
        self.fixture(
            {
                "version": 1,
                "status": "IN_PROGRESS",
                "execution": {
                    "disposition": "active",
                    "next_action": "wait",
                    "action_owner": "caller",
                },
            }
        )
        self.pin()
        self.assertEqual(self.run_caller("resume")[1]["status"], "NO_SELECTION")
        self.assertEqual(self.calls(), ["kapsel.get_status"])
        failed = subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--service",
                "other-journal",
                "--reference",
                str(self.ref),
                "read",
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(failed.returncode, 4)
        self.assertEqual(self.calls(), ["kapsel.get_status"])


if __name__ == "__main__":
    unittest.main()
