#!/usr/bin/env python3
"""Offline process/diagnostic and native preflight checks for installed qualification."""

import hashlib
import http.client
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import qualification as QUALIFY


class BoundedProcessTests(unittest.TestCase):
    def test_output_overflow_is_rejected_before_waiting_for_completion(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "byte bound"):
            QUALIFY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.write(1, b'x' * 65536); time.sleep(5)",
                ],
                stdout_max=1024,
                stderr_max=1024,
                timeout=10,
            )

    def test_hanging_command_is_killed_at_the_deadline(self) -> None:
        with self.assertRaises(subprocess.TimeoutExpired):
            QUALIFY.run_bounded(
                [sys.executable, "-I", "-c", "import time; time.sleep(5)"],
                stdout_max=1024,
                stderr_max=1024,
                timeout=0.1,
            )

    def test_closed_output_fds_do_not_end_the_deadline(self) -> None:
        with self.assertRaises(subprocess.TimeoutExpired):
            QUALIFY.run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os,time; os.close(1); os.close(2); time.sleep(5)",
                ],
                stdout_max=1024,
                stderr_max=1024,
                timeout=0.1,
            )

    def test_closed_stdin_pipe_does_not_hang(self) -> None:
        result = QUALIFY.run_bounded(
            [sys.executable, "-I", "-c", "import sys; sys.exit(0)"],
            input_bytes=b"x" * 1024 * 1024,
            stdout_max=1024,
            stderr_max=1024,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)

    def test_failed_checked_command_hides_raw_tool_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "command failed") as failure:
            QUALIFY.run_bounded(
                [sys.executable, "-I", "-c", "import sys; sys.stderr.write('SECRET'); sys.exit(7)"],
                stdout_max=1024,
                stderr_max=1024,
                timeout=5,
                check=True,
            )
        self.assertNotIn("SECRET", str(failure.exception))


class ServiceDiagnosticDrainTests(unittest.TestCase):
    def test_service_stderr_overflow_fails_without_blocking_cleanup(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                "import os,time; os.write(2, b'x' * 8192); time.sleep(5)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        assert process.stderr is not None
        drain = QUALIFY.ServiceStderrDrain(process)
        drain.start()
        try:
            process.wait(timeout=5)
            drain.finish()
            self.assertTrue(drain.overflow)
            self.assertNotEqual(process.returncode, 0)
            self.assertTrue(drain.failed())
            self.assertLessEqual(len(drain.diagnostic), QUALIFY.SERVICE_DIAGNOSTIC_BYTES_MAX)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            drain.finish()

    def test_service_stderr_graceful_cleanup_preserves_bounded_evidence(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", "import os; os.write(2, b'bounded diagnostic')"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        assert process.stderr is not None
        drain = QUALIFY.ServiceStderrDrain(process)
        drain.start()
        process.wait(timeout=5)
        drain.finish()
        self.assertEqual(process.returncode, 0)
        self.assertFalse(drain.failed())
        self.assertEqual(bytes(drain.diagnostic), b"bounded diagnostic")

    def test_finish_closes_the_reader_even_if_another_writer_keeps_the_pipe_open(self) -> None:
        reader, writer = os.pipe()
        source = os.fdopen(reader, "rb")
        process = mock.Mock(stderr=source)
        drain = QUALIFY.ServiceStderrDrain(process)
        drain.start()
        started = time.monotonic()
        try:
            drain.finish()
            self.assertLess(time.monotonic() - started, 3)
            self.assertFalse(drain.thread.is_alive())
            self.assertTrue(source.closed)
            self.assertTrue(drain.failed())
        finally:
            os.close(writer)
            drain.finish()


class NativePreflightTests(unittest.TestCase):
    def test_peer_denial_uses_different_effective_gid_and_supplementary_socket_access(self) -> None:
        passed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(QUALIFY, "run_bounded", return_value=passed) as run:
            QUALIFY.exercise_native_peer_denial(61001, 61000)
        self.assertEqual(run.call_args.kwargs["user"], 61001)
        self.assertEqual(run.call_args.kwargs["group"], 0)
        self.assertEqual(run.call_args.kwargs["extra_groups"], [61000])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        for result in (
            subprocess.CompletedProcess([], 1, b"", b""),
            subprocess.CompletedProcess([], 0, b"disclosed", b""),
            subprocess.CompletedProcess([], 0, b"", b"unexpected"),
        ):
            with mock.patch.object(QUALIFY, "run_bounded", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "not refused before frame read"):
                    QUALIFY.exercise_native_peer_denial(61001, 61000)
        with mock.patch.object(QUALIFY, "run_bounded") as run:
            with self.assertRaisesRegex(RuntimeError, "distinct effective group"):
                QUALIFY.exercise_native_peer_denial(61001, 0)
            run.assert_not_called()

    def test_native_qualification_preserves_and_refuses_dangling_enablement(self) -> None:
        for kind in ("wants", "requires", "alias", "linked-directory"):
            with (
                self.subTest(kind=kind),
                tempfile.TemporaryDirectory(prefix="kapsel-unit-reference-") as temporary,
            ):
                private = pathlib.Path(temporary)
                units = private / "units"
                units.mkdir()
                target = private / "vendor/kapseld.service"
                if kind == "alias":
                    link = units / "alias.service"
                else:
                    directory = units / (
                        "multi-user.target.requires"
                        if kind == "requires"
                        else "multi-user.target.wants"
                    )
                    if kind == "linked-directory":
                        external = private / "dependencies"
                        external.mkdir()
                        directory.symlink_to(external, target_is_directory=True)
                    else:
                        directory.mkdir()
                    link = directory / "kapseld.service"
                link.symlink_to(target)
                with self.assertRaisesRegex(RuntimeError, "existing service references"):
                    QUALIFY.refuse_systemd_references(units)
                self.assertTrue(link.is_symlink())
                self.assertFalse(target.exists())

    def test_native_qualification_refuses_wrong_platform_before_host_commands(self) -> None:
        with (
            mock.patch.object(QUALIFY.os, "uname", return_value=SimpleNamespace(machine="aarch64")),
            mock.patch.object(QUALIFY.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "x86-64 Linux"):
                QUALIFY.install_systemd_assets(pathlib.Path("/unused"))
            command.assert_not_called()


ROOT = pathlib.Path(__file__).resolve().parents[2]


class CallerContainerTests(unittest.TestCase):
    def test_model_process_retirement_and_receipt_custody(self) -> None:
        """Real Linux probes for timeout descendants and forged model receipt paths."""
        fixture_directory = pathlib.Path(__file__).parent
        script = (fixture_directory / "caller_custody_exercise.py").read_bytes()
        probe_sources = (
            ROOT / "tests/qualification/retire_callers.py",
            ROOT / "tests/qualification/snapshot_receipt.py",
            fixture_directory / "background_caller_fixture.py",
        )
        probe_volumes = [
            argument
            for source in probe_sources
            for argument in ("--volume", f"{source}:/fixtures/{source.name}:ro")
        ]
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=256m",
                *probe_volumes,
                "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1",
                "python3",
                "-I",
                "-",
            ],
            input=script,
            check=True,
            timeout=40,
        )


class ReceiverRequestTests(unittest.TestCase):
    def test_only_exact_patch_path_or_empty_query_delimiter_is_accepted(self) -> None:
        patch = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "artifact-deployment-uid",
                "resourceVersion": "1",
                "annotations": {"kapsel.dev/kap0038-operation-id": "artifact-op-1"},
            },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "image": "registry.example/kapsel/agent-api@sha256:"
                                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            }
                        ]
                    }
                }
            },
        }
        receiver = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QUALIFY.KubernetesFixture)
        thread = threading.Thread(target=receiver.serve_forever, daemon=True)
        thread.start()
        try:
            for query, expected in (("", 200), ("?", 200), ("?dryRun=All", 400), ("?other=x", 400)):
                with self.subTest(query=query):
                    QUALIFY.reset_kubernetes_fixture()
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", receiver.server_port, timeout=5
                    )
                    try:
                        connection.request(
                            "PATCH",
                            "/apis/apps/v1/namespaces/demo/deployments/agent-api" + query,
                            json.dumps(patch),
                            {"Content-Type": "application/strategic-merge-patch+json"},
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, expected)
                        response.read()
                    finally:
                        connection.close()
        finally:
            receiver.shutdown()
            receiver.server_close()
            thread.join(timeout=5)


class SelectedArtifactTests(unittest.TestCase):
    def fixture(self, root: pathlib.Path) -> dict:
        metadata = {"source_revision": "1" * 40, "source_dirty": False, "asset_files": {}}
        for name, relative in {
            "ordinary": "bin/kapsel",
            "service": "libexec/kapsel/kapseld",
            "client": "bin/kapsel-service-client",
            "mcp_bridge": "bin/kapsel-service-mcp",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            metadata[f"{name}_binary_bytes"] = len(name)
            metadata[f"{name}_binary_sha256"] = hashlib.sha256(name.encode()).hexdigest()
        for relative, value in {
            "share/kapsel/qualification.py": pathlib.Path(QUALIFY.__file__).read_bytes(),
            "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md": b"guide does not execute",
            "share/kapsel/kapseld.service": b"unit",
            "share/kapsel/kapseld.conf": b"users",
            "share/kapsel/kapseld-rbac.yaml": b"rbac",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
            metadata["asset_files"][relative] = {
                "bytes": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        (root / "RELEASE-METADATA.json").write_text(json.dumps(metadata))
        return metadata

    def test_changed_selected_inputs_refuse_before_any_host_command(self) -> None:
        for changed in ("revision", "dirty", "binary", "program", "guide", "unit"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                metadata = self.fixture(root)
                self.assertEqual(QUALIFY.selected_artifact(root, "1" * 40), metadata)
                if changed in ("revision", "dirty"):
                    metadata["source_dirty" if changed == "dirty" else "source_revision"] = (
                        True if changed == "dirty" else "0" * 40
                    )
                    (root / "RELEASE-METADATA.json").write_text(json.dumps(metadata))
                else:
                    relative = {
                        "binary": "bin/kapsel",
                        "program": "share/kapsel/qualification.py",
                        "guide": "share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
                        "unit": "share/kapsel/kapseld.service",
                    }[changed]
                    (root / relative).write_bytes(b"changed")
                with mock.patch.object(QUALIFY.subprocess, "Popen") as command:
                    with self.assertRaises(RuntimeError):
                        QUALIFY.selected_artifact(root, "1" * 40)
                    command.assert_not_called()

    def test_installed_profile_refuses_unprivileged_invocation(self) -> None:
        with mock.patch.object(QUALIFY.os, "geteuid", return_value=1000):
            with mock.patch.object(QUALIFY.subprocess, "Popen") as command:
                with self.assertRaisesRegex(RuntimeError, "requires root"):
                    QUALIFY.install(pathlib.Path("/unused"), True)
                command.assert_not_called()

    def test_isolated_import_cannot_launch_a_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "pathlib.py").write_text("raise SystemExit(99)\n")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import runpy,sys; p=runpy.run_path(sys.argv[1],run_name='fixture_import'); assert callable(p['main'])",
                    QUALIFY.__file__,
                ],
                cwd=root,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual([path.name for path in root.iterdir()], ["pathlib.py"])


if __name__ == "__main__":
    unittest.main(
        defaultTest=(
            "BoundedProcessTests",
            "ServiceDiagnosticDrainTests",
            "NativePreflightTests",
            "ReceiverRequestTests",
            "SelectedArtifactTests",
        )
    )
