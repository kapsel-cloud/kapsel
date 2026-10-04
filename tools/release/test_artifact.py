#!/usr/bin/env python3
"""Black-box smoke tests for the assembled Kapsel release artifact."""

from __future__ import annotations

import argparse
import ast
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer
from unittest import mock

import assemble_artifact as ASSEMBLY
import verify_artifact as SMOKE

ROOT = pathlib.Path(__file__).resolve().parents[2]
ASSEMBLER = pathlib.Path(__file__).with_name("assemble_artifact.py")
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SMOKE_IMAGE = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
RELEASE_ARCHIVE: pathlib.Path | None = None
EXAMPLE_REVISION: str | None = None


def release_archive() -> pathlib.Path:
    if RELEASE_ARCHIVE is None:
        raise RuntimeError("--archive is required")
    return RELEASE_ARCHIVE


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


JOURNEY_SPEC = importlib.util.spec_from_file_location(
    "kind_agent_action_workflow", ROOT / "tests/qualification/run_kind_agent_action_workflow.py"
)
if JOURNEY_SPEC is None or JOURNEY_SPEC.loader is None:
    raise RuntimeError("could not load the live journey runner")
JOURNEY = importlib.util.module_from_spec(JOURNEY_SPEC)
JOURNEY_SPEC.loader.exec_module(JOURNEY)


class ZeroReader(io.RawIOBase):
    def __init__(self, remaining: int) -> None:
        self.remaining = remaining

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: WriteableBuffer) -> int:
        view = memoryview(buffer).cast("B")
        count = min(len(view), self.remaining)
        if count == 0:
            return 0
        view[:count] = b"\0" * count
        self.remaining -= count
        return count


def synthetic_archive(
    archive: pathlib.Path,
    *,
    mutate: str | None = None,
) -> bytes:
    basename = archive.name.removesuffix(".tar.gz")
    ordinary = b"ordinary"
    service = b"service"
    client = b"client"
    mcp_bridge = b"mcp-bridge"
    metadata = {
        "artifact_schema": "kapsel.release-artifact.v3",
        "package_version": "0.2.0",
        "rust_target": TARGET,
        "source_revision": "1" * 40,
        "source_tree": "2" * 40,
        "source_dirty": False,
        "cargo_lock_sha256": "3" * 64,
        "cargo_graph_sha256": "4" * 64,
        "cargo_package_count": 1,
        "cargo_relationship_count": 1,
        "license": "Apache-2.0",
        "license_sha256": hashlib.sha256(b"license").hexdigest(),
        "builder_image": BUILDER_IMAGE,
        "smoke_image": SMOKE_IMAGE,
        "ordinary_binary_bytes": len(ordinary),
        "ordinary_binary_sha256": hashlib.sha256(ordinary).hexdigest(),
        "service_binary_bytes": len(service),
        "service_binary_sha256": hashlib.sha256(service).hexdigest(),
        "client_binary_bytes": len(client),
        "client_binary_sha256": hashlib.sha256(client).hexdigest(),
        "mcp_bridge_binary_bytes": len(mcp_bridge),
        "mcp_bridge_binary_sha256": hashlib.sha256(mcp_bridge).hexdigest(),
        "non_claims": "service-preview;not-production;no-public-rust-api;no-other-targets",
    }
    files: dict[str, bytes | int] = {
        f"{basename}/bin/kapsel": ordinary,
        f"{basename}/libexec/kapsel/kapseld": service,
        f"{basename}/bin/kapsel-service-client": client,
        f"{basename}/bin/kapsel-service-mcp": mcp_bridge,
        f"{basename}/share/kapsel/kapseld.service": b"unit\n",
        f"{basename}/share/kapsel/kapseld.conf": b"sysusers\n",
        f"{basename}/share/kapsel/kapseld-rbac.yaml": b"rbac\n",
        f"{basename}/share/doc/kapsel/COMMANDS.md": b"commands\n",
        f"{basename}/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md": b"operator\n",
        f"{basename}/share/doc/kapsel/KAPSEL_SERVICE.md": b"service\n",
        f"{basename}/share/doc/kapsel/PRIVACY.md": b"privacy\n",
        f"{basename}/share/doc/kapsel/RELEASE.md": b"release\n",
        f"{basename}/share/doc/kapsel/SECURITY.md": b"security\n",
        f"{basename}/share/doc/kapsel/UPGRADE.md": b"upgrade\n",
        f"{basename}/CHANGELOG.md": b"changelog\n",
        f"{basename}/LICENSE": b"license",
        f"{basename}/RELEASE-METADATA.json": (
            json.dumps(metadata, indent=2, separators=(",", ": ")) + "\n"
        ).encode(),
    }
    if mutate == "service-digest":
        files[f"{basename}/libexec/kapsel/kapseld"] = b"changed"
    if mutate == "client-digest":
        files[f"{basename}/bin/kapsel-service-client"] = b"changed"
    if mutate == "old-schema":
        metadata["artifact_schema"] = "kapsel.release-artifact.v2"
        files[f"{basename}/RELEASE-METADATA.json"] = (json.dumps(metadata) + "\n").encode()
    if mutate == "oversized-file":
        files[f"{basename}/CHANGELOG.md"] = 32 * 1024 * 1024 + 1
    if mutate == "oversized-expanded":
        for name in ["COMMANDS.md", "KAPSEL_SERVICE_OPERATOR.md", "KAPSEL_SERVICE.md"]:
            files[f"{basename}/share/doc/kapsel/{name}"] = 22 * 1024 * 1024

    directories = {
        f"{basename}/",
        f"{basename}/bin/",
        f"{basename}/libexec/",
        f"{basename}/libexec/kapsel/",
        f"{basename}/share/",
        f"{basename}/share/kapsel/",
        f"{basename}/share/doc/",
        f"{basename}/share/doc/kapsel/",
    }
    entries = sorted([*directories, *files])
    if mutate in {"extra", "traversal", "absolute", "duplicate"}:
        added = {
            "extra": f"{basename}/EXTRA",
            "traversal": f"{basename}/../escape",
            "absolute": "/escape",
            "duplicate": f"{basename}/CHANGELOG.md",
        }[mutate]
        entries.append(added)
        entries.sort()

    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        archive_format = {
            "pax": tarfile.PAX_FORMAT,
            "gnu": tarfile.GNU_FORMAT,
        }.get(mutate or "", tarfile.USTAR_FORMAT)
        with tarfile.open(fileobj=compressed, mode="w", format=archive_format) as release:
            for name in entries:
                is_directory = name.endswith("/")
                information = tarfile.TarInfo(name)
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                information.mtime = 0
                information.mode = (
                    0o755
                    if is_directory
                    or name.endswith(
                        ("/kapsel", "/kapseld", "/kapsel-service-client", "/kapsel-service-mcp")
                    )
                    else 0o644
                )
                if mutate == "unsafe-mode" and name.endswith("/CHANGELOG.md"):
                    information.mode = 0o666
                if mutate == "executable-unit" and name.endswith("/kapseld.service"):
                    information.mode = 0o755
                if mutate == "pax" and name.endswith("/CHANGELOG.md"):
                    information.pax_headers = {"comment": "hidden extension"}
                if is_directory:
                    information.type = tarfile.DIRTYPE
                    release.addfile(information)
                    continue
                value = files.get(name, b"extra\n")
                if mutate in {"symlink", "hardlink", "special"} and name.endswith("/CHANGELOG.md"):
                    information.type = {
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "special": tarfile.CHRTYPE,
                    }[mutate]
                    information.linkname = "LICENSE"
                    release.addfile(information)
                    continue
                information.type = tarfile.REGTYPE
                if isinstance(value, int):
                    information.size = value
                    release.addfile(information, ZeroReader(value))
                else:
                    information.size = len(value)
                    release.addfile(information, io.BytesIO(value))
    return output.getvalue()


class ReleaseVerifierTests(unittest.TestCase):
    def test_service_candidate_preparation_uses_one_receiver_read_and_exact_bytes(self) -> None:
        selected = os.environ.get("KAPSEL_TEST_INSPECT")
        if selected is None:
            self.skipTest("set KAPSEL_TEST_INSPECT to the built ordinary executable")
        assert selected is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            SMOKE.reset_kubernetes_fixture()
            SMOKE.KubernetesFixture.receiver_responses.insert(0, SMOKE.deployment("1", 1, False))
            server = SMOKE.http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0), SMOKE.KubernetesFixture
            )
            thread = SMOKE.threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                candidate = SMOKE.prepare_service_candidate(
                    pathlib.Path(selected), root, server.server_port
                )
                self.assertEqual(candidate, (root / "operator.candidate.json").read_bytes())
                self.assertEqual(SMOKE.KubernetesFixture.requests, 1)
                self.assertEqual(SMOKE.KubernetesFixture.mutations, 0)
                self.assertEqual(json.loads(candidate)["service_configuration_version"], 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                SMOKE.reset_kubernetes_fixture()

    def test_cargo_records_reject_malformed_shapes(self) -> None:
        for document in (
            None,
            {"packages": {}, "resolve": {"nodes": []}},
            {"packages": [7], "resolve": {"nodes": []}},
            {"packages": [], "resolve": {"nodes": [{"id": "x", "deps": [7]}]}},
            {
                "packages": [],
                "resolve": {"nodes": [{"id": "x", "deps": [{"pkg": "y", "dep_kinds": [{}]}]}]},
            },
            {
                "packages": [{"id": "x", "name": "x", "version": "1", "manifest_path": "x"}],
                "resolve": {"nodes": []},
            },
            {
                "packages": [],
                "resolve": {
                    "nodes": [{"id": "x", "deps": [{"pkg": "y", "dep_kinds": [{"kind": 7}]}]}]
                },
            },
        ):
            with self.subTest(document=document), self.assertRaises(RuntimeError):
                ASSEMBLY.cargo_graph_records(document)

    def test_kind_caller_probe_compiles_in_the_isolated_interpreter(self) -> None:
        source = JOURNEY.CUSTODY_PROBE_SOURCE.read_text()
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; compile(sys.stdin.read(), '<caller-probe>', 'exec')",
            ],
            input=source,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_extracted_fixture_imports_do_not_execute_the_journeys(self) -> None:
        fixtures = (
            ROOT / "tests/qualification/git_artifact_exercise.py",
            JOURNEY.EXERCISE_SOURCE,
            pathlib.Path(__file__).with_name("operator_example_exercise.py"),
            pathlib.Path(__file__).with_name("caller_custody_exercise.py"),
            pathlib.Path(__file__).with_name("background_caller_fixture.py"),
            JOURNEY.CUSTODY_PROBE_SOURCE,
            JOURNEY.RETIRE_SOURCE,
            JOURNEY.SNAPSHOT_SOURCE,
            JOURNEY.LOST_ACK_SOURCE,
            ROOT / "tests/qualification/git_receiver_hook.py",
            ROOT / "examples/mcp_bridge_fixture.py",
            ROOT / "examples/demo_journal_fixture.py",
            pathlib.Path(__file__).with_name("trivy_fixture.py"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "pathlib.py").write_text("raise SystemExit(99)\n")
            for fixture in fixtures:
                with self.subTest(fixture=fixture.name):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            "import runpy, sys; program = runpy.run_path(sys.argv[1], run_name='fixture_import'); assert callable(program['main'])",
                            str(fixture),
                        ],
                        cwd=root,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(tuple(path.name for path in root.iterdir()), ("pathlib.py",))

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
        }
        fixture_write = dict(event, auditID="fixture", userAgent="kapsel-journey-fixture")
        audit = b"\n".join(json.dumps(item).encode() for item in (fixture_write, event))
        with mock.patch.object(JOURNEY, "run", return_value=audit):
            counts = JOURNEY.collect_patch_counts("fixture")
        self.assertEqual(counts, {case: int(case == "healthy") for case in JOURNEY.CASES})
        duplicate = b"\n".join([json.dumps(event).encode()] * 2)
        with (
            mock.patch.object(JOURNEY, "run", return_value=duplicate),
            self.assertRaises(AssertionError),
        ):
            JOURNEY.collect_patch_counts("fixture")

    def test_agent_output_streams_are_bounded_before_completion(self) -> None:
        for stream in (1, 2):
            with self.subTest(stream=stream):
                with self.assertRaisesRegex(RuntimeError, "byte bound"):
                    JOURNEY.run_agent_process(
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            f"import os; os.write({stream}, b'x' * (256 * 1024 + 1))",
                        ]
                    )
        with self.assertRaises(subprocess.TimeoutExpired):
            JOURNEY.run_agent_process(
                [sys.executable, "-I", "-c", "import time; time.sleep(10)"], timeout=0.1
            )
        result = JOURNEY.run_agent_process(
            [sys.executable, "-I", "-c", "import os; os.write(1, b'out'); os.write(2, b'err')"]
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"out", b"err"))

    def test_journey_python_calls_exclude_caller_writable_imports(self) -> None:
        tree = ast.parse(JOURNEY.EXERCISE_SOURCE.read_bytes())
        invocations = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.List)
            and node.elts
            and ast.unparse(node.elts[0]) == "sys.executable"
        ]
        self.assertEqual(len(invocations), 2)
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
                self.assertEqual(prefix, [sys.executable, "-I", "-"])
                subprocess.run(prefix, input=b"import socket\n", cwd=root, check=True, timeout=5)

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
                report = {"status": "INSPECTED", "operation_id": operation, "result": result}
                path = mock.Mock()
                path.read_text.return_value = "1"
                path.read_bytes.return_value = b"frozen"
                scope = {
                    "pathlib": SimpleNamespace(Path=lambda _, path=path: path),
                    "json": json,
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

    def test_fifo_sidecar_is_rejected_without_waiting_for_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "fifo"
            os.mkfifo(path)
            code = (
                "import importlib.util,pathlib\n"
                f"s=importlib.util.spec_from_file_location('smoke', {str(ROOT / 'tools/release/verify_artifact.py')!r})\n"
                "m=importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\n"
                f"m.read_bounded_regular(pathlib.Path({str(path)!r}),256)\n"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", code], capture_output=True, timeout=5
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"not a bounded regular file", result.stderr)

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
                    SMOKE.refuse_systemd_references(units)
                self.assertTrue(link.is_symlink())
                self.assertFalse(target.exists())

    def test_native_qualification_rejects_dirty_artifact_before_host_commands(self) -> None:
        with (
            mock.patch.object(
                SMOKE, "verified_release", return_value=(b"", {"source_dirty": True})
            ),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "clean committed-source"):
                SMOKE.smoke(
                    pathlib.Path("/unused"), pathlib.Path("/unused"), "0" * 40, service_systemd=True
                )
            command.assert_not_called()

    def test_native_qualification_refuses_wrong_platform_before_host_commands(self) -> None:
        with (
            mock.patch.object(SMOKE.os, "uname", return_value=SimpleNamespace(machine="aarch64")),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "x86-64 Linux"):
                SMOKE.install_systemd_assets(pathlib.Path("/unused"))
            command.assert_not_called()

    def test_service_qualification_refuses_unprivileged_invocation(self) -> None:
        with (
            mock.patch.object(SMOKE.os, "geteuid", return_value=1000),
            mock.patch.object(SMOKE.subprocess, "run") as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                SMOKE.exercise_service(pathlib.Path("/unused"), pathlib.Path("/unused"), True)
            command.assert_not_called()

    def test_documented_bootstrap_never_executes_after_authentication_failure(self) -> None:
        document = ROOT.joinpath("docs/RELEASE.md").read_text()
        _, heading, section = document.partition("## Authenticate and extract the release\n")
        self.assertTrue(heading, "release authentication section is missing")
        section = section.split("\n## ", 1)[0]
        _, fence, commands = section.partition("```sh\n")
        self.assertTrue(fence, "release authentication command block is missing")
        block, closing_fence, _ = commands.partition("```")
        self.assertTrue(closing_fence, "release authentication command block is unterminated")
        with tempfile.TemporaryDirectory(prefix="kapsel-bootstrap-") as temporary:
            private = pathlib.Path(temporary)
            for name, code in {
                "cosign": 'exit "$AUTH_EXIT"',
                "sha256sum": 'exit "$CHECKSUM_EXIT"',
                "python3": ': > "$EXECUTED"',
            }.items():
                program = private / name
                program.write_text("#!/bin/sh\n" + code + "\n")
                program.chmod(0o755)
            for auth_exit, checksum_exit in [(1, 0), (0, 1), (0, 0)]:
                with self.subTest(auth=auth_exit, checksum=checksum_exit):
                    executed = private / "executed"
                    executed.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["/bin/sh", "-c", block],
                        cwd=private,
                        capture_output=True,
                        env={
                            "PATH": str(private),
                            "AUTH_EXIT": str(auth_exit),
                            "CHECKSUM_EXIT": str(checksum_exit),
                            "EXECUTED": str(executed),
                        },
                        timeout=5,
                        check=False,
                    )
                    successful = auth_exit == checksum_exit == 0
                    self.assertEqual(result.returncode == 0, successful)
                    self.assertEqual(executed.exists(), successful)

    def test_graph_includes_service_only_dependencies_but_not_dev_dependencies(self) -> None:
        packages = [
            {
                "id": name,
                "name": name,
                "version": "1.0.0",
                "source": None,
                "license": "MIT",
                "manifest_path": manifest,
            }
            for name, manifest in [
                ("kapsel", "/workspace/Cargo.toml"),
                ("kapsel-daemon", "/workspace/crates/kapsel-daemon/Cargo.toml"),
                ("service-only", "/registry/service-only/Cargo.toml"),
                ("test-only", "/registry/test-only/Cargo.toml"),
            ]
        ]
        nodes = [{"id": package["id"], "deps": []} for package in packages]
        nodes[1]["deps"] = [
            {"pkg": "kapsel", "dep_kinds": [{"kind": None}]},
            {"pkg": "service-only", "dep_kinds": [{"kind": "build"}]},
            {"pkg": "test-only", "dep_kinds": [{"kind": "dev"}]},
        ]
        graph, edges, root = ASSEMBLY.cargo_graph(
            {"packages": packages, "resolve": {"nodes": nodes}}
        )
        self.assertEqual(
            {package["name"] for package in graph}, {"kapsel", "kapsel-daemon", "service-only"}
        )
        self.assertEqual(len(edges), 2)
        self.assertEqual(root, "SPDXRef-Package-kapsel-source")

    def test_canonical_synthetic_archive_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-canonical-") as temporary:
            archive = pathlib.Path(temporary) / "kapsel-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
            metadata = SMOKE.validate_archive(archive, synthetic_archive(archive))
        self.assertEqual(metadata["package_version"], "0.2.0")

    def test_safe_extraction_negative_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-negative-") as temporary:
            archive = pathlib.Path(temporary) / "kapsel-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
            for mutation in [
                "service-digest",
                "client-digest",
                "old-schema",
                "executable-unit",
                "extra",
                "traversal",
                "absolute",
                "duplicate",
                "symlink",
                "hardlink",
                "special",
                "unsafe-mode",
                "oversized-file",
                "oversized-expanded",
                "pax",
                "gnu",
            ]:
                with self.subTest(mutation=mutation):
                    with self.assertRaises(RuntimeError):
                        SMOKE.validate_archive(archive, synthetic_archive(archive, mutate=mutation))

    def test_compressed_archive_size_excess_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-compressed-") as temporary:
            path = pathlib.Path(temporary) / "oversized.tar.gz"
            with path.open("wb") as output:
                output.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(RuntimeError):
                SMOKE.read_bounded_regular(path, 32 * 1024 * 1024)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlinks")
    def test_sidecar_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kapsel-release-sidecar-") as temporary:
            root = pathlib.Path(temporary)
            target = root / "target"
            target.write_text("value")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                SMOKE.read_bounded_regular(link, 256)


class ReleaseArtifactTests(unittest.TestCase):
    def test_model_process_retirement_and_receipt_custody(self) -> None:
        """Real Linux probes for timeout descendants and forged model receipt paths."""
        fixture_directory = pathlib.Path(__file__).parent
        script = (fixture_directory / "caller_custody_exercise.py").read_bytes()
        probe_sources = (
            JOURNEY.RETIRE_SOURCE,
            JOURNEY.SNAPSHOT_SOURCE,
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
                SMOKE_IMAGE,
                "python3",
                "-I",
                "-",
            ],
            input=script,
            check=True,
            timeout=40,
        )

    def test_documented_operator_example(self) -> None:
        """Execute guide preparation with extracted binaries and the existing HTTP fixture."""
        archive = release_archive()
        revision = (
            EXAMPLE_REVISION
            or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        )
        with tempfile.TemporaryDirectory(prefix="kapsel-doc-example-") as temporary:
            root = SMOKE.extract_release(
                archive,
                pathlib.Path(str(archive) + ".sha256"),
                revision,
                pathlib.Path(temporary) / "extracted",
            )
            # Only extracted binaries, their checksum-bound fixture and authored documentation
            # enter this container. No source build or private operator guidance is available.
            script = pathlib.Path(__file__).with_name("operator_example_exercise.py").read_bytes()
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-i",
                    "--platform",
                    "linux/amd64",
                    "--volume",
                    f"{root}:/artifact:ro",
                    "--volume",
                    f"{archive}.verify.py:/fixture.py:ro",
                    "--volume",
                    f"{ROOT / 'docs/KAPSEL_SERVICE_OPERATOR.md'}:/guide.md:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "-I",
                    "-",
                ],
                input=script,
                check=True,
                timeout=180,
            )

    def test_dirty_source_is_rejected_before_build(self) -> None:
        sentinel = ROOT / ".kapsel-release-dirty-test"
        sentinel.write_text("dirty\n")
        try:
            with tempfile.TemporaryDirectory(prefix="kapsel-release-rejected-") as temporary:
                result = subprocess.run(
                    [
                        "python3",
                        str(ASSEMBLER),
                        "--output-directory",
                        temporary,
                    ],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release assembly requires a clean worktree", result.stderr)
                self.assertEqual(list(pathlib.Path(temporary).iterdir()), [])
        finally:
            sentinel.unlink(missing_ok=True)

    def test_extraction_companion_needs_no_checkout_or_executable_invocation(self) -> None:
        archive = release_archive()
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with tempfile.TemporaryDirectory(prefix="kapsel-extraction-only-") as temporary:
            private = pathlib.Path(temporary)
            destination = private / "extracted"
            command = [
                "python3",
                str(archive) + ".verify.py",
                "--archive",
                str(archive),
                "--expected-revision",
                revision,
                "--extract-to",
                str(destination),
            ]
            result = subprocess.run(
                command, cwd=private, capture_output=True, text=True, timeout=30, check=True
            )
            extracted = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(result.stdout.strip(), str(extracted))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue((extracted / "share/kapsel/kapseld.service").is_file())
            before = (extracted / "RELEASE-METADATA.json").read_bytes()
            refused = subprocess.run(
                command, cwd=private, capture_output=True, timeout=30, check=False
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual((extracted / "RELEASE-METADATA.json").read_bytes(), before)
            # A bad revision must fail before creating any destination.
            wrong = private / "wrong"
            command[-1] = str(wrong)
            command[command.index("--expected-revision") + 1] = "0" * 40
            refused = subprocess.run(
                command, cwd=private, capture_output=True, timeout=30, check=False
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(wrong.exists())
            # Even a dangling destination symlink is not an empty extraction root.
            link = private / "link"
            link.symlink_to(private / "absent")
            with self.assertRaises(FileExistsError):
                SMOKE.extract_release(
                    archive, archive.with_name(archive.name + ".sha256"), revision, link
                )
            self.assertFalse((private / "absent").exists())

    def test_verifier_companion_is_digest_bound(self) -> None:
        archive = release_archive()
        with tempfile.TemporaryDirectory(prefix="kapsel-verifier-tamper-") as temporary:
            copied = pathlib.Path(temporary) / archive.name
            for suffix in ("", ".sha256", ".spdx.json", ".SHA256SUMS", ".verify.py"):
                shutil.copyfile(str(archive) + suffix, str(copied) + suffix)
            with pathlib.Path(str(copied) + ".verify.py").open("ab") as verifier:
                verifier.write(b"\n# altered\n")
            destination = pathlib.Path(temporary) / "extracted"
            with self.assertRaisesRegex(RuntimeError, "digest manifest mismatch"):
                SMOKE.extract_release(
                    copied, pathlib.Path(str(copied) + ".sha256"), "0" * 40, destination
                )
            self.assertFalse(destination.exists())

    def test_reference_archive_has_verified_exact_layout_and_smoke(self) -> None:
        expected_dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        )
        archive = release_archive()
        SMOKE.read_bounded_regular(archive, 32 * 1024 * 1024)
        with contextlib.nullcontext(archive.parent) as output:
            version = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())["workspace"][
                "package"
            ]["version"]
            basename = f"kapsel-{version}-{TARGET}"
            self.assertEqual(archive.name, f"{basename}.tar.gz")
            checksum = output / f"{archive.name}.sha256"
            sbom = output / f"{archive.name}.spdx.json"
            manifest = output / f"{archive.name}.SHA256SUMS"
            verifier = output / f"{archive.name}.verify.py"
            self.assertEqual(
                SMOKE.read_bounded_regular(verifier, 64 * 1024),
                ROOT.joinpath("tools/release/verify_artifact.py").read_bytes(),
            )
            checksum_bytes = SMOKE.read_bounded_regular(checksum, 1024)
            sbom_bytes = SMOKE.read_bounded_regular(sbom, 2 * 1024 * 1024)
            manifest_bytes = SMOKE.read_bounded_regular(manifest, 1024)
            self.assertEqual(checksum_bytes.decode(), f"{sha256(archive)}  {archive.name}\n")
            expected_manifest = "".join(
                f"{sha256(path)}  {path.name}\n"
                for path in sorted([archive, checksum, sbom, verifier], key=lambda path: path.name)
            )
            self.assertEqual(manifest_bytes.decode(), expected_manifest)

            expected = {
                f"{basename}/",
                f"{basename}/bin/",
                f"{basename}/bin/kapsel",
                f"{basename}/libexec/",
                f"{basename}/libexec/kapsel/",
                f"{basename}/libexec/kapsel/kapseld",
                f"{basename}/bin/kapsel-service-client",
                f"{basename}/bin/kapsel-service-mcp",
                f"{basename}/share/",
                f"{basename}/share/kapsel/",
                f"{basename}/share/kapsel/kapseld.service",
                f"{basename}/share/kapsel/kapseld.conf",
                f"{basename}/share/kapsel/kapseld-rbac.yaml",
                f"{basename}/share/doc/",
                f"{basename}/share/doc/kapsel/",
                f"{basename}/share/doc/kapsel/COMMANDS.md",
                f"{basename}/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
                f"{basename}/share/doc/kapsel/KAPSEL_SERVICE.md",
                f"{basename}/share/doc/kapsel/PRIVACY.md",
                f"{basename}/share/doc/kapsel/RELEASE.md",
                f"{basename}/share/doc/kapsel/SECURITY.md",
                f"{basename}/share/doc/kapsel/UPGRADE.md",
                f"{basename}/CHANGELOG.md",
                f"{basename}/LICENSE",
                f"{basename}/RELEASE-METADATA.json",
            }
            with tarfile.open(archive, "r:gz") as release:
                members = release.getmembers()
                names = {member.name + ("/" if member.isdir() else "") for member in members}
                self.assertEqual(names, expected)
                ordered_names = [member.name for member in members]
                self.assertEqual(ordered_names, sorted(ordered_names))
                for member in members:
                    identity = (
                        member.uid,
                        member.gid,
                        member.uname,
                        member.gname,
                        member.mtime,
                    )
                    self.assertEqual(identity, (0, 0, "", "", 0))
                    executable = member.isdir() or member.name.endswith(
                        ("/kapsel", "/kapseld", "/kapsel-service-client", "/kapsel-service-mcp")
                    )
                    expected_mode = 0o755 if executable else 0o644
                    self.assertEqual(member.mode, expected_mode, member.name)

                for asset in ("kapseld.service", "kapseld.conf", "kapseld-rbac.yaml"):
                    asset_file = release.extractfile(f"{basename}/share/kapsel/{asset}")
                    assert asset_file is not None
                    self.assertEqual(
                        asset_file.read(),
                        ROOT.joinpath("crates/kapsel-daemon/deploy", asset).read_bytes(),
                    )

                for document_name in [
                    "COMMANDS.md",
                    "KAPSEL_SERVICE_OPERATOR.md",
                    "KAPSEL_SERVICE.md",
                    "PRIVACY.md",
                    "RELEASE.md",
                    "SECURITY.md",
                    "UPGRADE.md",
                ]:
                    document_file = release.extractfile(
                        f"{basename}/share/doc/kapsel/{document_name}"
                    )
                    assert document_file is not None
                    document = document_file.read().decode()
                    for link in re.findall(
                        r"]\((?!https?://|#|mailto:)([^)\s]+[.]md)(?:#[^)]+)?\)", document
                    ):
                        target = posixpath.normpath(f"{basename}/share/doc/kapsel/{link}")
                        self.assertTrue(target.startswith(f"{basename}/"))
                        self.assertIn(target, names, document_name)

                metadata_file = release.extractfile(f"{basename}/RELEASE-METADATA.json")
                assert metadata_file is not None
                metadata_bytes = metadata_file.read()
                self.assertTrue(metadata_bytes.endswith(b"\n"))
                metadata = json.loads(metadata_bytes)
                self.assertEqual(metadata["artifact_schema"], "kapsel.release-artifact.v3")
                self.assertEqual(metadata["package_version"], version)
                self.assertEqual(metadata["rust_target"], TARGET)
                revision = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
                self.assertEqual(metadata["source_revision"], revision)
                tree = subprocess.run(
                    ["git", "rev-parse", "HEAD^{tree}"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
                self.assertEqual(metadata["source_tree"], tree)
                self.assertEqual(metadata["source_dirty"], expected_dirty)
                self.assertEqual(metadata["cargo_lock_sha256"], sha256(ROOT / "Cargo.lock"))
                self.assertEqual(metadata["license"], "Apache-2.0")
                manifest = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())
                self.assertEqual(metadata["license"], manifest["workspace"]["package"]["license"])
                license_file = release.extractfile(f"{basename}/LICENSE")
                assert license_file is not None
                license_bytes = license_file.read()
                self.assertEqual(license_bytes, ROOT.joinpath("LICENSE").read_bytes())
                self.assertEqual(
                    hashlib.sha256(license_bytes).hexdigest(),
                    metadata["license_sha256"],
                )
                self.assertEqual(metadata["builder_image"], BUILDER_IMAGE)
                self.assertEqual(metadata["smoke_image"], SMOKE_IMAGE)
                self.assertEqual(
                    metadata["non_claims"],
                    "service-preview;not-production;no-public-rust-api;no-other-targets",
                )
                self.assertEqual(
                    list(metadata),
                    [
                        "artifact_schema",
                        "package_version",
                        "rust_target",
                        "source_revision",
                        "source_tree",
                        "source_dirty",
                        "cargo_lock_sha256",
                        "cargo_graph_sha256",
                        "cargo_package_count",
                        "cargo_relationship_count",
                        "license",
                        "license_sha256",
                        "builder_image",
                        "smoke_image",
                        "ordinary_binary_bytes",
                        "ordinary_binary_sha256",
                        "service_binary_bytes",
                        "service_binary_sha256",
                        "client_binary_bytes",
                        "client_binary_sha256",
                        "mcp_bridge_binary_bytes",
                        "mcp_bridge_binary_sha256",
                        "non_claims",
                    ],
                )

                for name, path in {
                    "ordinary": "bin/kapsel",
                    "service": "libexec/kapsel/kapseld",
                    "client": "bin/kapsel-service-client",
                    "mcp_bridge": "bin/kapsel-service-mcp",
                }.items():
                    binary_file = release.extractfile(f"{basename}/{path}")
                    assert binary_file is not None
                    binary = binary_file.read()
                    self.assertEqual(len(binary), metadata[f"{name}_binary_bytes"])
                    self.assertEqual(
                        hashlib.sha256(binary).hexdigest(), metadata[f"{name}_binary_sha256"]
                    )
                    self.assertEqual(binary[:4], b"\x7fELF")
                    self.assertEqual(binary[4:6], b"\x02\x01")
                    self.assertEqual(int.from_bytes(binary[18:20], "little"), 62)

            sbom_document = json.loads(sbom_bytes)
            self.assertEqual(sbom_document["spdxVersion"], "SPDX-2.3")
            self.assertEqual(
                sbom_document["documentNamespace"],
                f"https://github.com/kapsel-cloud/kapsel/sbom/{revision}/{sha256(archive)}",
            )
            self.assertEqual(
                sbom_document["creationInfo"]["creators"],
                ["Tool: kapsel-release-sbom/1"],
            )
            self.assertIn(
                "SPDXRef-Package-kapsel-archive",
                {package["SPDXID"] for package in sbom_document["packages"]},
            )
            self.assertIn(
                "SPDXRef-Package-kapsel-source",
                {package["SPDXID"] for package in sbom_document["packages"]},
            )

            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--volume",
                    f"{output}:/input:ro",
                    "--volume",
                    f"{ROOT / 'tools/release/verify_artifact.py'}:/smoke.py:ro",
                    SMOKE_IMAGE,
                    "python3",
                    "/smoke.py",
                    "--archive",
                    f"/input/{archive.name}",
                    "--expected-revision",
                    revision,
                    "--service-container",
                ],
                cwd=ROOT,
                check=True,
                timeout=180,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument(
        "--example-revision",
        help="independently accepted revision for the documented example only; default checkout HEAD",
    )
    arguments, unittest_arguments = parser.parse_known_args()
    RELEASE_ARCHIVE = pathlib.Path(os.path.abspath(arguments.archive))
    EXAMPLE_REVISION = arguments.example_revision
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
