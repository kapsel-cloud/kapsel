#!/usr/bin/env python3
"""Offline verifier regressions and Linux smoke tests for assembled release artifacts."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest import mock

import assemble_artifact as ASSEMBLY
import verify_artifact as SMOKE

ROOT = pathlib.Path(__file__).resolve().parents[2]
ASSEMBLER = pathlib.Path(__file__).with_name("assemble_artifact.py")
TARGET = "x86_64-unknown-linux-gnu"
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

    def test_staged_document_names_and_links_survive_source_reorganisation(self) -> None:
        """Exercise real assembly mappings without compiling or running product binaries."""
        sources = {
            "COMMANDS.md": "docs/reference/commands.md",
            "KAPSEL_SERVICE_OPERATOR.md": "docs/guides/operator.md",
            "KAPSEL_SERVICE.md": "docs/reference/service.md",
            "PRIVACY.md": "docs/reference/privacy.md",
            "RELEASE.md": "docs/reference/release.md",
            "SECURITY.md": "SECURITY.md",
            "UPGRADE.md": "docs/guides/journal_retention.md",
        }

        def fake_build(directory: pathlib.Path):
            binaries = {}
            for name in ("ordinary", "service", "client", "mcp_bridge"):
                binary = directory / name
                binary.write_bytes(b"not an executable")
                binaries[name] = binary
            metadata = directory / "metadata.json"
            metadata.write_text("{}")
            return binaries, metadata

        revision = "1" * 40
        with (
            tempfile.TemporaryDirectory(prefix="kapsel-doc-staging-") as temporary,
            mock.patch.object(ASSEMBLY, "build_binaries", side_effect=fake_build),
            mock.patch.object(ASSEMBLY, "cargo_graph", return_value=([], [], "unused")),
        ):
            staging = pathlib.Path(temporary)
            ASSEMBLY.stage_release(staging, revision, "2" * 40, False)
            documents = staging / "share/doc/kapsel"
            self.assertEqual({path.name for path in documents.iterdir()}, set(sources))
            for name, source in sources.items():
                with self.subTest(document=name):
                    text = (documents / name).read_text()
                    self.assertEqual(
                        text.splitlines()[0], ROOT.joinpath(source).read_text().splitlines()[0]
                    )
                    for target in re.findall(r"]\(([^)\s]+[.]md(?:#[^)]+)?)\)", text):
                        if target.startswith(("https://", "http://")):
                            continue
                        self.assertTrue((documents / target.split("#", 1)[0]).is_file(), target)
            operator = documents.joinpath("KAPSEL_SERVICE_OPERATOR.md").read_text()
            self.assertIn("](RELEASE.md#authenticate-and-extract-the-release)", operator)
            self.assertIn("](KAPSEL_SERVICE.md#action-independence)", operator)
            self.assertIn(
                f"](https://github.com/kapsel-cloud/kapsel/blob/{revision}/"
                "docs/contributing/qualification.md#documented-operator-example)",
                operator,
            )
            self.assertIn(
                f"](https://github.com/kapsel-cloud/kapsel/blob/{revision}/"
                "docs/getting_started.md)",
                operator,
            )
            release = documents.joinpath("RELEASE.md").read_text()
            self.assertIn(
                "](KAPSEL_SERVICE_OPERATOR.md#prepare-your-own-extracted-artifact)", release
            )

    def test_documented_bootstrap_never_executes_after_authentication_failure(self) -> None:
        document = ROOT.joinpath("docs/reference/release.md").read_text()
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

    def test_reference_archive_has_verified_exact_layout_and_smoke(self) -> None:
        archive = release_archive()
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        _, metadata = SMOKE.verified_release(
            archive, archive.with_name(archive.name + ".sha256"), revision
        )
        package = tomllib.loads(ROOT.joinpath("Cargo.toml").read_text())["workspace"]["package"]
        self.assertEqual(archive.name, f"kapsel-{package['version']}-{TARGET}.tar.gz")
        self.assertFalse(metadata["source_dirty"], "artifact qualification needs clean source")
        self.assertEqual(
            metadata["source_tree"],
            subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
            ).strip(),
        )
        self.assertEqual(metadata["cargo_lock_sha256"], sha256(ROOT / "Cargo.lock"))
        self.assertEqual(metadata["license"], package["license"])
        verifier = archive.with_name(archive.name + ".verify.py")
        self.assertEqual(
            SMOKE.read_bounded_regular(verifier, 64 * 1024),
            ROOT.joinpath("tools/release/verify_artifact.py").read_bytes(),
        )

        # The verifier's independent hostile vectors own format, layout and digest rules.
        # This artifact adds source correspondence and actual executable/installed observations.
        with tempfile.TemporaryDirectory() as temporary:
            destination = pathlib.Path(temporary) / "extracted"
            extracted = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(verifier),
                    "--archive",
                    str(archive),
                    "--expected-revision",
                    revision,
                    "--extract-to",
                    str(destination),
                ],
                cwd=temporary,
                capture_output=True,
                timeout=30,
                check=True,
            )
            root = destination / archive.name.removesuffix(".tar.gz")
            self.assertEqual(extracted.stdout.decode().strip(), str(root))
            self.assertEqual(extracted.stderr, b"")
            self.assertEqual((root / "LICENSE").read_bytes(), ROOT.joinpath("LICENSE").read_bytes())
            for asset in ("kapseld.service", "kapseld.conf", "kapseld-rbac.yaml"):
                self.assertEqual(
                    root.joinpath("share/kapsel", asset).read_bytes(),
                    ROOT.joinpath("crates/kapsel-daemon/deploy", asset).read_bytes(),
                )
            for document in root.joinpath("share/doc/kapsel").glob("*.md"):
                for link in re.findall(
                    r"]\((?!https?://|#|mailto:)([^)\s]+[.]md)(?:#[^)]+)?\)", document.read_text()
                ):
                    target = (document.parent / link).resolve()
                    self.assertTrue(target.is_relative_to(root.resolve()))
                    self.assertTrue(target.is_file(), link)
            for relative in (
                "bin/kapsel",
                "libexec/kapsel/kapseld",
                "bin/kapsel-service-client",
                "bin/kapsel-service-mcp",
            ):
                with root.joinpath(relative).open("rb") as source:
                    header = source.read(20)
                self.assertEqual(header[:6], b"\x7fELF\x02\x01")
                self.assertEqual(int.from_bytes(header[18:20], "little"), 62)

        # Execute the checksum-bound companion, not a verifier mounted from the checkout.
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--volume",
                f"{archive.parent}:/input:ro",
                SMOKE_IMAGE,
                "python3",
                "-I",
                f"/input/{verifier.name}",
                "--archive",
                f"/input/{archive.name}",
                "--expected-revision",
                revision,
            ],
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
