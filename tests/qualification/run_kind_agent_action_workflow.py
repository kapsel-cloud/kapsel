#!/usr/bin/env python3
"""Exercise extracted preview binaries against one owned, audited kind receiver.

This is a disposable product-interface test with optional confined Codex execution, not native systemd proof.
The old source/test-hook experiment is reproducible at its recorded historical revision.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import selectors
import stat
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = (
    "kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4"
)
RUNNER = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
INITIAL = (
    "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
)
DESIRED = (
    "registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
CASES = {"healthy": 0, "stale": 0, "service-loss": 60, "caller-loss": 210, "independent": 0}

RETIRE_SOURCE = pathlib.Path(__file__).with_name("retire_callers.py")
SNAPSHOT_SOURCE = pathlib.Path(__file__).with_name("snapshot_receipt.py")
CUSTODY_PROBE_SOURCE = pathlib.Path(__file__).with_name("caller_custody_probe.py")
LOST_ACK_SOURCE = pathlib.Path(__file__).with_name("submit_without_ack.py")
RETIRE_CALLERS = RETIRE_SOURCE.read_bytes().decode("utf-8")
RECEIPT_SNAPSHOT = SNAPSHOT_SOURCE.read_bytes().decode("utf-8")

# Only the artifact, public procedure and scoped fixture authority enter the operating container.
# No product source, test-feature binary, private database edit or lifecycle hook is used.
EXERCISE_SOURCE = pathlib.Path(__file__).with_name("kind_agent_action_exercise.py")


# Current ordinary tool callers retain an 8 MiB audit head plus small command output/config input.
ORDINARY_TOOL_OUTPUT_LIMIT = 12 * 1024 * 1024
ORDINARY_TOOL_STDIN_LIMIT = 1024 * 1024
CODEX_OUTPUT_LIMIT = 256 * 1024


def run_bounded_process(
    arguments: list[str],
    *,
    data: bytes | None = None,
    timeout: float = 60,
    output_limit: int = ORDINARY_TOOL_OUTPUT_LIMIT,
    input_limit: int = ORDINARY_TOOL_STDIN_LIMIT,
    overflow_message: str = "command output exceeded its byte bound",
) -> subprocess.CompletedProcess:
    """Capture subprocess pipes within byte limits and one deadline through EOF and reap."""
    if data is not None and len(data) > input_limit:
        raise RuntimeError("command input exceeded its byte bound")

    streams = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    stdin_setting = subprocess.PIPE if data is not None else subprocess.DEVNULL
    input_offset = 0
    input_pipe = None

    with (
        subprocess.Popen(
            arguments, stdin=stdin_setting, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process,
        selectors.DefaultSelector() as selector,
    ):
        try:
            if data is not None:
                if process.stdin is None:
                    raise RuntimeError("command input pipe was not created")
                input_pipe = process.stdin
            for index, stream in enumerate((process.stdout, process.stderr)):
                if stream is None:
                    raise RuntimeError("command output pipe was not created")
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, ("output", index))
            if input_pipe is not None:
                os.set_blocking(input_pipe.fileno(), False)
                selector.register(input_pipe, selectors.EVENT_WRITE, ("input", None))

            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("subprocess", timeout)
                for key, _ in selector.select(remaining):
                    kind, index = key.data
                    if kind == "input":
                        assert data is not None
                        if input_offset < len(data):
                            try:
                                input_offset += os.write(key.fd, data[input_offset:])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                input_offset = len(data)
                        if input_offset == len(data):
                            selector.unregister(key.fileobj)
                            if input_pipe is not None:
                                input_pipe.close()
                        continue

                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    assert index is not None
                    output = streams[index]
                    if len(output) + len(chunk) > output_limit:
                        raise RuntimeError(overflow_message)
                    output.extend(chunk)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("subprocess", timeout)
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise subprocess.TimeoutExpired("subprocess", timeout) from None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
    return subprocess.CompletedProcess(
        arguments, process.returncode, bytes(streams[0]), bytes(streams[1])
    )


def run(arguments: list[str], *, data: bytes | None = None, timeout: int = 60) -> bytes:
    result = run_bounded_process(arguments, data=data, timeout=timeout)
    if result.returncode:
        # Never render argv, input or captured stderr: fixture commands may carry credentials.
        raise RuntimeError(f"command exited {result.returncode}")
    return result.stdout


def run_agent_process(arguments: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess:
    """Bound both model output streams while draining, before retaining their bytes."""
    return run_bounded_process(
        arguments,
        timeout=timeout,
        output_limit=CODEX_OUTPUT_LIMIT,
        overflow_message="confined Codex output exceeded its byte bound",
    )


def check_agent_product_evidence(caller: list[str], diagnostics: dict[str, object]) -> str:
    """Read installed-client evidence only after all model caller processes retire."""
    client = [*caller, "/usr/bin/kapsel-service-client"]
    status = json.loads(run([*client, "status", "healthy"]))
    if status.get("status") != "SUCCEEDED":
        raise RuntimeError(
            f"agent did not complete the original approved action: {status.get('status')}; "
            f"safe diagnostics: {json.dumps(diagnostics, sort_keys=True)}"
        )
    for case in CASES:
        if (
            case != "healthy"
            and json.loads(run([*client, "status", case])).get("status") != "NOT_FOUND"
        ):
            raise RuntimeError("agent selected an unintended fixture action")

    exported = json.loads(run([*client, "receipt", "healthy", "/home/caller/checked.receipt"]))
    if exported.get("status") != "READY":
        raise RuntimeError("original receipt unavailable after the model run")
    canonical = run(
        [
            *caller,
            "/usr/local/bin/python3",
            "-I",
            "-c",
            RECEIPT_SNAPSHOT,
            "/home/caller/checked.receipt",
        ]
    )

    again = json.loads(run([*client, "receipt", "healthy", "/home/caller/repeated.receipt"]))
    repeated = run(
        [
            *caller,
            "/usr/local/bin/python3",
            "-I",
            "-c",
            RECEIPT_SNAPSHOT,
            "/home/caller/repeated.receipt",
        ]
    )
    digest = exported.get("receipt_sha256")
    if (
        not isinstance(digest, str)
        or repeated != canonical
        or again.get("receipt_sha256") != digest
    ):
        raise RuntimeError("repeated retrieval changed original product evidence")
    return digest


def run_agent(
    name: str, workspace: pathlib.Path, binary: pathlib.Path, auth: pathlib.Path
) -> dict[str, object]:
    """Run Codex inside the confined caller, never as a privileged host tool driver."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready = subprocess.run(
            ["docker", "exec", name, "test", "-f", "/operator/caller-ready"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("caller confinement probes did not finish")

    run(["docker", "exec", name, "mkdir", "-m", "0700", "-p", "/home/caller/.codex"])
    run(["docker", "cp", str(binary), name + ":/usr/local/bin/codex"])
    code_host = binary.with_name("codex-code-mode-host")
    run(["docker", "cp", str(code_host), name + ":/usr/local/bin/codex-code-mode-host"])
    run(["docker", "cp", str(auth), name + ":/home/caller/.codex/auth.json"])
    config = b'[mcp_servers.kapsel_service]\ncommand = "/usr/bin/kapsel-service-mcp"\nargs = []\n'
    config_result = subprocess.run(
        ["docker", "exec", "-i", name, "tee", "/home/caller/.codex/config.toml"],
        input=config,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if config_result.returncode != 0:
        raise RuntimeError("Codex config write failed")
    run(["docker", "exec", name, "chown", "-R", "61001:61000", "/home/caller"])
    run(["docker", "exec", name, "chmod", "0700", "/home/caller", "/home/caller/.codex"])
    run(
        [
            "docker",
            "exec",
            name,
            "chmod",
            "0600",
            "/home/caller/.codex/auth.json",
            "/home/caller/.codex/config.toml",
        ]
    )

    caller = [
        "docker",
        "exec",
        "--user",
        "61001:61000",
        "--workdir",
        "/home/caller",
        "--env",
        "HOME=/home/caller",
        "--env",
        "CODEX_HOME=/home/caller/.codex",
        name,
    ]
    version = run([*caller, "/usr/local/bin/codex", "--version"]).decode().strip()
    prompt = (
        "This is an explicitly approved disposable Kapsel test. Use only the configured "
        "kapsel_service MCP tools to list operator-approved handles and read history. "
        "Select only the existing healthy ID for demo/agent-healthy, container api. Read its "
        "status, submit healthy if not yet admitted, then read status until a terminal result. "
        "Get its original receipt using MCP. Do not call a shell to mutate or read private files. "
        "Do not submit any other ID or create authority. Report the receiver result without claiming "
        "application quality. Do not open or print authentication material. You have an unprivileged "
        "shell in a disposable container, not operator or Kubernetes credentials."
    )
    try:
        # This bypass applies ONLY to Codex's inner prompts/sandbox. The actual execution boundary
        # is the already-probed non-root Docker identity, no-new-privileges and private OS custody.
        # There is no host shell tool, Docker socket, private bind or product source in this caller.
        try:
            result = run_agent_process(
                [
                    *caller,
                    "/usr/local/bin/codex",
                    "exec",
                    "--ephemeral",
                    "--ignore-rules",
                    "--skip-git-repo-check",
                    "--enable",
                    "code_mode_host",
                    "--color",
                    "never",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "--json",
                    prompt,
                ],
                timeout=120,
            )
        finally:
            retired = run(
                [*caller, "/usr/local/bin/python3", "-I", "-c", RETIRE_CALLERS], timeout=10
            )
            if retired != b"CALLERS_RETIRED\n":
                raise RuntimeError("model caller processes did not retire")
        if result.returncode != 0:
            raise RuntimeError("confined Codex run failed; inspect original product identity")

        events = [json.loads(line) for line in result.stdout.splitlines()]
        completed = [event for event in events if event.get("type") == "turn.completed"]
        runtime_error = any(event.get("item", {}).get("type") == "error" for event in events)
        if len(completed) != 1 or runtime_error:
            raise RuntimeError("Codex did not complete a turn without runtime errors")
        # Bounded diagnostics omit model text, tool arguments/results and credentials.
        known_items = {"agent_message", "mcp_tool_call", "command_execution", "reasoning", "error"}
        item_counts: dict[str, int] = {}
        for event in events:
            item_type = event.get("item", {}).get("type")
            if item_type is not None:
                count_key = item_type if item_type in known_items else "other"
                item_counts[count_key] = item_counts.get(count_key, 0) + 1
        diagnostics = {
            "item_counts": item_counts,
            "mcp_startup_failed": b"startup failed" in result.stderr.lower(),
        }

        receipt_digest = check_agent_product_evidence(caller, diagnostics)

        # Trust product evidence, not the model's prose. Only this fixed completion signal reaches
        # the fixture driver; model-produced commands and session identifiers never leave the caller.
        path = workspace / "selection.json"
        path.write_text(json.dumps({"operation_id": "healthy"}))
        run(["docker", "cp", str(path), name + ":/operator/selection.pending"])
        run(
            [
                "docker",
                "exec",
                name,
                "mv",
                "/operator/selection.pending",
                "/operator/selection.json",
            ]
        )
        print(
            "Confined Codex completed the approved healthy action through the service MCP bridge",
            flush=True,
        )
        return {
            "cli_version": version,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "code_mode_host_sha256": hashlib.sha256(code_host.read_bytes()).hexdigest(),
            "operation_id": "healthy",
            "status": "SUCCEEDED",
            "usage": completed[0].get("usage"),
            "uid": 61001,
            "raw_session_retained": False,
            "receipt_sha256": receipt_digest,
        }
    finally:
        run(["docker", "exec", name, "rm", "-f", "/home/caller/.codex/auth.json"])


def execute_journey_container(
    name: str,
    evidence: pathlib.Path,
    source: bytes,
    workspace: pathlib.Path,
    agent_binary: pathlib.Path | None,
    agent_auth: pathlib.Path,
) -> tuple[int, dict[str, object] | None]:
    agent_evidence = None
    with (evidence / "exercise.log").open("wb") as log:
        process = subprocess.Popen(
            ["docker", "start", "--attach", "--interactive", name],
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            if process.stdin is None:
                raise RuntimeError("journey input pipe was not created")
            process.stdin.write(source)
            process.stdin.close()
            if agent_binary is not None:
                agent_evidence = run_agent(name, workspace, agent_binary, agent_auth)
            exercise_exit = process.wait(timeout=450)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    return exercise_exit, agent_evidence


def collect_patch_counts(name: str) -> dict[str, int]:
    """Read bounded, unrotated API-server audit evidence, independently of product counters."""
    audit = run(
        [
            "docker",
            "exec",
            name + "-control-plane",
            "sh",
            "-c",
            "test -z \"$(find /var/log/kubernetes -maxdepth 1 -name 'journey-audit*' ! -name journey-audit.log -print)\" && head -c 8388609 /var/log/kubernetes/journey-audit.log",
        ]
    )
    assert len(audit) <= 8388608, "audit exceeded evidence bound"
    counts = {case: 0 for case in CASES}
    seen_audit_ids = set()
    for line in audit.splitlines():
        event = json.loads(line)
        is_patch = event.get("verb") == "patch"
        is_fixture_write = event.get("userAgent") == "kapsel-journey-fixture"
        if not is_patch or is_fixture_write:
            continue

        username = event.get("user", {}).get("username")
        if username != "system:serviceaccount:demo:journey":
            continue
        assert event["auditID"] not in seen_audit_ids
        seen_audit_ids.add(event["auditID"])
        case = event["objectRef"]["name"].removeprefix("agent-")
        counts[case] += 1
    return counts


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--retained-archive", type=pathlib.Path)
    parser.add_argument("--retained-revision")
    parser.add_argument(
        "--agent",
        action="store_true",
        help="Run Codex as the confined Linux caller for the first action",
    )
    parser.add_argument(
        "--codex-binary", type=pathlib.Path, help="Verified Linux x86-64 Codex executable"
    )
    parser.add_argument(
        "--codex-auth", type=pathlib.Path, default=pathlib.Path.home() / ".codex/auth.json"
    )
    args = parser.parse_args()
    if (args.retained_archive is None) != (args.retained_revision is None):
        parser.error("retained archive and exact revision must be supplied together")
    if args.agent:
        if args.codex_binary is None:
            parser.error("--agent requires --codex-binary with an accepted Linux executable")
        args.codex_binary = args.codex_binary.resolve()
        for component in (args.codex_binary, args.codex_binary.with_name("codex-code-mode-host")):
            if not component.is_file() or not os.access(component, os.X_OK):
                parser.error(
                    "Codex requires executable codex and matching codex-code-mode-host siblings"
                )
        custody = args.codex_auth.lstat()
        if (
            not stat.S_ISREG(custody.st_mode)
            or custody.st_uid != os.getuid()
            or custody.st_nlink != 1
            or custody.st_mode & 0o077
            or custody.st_size > 65536
        ):
            parser.error(
                "Codex auth must be an owned private single-link regular file, at most 64 KiB"
            )
    return args


def main() -> None:
    args = parse_arguments()
    os.umask(0o077)
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="kapsel-live-artifact-"))
    print(f"Private evidence workspace: {workspace}", flush=True)
    exercise_source = EXERCISE_SOURCE.read_bytes()
    (workspace / EXERCISE_SOURCE.name).write_bytes(exercise_source)
    custody_probe = CUSTODY_PROBE_SOURCE.read_bytes()
    lost_ack_source = LOST_ACK_SOURCE.read_bytes()
    for source_path, source_bytes in (
        (LOST_ACK_SOURCE, lost_ack_source),
        (CUSTODY_PROBE_SOURCE, custody_probe),
        (RETIRE_SOURCE, RETIRE_CALLERS.encode("utf-8")),
        (SNAPSHOT_SOURCE, RECEIPT_SNAPSHOT.encode("utf-8")),
    ):
        (workspace / source_path.name).write_bytes(source_bytes)
        digest = hashlib.sha256(source_bytes).hexdigest()
        (workspace / (source_path.name + ".sha256")).write_text(digest + "\n")

    spec = importlib.util.spec_from_file_location(
        "artifact", ROOT / "tools/release/verify_artifact.py"
    )
    assert spec is not None and spec.loader is not None
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    archive = args.archive.resolve()
    extracted = artifact.extract_release(
        archive, pathlib.Path(str(archive) + ".sha256"), args.revision, workspace / "extracted"
    )

    if json.loads((extracted / "RELEASE-METADATA.json").read_bytes())["source_dirty"]:
        raise RuntimeError("packaged Kubernetes qualification requires a clean-source artifact")
    retained = None
    retained_mount = []
    if args.retained_archive is not None:
        args.retained_archive = args.retained_archive.resolve(strict=True)
        retained = artifact.extract_release(
            args.retained_archive,
            pathlib.Path(str(args.retained_archive) + ".sha256"),
            args.retained_revision,
            workspace / "retained-extracted",
        )
        if json.loads((retained / "RELEASE-METADATA.json").read_bytes())["source_dirty"]:
            raise RuntimeError("retained history requires a clean-source producer")
        retained_mount = ["--volume", f"{retained}:/retained-artifact:ro"]

    name = "kapsel-journey-" + uuid.uuid4().hex[:10]
    kubeconfig = workspace / "admin.yaml"
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
    (inputs / CUSTODY_PROBE_SOURCE.name).write_bytes(custody_probe)
    (inputs / LOST_ACK_SOURCE.name).write_bytes(lost_ack_source)

    evidence = workspace / "evidence"
    evidence.mkdir(mode=0o700)

    policy = {
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Policy",
        "rules": [
            {
                "level": "Metadata",
                "verbs": ["get", "patch"],
                "namespaces": ["demo"],
                "resources": [{"group": "apps", "resources": ["deployments"]}],
                "omitStages": ["ResponseStarted", "ResponseComplete"],
            },
            {"level": "None"},
        ],
    }
    (workspace / "audit-policy.json").write_text(json.dumps(policy))
    configuration = f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {workspace}/audit-policy.json
    containerPath: /etc/kubernetes/journey-audit.json
    readOnly: true
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-policy-file: /etc/kubernetes/journey-audit.json
        audit-log-path: /var/log/kubernetes/journey-audit.log
        audit-log-maxsize: "8"
        audit-log-maxbackup: "1"
      extraVolumes:
      - name: audit-policy
        hostPath: /etc/kubernetes/journey-audit.json
        mountPath: /etc/kubernetes/journey-audit.json
        readOnly: true
        pathType: File
      - name: audit-log
        hostPath: /var/log/kubernetes
        mountPath: /var/log/kubernetes
        pathType: DirectoryOrCreate
"""
    (workspace / "kind.yaml").write_text(configuration)
    kubectl = ["kubectl", "--kubeconfig", str(kubeconfig)]
    cluster_owned = False
    container_owned = False
    try:
        assert name not in run(["kind", "get", "clusters"]).decode().splitlines()
        cluster_owned = True
        run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                name,
                "--image",
                NODE,
                "--config",
                str(workspace / "kind.yaml"),
                "--kubeconfig",
                str(kubeconfig),
                "--wait",
                "120s",
            ],
            timeout=180,
        )
        for image in (INITIAL, DESIRED):
            run(["docker", "exec", name + "-control-plane", "crictl", "pull", image], timeout=120)

        run([*kubectl, "create", "namespace", "demo"])
        for case in CASES:
            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "agent-" + case, "namespace": "demo"},
                "spec": {
                    "replicas": 1,
                    "minReadySeconds": CASES[case],
                    "progressDeadlineSeconds": 600,
                    "selector": {"matchLabels": {"app": case}},
                    "template": {
                        "metadata": {"labels": {"app": case}},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "containers": [{"name": "api", "image": INITIAL}],
                        },
                    },
                },
            }
            run([*kubectl, "apply", "-f", "-"], data=json.dumps(deployment).encode())
        run(
            [
                *kubectl,
                "-n",
                "demo",
                "wait",
                "deployment",
                "--all",
                "--for=condition=Available",
                "--timeout=300s",
            ],
            timeout=320,
        )

        run([*kubectl, "-n", "demo", "create", "serviceaccount", "journey"])
        run(
            [
                *kubectl,
                "-n",
                "demo",
                "create",
                "role",
                "journey",
                "--verb=get,patch",
                "--resource=deployments.apps",
                *("--resource-name=agent-" + case for case in CASES),
            ]
        )
        run(
            [
                *kubectl,
                "-n",
                "demo",
                "create",
                "rolebinding",
                "journey",
                "--role=journey",
                "--serviceaccount=demo:journey",
            ]
        )

        token = (
            run([*kubectl, "-n", "demo", "create", "token", "journey", "--duration=1h"])
            .decode()
            .strip()
        )
        admin = json.loads(run([*kubectl, "config", "view", "--raw", "-o", "json"]))
        address = (
            run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{.NetworkSettings.Networks.kind.IPAddress}}",
                    name + "-control-plane",
                ]
            )
            .decode()
            .strip()
        )
        scoped = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "journey",
            "clusters": [
                {
                    "name": "journey",
                    "cluster": {
                        "server": "https://" + address + ":6443",
                        "certificate-authority-data": admin["clusters"][0]["cluster"][
                            "certificate-authority-data"
                        ],
                    },
                }
            ],
            "users": [{"name": "journey", "user": {"token": token}}],
            "contexts": [{"name": "journey", "context": {"cluster": "journey", "user": "journey"}}],
        }

        (inputs / "kubeconfig.json").write_text(json.dumps(scoped))
        (inputs / "settings.json").write_text(
            json.dumps({"cases": CASES, "desired": DESIRED, "agent": args.agent})
        )
        run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--platform",
                "linux/amd64",
                "--network",
                "kind",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=4g" if args.agent else "--memory=1g",
                "--volume",
                f"{extracted}:/artifact:ro",
                *retained_mount,
                "-i",
                RUNNER,
                "python3",
                "-I",
                "-",
            ]
        )
        container_owned = True
        # Host bind permissions are not a portable caller boundary (notably under Docker Desktop).
        # Copy the private directory into the container with Docker's default root ownership.
        run(["docker", "cp", str(inputs), name + ":/inputs"])

        started = time.monotonic()
        exercise_exit, agent_evidence = execute_journey_container(
            name,
            evidence,
            exercise_source,
            workspace,
            args.codex_binary.resolve() if args.agent else None,
            args.codex_auth.resolve(),
        )
        run(["docker", "cp", name + ":/evidence/.", str(evidence)])

        counts = collect_patch_counts(name)
        summary = {
            "source_revision": args.revision,
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "retained_source_revision": args.retained_revision,
            "retained_archive_sha256": (
                hashlib.sha256(args.retained_archive.read_bytes()).hexdigest()
                if args.retained_archive is not None
                else None
            ),
            "exercise_sha256": hashlib.sha256(exercise_source).hexdigest(),
            "node": NODE,
            "runner": RUNNER,
            "http_patch_counts": counts,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "exercise_exit": exercise_exit,
            "representative_agent": agent_evidence,
            "limits": "container process/socket proof; no native systemd, publication or application-quality claim",
        }
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2), flush=True)
        assert exercise_exit == 0, "exercise failed; inspect private exercise.log"
        assert counts == {case: int(case != "stale") for case in CASES}, counts
    finally:
        try:
            if container_owned:
                run(["docker", "rm", "-f", name])
        finally:
            if cluster_owned:
                run(["kind", "delete", "cluster", "--name", name], timeout=120)
        print(
            f"Owned container/cluster cleanup finished. Private workspace retained: {workspace}",
            flush=True,
        )


if __name__ == "__main__":
    main()
