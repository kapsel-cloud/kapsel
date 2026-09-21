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

ROOT = pathlib.Path(__file__).resolve().parents[1]
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

# Runs only as the caller in the fixture's private PID namespace. Linux kill(-1) applies
# kernel UID checks and excludes the invoking process. No numeric-PID kill race, privileged
# signals, or reliance on killing only the host docker-exec client. Never invoke this as root.
RETIRE_CALLERS = r"""
import os
import pathlib
import signal
import time

assert os.getuid() == os.geteuid() == 61001 and os.getpid() != 1
self_status = pathlib.Path("/proc/self/status").read_bytes()
assert int(next(line for line in self_status.splitlines() if line.startswith(b"CapEff:")).split()[1], 16) == 0
deadline = time.monotonic() + 3
quiet = False
while True:
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass
    active = 0
    processes = list(pathlib.Path("/proc").glob("[0-9]*"))
    assert len(processes) <= 256, "unexpected process population"
    for path in processes:
        if int(path.name) == os.getpid():
            continue
        try:
            with (path / "status").open("rb") as stream:
                data = stream.read(4097)
        except FileNotFoundError:
            continue
        assert len(data) <= 4096
        fields = dict(line.split(b":", 1) for line in data.splitlines() if b":" in line)
        if fields[b"Uid"].split()[0] == b"61001" and fields[b"State"].split()[0] not in (b"Z", b"X"):
            active += 1
    if active == 0 and quiet:
        break
    quiet = active == 0
    assert time.monotonic() < deadline, "caller retirement incomplete"
    time.sleep(0.01)
print("CALLERS_RETIRED")
"""

RECEIPT_SNAPSHOT = r"""
import os
import stat
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    metadata = os.fstat(fd)
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    assert metadata.st_uid == os.getuid() and metadata.st_size <= 65536
    with os.fdopen(fd, "rb", closefd=False) as stream:
        data = stream.read(65537)
    assert len(data) <= 65536
    sys.stdout.buffer.write(data)
finally:
    os.close(fd)
"""

# Only the artifact, public procedure and scoped fixture authority enter the operating container.
# No product source, test-feature binary, private database edit or lifecycle hook is used.
EXERCISE = r'''
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

os.umask(0o077)
pathlib.Path("/evidence").mkdir(mode=0o700)
settings = json.loads(pathlib.Path("/inputs/settings.json").read_text())
workspace = pathlib.Path("/operator")
workspace.mkdir(mode=0o700)
os.chdir(workspace)
guide = pathlib.Path("/artifact/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md").read_text()
match = re.findall(r"<!-- example-keys -->\s*```sh\n(.*?)\n```", guide, re.S)
assert len(match) == 1, "artifact lacks the public key-generation example"
subprocess.run(["sh", "-eu", "-c", match[0]], check=True, timeout=30)
for directory in ("/usr/libexec", "/usr/libexec/kapsel"):
    pathlib.Path(directory).mkdir(mode=0o755, exist_ok=True)
    pathlib.Path(directory).chmod(0o755)
for source, destination in (("bin/kapsel", "/usr/bin/kapsel"),
                            ("bin/kapsel-service-client", "/usr/bin/kapsel-service-client"),
                            ("libexec/kapsel/kapseld", "/usr/libexec/kapsel/kapseld")):
    pathlib.Path(destination).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile("/artifact/" + source, destination)
    pathlib.Path(destination).chmod(0o755)
for path, mode in (("/etc/kapsel", 0o700), ("/var/lib/kapsel", 0o700), ("/run/kapsel", 0o750)):
    pathlib.Path(path).mkdir(mode=mode)
    pathlib.Path(path).chmod(mode)
    os.chown(path, 61000, 61000)

config = json.loads(pathlib.Path("/inputs/kubeconfig.json").read_text())
cluster = config["clusters"][0]["cluster"]
context = ssl.create_default_context(cadata=base64.b64decode(cluster["certificate-authority-data"]).decode())
token = config["users"][0]["user"]["token"]

def receiver(name, patch=None):
    data = None if patch is None else json.dumps(patch).encode()
    request = urllib.request.Request(cluster["server"] + "/apis/apps/v1/namespaces/demo/deployments/" + name,
        data=data, method="GET" if patch is None else "PATCH",
        headers={"Authorization": "Bearer " + token, "User-Agent": "kapsel-journey-fixture",
                 "Content-Type": "application/merge-patch+json"})
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        body = response.read(262145)
        assert len(body) <= 262144
        return json.loads(body)

def command(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=30, **kwargs)
    assert result.returncode == 0, (arguments[0], result.returncode)
    return result.stdout

# The fixture operator explicitly owns these disposable Deployments. No GitOps reconciler is
# disabled. B is independently assessed; conflicting intent is never provisioned to the caller.
prepare = ["/usr/bin/kapsel", "prepare-service-config", "--authorization-key", "approval-key-1", "approval.pub"]
for case in settings["cases"]:
    intent = {"authorization_id": "approval-" + case, "operation_id": case,
        "namespace": "demo", "deployment": "agent-" + case, "container": "api",
        "immutable_image_digest": settings["desired"]}
    pathlib.Path(case + ".json").write_text(json.dumps(intent))
    command(["/usr/bin/kapsel", "provision-snapshot-grant", "--authorization", case + ".json",
        "--kubeconfig", "/inputs/kubeconfig.json", "--signing-seed", "approval.seed",
        "--signing-key-id", "approval-key-1", "--output", case + ".grant"])
    prepare += ["--approval", "Approved " + case, case + ".grant"]
prepare += ["--receipt-signing-key-id", "receipt-key-1", "--output", "candidate.json"]
command(prepare)
document = pathlib.Path("candidate.json").read_bytes()
for source, target in (("/inputs/kubeconfig.json", "/etc/kapsel/kubeconfig.yaml"),
                       ("receipt.seed", "/etc/kapsel/receipt.seed")):
    shutil.copyfile(source, target)
    os.chmod(target, 0o600)
    os.chown(target, 61000, 61000)
service = "/usr/libexec/kapsel/kapseld"
client = "/usr/bin/kapsel-service-client"
identity = {"user": 61001, "group": 61000, "extra_groups": []}

def publish(value):
    result = command([service, "--replace-operator-config"], input=value,
                     user=61000, group=61000, extra_groups=[])
    assert result == b"PUBLISHED\n"

publish(document)
receiver("agent-stale", {"metadata": {"annotations": {"journey-fixture/stale": "true"}}})
process = None
reports = []

def read(*arguments):
    result = json.loads(command([client, *arguments], **identity))
    assert result["version"] == 1
    return result

def wait(case, predicate, seconds=200):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert process.poll() is None, "service exited"
        result = read("status", case)
        if predicate(result):
            return result
        time.sleep(0.1)
    raise AssertionError("status deadline: " + case)

def start():
    global process
    process = subprocess.Popen([service, "--operator-config", "/etc/kapsel/operator.json",
        "--socket", "/run/kapsel/kapseld.sock"], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        user=61000, group=61000, extra_groups=[], umask=0o077)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        assert process.poll() is None, "service startup failed"
        result = subprocess.run([client, "history"], capture_output=True, timeout=10, **identity)
        if result.returncode == 0:
            return
        time.sleep(0.05)
    raise AssertionError("history unavailable")

def stop(crash=False):
    if crash:
        process.kill()
    else:
        process.terminate()
    _, diagnostics = process.communicate(timeout=30)
    assert process.returncode == (-9 if crash else 0)
    assert len(diagnostics) <= 4096
    for secret in (token.encode(), pathlib.Path("approval.seed").read_bytes().hex().encode(),
                   pathlib.Path("receipt.seed").read_bytes().hex().encode()):
        assert secret not in diagnostics

def receipt(case, suffix):
    path = pathlib.Path("/tmp/" + case + "-" + suffix + ".receipt")
    assert read("receipt", case, str(path))["status"] == "READY"
    report = json.loads(command(["/usr/bin/kapsel", "inspect", "--receipt", str(path),
        "--trust", "receipt.trust", "--evaluation-time-unix-s",
        pathlib.Path("evaluation-time.txt").read_text().strip()]))
    assert report["status"] == "INSPECTED"
    assert report["operation_id"] == case, report
    assert report["result"] == ("UNKNOWN" if case == "caller-loss" else "SUCCEEDED"), report
    return path.read_bytes()

try:
    start()
    catalog = read("list")
    assert {entry["operation_id"] for entry in catalog["entries"]} == set(settings["cases"])
    assert read("history")["entries"] == []
    # These probes run under the exact caller identity, not merely a polite tool allowlist.
    probe = r"""
import os
for path in ('/etc/kapsel/operator.json', '/etc/kapsel/kubeconfig.yaml',
             '/etc/kapsel/receipt.seed', '/var/lib/kapsel/journal.sqlite3',
             '/operator/approval.seed', '/inputs/kubeconfig.json'):
    try:
        open(path, 'rb')
    except PermissionError:
        pass
    else:
        raise AssertionError('private input readable: ' + path)
for path in ('/usr/bin/kapsel-service-client', '/usr/libexec/kapsel/kapseld'):
    assert not os.access(path, os.W_OK)
assert not os.path.exists('/var/run/docker.sock')
try:
    os.setuid(0)
except PermissionError:
    pass
else:
    raise AssertionError('caller became root')
"""
    probe_result = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True,
                                  timeout=10, cwd="/tmp", **identity)
    assert probe_result.returncode == 0, probe_result.stderr[:2048]
    if settings["agent"]:
        pathlib.Path("/operator/caller-ready").touch()
        selection = pathlib.Path("/operator/selection.json")
        deadline = time.monotonic() + 150
        while not selection.exists():
            assert time.monotonic() < deadline, "agent completion deadline"
            time.sleep(0.1)
        assert json.loads(selection.read_text()) == {"operation_id": "healthy"}
    for case in settings["cases"]:
        started = time.monotonic()
        if case == "caller-loss":
            # The public framed socket request is sent by the caller process, which exits without
            # reading an acknowledgement. Reconnect never invents another operation identity.
            body = json.dumps({"version": 1, "request": "submit_set_deployment_image",
                               "operation_id": case}).encode()
            lost = "import socket,os; s=socket.socket(socket.AF_UNIX); s.connect('/run/kapsel/kapseld.sock'); s.sendall(bytes.fromhex('" + (len(body).to_bytes(4, 'big') + body).hex() + "')); os._exit(0)"
            command([sys.executable, "-I", "-c", lost], cwd="/tmp", **identity)
        elif not (settings["agent"] and case == "healthy"):
            assert read("submit", case)["status"] == "ADMITTED"
        if case == "service-loss":
            deadline = time.monotonic() + 20
            while receiver("agent-" + case)["spec"]["template"]["spec"]["containers"][0]["image"] != settings["desired"]:
                assert time.monotonic() < deadline
                time.sleep(0.02)
            stop(crash=True)
            start()
            state = read("status", case)
            assert state["status"] == "IN_PROGRESS", state
            assert state["execution"]["disposition"] == "resume_required", state
            # Startup has not selected B or resumed A. The caller explicitly reselects original A.
            assert read("status", "independent")["status"] == "NOT_FOUND"
            assert read("submit", case)["status"] == "ADMITTED"
        terminal = wait(case, lambda r: r["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED"))
        expected = "NOT_ATTEMPTED" if case == "stale" else "UNKNOWN" if case == "caller-loss" else "SUCCEEDED"
        assert terminal["status"] == expected, (case, terminal)
        if case == "stale":
            assert terminal["target_rejection"] == "STALE_APPROVAL", terminal
            digest = None
        else:
            frozen = receipt(case, "first")
            digest = hashlib.sha256(frozen).hexdigest()
            assert read("submit", case) == {"version": 1, "status": "ADMITTED", "phase": "finalized"}
            assert receipt(case, "duplicate") == frozen
        if case == "caller-loss":
            # A conflicting follow-on approval was deliberately never provisioned. Hostile ID
            # selection cannot make it available, including after an enforced cold replacement.
            assert read("submit", "conflicting-b")["status"] == "ERROR"
            stop()
            changed = json.loads(document)
            changed["approvals"] = [a for a in changed["approvals"] if a["label"] == "Approved independent"]
            publish(json.dumps(changed).encode())
            start()
            assert read("submit", "conflicting-b")["status"] == "ERROR"
            assert read("status", "conflicting-b")["status"] == "NOT_FOUND"
            assert read("status", case) == terminal
            assert receipt(case, "restart") == frozen
            assert receipt("healthy", "old-result")
        reports.append({"case": case, "status": expected, "seconds": round(time.monotonic() - started, 3),
                        "receipt_sha256": digest})
        print(json.dumps(reports[-1]), flush=True)
    stop()
    pathlib.Path("/evidence/results.json").write_text(json.dumps(reports, indent=2) + "\n")
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.communicate(timeout=10)
'''


def run(arguments: list[str], *, data: bytes | None = None, timeout: int = 60) -> bytes:
    result = subprocess.run(
        arguments, input=data, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode:
        # Never render argv or input: some fixture commands provision short-lived credentials.
        raise RuntimeError(
            f"{arguments[0]} exited {result.returncode}: {result.stderr[-2048:].decode(errors='replace')}"
        )
    return result.stdout


def run_agent_process(arguments: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess:
    """Bound both model output streams while draining, before retaining their bytes."""
    maximum = 256 * 1024
    streams = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    with (
        subprocess.Popen(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process,
        selectors.DefaultSelector() as selector,
    ):
        try:
            for index, stream in enumerate((process.stdout, process.stderr)):
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments[0], timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output = streams[key.data]
                    if len(output) + len(chunk) > maximum:
                        raise RuntimeError("confined Codex output exceeded its byte bound")
                    output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments[0], timeout)
            process.wait(timeout=remaining)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return subprocess.CompletedProcess(
        arguments, process.returncode, bytes(streams[0]), bytes(streams[1])
    )


def run_agent(
    name: str, workspace: pathlib.Path, binary: pathlib.Path, auth: pathlib.Path
) -> dict[str, object]:
    """Run Codex inside the confined caller, never as a privileged host tool driver."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready = subprocess.run(
            ["docker", "exec", name, "test", "-f", "/operator/caller-ready"],
            capture_output=True,
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
    run(["docker", "exec", name, "chown", "-R", "61001:61000", "/home/caller"])
    run(["docker", "exec", name, "chmod", "0700", "/home/caller", "/home/caller/.codex"])
    run(["docker", "exec", name, "chmod", "0600", "/home/caller/.codex/auth.json"])
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
        "This is an explicitly approved disposable Kapsel test. Use /usr/bin/kapsel-service-client "
        "list to inspect the operator-approved catalog. Select only the existing healthy ID for "
        "demo/agent-healthy, container api. Read its status, submit healthy if not yet admitted, "
        "then read status until a terminal result. Export its receipt to /home/caller/healthy.receipt. "
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
                    "--ignore-user-config",
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
        if len(completed) != 1 or any(
            event.get("item", {}).get("type") == "error" for event in events
        ):
            raise RuntimeError("Codex did not complete a turn without runtime errors")
        # This is the installed native client with its fixed socket, not a Python script.
        client = [*caller, "/usr/bin/kapsel-service-client"]
        status = json.loads(run([*client, "status", "healthy"]))
        if status.get("status") != "SUCCEEDED":
            raise RuntimeError(
                f"agent did not complete the original approved action: {status.get('status')}"
            )
        for case in CASES:
            if (
                case != "healthy"
                and json.loads(run([*client, "status", case])).get("status") != "NOT_FOUND"
            ):
                raise RuntimeError("agent selected an unintended fixture action")
        snapshot = run(
            [
                *caller,
                "/usr/local/bin/python3",
                "-I",
                "-c",
                RECEIPT_SNAPSHOT,
                "/home/caller/healthy.receipt",
            ]
        )
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
        if snapshot != canonical:
            raise RuntimeError("model receipt differs from the original product evidence")
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
            "Confined Codex completed the approved healthy action through the product client",
            flush=True,
        )
        return {
            "cli_version": version,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "code_mode_host_sha256": hashlib.sha256(code_host.read_bytes()).hexdigest(),
            "operation_id": "healthy",
            "status": status["status"],
            "usage": completed[0].get("usage"),
            "uid": 61001,
            "raw_session_retained": False,
            "receipt_sha256": exported["receipt_sha256"],
        }
    finally:
        run(["docker", "exec", name, "rm", "-f", "/home/caller/.codex/auth.json"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
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
    os.umask(0o077)
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="kapsel-live-artifact-"))
    print(f"Private evidence workspace: {workspace}", flush=True)
    spec = importlib.util.spec_from_file_location(
        "artifact", ROOT / "scripts/smoke-release-artifact.py"
    )
    assert spec is not None and spec.loader is not None
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    archive = args.archive.resolve()
    extracted = artifact.extract_release(
        archive, pathlib.Path(str(archive) + ".sha256"), args.revision, workspace / "extracted"
    )
    name = "kapsel-journey-" + uuid.uuid4().hex[:10]
    kubeconfig = workspace / "admin.yaml"
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
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
                "-i",
                RUNNER,
                "python3",
                "-",
            ]
        )
        container_owned = True
        # Host bind permissions are not a portable caller boundary (notably under Docker Desktop).
        # Copy the private directory into the container with Docker's default root ownership.
        run(["docker", "cp", str(inputs), name + ":/inputs"])
        started = time.monotonic()
        agent_evidence = None
        with (evidence / "exercise.log").open("wb") as log:
            process = subprocess.Popen(
                ["docker", "start", "--attach", "--interactive", name],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                assert process.stdin is not None
                process.stdin.write(EXERCISE.encode())
                process.stdin.close()
                if args.agent:
                    agent_evidence = run_agent(
                        name, workspace, args.codex_binary.resolve(), args.codex_auth.resolve()
                    )
                exercise_exit = process.wait(timeout=450)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        run(["docker", "cp", name + ":/evidence/.", str(evidence)])
        # Read the API server's bounded audit file, not product or shim counters. Rotation invalidates
        # completeness rather than silently dropping early requests.
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
        seen = set()
        for line in audit.splitlines():
            event = json.loads(line)
            if event.get("verb") != "patch" or event.get("userAgent") == "kapsel-journey-fixture":
                continue
            if event.get("user", {}).get("username") != "system:serviceaccount:demo:journey":
                continue
            assert event["auditID"] not in seen
            seen.add(event["auditID"])
            case = event["objectRef"]["name"].removeprefix("agent-")
            counts[case] += 1
        summary = {
            "source_revision": args.revision,
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
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
