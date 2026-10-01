#!/usr/bin/env python3
"""Qualify extracted production binaries against a disposable local Git receiver.

Uses one isolated Linux container per case, with distinct service and caller identities.
No system installation, source harness, product pause hook, or live repository is used.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = "python@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
CASES = ("healthy", "pre-receive", "post-receive", "service-loss")

# This driver is the fixture operator, not the caller. Only extracted product bytes and
# an explicitly selected Git executable enter the container. Faults belong to the receiver.
EXERCISE = r"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time

os.umask(0o077)
case = os.environ["GIT_CASE"]
service_uid, caller_uid = 61000, 61001
reference = "refs/heads/approved"
state = Path("/var/lib/kapsel")
config = Path("/etc/kapsel")
control = state / "fixture-control"
for directory, mode in ((state, 0o700), (config, 0o700), (Path("/run/kapsel"), 0o750)):
    directory.mkdir(mode=mode)
    directory.chmod(mode)
    os.chown(directory, service_uid, service_uid)
for directory in (control, state / "git-bin", Path("/caller"), Path("/evidence")):
    directory.mkdir(mode=0o700)
os.chown("/caller", caller_uid, service_uid)
for directory in (Path("/usr/libexec"), Path("/usr/libexec/kapsel")):
    directory.mkdir(mode=0o755, exist_ok=True)
    directory.chmod(0o755)
for source, destination in (
    ("bin/kapsel", "/usr/bin/kapsel"),
    ("bin/kapsel-service-client", "/usr/bin/kapsel-service-client"),
    ("bin/kapsel-service-mcp", "/usr/bin/kapsel-service-mcp"),
    ("libexec/kapsel/kapseld", "/usr/libexec/kapsel/kapseld"),
):
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile("/artifact/" + source, destination)
    os.chmod(destination, 0o755)
git_binary = state / "git-bin/git"
shutil.copyfile("/inputs/git", git_binary)
git_binary.chmod(0o700)
environment = {
    "PATH": "/usr/bin:/bin", "HOME": str(state), "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}

def command(arguments, *, uid=0, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=30,
        user=uid, group=service_uid if uid else 0, extra_groups=[], **kwargs)
    assert result.returncode == 0, (arguments[0], result.returncode, result.stderr[:2048])
    assert len(result.stdout) <= 262144, "fixture output exceeded bound"
    return result.stdout

def git(*arguments, **kwargs):
    return command([str(git_binary), *map(str, arguments)], env=environment, **kwargs).decode().strip()

def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)

def wait(predicate, *, timeout=20):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "fixture deadline exceeded"
        time.sleep(0.02)

assert git("--version") == "git version 2.55.0"
sender, receiver = state / "sender.git", state / "receiver.git"
for repository in (sender, receiver):
    git("init", "--bare", "--quiet", "--template=", repository)
for key, value in (("receive.denyDeletes", "true"), ("receive.denyNonFastForwards", "true"),
                   ("kapsel.repositoryId", "fixture-repository")):
    git("--git-dir", receiver, "config", key, value)
tree = git("--git-dir", sender, "hash-object", "-w", "-t", "tree", "--stdin", input=b"")
old = git("--git-dir", sender, "commit-tree", tree, input=b"A\n")
new = git("--git-dir", sender, "commit-tree", tree, "-p", old, input=b"B\n")
git("--git-dir", sender, "push", receiver, f"{old}:{reference}")
for hook in ("pre-receive", "post-receive"):
    path = receiver / "hooks" / hook
    script = f"#!/bin/sh\nwhile read -r line; do printf '%s\\n' \"$line\" >> '{control / hook}'; done\n"
    if hook == case:
        script += 'kill -KILL "$PPID"\n'
    elif case == "service-loss" and hook == "post-receive":
        script += f"touch '{control / 'ready'}'\n"
        script += f"n=0; while test ! -f '{control / 'release'}'; do n=$((n+1)); test $n -lt 200 || exit 1; sleep 0.1; done\n"
        script += f"touch '{control / 'finished'}'\n"
    path.write_text(script)
    path.chmod(0o700)
material = {"executable": str(git_binary), "sender": str(sender), "receiver": str(receiver),
            "repository_id": "fixture-repository"}
write(config / "git-receiver.json", material)
write(Path("/inputs/authorization.json"), {
    "operation_id": "git-example", "authorization_id": "git-approval",
    "repository_id": "fixture-repository", "reference": reference,
    "old_commit": old, "new_commit": new,
})

def keys(name):
    seed = os.urandom(32)
    encoded = command(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=bytes.fromhex("302e020100300506032b657004220420") + seed)
    prefix = bytes.fromhex("302a300506032b6570032100")
    assert len(encoded) == len(prefix) + 32 and encoded.startswith(prefix)
    write(Path("/inputs") / (name + ".seed"), seed)
    write(Path("/inputs") / (name + ".pub"), encoded[len(prefix):])
    return encoded[len(prefix):]

keys("approval")
receipt_public = keys("receipt")
command(["/usr/bin/kapsel", "provision-git-grant", "--authorization", "/inputs/authorization.json",
    "--git-receiver", str(config / "git-receiver.json"), "--signing-seed", "/inputs/approval.seed",
    "--signing-key-id", "approval-key", "--output", "/inputs/approval.grant"])
command(["/usr/bin/kapsel", "prepare-service-config", "--authorization-key", "approval-key",
    "/inputs/approval.pub", "--approval", "Approved Git transition", "/inputs/approval.grant",
    "--receipt-signing-key-id", "receipt-key", "--output", str(config / "operator.json")])
write(config / "receipt.seed", Path("/inputs/receipt.seed").read_bytes())
for root in (state, config):
    for path in [root, *root.rglob("*")]:
        os.chown(path, service_uid, service_uid)

# The caller must not have direct access to receiver, journal, authority or private Git.
for path in (config / "operator.json", config / "receipt.seed", git_binary, receiver / "config"):
    probe = subprocess.run(["python3", "-I", "-c", "import sys; open(sys.argv[1], 'rb')", str(path)],
        user=caller_uid, group=service_uid, extra_groups=[], capture_output=True, timeout=5)
    assert probe.returncode != 0, "caller acquired private fixture material"

def call(*arguments):
    return json.loads(command(["/usr/bin/kapsel-service-client", *arguments], uid=caller_uid))

process = None
log = Path("/evidence/service.log").open("ab")

def start():
    global process
    process = subprocess.Popen(["/usr/libexec/kapsel/kapseld", "--operator-config",
        "/etc/kapsel/operator.json", "--socket", "/run/kapsel/kapseld.sock"],
        user=service_uid, group=service_uid, extra_groups=[],
        env={"PATH": "/usr/bin:/bin", "HOME": str(state)}, stdin=subprocess.DEVNULL,
        stdout=log, stderr=log)
    def ready():
        assert process.poll() is None, "service exited before socket publication"
        with socket.socket(socket.AF_UNIX) as client:
            try:
                client.connect("/run/kapsel/kapseld.sock")
                return True
            except OSError:
                return False
    wait(ready)

def stop():
    if process is not None and process.poll() is None:
        process.terminate()
        process.wait(timeout=15)

def active_git():
    for path in Path("/proc").glob("[0-9]*/exe"):
        try:
            if path.readlink() == git_binary:
                return True
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return False

try:
    start()
    expected_tuple = {"repository_id": "fixture-repository", "reference": reference,
                      "old_commit": old, "new_commit": new}
    listed = call("list")
    assert len(listed["entries"]) == 1, listed
    entry = listed["entries"][0]
    assert entry["operation_id"] == "git-example" and entry["effect"] == "git.transition_ref"
    assert {key: entry[key] for key in expected_tuple} == expected_tuple
    assert call("submit", "git-example")["status"] == "ADMITTED"
    if case == "service-loss":
        wait(lambda: (control / "ready").exists())
        assert git("--git-dir", receiver, "rev-parse", "--verify", reference) == new
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=10)
        write(control / "release", b"release receiver hook\n")
        wait(lambda: (control / "finished").exists())
        wait(lambda: not active_git())
        start()
        assert call("status", "git-example")["status"] == "IN_PROGRESS"
        assert call("submit", "git-example")["status"] == "ADMITTED"
    terminal = {}
    def complete():
        global terminal
        terminal = call("status", "git-example")
        return terminal["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED")
    wait(complete)
    expected = "SUCCEEDED" if case == "healthy" else "UNKNOWN"
    expected_ref = old if case == "pre-receive" else new
    acknowledgement = "updated" if case == "healthy" else "unknown"
    observed = {"kind": "commit", "commit": expected_ref}
    expected_evidence = {**expected_tuple, "attempted": True,
                         "acknowledgement": acknowledgement, "observed_ref": observed}
    assert terminal["status"] == expected and terminal["git"] == expected_evidence, terminal
    assert git("--git-dir", receiver, "rev-parse", "--verify", reference) == expected_ref
    first = call("receipt", "git-example", "/caller/first.bin")
    first_bytes = Path("/caller/first.bin").read_bytes()
    assert hashlib.sha256(first_bytes).hexdigest() == first["receipt_sha256"]
    stop()
    hook_inputs = {hook: (control / hook).read_text().splitlines() if (control / hook).exists() else []
                   for hook in ("pre-receive", "post-receive")}
    assert hook_inputs["pre-receive"] == [f"{old} {new} {reference}"], hook_inputs
    assert hook_inputs["post-receive"] == ([] if case == "pre-receive" else [f"{old} {new} {reference}"])
    for path in (config / "receipt.seed", config / "git-receiver.json"):
        path.unlink()
    operator = json.loads((config / "operator.json").read_bytes())
    operator["approvals"] = []
    write(config / "operator.json", operator)
    shutil.rmtree(receiver)
    start()
    reopened = call("status", "git-example")
    assert reopened["status"] == expected and reopened["git"] == expected_evidence, reopened
    assert call("submit", "git-example")["status"] == "NO_SELECTION"
    second = call("receipt", "git-example", "/caller/second.bin")
    assert second["receipt_sha256"] == first["receipt_sha256"]
    assert Path("/caller/second.bin").read_bytes() == first_bytes
    stop()
    fields = [b"receipt-key", receipt_public, b"kapsel.git-ref-transition-receipt.v1",
              (0).to_bytes(8, "big"), (100).to_bytes(8, "big")]
    trust = b"KAPSEL-KAP0038-K8S-TRUST-V2\0" + b"".join(
        bytes([number]) + len(value).to_bytes(4, "big") + value
        for number, value in enumerate(fields, 1))
    write(Path("/inputs/receipt.trust"), trust)
    report = json.loads(command(["/usr/bin/kapsel", "inspect", "--receipt", "/caller/first.bin",
        "--trust", "/inputs/receipt.trust", "--evaluation-time-unix-s", "50"]))
    assert report["status"] == "INSPECTED" and report["result"] == expected, report
    assert report["effect"] == "git.transition_ref" and report["operation_id"] == "git-example"
    assert report["authorization_id"] == "git-approval"
    assert {key: report[key] for key in expected_tuple} == expected_tuple
    assert report["acknowledgement"] == acknowledgement and report["observed_ref"] == observed
    assert report["attribution"] == ("acknowledged_update" if expected == "SUCCEEDED" else "not_established")
    summary = {"case": case, "result": expected, "receiver_ref": expected_ref,
               "acknowledgement": acknowledgement, "hook_inputs": hook_inputs,
               "receipt_sha256": first["receipt_sha256"], "inspection": report["status"],
               "identical_retained_receipt": True, "caller_private_access_denied": True}
    Path("/evidence/summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
finally:
    stop()
    log.close()
"""


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, timeout=60, **kwargs).stdout


def qualify(archive: Path, revision: str, git: Path) -> Path:
    os.umask(0o077)
    workspace = Path(tempfile.mkdtemp(prefix="kapsel-git-artifact-"))
    print(f"Private evidence workspace: {workspace}", flush=True)
    spec = importlib.util.spec_from_file_location(
        "artifact", ROOT / "tools/release/verify_artifact.py"
    )
    assert spec is not None and spec.loader is not None
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    archive = archive.resolve(strict=True)
    git = git.resolve(strict=True)
    extracted = artifact.extract_release(
        archive, Path(str(archive) + ".sha256"), revision, workspace / "extracted"
    )
    metadata = json.loads((extracted / "RELEASE-METADATA.json").read_bytes())
    if metadata["source_dirty"]:
        raise RuntimeError("packaged Git qualification requires a clean-source artifact")
    if not git.is_file() or not os.access(git, os.X_OK):
        raise RuntimeError("--git must select an executable regular file")
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
    shutil.copyfile(git, inputs / "git")
    (inputs / "git").chmod(0o700)
    summaries = []
    for case in CASES:
        name = "kapsel-git-" + uuid.uuid4().hex[:12]
        evidence = workspace / case
        evidence.mkdir(mode=0o700)
        owned = False
        try:
            run(
                [
                    "docker",
                    "create",
                    "--name",
                    name,
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "none",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=128",
                    "--memory=1g",
                    "--volume",
                    f"{extracted}:/artifact:ro",
                    "--env",
                    f"GIT_CASE={case}",
                    "-i",
                    RUNNER,
                    "python3",
                    "-I",
                    "-",
                ]
            )
            owned = True
            run(["docker", "cp", str(inputs), name + ":/inputs"])
            with (evidence / "exercise.log").open("wb") as log:
                result = subprocess.run(
                    ["docker", "start", "--attach", "--interactive", name],
                    input=EXERCISE.encode(),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=180,
                    check=False,
                )
            run(["docker", "cp", name + ":/evidence/.", str(evidence)])
            if result.returncode != 0:
                raise RuntimeError(f"{case} failed; inspect the private exercise.log")
            summary = json.loads((evidence / "summary.json").read_bytes())
            assert summary["case"] == case
            summaries.append(summary)
        finally:
            if owned:
                run(["docker", "rm", "-f", name])
    summary = {
        "source_revision": revision,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "git_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
        "runner": RUNNER,
        "cases": summaries,
        "limits": "container process/socket and hook-input proof; not packet counts, native systemd, power loss or publication",
    }
    (workspace / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)
    return workspace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--git", required=True, type=Path, help="accepted Linux Git 2.55.0 executable"
    )
    args = parser.parse_args()
    qualify(args.archive, args.revision, args.git)


if __name__ == "__main__":
    main()
