"""Disposable operator fixture for the packaged Git transition journey."""

import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from pathlib import Path


def install_binaries(artifact: Path) -> None:
    """Replace fixture executables only. The caller must stop the service first."""
    for source, destination in (
        ("bin/kapsel", "/usr/bin/kapsel"),
        ("bin/kapsel-service-client", "/usr/bin/kapsel-service-client"),
        ("bin/kapsel-service-mcp", "/usr/bin/kapsel-service-mcp"),
        ("libexec/kapsel/kapseld", "/usr/libexec/kapsel/kapseld"),
    ):
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact / source, destination)
        os.chmod(destination, 0o755)


def retained_row(journal: Path) -> tuple[object, ...]:
    """Snapshot the bounded fixture row independently of the service projection."""
    assert journal.is_file() and not journal.is_symlink()
    assert journal.stat().st_size <= 64 * 1024 * 1024
    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        row = connection.execute(
            "SELECT * FROM git_ref_operations WHERE operation_id = 'git-example'"
        ).fetchone()
    assert row is not None
    return row


def main() -> None:
    def command(
        arguments: list[str],
        *,
        uid: int = 0,
        input: bytes | None = None,
        env: Mapping[str, str] | None = None,
    ) -> bytes:
        result = subprocess.run(
            arguments,
            capture_output=True,
            timeout=30,
            user=uid,
            group=service_uid if uid else 0,
            extra_groups=[],
            input=input,
            env=env,
        )
        assert result.returncode == 0, (arguments[0], result.returncode, result.stderr[:2048])
        assert len(result.stdout) <= 262144, "fixture output exceeded bound"
        return result.stdout

    def git(*arguments: str | Path, input: bytes | None = None) -> str:
        output = command(
            [str(git_binary), f"--exec-path={git_binary.parent}", *map(str, arguments)],
            env=environment,
            input=input,
        )
        return output.decode().strip()

    def write(path: Path, value: bytes | Mapping[str, object]) -> None:
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(0o600)

    def wait(predicate: Callable[[], bool], *, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            assert time.monotonic() < deadline, "fixture deadline exceeded"
            time.sleep(0.02)

    def write_key_pair(name: str) -> bytes:
        seed = os.urandom(32)
        encoded = command(
            ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            input=bytes.fromhex("302e020100300506032b657004220420") + seed,
        )
        prefix = bytes.fromhex("302a300506032b6570032100")
        assert len(encoded) == len(prefix) + 32 and encoded.startswith(prefix)
        write(Path("/inputs") / (name + ".seed"), seed)
        write(Path("/inputs") / (name + ".pub"), encoded[len(prefix) :])
        return encoded[len(prefix) :]

    def call(*arguments):
        return json.loads(command(["/usr/bin/kapsel-service-client", *arguments], uid=caller_uid))

    def start() -> None:
        nonlocal process
        started = subprocess.Popen(
            [
                "/usr/libexec/kapsel/kapseld",
                "--operator-config",
                "/etc/kapsel/operator.json",
                "--socket",
                "/run/kapsel/kapseld.sock",
            ],
            user=service_uid,
            group=service_uid,
            extra_groups=[],
            env={"PATH": "/usr/bin:/bin", "HOME": str(state)},
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
        )
        process = started

        def ready() -> bool:
            assert started.poll() is None, "service exited before socket publication"
            with socket.socket(socket.AF_UNIX) as client:
                try:
                    client.connect("/run/kapsel/kapseld.sock")
                    return True
                except OSError:
                    return False

        wait(ready)

    def stop() -> None:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=15)

    def active_git() -> bool:
        for path in Path("/proc").glob("[0-9]*/exe"):
            try:
                if path.readlink() == git_binary:
                    return True
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        return False

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

    for directory in (control, state / "git-bin", Path("/caller"), Path("/evidence")):
        directory.mkdir(mode=0o700)
    os.chown("/caller", caller_uid, service_uid)
    for directory in (Path("/usr/libexec"), Path("/usr/libexec/kapsel")):
        directory.mkdir(mode=0o755, exist_ok=True)
        directory.chmod(0o755)

    retained_artifact = Path("/retained-artifact")
    install_binaries(retained_artifact if retained_artifact.is_dir() else Path("/artifact"))

    git_binary = state / "git-bin/git"
    shutil.copyfile("/inputs/git", git_binary)
    git_binary.chmod(0o700)
    environment = {
        "PATH": str(git_binary.parent) + ":/usr/bin:/bin",
        "HOME": str(state),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }

    assert git("--version") == "git version 2.55.0"
    sender, receiver = state / "sender.git", state / "receiver.git"
    for repository in (sender, receiver):
        git("init", "--bare", "--quiet", "--template=", repository)
    for key, value in (
        ("receive.denyDeletes", "true"),
        ("receive.denyNonFastForwards", "true"),
        ("kapsel.repositoryId", "fixture-repository"),
    ):
        git("--git-dir", receiver, "config", key, value)
    tree = git("--git-dir", sender, "hash-object", "-w", "-t", "tree", "--stdin", input=b"")
    old = git("--git-dir", sender, "commit-tree", tree, input=b"A\n")
    new = git("--git-dir", sender, "commit-tree", tree, "-p", old, input=b"B\n")
    git(
        "--git-dir",
        sender,
        "push",
        f"--receive-pack={git_binary} receive-pack",
        receiver,
        f"{old}:{reference}",
    )

    (receiver / "hooks").mkdir(mode=0o700)
    write(control / "hook-settings.json", {"case": case})
    hook_source = Path("/inputs/git_receiver_hook.py").read_bytes()
    for hook in ("pre-receive", "post-receive"):
        hook_path = receiver / "hooks" / hook
        hook_path.write_bytes(hook_source)
        hook_path.chmod(0o700)

    material = {
        "executable": str(git_binary),
        "sender": str(sender),
        "receiver": str(receiver),
        "repository_id": "fixture-repository",
    }
    write(config / "git-receiver.json", material)
    write(
        Path("/inputs/authorization.json"),
        {
            "operation_id": "git-example",
            "authorization_id": "git-approval",
            "repository_id": "fixture-repository",
            "reference": reference,
            "old_commit": old,
            "new_commit": new,
        },
    )

    write_key_pair("approval")
    receipt_public = write_key_pair("receipt")
    command(
        [
            "/usr/bin/kapsel",
            "provision-git-grant",
            "--authorization",
            "/inputs/authorization.json",
            "--git-receiver",
            str(config / "git-receiver.json"),
            "--signing-seed",
            "/inputs/approval.seed",
            "--signing-key-id",
            "approval-key",
            "--output",
            "/inputs/approval.grant",
        ]
    )
    command(
        [
            "/usr/bin/kapsel",
            "prepare-service-config",
            "--authorization-key",
            "approval-key",
            "/inputs/approval.pub",
            "--approval",
            "Approved Git transition",
            "/inputs/approval.grant",
            "--receipt-signing-key-id",
            "receipt-key",
            "--output",
            str(config / "operator.json"),
        ]
    )
    write(config / "receipt.seed", Path("/inputs/receipt.seed").read_bytes())
    for root in (state, config):
        for path in [root, *root.rglob("*")]:
            os.chown(path, service_uid, service_uid)
    os.chown("/run/kapsel", service_uid, service_uid)

    # The caller must not have direct access to receiver, journal, authority or private Git.
    for path in (
        config / "operator.json",
        config / "receipt.seed",
        git_binary,
        receiver / "config",
    ):
        probe = subprocess.run(
            ["python3", "-I", "-c", "import sys; open(sys.argv[1], 'rb')", str(path)],
            user=caller_uid,
            group=service_uid,
            extra_groups=[],
            capture_output=True,
            timeout=5,
        )
        assert probe.returncode != 0, "caller acquired private fixture material"

    process: subprocess.Popen[bytes] | None = None
    log = Path("/evidence/service.log").open("ab")

    try:
        start()
        expected_tuple = {
            "repository_id": "fixture-repository",
            "reference": reference,
            "old_commit": old,
            "new_commit": new,
        }
        listed = call("list")
        assert len(listed["entries"]) == 1, listed
        entry = listed["entries"][0]
        assert entry["operation_id"] == "git-example" and entry["effect"] == "git.transition_ref"
        listed_transition = {key: entry[key] for key in expected_tuple}
        assert listed_transition == expected_tuple

        assert call("submit", "git-example")["status"] == "ADMITTED"
        if case == "service-loss":
            wait(lambda: (control / "ready").exists())
            assert git("--git-dir", receiver, "rev-parse", "--verify", reference) == new
            assert process is not None, "service-loss case requires a started service"
            process.send_signal(signal.SIGKILL)
            process.wait(timeout=10)
            write(control / "release", b"release receiver hook\n")
            wait(lambda: (control / "finished").exists())
            wait(lambda: not active_git())
            attempted = retained_row(state / "journal.sqlite3")
            install_binaries(Path("/artifact"))
            start()
            assert retained_row(state / "journal.sqlite3") == attempted
            assert call("status", "git-example")["status"] == "IN_PROGRESS"
            assert call("submit", "git-example")["status"] == "ADMITTED"

        terminal = {}

        def complete():
            nonlocal terminal
            terminal = call("status", "git-example")
            return terminal["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED")

        wait(complete)
        expected = "SUCCEEDED" if case == "healthy" else "UNKNOWN"
        expected_ref = old if case == "pre-receive" else new
        acknowledgement = "updated" if case == "healthy" else "unknown"
        observed = {"kind": "commit", "commit": expected_ref}
        expected_evidence = {
            **expected_tuple,
            "attempted": True,
            "acknowledgement": acknowledgement,
            "observed_ref": observed,
        }
        assert terminal["status"] == expected and terminal["git"] == expected_evidence, terminal
        assert git("--git-dir", receiver, "rev-parse", "--verify", reference) == expected_ref

        first = call("receipt", "git-example", "/caller/first.bin")
        first_bytes = Path("/caller/first.bin").read_bytes()
        assert hashlib.sha256(first_bytes).hexdigest() == first["receipt_sha256"]
        stop()
        original_row = retained_row(state / "journal.sqlite3")
        install_binaries(Path("/artifact"))
        assert retained_row(state / "journal.sqlite3") == original_row
        hook_inputs = {
            hook: (control / hook).read_text().splitlines() if (control / hook).exists() else []
            for hook in ("pre-receive", "post-receive")
        }
        assert hook_inputs["pre-receive"] == [f"{old} {new} {reference}"], hook_inputs
        assert hook_inputs["post-receive"] == (
            [] if case == "pre-receive" else [f"{old} {new} {reference}"]
        )

        for path in (config / "receipt.seed", config / "git-receiver.json"):
            path.unlink()
        operator = json.loads((config / "operator.json").read_bytes())
        operator["approvals"] = []
        write(config / "operator.json", operator)
        shutil.rmtree(receiver)
        start()
        assert retained_row(state / "journal.sqlite3") == original_row
        reopened = call("status", "git-example")
        assert reopened["status"] == expected and reopened["git"] == expected_evidence, reopened
        assert call("list")["entries"] == []
        retained_admission = call("submit", "git-example")
        assert retained_admission == {"version": 1, "status": "ADMITTED", "phase": "finalized"}, (
            retained_admission
        )

        second = call("receipt", "git-example", "/caller/second.bin")
        assert second["receipt_sha256"] == first["receipt_sha256"]
        assert Path("/caller/second.bin").read_bytes() == first_bytes
        stop()

        fields = [
            b"receipt-key",
            receipt_public,
            b"kapsel.git-ref-transition-receipt.v1",
            (0).to_bytes(8, "big"),
            (100).to_bytes(8, "big"),
        ]
        trust = b"KAPSEL-KAP0038-K8S-TRUST-V2\0" + b"".join(
            bytes([number]) + len(value).to_bytes(4, "big") + value
            for number, value in enumerate(fields, 1)
        )
        write(Path("/inputs/receipt.trust"), trust)
        report = json.loads(
            command(
                [
                    "/usr/bin/kapsel",
                    "inspect",
                    "--receipt",
                    "/caller/first.bin",
                    "--trust",
                    "/inputs/receipt.trust",
                    "--evaluation-time-unix-s",
                    "50",
                ]
            )
        )
        assert report["status"] == "INSPECTED" and report["result"] == expected, report
        assert report["effect"] == "git.transition_ref" and report["operation_id"] == "git-example"
        assert report["authorization_id"] == "git-approval"
        assert {key: report[key] for key in expected_tuple} == expected_tuple
        assert report["acknowledgement"] == acknowledgement and report["observed_ref"] == observed
        assert report["attribution"] == (
            "acknowledged_update" if expected == "SUCCEEDED" else "not_established"
        )

        summary = {
            "case": case,
            "result": expected,
            "receiver_ref": expected_ref,
            "acknowledgement": acknowledgement,
            "hook_inputs": hook_inputs,
            "receipt_sha256": first["receipt_sha256"],
            "inspection": report["status"],
            "identical_retained_receipt": True,
            "retained_format6_replacement": retained_artifact.is_dir(),
            "caller_private_access_denied": True,
        }
        Path("/evidence/summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary), flush=True)
    finally:
        stop()
        log.close()


if __name__ == "__main__":
    main()
