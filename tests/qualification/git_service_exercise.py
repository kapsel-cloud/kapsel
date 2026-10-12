"""One concrete Git service procedure for source and installed launch profiles."""

import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Launch:
    root: Path
    git: Path
    kapsel: Path
    daemon: Path
    bridge: Path
    caller_source: Path
    hook_source: Path
    artifact: Path | None = None
    retained: Path | None = None

    @property
    def installed(self) -> bool:
        return self.artifact is not None

    def service_environment(self, case: str) -> dict[str, str]:
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.root / "var/lib/kapsel"),
        }
        if not self.installed:
            environment["KAPSELD_TEST_INSTALLATION_ROOT"] = str(self.root)
            if case in ("after_apply", "before_receipt_commit", "after_receipt_commit"):
                environment.update(
                    KAPSEL_DEMO_CONTROL_DIRECTORY=str(self.root / "control"), KAPSEL_DEMO_PAUSE=case
                )
        return environment


def private_directories(root: Path) -> None:
    for name, mode in (
        ("var/lib/kapsel", 0o700),
        ("etc/kapsel", 0o700),
        ("run/kapsel", 0o750),
        ("control", 0o700),
        ("caller", 0o700),
        ("evidence", 0o700),
        ("inputs", 0o700),
    ):
        path = root / name
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)


def retire_service(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def exercise(launch: Launch, case: str) -> None:
    def command(
        arguments: list[str],
        *,
        uid: int | None = None,
        input: bytes | None = None,
        env: Mapping[str, str] | None = None,
    ) -> bytes:
        result = subprocess.run(
            arguments,
            capture_output=True,
            timeout=30,
            user=uid,
            group=service_uid if uid is not None else None,
            extra_groups=[] if uid is not None else None,
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
        write((launch.root / "inputs") / (name + ".seed"), seed)
        write((launch.root / "inputs") / (name + ".pub"), encoded[len(prefix) :])
        return encoded[len(prefix) :]

    def call(action: str, *arguments: str, reference_file: str = "reference"):
        result = subprocess.run(
            [
                "python3",
                "-I",
                str(caller),
                "--service",
                "git-fixture",
                "--reference",
                str(launch.root / "caller" / reference_file),
                action,
                *arguments,
            ],
            user=caller_uid,
            group=service_uid,
            extra_groups=[] if caller_uid is not None else None,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                **({"KAPSELD_TEST_CLIENT_SOCKET": str(address)} if not launch.installed else {}),
            },
            capture_output=True,
            timeout=15,
        )
        assert result.returncode in (0, 4), result.stderr[:2048]
        assert len(result.stdout) <= 262144
        return json.loads(result.stdout)["service"]

    def start(selected_case: str = "healthy") -> None:
        nonlocal process
        started = subprocess.Popen(
            [
                str(launch.daemon),
                "--operator-config",
                "/etc/kapsel/operator.json",
                "--socket",
                "/run/kapsel/kapseld.sock",
            ],
            user=service_uid,
            group=service_uid,
            extra_groups=[] if service_uid is not None else None,
            env=launch.service_environment(selected_case),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
        )
        process = started

        def ready() -> bool:
            assert started.poll() is None, "service exited before socket publication"
            with socket.socket(socket.AF_UNIX) as client:
                try:
                    client.connect(str(address))
                    return True
                except OSError:
                    return False

        wait(ready)

    def stop() -> None:
        retire_service(process)

    def active_git() -> bool:
        for path in Path("/proc").glob("[0-9]*/exe"):
            try:
                if path.readlink() == git_binary:
                    return True
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        return False

    os.umask(0o077)
    service_uid, caller_uid = (61000, 61001) if launch.installed else (None, None)
    reference = "refs/heads/approved"
    state = launch.root / "var/lib/kapsel"
    config = launch.root / "etc/kapsel"
    control = state / "fixture-control"
    private_directories(launch.root)
    for directory in (control, state / "git-bin"):
        directory.mkdir(mode=0o700)
    if launch.installed:
        assert caller_uid is not None and service_uid is not None
        os.chown(launch.root / "caller", caller_uid, service_uid)
        for directory in (Path("/usr/libexec"), Path("/usr/libexec/kapsel")):
            directory.mkdir(mode=0o755, exist_ok=True)
            directory.chmod(0o755)
        assert launch.artifact is not None
        install_binaries(launch.retained or launch.artifact)
    caller = launch.root / "caller/fresh_session_caller.py"
    caller.write_bytes(
        launch.caller_source.read_bytes().replace(
            b'BRIDGE = "/usr/bin/kapsel-service-mcp"', f"BRIDGE = {str(launch.bridge)!r}".encode()
        )
    )
    caller.chmod(0o600)
    if launch.installed:
        assert caller_uid is not None and service_uid is not None
        os.chown(caller, caller_uid, service_uid)
    address = launch.root / "run/kapsel/kapseld.sock"

    git_binary = state / "git-bin/git"
    shutil.copyfile(launch.git, git_binary)
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
    hook_source = launch.hook_source.read_bytes()
    for hook in ("pre-receive", "post-receive"):
        hook_path = receiver / "hooks" / hook
        body = hook_path.with_suffix(".py")
        body.write_bytes(hook_source)
        body.chmod(0o600)
        interpreter = "/usr/local/bin/python3" if launch.installed else sys.executable
        hook_path.write_text(f"#!/bin/sh\nexec '{interpreter}' -I '{body}'\n")
        hook_path.chmod(0o700)

    material = {
        "executable": str(git_binary),
        "sender": str(sender),
        "receiver": str(receiver),
        "repository_id": "fixture-repository",
    }
    write(config / "git-receiver.json", material)
    write(
        launch.root / "inputs/authorization.json",
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
            str(launch.kapsel),
            "provision-git-grant",
            "--authorization",
            str(launch.root / "inputs/authorization.json"),
            "--git-receiver",
            str(config / "git-receiver.json"),
            "--signing-seed",
            str(launch.root / "inputs/approval.seed"),
            "--signing-key-id",
            "approval-key",
            "--output",
            str(launch.root / "inputs/approval.grant"),
        ]
    )
    command(
        [
            str(launch.kapsel),
            "prepare-service-config",
            "--authorization-key",
            "approval-key",
            str(launch.root / "inputs/approval.pub"),
            "--approval",
            "Approved Git transition",
            str(launch.root / "inputs/approval.grant"),
            "--receipt-signing-key-id",
            "receipt-key",
            "--output",
            str(config / "operator.json"),
        ]
    )
    if case != "healthy":
        write(config / "receipt.seed", (launch.root / "inputs/receipt.seed").read_bytes())
    if launch.installed:
        assert service_uid is not None
        for root in (state, config):
            for path in [root, *root.rglob("*")]:
                os.chown(path, service_uid, service_uid)
        os.chown(launch.root / "run/kapsel", service_uid, service_uid)

        # The caller must not have direct access to receiver, journal, authority or private Git.
        for path in (
            config / "operator.json",
            launch.root / "inputs/receipt.seed",
            git_binary,
            receiver / "config",
        ):
            probe = subprocess.run(
                [
                    "python3",
                    "-I",
                    "-c",
                    "import sys\ntry: open(sys.argv[1], 'rb')\nexcept PermissionError: sys.exit(73)\n",
                    str(path),
                ],
                user=caller_uid,
                group=service_uid,
                extra_groups=[],
                capture_output=True,
                timeout=5,
            )
            assert probe.returncode == 73, "caller private-material probe did not establish denial"

    process: subprocess.Popen[bytes] | None = None
    log = (launch.root / "evidence/service.log").open("ab")

    try:
        start(case)
        expected_tuple = {
            "repository_id": "fixture-repository",
            "reference": reference,
            "old_commit": old,
            "new_commit": new,
        }
        listed = call("approved")
        assert len(listed["entries"]) == 1, listed
        entry = listed["entries"][0]
        assert entry["operation_id"] == "git-example" and entry["effect"] == "git.transition_ref"
        listed_transition = {key: entry[key] for key in expected_tuple}
        assert listed_transition == expected_tuple

        assert call("start", "git-example")["status"] == "ADMITTED"
        original_ref = None
        if case == "healthy":

            def signing_blocked() -> bool:
                stored = call("read")
                return stored["status"] == "IN_PROGRESS" and stored["git"]["observed_ref"] == {
                    "kind": "commit",
                    "commit": new,
                }

            wait(signing_blocked)
            assert call("read")["git"]["acknowledgement"] == "updated"
            assert call("receipt")["status"] == "NOT_READY"
            stop()
            original_ref = git("--git-dir", receiver, "rev-parse", "--verify", reference)
            shutil.rmtree(receiver)
            (config / "git-receiver.json").unlink()
            operator = json.loads((config / "operator.json").read_bytes())
            operator["approvals"] = []
            write(config / "operator.json", operator)
            write(config / "receipt.seed", (launch.root / "inputs/receipt.seed").read_bytes())
            if launch.installed:
                os.chown(config / "receipt.seed", 61000, 61000)
            start()
            assert call("resume")["status"] == "ADMITTED"
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
            if launch.artifact is not None:
                install_binaries(launch.artifact)
            start()
            assert retained_row(state / "journal.sqlite3") == attempted
            assert call("read")["status"] == "IN_PROGRESS"
            assert call("resume")["status"] == "ADMITTED"

        if case in ("after_apply", "before_receipt_commit", "after_receipt_commit"):
            marker = launch.root / "control" / (case.replace("_", "-") + ".ready")
            wait(marker.exists)
            assert process is not None and process.poll() is None
            process.kill()
            process.wait(timeout=10)
            before = retained_row(state / "journal.sqlite3")
            start()
            assert retained_row(state / "journal.sqlite3") == before
            assert call("read")["status"] == (
                "SUCCEEDED" if case == "after_receipt_commit" else "IN_PROGRESS"
            )
            if case != "after_receipt_commit":
                assert call("resume")["status"] == "ADMITTED"

        terminal = {}

        def complete():
            nonlocal terminal
            terminal = call("read")
            return terminal["status"] in ("SUCCEEDED", "FAILED", "UNKNOWN", "NOT_ATTEMPTED")

        wait(complete)
        expected = (
            "UNKNOWN"
            if case in ("after_apply", "pre-receive", "post-receive", "service-loss")
            else "SUCCEEDED"
        )
        expected_ref = old if case == "pre-receive" else new
        acknowledgement = "updated" if expected == "SUCCEEDED" else "unknown"
        observed = {"kind": "commit", "commit": expected_ref}
        expected_evidence = {
            **expected_tuple,
            "attempted": True,
            "acknowledgement": acknowledgement,
            "observed_ref": observed,
        }
        assert terminal["status"] == expected and terminal["git"] == expected_evidence, terminal
        assert (
            original_ref or git("--git-dir", receiver, "rev-parse", "--verify", reference)
        ) == expected_ref

        first = call("receipt")
        assert first["status"] == "READY", first
        first_bytes = bytes.fromhex(first["receipt_hex"])
        write(launch.root / "caller/first.bin", first_bytes)
        if launch.installed:
            command(
                ["/usr/bin/kapsel-service-client", "receipt", "git-example", "/caller/export.bin"],
                uid=caller_uid,
            )
            assert Path("/caller/export.bin").read_bytes() == first_bytes
        assert hashlib.sha256(first_bytes).hexdigest() == first["receipt_sha256"]
        stop()
        original_row = retained_row(state / "journal.sqlite3")
        if launch.artifact is not None:
            install_binaries(launch.artifact)
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
            if path.exists():
                path.unlink()
        operator = json.loads((config / "operator.json").read_bytes())
        operator["approvals"] = []
        write(config / "operator.json", operator)
        if receiver.exists():
            shutil.rmtree(receiver)
        start()
        assert retained_row(state / "journal.sqlite3") == original_row
        reopened = call("read")
        assert reopened["status"] == expected and reopened["git"] == expected_evidence, reopened
        assert call("approved")["entries"] == []
        assert call("resume")["status"] == "NO_SELECTION"
        retained_admission = call("start", "git-example", reference_file="finalized-reference")
        assert retained_admission == {"version": 1, "status": "ADMITTED", "phase": "finalized"}

        second = call("receipt")
        assert second == first
        assert bytes.fromhex(second["receipt_hex"]) == first_bytes
        assert retained_row(state / "journal.sqlite3") == original_row
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
        write(launch.root / "inputs/receipt.trust", trust)
        report = json.loads(
            command(
                [
                    str(launch.kapsel),
                    "inspect",
                    "--receipt",
                    str(launch.root / "caller/first.bin"),
                    "--trust",
                    str(launch.root / "inputs/receipt.trust"),
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
            "finalized_submission": retained_admission,
            "retained_format6_replacement": launch.retained is not None,
            "caller_private_access_denied": launch.installed,
            "signing_repair_without_receiver": case == "healthy",
        }
        (launch.root / "evidence/summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary), flush=True)
    finally:
        try:
            stop()
        finally:
            log.close()


def main() -> None:
    artifact = Path("/artifact")
    retained = Path("/retained-artifact")
    exercise(
        Launch(
            Path("/"),
            Path("/inputs/git"),
            Path("/usr/bin/kapsel"),
            Path("/usr/libexec/kapsel/kapseld"),
            Path("/usr/bin/kapsel-service-mcp"),
            Path("/inputs/fresh_session_caller.py"),
            Path("/inputs/git_receiver_hook.py"),
            artifact,
            retained if retained.is_dir() else None,
        ),
        os.environ["GIT_CASE"],
    )


if __name__ == "__main__":
    main()
