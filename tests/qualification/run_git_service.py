#!/usr/bin/env python3
"""Linux source fixture: real Git, fixed-root service, fresh caller processes and offline inspection."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FixtureInputs:
    git: Path
    kapsel: Path
    kapseld: Path
    bridge: Path


@dataclass(frozen=True)
class GitReceiver:
    root: Path
    executable: Path
    environment: dict[str, str]
    sender: Path
    receiver: Path
    old_commit: str
    new_commit: str

    def command(self, *arguments: str | Path, input: bytes | None = None) -> str:
        output = run(
            str(self.executable),
            *map(str, arguments),
            cwd=self.root,
            env=self.environment,
            input=input,
        )
        return output.decode().strip()


def prepare_git_receiver(root: Path, selected_git: Path, case: str) -> GitReceiver:
    executable = root / "git"
    shutil.copyfile(selected_git, executable)
    executable.chmod(0o700)
    environment = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(root),
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }

    def git(*arguments: str | Path, input: bytes | None = None) -> str:
        output = run(str(executable), *map(str, arguments), cwd=root, env=environment, input=input)
        return output.decode().strip()

    assert git("--version") == "git version 2.55.0"
    sender, receiver = root / "sender.git", root / "receiver.git"
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
    git("--git-dir", sender, "push", receiver, f"{old}:{REF}")

    (receiver / "hooks").mkdir(exist_ok=True)
    for hook in ("pre-receive", "post-receive"):
        path = receiver / "hooks" / hook
        path.write_text(
            f"#!/bin/sh\nwhile read -r line; do printf '%s\\n' \"$line\" >> '{root / hook}'; done\n"
            + ('kill -KILL "$PPID"\n' if hook == case else "")
        )
        path.chmod(0o700)

    return GitReceiver(
        root=root,
        executable=executable,
        environment=environment,
        sender=sender,
        receiver=receiver,
        old_commit=old,
        new_commit=new,
    )


REF = "refs/heads/approved"
PURPOSE = b"kapsel.git-ref-transition-receipt.v1"
REPO = Path(__file__).resolve().parents[2]


def run(
    *args: str,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input: bytes | None = None,
) -> bytes:
    return subprocess.run(
        args, cwd=cwd, env=env, input=input, capture_output=True, check=True, timeout=30
    ).stdout


def write(path: Path, value: bytes | Mapping[str, object]) -> None:
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)


def keys(root: Path, name: str) -> bytes:
    seed = os.urandom(32)
    encoded = run(
        "openssl",
        "pkey",
        "-inform",
        "DER",
        "-pubout",
        "-outform",
        "DER",
        input=bytes.fromhex("302e020100300506032b657004220420") + seed,
    )
    prefix = bytes.fromhex("302a300506032b6570032100")
    assert len(encoded) == len(prefix) + 32 and encoded.startswith(prefix)
    write(root / f"{name}.seed", seed)
    write(root / f"{name}.pub", encoded[len(prefix) :])
    return encoded[len(prefix) :]


def wait_for(predicate: Callable[[], bool], process: subprocess.Popen[bytes] | None) -> None:
    assert process is not None, "fixture barrier requires a started service"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        assert process.poll() is None, "service exited before fixture barrier"
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("service fixture deadline exceeded")


def listening(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX) as client:
        try:
            client.connect(str(path))
            return True
        except OSError:
            return False


def fixture(args: FixtureInputs, case: str) -> None:
    with tempfile.TemporaryDirectory(prefix="kapsel-git-service-") as temporary:
        root = Path(temporary).resolve()
        for directory in ("etc/kapsel", "var/lib/kapsel", "run/kapsel", "control"):
            (root / directory).mkdir(parents=True)
        (root / "run/kapsel").chmod(0o750)
        config = root / "etc/kapsel"
        prepared = prepare_git_receiver(root, args.git, case)
        executable, sender, receiver = prepared.executable, prepared.sender, prepared.receiver
        old, new = prepared.old_commit, prepared.new_commit
        git = prepared.command
        material = {
            "executable": str(executable),
            "sender": str(sender),
            "receiver": str(receiver),
            "repository_id": "fixture-repository",
        }
        write(config / "git-receiver.json", material)
        write(
            root / "authorization.json",
            {
                "operation_id": "git-example",
                "authorization_id": "git-approval",
                "repository_id": "fixture-repository",
                "reference": REF,
                "old_commit": old,
                "new_commit": new,
            },
        )
        keys(root, "approval")
        receipt_public = keys(root, "receipt")
        run(
            str(args.kapsel),
            "provision-git-grant",
            "--authorization",
            str(root / "authorization.json"),
            "--git-receiver",
            str(config / "git-receiver.json"),
            "--signing-seed",
            str(root / "approval.seed"),
            "--signing-key-id",
            "approval-key",
            "--output",
            str(root / "approval.grant"),
        )
        run(
            str(args.kapsel),
            "prepare-service-config",
            "--authorization-key",
            "approval-key",
            str(root / "approval.pub"),
            "--approval",
            "Approved Git transition",
            str(root / "approval.grant"),
            "--receipt-signing-key-id",
            "receipt-key",
            "--output",
            str(config / "operator.json"),
        )
        write(config / "receipt.seed", (root / "receipt.seed").read_bytes())
        caller = root / "caller.py"
        caller.write_text(
            (REPO / "examples/fresh_session_caller.py")
            .read_text()
            .replace('BRIDGE = "/usr/bin/kapsel-service-mcp"', f"BRIDGE = {str(args.bridge)!r}")
        )
        address = root / "run/kapsel/kapseld.sock"

        def call(command, *extra):
            result = subprocess.run(
                [
                    "python3",
                    str(caller),
                    "--service",
                    "git-fixture",
                    "--reference",
                    str(root / "reference"),
                    command,
                    *extra,
                ],
                env={**os.environ, "KAPSELD_TEST_CLIENT_SOCKET": str(address)},
                capture_output=True,
                timeout=15,
                check=False,
            )
            assert result.returncode in (0, 4), result.stderr
            return json.loads(result.stdout)["service"]

        process: subprocess.Popen[bytes] | None = None

        def start(seam: str | None = None) -> None:
            nonlocal process
            service_env = {**os.environ, "KAPSELD_TEST_INSTALLATION_ROOT": str(root)}
            for key in (
                "KAPSEL_DEMO_CONTROL_DIRECTORY",
                "KAPSEL_DEMO_PAUSE",
                "KAPSELD_TEST_CONNECTIONS",
            ):
                service_env.pop(key, None)
            if seam:
                service_env.update(
                    KAPSEL_DEMO_CONTROL_DIRECTORY=str(root / "control"), KAPSEL_DEMO_PAUSE=seam
                )
            process = subprocess.Popen(
                [
                    str(args.kapseld),
                    "--operator-config",
                    "/etc/kapsel/operator.json",
                    "--socket",
                    "/run/kapsel/kapseld.sock",
                ],
                env=service_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for(lambda: listening(address), process)

        def stop() -> None:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)

        try:
            seam = (
                case
                if case in ("after_apply", "before_receipt_commit", "after_receipt_commit")
                else None
            )
            start(seam)
            listed = call("approved")
            expected_tuple = {
                "repository_id": "fixture-repository",
                "reference": REF,
                "old_commit": old,
                "new_commit": new,
            }
            assert len(listed["entries"]) == 1, listed
            entry = listed["entries"][0]
            assert entry["effect"] == "git.transition_ref", listed
            assert entry["operation_id"] == "git-example", entry
            assert {key: entry[key] for key in expected_tuple} == expected_tuple, entry
            assert call("start", "git-example")["status"] == "ADMITTED"
            if seam:
                marker = root / "control" / (seam.replace("_", "-") + ".ready")
                wait_for(marker.exists, process)
                stop()
                start()
                before = call("read")
                expected_before = "SUCCEEDED" if seam == "after_receipt_commit" else "IN_PROGRESS"
                assert before["status"] == expected_before, before
                if seam != "after_receipt_commit":
                    assert call("resume")["status"] == "ADMITTED"
            terminal = {}

            def complete():
                nonlocal terminal
                terminal = call("read")
                return terminal["status"] in ("SUCCEEDED", "UNKNOWN", "FAILED", "NOT_ATTEMPTED")

            wait_for(complete, process)
            expected = (
                "UNKNOWN" if case in ("after_apply", "pre-receive", "post-receive") else "SUCCEEDED"
            )
            assert terminal["status"] == expected, terminal
            expected_ref = old if case == "pre-receive" else new
            assert git("--git-dir", receiver, "rev-parse", "--verify", REF) == expected_ref
            expected_observation = {"kind": "commit", "commit": expected_ref}
            expected_ack = "updated" if expected == "SUCCEEDED" else "unknown"
            expected_evidence = {
                **expected_tuple,
                "attempted": True,
                "acknowledgement": expected_ack,
                "observed_ref": expected_observation,
            }
            assert terminal["effect"] == "git.transition_ref", terminal
            assert terminal["git"] == expected_evidence, terminal
            frozen = call("receipt")
            assert frozen["status"] == "READY", frozen
            stop()
            before_hooks = {
                hook: (root / hook).read_bytes() if (root / hook).exists() else b""
                for hook in ("pre-receive", "post-receive")
            }
            assert before_hooks["pre-receive"].decode().splitlines() == [f"{old} {new} {REF}"]
            assert len(before_hooks["post-receive"].splitlines()) == (
                0 if case == "pre-receive" else 1
            )
            for file in (config / "receipt.seed", config / "git-receiver.json"):
                file.unlink()
            operator = json.loads((config / "operator.json").read_bytes())
            operator["approvals"] = []
            write(config / "operator.json", operator)
            shutil.rmtree(receiver)
            start()
            reopened = call("read")
            assert reopened["status"] == expected, reopened
            assert reopened["git"] == expected_evidence, reopened
            assert call("resume")["status"] == "NO_SELECTION"
            assert call("receipt") == frozen
            stop()
            write(root / "receipt.bin", bytes.fromhex(frozen["receipt_hex"]))
            fields = [
                b"receipt-key",
                receipt_public,
                PURPOSE,
                (0).to_bytes(8, "big"),
                (100).to_bytes(8, "big"),
            ]
            trust = b"KAPSEL-KAP0038-K8S-TRUST-V2\0" + b"".join(
                bytes([number]) + len(value).to_bytes(4, "big") + value
                for number, value in enumerate(fields, 1)
            )
            write(root / "receipt.trust", trust)
            report = json.loads(
                run(
                    str(args.kapsel),
                    "inspect",
                    "--receipt",
                    str(root / "receipt.bin"),
                    "--trust",
                    str(root / "receipt.trust"),
                    "--evaluation-time-unix-s",
                    "50",
                )
            )
            assert report["status"] == "INSPECTED" and report["result"] == expected, report
            assert report["effect"] == "git.transition_ref", report
            assert report["operation_id"] == "git-example", report
            assert report["authorization_id"] == "git-approval", report
            assert {key: report[key] for key in expected_tuple} == expected_tuple, report
            assert report["acknowledgement"] == expected_ack, report
            assert report["observed_ref"] == expected_observation, report
            assert report["attribution"] == (
                "acknowledged_update" if expected == "SUCCEEDED" else "not_established"
            )
            print(
                json.dumps(
                    {
                        "case": case,
                        "result": expected,
                        "inspection": report["status"],
                        "pre_receive_inputs": 1,
                        "receipt_sha256": frozen["receipt_sha256"],
                    }
                )
            )
        finally:
            stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--git", required=True, type=Path, help="operator-selected Git 2.55.0 binary"
    )
    for binary in ("kapsel", "kapseld", "bridge"):
        name = "kapsel-service-mcp" if binary == "bridge" else binary
        parser.add_argument(f"--{binary}", type=Path, default=REPO / "target/debug" / name)
    args = parser.parse_args()
    inputs = FixtureInputs(
        args.git.resolve(strict=True),
        args.kapsel.resolve(strict=True),
        args.kapseld.resolve(strict=True),
        args.bridge.resolve(strict=True),
    )
    os.umask(0o077)
    for case in (
        "healthy",
        "after_apply",
        "before_receipt_commit",
        "after_receipt_commit",
        "pre-receive",
        "post-receive",
    ):
        fixture(inputs, case)


if __name__ == "__main__":
    main()
