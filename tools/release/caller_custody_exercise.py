"""Exercise caller retirement and receipt custody in disposable Linux, without product state."""

import os
import pathlib
import select
import subprocess
import sys
import tempfile
from typing import NotRequired, TypedDict


class CallerIdentity(TypedDict):
    user: int
    group: int
    extra_groups: list[int]
    cwd: str
    env: NotRequired[dict[str, str]]


def retire_callers(identity: CallerIdentity, source: str) -> None:
    output = subprocess.check_output([sys.executable, "-I", "-c", source], timeout=5, **identity)
    assert output == b"CALLERS_RETIRED\n"


def exercise_retirement(identity: CallerIdentity, retirement_source: str) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **identity,
    )
    try:
        process.wait(timeout=0.05)
        raise AssertionError("timeout fixture exited early")
    except subprocess.TimeoutExpired:
        pass

    retire_callers(identity, retirement_source)
    assert process.wait(timeout=5) == -9

    read_descriptor, write_descriptor = os.pipe()
    try:
        subprocess.run(
            [sys.executable, "-I", "/fixtures/background_caller_fixture.py"],
            capture_output=True,
            pass_fds=(write_descriptor,),
            check=True,
            timeout=5,
            **identity,
        )
        os.close(write_descriptor)
        write_descriptor = None
        assert not select.select([read_descriptor], [], [], 0)[0], (
            "background fixture already retired"
        )

        retire_callers(identity, retirement_source)
        assert select.select([read_descriptor], [], [], 1)[0], (
            "background child survived completed parent"
        )
        assert os.read(read_descriptor, 1) == b"", "background child retained its descriptor"
    finally:
        os.close(read_descriptor)
        if write_descriptor is not None:
            os.close(write_descriptor)


def snapshot_receipt(
    identity: CallerIdentity, source: str, path: pathlib.Path
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-c", source, str(path)],
        capture_output=True,
        timeout=5,
        **identity,
    )


def exercise_receipt_custody(
    identity: CallerIdentity, retirement_source: str, snapshot_source: str
) -> None:
    root = pathlib.Path(tempfile.mkdtemp())
    os.chown(root, 61001, 61000)
    # A writable caller HOME/CWD must not poison the independent Python observer.
    (root / "sitecustomize.py").write_text("raise SystemExit(99)\n")
    (root / "pathlib.py").write_text("raise SystemExit(99)\n")
    identity["cwd"] = str(root)
    identity["env"] = dict(os.environ, PYTHONPATH=str(root), HOME=str(root))
    retire_callers(identity, retirement_source)

    caller_receipt = root / "model.receipt"
    canonical_receipt = root / "checked.receipt"
    caller_receipt.symlink_to(canonical_receipt)
    for target_exists in (False, True):
        if target_exists:
            canonical_receipt.write_bytes(b"frozen")
            os.chown(canonical_receipt, 61001, 61000)
        result = snapshot_receipt(identity, snapshot_source, caller_receipt)
        assert result.returncode != 0 and not result.stdout
    caller_receipt.unlink()

    os.link(canonical_receipt, caller_receipt)
    result = snapshot_receipt(identity, snapshot_source, caller_receipt)
    assert result.returncode != 0
    caller_receipt.unlink()

    for content in (b"x" * 65537, b"frozen"):
        caller_receipt.write_bytes(content)
        os.chown(caller_receipt, 61001, 61000)
        result = snapshot_receipt(identity, snapshot_source, caller_receipt)
        within_byte_bound = content == b"frozen"
        assert (result.returncode == 0) == within_byte_bound
        if result.returncode == 0:
            assert result.stdout == content
    caller_receipt.unlink()

    os.mkfifo(caller_receipt, 0o600)
    os.chown(caller_receipt, 61001, 61000)
    result = snapshot_receipt(identity, snapshot_source, caller_receipt)
    assert result.returncode != 0


def main() -> None:
    retirement_source = pathlib.Path("/fixtures/retire_callers.py").read_text()
    snapshot_source = pathlib.Path("/fixtures/snapshot_receipt.py").read_text()
    root_attempt = subprocess.run(
        [sys.executable, "-I", "-c", retirement_source], capture_output=True, timeout=5
    )
    assert root_attempt.returncode != 0

    identity: CallerIdentity = {
        "user": 61001,
        "group": 61000,
        "extra_groups": [],
        "cwd": "/tmp",
    }
    exercise_retirement(identity, retirement_source)
    exercise_receipt_custody(identity, retirement_source, snapshot_source)
    print("Caller timeout/background retirement and receipt custody probes passed")


if __name__ == "__main__":
    main()
