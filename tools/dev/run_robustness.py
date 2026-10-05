#!/usr/bin/env python3
"""Project-owned, fail-closed supervision for simulation and receipt fuzz lanes."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from types import FrameType
from typing import BinaryIO, Literal, NotRequired, TypedDict, cast

RunStatus = Literal["RUNNING", "PASSED", "FINDING", "INCOMPLETE", "CANCELLED", "TRIAGED"]
Lane = Literal["simulation", "fuzz", "unclassified"]


class CommandRecord(TypedDict):
    command: list[str]
    cwd: str
    environment: dict[str, str]
    status: Literal["RUNNING", "EXITED", "RETIREMENT_UNCONFIRMED"]
    log: str
    exit_status: NotRequired[int | None]


class SourceIdentity(TypedDict):
    revision: str
    rustc: str
    cargo: str


class ResultRecord(TypedDict):
    status: RunStatus
    lane: Lane
    mode: NotRequired[str]
    seeds: NotRequired[list[int]]
    cases: NotRequired[int]
    shards: NotRequired[int]
    scratch: NotRequired[str]
    started: NotRequired[float]
    timeout: NotRequired[int]
    revision: NotRequired[str]
    rustc: NotRequired[str]
    cargo: NotRequired[str]
    error: NotRequired[str]
    prior_status: NotRequired[RunStatus]
    regression: NotRequired[str]
    cancellation_requested: NotRequired[str]
    finished: NotRequired[float]
    exit_status: NotRequired[int]


ROOT = Path(__file__).resolve().parents[2]
TEST = "simulation_tests::seeded_lifecycle_crash_simulation_preserves_invariants"
NIGHTLY = "nightly-2026-07-03"
LOG_LIMIT = 8 * 1024 * 1024
STATE_LIMIT = 1024 * 1024 * 1024
FUZZ_TARGETS = {
    "inspect_receipt": 17 * 1024 + 5,
    "inspect_git_receipt": 17 * 1024 + 5,
    "verify_kubernetes_grant": 4097,
    "verify_git_grant": 4097,
    "service_document": 160 * 1024 + 1,
}
_pending_signal: int | None = None
_terminal_decided = False


class Incomplete(RuntimeError):
    pass


class Finding(RuntimeError):
    pass


class Cancelled(RuntimeError):
    pass


def private_root(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise Incomplete("roots must be absolute, existing private directories")
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise Incomplete(f"symlink component: {component}")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Incomplete(f"root must be owned by this user and mode 0700: {path}")
    if path == ROOT or path in ROOT.parents or ROOT in path.parents:
        raise Incomplete("roots must be outside the source checkout")
    return path


def atomic_json(path: Path, value: Mapping[str, object]) -> None:
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".new", dir=path.parent)
    temporary = Path(name)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)

    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def acquire_lock(state: Path) -> int:
    fd = os.open(state / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        os.close(fd)
        raise Incomplete("unsafe lock file")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        os.close(fd)
        raise Incomplete("another run owns the lock") from error
    return fd


def check_storage(state: Path, enforce_budget: bool = True) -> None:
    total = 0
    for directory, directories, files in os.walk(state, followlinks=False):
        for name in directories + files:
            info = (Path(directory) / name).lstat()
            if (
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or info.st_uid != os.getuid()
            ):
                raise Incomplete("unsafe entry in retained state")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    if enforce_budget:
        if total > STATE_LIMIT - 64 * 1024 * 1024:
            raise Incomplete("retained evidence budget exhausted; triage and archive explicitly")
        if shutil.disk_usage(state).free < 128 * 1024 * 1024:
            raise Incomplete("insufficient evidence storage")


def read_result(path: Path) -> ResultRecord:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise Incomplete("unsafe result record")
        if info.st_size > 1024 * 1024:
            raise Incomplete("oversized result record")
        data = source.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise Incomplete("oversized result record")
    result = json.loads(data)
    statuses = {"RUNNING", "PASSED", "FINDING", "INCOMPLETE", "CANCELLED", "TRIAGED"}
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("status"), str)
        or result.get("status") not in statuses
        or not isinstance(result.get("lane"), str)
        or result.get("lane") not in {"simulation", "fuzz", "unclassified"}
    ):
        raise Incomplete("invalid result record")
    # Legacy interrupted records can be partial. Validate each optional field before typing it.
    for field in (
        "mode",
        "scratch",
        "revision",
        "rustc",
        "cargo",
        "error",
        "regression",
        "cancellation_requested",
    ):
        if field in result and not isinstance(result[field], str):
            raise Incomplete("invalid result record")
    for field in ("cases", "shards", "timeout", "exit_status"):
        if field in result and type(result[field]) is not int:
            raise Incomplete("invalid result record")
    for field in ("started", "finished"):
        if field in result and type(result[field]) not in (int, float):
            raise Incomplete("invalid result record")
    if "prior_status" in result and (
        not isinstance(result["prior_status"], str) or result["prior_status"] not in statuses
    ):
        raise Incomplete("invalid result record")
    if "seeds" in result and (
        not isinstance(result["seeds"], list)
        or any(type(seed) is not int for seed in result["seeds"])
    ):
        raise Incomplete("invalid result record")
    return cast(ResultRecord, result)


def unresolved(state: Path, lane: str) -> list[Path]:
    pending = []
    for path in sorted(state.glob("run-*/result.json")):
        result = read_result(path)
        if result["lane"] in (lane, "unclassified") and result["status"] not in (
            "PASSED",
            "TRIAGED",
        ):
            pending.append(path.parent)
    # A directory without a result may be a crash before publication, never a pass.
    for path in state.glob("run-*"):
        if not (path / "result.json").is_file():
            pending.append(path)
    return pending


def check_cancellation() -> None:
    global _pending_signal
    if _pending_signal is not None:
        signum = _pending_signal
        _pending_signal = None
        raise Cancelled(f"cancelled by signal {signum}")


def retire_all(processes: list[subprocess.Popen[bytes]]) -> None:
    # Kill every owned group before waiting on any leader. A stuck leader must not spare peers.
    error = None
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as failure:
            error = failure
    deadline = time.monotonic() + 10
    for process in processes:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as failure:
            error = failure
    if error is not None:
        raise Incomplete(f"command retirement could not be confirmed: {error}") from error


def retire(process: subprocess.Popen[bytes]) -> None:
    retire_all([process])


class Supervisor:
    def __init__(self, evidence: Path, scratch: Path, lock: int, seconds: int) -> None:
        self.evidence = evidence
        self.scratch = scratch
        self.lock = lock
        self.deadline = time.monotonic() + seconds
        self.counter = 0
        self.commands: list[CommandRecord] = []

    def run(
        self,
        commands: list[list[str]],
        environments: list[dict[str, str]] | None = None,
        finding: bool = False,
    ) -> list[str]:
        if not commands:
            raise Incomplete("empty command selection")
        selector = selectors.DefaultSelector()
        children: list[subprocess.Popen[bytes]] = []
        logs: list[BinaryIO] = []
        records: list[CommandRecord] = []
        outputs = [bytearray() for _ in commands]
        retired: set[int] = set()
        try:
            for index, command in enumerate(commands):
                if time.monotonic() >= self.deadline:
                    raise Incomplete("overall timeout")
                self.counter += 1
                name = f"command-{self.counter:03}"
                selected_environment = dict(environments[index]) if environments else {}
                selected_environment.update(
                    TMPDIR=str(self.scratch), KAPSEL_SIMULATION_SCRATCH_ROOT=str(self.scratch)
                )
                record: CommandRecord = {
                    "command": command,
                    "cwd": str(ROOT),
                    "environment": selected_environment,
                    "status": "RUNNING",
                    "log": name + ".log",
                }
                records.append(record)
                self.commands.append(record)
                atomic_json(self.evidence / "commands.json", {"commands": self.commands})
                log = (self.evidence / (name + ".log")).open("xb")
                logs.append(log)
                env = os.environ.copy()
                env.update(record["environment"])
                check_cancellation()
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(self.lock,),
                )
                children.append(process)
                if process.stdout is None:
                    raise Incomplete("command output pipe was not created")
                selector.register(process.stdout, selectors.EVENT_READ, index)
                check_cancellation()

            next_storage_check = 0.0
            failure = None
            while selector.get_map() or any(child.poll() is None for child in children):
                check_cancellation()
                if time.monotonic() >= next_storage_check:
                    check_storage(self.evidence.parent)
                    next_storage_check = time.monotonic() + 1
                if time.monotonic() >= self.deadline:
                    raise Incomplete("overall timeout")
                for key, _ in selector.select(timeout=0.1):
                    index = key.data
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = LOG_LIMIT - len(outputs[index])
                    logs[index].write(data[:remaining])
                    logs[index].flush()
                    outputs[index].extend(data[:remaining])
                    if len(data) > remaining:
                        raise Incomplete(
                            "log limit exceeded; execution stopped, evidence incomplete"
                        )

                if failure is None:
                    for process in children:
                        status = process.poll()
                        if status == 0 and process.pid not in retired:
                            retire(process)
                            retired.add(process.pid)
                        if status not in (None, 0):
                            failure_type = Finding if finding and status > 0 else Incomplete
                            failure = failure_type(f"command exited {process.returncode}")
                            # Stop peers immediately, but drain bounded output before classifying.
                            pending = [child for child in children if child.pid not in retired]
                            retire_all(pending)
                            retired.update(child.pid for child in pending)
                            break
            check_cancellation()
            if failure is not None:
                raise failure

            for process in children:
                remaining = max(0.01, self.deadline - time.monotonic())
                try:
                    status = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired as error:
                    raise Incomplete("overall timeout") from error
                if status:
                    raise (Finding if finding and status > 0 else Incomplete)(
                        f"command exited {status}"
                    )
            return [output.decode("utf-8", errors="replace") for output in outputs]
        finally:
            retirement_error = None
            try:
                retire_all([process for process in children if process.pid not in retired])
            except Incomplete as error:
                retirement_error = error
            for process, record in zip(children, records, strict=False):
                record["exit_status"] = process.returncode
                record["status"] = (
                    "EXITED" if process.returncode is not None else "RETIREMENT_UNCONFIRMED"
                )
                if process.stdout is not None:
                    process.stdout.close()
            for log in logs:
                log.flush()
                os.fsync(log.fileno())
                log.close()
            selector.close()
            atomic_json(self.evidence / "commands.json", {"commands": self.commands})
            if retirement_error is not None:
                raise retirement_error
            check_cancellation()


def source_identity(supervisor: Supervisor) -> SourceIdentity:
    revision, dirty, compiler, cargo = supervisor.run(
        [
            ["git", "rev-parse", "HEAD"],
            ["git", "status", "--porcelain", "--untracked-files=all"],
            ["rustc", "-vV"],
            ["cargo", "-V"],
        ]
    )
    if dirty.strip() or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision.strip()):
        raise Incomplete("clean committed source required; no automatic update")
    return {"revision": revision.strip(), "rustc": compiler.strip(), "cargo": cargo.strip()}


def simulation(supervisor: Supervisor, seeds: list[int], cases: int, shards: int) -> None:
    output = supervisor.run(
        [
            [
                "cargo",
                "test",
                "--release",
                "--locked",
                "-p",
                "kapsel",
                "--lib",
                "--no-run",
                "--message-format=json",
                "--target-dir",
                str(supervisor.scratch / "simulation-build"),
            ]
        ]
    )[0]
    executables = []
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("executable")
            and message.get("target", {}).get("name") == "kapsel"
            and message.get("profile", {}).get("test")
        ):
            executables.append(message["executable"])
    if len(executables) != 1:
        raise Incomplete("missing or ambiguous simulation test executable")
    executable = executables[0]
    digest = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    atomic_json(
        supervisor.evidence / "simulation.json",
        {
            "seeds": seeds,
            "cases": cases,
            "shards": shards,
            "executable": executable,
            "sha256": digest,
        },
    )
    for seed in seeds:
        environments = [
            {
                "KAPSEL_SIMULATION_SEED": str(seed),
                "KAPSEL_SIMULATION_CASES": str(cases),
                "KAPSEL_SIMULATION_SHARDS": str(shards),
                "KAPSEL_SIMULATION_SHARD_INDEX": str(index),
            }
            for index in range(shards)
        ]
        outputs = supervisor.run(
            [[executable, TEST, "--ignored", "--exact", "--nocapture"] for _ in range(shards)],
            environments,
            finding=True,
        )
        for index, output in enumerate(outputs):
            count = len(range(index, cases, shards))
            marker = f"KAPSEL_SIMULATION_COMPLETED seed={seed} shard={index}/{shards} cases={count}"
            if output.splitlines().count(marker) != 1 or not re.search(
                r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE
            ):
                raise Incomplete(f"missing execution evidence for seed={seed} shard={index}")


def corpus_identity(path: Path) -> dict[str, str]:
    entries = {}
    total = 0
    for item in sorted(path.iterdir()):
        info = item.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Incomplete("unsafe corpus entry")
        total += info.st_size
        if info.st_size > LOG_LIMIT or total > 64 * 1024 * 1024:
            raise Incomplete("corpus replay budget exceeded")
        entries[item.name] = hashlib.sha256(item.read_bytes()).hexdigest()
    if not entries:
        raise Incomplete("empty corpus")
    return entries


def fuzz(
    supervisor: Supervisor,
    state: Path,
    seed: int,
    seconds: int,
    smoke: bool,
    target: str = "inspect_receipt",
) -> None:
    if target not in FUZZ_TARGETS:
        raise Incomplete("unknown fuzz target")
    # Preserve the original Kubernetes retained corpus; distinct decoders never share corpus state.
    corpus_name = "corpus" if target == "inspect_receipt" else "corpus-" + target
    corpus = (supervisor.scratch if smoke else state) / corpus_name
    seeds = ROOT / "fuzz/corpus" / target
    seed_identity = corpus_identity(seeds)
    if not corpus.exists():
        shutil.copytree(seeds, corpus)
        corpus.chmod(0o700)
    else:
        # Add new maintained seeds without replacing or pruning discovered inputs.
        for name, digest in seed_identity.items():
            destination = corpus / ("seed-" + digest)
            if not destination.exists():
                shutil.copyfile(seeds / name, destination)
    before = corpus_identity(corpus)
    # Keep the exact starting corpus, not only names or hashes after mutation.
    replay = supervisor.evidence / "corpus-before"
    shutil.copytree(corpus, replay)
    atomic_json(
        supervisor.evidence / "fuzz.json",
        {"target": target, "seed": seed, "seconds": seconds, "corpus_before": before},
    )
    identities = supervisor.run(
        [
            ["rustup", "run", NIGHTLY, "rustc", "-vV"],
            ["rustup", "run", NIGHTLY, "cargo", "fuzz", "--version"],
            [
                "rustup",
                "run",
                NIGHTLY,
                "cargo",
                "metadata",
                "--locked",
                "--manifest-path",
                "fuzz/Cargo.toml",
                "--format-version",
                "1",
            ],
        ]
    )

    host = re.search(r"^host: ([a-zA-Z0-9_.-]+)$", identities[0], re.MULTILINE)
    if host is None:
        raise Incomplete("missing nightly target identity")
    build_root = supervisor.scratch / "fuzz-build"
    lock = ROOT / "fuzz/Cargo.lock"
    before_lock = lock.read_bytes()
    artifacts = supervisor.evidence / "artifacts"
    artifacts.mkdir(mode=0o700)
    runs = str(int(os.environ.get("KAPSEL_FUZZ_RUNS", "10000"))) if smoke else "-1"
    if smoke and int(runs) <= 0:
        raise Incomplete("smoke requires a positive run count")
    runtime_started = False
    try:
        supervisor.run(
            [
                [
                    "rustup",
                    "run",
                    NIGHTLY,
                    "cargo",
                    "fuzz",
                    "build",
                    "--dev",
                    "--fuzz-dir",
                    "fuzz",
                    "--target",
                    host[1],
                    "--target-dir",
                    str(build_root),
                    target,
                ]
            ]
        )
        executable = build_root / host[1] / "debug" / target
        if not executable.is_file():
            raise Incomplete("missing built fuzz executable")
        atomic_json(
            supervisor.evidence / "fuzz.json",
            {
                "target": target,
                "seed": seed,
                "seconds": seconds,
                "corpus_before": before,
                "nightly": identities[0],
                "cargo_fuzz": identities[1],
                "executable": str(executable),
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            },
        )
        # cargo-fuzz run creates a default artifact directory in source even with an override.
        # Launch the built libFuzzer binary directly, with cargo-fuzz's ASan default.
        asan = os.environ.get("ASAN_OPTIONS", "")
        asan = (asan + ":" if asan else "") + "detect_odr_violation=0"
        runtime_started = True
        output = supervisor.run(
            [
                [
                    str(executable),
                    str(corpus),
                    f"-runs={runs}",
                    f"-seed={seed}",
                    f"-max_total_time={seconds}",
                    f"-max_len={FUZZ_TARGETS[target]}",
                    "-timeout=10",
                    "-rss_limit_mb=2048",
                    f"-artifact_prefix={artifacts}/",
                ]
            ],
            [{"ASAN_OPTIONS": asan}],
            finding=True,
        )[0]
    except (Finding, Incomplete) as error:
        if not runtime_started or not str(error).startswith("command exited"):
            raise
        output = (supervisor.evidence / supervisor.commands[-1]["log"]).read_text(errors="replace")
        if any(
            marker in output
            for marker in ("ERROR: libFuzzer:", "ERROR: AddressSanitizer:", "panicked at")
        ):
            raise Finding(str(error)) from error
        raise Incomplete("fuzz command failed without a discovered-failure diagnostic") from error
    finally:
        if lock.read_bytes() != before_lock:
            raise Incomplete("fuzz lockfile changed")

    completed = re.search(r"Done (\d+) runs in ", output)
    if completed is None or int(completed[1]) <= 0:
        raise Incomplete("missing fuzz execution evidence")
    atomic_json(supervisor.evidence / "corpus-after.json", corpus_identity(corpus))


def positive(value: str) -> int:
    number = int(value)
    if not 0 < number <= 1_000_000:
        raise argparse.ArgumentTypeError("expected integer in 1..1000000")
    return number


def cancel(signum: int, _frame: FrameType | None) -> None:
    global _pending_signal
    if _terminal_decided:
        return
    # Further termination requests cannot interrupt retirement or result publication.
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(name, signal.SIG_IGN)
    # Never raise asynchronously: spawning and cleanup must finish registering/retiring children.
    _pending_signal = signum


def triage_run(state: Path, run_name: str | None, regression: str | None) -> None:
    if (
        not run_name
        or not run_name.startswith("run-")
        or Path(run_name).name != run_name
        or not regression
    ):
        raise Incomplete("triage requires --run basename and --regression reference")

    result_path = state / run_name / "result.json"
    result: ResultRecord = (
        read_result(result_path)
        if result_path.exists()
        else {
            "status": "INCOMPLETE",
            "lane": "unclassified",
            "error": "interrupted before initial result publication",
        }
    )
    if result["status"] in ("PASSED", "TRIAGED"):
        raise Incomplete("run does not need triage")

    result.update(status="TRIAGED", prior_status=result["status"], regression=regression)
    atomic_json(result_path, result)


def select_seeds(lane: Lane, mode: str, explicit: list[int] | None) -> list[int]:
    seeds = explicit
    seed_bits = 64 if lane == "simulation" else 32
    if not seeds:
        environment_key = "KAPSEL_SIMULATION_SEED" if lane == "simulation" else "KAPSEL_FUZZ_SEED"
        environment_seed = os.environ.get(environment_key)
        if environment_seed:
            seeds = [int(environment_seed)]
        else:
            seed_count = 3 if mode == "soak" else 1
            seeds = [secrets.randbits(seed_bits) or 1 for _ in range(seed_count)]

    if any(not 0 < seed < 2**seed_bits for seed in seeds):
        raise Incomplete(f"seeds must be nonzero u{seed_bits} values")
    if lane == "fuzz" and len(seeds) != 1:
        raise Incomplete("fuzz requires exactly one seed")
    return seeds


def main() -> int:
    global _terminal_decided
    _terminal_decided = False
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("simulation", "soak", "fuzz", "fuzz-smoke", "triage"))
    parser.add_argument("--state", default=os.environ.get("KAPSEL_SOAK_STATE_DIR"))
    parser.add_argument("--scratch", default=os.environ.get("KAPSEL_SCRATCH_ROOT"))
    parser.add_argument("--timeout", type=positive, default=3600)
    parser.add_argument(
        "--cases", type=positive, default=os.environ.get("KAPSEL_SIMULATION_CASES", "1000")
    )
    parser.add_argument(
        "--shards", type=positive, default=os.environ.get("KAPSEL_SIMULATION_SHARDS", "2")
    )
    parser.add_argument("--seed", type=int, action="append")
    parser.add_argument(
        "--fuzz-seconds", type=positive, default=os.environ.get("KAPSEL_FUZZ_MAX_TIME", "1800")
    )
    parser.add_argument("--fuzz-target", choices=tuple(FUZZ_TARGETS), default="inspect_receipt")
    parser.add_argument("--run")
    parser.add_argument("--regression", help="committed regression reference and passing check")
    args = parser.parse_args()
    if not args.state or (args.mode != "triage" and not args.scratch):
        parser.error("select existing private --state and --scratch roots")
    os.umask(0o077)
    if os.environ.get("KAPSEL_SOAK_AUTO_UPDATE", "0") != "0":
        raise Incomplete("automatic source updates are not supported")
    state = private_root(args.state)
    lock_descriptor = acquire_lock(state)
    try:
        check_storage(state, enforce_budget=args.mode != "triage")
        if args.mode == "triage":
            triage_run(state, args.run, args.regression)
            return 0

        scratch_root = private_root(args.scratch)
        if state == scratch_root or state in scratch_root.parents or scratch_root in state.parents:
            raise Incomplete("state and scratch roots must be disjoint")
        lane: Lane = "simulation" if args.mode in ("simulation", "soak") else "fuzz"
        blocked = unresolved(state, lane)
        if blocked:
            raise Incomplete(f"lane stopped pending explicit triage: {blocked[0]}")
        if args.shards > 128 or args.shards > args.cases:
            raise Incomplete("simulation requires 1..128 nonempty shards")

        seeds = select_seeds(lane, args.mode, args.seed)

        evidence = Path(tempfile.mkdtemp(prefix="run-", dir=state))
        scratch = Path(tempfile.mkdtemp(prefix="run-", dir=scratch_root))
        scratch_identity = scratch.stat()
        result: ResultRecord = {
            "status": "RUNNING",
            "lane": lane,
            "mode": args.mode,
            "seeds": seeds,
            "cases": args.cases,
            "shards": args.shards,
            "scratch": str(scratch),
            "started": time.time(),
            "timeout": args.timeout,
        }
        atomic_json(evidence / "result.json", result)
        print(f"evidence: {evidence}", flush=True)

        supervisor = Supervisor(evidence, scratch, lock_descriptor, args.timeout)
        code = 2
        try:
            identity = source_identity(supervisor)
            result.update(
                revision=identity["revision"], rustc=identity["rustc"], cargo=identity["cargo"]
            )
            atomic_json(evidence / "result.json", result)
            if lane == "simulation":
                simulation(supervisor, seeds, args.cases, args.shards)
            else:
                fuzz(
                    supervisor,
                    state,
                    seeds[0],
                    args.fuzz_seconds,
                    args.mode == "fuzz-smoke",
                    args.fuzz_target,
                )
            # Refuse a pass if source changed during execution.
            if source_identity(supervisor)["revision"] != identity["revision"]:
                raise Incomplete("source changed during run")
            check_cancellation()
            private_root(str(scratch_root))
            current = scratch.lstat()
            if (current.st_dev, current.st_ino) != (
                scratch_identity.st_dev,
                scratch_identity.st_ino,
            ):
                raise Incomplete("scratch identity changed; refusing cleanup")
            check_cancellation()
            shutil.rmtree(scratch)
            check_cancellation()
            result["status"] = "PASSED"
            code = 0
        except Finding as error:
            result.update(status="FINDING", error=str(error))
            code = 1
        except Cancelled as error:
            result.update(status="CANCELLED", error=str(error))
            code = 130
        except (OSError, ValueError, Incomplete) as error:
            result.update(status="INCOMPLETE", error=str(error))
        finally:
            # All owned groups have been handled. Requests before this decision are classified;
            # later signals cannot change an already selected terminal outcome.
            _terminal_decided = True
            try:
                check_cancellation()
            except Cancelled as error:
                if result["status"] == "INCOMPLETE":
                    result["cancellation_requested"] = str(error)
                else:
                    result.update(status="CANCELLED", error=str(error))
                    code = 130
            result.update(finished=time.time(), exit_status=code)
            atomic_json(evidence / "result.json", result)
        print(f"{result['status']}: {evidence}", flush=True)
        return code
    finally:
        os.close(lock_descriptor)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGHUP, cancel)
    try:
        sys.exit(main())
    except (OSError, ValueError, Incomplete, Cancelled) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        sys.exit(2)
