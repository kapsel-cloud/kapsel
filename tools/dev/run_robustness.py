#!/usr/bin/env python3
"""Run one bounded simulation or fuzz job in a new evidence directory.

Jobs never consult previous results or modify input corpora. Hard resource isolation belongs
to the invoking CI/container owner, not this process-group launcher.
"""

import argparse
import hashlib
import io
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from types import FrameType
from typing import BinaryIO, Literal, NotRequired, TypedDict

ROOT = Path(__file__).resolve().parents[2]
KERNEL_TEST = "kernel_simulation_tests::kernel_trace_exploration_or_replay"
NIGHTLY = "nightly-2026-07-03"
LOG_LIMIT = 8 * 1024 * 1024
SOURCE_LIMIT = 64 * 1024 * 1024
CORPUS_FILES = 10000
BUILD_ENVIRONMENT = (
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTUP_TOOLCHAIN",
)
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


class CommandFailed(Incomplete):
    def __init__(self, status: int, output: str) -> None:
        super().__init__(f"command exited {status}")
        self.status = status
        self.output = output


class CommandRecord(TypedDict):
    command: list[str]
    environment: dict[str, str]
    phase: str
    status: Literal["RUNNING", "EXITED", "RETIREMENT_UNCONFIRMED"]
    log: str
    seconds: NotRequired[float]
    exit_status: NotRequired[int | None]


def atomic_json(path: Path, value: Mapping[str, object]) -> None:
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".new", dir=path.parent)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(name, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bounded_bytes(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Incomplete(f"not a bounded regular file: {path}")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise Incomplete(f"file grew beyond limit: {path}")
        return data


def read_json(path: Path) -> dict:
    value = json.loads(bounded_bytes(path, 256 * 1024))
    if not isinstance(value, dict):
        raise Incomplete(f"expected an object: {path}")
    return value


def check_cancellation() -> None:
    global _pending_signal
    if _pending_signal is not None:
        signum = _pending_signal
        _pending_signal = None
        raise Cancelled(f"cancelled by signal {signum}")


def retire_all(processes: list[subprocess.Popen[bytes]]) -> None:
    # Kill all owned groups before waiting on any leader. A stuck leader must not spare peers.
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


class Job:
    def __init__(self, evidence: Path, seconds: int) -> None:
        self.evidence = evidence
        self.deadline = time.monotonic() + seconds
        self.commands: list[CommandRecord] = []
        self.phase = "setup"
        self.timings: dict[str, float] = {}
        self.temporary = evidence / "tmp"
        self.temporary.mkdir(mode=0o700)

    def checkpoint(self) -> None:
        check_cancellation()
        if time.monotonic() >= self.deadline:
            raise Incomplete("overall timeout")

    def run(
        self, commands: list[list[str]], environments: list[dict[str, str]] | None = None
    ) -> list[str]:
        if not commands:
            raise Incomplete("empty command selection")
        selector = selectors.DefaultSelector()
        children: list[subprocess.Popen[bytes]] = []
        logs: list[BinaryIO] = []
        records: list[CommandRecord] = []
        outputs = [bytearray() for _ in commands]
        retired: set[int] = set()
        started = time.monotonic()
        try:
            for index, command in enumerate(commands):
                self.checkpoint()
                name = f"command-{len(self.commands) + 1:03}"
                selected = {
                    name: os.environ[name] for name in BUILD_ENVIRONMENT if name in os.environ
                }
                if environments:
                    selected.update(environments[index])
                selected.update(TMPDIR=str(self.temporary))
                record: CommandRecord = {
                    "command": command,
                    "environment": selected,
                    "phase": self.phase,
                    "status": "RUNNING",
                    "log": name + ".log",
                }
                records.append(record)
                self.commands.append(record)
                atomic_json(self.evidence / "commands.json", {"commands": self.commands})
                log = (self.evidence / record["log"]).open("xb")
                logs.append(log)
                # Ambient replay/control variables must not replace the selected workload.
                env = {k: v for k, v in os.environ.items() if not k.startswith("KAPSEL_KERNEL_")}
                env.update(selected)
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                children.append(process)
                if process.stdout is None:
                    raise Incomplete("command output pipe was not created")
                selector.register(process.stdout, selectors.EVENT_READ, index)
                self.checkpoint()

            failure: tuple[int, int] | None = None
            while selector.get_map() or any(child.poll() is None for child in children):
                self.checkpoint()
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
                    for index, process in enumerate(children):
                        status = process.poll()
                        if status == 0 and process.pid not in retired:
                            retire(process)
                            retired.add(process.pid)
                        if status not in (None, 0):
                            failure = (index, status)
                            pending = [child for child in children if child.pid not in retired]
                            retire_all(pending)
                            retired.update(child.pid for child in pending)
                            break
            self.checkpoint()
            # EOF and exit are separate events; reconcile late failures before accepting output.
            if failure is None:
                for index, process in enumerate(children):
                    status = process.wait(timeout=max(0.01, self.deadline - time.monotonic()))
                    if status:
                        failure = (index, status)
                        break
            if failure is not None:
                index, status = failure
                raise CommandFailed(status, outputs[index].decode("utf-8", errors="replace"))
            return [output.decode("utf-8", errors="replace") for output in outputs]
        finally:
            retirement_error = None
            try:
                retire_all([process for process in children if process.pid not in retired])
            except Incomplete as error:
                retirement_error = error
            for process, record in zip(children, records, strict=False):
                record["exit_status"] = process.returncode
                record["seconds"] = time.monotonic() - started
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
            elapsed = time.monotonic() - started
            self.timings[self.phase] = self.timings.get(self.phase, 0.0) + elapsed
            atomic_json(self.evidence / "commands.json", {"commands": self.commands})
            if retirement_error is not None:
                raise retirement_error
            check_cancellation()


def source_snapshot(job: Job, retain: bool) -> str:
    names = job.run([["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]])[0]
    digest = hashlib.sha256()
    total = 0
    archive = tarfile.open(job.evidence / "source.tar", "x") if retain else None
    try:
        for name in sorted(set(names.split("\0")) - {""}):
            job.checkpoint()
            path = ROOT / name
            if not path.exists() and not path.is_symlink():
                continue  # Git's index still lists unstaged deletions.
            data = bounded_bytes(path, SOURCE_LIMIT - total)
            total += len(data)
            encoded = name.encode()
            digest.update(len(encoded).to_bytes(8, "little") + encoded)
            digest.update(len(data).to_bytes(8, "little") + data)
            if archive is not None:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = stat.S_IMODE(path.stat().st_mode)
                archive.addfile(member, io.BytesIO(data))
    finally:
        if archive is not None:
            archive.close()
    return digest.hexdigest()


def retain_executable(job: Job, built: Path) -> tuple[Path, str]:
    data = bounded_bytes(built, 512 * 1024 * 1024)
    retained = job.evidence / "executable"
    with retained.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    retained.chmod(0o700)
    return retained, hashlib.sha256(data).hexdigest()


def simulation_executable(output: str) -> Path:
    executables = []
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        target, profile = message.get("target"), message.get("profile")
        if (
            message.get("reason") == "compiler-artifact"
            and isinstance(target, dict)
            and target.get("name") == "kapsel"
            and isinstance(profile, dict)
            and profile.get("test") is True
            and isinstance(message.get("executable"), str)
        ):
            executables.append(Path(message["executable"]))
    if len(executables) != 1 or not executables[0].is_absolute():
        raise Incomplete("missing or ambiguous simulation test executable")
    return executables[0]


def require_test_completion(output: str, marker: str) -> None:
    if output.splitlines().count(marker) != 1 or not re.search(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE
    ):
        raise Incomplete(f"missing execution evidence: {marker}")


def finding_marker(error: CommandFailed) -> dict:
    matches = re.findall(r"^KAPSEL_KERNEL_FINDING (.+)$", error.output, re.MULTILINE)
    if error.status != 101 or len(matches) != 1:
        raise Incomplete("simulation failed without a complete law finding") from error
    value = json.loads(matches[0])
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("law"), str)
        or not isinstance(value.get("event"), int)
        or value["event"] < 0
        or not isinstance(value.get("defect_reached"), list)
    ):
        raise Incomplete("invalid law finding")
    return value


def replay_trace(job: Job, command: list[str], path: Path) -> dict | None:
    try:
        output = job.run(
            [command], [{"KAPSEL_KERNEL_REPLAY": str(path), "KAPSEL_KERNEL_JOB": "1"}]
        )[0]
    except CommandFailed as error:
        return finding_marker(error)
    require_test_completion(output, "KAPSEL_KERNEL_REPLAYED cases=1")
    return None


def duration_completion(
    output: str, seed: int, shards: int, index: int, steps: int, duration_ms: int
) -> int:
    prefix = (
        f"KAPSEL_KERNEL_DURATION_COMPLETED seed={seed} shard={index}/{shards} "
        rf"cases=([1-9]\d*) steps={steps} duration_ms={duration_ms} elapsed_ms=(\d+)"
    )
    matches = list(re.finditer("^" + prefix + "$", output, re.MULTILINE))
    if len(matches) != 1 or int(matches[0][2]) < duration_ms:
        raise Incomplete("missing orderly duration completion after useful work")
    require_test_completion(output, matches[0][0])
    return int(matches[0][1])


def retained_traces(
    directory: Path, seed: int, cases: int, shards: int, index: int, digest: str, source: str
) -> None:
    expected = {f"case-{case}.json" for case in range(index, cases, shards)}
    if {path.name for path in directory.iterdir()} != expected:
        raise Incomplete("missing or unexpected exploration traces")
    hashes = {}
    for case in range(index, cases, shards):
        path = directory / f"case-{case}.json"
        data = read_json(path)
        if (
            data.get("seed") != (seed + case) % 2**64
            or data.get("executable_sha256") != digest
            or data.get("source_sha256") != source
        ):
            raise Incomplete("exploration trace identity mismatch")
        hashes[path.name] = hashlib.sha256(bounded_bytes(path, 64 * 1024)).hexdigest()
    atomic_json(directory.with_suffix(".json"), hashes)


def simulation(job: Job, args: argparse.Namespace, source: str) -> None:
    job.phase = "build"
    if args.executable:
        built = args.executable
    else:
        output = job.run(
            [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "kapsel",
                    "--lib",
                    "--no-run",
                    "--message-format=json",
                ]
            ]
        )[0]
        built = simulation_executable(output)
    executable, digest = retain_executable(job, built)
    atomic_json(
        job.evidence / "simulation.json",
        {
            "executable_sha256": digest,
            "source_sha256": source,
            "cargo_build_requested": not bool(args.executable),
        },
    )
    command = [str(executable), KERNEL_TEST, "--ignored", "--exact", "--nocapture"]
    job.phase = "execution"
    if args.replay:
        retained = job.evidence / "replay.json"
        retained.write_bytes(bounded_bytes(args.replay, 64 * 1024))
        if args.executable and read_json(retained).get("executable_sha256") != digest:
            raise Incomplete("original replay executable does not match trace identity")
        finding = replay_trace(job, command, retained)
        if finding is not None:
            atomic_json(job.evidence / "finding.json", finding)
            raise Finding(f"replayed {finding['law']}")
        return

    duration = args.duration
    if duration and job.deadline - time.monotonic() < duration + 10:
        raise Incomplete("duration requires ten seconds of watchdog recording/cleanup grace")
    for seed in args.seed:
        environments = []
        for index in range(args.shards):
            directory = job.evidence / f"traces-{seed}-{index}"
            directory.mkdir(mode=0o700)
            environments.append(
                {
                    "KAPSEL_KERNEL_SEED": str(seed),
                    "KAPSEL_KERNEL_CASES": str(args.cases),
                    "KAPSEL_KERNEL_STEPS": str(args.steps),
                    "KAPSEL_KERNEL_DURATION_MS": str((duration or 0) * 1000),
                    "KAPSEL_KERNEL_SHARDS": str(args.shards),
                    "KAPSEL_KERNEL_SHARD_INDEX": str(index),
                    "KAPSEL_KERNEL_EVIDENCE": str(directory),
                    "KAPSEL_KERNEL_JOB": "1",
                }
            )
        try:
            outputs = job.run([command] * args.shards, environments)
        except CommandFailed as error:
            finding = finding_marker(error)
            # A diagnostic alone cannot establish custody or successful minimization/replay.
            failures = list(job.evidence.glob(f"traces-{seed}-*/failure.json"))
            if not failures:
                raise Incomplete("missing retained finding") from error
            for failure in failures:
                report = read_json(failure)
                case = report.get("case")
                if (
                    type(case) is not int
                    or not 0 <= case < (10000 * args.shards if duration else args.cases)
                    or report.get("finding") != finding
                ):
                    raise Incomplete("finding record mismatch") from error
                for name in (f"case-{case}.json", f"finding-{case}.json"):
                    path = failure.parent / name
                    trace = read_json(path)
                    if (
                        trace.get("executable_sha256") != digest
                        or trace.get("source_sha256") != source
                    ):
                        raise Incomplete("finding trace identity mismatch") from error
                    replayed = replay_trace(job, command, path)
                    if replayed is None or replayed["law"] != finding["law"]:
                        raise Incomplete("retained finding did not reproduce") from error
            raise Finding(finding["law"]) from error
        for index, output in enumerate(outputs):
            if duration:
                count = duration_completion(
                    output, seed, args.shards, index, args.steps, duration * 1000
                )
                last_case = index + count * args.shards
            else:
                count = len(range(index, args.cases, args.shards))
                marker = f"KAPSEL_KERNEL_COMPLETED seed={seed} shard={index}/{args.shards} cases={count} steps={args.steps}"
                require_test_completion(output, marker)
                last_case = args.cases
            retained_traces(
                job.evidence / f"traces-{seed}-{index}",
                seed,
                last_case,
                args.shards,
                index,
                digest,
                source,
            )


def corpus_identity(path: Path, job: Job | None = None) -> dict[str, str]:
    entries = {}
    total = 0
    with os.scandir(path) as directory:
        for index, item in enumerate(directory):
            if index >= CORPUS_FILES:
                raise Incomplete("corpus entry limit exceeded")
            if job is not None:
                job.checkpoint()
            data = bounded_bytes(Path(item.path), min(LOG_LIMIT, SOURCE_LIMIT - total))
            total += len(data)
            entries[item.name] = hashlib.sha256(data).hexdigest()
    return dict(sorted(entries.items()))


def fuzz_completion(status: int, output: str, runs: int, artifacts: Path) -> None:
    if status:
        if any(
            marker in output
            for marker in (
                "ERROR: libFuzzer: timeout",
                "ERROR: libFuzzer: out-of-memory",
                "ERROR: libFuzzer: file size exceeded",
                "ERROR: AddressSanitizer: out-of-memory",
                "ERROR: AddressSanitizer: allocator is out of memory",
            )
        ):
            raise Incomplete("fuzz execution exceeded a resource limit")
        diagnostic = any(
            marker in output
            for marker in ("ERROR: libFuzzer:", "ERROR: AddressSanitizer:", "panicked at")
        )
        if diagnostic and corpus_identity(artifacts):
            raise Finding(f"fuzz command exited {status}; crash input retained")
        raise Incomplete(f"fuzz command exited {status} without retained finding evidence")
    completed = re.findall(r"^Done (\d+) runs in ", output, re.MULTILINE)
    if len(completed) != 1 or int(completed[0]) != runs:
        raise Incomplete("missing or mismatched fuzz execution count")


def fuzz(job: Job, args: argparse.Namespace, source: str) -> None:
    before = job.evidence / "corpus-before"
    before.mkdir(mode=0o700)
    inputs = {}
    total = 0
    files = 0
    for index, path in enumerate(args.corpus):
        identity = corpus_identity(path, job)
        if not identity:
            raise Incomplete("empty input corpus")
        inputs[str(path)] = identity
        for name in identity:
            job.checkpoint()
            files += 1
            if files > CORPUS_FILES:
                raise Incomplete("combined corpus entry limit exceeded")
            data = bounded_bytes(path / name, min(LOG_LIMIT, SOURCE_LIMIT - total))
            total += len(data)
            if hashlib.sha256(data).hexdigest() != identity[name]:
                raise Incomplete("input corpus changed during snapshot")
            retained = before / f"{index}-{name}"
            retained.write_bytes(data)
            retained.chmod(0o400)
    discoveries = job.evidence / "discoveries" / args.fuzz_target
    discoveries.mkdir(mode=0o700, parents=True)
    artifacts = job.evidence / "artifacts"
    artifacts.mkdir(mode=0o700)
    snapshot = corpus_identity(before, job)
    if args.runs <= len(snapshot):
        raise Incomplete("run limit must exceed corpus initialization count")
    atomic_json(job.evidence / "corpora.json", {"inputs": inputs, "snapshot": snapshot})
    identities = job.run(
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
                "--no-deps",
            ],
        ]
    )
    host = re.search(r"^host: ([a-zA-Z0-9_.-]+)$", identities[0], re.MULTILINE)
    if host is None:
        raise Incomplete("missing nightly target identity")
    build_root = Path(json.loads(identities[2])["target_directory"])
    job.phase = "build"
    job.run(
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
                args.fuzz_target,
            ]
        ]
    )
    executable, digest = retain_executable(job, build_root / host[1] / "debug" / args.fuzz_target)
    atomic_json(
        job.evidence / "fuzz.json",
        {
            "target": args.fuzz_target,
            "seed": args.seed[0],
            "runs": args.runs,
            "nightly": identities[0],
            "cargo_fuzz": identities[1],
            "executable_sha256": digest,
            "source_sha256": source,
        },
    )
    command = [
        str(executable),
        str(discoveries),
        str(before),
        f"-runs={args.runs}",
        f"-seed={args.seed[0]}",
        f"-max_len={FUZZ_TARGETS[args.fuzz_target]}",
        "-timeout=10",
        "-rss_limit_mb=2048",
        f"-artifact_prefix={artifacts}/",
    ]
    job.phase = "execution"
    status = 0
    try:
        output = job.run([command], [{"ASAN_OPTIONS": "detect_odr_violation=0"}])[0]
    except CommandFailed as error:
        status, output = error.status, error.output
    finally:
        atomic_json(job.evidence / "discoveries.json", corpus_identity(discoveries, job))
        atomic_json(job.evidence / "artifacts.json", corpus_identity(artifacts, job))
        for path, identity in inputs.items():
            if corpus_identity(Path(path), job) != identity:
                raise Incomplete("read-only input corpus changed")
        if corpus_identity(before, job) != snapshot:
            raise Incomplete("input snapshot changed")
    fuzz_completion(status, output, args.runs, artifacts)


def seal_evidence(job: Job) -> None:
    hashes = {}
    for path in sorted(job.evidence.rglob("*")):
        job.checkpoint()
        if path.is_dir() and not path.is_symlink():
            continue
        data = bounded_bytes(path, 512 * 1024 * 1024)
        hashes[str(path.relative_to(job.evidence))] = hashlib.sha256(data).hexdigest()
        with path.open("rb") as retained:
            os.fsync(retained.fileno())
    source = read_json(job.evidence / "source.json")
    if hashes.get("source.tar") != source["archive_sha256"]:
        raise Incomplete("retained source archive changed")
    for name in ("simulation.json", "fuzz.json"):
        if (job.evidence / name).exists():
            if hashes.get("executable") != read_json(job.evidence / name)["executable_sha256"]:
                raise Incomplete("retained executable changed")
    # result.json is published last and is deliberately not covered by this manifest.
    hashes.pop("result.json", None)
    atomic_json(job.evidence / "evidence.json", hashes)


def positive(value: str) -> int:
    number = int(value)
    if not 0 < number <= 1_000_000:
        raise argparse.ArgumentTypeError("expected integer in 1..1000000")
    return number


def cancel(signum: int, _frame: FrameType | None) -> None:
    global _pending_signal
    if _terminal_decided:
        return
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(name, signal.SIG_IGN)
    # Register/retire children at safe checkpoints, never raise inside Popen or cleanup.
    _pending_signal = signum


def main() -> int:
    global _terminal_decided
    _terminal_decided = False
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("simulation", "fuzz"))
    parser.add_argument(
        "--output", type=Path, required=True, help="new absolute evidence directory"
    )
    parser.add_argument("--timeout", type=positive, default=3600)
    parser.add_argument("--seed", type=int, action="append")
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument("--cases", type=positive, default=1000)
    workload.add_argument("--smoke", action="store_true", help="32 histories, 32 steps, one shard")
    workload.add_argument(
        "--duration",
        type=positive,
        help="simulation seconds per seed/shard; finish between complete useful histories",
    )
    parser.add_argument("--steps", type=positive, default=32)
    parser.add_argument("--shards", type=positive, default=2)
    parser.add_argument(
        "--replay", type=Path, help="exact simulation trace, not a regenerated seed"
    )
    parser.add_argument("--executable", type=Path, help="trusted original simulation replay binary")
    parser.add_argument("--fuzz-target", choices=tuple(FUZZ_TARGETS), default="inspect_receipt")
    parser.add_argument(
        "--corpus", type=Path, action="append", help="explicit read-only input corpus"
    )
    parser.add_argument("--runs", type=positive, default=10000)
    args = parser.parse_args()
    if args.smoke:
        if args.mode != "simulation" or args.replay:
            parser.error("simulation smoke does not accept replay")
        args.cases, args.steps, args.shards = 32, 32, 1
    if not args.output.is_absolute() or args.output.parent.resolve() != args.output.parent:
        parser.error("output requires an absolute path without symlink components")
    if args.output == ROOT or ROOT in args.output.parents:
        parser.error("retain job output outside the source checkout")
    if args.executable and not args.replay:
        parser.error("an existing executable is only accepted for explicit replay")
    if args.duration and (args.mode != "simulation" or args.replay or len(args.seed or []) != 1):
        parser.error("duration requires simulation, one seed and no replay")
    if args.duration and args.duration + 10 >= args.timeout:
        parser.error("duration requires more than ten seconds of outer watchdog grace")
    if args.mode == "fuzz" and (not args.corpus or args.replay or args.executable):
        parser.error("fuzz requires --corpus and does not accept simulation replay options")
    bits = 64 if args.mode == "simulation" else 32
    if not args.replay and (not args.seed or any(not 0 < seed < 2**bits for seed in args.seed)):
        parser.error(f"select explicit nonzero u{bits} --seed values")
    if args.seed and len(set(args.seed)) != len(args.seed):
        parser.error("duplicate seeds")
    if args.mode == "fuzz" and len(args.seed) != 1:
        parser.error("fuzz requires one seed")
    if not (
        args.cases <= 10000 and 8 <= args.steps <= 32 and 1 <= args.shards <= min(128, args.cases)
    ):
        parser.error("simulation requires <=10000 cases, 8..32 steps and 1..128 nonempty shards")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    print(f"evidence: {args.output}", flush=True)
    result: dict[str, object] = {
        "status": "RUNNING",
        "started": time.time(),
        "cwd": str(ROOT),
        "arguments": {k: str(v) for k, v in vars(args).items()},
    }
    atomic_json(args.output / "result.json", result)
    job = Job(args.output, args.timeout)
    code = 2
    try:
        revision, compiler, cargo = job.run(
            [["git", "rev-parse", "HEAD"], ["rustc", "-vV"], ["cargo", "-V"]]
        )
        source = source_snapshot(job, retain=True)
        atomic_json(
            args.output / "source.json",
            {
                "revision": revision.strip(),
                "source_sha256": source,
                "rustc": compiler,
                "cargo": cargo,
                "archive_sha256": hashlib.sha256(
                    bounded_bytes(args.output / "source.tar", SOURCE_LIMIT * 2)
                ).hexdigest(),
            },
        )
        try:
            if args.mode == "simulation":
                simulation(job, args, source)
            else:
                fuzz(job, args, source)
        finally:
            job.phase = "retention"
            if source_snapshot(job, retain=False) != source:
                raise Incomplete("source changed during build/execution")
            seal_evidence(job)
        job.checkpoint()
        result["status"], code = "COMPLETED", 0
    except Finding as error:
        result.update(status="FINDING", error=str(error))
        code = 1
    except Cancelled as error:
        result.update(status="CANCELLED", error=str(error))
        code = 130
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, Incomplete) as error:
        result.update(status="INCOMPLETE", error=str(error))
    finally:
        _terminal_decided = True
        try:
            check_cancellation()
        except Cancelled as error:
            if result["status"] == "INCOMPLETE":
                result["cancellation_requested"] = str(error)
            else:
                result.update(status="CANCELLED", error=str(error))
                code = 130
        result.update(finished=time.time(), exit_status=code, command_seconds=job.timings)
        # A failed terminal write leaves RUNNING, never an invented pass.
        atomic_json(args.output / "result.json", result)
    print(f"{result['status']}: {args.output}", flush=True)
    return code


if __name__ == "__main__":
    for selected_signal in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(selected_signal, cancel)
    try:
        sys.exit(main())
    except (OSError, ValueError, Incomplete, Cancelled) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        sys.exit(2)
