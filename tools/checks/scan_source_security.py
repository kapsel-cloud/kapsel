#!/usr/bin/env python3
"""Scan committed source with RustSec and Trivy, retaining scanner database identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, TypedDict, cast


class AuditResult(TypedDict):
    vulnerabilities: int
    warning_counts: dict[str, int]


class AuditTool(TypedDict):
    version: str
    database_commit: str
    database_sha256: str
    database_utc: str


class VulnerabilityFinding(TypedDict):
    vulnerability_id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str


class TrivyResult(TypedDict):
    vulnerability_counts: dict[str, int]
    findings: list[VulnerabilityFinding]
    secrets: int


class TrivyTool(TypedDict):
    version: str
    database_version: int
    database_utc: str
    database_sha256: str


@dataclass(frozen=True)
class CommandLimits:
    deadline_seconds: float
    stream_bytes: int


GIT_LIMITS = CommandLimits(deadline_seconds=60.0, stream_bytes=4 * 1024 * 1024)
SCANNER_LIMITS = CommandLimits(deadline_seconds=10 * 60.0, stream_bytes=32 * 1024 * 1024)
TRIVY_REPORT_LIMIT_BYTES = 32 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
TRIVY_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def scanner_text(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("scanner returned an invalid text field")
    return value


def scanner_count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeError("scanner returned an invalid count")
    return value


def scanner_list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise RuntimeError(f"Trivy returned an invalid {field} field")
    return value


def scanner_mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"Trivy returned an invalid {field} item")
    return value


def trivy_severity(vulnerability: dict[str, object]) -> str:
    if "Severity" not in vulnerability:
        raise RuntimeError("Trivy returned a vulnerability without severity")
    severity = scanner_text(vulnerability["Severity"])
    if severity not in TRIVY_SEVERITIES:
        raise RuntimeError("Trivy returned a noncanonical vulnerability severity")
    return severity


def _read_ready_streams(
    selector: selectors.BaseSelector,
    buffers: dict[IO[bytes], bytearray],
    limit: int,
    timeout: float,
) -> None:
    for key, _ in selector.select(timeout):
        stream = cast(IO[bytes], key.fileobj)
        chunk = os.read(stream.fileno(), READ_CHUNK_BYTES)
        if not chunk:
            selector.unregister(stream)
            stream.close()
            continue
        buffer = buffers[stream]
        if len(buffer) + len(chunk) > limit:
            raise RuntimeError("scanner command output exceeded the configured bound")
        buffer.extend(chunk)


def _bounded_completed_process(
    command: list[str],
    cwd: Path,
    limits: CommandLimits,
    *,
    check: bool,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    os.set_blocking(process.stdout.fileno(), False)
    os.set_blocking(process.stderr.fileno(), False)
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + limits.deadline_seconds
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("scanner command exceeded the configured deadline")
            _read_ready_streams(selector, buffers, limits.stream_bytes, remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("scanner command exceeded the configured deadline")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("scanner command exceeded the configured deadline") from error
        completed = subprocess.CompletedProcess(
            command,
            returncode,
            bytes(buffers[process.stdout]),
            bytes(buffers[process.stderr]),
        )
        if check and returncode != 0:
            raise RuntimeError("scanner command failed")
        return completed
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        for key in list(selector.get_map().values()):
            stream = cast(IO[bytes], key.fileobj)
            try:
                selector.unregister(stream)
            except KeyError:
                pass
            stream.close()
        selector.close()
        process.stdout.close()
        process.stderr.close()


def run_scanner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return _bounded_completed_process(command, cwd, SCANNER_LIMITS, check=True)


def run_git(
    command: list[str], cwd: Path, *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return _bounded_completed_process(command, cwd, GIT_LIMITS, check=check)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_json_file(path: Path, limit_bytes: int) -> object:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("scanner report is not a bounded regular file") from error

    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > limit_bytes:
            raise RuntimeError("scanner report is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit_bytes:
                raise RuntimeError("scanner report exceeded the configured bound")
            chunks.append(chunk)
        return json.loads(b"".join(chunks))
    finally:
        os.close(descriptor)


def trivy_database() -> Path:
    home = Path.home()
    candidates = [
        home / "Library/Caches/trivy/db/trivy.db",
        home / ".cache/trivy/db/trivy.db",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("Trivy vulnerability database file is unavailable")


def utc_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    age = datetime.now(timezone.utc) - parsed
    age_seconds = age.total_seconds()
    if age_seconds < 0 or age_seconds > 24 * 60 * 60:
        raise RuntimeError("scanner database is unavailable or older than 24 hours")
    return parsed.isoformat().replace("+00:00", "Z")


def git_tree_sha256(repository: Path, commit: str) -> str:
    paths = (
        run_git(["git", "ls-tree", "-r", "--name-only", commit], repository)
        .stdout.decode()
        .splitlines()
    )
    digest = hashlib.sha256()
    for path in sorted(paths):
        contents = run_git(["git", "show", f"{commit}:{path}"], repository).stdout
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(contents)
        digest.update(b"\0")
    return digest.hexdigest()


def cargo_audit_result(root: Path) -> tuple[AuditResult, AuditTool]:
    run_scanner(["cargo-audit", "audit", "--json"], root)
    database = Path.home() / ".cargo/advisory-db"
    commit = run_git(["git", "rev-parse", "HEAD"], database).stdout.decode().strip()
    database_sha256 = git_tree_sha256(database, commit)
    completed = run_scanner(["cargo-audit", "audit", "--json", "--no-fetch"], root)
    document = json.loads(completed.stdout)
    vulnerability_count = scanner_count(document["vulnerabilities"]["count"])
    warnings = document.get("warnings", {})
    if not isinstance(warnings, dict) or any(
        not isinstance(name, str) or not isinstance(items, list) for name, items in warnings.items()
    ):
        raise RuntimeError("cargo-audit returned invalid warnings")
    warning_counts = {name: len(items) for name, items in sorted(warnings.items())}

    if vulnerability_count != 0 or any(warning_counts.values()):
        raise RuntimeError("cargo-audit reported a vulnerability or warning")
    version = run_scanner(["cargo-audit", "--version"], root).stdout.decode().strip()
    if git_tree_sha256(database, commit) != database_sha256:
        raise RuntimeError("RustSec database identity changed during the accepted scan")

    refreshed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    result: AuditResult = {
        "vulnerabilities": vulnerability_count,
        "warning_counts": warning_counts,
    }
    tool: AuditTool = {
        "version": version,
        "database_commit": commit,
        "database_sha256": database_sha256,
        "database_utc": refreshed_at,
    }
    return result, tool


def trivy_result(root: Path, commit: str) -> tuple[TrivyResult, TrivyTool]:
    run_scanner(["trivy", "filesystem", "--download-db-only", str(root)], root)
    version_document = json.loads(
        run_scanner(["trivy", "version", "--format", "json"], root).stdout
    )
    database = trivy_database()
    database_sha256 = sha256(database)
    with tempfile.TemporaryDirectory(prefix="kapsel-source-trivy-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "source.tar"
        run_git(["git", "archive", "--format=tar", "--output", str(archive), commit], root)
        checkout = temporary_root / "source"
        checkout.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(checkout, filter="data")
        report = temporary_root / "trivy-report.json"
        run_scanner(
            [
                "trivy",
                "filesystem",
                "--scanners",
                "vuln,secret",
                "--format",
                "json",
                "--output",
                str(report),
                "--skip-db-update",
                str(checkout),
            ],
            root,
        )
        document = bounded_json_file(report, TRIVY_REPORT_LIMIT_BYTES)
    if not isinstance(document, dict):
        raise RuntimeError("Trivy returned an invalid report")

    vulnerabilities: dict[str, int] = {}
    findings: list[VulnerabilityFinding] = []
    secrets = 0
    raw_results = document.get("Results", [])
    results = scanner_list(raw_results, "Results")
    for raw_result in results:
        scan_result = scanner_mapping(raw_result, "Results")
        raw_vulnerabilities = scan_result.get("Vulnerabilities", [])
        raw_secrets = scan_result.get("Secrets", [])
        result_vulnerabilities = scanner_list(raw_vulnerabilities, "Vulnerabilities")
        result_secrets = scanner_list(raw_secrets, "Secrets")
        for raw_vulnerability in result_vulnerabilities:
            vulnerability = scanner_mapping(raw_vulnerability, "Vulnerabilities")
            severity = trivy_severity(vulnerability)
            vulnerabilities[severity] = vulnerabilities.get(severity, 0) + 1
            findings.append(
                {
                    "vulnerability_id": scanner_text(
                        vulnerability.get("VulnerabilityID", "UNKNOWN")
                    ),
                    "package": scanner_text(vulnerability.get("PkgName", "UNKNOWN")),
                    "installed_version": scanner_text(
                        vulnerability.get("InstalledVersion", "UNKNOWN")
                    ),
                    "fixed_version": scanner_text(
                        vulnerability.get("FixedVersion") or "unavailable"
                    ),
                    "severity": severity,
                }
            )
        for raw_secret in result_secrets:
            scanner_mapping(raw_secret, "Secrets")
        secrets += len(result_secrets)

    severe_vulnerabilities = vulnerabilities.get("HIGH", 0) or vulnerabilities.get("CRITICAL", 0)
    if severe_vulnerabilities or secrets:
        raise RuntimeError("Trivy reported a rejected vulnerability or secret")
    if sha256(database) != database_sha256:
        raise RuntimeError("Trivy database identity changed during the accepted scan")

    vulnerability_db = version_document["VulnerabilityDB"]
    result: TrivyResult = {
        "vulnerability_counts": dict(sorted(vulnerabilities.items())),
        "findings": sorted(
            findings,
            key=lambda finding: (
                finding["severity"],
                finding["vulnerability_id"],
                finding["package"],
                finding["installed_version"],
            ),
        ),
        "secrets": secrets,
    }
    tool: TrivyTool = {
        "version": scanner_text(version_document["Version"]),
        "database_version": scanner_count(vulnerability_db["Version"]),
        "database_utc": utc_timestamp(scanner_text(vulnerability_db["UpdatedAt"])),
        "database_sha256": database_sha256,
    }
    return result, tool


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if run_git(["git", "diff", "--quiet", "--exit-code"], root, check=False).returncode != 0:
        raise RuntimeError("security scan requires a clean source tree")
    if (
        run_git(["git", "diff", "--cached", "--quiet", "--exit-code"], root, check=False).returncode
        != 0
    ):
        raise RuntimeError("security scan requires a clean index")

    commit = run_git(["git", "rev-parse", "HEAD"], root).stdout.decode().strip()
    cargo_audit, audit_tool = cargo_audit_result(root)
    trivy, trivy_tool = trivy_result(root, commit)
    result = {
        "schema_version": 1,
        "commit": commit,
        "scanned_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cargo_lock_sha256": sha256(root / "Cargo.lock"),
        "cargo_audit": cargo_audit,
        "cargo_audit_tool": audit_tool,
        "trivy": trivy,
        "trivy_tool": trivy_tool,
        "status": "passed",
    }
    arguments.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
