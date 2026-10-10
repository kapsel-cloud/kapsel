#!/usr/bin/env python3
"""Scan a release SBOM with pinned Trivy and a database no older than 24 hours."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from typing import Any

TRIVY_VERSION = "0.72.0"
DATABASE_MAX_AGE = datetime.timedelta(hours=24)
SBOM_BYTES_MAX = 2 * 1024 * 1024
TRIVY_JSON_BYTES_MAX = 8 * 1024 * 1024
METADATA_BYTES_MAX = 64 * 1024
OUTPUT_BYTES_MAX = 1024 * 1024
VERSION_TIMEOUT_SECONDS = 10
REFRESH_TIMEOUT_SECONDS = 120
SCAN_TIMEOUT_SECONDS = 120
VALID_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


class ScannerSubprocessError(RuntimeError):
    """A subprocess failed without exposing tool-controlled output in diagnostics."""


class BoundedPipe:
    def __init__(self, pipe: Any, name: str, maximum: int) -> None:
        self.pipe = pipe
        self.name = name
        self.maximum = maximum
        self.chunks: list[bytes] = []
        self.size = 0

    def append(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size > self.maximum:
            raise ScannerSubprocessError(f"Trivy {self.name} exceeded its byte bound")
        self.chunks.append(chunk)

    def value(self) -> bytes:
        return b"".join(self.chunks)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_bounded_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise RuntimeError("release SBOM is not a bounded regular file")
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise RuntimeError("release SBOM exceeded its byte bound")
    return value


def write_exclusive(path: pathlib.Path, value: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def run_bounded_capture(
    command: list[str], *, timeout_seconds: int, output_bytes_maximum: int
) -> bytes:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    stdout = BoundedPipe(process.stdout, "stdout", output_bytes_maximum)
    stderr = BoundedPipe(process.stderr, "stderr", output_bytes_maximum)
    deadline = time.monotonic() + timeout_seconds
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Trivy command timed out")
                for key, _events in selector.select(remaining):
                    pipe = key.data
                    chunk = pipe.pipe.read(8192)
                    if chunk:
                        pipe.append(chunk)
                    else:
                        selector.unregister(pipe.pipe)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Trivy command timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Trivy command timed out") from error
        if return_code != 0:
            raise ScannerSubprocessError("Trivy command failed")
        return stdout.value()
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


def run_json_metadata(command: list[str], *, timeout_seconds: int) -> Mapping[str, Any]:
    raw = run_bounded_capture(
        command,
        timeout_seconds=timeout_seconds,
        output_bytes_maximum=METADATA_BYTES_MAX,
    )
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Trivy metadata has an invalid shape")
    return value


def run_quiet(command: list[str], *, timeout_seconds: int) -> None:
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Trivy command timed out") from error


def require_optional_string(record: Mapping[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise RuntimeError("Trivy report has an invalid vulnerability field")
    return value


def require_string(record: Mapping[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str):
        raise RuntimeError("Trivy report has an invalid vulnerability field")
    return value


def validated_findings(report: Any) -> list[dict[str, str | None]]:
    if not isinstance(report, dict):
        raise RuntimeError("Trivy report has an invalid shape")
    results = report.get("Results", [])
    if not isinstance(results, list):
        raise RuntimeError("Trivy report has an invalid results shape")

    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise RuntimeError("Trivy report has an invalid result entry")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise RuntimeError("Trivy report has an invalid vulnerabilities shape")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise RuntimeError("Trivy report has an invalid vulnerability entry")
            severity = require_string(vulnerability, "Severity")
            if severity not in VALID_SEVERITIES:
                raise RuntimeError("Trivy report has an unsupported vulnerability severity")
            findings.append(
                {
                    "id": require_string(vulnerability, "VulnerabilityID"),
                    "package": require_optional_string(vulnerability, "PkgName"),
                    "installed_version": require_optional_string(vulnerability, "InstalledVersion"),
                    "fixed_version": require_optional_string(vulnerability, "FixedVersion"),
                    "severity": severity,
                }
            )
    findings.sort(
        key=lambda finding: (
            str(finding["severity"]),
            str(finding["id"]),
            str(finding["package"]),
        )
    )
    return findings


def parse_utc(value: str) -> datetime.datetime:
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("Trivy database time has no timezone")
    return parsed.astimezone(datetime.timezone.utc)


def scan(sbom: pathlib.Path, output: pathlib.Path) -> None:
    if shutil.which("trivy") is None:
        raise RuntimeError("Trivy is required for release SBOM scanning")
    tool = run_json_metadata(
        ["trivy", "--version", "--format", "json"], timeout_seconds=VERSION_TIMEOUT_SECONDS
    )
    if tool.get("Version") != TRIVY_VERSION:
        raise RuntimeError(f"release SBOM scan requires exact Trivy {TRIVY_VERSION}")
    sbom_bytes = read_bounded_regular(sbom, SBOM_BYTES_MAX)

    with tempfile.TemporaryDirectory(prefix="kapsel-release-sbom-scan-") as temporary:
        private = pathlib.Path(temporary)
        private.chmod(0o700)
        cache = private / "cache"
        snapshot = private / "candidate.spdx.json"
        snapshot.write_bytes(sbom_bytes)
        snapshot.chmod(0o600)

        run_quiet(
            [
                "trivy",
                "filesystem",
                "--cache-dir",
                str(cache),
                "--download-db-only",
                str(private),
            ],
            timeout_seconds=REFRESH_TIMEOUT_SECONDS,
        )
        version = run_json_metadata(
            ["trivy", "--cache-dir", str(cache), "--version", "--format", "json"],
            timeout_seconds=VERSION_TIMEOUT_SECONDS,
        )

        database = version.get("VulnerabilityDB")
        if version.get("Version") != TRIVY_VERSION:
            raise RuntimeError("Trivy identity changed after database refresh")
        if not isinstance(database, dict) or database.get("Version") != 2:
            raise RuntimeError("Trivy vulnerability database identity is unavailable")
        updated = parse_utc(str(database.get("UpdatedAt")))
        now = datetime.datetime.now(datetime.timezone.utc)
        if updated > now or now - updated > DATABASE_MAX_AGE:
            raise RuntimeError("Trivy vulnerability database is unavailable or older than 24 hours")
        database_path = cache / "db" / "trivy.db"
        if not database_path.is_file():
            raise RuntimeError("private Trivy vulnerability database file is unavailable")
        database_sha256 = sha256(database_path)

        raw = private / "trivy.json"
        run_quiet(
            [
                "trivy",
                "sbom",
                "--cache-dir",
                str(cache),
                "--scanners",
                "vuln",
                "--skip-db-update",
                "--format",
                "json",
                "--output",
                str(raw),
                str(snapshot),
            ],
            timeout_seconds=SCAN_TIMEOUT_SECONDS,
        )
        report = json.loads(read_bounded_regular(raw, TRIVY_JSON_BYTES_MAX))
        if sha256(database_path) != database_sha256:
            raise RuntimeError("Trivy vulnerability database identity changed during the scan")

        findings = validated_findings(report)

        blocked = [finding for finding in findings if finding["severity"] in {"HIGH", "CRITICAL"}]
        summary = {
            "schema": "kapsel.release-sbom-scan.v1",
            "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
            "trivy_version": version["Version"],
            "database_version": database["Version"],
            "database_updated_utc": updated.isoformat().replace("+00:00", "Z"),
            "database_sha256": database_sha256,
            "scanned_utc": now.isoformat().replace("+00:00", "Z"),
            "finding_count": len(findings),
            "findings": findings,
            "status": "failed" if blocked else "passed",
        }

    encoded = (json.dumps(summary, indent=2, separators=(",", ": ")) + "\n").encode()
    if len(encoded) > OUTPUT_BYTES_MAX:
        raise RuntimeError("release SBOM vulnerability summary exceeded its byte bound")
    write_exclusive(output, encoded)
    if blocked:
        raise RuntimeError("release SBOM has a detected HIGH or CRITICAL vulnerability")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        sbom = pathlib.Path(os.path.abspath(arguments.sbom))
        output = pathlib.Path(os.path.abspath(arguments.output))
        scan(sbom, output)
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"Kapsel release SBOM scan failed: {error}", file=sys.stderr)
        return 1
    print(arguments.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
