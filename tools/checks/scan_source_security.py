#!/usr/bin/env python3
"""Scan committed source with RustSec and Trivy, retaining scanner database identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict


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


def scanner_text(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("scanner returned an invalid text field")
    return value


def scanner_count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeError("scanner returned an invalid count")
    return value


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, capture_output=True, check=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        run(["git", "ls-tree", "-r", "--name-only", commit], repository)
        .stdout.decode()
        .splitlines()
    )
    digest = hashlib.sha256()
    for path in sorted(paths):
        contents = run(["git", "show", f"{commit}:{path}"], repository).stdout
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(contents)
        digest.update(b"\0")
    return digest.hexdigest()


def cargo_audit_result(root: Path) -> tuple[AuditResult, AuditTool]:
    run(["cargo-audit", "audit", "--json"], root)
    database = Path.home() / ".cargo/advisory-db"
    commit = run(["git", "rev-parse", "HEAD"], database).stdout.decode().strip()
    database_sha256 = git_tree_sha256(database, commit)
    completed = run(["cargo-audit", "audit", "--json", "--no-fetch"], root)
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
    version = run(["cargo-audit", "--version"], root).stdout.decode().strip()
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
    run(["trivy", "filesystem", "--download-db-only", str(root)], root)
    version_document = json.loads(run(["trivy", "version", "--format", "json"], root).stdout)
    database = trivy_database()
    database_sha256 = sha256(database)
    with tempfile.TemporaryDirectory(prefix="kapsel-source-trivy-") as temporary:
        temporary_root = Path(temporary)
        archive = temporary_root / "source.tar"
        run(["git", "archive", "--format=tar", "--output", str(archive), commit], root)
        checkout = temporary_root / "source"
        checkout.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(checkout, filter="data")
        completed = run(
            [
                "trivy",
                "filesystem",
                "--scanners",
                "vuln,secret",
                "--format",
                "json",
                "--skip-db-update",
                str(checkout),
            ],
            root,
        )
        document = json.loads(completed.stdout)

    vulnerabilities: dict[str, int] = {}
    findings: list[VulnerabilityFinding] = []
    secrets = 0
    for result in document.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = scanner_text(vulnerability.get("Severity", "UNKNOWN"))
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
        secrets += len(result.get("Secrets") or [])

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
    if subprocess.run(["git", "diff", "--quiet", "--exit-code"], cwd=root).returncode != 0:
        raise RuntimeError("security scan requires a clean source tree")
    if (
        subprocess.run(["git", "diff", "--cached", "--quiet", "--exit-code"], cwd=root).returncode
        != 0
    ):
        raise RuntimeError("security scan requires a clean index")

    commit = run(["git", "rev-parse", "HEAD"], root).stdout.decode().strip()
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
