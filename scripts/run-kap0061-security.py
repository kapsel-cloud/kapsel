#!/usr/bin/env python3
"""Run the closed KAP-0061 dependency and clean-tree security scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


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


def cargo_audit_result(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    completed = run(["cargo-audit", "audit", "--json"], root)
    document = json.loads(completed.stdout)
    vulnerability_count = document["vulnerabilities"]["count"]
    warning_counts = {
        name: len(items) for name, items in sorted(document.get("warnings", {}).items())
    }
    if vulnerability_count != 0 or any(warning_counts.values()):
        raise RuntimeError("cargo-audit reported a vulnerability or warning")
    version = run(["cargo-audit", "--version"], root).stdout.decode().strip()
    database = Path.home() / ".cargo/advisory-db"
    commit = run(["git", "rev-parse", "HEAD"], database).stdout.decode().strip()
    timestamp = run(["git", "log", "-1", "--format=%cI"], database).stdout.decode().strip()
    result = {
        "vulnerabilities": vulnerability_count,
        "warning_counts": warning_counts,
    }
    tool = {
        "version": version,
        "database_commit": commit,
        "database_utc": timestamp,
    }
    return result, tool


def trivy_result(root: Path, commit: str) -> tuple[dict[str, object], dict[str, object]]:
    version_document = json.loads(run(["trivy", "version", "--format", "json"], root).stdout)
    with tempfile.TemporaryDirectory(prefix="kap0061-trivy-") as temporary:
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
                str(checkout),
            ],
            root,
        )
        document = json.loads(completed.stdout)
    vulnerabilities: dict[str, int] = {}
    secrets = 0
    for result in document.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = vulnerability.get("Severity", "UNKNOWN")
            vulnerabilities[severity] = vulnerabilities.get(severity, 0) + 1
        secrets += len(result.get("Secrets") or [])
    if vulnerabilities.get("HIGH", 0) or vulnerabilities.get("CRITICAL", 0) or secrets:
        raise RuntimeError("Trivy reported a rejected vulnerability or secret")
    database = trivy_database()
    vulnerability_db = version_document["VulnerabilityDB"]
    result = {
        "vulnerability_counts": dict(sorted(vulnerabilities.items())),
        "secrets": secrets,
    }
    tool = {
        "version": version_document["Version"],
        "database_version": vulnerability_db["Version"],
        "database_utc": vulnerability_db["UpdatedAt"],
        "database_sha256": sha256(database),
    }
    return result, tool


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if subprocess.run(["git", "diff", "--quiet", "--exit-code"], cwd=root).returncode != 0:
        raise RuntimeError("security scan requires a clean source tree")
    if subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--exit-code"], cwd=root
    ).returncode != 0:
        raise RuntimeError("security scan requires a clean index")
    commit = run(["git", "rev-parse", "HEAD"], root).stdout.decode().strip()
    cargo_audit, audit_tool = cargo_audit_result(root)
    trivy, trivy_tool = trivy_result(root, commit)
    result = {
        "schema_version": 1,
        "commit": commit,
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
