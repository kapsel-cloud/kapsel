#!/usr/bin/env python3
"""Check repository source for private material and unsupported public claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ROOT_FILES = {
    "AGENTS.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
    "SECURITY.md",
    "rust-toolchain.toml",
}
ROOT_PREFIXES = (
    ".cargo/",
    ".github/",
    ".githooks/",
    "crates/",
    "fuzz/",
    "docs/",
    "examples/",
    "scripts/",
    "tools/",
    "xtask/",
    "src/",
    "tests/",
    "vectors/",
)
PRIVATE_PATHS = (
    re.compile(rb"/Users/[^\s\x00]+"),
    re.compile(rb"/private/var/[^\s\x00]+"),
)
CREDENTIAL_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
)
AFFIRMATIVE_OVERCLAIMS = (
    re.compile(r"\bis production[- ]ready\b", re.IGNORECASE),
    re.compile(r"\bguarantees? exactly[- ]once\b", re.IGNORECASE),
    re.compile(r"\bprovides? (?:a )?production[- ]support SLA\b", re.IGNORECASE),
    re.compile(r"\bsupports? (?:all|every) Kubernetes(?: distribution)?\b", re.IGNORECASE),
    re.compile(r"\bestablishes? native[- ]host performance\b", re.IGNORECASE),
)
PRIVATE_ARTIFACT_SUFFIXES = (".key", ".kubeconfig", ".pem", ".receipt", ".seed", ".sqlite3")
PATTERN_FIXTURE_FILES = {
    "tools/checks/check_source_privacy.py",
    "tools/checks/test_source_checks.py",
}
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024


def tracked_paths(root: Path) -> list[str]:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        text=True,
    ).splitlines()
    selected = [path for path in paths if path in ROOT_FILES or path.startswith(ROOT_PREFIXES)]
    return sorted(selected)


def read_bounded_regular_file(path: Path, relative: str) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"unsupported source file at {relative}") from error

    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise RuntimeError(f"unsupported source file at {relative}")
        if status.st_size > MAX_SOURCE_FILE_BYTES:
            raise RuntimeError(f"source file exceeds size limit at {relative}")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, MAX_SOURCE_FILE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_FILE_BYTES:
                raise RuntimeError(f"source file exceeds size limit at {relative}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def fail(category: str, path: str, line: int | None = None) -> None:
    location = path if line is None else f"{path}:{line}"
    raise RuntimeError(f"{category} finding at {location}")


def validate(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        if relative.endswith(PRIVATE_ARTIFACT_SUFFIXES):
            fail("private artifact", relative)

        data = read_bounded_regular_file(path, relative)
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")

        if relative not in PATTERN_FIXTURE_FILES:
            for pattern in PRIVATE_PATHS:
                if pattern.search(data):
                    fail("absolute private path", relative)
            for pattern in CREDENTIAL_PATTERNS:
                if pattern.search(data):
                    fail("credential material", relative)

        if path.suffix == ".md":
            text = data.decode("utf-8")
            for line_number, line in enumerate(text.splitlines(), start=1):
                for pattern in AFFIRMATIVE_OVERCLAIMS:
                    if pattern.search(line):
                        fail("unsupported claim", relative, line_number)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    paths = tracked_paths(root)
    digest = validate(root, paths)
    result = {
        "schema_version": 1,
        "checked_file_count": len(paths),
        "checked_source_sha256": digest,
        "checks": [
            "no-absolute-private-path",
            "no-credential-material",
            "no-private-artifact",
            "no-production-sla-overclaim",
        ],
        "status": "passed",
    }
    if arguments.output is not None:
        arguments.output.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        )
    else:
        print(f"source privacy checks passed: {len(paths)} files")


if __name__ == "__main__":
    main()
