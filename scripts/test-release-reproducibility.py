#!/usr/bin/env python3
"""Compare one strict Kapsel release assembly with one independent assembly."""

from __future__ import annotations

import argparse
import os
import pathlib
import stat
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "assemble-release-artifact.py"
ARCHIVE_BYTES_MAX = 32 * 1024 * 1024
SIDECARS = [
    (".sha256", "checksum", 1024),
    (".spdx.json", "SBOM", 2 * 1024 * 1024),
    (".SHA256SUMS", "digest manifest", 1024),
]


def assemble(output: pathlib.Path) -> pathlib.Path:
    result = subprocess.run(
        [
            "python3",
            str(ASSEMBLER),
            "--output-directory",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    return pathlib.Path(result.stdout.strip())


def require_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"release evidence is not one regular file: {path}")
        if metadata.st_size > maximum:
            raise RuntimeError(f"release evidence exceeds its byte bound: {path}")
        return source.read(maximum + 1)


def compare(reference: pathlib.Path, candidate: pathlib.Path) -> None:
    if reference.name != candidate.name:
        raise RuntimeError("isolated release archive names are not identical")
    if require_regular(reference, ARCHIVE_BYTES_MAX) != require_regular(
        candidate, ARCHIVE_BYTES_MAX
    ):
        raise RuntimeError("isolated release archives are not byte-for-byte identical")
    for suffix, label, maximum in SIDECARS:
        reference_sidecar = reference.with_name(reference.name + suffix)
        candidate_sidecar = candidate.with_name(candidate.name + suffix)
        if require_regular(reference_sidecar, maximum) != require_regular(
            candidate_sidecar, maximum
        ):
            raise RuntimeError(f"isolated release {label} files are not identical")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-archive", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    reference = pathlib.Path(os.path.abspath(arguments.reference_archive))
    with tempfile.TemporaryDirectory(prefix="kapsel-reproducibility-b-") as temporary:
        candidate = assemble(pathlib.Path(temporary))
        compare(reference, candidate)
    print("Kapsel release reproducibility: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
