#!/usr/bin/env python3
"""Compare a strict Kapsel service artifact with one independent strict assembly."""

from __future__ import annotations

import argparse
import os
import pathlib
import stat
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts/assemble-kapsel-service-artifact.py"
LIMITS = [("", 32 * 1024 * 1024), (".sha256", 1024), (".SHA256SUMS", 1024)]


def assemble(output: pathlib.Path) -> pathlib.Path:
    result = subprocess.run(
        ["python3", str(ASSEMBLER), "--output-directory", str(output)],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    return pathlib.Path(result.stdout.strip())


def read_regular(path: pathlib.Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
            raise RuntimeError(f"Kapsel service artifact evidence is not bounded and regular: {path}")
        return source.read(maximum + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-archive", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    reference = pathlib.Path(os.path.abspath(arguments.reference_archive))
    with tempfile.TemporaryDirectory(prefix="kapsel-service-repro-b-") as temporary:
        candidate = assemble(pathlib.Path(temporary))
        if candidate.name != reference.name:
            raise RuntimeError("Kapsel service artifact archive names differ")
        for suffix, maximum in LIMITS:
            if read_regular(reference.with_name(reference.name + suffix), maximum) != read_regular(
                candidate.with_name(candidate.name + suffix), maximum
            ):
                raise RuntimeError(f"Kapsel service artifact {suffix or 'archive'} bytes differ")
    print("Kapsel service artifact reproducibility: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
