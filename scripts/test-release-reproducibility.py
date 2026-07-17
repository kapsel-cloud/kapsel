#!/usr/bin/env python3
"""Verify two isolated Kapsel release assemblies produce identical bytes."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "assemble-release-artifact.py"


def assemble(output: pathlib.Path) -> pathlib.Path:
    result = subprocess.run(
        [
            "python3",
            str(ASSEMBLER),
            "--output-directory",
            str(output),
            "--allow-dirty",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    return pathlib.Path(result.stdout.strip())


def main() -> int:
    with (
        tempfile.TemporaryDirectory(prefix="kapsel-reproducibility-a-") as first_temporary,
        tempfile.TemporaryDirectory(prefix="kapsel-reproducibility-b-") as second_temporary,
    ):
        first = assemble(pathlib.Path(first_temporary))
        second = assemble(pathlib.Path(second_temporary))
        if first.read_bytes() != second.read_bytes():
            raise RuntimeError("isolated release archives are not byte-for-byte identical")
        first_checksum = first.with_name(first.name + ".sha256")
        second_checksum = second.with_name(second.name + ".sha256")
        if first_checksum.read_bytes() != second_checksum.read_bytes():
            raise RuntimeError("isolated release checksum files are not identical")
    print("Kapsel release reproducibility: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
