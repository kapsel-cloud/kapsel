#!/usr/bin/env python3
"""Prove the KAP-0052 one-way package graph and ordinary-package deletion boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout


def main() -> None:
    metadata = json.loads(
        run(
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        )
    )
    packages = {package["name"]: package for package in metadata["packages"]}
    assert "kapsel" in packages
    assert "kapsel-sandbox" in packages
    root_dependencies = {dependency["name"] for dependency in packages["kapsel"]["dependencies"]}
    sandbox_dependencies = {
        dependency["name"] for dependency in packages["kapsel-sandbox"]["dependencies"]
    }
    assert "kapsel-sandbox" not in root_dependencies
    assert "kapsel" in sandbox_dependencies

    root_tree = run("cargo", "tree", "--locked", "--offline", "-p", "kapsel", "-e", "normal")
    assert "kapsel-sandbox" not in root_tree

    with tempfile.TemporaryDirectory(prefix="kapsel-deletion-proof-") as temporary:
        checkout = Path(temporary) / "kapsel"
        shutil.copytree(
            ROOT,
            checkout,
            ignore=shutil.ignore_patterns(".git", "target", "dist", ".DS_Store"),
        )
        shutil.rmtree(checkout / "crates" / "kapsel-sandbox")
        manifest = checkout / "Cargo.toml"
        manifest_text = manifest.read_text(encoding="utf-8")
        member = 'members = ["crates/kapsel-dev", "crates/kapsel-sandbox"]'
        assert member in manifest_text
        manifest.write_text(
            manifest_text.replace(member, 'members = ["crates/kapsel-dev"]'),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(ROOT / "target" / "deletion-proof")
        run(
            "cargo",
            "check",
            "--locked",
            "--offline",
            "-p",
            "kapsel",
            "--all-targets",
            cwd=checkout,
            env=environment,
        )

    print("sandbox package boundary: ok")


if __name__ == "__main__":
    main()
