#!/usr/bin/env python3
"""Select the fixed deterministic owners; never assemble or qualify a product."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from resolve_git import resolve_git

AREAS = ("authority", "core", "service", "tools", "release", "docs")
PACKAGES = {
    "authority": "kapsel-authority",
    "core": "kapsel",
    "service": "kapsel-daemon",
    "tools": "xtask",
}
PYTHON_TESTS = {
    "tools": (
        "tools/dev/test_checks.py",
        "tools/dev/test_format.py",
        "tools/dev/test_dev_tools.py",
        "tools/dev/test_robustness.py",
        "tools/dev/test_assurance_census.py",
        "tools/checks/test_source_checks.py",
        "tools/checks/test_check_markdown_links.py",
    ),
    "release": (
        "tests/qualification/test_storage_enospc.py",
        "tests/qualification/test_git_artifact.py",
        "tests/qualification/test_git_service.py",
        "tests/qualification/test_kind_agent_action_exercise.py",
        "tests/qualification/test_caller_custody_probe.py",
        "tools/release/test_qualification.py",
        "tools/release/test_verify_artifact.py",
        "tools/release/test_assemble_artifact.py",
        "tools/release/test_scan_sbom.py",
    ),
}


@dataclass(frozen=True)
class Step:
    owner: str
    command: tuple[str, ...]
    # Only explicitly selected libtest groups/targets require a nonempty listing.
    tests: bool = False
    # Temporary CI aliases select phases from this same owner mapping.
    lane: str = "static"
    executable_environment: str | None = None


def cargo_tests(owner: str, *selection: str) -> Step:
    lane = "doc" if "--doc" in selection else "rust"
    return Step(owner, ("cargo", "test", "--locked", *selection), tests=True, lane=lane)


def python_test(path: str, *arguments: str) -> Step:
    return Step(path, ("python3", path, *arguments))


def plan(mode: str, area: str | None, linux: bool) -> list[Step]:
    areas = AREAS if area is None else (area,)
    steps: list[Step] = []
    if mode == "check":
        if areas == ("docs",):
            steps.append(
                Step(
                    "prose format",
                    (os.environ["PRETTIER"], "--check", "--ignore-path", ".gitignore", "**/*.md"),
                )
            )
        else:
            steps.append(Step("source format", ("sh", "scripts/fmt.sh", "--check")))
        steps.extend(
            (
                python_test("tools/checks/check_markdown_links.py"),
                python_test("tools/checks/check_source_privacy.py"),
            )
        )
        if any(item in areas for item in ("tools", "release", "service")):
            steps.append(
                Step(
                    "type checker prerequisite",
                    ("sh", "-c", ". ./tools/dev/dev-tools.sh; check_type_checker"),
                )
            )
            steps.append(Step("Python lint", (os.environ["RUFF"], "check", "--no-cache", ".")))
            for platform in ("Linux", "Darwin"):
                steps.append(
                    Step(
                        "Python types",
                        (
                            os.environ["PYRIGHT"],
                            "--project",
                            "pyrightconfig.json",
                            "--pythonplatform",
                            platform,
                            "--warnings",
                        ),
                    )
                )
        if "tools" in areas:
            steps.append(Step("shell lint", ("sh", "tools/checks/check-shell.sh")))
        packages = [PACKAGES[item] for item in areas if item in PACKAGES]
        if "release" in areas and "kapsel-daemon" not in packages:
            packages.append("kapsel-daemon")
        if packages:
            selection = (
                ("--workspace",)
                if area is None
                else tuple(value for package in packages for value in ("-p", package))
            )
            steps.append(
                Step(
                    "Rust lint",
                    (
                        "cargo",
                        "clippy",
                        "--locked",
                        *selection,
                        "--all-targets",
                        "--all-features",
                        "--",
                        "-D",
                        "warnings",
                    ),
                    lane="rust",
                )
            )
            steps.append(
                Step(
                    "import policy",
                    (
                        "cargo",
                        "run",
                        "--locked",
                        "--quiet",
                        "-p",
                        "xtask",
                        "--bin",
                        "check-rust-imports",
                    ),
                )
            )
            steps.append(Step("Rust width", ("sh", "tools/checks/check-rust-width.sh")))
        if "core" in areas or "authority" in areas:
            steps.append(
                Step(
                    "fuzz lint",
                    (
                        "cargo",
                        "clippy",
                        "--locked",
                        "--manifest-path",
                        "fuzz/Cargo.toml",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ),
                    lane="rust",
                )
            )
        if area is None:
            steps.append(
                Step(
                    "rustdoc", ("cargo", "doc", "--locked", "--workspace", "--no-deps"), lane="rust"
                )
            )

    if area is None:
        steps.append(cargo_tests("default workspace", "--workspace", "--lib", "--bins", "--tests"))
    else:
        for item in areas:
            if item in PACKAGES:
                # --tests includes library tests when present, and also supports bin-only xtask.
                steps.append(cargo_tests(item, "-p", PACKAGES[item], "--bins", "--tests"))
    for item in areas:
        for path in PYTHON_TESTS.get(item, ()):
            # Running this file preserves its explicit offline defaultTest classes.
            # unittest discovery would also select CallerContainerTests (Docker).
            steps.append(python_test(path))
    if "release" in areas:
        steps.append(
            python_test(
                "tools/release/test_artifact.py",
                "--archive",
                "/tmp/unused.tar.gz",
                "SourceCorrespondenceTests",
            )
        )
        if area is not None:
            steps.append(
                cargo_tests(
                    "installed asset expectations",
                    "-p",
                    "kapsel-daemon",
                    "--test",
                    "install_assets",
                )
            )
    if "authority" in areas or "core" in areas:
        # W1 owns splitting/fixing reviewed regression replay; retain today's shared owner.
        steps.append(
            cargo_tests(
                "authenticated corpus", "--manifest-path", "fuzz/Cargo.toml", "--test", "corpus"
            )
        )
        steps.append(
            Step(
                "maintained seed bytes",
                (
                    "cargo",
                    "run",
                    "--locked",
                    "--manifest-path",
                    "fuzz/Cargo.toml",
                    "--example",
                    "seed_corpus",
                    "--",
                    "--check",
                ),
                lane="rust",
            )
        )
    if "core" in areas:
        steps.append(
            cargo_tests(
                "local Git 2.55.0 adapters",
                "-p",
                "kapsel",
                "--lib",
                "gateway::git::tests::real_git_",
                "--",
                "--ignored",
                "--test-threads=1",
            )
        )
    if "service" in areas and linux:
        steps.append(
            Step(
                "inspection executable",
                (
                    "cargo",
                    "build",
                    "--locked",
                    "-p",
                    "kapsel",
                    "--bin",
                    "kapsel",
                    "--message-format=json",
                ),
                lane="rust",
                executable_environment="KAPSEL_TEST_INSPECT",
            )
        )
        for target in ("linux_process", "service_mcp"):
            steps.append(
                cargo_tests(
                    f"Linux source {target}",
                    "-p",
                    "kapsel-daemon",
                    "--features",
                    "test-harness",
                    "--test",
                    target,
                )
            )
        steps.append(
            cargo_tests(
                "feature-enabled client failures",
                "-p",
                "kapsel-daemon",
                "--features",
                "test-harness",
                "--test",
                "command_interface",
                "client_failures::",
            )
        )
        steps.append(
            Step(
                "caller bridge executable",
                (
                    "cargo",
                    "build",
                    "--locked",
                    "-p",
                    "kapsel-daemon",
                    "--features",
                    "test-harness",
                    "--bin",
                    "kapsel-service-mcp",
                    "--message-format=json",
                ),
                lane="rust",
                executable_environment="KAPSEL_TEST_BRIDGE",
            )
        )
    if "service" in areas:
        steps.append(
            Step(
                "examples/test_fresh_session_caller.py",
                ("python3", "examples/test_fresh_session_caller.py"),
                lane="rust",
            )
        )
    if mode == "test" and area == "docs":
        steps.extend(
            (
                python_test("tools/checks/check_markdown_links.py"),
                python_test("tools/checks/check_source_privacy.py"),
            )
        )
    if mode == "check":
        if area is None:
            steps.append(cargo_tests("workspace doctests", "--workspace", "--doc"))
        elif area in ("authority", "core", "service"):
            steps.append(cargo_tests("owner doctests", "-p", PACKAGES[area], "--doc"))
        steps.append(Step("diff whitespace", ("git", "diff", "--check")))
    return steps


def execute(
    command: tuple[str, ...],
    root: Path,
    environment: dict[str, str],
    timeout: int,
    capture: bool = False,
) -> str:
    with subprocess.Popen(
        command,
        cwd=root,
        env=environment,
        start_new_session=True,
        stdout=subprocess.PIPE if capture else None,
        text=True,
    ) as child:
        try:
            output, _ = child.communicate(timeout=timeout)
        finally:
            # Cargo/tool children belong to this invocation, including on timeout.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if child.returncode:
            raise RuntimeError(f"nonzero exit {child.returncode}: {shlex.join(command)}")
    return output or ""


def run_steps(steps: list[Step], root: Path, environment: dict[str, str], timeout: int) -> None:
    if not steps:
        raise RuntimeError("empty owner selection")
    started = time.monotonic()
    completed = 0
    try:
        for step in steps:
            print(f"==> {step.owner}: {shlex.join(step.command)}", flush=True)
            if step.tests and "--doc" not in step.command:
                listing = (
                    (*step.command, "--list", "--format", "terse")
                    if "--" in step.command
                    else (*step.command, "--", "--list", "--format", "terse")
                )
                output = execute(listing, root, environment, timeout, capture=True)
                selected = sum(line.endswith(": test") for line in output.splitlines())
                if "--ignored" not in step.command:
                    # libtest lists ignored tests by default. An ignored-only target cannot
                    # establish runnable coverage unless this command explicitly selects it.
                    ignored_output = execute(
                        (*listing, "--ignored"), root, environment, timeout, capture=True
                    )
                    selected -= sum(line.endswith(": test") for line in ignored_output.splitlines())
                if selected <= 0:
                    raise RuntimeError(f"empty runnable test selection: {step.owner}")
            output = execute(
                step.command,
                root,
                environment,
                timeout,
                capture=step.executable_environment is not None,
            )
            if step.executable_environment is not None:
                artifacts = [json.loads(line) for line in output.splitlines()]
                executables = [
                    record["executable"]
                    for record in artifacts
                    if isinstance(record, dict)
                    and record.get("reason") == "compiler-artifact"
                    and isinstance(record.get("executable"), str)
                    and record["executable"]
                ]
                if len(executables) != 1:
                    raise RuntimeError(f"Cargo did not identify one executable: {step.owner}")
                environment[step.executable_environment] = executables[0]
            completed += 1
    finally:
        result = "PASSED" if completed == len(steps) else "INCOMPLETE"
        print(
            f"==> {result}: {completed}/{len(steps)} owner commands; {time.monotonic() - started:.1f}s elapsed (Cargo build time included)",
            flush=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("test", "check", "ci-static", "ci-rust", "ci-doc"))
    parser.add_argument("area", nargs="?", choices=AREAS)
    arguments = parser.parse_args()
    if arguments.mode == "test" and arguments.area is None:
        parser.error("test requires an area")
    legacy_lane = arguments.mode.removeprefix("ci-") if arguments.mode.startswith("ci-") else None
    if legacy_lane is not None and arguments.area is not None:
        parser.error("CI compatibility lanes do not accept an area")
    root = Path.cwd()
    environment = dict(os.environ)
    environment["RUSTDOCFLAGS"] = "-D warnings"
    # Runtime paths come from Cargo artifact messages, including configured target directories.
    environment.pop("KAPSEL_TEST_INSPECT", None)
    environment.pop("KAPSEL_TEST_BRIDGE", None)
    if arguments.area in (None, "core") and legacy_lane not in ("static", "doc"):
        try:
            git = resolve_git(environment.get("KAPSEL_TEST_GIT"))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise RuntimeError(
                f"Local Git prerequisite: {error}. Install Git 2.55.0 explicitly and set absolute KAPSEL_TEST_GIT; check never installs tools."
            ) from error
        environment["KAPSEL_TEST_GIT"] = str(git)
        print(f"Prerequisite: Git 2.55.0 at {git}", flush=True)
    if (
        arguments.area in (None, "service")
        and sys.platform != "linux"
        and legacy_lane not in ("static", "doc")
    ):
        print(
            "Linux PR CI must execute test-harness linux_process, service_mcp, command_interface client cases and the real fresh-session MCP bridge witness; this host cannot supply them.",
            flush=True,
        )
        environment.pop("KAPSEL_TEST_BRIDGE", None)
    steps = plan(
        "check" if legacy_lane else arguments.mode, arguments.area, sys.platform == "linux"
    )
    if legacy_lane is not None:
        steps = [step for step in steps if step.lane == legacy_lane]
    print(
        f"Selected areas: {arguments.area or ', '.join(AREAS)}; {len(steps)} owner commands. No external qualification.",
        flush=True,
    )
    run_steps(steps, root, environment, 3600)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"check incomplete: {error}", file=sys.stderr)
        raise SystemExit(1) from error
