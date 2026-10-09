#!/usr/bin/env python3
"""Count physical assurance-source ranges without credit for product relocation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "a009071896cf394062d31159ff1e3c5783430efa"
SOURCE_SUFFIXES = {".rs", ".py", ".sh", ".sql"}
# General build/release implementations remain tooling, not removable assurance.
SUPPORT_FILES = {
    "examples/mcp_bridge_fixture.py",
    "tools/dev/assurance_census.py",
    "tools/dev/robustness_process_fixture.py",
    "tools/dev/run_robustness.py",
    "tools/dev/run-nightly-soak.sh",
    "tools/release/background_caller_fixture.py",
    "tools/release/caller_custody_exercise.py",
    "tools/release/operator_example_exercise.py",
    "tools/release/trivy_fixture.py",
    "src/gateway/demo_control.rs",
    "crates/kapsel-daemon/src/server/harness.rs",
    "crates/kapsel-daemon/src/server/linux_tests.rs",
    "src/gateway/receiver_recovery_tests.rs",
    "src/gateway/receiver_recovery_tests/receiver.rs",
    "src/gateway/git/exploration.rs",
}
LITERAL = re.compile(r"""(?:b|c)?"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\\n])' """.strip(), re.DOTALL)
RAW_STRING = re.compile(r'(?:b|c)?r(\#*)"')
TEST_GATE = re.compile(r"\btest\b|feature\s*=\s*\"(?:test|demo)-harness\"")


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, timeout=60)


def mask_rust(source: str) -> str:
    """Hide literals/comments, retaining offsets, newlines and Rust delimiters."""
    masked = list(source)
    position = 0
    while position < len(source):
        end = position
        if source.startswith("//", position):
            newline = source.find("\n", position)
            end = len(source) if newline < 0 else newline
        elif source.startswith("/*", position):
            depth = 1
            end = position + 2
            while depth and end < len(source):
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("unterminated Rust comment")
        elif raw := RAW_STRING.match(source, position):
            terminator = '"' + raw[1]
            close = source.find(terminator, raw.end())
            if close < 0:
                raise ValueError("unterminated Rust raw string")
            end = close + len(terminator)
        elif literal := LITERAL.match(source, position):
            end = literal.end()
        if end > position:
            masked[position:end] = ["\n" if char == "\n" else " " for char in source[position:end]]
            position = end
        else:
            position += 1
    return "".join(masked)


def closing(masked: str, start: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[masked[start]]]
    for position in range(start + 1, len(masked)):
        char = masked[position]
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if char != stack.pop():
                raise ValueError("unbalanced Rust delimiters")
            if not stack:
                return position + 1
    raise ValueError("unterminated Rust delimiters")


def gated_ranges(source: str) -> list[list[int]]:
    """Conservative item/statement ranges; mixed physical lines count once."""
    masked = mask_rust(source)
    lines: set[int] = set()
    for match in re.finditer(r"#\s*\[\s*cfg\s*\(", masked):
        attribute_end = closing(masked, masked.index("[", match.start()))
        gate = source[match.start() : attribute_end]
        # any(not(linux), test, ...) also ships outside Linux: it stays product.
        if not TEST_GATE.search(gate) or re.search(r"\b(?:not|any)\s*\(", gate):
            continue
        position = attribute_end
        angles = 0
        while position < len(masked):
            char = masked[position]
            if char == "#":
                position = closing(masked, masked.index("[", position))
                continue
            if char in "([":
                position = closing(masked, position)
                continue
            if char == "{":
                position = closing(masked, position)
                break
            if char == "<":
                angles += 1
            elif char == ">" and angles:
                angles -= 1
            if char == ";" or (char == "," and not angles):
                position += 1
                break
            # A cfg-gated argument ends before its enclosing parenthesis.
            if char == ")":
                break
            position += 1
        first = source.count("\n", 0, match.start()) + 1
        last = source.count("\n", 0, max(match.start(), position - 1)) + 1
        lines.update(range(first, last + 1))
    ranges: list[list[int]] = []
    for line in sorted(lines):
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1][1] = line
        else:
            ranges.append([line, line])
    return ranges


def whole_support(path: str) -> bool:
    parts = Path(path).parts
    return (
        path in SUPPORT_FILES
        or "tests" in parts
        or path.startswith("fuzz/")
        or Path(path).name.startswith("test_")
        or Path(path).stem.endswith("_tests")
    )


class FileRanges(TypedDict):
    path: str
    sha256: str
    lines: int
    assurance_ranges: list[list[int]]
    remainder: str


class Snapshot(TypedDict):
    revision: str
    totals: dict[str, int]
    files: list[FileRanges]


def census(revision: str) -> Snapshot:
    if revision == "WORKTREE":
        # Include untracked additions; ignored build/generated files never enter.
        paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    else:
        revision = git("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
        paths = git("ls-tree", "-r", "--name-only", "-z", revision)
    records: list[FileRanges] = []
    totals = {"assurance": 0, "product": 0, "tooling": 0}
    for path in sorted(set(paths.decode().split("\0")) - {""}):
        if Path(path).suffix not in SOURCE_SUFFIXES:
            continue
        if revision == "WORKTREE":
            file = ROOT / path
            if not file.exists():
                continue
            data = file.read_bytes()
        else:
            data = git("show", f"{revision}:{path}")
        source = data.decode("utf-8")
        count = len(source.splitlines())
        if whole_support(path):
            ranges = [[1, count]] if count else []
        else:
            try:
                ranges = gated_ranges(source) if path.endswith(".rs") else []
            except ValueError as error:
                raise ValueError(f"{revision}:{path}: {error}") from error
        assurance = sum(last - first + 1 for first, last in ranges)
        remainder = "product" if path.endswith(".rs") else "tooling"
        totals["assurance"] += assurance
        totals[remainder] += count - assurance
        records.append(
            {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "lines": count,
                "assurance_ranges": ranges,
                "remainder": remainder,
            }
        )
    return {"revision": revision, "totals": totals, "files": records}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", default=BASELINE)
    parser.add_argument("--after", default="WORKTREE")
    arguments = parser.parse_args()
    before = census(arguments.before)
    after = census(arguments.after)
    # Read totals from the report rather than infer savings from changed files.
    before_totals = before["totals"]
    after_totals = after["totals"]
    product_charge = max(0, after_totals["product"] - before_totals["product"])
    charged_after = after_totals["assurance"] + product_charge
    print(
        json.dumps(
            {
                "schema": 1,
                "classifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "before": before,
                "after": after,
                "net_added_product_charge": product_charge,
                "charged_after": charged_after,
                "net_reduction_lines": before_totals["assurance"] - charged_after,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
