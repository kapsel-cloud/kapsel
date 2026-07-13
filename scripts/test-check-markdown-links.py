#!/usr/bin/env python3
"""Regression tests for the repository-local Markdown link checker."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

CHECKER = Path(__file__).with_name("check-markdown-links.py")
SPEC = importlib.util.spec_from_file_location("check_markdown_links", CHECKER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Markdown link checker")
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def run(root: Path) -> tuple[int, str]:
    """Run the checker against one temporary tracked fixture."""

    checker.ROOT = root.resolve()
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = checker.main()
    return status, stdout.getvalue() + stderr.getvalue()


def write(path: Path, content: str) -> None:
    """Write one UTF-8 fixture file."""

    path.write_text(content, encoding="utf-8")


def main() -> int:
    """Exercise supported links, anchors, fences, and failures."""

    with tempfile.TemporaryDirectory() as raw_root:
        root = Path(raw_root).resolve()
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        write(
            root / "target.md",
            """# Foo
# Foo-1
# Foo

Setext Heading
--------------

<a class="fixture" id="explicit-anchor"></a>

# Function (call)
""",
        )
        write(root / "with(paren).md", "# Balanced\n")
        write(root / "space name.md", "# Encoded\n")
        write(
            root / "source.md",
            """[first](target.md#foo)
[second](target.md#foo-1)
[collision](target.md#foo-2)
[setext][setext-ref]
[explicit](target.md#explicit-anchor)
[balanced](with(paren).md#balanced "title")
[encoded](<space%20name.md#encoded>)

[setext-ref]: target.md#setext-heading

````markdown
```markdown
[ignored](missing.md)
```
````
""",
        )
        subprocess.run(
            ["git", "add", "source.md", "target.md", "with(paren).md", "space name.md"],
            cwd=root,
            check=True,
        )

        status, output = run(root)
        assert status == 0, output
        assert checker.anchors(root / "target.md") >= {
            "foo",
            "foo-1",
            "foo-2",
            "setext-heading",
            "explicit-anchor",
            "function-call",
        }

        write(root / "source.md", "[broken][ref]\n\n[ref]: missing.md\n")
        status, output = run(root)
        assert status == 1 and "missing path missing.md" in output, output

        write(root / "source.md", "[broken][undefined]\n")
        status, output = run(root)
        assert status == 1 and "missing reference definition [undefined]" in output, output

        write(root / "source.md", "[escape](../outside.md)\n")
        status, output = run(root)
        assert status == 1 and "path escapes repository" in output, output

    print("Markdown link checker regressions: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
