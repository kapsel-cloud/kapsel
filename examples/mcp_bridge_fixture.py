#!/usr/bin/env python3
"""Adversarial pipe peer for actual caller byte/deadline and child-retirement checks."""

import os
import sys
import time
from pathlib import Path


def main() -> None:
    Path(os.environ["FIXTURE_PID"]).write_text(str(os.getpid()))
    sys.stdin.buffer.read()
    mode = os.environ["FIXTURE_MODE"]
    if mode == "oversized":
        sys.stdout.buffer.write(b"x" * 100_001)
    elif mode == "partial":
        sys.stdout.buffer.write(b'{"id":1}\n')
    elif mode == "eof_then_wait":
        os.close(1)
        os.close(2)
        time.sleep(30)
    else:
        raise ValueError("unknown pipe fixture")


if __name__ == "__main__":
    main()
