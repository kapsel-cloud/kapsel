#!/usr/local/bin/python3 -I
"""Record real receiver hook input and inject the selected acknowledgement-loss seam."""

import json
import os
import signal
import sys
import time
from pathlib import Path


def main() -> None:
    hook_name = Path(sys.argv[0]).name
    # Installed hooks live in receiver.git/hooks. Read controls from receiver.git's sibling directory.
    control = Path(__file__).resolve().parents[2] / "fixture-control"
    case = json.loads((control / "hook-settings.json").read_text())["case"]
    with (control / hook_name).open("a") as output:
        output.write(sys.stdin.read())

    if hook_name == case:
        os.kill(os.getppid(), signal.SIGKILL)
    elif case == "service-loss" and hook_name == "post-receive":
        (control / "ready").touch()
        deadline = time.monotonic() + 20
        while not (control / "release").exists():
            assert time.monotonic() < deadline
            time.sleep(0.1)
        (control / "finished").touch()


if __name__ == "__main__":
    main()
