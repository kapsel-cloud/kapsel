"""Retire caller-owned descendants inside the fixture's private PID namespace."""

import os
import pathlib
import signal
import time


def main() -> None:
    # kill(-1) enforces kernel UID checks and excludes this observer. Never run as root.
    assert os.getuid() == os.geteuid() == 61001 and os.getpid() != 1
    observer_status = pathlib.Path("/proc/self/status").read_bytes()
    capability_line = next(
        line for line in observer_status.splitlines() if line.startswith(b"CapEff:")
    )
    assert int(capability_line.split()[1], 16) == 0

    deadline = time.monotonic() + 3
    previously_quiet = False
    while True:
        try:
            os.kill(-1, signal.SIGKILL)
        except ProcessLookupError:
            pass

        processes = list(pathlib.Path("/proc").glob("[0-9]*"))
        assert len(processes) <= 256, "unexpected process population"
        active_callers = 0
        for process_path in processes:
            if int(process_path.name) == os.getpid():
                continue
            try:
                with (process_path / "status").open("rb") as stream:
                    status = stream.read(4097)
            except FileNotFoundError:
                continue
            assert len(status) <= 4096

            fields = dict(line.split(b":", 1) for line in status.splitlines() if b":" in line)
            owned_by_caller = fields[b"Uid"].split()[0] == b"61001"
            still_running = fields[b"State"].split()[0] not in (b"Z", b"X")
            if owned_by_caller and still_running:
                active_callers += 1

        quiet = active_callers == 0
        if quiet and previously_quiet:
            break
        previously_quiet = quiet
        assert time.monotonic() < deadline, "caller retirement incomplete"
        time.sleep(0.01)

    print("CALLERS_RETIRED")


if __name__ == "__main__":
    main()
