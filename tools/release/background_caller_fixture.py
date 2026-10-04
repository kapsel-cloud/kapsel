"""Leave a caller-owned descendant holding an inherited readiness descriptor."""

import os
import time


def main() -> None:
    child_pid = os.fork()
    if child_pid == 0:
        os.close(1)
        os.close(2)
        time.sleep(60)
    else:
        print(child_pid, flush=True)
        os._exit(0)


if __name__ == "__main__":
    main()
