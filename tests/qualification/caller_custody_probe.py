"""Check the packaged journey's private inputs and executable custody as the caller."""

import os
import stat

PRIVATE_INPUTS = (
    "/etc/kapsel/operator.json",
    "/etc/kapsel/kubeconfig.yaml",
    "/etc/kapsel/receipt.seed",
    "/var/lib/kapsel/journal.sqlite3",
    "/operator/approval.seed",
    "/inputs/kubeconfig.json",
)
EXECUTABLES = (
    "/usr/bin/kapsel-service-client",
    "/usr/bin/kapsel-service-mcp",
    "/usr/libexec/kapsel/kapseld",
)


def check_executable(path: str) -> None:
    # An absent file also passes a negative writability test. Establish custody positively.
    executable = os.stat(path)
    parent = os.stat(os.path.dirname(path))
    assert stat.S_ISREG(executable.st_mode), "installed executable is not a regular file"
    assert executable.st_uid == 0, "installed executable is not root-owned"
    assert stat.S_ISDIR(parent.st_mode), "executable parent is not a directory"
    assert parent.st_uid == 0, "executable directory is not root-owned"
    assert not os.access(os.path.dirname(path), os.W_OK), "caller can replace executable"
    assert not os.access(path, os.W_OK), "caller can modify executable"
    assert os.access(path, os.X_OK), "installed executable cannot run as caller"


def main() -> None:
    for path in PRIVATE_INPUTS:
        try:
            with open(path, "rb"):
                pass
        except PermissionError:
            pass
        else:
            raise AssertionError("private input readable: " + path)

    for path in EXECUTABLES:
        check_executable(path)
    assert not os.path.exists("/var/run/docker.sock")

    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise AssertionError("caller became root")


if __name__ == "__main__":
    main()
