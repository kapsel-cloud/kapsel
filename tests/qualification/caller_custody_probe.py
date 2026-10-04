"""Check the packaged journey's private inputs and executable custody as the caller."""

import os

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
        assert not os.access(path, os.W_OK)
    assert not os.path.exists("/var/run/docker.sock")

    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise AssertionError("caller became root")


if __name__ == "__main__":
    main()
