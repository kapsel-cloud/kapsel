"""Send the caller's framed request and exit without reading its acknowledgement."""

import os
import socket
import sys


def main() -> None:
    framed_request = bytes.fromhex(sys.argv[1])
    client = socket.socket(socket.AF_UNIX)
    client.connect("/run/kapsel/kapseld.sock")
    client.sendall(framed_request)
    os._exit(0)


if __name__ == "__main__":
    main()
