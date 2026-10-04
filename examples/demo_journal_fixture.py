"""Freeze the old demo harness's disposable finalized-row fixture."""

import hashlib
import sqlite3
import sys


def main() -> None:
    with sqlite3.connect(sys.argv[1]) as connection:
        connection.execute("CREATE TABLE kubernetes_image_operations(state, receipt_digest)")
        frozen_result = ("finalized", hashlib.sha256(b"receipt").hexdigest())
        connection.execute("INSERT INTO kubernetes_image_operations VALUES (?, ?)", frozen_result)


if __name__ == "__main__":
    main()
