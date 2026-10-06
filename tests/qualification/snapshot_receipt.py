"""Accept a caller-owned regular receipt file of at most 64 KiB.

Read one extra byte to detect growth beyond the bound. Refuse a symlink at the final
path component. Parent directories are not checked here.
"""

import os
import stat
import sys


def main() -> None:
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        assert metadata.st_uid == os.getuid() and metadata.st_size <= 65536

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            receipt = stream.read(65537)
        assert len(receipt) <= 65536
        sys.stdout.buffer.write(receipt)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
