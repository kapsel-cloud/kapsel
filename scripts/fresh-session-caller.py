#!/usr/bin/env python3
"""One initial selection, then read-first recovery from a caller-owned reference."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

BRIDGE = "/usr/bin/kapsel-service-mcp"
PROTOCOL = "2025-11-25"
IDENTITY = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")


def exchange(name, arguments):
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "kapsel-fresh-session-example", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    ]
    try:
        result = subprocess.run(
            [BRIDGE],
            input=b"".join(json.dumps(m).encode() + b"\n" for m in messages),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=True,
        )
        if len(result.stdout) > 100_000:
            raise ValueError("oversized MCP response")
        lines = result.stdout.splitlines()
        if len(lines) != 2:
            raise ValueError("unexpected MCP response count")
        init, reply = (json.loads(line) for line in lines)
        if (
            init.get("id") != 1
            or init.get("result", {}).get("protocolVersion") != PROTOCOL
            or reply.get("id") != 2
        ):
            raise ValueError("unexpected MCP handshake")
        text = reply["result"]["content"][0]["text"]
        body = json.loads(text)
        service = body["service"]
        if body.get("operation_id") != arguments.get("operation_id") or not isinstance(
            service, dict
        ):
            raise ValueError("wrong operation response")
        if service.get("version") != 1 and service.get("status") != "ERROR":
            raise ValueError("unexpected service version")
        return service
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError):
        return {"status": "ERROR", "error_class": "exchange_uncertain"}


def reference(path, service, operation_id=None):
    """Create before submission; never overwrite a reference after an uncertain response."""
    if not service or len(service) > 128 or not IDENTITY.fullmatch(service):
        raise ValueError("invalid operator-provisioned service label")
    parent = Path(path).parent
    directory = parent.stat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.getuid()
        or directory.st_mode & 0o077
    ):
        raise ValueError("reference directory must be private and caller-owned")
    if operation_id is not None:
        if not IDENTITY.fullmatch(operation_id):
            raise ValueError("invalid operation ID")
        data = {"version": 1, "service": service, "operation_id": operation_id}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(data, output, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            # Keep a partially written reference visible for manual inspection; never replace it.
            raise
        return data
    info = Path(path).lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise ValueError("reference must be a private caller-owned regular file")
    if info.st_size > 512:
        raise ValueError("oversized reference")
    data = json.loads(Path(path).read_text())
    if (
        data.get("version") != 1
        or data.get("service") != service
        or not isinstance(data.get("operation_id"), str)
        or not IDENTITY.fullmatch(data["operation_id"])
    ):
        raise ValueError("reference does not match this service/history label")
    return data


def status(operation_id):
    return exchange("kapsel.get_status", {"operation_id": operation_id})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True, help="operator-provisioned history label")
    parser.add_argument("--reference", required=True, help="private caller-owned reference file")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="pin a new ID, then explicitly select it once")
    start.add_argument("operation_id")
    approved = commands.add_parser("approved", help="read one page of approved handles")
    approved.add_argument("after", nargs="?", default=None)
    commands.add_parser("read", help="read stored status only; never advances work")
    commands.add_parser("resume", help="explicit same-ID selection after reading")
    commands.add_parser("receipt", help="retrieve original receipt bytes (hex) and digest")
    args = parser.parse_args()
    try:
        if args.command == "approved":
            if args.after is not None and not IDENTITY.fullmatch(args.after):
                raise ValueError("invalid catalog cursor")
            result = exchange("kapsel.list_approved_actions", {"after": args.after})
            print(json.dumps({"service": result}, separators=(",", ":")))
            return 4 if result.get("status") == "ERROR" else 0
        saved = reference(
            args.reference, args.service, args.operation_id if args.command == "start" else None
        )
        operation_id = saved["operation_id"]
        if args.command == "start":
            # Exclusive creation above is the durable intent marker. Never rerun start for this file.
            result = exchange("kapsel.submit", {"operation_id": operation_id})
        elif args.command == "read":
            result = status(operation_id)
        elif args.command == "receipt":
            result = exchange("kapsel.get_receipt", {"operation_id": operation_id})
            if result.get("status") == "READY":
                receipt_hex = result["receipt_hex"]
                if (
                    not isinstance(receipt_hex, str)
                    or len(receipt_hex) > 80_000
                    or len(receipt_hex) % 2
                    or receipt_hex.lower() != receipt_hex
                ):
                    raise ValueError("invalid receipt encoding")
                raw = bytes.fromhex(receipt_hex)
                if hashlib.sha256(raw).hexdigest() != result["receipt_sha256"]:
                    raise ValueError("receipt digest mismatch")
        else:
            current = status(operation_id)
            execution = current.get("execution", {})
            if (
                current.get("status") != "IN_PROGRESS"
                or execution.get("disposition") != "resume_required"
                or execution.get("action_owner") != "caller"
                or execution.get("next_action") != "select_same_id"
            ):
                result = {"status": "NO_SELECTION", "current": current}
            else:
                result = exchange("kapsel.submit", {"operation_id": operation_id})
        print(json.dumps({"reference": saved, "service": result}, separators=(",", ":")))
        if result.get("status") in ("ERROR", "UNKNOWN", "NO_SELECTION"):
            return 4
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"caller: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
