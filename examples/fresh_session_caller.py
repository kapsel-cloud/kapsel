#!/usr/bin/env python3
"""One initial selection, then read-first recovery from a caller-owned reference."""

import argparse
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal, NotRequired, TypedDict, cast


class ExecutionResponse(TypedDict, total=False):
    disposition: str
    action_owner: str
    next_action: str


class ServiceResponse(TypedDict):
    status: str
    version: NotRequired[int]
    error_class: NotRequired[str]
    execution: NotRequired[ExecutionResponse]
    receipt_hex: NotRequired[str]
    receipt_sha256: NotRequired[str]


class NoSelectionResponse(TypedDict):
    status: Literal["NO_SELECTION"]
    current: ServiceResponse


class OperationReference(TypedDict):
    version: int
    service: str
    operation_id: str


def service_response(value: object) -> ServiceResponse:
    """Check types for fields this caller uses. Preserve other protocol fields."""
    if not isinstance(value, dict) or not isinstance(value.get("status"), str):
        raise ValueError("invalid service response")
    if "version" in value and type(value["version"]) is not int:
        raise ValueError("invalid service version")
    for field in ("error_class", "receipt_hex", "receipt_sha256"):
        if field in value and not isinstance(value[field], str):
            raise ValueError("invalid service response field")
    if "execution" in value:
        execution = value["execution"]
        if not isinstance(execution, dict):
            raise ValueError("invalid execution response")
        for field in ("disposition", "action_owner", "next_action"):
            if field in execution and not isinstance(execution[field], str):
                raise ValueError("invalid execution response field")
    return cast(ServiceResponse, value)


BRIDGE = "/usr/bin/kapsel-service-mcp"
PROTOCOL = "2025-11-25"
IDENTITY = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
MCP_RESPONSE_LIMIT = 100_000
EXCHANGE_DEADLINE_SECONDS = 8.0
REFERENCE_LIMIT = 512


def exchange_pipes(process: subprocess.Popen[bytes], input_bytes: bytes, deadline: float) -> bytes:
    output = bytearray()
    assert process.stdin is not None and process.stdout is not None
    os.set_blocking(process.stdin.fileno(), False)
    os.set_blocking(process.stdout.fileno(), False)
    input_offset = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP exchange timed out")
        input_streams = [] if process.stdin.closed else [process.stdin]
        readable, writable, _ = select.select([process.stdout], input_streams, [], remaining)
        if writable:
            input_offset += os.write(process.stdin.fileno(), input_bytes[input_offset:])
            if input_offset == len(input_bytes):
                process.stdin.close()
        if not readable:
            continue
        chunk = os.read(process.stdout.fileno(), min(8192, MCP_RESPONSE_LIMIT + 1 - len(output)))
        if not chunk:
            break
        if len(output) + len(chunk) > MCP_RESPONSE_LIMIT:
            raise ValueError("oversized MCP response")
        output.extend(chunk)
    return bytes(output)


def run_bridge(input_bytes: bytes) -> bytes:
    process = subprocess.Popen(
        [BRIDGE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + EXCHANGE_DEADLINE_SECONDS
    try:
        stdout = exchange_pipes(process, input_bytes, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP exchange timed out")
        process.wait(timeout=remaining)
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, [BRIDGE])
        return stdout
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


def exchange(name: str, arguments: dict[str, str | None]) -> ServiceResponse:
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
        output = run_bridge(b"".join(json.dumps(m).encode() + b"\n" for m in messages))
        lines = output.splitlines()
        if len(lines) != 2:
            raise ValueError("unexpected MCP response count")
        init, reply = (json.loads(line) for line in lines)
        if not isinstance(init, dict) or not isinstance(reply, dict):
            raise ValueError("unexpected MCP response shape")
        initialization = init.get("result")
        if (
            init.get("id") != 1
            or not isinstance(initialization, dict)
            or initialization.get("protocolVersion") != PROTOCOL
            or reply.get("id") != 2
        ):
            raise ValueError("unexpected MCP handshake")

        text = reply["result"]["content"][0]["text"]
        body = json.loads(text)
        service = service_response(body["service"])
        if body.get("operation_id") != arguments.get("operation_id") or not isinstance(
            service, dict
        ):
            raise ValueError("wrong operation response")
        if service.get("version") != 1 and service.get("status") != "ERROR":
            raise ValueError("unexpected service version")
        return service
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
    ):
        return {"status": "ERROR", "error_class": "exchange_uncertain"}


def reference(path: str, service: str, operation_id: str | None = None) -> OperationReference:
    """Create or read the caller's reference without replacing an existing file."""
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
        data: OperationReference = {"version": 1, "service": service, "operation_id": operation_id}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        # A failed write leaves the partial file in place. A retry must not replace the pinned ID.
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
        return data

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("reference must be a private caller-owned regular file")
        if info.st_size > REFERENCE_LIMIT:
            raise ValueError("oversized reference")

        raw = os.read(descriptor, REFERENCE_LIMIT + 1)
        after_read = os.fstat(descriptor)
        if len(raw) > REFERENCE_LIMIT or len(raw) != after_read.st_size:
            raise ValueError("reference changed while reading")
        if (
            after_read.st_mode != info.st_mode
            or after_read.st_uid != info.st_uid
            or after_read.st_nlink != info.st_nlink
            or after_read.st_size != info.st_size
        ):
            raise ValueError("reference changed while reading")
        decoded = json.loads(raw.decode())
    finally:
        os.close(descriptor)
    if (
        not isinstance(decoded, dict)
        or type(decoded.get("version")) is not int
        or decoded.get("version") != 1
        or decoded.get("service") != service
        or not isinstance(decoded.get("operation_id"), str)
        or not IDENTITY.fullmatch(decoded["operation_id"])
    ):
        raise ValueError("reference does not match this service/history label")
    return cast(OperationReference, decoded)


def status(operation_id: str) -> ServiceResponse:
    return exchange("kapsel.get_status", {"operation_id": operation_id})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True, help="operator-provisioned history label")
    parser.add_argument("--reference", required=True, help="private caller-owned reference file")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="pin a new ID, then explicitly select it once")
    start.add_argument("operation_id")
    approved = commands.add_parser("approved", help="read one page of approved handles")
    approved.add_argument("after", nargs="?", default=None)
    history = commands.add_parser("history", help="read one page of retained operation history")
    history.add_argument("after", nargs="?", default=None)
    commands.add_parser("read", help="read stored status only; never advances work")
    commands.add_parser("resume", help="explicit same-ID selection after reading")
    commands.add_parser("receipt", help="retrieve original receipt bytes (hex) and digest")
    args = parser.parse_args()
    result: ServiceResponse | NoSelectionResponse
    try:
        if args.command in ("approved", "history"):
            if args.after is not None and not IDENTITY.fullmatch(args.after):
                raise ValueError("invalid listing cursor")
            tool = (
                "kapsel.list_approved_actions"
                if args.command == "approved"
                else "kapsel.list_operation_history"
            )
            result = exchange(tool, {"after": args.after})
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
                receipt_hex = result.get("receipt_hex")
                if (
                    not isinstance(receipt_hex, str)
                    or len(receipt_hex) > 80_000
                    or len(receipt_hex) % 2
                    or receipt_hex.lower() != receipt_hex
                ):
                    raise ValueError("invalid receipt encoding")
                raw = bytes.fromhex(receipt_hex)
                if hashlib.sha256(raw).hexdigest() != result.get("receipt_sha256"):
                    raise ValueError("receipt digest mismatch")
        else:
            current = status(operation_id)
            execution = current.get("execution", {})
            requires_caller_selection = (
                current.get("status") == "IN_PROGRESS"
                and execution.get("disposition") == "resume_required"
                and execution.get("action_owner") == "caller"
                and execution.get("next_action") == "select_same_id"
            )
            if not requires_caller_selection:
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
