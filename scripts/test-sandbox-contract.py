#!/usr/bin/env python3
"""Validate the KAP-0051 sandbox v1 contract fixtures without a service."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "docs" / "fixtures" / "sandbox-v1"
FIXTURE_NAMES = {
    "errors",
    "expiry",
    "healthy",
    "incompatible-version",
    "saturation",
    "setup-failure",
    "unavailable-image",
    "unavailable-service",
}
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
RUN_PATH = re.compile(r"/sandbox/v1/runs/([0-9a-f]{32})(?:/|\?|\Z)")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
IDEMPOTENCY_KEY = re.compile(r"[0-9a-f]{32}\Z")

ADMISSION_KEYS = [
    "api_version",
    "run_id",
    "operation_id",
    "scenario",
    "admission_disposition",
    "admitted_at",
    "expires_at",
    "last_sequence",
]
SNAPSHOT_KEYS = [
    "api_version",
    "run_id",
    "operation_id",
    "scenario",
    "execution_state",
    "receiver_result",
    "target_rejection",
    "receipt_available",
    "cleanup_state",
    "admitted_at",
    "expires_at",
    "last_sequence",
]
EVENT_RESPONSE_KEYS = ["api_version", "run_id", "events", "last_sequence", "next_after"]
EVENT_KEYS = [
    "sequence",
    "kind",
    "occurred_at",
    "execution_state",
    "receiver_result",
    "target_rejection",
    "receipt_available",
    "cleanup_state",
]
ERROR_KEYS = ["api_version", "error"]
ERROR_DETAIL_KEYS = ["code", "message", "retryable"]

SCENARIOS = {"healthy", "unavailable-image"}
EXECUTION_STATES = {"queued", "running", "not_attempted", "service_failed", "terminal"}
RESULTS = {"SUCCEEDED", "FAILED", "UNKNOWN"}
REJECTIONS = {"DEPLOYMENT_NOT_FOUND", "CONTAINER_NOT_FOUND", "INVALID_TARGET"}
CLEANUP_STATES = {"pending", "running", "succeeded", "failed"}
EVENT_KINDS = {
    "admission.accepted",
    "execution.started",
    "execution.deadline_reached",
    "execution.not_attempted",
    "execution.service_failed",
    "execution.terminal",
    "receipt.available",
    "cleanup.started",
    "cleanup.succeeded",
    "cleanup.failed",
}
ERRORS = {
    "invalid_request": (400, "The request is invalid.", False),
    "unsupported_version": (400, "The API version is unsupported.", False),
    "run_not_found": (404, "The run was not found.", False),
    "idempotency_conflict": (409, "The idempotency key names another request.", False),
    "receipt_not_available": (409, "The receipt is not available.", True),
    "run_expired": (410, "The run has expired.", False),
    "rate_limited": (429, "The anonymous request rate is limited.", True),
    "capacity_saturated": (503, "Sandbox capacity is temporarily saturated.", True),
    "service_unavailable": (503, "The sandbox service is temporarily unavailable.", True),
}
EXPECTED_RECEIPT_SIZE = 1112
EXPECTED_RECEIPT_SHA256 = "905fb779d9062e2bad945a6129516d02ffe18a4d0f81e5b42baab0d25c7a2f19"
FORBIDDEN_BODY_KEYS = {
    "callback",
    "credential",
    "fault_control",
    "journal",
    "kubeconfig",
    "lease_id",
    "log",
    "manifest",
    "node_id",
    "pod_id",
    "private_key",
    "runner_id",
    "secret",
    "signing_seed",
    "store_key",
    "trust",
}


def require(condition: bool, message: str) -> None:
    """Raise one fixture-focused assertion when a contract invariant fails."""
    if not condition:
        raise AssertionError(message)


def exact_keys(value: dict[str, object], expected: list[str], where: str) -> None:
    """Require exact key membership and canonical fixture ordering."""
    require(list(value) == expected, f"{where}: keys {list(value)!r} != {expected!r}")


def walk_keys(value: object) -> set[str]:
    """Collect nested JSON object keys."""
    if isinstance(value, dict):
        return set(value).union(*(walk_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(walk_keys(item) for item in value))
    return set()


def parse_time(value: object, where: str) -> datetime:
    """Parse the exact public whole-second UTC form."""
    require(isinstance(value, str) and TIME.fullmatch(value) is not None, f"{where}: bad time")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_outcome(value: dict[str, object], where: str) -> None:
    """Check that sandbox projection does not blur Kapsel outcome classes."""
    state = value["execution_state"]
    result = value["receiver_result"]
    rejection = value["target_rejection"]
    require(state in EXECUTION_STATES, f"{where}: bad execution_state")
    require(value["cleanup_state"] in CLEANUP_STATES, f"{where}: bad cleanup_state")
    require(isinstance(value["receipt_available"], bool), f"{where}: bad receipt_available")
    if state in {"queued", "running", "service_failed"}:
        require(result is None and rejection is None, f"{where}: premature outcome")
        if state == "service_failed":
            require(value["receipt_available"] is False,
                    f"{where}: service failure has receipt")
    elif state == "not_attempted":
        require(result is None and rejection in REJECTIONS, f"{where}: bad rejection outcome")
        require(value["receipt_available"] is False, f"{where}: rejected run has receipt")
    else:
        require(result in RESULTS and rejection is None, f"{where}: bad receiver outcome")
    if value["receipt_available"]:
        require(state == "terminal", f"{where}: receipt without terminal receiver outcome")


def validate_identity(value: dict[str, object], where: str) -> None:
    """Check public identities and retained timestamps."""
    run_id = value["run_id"]
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None, f"{where}: bad run_id")
    require(value["operation_id"] == f"sandbox-{run_id}", f"{where}: bad operation_id")
    require(value["scenario"] in SCENARIOS, f"{where}: bad scenario")
    admitted = parse_time(value["admitted_at"], f"{where}.admitted_at")
    expires = parse_time(value["expires_at"], f"{where}.expires_at")
    require(expires - admitted == timedelta(hours=24), f"{where}: retention is not 24 hours")
    require(isinstance(value["last_sequence"], int) and 1 <= value["last_sequence"] <= 64,
            f"{where}: bad last_sequence")


def validate_error(response: dict[str, object], where: str) -> None:
    """Check stable bounded error status and bytes."""
    body = response["body"]
    require(isinstance(body, dict), f"{where}: error body is not an object")
    exact_keys(body, ERROR_KEYS, f"{where}.body")
    require(body["api_version"] == "v1", f"{where}: bad error api_version")
    detail = body["error"]
    require(isinstance(detail, dict), f"{where}: error detail is not an object")
    exact_keys(detail, ERROR_DETAIL_KEYS, f"{where}.body.error")
    code = detail["code"]
    require(code in ERRORS, f"{where}: unknown error code")
    expected_status, expected_message, expected_retryable = ERRORS[code]
    require(response["status"] == expected_status, f"{where}: wrong error status")
    require(detail["message"] == expected_message, f"{where}: wrong error message")
    require(detail["retryable"] is expected_retryable, f"{where}: wrong retryable value")
    headers = response["headers"]
    if expected_retryable:
        retry_after = headers.get("retry-after")
        require(isinstance(retry_after, str) and retry_after.isdecimal(),
                f"{where}: missing Retry-After")
        require(1 <= int(retry_after) <= 300, f"{where}: Retry-After out of range")


def validate_event_history(events: list[dict[str, object]], where: str) -> None:
    """Check cross-event ordering, cardinality, and immutable outcome projection."""
    if not events:
        return
    require(events[0]["sequence"] == 1 and events[0]["kind"] == "admission.accepted",
            f"{where}: full history does not start with admission")
    execution_state = "queued"
    cleanup_state = "pending"
    receiver_result: object = None
    target_rejection: object = None
    receipt_available = False
    seen_kinds: set[str] = set()
    terminal_kinds = {
        "execution.not_attempted",
        "execution.service_failed",
        "execution.terminal",
    }
    for index, event in enumerate(events):
        kind = event["kind"]
        require(kind not in seen_kinds, f"{where}: duplicate public event kind {kind}")
        seen_kinds.add(kind)
        if index == 0:
            pass
        elif kind == "execution.started":
            require(execution_state == "queued", f"{where}: execution started out of order")
            execution_state = "running"
        elif kind == "execution.deadline_reached":
            require(execution_state == "running", f"{where}: deadline event out of order")
        elif kind in terminal_kinds:
            require(execution_state == "running", f"{where}: terminal event out of order")
            execution_state = event["execution_state"]
            receiver_result = event["receiver_result"]
            target_rejection = event["target_rejection"]
        elif kind == "receipt.available":
            require(execution_state == "terminal" and not receipt_available,
                    f"{where}: receipt event out of order")
            receipt_available = True
        elif kind == "cleanup.started":
            require(execution_state in {"terminal", "not_attempted", "service_failed"},
                    f"{where}: cleanup started before terminal projection")
            require(execution_state != "terminal" or receipt_available,
                    f"{where}: receiver cleanup started before receipt")
            require(cleanup_state == "pending", f"{where}: cleanup started twice")
            cleanup_state = "running"
        elif kind == "cleanup.failed":
            require(cleanup_state == "running", f"{where}: cleanup failed out of order")
            cleanup_state = "failed"
        elif kind == "cleanup.succeeded":
            require(cleanup_state in {"running", "failed"},
                    f"{where}: cleanup succeeded out of order")
            cleanup_state = "succeeded"
        else:
            require(False, f"{where}: unexpected event kind {kind}")
        require(event["execution_state"] == execution_state,
                f"{where}: event execution projection regressed")
        require(event["receiver_result"] == receiver_result,
                f"{where}: event receiver result changed outside terminal event")
        require(event["target_rejection"] == target_rejection,
                f"{where}: event rejection changed outside terminal event")
        require(event["receipt_available"] is receipt_available,
                f"{where}: event receipt projection changed outside receipt event")
        require(event["cleanup_state"] == cleanup_state,
                f"{where}: event cleanup projection changed outside cleanup event")
    require(len(seen_kinds.intersection(terminal_kinds)) == 1,
            f"{where}: full history has no single terminal execution event")


def validate_event_response(body: dict[str, object], request_path: str, where: str) -> None:
    """Check cursor semantics and complete event projection invariants."""
    exact_keys(body, EVENT_RESPONSE_KEYS, where)
    require(body["api_version"] == "v1", f"{where}: bad api_version")
    require(isinstance(body["run_id"], str) and RUN_ID.fullmatch(body["run_id"]) is not None,
            f"{where}: bad run_id")
    query = parse_qs(urlsplit(request_path).query, strict_parsing=True)
    require(set(query) == {"after", "limit"}, f"{where}: bad fixture query")
    after = int(query["after"][0])
    limit = int(query["limit"][0])
    events = body["events"]
    require(isinstance(events, list) and len(events) <= limit <= 64, f"{where}: bad page size")
    sequences: list[int] = []
    prior_time: datetime | None = None
    for index, event in enumerate(events):
        require(isinstance(event, dict), f"{where}.events[{index}]: not an object")
        exact_keys(event, EVENT_KEYS, f"{where}.events[{index}]")
        sequence = event["sequence"]
        require(isinstance(sequence, int) and after < sequence <= 64,
                f"{where}.events[{index}]: bad sequence")
        sequences.append(sequence)
        require(event["kind"] in EVENT_KINDS, f"{where}.events[{index}]: bad kind")
        occurred = parse_time(event["occurred_at"], f"{where}.events[{index}].occurred_at")
        require(prior_time is None or occurred >= prior_time, f"{where}: event time decreased")
        prior_time = occurred
        validate_outcome(event, f"{where}.events[{index}]")
        kind = event["kind"]
        if kind == "admission.accepted":
            require(sequence == 1 and event["execution_state"] == "queued",
                    f"{where}.events[{index}]: bad admission event")
        elif kind in {"execution.started", "execution.deadline_reached"}:
            require(event["execution_state"] == "running",
                    f"{where}.events[{index}]: bad running event")
        elif kind == "execution.not_attempted":
            require(event["execution_state"] == "not_attempted",
                    f"{where}.events[{index}]: bad not-attempted event")
        elif kind == "execution.service_failed":
            require(event["execution_state"] == "service_failed",
                    f"{where}.events[{index}]: bad service-failed event")
        elif kind == "execution.terminal":
            require(event["execution_state"] == "terminal" and not event["receipt_available"],
                    f"{where}.events[{index}]: bad terminal event")
        elif kind == "receipt.available":
            require(event["receipt_available"] is True,
                    f"{where}.events[{index}]: bad receipt event")
        elif kind == "cleanup.started":
            require(event["cleanup_state"] == "running",
                    f"{where}.events[{index}]: bad cleanup-started event")
        elif kind == "cleanup.succeeded":
            require(event["cleanup_state"] == "succeeded",
                    f"{where}.events[{index}]: bad cleanup-succeeded event")
        elif kind == "cleanup.failed":
            require(event["cleanup_state"] == "failed",
                    f"{where}.events[{index}]: bad cleanup-failed event")
    require(sequences == list(range(after + 1, after + 1 + len(sequences))),
            f"{where}: replay sequence has a gap")
    last_sequence = body["last_sequence"]
    require(isinstance(last_sequence, int) and 1 <= last_sequence <= 64,
            f"{where}: bad last_sequence")
    expected_next = sequences[-1] if sequences else after
    require(body["next_after"] == expected_next, f"{where}: bad next_after")
    if sequences:
        require(expected_next <= last_sequence, f"{where}: event exceeds high-water mark")
    if sequences and sequences[0] == 1:
        validate_event_history(events, where)


def validate_exchange(exchange: dict[str, object], fixture_path: Path, index: int) -> None:
    """Validate one request/response transcript exchange."""
    where = f"{fixture_path.name}.exchanges[{index}]"
    exact_keys(exchange, ["request", "response"], where)
    request = exchange["request"]
    response = exchange["response"]
    require(isinstance(request, dict) and isinstance(response, dict), f"{where}: bad exchange")
    exact_keys(request, ["method", "path", "headers", "body"], f"{where}.request")
    require(list(response) in (
        ["status", "headers", "body"],
        ["status", "headers", "body_hex_file"],
    ), f"{where}.response: bad keys")
    require(isinstance(response["status"], int), f"{where}: bad status")
    require(isinstance(request["headers"], dict) and isinstance(response["headers"], dict),
            f"{where}: headers are not objects")
    request_headers = request["headers"]
    response_headers = response["headers"]
    if request["method"] == "POST":
        require(set(request_headers) == {"content-type", "idempotency-key"},
                f"{where}: unexpected POST request header")
        require(request_headers["content-type"] == "application/json",
                f"{where}: bad request content-type")
    else:
        require(request_headers == {}, f"{where}: unexpected GET request header")
    if "body_hex_file" in response:
        require(set(response_headers) == {
            "content-type", "content-length", "etag", "cache-control"
        }, f"{where}: unexpected receipt response header")
        require(response_headers["content-type"] ==
                "application/vnd.kapsel.kap0038.receipt",
                f"{where}: bad receipt content-type")
    else:
        expected_response_headers = {"content-type", "cache-control"}
        body = response["body"]
        if (isinstance(body, dict) and isinstance(body.get("error"), dict)
                and body["error"].get("retryable") is True):
            expected_response_headers.add("retry-after")
        require(set(response_headers) == expected_response_headers,
                f"{where}: unexpected JSON response header")
        require(response_headers["content-type"] == "application/json",
                f"{where}: bad response content-type")
    require(response_headers["cache-control"] == "no-store",
            f"{where}: response is cacheable")

    body_keys = walk_keys(request["body"])
    if "body" in response:
        body_keys |= walk_keys(response["body"])
    require(not body_keys.intersection(FORBIDDEN_BODY_KEYS), f"{where}: forbidden public field")

    if request["method"] == "POST":
        key = request["headers"].get("idempotency-key")
        require(isinstance(key, str) and IDEMPOTENCY_KEY.fullmatch(key) is not None,
                f"{where}: bad idempotency key")
        request_body = request["body"]
        require(isinstance(request_body, dict), f"{where}: POST body is not object")
        exact_keys(request_body, ["api_version", "scenario"], f"{where}.request.body")
        encoded_request = json.dumps(request_body, separators=(",", ":")).encode("utf-8")
        require(len(encoded_request) <= 512, f"{where}: admission request exceeds bound")
        require(request_body["scenario"] in SCENARIOS, f"{where}: bad request scenario")

    if response["status"] >= 400:
        validate_error(response, f"{where}.response")
        return

    if "body_hex_file" in response:
        relative = response["body_hex_file"]
        require(isinstance(relative, str), f"{where}: bad body_hex_file")
        body_path = (fixture_path.parent / relative).resolve()
        require(body_path.is_relative_to(ROOT) and body_path.is_file(), f"{where}: unsafe body file")
        raw = bytes.fromhex("".join(body_path.read_text(encoding="ascii").split()))
        require(len(raw) == EXPECTED_RECEIPT_SIZE, f"{where}: receipt size changed")
        headers = response["headers"]
        require(headers["content-length"] == str(len(raw)), f"{where}: wrong content-length")
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == EXPECTED_RECEIPT_SHA256, f"{where}: receipt digest changed")
        require(headers["etag"] == f'"{digest}"', f"{where}: wrong receipt ETag")
        path_match = RUN_PATH.search(request["path"])
        require(path_match is not None, f"{where}: receipt path has no run identity")
        run_id = path_match.group(1)
        require(f"sandbox-{run_id}".encode("ascii") in raw,
                f"{where}: receipt does not bind the run operation")
        return

    body = response["body"]
    require(isinstance(body, dict), f"{where}: success body is not an object")
    path = request["path"]
    if request["method"] == "POST":
        exact_keys(body, ADMISSION_KEYS, f"{where}.response.body")
        require(response["status"] in {200, 201}, f"{where}: bad admission status")
        expected = "replayed" if response["status"] == 200 else "created"
        require(body["admission_disposition"] == expected, f"{where}: bad admission disposition")
        require(body["api_version"] == "v1", f"{where}: bad api_version")
        validate_identity(body, f"{where}.response.body")
    elif "/events?" in path:
        validate_event_response(body, path, f"{where}.response.body")
        path_match = RUN_PATH.search(path)
        require(path_match is not None and body["run_id"] == path_match.group(1),
                f"{where}: event response run_id does not match URL")
    else:
        exact_keys(body, SNAPSHOT_KEYS, f"{where}.response.body")
        require(body["api_version"] == "v1", f"{where}: bad api_version")
        validate_identity(body, f"{where}.response.body")
        validate_outcome(body, f"{where}.response.body")
        path_match = RUN_PATH.search(path)
        require(path_match is not None and body["run_id"] == path_match.group(1),
                f"{where}: snapshot run_id does not match URL")


def main() -> None:
    """Load and validate the complete normative fixture set."""
    paths = sorted(FIXTURE_DIR.glob("*.json"))
    require({path.stem for path in paths} == FIXTURE_NAMES, "fixture coverage mismatch")
    seen: set[str] = set()
    seen_error_codes: set[str] = set()
    loaded: dict[str, dict[str, object]] = {}
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(document, dict), f"{path.name}: root is not an object")
        exact_keys(document, ["fixture", "exchanges"], path.name)
        require(document["fixture"] == path.stem, f"{path.name}: fixture name mismatch")
        exchanges = document["exchanges"]
        require(isinstance(exchanges, list) and exchanges, f"{path.name}: empty exchanges")
        for index, exchange in enumerate(exchanges):
            require(isinstance(exchange, dict), f"{path.name}.exchanges[{index}]: not object")
            validate_exchange(exchange, path, index)
        if path.stem == "healthy":
            created = exchanges[0]["response"]["body"]
            replayed = exchanges[1]["response"]["body"]
            require(isinstance(created, dict) and isinstance(replayed, dict),
                    "healthy: admission responses are not objects")
            immutable_keys = [key for key in ADMISSION_KEYS if key != "admission_disposition"]
            require(all(created[key] == replayed[key] for key in immutable_keys),
                    "healthy: idempotent replay changed admitted identity or facts")
        for exchange in exchanges:
            response_body = exchange["response"].get("body")
            if isinstance(response_body, dict) and isinstance(response_body.get("error"), dict):
                seen_error_codes.add(response_body["error"]["code"])
        loaded[path.stem] = document
        seen.add(path.stem)

    require(seen == FIXTURE_NAMES, "not all required fixtures were validated")
    require(seen_error_codes == set(ERRORS), "error fixture coverage mismatch")
    healthy_request = loaded["healthy"]["exchanges"][0]["request"]
    conflict_request = loaded["errors"]["exchanges"][2]["request"]
    require(healthy_request["headers"]["idempotency-key"] ==
            conflict_request["headers"]["idempotency-key"],
            "idempotency conflict does not reuse the admitted key")
    require(healthy_request["body"] != conflict_request["body"],
            "idempotency conflict does not change the parsed request")
    print(f"sandbox v1 contract fixtures: ok ({len(seen)} behaviors)")


if __name__ == "__main__":
    main()
