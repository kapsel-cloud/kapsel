#!/usr/bin/env python3
"""Validate the closed KAP-0061 qualification-baseline manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")

BUDGET_FIELDS = (
    "metric",
    "class",
    "statistic",
    "limit",
    "comparator",
    "unit",
    "warmups",
    "required_samples",
    "failure_ceiling",
)
EXPECTED_BUDGETS = {
    "bounded-unknown-wall": ("wall time", "bounded unknown observation", "maximum", 35000, "less_than_or_equal", "milliseconds", 0, 1, 0),
    "complete-recovery-cpu": ("CPU time", "complete recovery", "p95", 2000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "complete-success-cpu": ("CPU time", "complete success", "p95", 2000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "conditional-patch-wall": ("wall time", "conditional patch", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "demo-executable-size": ("file size", "demonstration executable", "maximum", 33554432, "less_than_or_equal", "bytes", 0, 1, 0),
    "grant-provision-cpu": ("CPU time", "grant provision", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "grant-provision-wall": ("wall time", "grant provision", "p95", 500000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "grant-size": ("wire size", "grant", "maximum", 4096, "less_than_or_equal", "bytes", 0, 1, 0),
    "immutable-image-size": ("input size", "immutable image", "maximum", 512, "less_than_or_equal", "bytes", 0, 1, 0),
    "journal-average-growth": ("average growth", "journal operation", "maximum", 8192, "less_than_or_equal", "bytes", 0, 10000, 0),
    "journal-fresh-open-cpu": ("CPU time", "fresh journal open", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "journal-fresh-open-wall": ("wall time", "fresh journal open", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "journal-marked-open-cpu": ("CPU time", "marked journal open", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "journal-marked-open-wall": ("wall time", "marked journal open", "p95", 500000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "journal-size": ("file size", "journal at capacity", "maximum", 67108864, "less_than_or_equal", "bytes", 0, 1, 0),
    "kubernetes-identity-size": ("input size", "Kubernetes identity fact", "maximum", 128, "less_than_or_equal", "bytes", 0, 1, 0),
    "kubernetes-response-size": ("input size", "Kubernetes response body", "maximum", 2097152, "less_than_or_equal", "bytes", 0, 3, 0),
    "live-cleanup-wall": ("wall time", "live owned cleanup", "maximum", 15000, "less_than_or_equal", "milliseconds", 0, 1, 0),
    "live-failed-wall": ("wall time", "live failed scenario", "maximum", 60000, "less_than_or_equal", "milliseconds", 0, 1, 0),
    "live-healthy-wall": ("wall time", "live healthy scenario", "maximum", 60000, "less_than_or_equal", "milliseconds", 0, 1, 0),
    "live-unknown-wall": ("wall time", "live unknown scenario", "maximum", 60000, "less_than_or_equal", "milliseconds", 0, 1, 0),
    "machine-output-size": ("output size", "machine output", "maximum", 65536, "less_than_or_equal", "bytes", 0, 1, 0),
    "mcp-frame-size": ("input size", "MCP frame", "maximum", 16384, "less_than_or_equal", "bytes", 0, 1, 0),
    "mcp-response-size": ("output size", "MCP response", "maximum", 8192, "less_than_or_equal", "bytes", 0, 1, 0),
    "offline-inspection-cpu": ("CPU time", "offline inspection", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "offline-inspection-wall": ("wall time", "offline inspection", "p95", 500000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "ordinary-executable-size": ("file size", "ordinary executable", "maximum", 33554432, "less_than_or_equal", "bytes", 0, 1, 0),
    "persisted-value-size": ("value size", "persisted text or blob", "maximum", 16384, "less_than_or_equal", "bytes", 0, 1, 0),
    "process-rss": ("peak RSS", "ordinary measured process", "maximum", 134217728, "less_than_or_equal", "bytes", 0, 211, 0),
    "process-startup-cpu": ("CPU time", "process startup", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "process-startup-wall": ("wall time", "process startup", "maximum", 500000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "receipt-finalize-wall": ("wall time", "receipt finalization", "p95", 500000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "receipt-size": ("wire size", "receipt", "maximum", 16384, "less_than_or_equal", "bytes", 0, 1, 0),
    "reconcile-apply-started-wall": ("wall time", "apply-started reconciliation", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "request-json-size": ("input size", "request JSON", "maximum", 16384, "less_than_or_equal", "bytes", 0, 1, 0),
    "restart-recovery-wall": ("wall time", "restart recovery", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "rollback-journal-size": ("artifact size", "rollback journal", "maximum", 68157440, "less_than_or_equal", "bytes", 0, 1, 0),
    "security-findings": ("finding count", "rejected security findings", "maximum", 0, "less_than_or_equal", "count", 0, 2, 0),
    "sqlite-value-or-row-size": ("allocation limit", "SQLite value or row", "maximum", 65536, "less_than_or_equal", "bytes", 0, 1, 0),
    "statement-size": ("wire size", "statement", "maximum", 8192, "less_than_or_equal", "bytes", 0, 1, 0),
    "submit-authorized-wall": ("wall time", "authorized submission", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "target-read-wall": ("wall time", "target read", "p95", 1000000, "less_than_or_equal", "microseconds", 5, 30, 0),
    "trust-size": ("wire size", "trust", "maximum", 1024, "less_than_or_equal", "bytes", 0, 1, 0),
}
EXPECTED_LANES = {
    "default",
    "hostile-input",
    "simulation",
    "fuzz",
    "subprocess",
    "demo",
    "live-kind",
    "measurement",
    "cargo-audit",
    "trivy",
    "privacy",
}
EXPECTED_REPLAY = {
    "fuzz_seed": 2118243591,
    "fuzz_runs": 10000,
    "fuzz_corpus_sha256": "86dda67e958b96cd56452de77199c2ebfac36400d6c971e84966a4b9fb3e9e8d",
    "simulation_seed": 21182435914953528,
    "simulation_cases": 10000,
}
EXPECTED_INVALIDATION = {
    "root-source-or-identity": {"all"},
    "qualification-input": {"all"},
    "distribution-only": {"default", "privacy", "trivy"},
    "semantic-or-budget": {"all"},
}
EXPECTED_PRIVACY_COMMAND = [
    "python3",
    "scripts/check-kap0061-privacy.py",
    "--output",
    "BOUNDED_OUTPUT",
]


def fail(message: str) -> None:
    raise ValueError(message)


def exact(value: dict[str, Any], fields: set[str], context: str) -> None:
    if set(value) != fields:
        fail(f"{context} fields differ: {sorted(set(value) ^ fields)}")


def identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        fail(f"{context} is not a stable identifier")
    return value


def integer(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(f"{context} is not a nonnegative integer")
    return value


def text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{context} is not bounded text")
    if value.startswith("/") or re.search(r"(?:^|\s)/Users/|(?:^|\s)/private/var/", value):
        fail(f"{context} contains an absolute private path")
    return value


def unique(items: list[dict[str, Any]], context: str) -> set[str]:
    identifiers = [identifier(item.get("id"), f"{context}.id") for item in items]
    if len(identifiers) != len(set(identifiers)):
        fail(f"{context} contains duplicate ids")
    return set(identifiers)


def validate(path: Path) -> None:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        fail("manifest must be an object")
    exact(
        document,
        {
            "schema_version",
            "baseline",
            "environments",
            "tools",
            "budgets",
            "lanes",
            "results",
            "replay",
            "security",
            "residual_risks",
            "invalidation_rules",
        },
        "manifest",
    )
    if document["schema_version"] != 1:
        fail("schema_version must be 1")

    baseline = document["baseline"]
    exact(
        baseline,
        {
            "commit",
            "tree",
            "source_sha256",
            "source_path_count",
            "ordinary_executable_sha256",
            "demo_executable_sha256",
            "ordinary_executable_bytes",
            "demo_executable_bytes",
            "qualification_baseline_only",
        },
        "baseline",
    )
    for field in ("commit", "tree"):
        if not isinstance(baseline[field], str) or HEX40.fullmatch(baseline[field]) is None:
            fail(f"baseline.{field} is not lowercase SHA-1")
    for field in ("source_sha256", "ordinary_executable_sha256", "demo_executable_sha256"):
        if not isinstance(baseline[field], str) or HEX64.fullmatch(baseline[field]) is None:
            fail(f"baseline.{field} is not lowercase SHA-256")
    integer(baseline["source_path_count"], "baseline.source_path_count")
    integer(baseline["ordinary_executable_bytes"], "baseline.ordinary_executable_bytes")
    integer(baseline["demo_executable_bytes"], "baseline.demo_executable_bytes")
    if baseline["qualification_baseline_only"] is not True:
        fail("baseline must remain qualification-only")

    environments = document["environments"]
    if not isinstance(environments, list) or not environments:
        fail("environments must be nonempty")
    environment_ids = unique(environments, "environments")
    for environment in environments:
        exact(
            environment,
            {
                "id",
                "os",
                "architecture",
                "cpu_count",
                "memory_bytes",
                "virtualized",
                "description",
            },
            f"environment.{environment['id']}",
        )
        text(environment["os"], "environment.os")
        text(environment["architecture"], "environment.architecture")
        integer(environment["cpu_count"], "environment.cpu_count")
        integer(environment["memory_bytes"], "environment.memory_bytes")
        if not isinstance(environment["virtualized"], bool):
            fail("environment.virtualized must be boolean")
        text(environment["description"], "environment.description")

    tools = document["tools"]
    if not isinstance(tools, list) or not tools:
        fail("tools must be nonempty")
    unique(tools, "tools")
    for tool in tools:
        fields = {"id", "version", "environment_id"}
        if "database_utc" in tool:
            fields.add("database_utc")
        exact(tool, fields, f"tool.{tool['id']}")
        text(tool["version"], "tool.version")
        if tool["environment_id"] not in environment_ids:
            fail("tool references an unknown environment")
        if "database_utc" in tool:
            text(tool["database_utc"], "tool.database_utc")

    budgets = document["budgets"]
    lanes = document["lanes"]
    if not isinstance(budgets, list) or not isinstance(lanes, list):
        fail("budgets and lanes must be arrays")
    budget_ids = unique(budgets, "budgets")
    lane_ids = unique(lanes, "lanes")
    if budget_ids != set(EXPECTED_BUDGETS):
        fail("manifest budget set differs from the frozen KAP-0061 contract")
    if lane_ids != EXPECTED_LANES:
        fail("manifest lane set differs from the frozen KAP-0061 contract")
    budget_by_id = {budget["id"]: budget for budget in budgets}
    for budget in budgets:
        exact(
            budget,
            {
                "id",
                "metric",
                "class",
                "statistic",
                "limit",
                "comparator",
                "unit",
                "warmups",
                "required_samples",
                "failure_ceiling",
            },
            f"budget.{budget['id']}",
        )
        for field in ("metric", "class", "unit"):
            text(budget[field], f"budget.{field}")
        if budget["statistic"] not in {"p95", "maximum"}:
            fail("budget statistic is unsupported")
        if budget["comparator"] != "less_than_or_equal":
            fail("budget comparator is unsupported")
        for field in ("limit", "warmups", "required_samples", "failure_ceiling"):
            integer(budget[field], f"budget.{field}")
        if budget["required_samples"] == 0:
            fail("budget required_samples must be positive")
        observed = tuple(budget[field] for field in BUDGET_FIELDS)
        if observed != EXPECTED_BUDGETS[budget["id"]]:
            fail(f"budget.{budget['id']} differs from the frozen contract")
    for lane in lanes:
        exact(lane, {"id", "description", "required"}, f"lane.{lane['id']}")
        text(lane["description"], "lane.description")
        if lane["required"] is not True:
            fail("KAP-0061 lanes must be required")

    results = document["results"]
    if not isinstance(results, list):
        fail("results must be an array")
    unique(results, "results")
    seen_budgets: set[str] = set()
    seen_lanes: set[str] = set()
    for result in results:
        exact(
            result,
            {
                "id",
                "kind",
                "subject_id",
                "environment_id",
                "command",
                "input_sha256",
                "status",
                "sample_count",
                "failure_count",
                "duration_ms",
                "bounded_output_sha256",
                "measurements",
                "assertions",
            },
            f"result.{result['id']}",
        )
        if result["kind"] == "budget":
            if result["subject_id"] not in budget_ids:
                fail("budget result references an unknown budget")
            if result["id"] != f"budget-{result['subject_id']}":
                fail("budget result id does not match its subject")
            if result["subject_id"] in seen_budgets:
                fail("budget has more than one result")
            seen_budgets.add(result["subject_id"])
        elif result["kind"] == "lane":
            if result["subject_id"] not in lane_ids:
                fail("lane result references an unknown lane")
            if result["id"] != f"lane-{result['subject_id']}":
                fail("lane result id does not match its subject")
            if result["subject_id"] in seen_lanes:
                fail("lane has more than one result")
            seen_lanes.add(result["subject_id"])
        else:
            fail("result kind is unsupported")
        if result["environment_id"] not in environment_ids:
            fail("result references an unknown environment")
        if not isinstance(result["command"], list) or not result["command"]:
            fail("result command must be nonempty argv")
        for argument in result["command"]:
            text(argument, "result.command")
        if not isinstance(result["input_sha256"], dict):
            fail("result inputs must be an object")
        if list(result["input_sha256"]) != sorted(result["input_sha256"]):
            fail("result input map must be sorted")
        for name, digest in result["input_sha256"].items():
            identifier(name, "result.input name")
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
                fail("result input is not lowercase SHA-256")
        if result["status"] != "passed":
            fail("every required KAP-0061 result must pass")
        for field in ("sample_count", "failure_count", "duration_ms"):
            integer(result[field], f"result.{field}")
        if result["kind"] == "budget":
            budget = budget_by_id[result["subject_id"]]
            if result["sample_count"] != budget["required_samples"]:
                fail("budget result sample count differs from its requirement")
            if result["failure_count"] > budget["failure_ceiling"]:
                fail("budget result exceeded its failure ceiling")
        elif result["failure_count"] != 0:
            fail("lane result exceeded its failure ceiling")
        if not isinstance(result["bounded_output_sha256"], str) or HEX64.fullmatch(result["bounded_output_sha256"]) is None:
            fail("result output is not lowercase SHA-256")
        if not isinstance(result["measurements"], list) or not isinstance(result["assertions"], list):
            fail("result measurements and assertions must be arrays")
        unique(result["measurements"], "measurements")
        for measurement in result["measurements"]:
            exact(measurement, {"id", "value", "unit", "statistic"}, "measurement")
            integer(measurement["value"], "measurement.value")
            text(measurement["unit"], "measurement.unit")
            if measurement["statistic"] not in {"p95", "maximum", "count", "exact"}:
                fail("measurement statistic is unsupported")
        if result["kind"] == "budget":
            if len(result["measurements"]) != 1:
                fail("budget result must contain exactly one measurement")
            measurement = result["measurements"][0]
            budget = budget_by_id[result["subject_id"]]
            if measurement["statistic"] != budget["statistic"]:
                fail("budget measurement statistic differs from its budget")
            if measurement["unit"] != budget["unit"]:
                fail("budget measurement unit differs from its budget")
            if measurement["value"] > budget["limit"]:
                fail("budget measurement exceeds its limit")
        elif result["measurements"]:
            fail("lane result must not contain measurements")
        if not result["assertions"]:
            fail("result assertions must be nonempty")
        unique(result["assertions"], "assertions")
        for assertion in result["assertions"]:
            exact(assertion, {"id", "passed", "detail"}, "assertion")
            if assertion["passed"] is not True:
                fail("result assertion failed")
            text(assertion["detail"], "assertion.detail")
    if seen_budgets != budget_ids or seen_lanes != lane_ids:
        fail("manifest lacks exactly one result for every budget and lane")
    result_by_subject = {
        (result["kind"], result["subject_id"]): result for result in results
    }

    replay = document["replay"]
    exact(
        replay,
        {"fuzz_seed", "fuzz_runs", "fuzz_corpus_sha256", "simulation_seed", "simulation_cases", "simulation_shards"},
        "replay",
    )
    for field in ("fuzz_seed", "fuzz_runs", "simulation_seed", "simulation_cases", "simulation_shards"):
        integer(replay[field], f"replay.{field}")
    if not isinstance(replay["fuzz_corpus_sha256"], str) or HEX64.fullmatch(replay["fuzz_corpus_sha256"]) is None:
        fail("replay corpus digest is invalid")
    for field, expected in EXPECTED_REPLAY.items():
        if replay[field] != expected:
            fail(f"replay.{field} differs from the frozen contract")
    if replay["simulation_shards"] == 0:
        fail("simulation_shards must be positive")

    fuzz_result = result_by_subject[("lane", "fuzz")]
    if fuzz_result["sample_count"] != replay["fuzz_runs"]:
        fail("fuzz result count differs from replay")
    if fuzz_result["input_sha256"].get("corpus") != replay["fuzz_corpus_sha256"]:
        fail("fuzz corpus input differs from replay")
    simulation_result = result_by_subject[("lane", "simulation")]
    if simulation_result["sample_count"] != replay["simulation_cases"]:
        fail("simulation result count differs from replay")
    simulation_seed_digest = hashlib.sha256(str(replay["simulation_seed"]).encode()).hexdigest()
    if simulation_result["input_sha256"].get("simulation-seed") != simulation_seed_digest:
        fail("simulation seed input differs from replay")
    if fuzz_result["duration_ms"] > 600_000 or simulation_result["duration_ms"] > 600_000:
        fail("replay lane exceeded its ten-minute ceiling")

    privacy_result = result_by_subject[("lane", "privacy")]
    if privacy_result["command"] != EXPECTED_PRIVACY_COMMAND:
        fail("privacy result command differs from the closed review command")
    if not privacy_result["input_sha256"]:
        fail("privacy result lacks input identity")
    required_assertions = {
        ("budget", "bounded-unknown-wall"): {
            "deterministic-404-fixture",
            "receiver-result-unknown",
            "thirty-read-schedule",
            "zero-recovery-patches",
        },
        ("lane", "measurement"): {"all-budgets", "explicit-target-build"},
        ("lane", "live-kind"): {"three-scenarios", "one-patch-each", "owned-cleanup"},
        ("lane", "privacy"): {
            "no-private-material",
            "no-credentials",
            "no-raw-evidence",
            "no-sla-overclaim",
        },
    }
    for key, required in required_assertions.items():
        observed = {item["id"] for item in result_by_subject[key]["assertions"]}
        if not required.issubset(observed):
            fail(f"result {key[1]} lacks required semantic assertions")

    measurement_result = result_by_subject[("lane", "measurement")]
    measurement_subjects = {
        "process-startup-wall",
        "grant-provision-wall",
        "journal-fresh-open-wall",
        "journal-marked-open-wall",
        "offline-inspection-wall",
        "submit-authorized-wall",
        "target-read-wall",
        "conditional-patch-wall",
        "reconcile-apply-started-wall",
        "receipt-finalize-wall",
        "restart-recovery-wall",
        "process-startup-cpu",
        "grant-provision-cpu",
        "journal-fresh-open-cpu",
        "journal-marked-open-cpu",
        "offline-inspection-cpu",
        "complete-success-cpu",
        "complete-recovery-cpu",
        "process-rss",
        "bounded-unknown-wall",
        "journal-size",
        "journal-average-growth",
        "persisted-value-size",
        "sqlite-value-or-row-size",
        "rollback-journal-size",
        "grant-size",
        "trust-size",
        "receipt-size",
        "statement-size",
        "ordinary-executable-size",
        "demo-executable-size",
    }
    for subject in measurement_subjects:
        result = result_by_subject[("budget", subject)]
        for field in ("command", "environment_id", "input_sha256", "bounded_output_sha256"):
            if result[field] != measurement_result[field]:
                fail(f"measurement budget {subject} is disconnected from its producer")
    source_digest = baseline["source_sha256"]
    if measurement_result["input_sha256"].get("source") != source_digest:
        fail("measurement source input differs from the baseline")
    if result_by_subject[("budget", "ordinary-executable-size")]["measurements"][0]["value"] != baseline["ordinary_executable_bytes"]:
        fail("ordinary executable size differs from the baseline")
    if result_by_subject[("budget", "demo-executable-size")]["measurements"][0]["value"] != baseline["demo_executable_bytes"]:
        fail("demonstration executable size differs from the baseline")

    live_result = result_by_subject[("lane", "live-kind")]
    for subject in (
        "live-healthy-wall",
        "live-failed-wall",
        "live-unknown-wall",
        "live-cleanup-wall",
    ):
        result = result_by_subject[("budget", subject)]
        for field in ("command", "environment_id", "input_sha256", "bounded_output_sha256"):
            if result[field] != live_result[field]:
                fail(f"live budget {subject} is disconnected from its producer")
    harness_digest = live_result["input_sha256"].get("kind-harness")
    if harness_digest is None or harness_digest == live_result["bounded_output_sha256"]:
        fail("live harness input is absent or conflated with bounded output")
    if live_result["input_sha256"].get("source") != source_digest:
        fail("live source input differs from the baseline")

    security = document["security"]
    exact(security, {"findings", "exceptions", "reviews"}, "security")
    if security["findings"] != [] or security["exceptions"] != []:
        fail("accepted baseline contains a security finding or exception")
    if not isinstance(security["reviews"], list) or not security["reviews"]:
        fail("security reviews are required")
    unique(security["reviews"], "security.reviews")
    for review in security["reviews"]:
        exact(review, {"id", "status", "disposition"}, "security.review")
        if review["status"] != "passed":
            fail("security review did not pass")
        text(review["disposition"], "security.review.disposition")

    for field in ("residual_risks", "invalidation_rules"):
        values = document[field]
        if not isinstance(values, list) or not values:
            fail(f"{field} must be nonempty")
        unique(values, field)
    for risk in document["residual_risks"]:
        exact(risk, {"id", "statement"}, "residual_risk")
        text(risk["statement"], "residual_risk.statement")
    rules = {rule["id"]: rule for rule in document["invalidation_rules"]}
    if set(rules) != set(EXPECTED_INVALIDATION):
        fail("invalidation rule set differs from the frozen contract")
    for rule in document["invalidation_rules"]:
        exact(rule, {"id", "trigger", "rerun_lanes"}, "invalidation_rule")
        text(rule["trigger"], "invalidation_rule.trigger")
        if not isinstance(rule["rerun_lanes"], list) or not rule["rerun_lanes"]:
            fail("invalidation rule must name lanes")
        if len(rule["rerun_lanes"]) != len(set(rule["rerun_lanes"])):
            fail("invalidation rule contains duplicate lanes")
        if "all" in rule["rerun_lanes"] and rule["rerun_lanes"] != ["all"]:
            fail("all must be the sole invalidation lane")
        for lane in rule["rerun_lanes"]:
            if lane != "all" and lane not in lane_ids:
                fail("invalidation rule references an unknown lane")
        if set(rule["rerun_lanes"]) != EXPECTED_INVALIDATION[rule["id"]]:
            fail(f"invalidation rule {rule['id']} differs from the frozen lane set")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    validate(arguments.manifest)
    print(f"KAP-0061 baseline manifest valid: {arguments.manifest}")


if __name__ == "__main__":
    main()
