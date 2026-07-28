#!/usr/bin/env python3
"""Validate the closed KAP-0061 qualification-baseline manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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
            if result["subject_id"] in seen_budgets:
                fail("budget has more than one result")
            seen_budgets.add(result["subject_id"])
        elif result["kind"] == "lane":
            if result["subject_id"] not in lane_ids:
                fail("lane result references an unknown lane")
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
        if result["failure_count"] != 0:
            fail("result exceeded its failure ceiling")
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
        unique(result["assertions"], "assertions")
        for assertion in result["assertions"]:
            exact(assertion, {"id", "passed", "detail"}, "assertion")
            if assertion["passed"] is not True:
                fail("result assertion failed")
            text(assertion["detail"], "assertion.detail")
    if seen_budgets != budget_ids or seen_lanes != lane_ids:
        fail("manifest lacks exactly one result for every budget and lane")

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
    for rule in document["invalidation_rules"]:
        exact(rule, {"id", "trigger", "rerun_lanes"}, "invalidation_rule")
        text(rule["trigger"], "invalidation_rule.trigger")
        if not isinstance(rule["rerun_lanes"], list) or not rule["rerun_lanes"]:
            fail("invalidation rule must name lanes")
        for lane in rule["rerun_lanes"]:
            if lane != "all" and lane not in lane_ids:
                fail("invalidation rule references an unknown lane")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    validate(arguments.manifest)
    print(f"KAP-0061 baseline manifest valid: {arguments.manifest}")


if __name__ == "__main__":
    main()
