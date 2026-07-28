#!/usr/bin/env python3
"""Regression tests for the closed KAP-0061 baseline validator."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "scripts/validate-kap0061-baseline.py"
MANIFEST = ROOT / "qualification/kap0061-baseline.json"
SPEC = importlib.util.spec_from_file_location("kap0061_validator", VALIDATOR)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BaselineValidatorTests(unittest.TestCase):
    def run_document(self, document: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as output:
            json.dump(document, output)
            output.flush()
            return subprocess.run(
                ["python3", str(VALIDATOR), output.name],
                capture_output=True,
                text=True,
                check=False,
            )

    def canonical_document(self) -> dict:
        return json.loads(MANIFEST.read_text())

    def valid_document(self) -> dict:
        document = self.canonical_document()
        budget_by_id = {budget["id"]: budget for budget in document["budgets"]}
        result_by_subject = {
            (result["kind"], result["subject_id"]): result
            for result in document["results"]
        }
        measurement_lane = copy.deepcopy(result_by_subject[("lane", "measurement")])
        measurement_lane["input_sha256"]["source"] = document["baseline"]["source_sha256"]
        measurement_lane["input_sha256"]["ordinary-executable"] = document["baseline"]["ordinary_executable_sha256"]
        measurement_lane["input_sha256"]["demo-executable"] = document["baseline"]["demo_executable_sha256"]
        measurement_lane["assertions"] = [
            {"id": "all-budgets", "passed": True, "detail": "all budgets passed"},
            {
                "id": "explicit-target-build",
                "passed": True,
                "detail": "explicit target used",
            },
        ]
        result_by_subject[("lane", "measurement")] = measurement_lane
        for id_, definition in MODULE.EXPECTED_BUDGETS.items():
            values = dict(zip(MODULE.BUDGET_FIELDS, definition, strict=True))
            budget = {"id": id_, **values}
            budget_by_id[id_] = budget
            key = ("budget", id_)
            if key not in result_by_subject:
                result = {
                    "id": f"budget-{id_}",
                    "kind": "budget",
                    "subject_id": id_,
                    "environment_id": measurement_lane["environment_id"],
                    "command": measurement_lane["command"],
                    "input_sha256": copy.deepcopy(measurement_lane["input_sha256"]),
                    "status": "passed",
                    "sample_count": values["required_samples"],
                    "failure_count": 0,
                    "duration_ms": measurement_lane["duration_ms"],
                    "bounded_output_sha256": measurement_lane["bounded_output_sha256"],
                    "measurements": [
                        {
                            "id": "budget-value",
                            "value": 0,
                            "unit": values["unit"],
                            "statistic": values["statistic"],
                        }
                    ],
                    "assertions": [
                        {"id": "within-budget", "passed": True, "detail": "within budget"}
                    ],
                }
                result_by_subject[key] = result
            result = result_by_subject[key]
            result["id"] = f"budget-{id_}"
            result["sample_count"] = values["required_samples"]
            result["failure_count"] = 0
            if not result["measurements"]:
                result["measurements"] = [{"id": "budget-value", "value": 0}]
            result["measurements"] = [result["measurements"][0]]
            result["measurements"][0]["value"] = min(
                result["measurements"][0].get("value", 0), values["limit"]
            )
            result["measurements"][0]["unit"] = values["unit"]
            result["measurements"][0]["statistic"] = values["statistic"]
            if not result["assertions"]:
                result["assertions"] = [
                    {"id": "within-budget", "passed": True, "detail": "within budget"}
                ]
        measurement_subjects = {
            "process-startup-wall", "grant-provision-wall", "journal-fresh-open-wall",
            "journal-marked-open-wall", "offline-inspection-wall", "submit-authorized-wall",
            "target-read-wall", "conditional-patch-wall", "reconcile-apply-started-wall",
            "receipt-finalize-wall", "restart-recovery-wall", "process-startup-cpu",
            "grant-provision-cpu", "journal-fresh-open-cpu", "journal-marked-open-cpu",
            "offline-inspection-cpu", "complete-success-cpu", "complete-recovery-cpu",
            "process-rss", "bounded-unknown-wall", "journal-size", "journal-average-growth",
            "persisted-value-size", "sqlite-value-or-row-size", "rollback-journal-size",
            "grant-size", "trust-size", "receipt-size", "statement-size",
            "ordinary-executable-size", "demo-executable-size",
        }
        for subject in measurement_subjects:
            result = result_by_subject[("budget", subject)]
            for field in (
                "environment_id", "command", "input_sha256", "duration_ms",
                "bounded_output_sha256",
            ):
                result[field] = copy.deepcopy(measurement_lane[field])
        bounded_unknown = result_by_subject[("budget", "bounded-unknown-wall")]
        for field in ("environment_id", "command", "input_sha256", "duration_ms", "bounded_output_sha256"):
            bounded_unknown[field] = copy.deepcopy(measurement_lane[field])
        bounded_unknown["assertions"] = [
            {"id": "deterministic-404-fixture", "passed": True, "detail": "404 fixture"},
            {"id": "receiver-result-unknown", "passed": True, "detail": "UNKNOWN"},
            {"id": "thirty-read-schedule", "passed": True, "detail": "30 reads"},
            {"id": "zero-recovery-patches", "passed": True, "detail": "zero patches"},
        ]
        live = result_by_subject[("lane", "live-kind")]
        live["input_sha256"] = {
            "kind-harness": "1" * 64,
            "source": document["baseline"]["source_sha256"],
        }
        live["assertions"] = [
            {"id": "three-scenarios", "passed": True, "detail": "three scenarios"},
            {"id": "one-patch-each", "passed": True, "detail": "one patch each"},
            {"id": "owned-cleanup", "passed": True, "detail": "owned cleanup"},
        ]
        for subject in (
            "live-healthy-wall",
            "live-failed-wall",
            "live-unknown-wall",
            "live-cleanup-wall",
        ):
            result = result_by_subject[("budget", subject)]
            for field in ("environment_id", "command", "input_sha256", "duration_ms", "bounded_output_sha256"):
                result[field] = copy.deepcopy(live[field])
        privacy = result_by_subject[("lane", "privacy")]
        privacy["command"] = copy.deepcopy(MODULE.EXPECTED_PRIVACY_COMMAND)
        privacy["input_sha256"] = {
            "checked-source": MODULE.canonical_git_digest(
                document["baseline"]["commit"],
                MODULE.privacy_source_paths(document["baseline"]["commit"]),
            ),
            "privacy-check": "2" * 64,
        }
        privacy["assertions"] = [
            {"id": "no-private-material", "passed": True, "detail": "no private paths"},
            {"id": "no-credentials", "passed": True, "detail": "no credentials"},
            {"id": "no-raw-evidence", "passed": True, "detail": "no raw evidence"},
            {"id": "no-sla-overclaim", "passed": True, "detail": "no overclaim"},
        ]
        for result in result_by_subject.values():
            if result["kind"] == "lane":
                result["measurements"] = []
                result["sample_count"] = MODULE.EXPECTED_LANE_SAMPLES[result["subject_id"]]
                if not result["assertions"]:
                    result["assertions"] = [
                        {"id": "passed", "passed": True, "detail": "lane passed"}
                    ]
        audit = result_by_subject[("lane", "cargo-audit")]
        audit["input_sha256"] = {
            "cargo-lock": __import__("hashlib").sha256(
                MODULE.git_output("show", f"{document['baseline']['commit']}:Cargo.lock")
            ).hexdigest(),
            "rustsec-database": "3" * 64,
            "source": document["baseline"]["source_sha256"],
            "trivy-database": "4" * 64,
        }
        for key in (("lane", "trivy"), ("budget", "security-findings")):
            result = result_by_subject[key]
            for field in (
                "command", "environment_id", "input_sha256", "duration_ms",
                "bounded_output_sha256",
            ):
                result[field] = copy.deepcopy(audit[field])
        for tool in document["tools"]:
            tool["version"] = MODULE.EXPECTED_TOOL_VERSIONS[tool["id"]]
            if tool["id"] in {"cargo-audit", "trivy"}:
                tool["database_utc"] = "2026-07-28T00:00:00Z"
            else:
                tool.pop("database_utc", None)
        document["budgets"] = [budget_by_id[id_] for id_ in sorted(budget_by_id)]
        document["results"] = list(result_by_subject.values())
        for result in document["results"]:
            result["input_sha256"] = dict(sorted(result["input_sha256"].items()))
        for rule in document["invalidation_rules"]:
            rule["rerun_lanes"] = sorted(MODULE.EXPECTED_INVALIDATION[rule["id"]])
        return document

    def test_canonical_manifest_is_rejected_until_replaced_then_must_pass(self) -> None:
        document = self.canonical_document()
        result = self.run_document(document)
        ids = {budget["id"] for budget in document["budgets"]}
        if ids == set(MODULE.EXPECTED_BUDGETS):
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)

    def test_complete_synthetic_manifest_passes(self) -> None:
        result = self.run_document(self.valid_document())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shape_and_contract_mutations_fail(self) -> None:
        mutations = []
        unknown = self.valid_document()
        unknown["unknown"] = True
        mutations.append(unknown)
        null = self.valid_document()
        null["baseline"]["source_sha256"] = None
        mutations.append(null)
        duplicate = self.valid_document()
        duplicate["budgets"].append(copy.deepcopy(duplicate["budgets"][0]))
        mutations.append(duplicate)
        floating = self.valid_document()
        floating["results"][0]["duration_ms"] = 1.5
        mutations.append(floating)
        absolute = self.valid_document()
        absolute["results"][0]["command"][0] = "/private/var/secret"
        mutations.append(absolute)
        missing = self.valid_document()
        missing["results"].pop()
        mutations.append(missing)
        removed_contract = self.valid_document()
        removed = removed_contract["budgets"].pop()
        removed_contract["results"] = [
            result
            for result in removed_contract["results"]
            if not (result["kind"] == "budget" and result["subject_id"] == removed["id"])
        ]
        mutations.append(removed_contract)
        for document in mutations:
            with self.subTest():
                self.assertNotEqual(self.run_document(document).returncode, 0)

    def test_budget_semantic_mutations_fail(self) -> None:
        cases = []
        samples = self.valid_document()
        samples["results"][0]["sample_count"] = 0
        cases.append(samples)
        over_budget = self.valid_document()
        over_budget["results"][0]["measurements"][0]["value"] = 10**12
        cases.append(over_budget)
        wrong_unit = self.valid_document()
        wrong_unit["results"][0]["measurements"][0]["unit"] = "count"
        cases.append(wrong_unit)
        wrong_statistic = self.valid_document()
        wrong_statistic["results"][0]["measurements"][0]["statistic"] = "exact"
        cases.append(wrong_statistic)
        empty_measurement = self.valid_document()
        empty_measurement["results"][0]["measurements"] = []
        cases.append(empty_measurement)
        empty_assertion = self.valid_document()
        empty_assertion["results"][0]["assertions"] = []
        cases.append(empty_assertion)
        wrong_id = self.valid_document()
        wrong_id["results"][0]["id"] = "arbitrary"
        cases.append(wrong_id)
        for document in cases:
            with self.subTest():
                self.assertNotEqual(self.run_document(document).returncode, 0)

    def test_replay_input_privacy_and_invalidation_mutations_fail(self) -> None:
        cases = []
        fuzz_seed = self.valid_document()
        fuzz_seed["replay"]["fuzz_seed"] += 1
        cases.append(fuzz_seed)
        simulation_cases = self.valid_document()
        simulation_cases["replay"]["simulation_cases"] = 1
        cases.append(simulation_cases)
        corpus = self.valid_document()
        corpus["replay"]["fuzz_corpus_sha256"] = "0" * 64
        cases.append(corpus)
        privacy = self.valid_document()
        next(result for result in privacy["results"] if result["subject_id"] == "privacy")[
            "command"
        ] = ["true"]
        cases.append(privacy)
        duplicate_lane = self.valid_document()
        duplicate_lane["invalidation_rules"][0]["rerun_lanes"] = ["all", "all"]
        cases.append(duplicate_lane)
        incomplete = self.valid_document()
        incomplete["invalidation_rules"][1]["rerun_lanes"] = ["privacy"]
        cases.append(incomplete)
        lane_count = self.valid_document()
        next(result for result in lane_count["results"] if result["subject_id"] == "live-kind")[
            "sample_count"
        ] = 0
        cases.append(lane_count)
        tool_version = self.valid_document()
        next(tool for tool in tool_version["tools"] if tool["id"] == "kind")["version"] = "not-a-version"
        cases.append(tool_version)
        baseline_tree = self.valid_document()
        baseline_tree["baseline"]["tree"] = "0" * 40
        cases.append(baseline_tree)
        executable = self.valid_document()
        executable["baseline"]["ordinary_executable_sha256"] = "0" * 64
        cases.append(executable)
        checked_source = self.valid_document()
        next(result for result in checked_source["results"] if result["subject_id"] == "privacy")[
            "input_sha256"
        ]["checked-source"] = "0" * 64
        cases.append(checked_source)
        for document in cases:
            with self.subTest():
                self.assertNotEqual(self.run_document(document).returncode, 0)


if __name__ == "__main__":
    unittest.main()
