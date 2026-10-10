#!/usr/bin/env python3
"""Model Trivy database refresh, identity and findings without network access."""

import datetime
import json
import os
import pathlib
import sys
import time


def main() -> None:
    arguments = sys.argv[1:]
    if "--cache-dir" in arguments:
        cache_directory = pathlib.Path(arguments[arguments.index("--cache-dir") + 1])
    else:
        cache_directory = pathlib.Path(os.environ["HOME"]) / ".cache" / "trivy"
    database = cache_directory / "db" / "trivy.db"

    if arguments and arguments[0] == "filesystem" and "--download-db-only" in arguments:
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_bytes(b"fresh-database")
    elif "--version" in arguments and "--format" in arguments:
        if os.environ.get("FAKE_TRIVY_CLOSE_PIPES_THEN_SLEEP"):
            os.close(sys.stdout.fileno())
            os.close(sys.stderr.fileno())
            time.sleep(float(os.environ["FAKE_TRIVY_CLOSE_PIPES_THEN_SLEEP"]))
            return
        if os.environ.get("FAKE_TRIVY_SLEEP_VERSION"):
            time.sleep(float(os.environ["FAKE_TRIVY_SLEEP_VERSION"]))
        if os.environ.get("FAKE_TRIVY_FAIL_VERSION"):
            print("SECRET fixture stderr", file=sys.stderr)
            raise SystemExit(7)
        stderr_bytes = os.environ.get("FAKE_TRIVY_VERSION_STDERR_BYTES")
        if stderr_bytes is not None:
            sys.stderr.write("SECRET" + ("x" * int(stderr_bytes)))
            return
        stdout_bytes = os.environ.get("FAKE_TRIVY_VERSION_STDOUT_BYTES")
        if stdout_bytes is not None:
            sys.stdout.write("x" * int(stdout_bytes))
            return
        updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        identity = {
            "Version": "0.72.0",
            "VulnerabilityDB": {"Version": 2, "UpdatedAt": updated_at},
        }
        print(json.dumps(identity))
    elif arguments and arguments[0] == "sbom":
        if os.environ.get("FAKE_TRIVY_SLEEP_SBOM"):
            time.sleep(float(os.environ["FAKE_TRIVY_SLEEP_SBOM"]))
        if os.environ.get("FAKE_TRIVY_MUTATE") == "1":
            database.write_bytes(b"changed-database")

        output_path = pathlib.Path(arguments[arguments.index("--output") + 1])
        report_kind = os.environ.get("FAKE_TRIVY_REPORT_KIND")
        if report_kind == "oversized":
            with output_path.open("wb") as output:
                output.truncate(8 * 1024 * 1024 + 1)
            return
        if report_kind == "symlink":
            target = output_path.with_name("target-trivy.json")
            target.write_text("{}")
            output_path.symlink_to(target)
            return
        if report_kind == "fifo":
            os.mkfifo(output_path)
            return
        if report_kind == "omitted-results":
            output_path.write_text("{}")
            return
        if report_kind == "omitted-vulnerabilities":
            output_path.write_text(json.dumps({"Results": [{}]}))
            return
        if report_kind == "top-list":
            output_path.write_text("[]")
            return
        if report_kind == "results-object":
            output_path.write_text(json.dumps({"Results": {}}))
            return
        if report_kind == "vulnerabilities-object":
            output_path.write_text(json.dumps({"Results": [{"Vulnerabilities": {}}]}))
            return
        if report_kind == "vulnerability-string":
            output_path.write_text(json.dumps({"Results": [{"Vulnerabilities": ["bad"]}]}))
            return

        severity = os.environ.get("FAKE_TRIVY_SEVERITY")
        vulnerabilities = []
        if severity:
            vulnerabilities.append(
                {
                    "VulnerabilityID": "CVE-TEST-1",
                    "PkgName": "example",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1",
                    "Severity": severity,
                }
            )
        output_path.write_text(json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]}))
    else:
        raise SystemExit(f"unexpected fake Trivy arguments: {arguments}")


if __name__ == "__main__":
    main()
