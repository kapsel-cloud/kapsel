#!/usr/bin/env python3
"""Model Trivy database refresh, identity and findings without network access."""

import datetime
import json
import os
import pathlib
import sys


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
        updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        identity = {
            "Version": "0.72.0",
            "VulnerabilityDB": {"Version": 2, "UpdatedAt": updated_at},
        }
        print(json.dumps(identity))
    elif arguments and arguments[0] == "sbom":
        if os.environ.get("FAKE_TRIVY_MUTATE") == "1":
            database.write_bytes(b"changed-database")

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
        output_path = pathlib.Path(arguments[arguments.index("--output") + 1])
        output_path.write_text(json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]}))
    else:
        raise SystemExit(f"unexpected fake Trivy arguments: {arguments}")


if __name__ == "__main__":
    main()
