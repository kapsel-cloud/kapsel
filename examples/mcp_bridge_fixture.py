#!/usr/bin/env python3
"""Reply to one caller exchange from a disposable test-owned response queue."""

import json
import os
import sys
from pathlib import Path


def main() -> None:
    requests = [json.loads(line) for line in sys.stdin]
    invocation = requests[2]["params"]
    tool_name = invocation["name"]
    operation_id = invocation["arguments"].get("operation_id")

    state_path = Path(os.environ["FIXTURE_STATE"])
    state = json.loads(state_path.read_text())
    state["calls"].append(tool_name)
    configured_response = state["responses"][tool_name]
    response = (
        configured_response.pop(0) if isinstance(configured_response, list) else configured_response
    )
    state_path.write_text(json.dumps(state))

    initialization = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}}
    service_result = {"operation_id": operation_id, "service": response}
    reply = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"content": [{"type": "text", "text": json.dumps(service_result)}]},
    }
    print(json.dumps(initialization))
    print(json.dumps(reply))


if __name__ == "__main__":
    main()
