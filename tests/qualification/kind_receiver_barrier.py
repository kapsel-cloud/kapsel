"""Operator-owned transport barriers forwarding bounded requests to the real API server."""

import base64
import http.server
import json
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 262144


def upstream(
    server: str,
    context: ssl.SSLContext | None,
    token: str,
    path: str,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str = "application/json",
    user_agent: str = "kapsel-journey-fixture",
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        server + path,
        data=body,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": content_type,
            "User-Agent": user_agent,
        },
    )
    try:
        response = urllib.request.urlopen(request, context=context, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(LIMIT + 1)
        assert len(data) <= LIMIT, "API response bound"
        return response.code, data


def send_reply(handler: http.server.BaseHTTPRequestHandler, status: int, data: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    try:
        handler.end_headers()
        handler.wfile.write(data)
    except (BrokenPipeError, ConnectionResetError):
        pass  # Deliberate service loss may close either the header or body transport.


def main(inputs: pathlib.Path, evidence: pathlib.Path, coordination: pathlib.Path) -> None:
    config = json.loads((inputs / "kubeconfig.json").read_bytes())
    cluster = config["clusters"][0]["cluster"]
    token = config["users"][0]["user"]["token"]
    fixture_token = (inputs / "fixture-token").read_text()
    context = ssl.create_default_context(
        cadata=(
            base64.b64decode(cluster["certificate-authority-data"]).decode()
            if "certificate-authority-data" in cluster
            else None
        )
    )
    server = cluster["server"]
    cases = json.loads((inputs / "settings.json").read_bytes())["cases"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def forward(self) -> None:
            if self.headers.get("Authorization") != "Bearer " + token:
                self.send_error(403)
                return
            try:
                self.forward_request()
            except Exception as error:
                (evidence / "barrier.violation").write_text(
                    "barrier error: " + type(error).__name__
                )
                self.send_error(500, "fixture barrier failed")

        def forward_request(self) -> None:
            self.connection.settimeout(10)
            path = urllib.parse.urlsplit(self.path).path
            case = path.removeprefix("/apis/apps/v1/namespaces/demo/deployments/agent-")
            assert case in cases
            length = int(self.headers.get("Content-Length", "0"))
            assert 0 <= length <= 16384
            body = self.rfile.read(length) if length else None
            content_type = self.headers.get("Content-Type", "application/json")
            user_agent = self.headers.get("User-Agent", "kapsel-product-barrier")
            record = evidence / (case + ".patch.json")
            patch = None
            duplicate = False
            if self.command == "PATCH":
                assert body is not None
                patch = json.loads(body)
                try:
                    with record.with_suffix(".request.json").open("x") as output:
                        json.dump({"request": patch}, output)
                    duplicate = False
                except FileExistsError:
                    duplicate = True
                    # Report retries without suppressing the actual second API request.
                    (evidence / "barrier.violation").write_text("duplicate product PATCH: " + case)
                if case == "race" and not duplicate:
                    status, _ = upstream(
                        server,
                        context,
                        fixture_token,
                        self.path,
                        "PATCH",
                        json.dumps(
                            {"metadata": {"annotations": {"journey-fixture/race": "true"}}}
                        ).encode(),
                        "application/merge-patch+json",
                    )
                    assert status == 200
            status, data = upstream(
                server, context, token, self.path, self.command, body, content_type, user_agent
            )
            if self.command == "GET":
                with (evidence / (case + ".gets.jsonl")).open("a") as output:
                    output.write(json.dumps({"at": time.time(), "status": status}) + "\n")
            if patch is not None and not duplicate:
                completed = record.with_suffix(".complete.json")
                completed.write_text(
                    json.dumps({"request": patch, "status": status, "response": json.loads(data)})
                )
                completed.replace(record)
                if case in ("failed", "deleted"):
                    assert status == 200
                    deadline = time.monotonic() + 30
                    release = coordination / (case + ".release")
                    while not release.exists():
                        assert time.monotonic() < deadline, "transport barrier deadline"
                        time.sleep(0.01)
            send_reply(self, status, data)

        do_GET = forward
        do_PATCH = forward

        def log_message(self, format, *args):
            return

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    (coordination / "barrier.ready").write_text(str(httpd.server_port))
    httpd.serve_forever()


if __name__ == "__main__":
    main(*(pathlib.Path(argument) for argument in sys.argv[1:]))
