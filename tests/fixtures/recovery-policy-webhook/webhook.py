#!/usr/bin/env python3
"""Disposable admission-side-effect evidence.

Never install this deliberately side-effecting webhook in an existing cluster.
"""

import http.server
import json
import ssl

MAX_BODY_BYTES = 1 << 20
OPERATION_ANNOTATION = "kapsel.dev/kap0038-operation-id"


class AdmissionHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("invalid body length")
        review = json.loads(self.rfile.read(length))
        request = review["request"]
        annotations = request.get("object", {}).get("metadata", {}).get("annotations", {})
        operation_id = annotations.get(OPERATION_ANNOTATION, "missing")
        if not request.get("dryRun", False):
            # This flushed log is the out-of-band effect counted by the live proof.
            print(
                f"KAPSEL_ADMISSION_EFFECT uid={request['uid']} operation_id={operation_id}",
                flush=True,
            )

        body = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": request["uid"], "allowed": True},
        }
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


def main() -> None:
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), AdmissionHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
