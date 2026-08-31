#!/usr/bin/env python3
"""Smoke the release-only installer bundle seam with test-only ELF fixtures."""

from __future__ import annotations

import base64
import os
import pathlib
import secrets
import shutil
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
BUILDER_IMAGE = (
    "rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
)


def test_elf() -> bytes:
    """Return a minimal structurally valid ELF64 fixture; it is never executed."""
    value = bytearray(120)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", value, 16, 3, 62, 1)
    struct.pack_into("<Q", value, 32, 64)
    struct.pack_into("<HHH", value, 52, 64, 56, 1)
    struct.pack_into("<II", value, 64, 1, 1)
    struct.pack_into("<QQQ", value, 72, 0, 0, 0)
    struct.pack_into("<QQ", value, 96, len(value), len(value))
    struct.pack_into("<Q", value, 112, 4096)
    return bytes(value)


def copy(source: pathlib.Path, destination: pathlib.Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage_bundle(stage: pathlib.Path) -> None:
    stage.chmod(0o755)
    for path in [
        "usr/bin/kapsel",
        "usr/bin/kapsel-service-client",
        "usr/libexec/kapsel/kapseld",
    ]:
        destination = stage / path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        destination.write_bytes(test_elf())
        destination.chmod(0o755)
    for source, destination in [
        ("crates/kapseld/deploy/kapseld.service", "usr/lib/systemd/system/kapseld.service"),
        ("crates/kapseld/deploy/kapseld.conf", "usr/lib/sysusers.d/kapseld.conf"),
        ("crates/kapseld/deploy/kapseld-rbac.yaml", "usr/share/kapsel/kapseld-rbac.yaml"),
        (
            "docs/KAPSEL_SERVICE_OPERATOR.md",
            "usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        ),
        ("LICENSE", "LICENSE"),
    ]:
        copy(ROOT / source, stage / destination, 0o644)
    metadata = stage / "KAPSEL-SERVICE-METADATA.json"
    metadata.write_text('{"fixture":"test-only;not-candidate-metadata"}\n')
    metadata.chmod(0o644)
    for directory in [stage, *[path for path in stage.rglob("*") if path.is_dir()]]:
        directory.chmod(0o755)


def operator_input(directory: pathlib.Path, certificate_authority: bytes) -> None:
    directory.chmod(0o700)
    files = {
        "grant.bin": bytes.fromhex(
            (ROOT / "vectors/effect-gateway-grant.hex").read_text().strip()
        ),
        "authorization.pub": bytes.fromhex(
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        ),
        "receipt.seed": bytes([9]) * 32,
        "receipt.trust": bytes.fromhex(
            (ROOT / "vectors/effect-gateway-trust.hex").read_text().strip()
        ),
        "bootstrap-kubeconfig.yaml": f"""apiVersion: v1
kind: Config
clusters:
- name: fixture
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: {base64.b64encode(certificate_authority).decode()}
users:
- name: fixture
  user:
    token: fixture-token
contexts:
- name: nonprod
  context:
    cluster: fixture
    user: fixture
    namespace: demo
current-context: nonprod
""".encode(),
    }
    for name, contents in files.items():
        path = directory / name
        path.write_bytes(contents)
        path.chmod(0o600)


def kubernetes_fixture(path: pathlib.Path) -> None:
    path.write_text(r'''#!/usr/bin/env python3
import http.server, json, pathlib, ssl
ROOT = pathlib.Path("/target")
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_): pass
    def reply(self, status, value):
        body=json.dumps(value,separators=(",", ":")).encode(); self.send_response(status)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        with (ROOT/"kube-requests").open("a") as f: f.write(f"GET {self.path}\n")
        mode=(ROOT/"kube-mode").read_text().strip()
        if mode=="api-failure" and self.path=="/api/v1/namespaces/demo":
            return self.reply(500,{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","code":500})
        if self.path=="/api/v1/namespaces/demo":
            return self.reply(200,{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"demo","uid":"namespace-uid"}})
        if self.path=="/apis/apps/v1/namespaces/demo/deployments/agent-api":
            return self.reply(200,{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"agent-api","namespace":"demo","uid":"deployment-uid"},"spec":{"selector":{"matchLabels":{"app":"agent-api"}},"template":{"metadata":{"labels":{"app":"agent-api"}},"spec":{"containers":[{"name":"api","image":"example.invalid/image@sha256:"+"1"*64}]}}}})
        if mode=="role-conflict" and self.path=="/apis/rbac.authorization.k8s.io/v1/namespaces/demo/roles/kapsel-service-agent-api":
            return self.reply(200,{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"kapsel-service-agent-api","namespace":"demo","uid":"hostile-role"}})
        self.reply(404,{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404})
    def reject(self):
        with (ROOT/"kube-requests").open("a") as f: f.write(f"{self.command} {self.path}\n")
        self.reply(405,{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"MethodNotAllowed","code":405})
    do_POST=do_PUT=do_PATCH=do_DELETE=reject
server=http.server.ThreadingHTTPServer(("127.0.0.1",6443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain("/target/kube.crt","/target/kube.key")
server.socket=context.wrap_socket(server.socket,server_side=True); (ROOT/"kube-ready").write_text("ready"); server.serve_forever()
''')
    path.chmod(0o755)


def main() -> int:
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise RuntimeError("Docker and openssl are required")
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, timeout=30)
    with tempfile.TemporaryDirectory(prefix="kapsel-installer-stage-") as st, tempfile.TemporaryDirectory(prefix="kapsel-installer-target-") as tt, tempfile.TemporaryDirectory(prefix="kapsel-installer-input-") as it:
        stage, target, operator = pathlib.Path(st), pathlib.Path(tt), pathlib.Path(it)
        stage_bundle(stage)
        openssl = {"check": True, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", target / "ca.key", "-out", target / "ca.crt", "-days", "1", "-subj", "/CN=kapsel-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], **openssl)
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", target / "kube.key", "-out", target / "kube.csr", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], **openssl)
        (target / "kube.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        subprocess.run(["openssl", "x509", "-req", "-in", target / "kube.csr", "-CA", target / "ca.crt", "-CAkey", target / "ca.key", "-CAcreateserial", "-out", target / "kube.crt", "-days", "1", "-extfile", target / "kube.ext"], **openssl)
        operator_input(operator, (target / "ca.crt").read_bytes())
        kubernetes_fixture(target / "kube-server.py")
        script = rf'''
set -eu
kube_pid=
restore() {{ chown -R "$HOST_UID:$HOST_GID" /target; }}
cleanup() {{ test -z "$kube_pid" || kill "$kube_pid" 2>/dev/null || true; restore; }}
trap cleanup EXIT
export KAPSEL_INSTALLER_TEST_CRASH_SEAMS=1
cargo build --release --locked --target {TARGET} -p kapsel-installer
cargo test --release --locked --target {TARGET} -p kapsel-installer --bin kapsel-installer
installer=/target/{TARGET}/release/kapsel-installer
mkdir -p /secure; cp -a /operator-fixture /secure/kapsel; chown -R 0:0 /secure/kapsel
host=/host-fixture
mkdir -p "$host"/usr/sbin "$host"/usr/bin "$host"/run/systemd/system "$host"/etc/systemd/system/multi-user.target.wants "$host"/var/lib "$host"/usr/lib/systemd/system "$host"/usr/lib/sysusers.d "$host"/usr/libexec "$host"/usr/share/doc
cat >"$host/usr/bin/systemctl" <<'EOF'
#!/bin/sh
case "$1" in show-environment) exit 0;; cat) exit 1;; is-active) exit 3;; is-enabled) exit 1;; *) exit 9;; esac
EOF
printf '#!/bin/sh\nexit 2\n' >"$host/usr/bin/getent"
for tool in groupadd useradd usermod nologin; do cp "$host/usr/bin/getent" "$host/usr/sbin/$tool"; done
chmod 0755 "$host/usr/bin/"* "$host/usr/sbin/"*; chown -R 0:0 "$host"
export KAPSEL_INSTALLER_TEST_HOST_ROOT="$host"
: >/target/kube-requests; echo success >/target/kube-mode; /target/kube-server.py & kube_pid=$!
for _ in $(seq 1 500); do test -f /target/kube-ready && break; kill -0 "$kube_pid"; sleep .01; done
test -f /target/kube-ready
run_failure() {{
 expected=$1; action=${{2:-install}}; : >/target/stdout; : >/target/stderr; set +e
 "$installer" "$action" --operator-input /secure/kapsel --kube-context nonprod >/target/stdout 2>/target/stderr; status=$?; set -e
 test "$status" = 1; test ! -s /target/stdout
 actual=$(cat /target/stderr)
 if test "$actual" != "Kapsel installer failure: $expected"; then cat /target/kube-requests >&2; printf '%s\n' "$actual" >&2; return 1; fi
}}
run_killed() {{
 seam=$1; : >/target/stdout; : >/target/stderr
 (export KAPSEL_INSTALLER_TEST_STOP_AT_SEAM="$seam"; exec "$installer" install --operator-input /secure/kapsel --kube-context nonprod) >/target/stdout 2>/target/stderr & pid=$!
 stopped=false; for _ in $(seq 1 1500); do case "$(ps -o stat= -p "$pid" 2>/dev/null || true)" in *T*) stopped=true; break;; esac; kill -0 "$pid" 2>/dev/null || break; sleep .01; done
 test "$stopped" = true; kill -KILL "$pid"; status=0; wait "$pid" || status=$?; test "$status" = 137
}}
reset() {{ rm -rf /var/lib/kapsel-installer; rm -f /run/lock/kapsel-installer.lock; : >/target/kube-requests; echo success >/target/kube-mode; }}
prepared() {{ grep -F '"phase":"prepared"' /var/lib/kapsel-installer/transaction.json >/dev/null; }}
installing() {{ grep -F '"phase":"installing"' /var/lib/kapsel-installer/transaction.json >/dev/null; }}
get_only() {{ test -s /target/kube-requests; ! grep -Ev '^GET /' /target/kube-requests; }}
no_resources() {{ for p in etc/kapsel var/lib/kapsel run/kapsel usr/libexec/kapsel usr/share/kapsel usr/share/doc/kapsel usr/bin/kapsel usr/bin/kapsel-service-client usr/lib/systemd/system/kapseld.service usr/lib/sysusers.d/kapseld.conf; do test ! -e "$host/$p"; done; }}

reset; run_failure transaction_failure refresh-credential; test ! -e /var/lib/kapsel-installer
run_failure transaction_failure uninstall; test ! -e /var/lib/kapsel-installer; test ! -s /target/kube-requests
reset; run_failure implementation_incomplete; installing; get_only; test "$(wc -l </target/kube-requests)" = 5
cp /var/lib/kapsel-installer/transaction.json /target/installing.json; requests=$(wc -l </target/kube-requests)
run_failure implementation_incomplete; cmp /var/lib/kapsel-installer/transaction.json /target/installing.json; test "$(wc -l </target/kube-requests)" = "$requests"
run_failure implementation_incomplete refresh-credential; run_failure implementation_incomplete uninstall; test "$(wc -l </target/kube-requests)" = "$requests"; no_resources
initial=$(sed -n 's/.*"bootstrap_kubeconfig_initial_sha256":"\([0-9a-f]*\)".*/\1/p' /var/lib/kapsel-installer/transaction.json)
sed -i 's/token: fixture-token/token: renewed-token/' /secure/kapsel/bootstrap-kubeconfig.yaml; run_failure implementation_incomplete
current=$(sed -n 's/.*"bootstrap_kubeconfig_sha256":"\([0-9a-f]*\)".*/\1/p' /var/lib/kapsel-installer/transaction.json)
test "$initial" != "$current"; grep -F "\"bootstrap_kubeconfig_initial_sha256\":\"$initial\"" /var/lib/kapsel-installer/transaction.json >/dev/null; test "$(wc -l </target/kube-requests)" = "$requests"
sed -i 's/token: renewed-token/token: fixture-token/' /secure/kapsel/bootstrap-kubeconfig.yaml

reset; printf sentinel >"$host/usr/bin/kapsel"; chmod 0711 "$host/usr/bin/kapsel"; before=$(stat -c '%i:%s:%a' "$host/usr/bin/kapsel"):$(sha256sum "$host/usr/bin/kapsel")
run_failure host_preflight_failure; prepared; after=$(stat -c '%i:%s:%a' "$host/usr/bin/kapsel"):$(sha256sum "$host/usr/bin/kapsel"); test "$before" = "$after"; rm "$host/usr/bin/kapsel"; test ! -s /target/kube-requests
reset; echo role-conflict >/target/kube-mode; run_failure kubernetes_preflight_failure; prepared; get_only; no_resources
reset; echo api-failure >/target/kube-mode; run_failure kubernetes_preflight_failure; prepared; get_only; no_resources

reset; run_killed successor-inode-synced; prepared; test ! -e /var/lib/kapsel-installer/.transaction.next; first=$(wc -l </target/kube-requests); run_failure implementation_incomplete; installing; test "$(wc -l </target/kube-requests)" -gt "$first"
reset; run_killed successor-linked; prepared; test -f /var/lib/kapsel-installer/.transaction.next; first=$(wc -l </target/kube-requests); run_failure implementation_incomplete; installing; test ! -e /var/lib/kapsel-installer/.transaction.next; test "$(wc -l </target/kube-requests)" = "$first"
reset; run_killed successor-renamed; installing; test ! -e /var/lib/kapsel-installer/.transaction.next; first=$(wc -l </target/kube-requests); run_failure implementation_incomplete; test "$(wc -l </target/kube-requests)" = "$first"

reset; run_killed successor-inode-synced; transaction=/var/lib/kapsel-installer/transaction.json; successor=/var/lib/kapsel-installer/.transaction.next
sed 's/"phase":"prepared"/"phase":"installed"/' "$transaction" >"$successor"; chmod 0600 "$successor"
cat >/target/set-xattr.c <<'EOF'
#include <string.h>
#include <sys/xattr.h>
int main(int c, char **v) {{ return c != 3 || setxattr(v[1], "user.kapsel.transaction-id", v[2], strlen(v[2]), XATTR_CREATE); }}
EOF
cc /target/set-xattr.c -o /target/set-xattr; transaction_id=$(sed -n 's/.*"transaction_id":"\([0-9a-f]*\)".*/\1/p' "$transaction")
/target/set-xattr "$successor" "$transaction_id"; cp "$successor" /target/hostile-next
run_failure transaction_failure; cmp "$successor" /target/hostile-next; run_failure transaction_failure refresh-credential; cmp "$successor" /target/hostile-next; prepared; get_only; no_resources
'''
        container = f"kapsel-installer-bundle-{os.getpid()}-{secrets.token_hex(4)}"
        command = ["docker", "run", "--rm", "--name", container, "--platform", "linux/amd64", "--volume", f"{ROOT}:/workspace:ro", "--volume", f"{stage}:/stage:ro", "--volume", f"{target}:/target", "--volume", f"{operator}:/operator-fixture:ro", "--workdir", "/workspace", "--env", "CARGO_TARGET_DIR=/target", "--env", "KAPSEL_INSTALLER_STAGE=/stage", "--env", f"HOST_UID={os.getuid()}", "--env", f"HOST_GID={os.getgid()}", BUILDER_IMAGE, "sh", "-eu", "-c", script]
        try:
            subprocess.run(command, cwd=ROOT, check=True, timeout=1200)
        finally:
            subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    print("installer release-bundle smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
