#!/usr/bin/env python3
"""Run the disposable, audited later-observation experiment. Not an installed command."""

import argparse
import collections
import contextlib
import hashlib
import io
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAMESPACE = "kapsel-later-observation"
NODE = (
    "kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4"
)
IMAGES = (
    "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a",
    "registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c",
)
INPUTS = ("Cargo.toml", "tests/later_observation.rs", "scripts/test-kind-later-observation.py")


def run(
    *args: str, env: dict[str, str] | None = None, timeout: int = 60, echo: bool = True
) -> bytes:
    """Bound command time and combined output, killing descendants on interruption."""
    print(f"[later command] {' '.join(args)}", flush=True)
    with subprocess.Popen(
        args,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    ) as process:
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f"command exceeded {timeout}s: {args[0]}")
                    for key, _ in selector.select(min(remaining, 1)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(output) + len(chunk) > 8 * 1024 * 1024:
                            raise RuntimeError(f"command output exceeded 8 MiB: {args[0]}")
                        output.extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if code:
                raise subprocess.CalledProcessError(code, args)
        finally:
            # The process group may still contain children even if its leader exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            if echo:
                print(output.decode(errors="replace"), end="", flush=True)
    return bytes(output)


def source_hashes() -> str:
    return "".join(
        f"{hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}  {name}\n" for name in INPUTS
    )


def check_audit(data: bytes) -> None:
    counts = collections.Counter()
    for line in data.splitlines():
        event = json.loads(line)
        agent = event.get("userAgent", "")
        if event["stage"] == "RequestReceived" and agent.startswith("kapsel-later-"):
            counts[agent, event["verb"]] += 1
    followup = {
        verb: count for (agent, verb), count in counts.items() if agent == "kapsel-later-followup"
    }
    if counts["kapsel-later-execution", "patch"] != 1 or followup != {"get": 1}:
        raise RuntimeError(f"unexpected receiver request counts: {counts}")
    for (agent, verb), count in sorted(counts.items()):
        print(f"[later audit] {agent} {verb}={count}")


def prepare(workspace: Path) -> None:
    audit = {
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Policy",
        "rules": [
            {
                "level": "Metadata",
                "namespaces": [NAMESPACE],
                "resources": [{"group": "apps", "resources": ["deployments"]}],
                "omitStages": ["ResponseStarted", "ResponseComplete"],
            },
            {"level": "None"},
        ],
    }
    (workspace / "audit.json").write_text(json.dumps(audit))
    config = {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "nodes": [
            {
                "role": "control-plane",
                "extraMounts": [
                    {
                        "hostPath": str(workspace / "audit.json"),
                        "containerPath": "/etc/kubernetes/kapsel-audit.json",
                        "readOnly": True,
                    }
                ],
                "kubeadmConfigPatches": [
                    json.dumps(
                        {
                            "kind": "ClusterConfiguration",
                            "apiServer": {
                                "extraArgs": {
                                    "audit-policy-file": "/etc/kubernetes/kapsel-audit.json",
                                    "audit-log-path": "/var/log/kubernetes/kapsel-audit.log",
                                    "audit-log-maxsize": "5",
                                },
                                "extraVolumes": [
                                    {
                                        "name": "audit-policy",
                                        "hostPath": "/etc/kubernetes/kapsel-audit.json",
                                        "mountPath": "/etc/kubernetes/kapsel-audit.json",
                                        "readOnly": True,
                                        "pathType": "File",
                                    },
                                    {
                                        "name": "audit-log",
                                        "hostPath": "/var/log/kubernetes",
                                        "mountPath": "/var/log/kubernetes",
                                        "pathType": "DirectoryOrCreate",
                                    },
                                ],
                            },
                        }
                    )
                ],
            }
        ],
    }
    (workspace / "kind.json").write_text(json.dumps(config))
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "agent-api", "namespace": NAMESPACE},
        "spec": {
            "replicas": 1,
            "minReadySeconds": 60,
            "progressDeadlineSeconds": 180,
            "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {
                "metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{"name": "api", "image": IMAGES[0]}]},
            },
        },
    }
    (workspace / "deployment.json").write_text(json.dumps(deployment))


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix="kapsel-later.")).resolve()
    cluster = f"kapsel-later-observation-{workspace.name.split('.')[-1].replace('_', '-')}"
    owned = False
    try:
        run("docker", "info", echo=False)
        run("kind", "version")
        run("kubectl", "version", "--client", "-o", "json")
        run("cargo", "test", "--locked", "--test", "later_observation", "--no-run", timeout=600)
        run("git", "rev-parse", "HEAD")
        hashes = source_hashes()
        (workspace / "source.sha256").write_text(hashes)
        print(hashes, end="")
        prepare(workspace)
        if cluster in run("kind", "get", "clusters").decode().splitlines():
            raise RuntimeError(f"refusing pre-existing cluster: {cluster}")
        owned = True  # Also clean up a partially created cluster.
        run(
            "kind",
            "create",
            "cluster",
            "--name",
            cluster,
            "--config",
            str(workspace / "kind.json"),
            "--image",
            NODE,
            "--kubeconfig",
            str(workspace / "kubeconfig"),
            "--wait",
            "120s",
            timeout=300,
        )
        env = {**os.environ, "KUBECONFIG": str(workspace / "kubeconfig")}
        for image in IMAGES:
            run("docker", "exec", f"{cluster}-control-plane", "crictl", "pull", image, timeout=180)
        run("kubectl", "create", "namespace", NAMESPACE, env=env)
        run("kubectl", "apply", "-f", str(workspace / "deployment.json"), env=env)
        run(
            "kubectl",
            "-n",
            NAMESPACE,
            "rollout",
            "status",
            "deployment/agent-api",
            "--timeout=300s",
            env=env,
            timeout=330,
        )
        if source_hashes() != hashes:
            raise RuntimeError("experiment inputs changed before execution")
        result = run(
            "cargo",
            "test",
            "--locked",
            "--test",
            "later_observation",
            "live_slow_rollout",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            env={**env, "KAPSEL_LATER_KIND": "1"},
            timeout=300,
        )
        (workspace / "result.log").write_bytes(result)
        if source_hashes() != hashes:
            raise RuntimeError("experiment inputs changed during execution")
        audit = run(
            "docker",
            "exec",
            f"{cluster}-control-plane",
            "cat",
            "/var/log/kubernetes/kapsel-audit.log",
            echo=False,
        )
        (workspace / "audit.jsonl").write_bytes(audit)
        check_audit(audit)
    finally:
        try:
            if owned:
                run("kind", "delete", "cluster", "--name", cluster, timeout=180)
        finally:
            print(f"[later evidence, keep private] {workspace}")


def interrupted(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


class LauncherTests(unittest.TestCase):
    def test_audit_requires_one_patch_and_only_one_followup_get(self):
        events = [
            {"stage": "RequestReceived", "userAgent": "kapsel-later-execution", "verb": "patch"},
            {"stage": "RequestReceived", "userAgent": "kapsel-later-followup", "verb": "get"},
        ]

        def check(items):
            data = b"\n".join(json.dumps(item).encode() for item in items)
            with contextlib.redirect_stdout(io.StringIO()):
                check_audit(data)

        check(events)
        for invalid in [events[:1], events + [events[1]], events + [events[0]]]:
            with self.assertRaises(RuntimeError):
                check(invalid)
        with self.assertRaises(RuntimeError):
            check(events + [{**events[1], "verb": "patch"}])

    def test_command_success_and_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run(sys.executable, "-c", "print('ok')"), b"ok\n")
            with self.assertRaises(subprocess.CalledProcessError):
                run(sys.executable, "-c", "raise SystemExit(7)")

    def test_command_deadline(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(TimeoutError):
            run(sys.executable, "-c", "import time; time.sleep(60)", timeout=1)

    def test_command_output_bound(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            run(sys.executable, "-c", "import sys; sys.stdout.write('x' * 9000000)", echo=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run regressions without Docker")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    else:
        signal.signal(signal.SIGTERM, interrupted)
        main()
