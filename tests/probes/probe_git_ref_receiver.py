#!/usr/bin/env python3
"""Executable receiver probe, not a Kapsel capability or a replay policy."""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

REF = "refs/heads/approved"
GIT_VERSION = "git version 2.55.0"
RECEIVER_ID = "fixture-receiver-1"


@dataclass(frozen=True)
class Approval:
    operation_id: str
    receiver_id: str
    ref: str
    old: str
    new: str


def git(env, *args, check=True):
    result = subprocess.run(
        ["git", *map(str, args)],
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if check and result.returncode:
        raise AssertionError(f"git {args[0]} failed: {result.stderr[-2000:]}")
    return result


def setup(root, env):
    sender = root / "sender"
    receiver = root / "receiver.git"
    git(env, "init", "--quiet", "--bare", receiver)
    git(env, "--git-dir", receiver, "config", "receive.denyNonFastForwards", "true")
    git(env, "--git-dir", receiver, "config", "receive.denyDeletes", "true")
    git(env, "--git-dir", receiver, "config", "kapsel.probeIdentity", RECEIVER_ID)
    git(env, "init", "--quiet", sender)
    git(env, "-C", sender, "config", "user.name", "Probe")
    git(env, "-C", sender, "config", "user.email", "probe@example.invalid")
    for name, base in (("A", None), ("B", "A"), ("C", "A"), ("D", "B")):
        if base:
            git(env, "-C", sender, "checkout", "--quiet", "--detach", base)
        (sender / "payload").write_text(name + "\n")
        git(env, "-C", sender, "add", "payload")
        git(env, "-C", sender, "commit", "--quiet", "-m", name)
        git(env, "-C", sender, "tag", name)
    ids = {name: git(env, "-C", sender, "rev-parse", name).stdout.strip() for name in "ABCD"}
    git(
        env,
        "-C",
        sender,
        "-c",
        "protocol.file.allow=always",
        "push",
        f"file://{receiver}",
        f"{ids['A']}:{REF}",
    )
    for hook in ("pre-receive", "post-receive"):
        path = receiver / "hooks" / hook
        path.write_text(
            "#!/bin/sh\nprintf 'invoked\\n' >> \"$GIT_PROBE_"
            + hook.upper().replace("-", "_")
            + '"\ncat >/dev/null\n'
            + f'if [ "$GIT_PROBE_KILL_AT" = "{hook}" ]; then kill -KILL "$PPID"; fi\n'
        )
        path.chmod(0o700)
    return sender, receiver, ids


def observed(env, receiver):
    return git(env, "--git-dir", receiver, "rev-parse", REF).stdout.strip()


def counts(root, trace):
    packets = trace.read_text() if trace.exists() else ""
    # Receiver-side packet trace counts update commands, not object-pack frames.
    requests = len(re.findall(r"receive-pack< [0-9a-f]{40,64} [0-9a-f]{40,64} " + REF, packets))

    def invocations(name):
        path = root / name
        return path.read_text().count("invoked\n") if path.exists() else 0

    return {
        "update_requests": requests,
        "pre_receive": invocations("pre"),
        "post_receive": invocations("post"),
    }


def validate_approval(env, sender, receiver, approval, proposed):
    if proposed != approval or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", approval.operation_id):
        return False
    if (
        approval.receiver_id
        != git(env, "--git-dir", receiver, "config", "--get", "kapsel.probeIdentity").stdout.strip()
    ):
        return False
    if approval.ref != REF or approval.old == approval.new:
        return False
    if not all(re.fullmatch(r"[0-9a-f]{40}", oid) for oid in (approval.old, approval.new)):
        return False
    if git(env, "-C", sender, "cat-file", "-t", approval.new).stdout.strip() != "commit":
        return False
    return (
        git(
            env,
            "-C",
            sender,
            "merge-base",
            "--is-ancestor",
            approval.old,
            approval.new,
            check=False,
        ).returncode
        == 0
    )


def push(env, root, sender, receiver, old, new, kill_at="none"):
    trace = root / "trace"
    trace.unlink(missing_ok=True)
    sending = dict(env, GIT_TRACE_PACKET=str(trace), GIT_PROBE_KILL_AT=kill_at)
    result = git(
        sending,
        "-C",
        sender,
        "-c",
        "protocol.file.allow=always",
        "push",
        "--porcelain",
        f"--force-with-lease={REF}:{old}",
        f"file://{receiver}",
        f"{new}:{REF}",
        check=False,
    )
    return result, counts(root, trace)


def main():
    with tempfile.TemporaryDirectory(prefix="kapsel-git-probe-") as temp:
        root = Path(temp)
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(
            HOME=temp,
            XDG_CONFIG_HOME=temp,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0",
            GIT_AUTHOR_DATE="2001-01-01T00:00:00+0000",
            GIT_COMMITTER_DATE="2001-01-01T00:00:00+0000",
            GIT_PROBE_PRE_RECEIVE=str(root / "pre"),
            GIT_PROBE_POST_RECEIVE=str(root / "post"),
        )
        version = git(env, "--version").stdout.strip()
        if version != GIT_VERSION:
            raise SystemExit(f"probe requires {GIT_VERSION}; found {version}")
        sender, receiver, ids = setup(root, env)
        contender = root / "contender"
        git(env, "clone", "--quiet", "--no-local", sender, contender)
        assert (
            git(env, "-C", sender, "merge-base", "--is-ancestor", ids["A"], ids["B"]).returncode
            == 0
        )
        assert ids["B"] != ids["C"]
        approved = Approval("operation-1", RECEIVER_ID, REF, ids["A"], ids["B"])
        assert validate_approval(env, sender, receiver, approved, approved)
        assert not validate_approval(
            env,
            sender,
            receiver,
            approved,
            Approval("operation-1", RECEIVER_ID, REF, ids["A"], ids["C"]),
        )
        assert not validate_approval(
            env,
            sender,
            receiver,
            approved,
            Approval("operation-2", RECEIVER_ID, REF, ids["A"], ids["B"]),
        )
        assert not validate_approval(
            env,
            sender,
            receiver,
            approved,
            Approval("operation-1", "other-repository", REF, ids["A"], ids["B"]),
        )
        assert not validate_approval(
            env,
            sender,
            receiver,
            approved,
            Approval("operation-1", RECEIVER_ID, REF, ids["B"], ids["C"]),
        )
        non_descendant = Approval("operation-3", RECEIVER_ID, REF, ids["B"], ids["C"])
        assert not validate_approval(env, sender, receiver, non_descendant, non_descendant)
        blob = git(env, "-C", sender, "rev-parse", f"{ids['B']}:payload").stdout.strip()
        non_commit = Approval("operation-4", RECEIVER_ID, REF, ids["A"], blob)
        assert not validate_approval(env, sender, receiver, non_commit, non_commit)
        results = []

        def record(case, acknowledgement, expected, request, hooks):
            present = observed(env, receiver)
            assert present == ids[expected], (case, present, ids[expected])
            assert request == hooks["update_requests"], (case, hooks)
            results.append(
                {
                    "case": case,
                    "sender_ack": acknowledgement,
                    "receiver_ref": expected,
                    "original_attempt_requests": request,
                    "hook_totals": {k: hooks[k] for k in ("pre_receive", "post_receive")},
                }
            )

        # Two senders prepared at A. Only one can advance the branch in this ordering.
        first, counts_first = push(env, root, sender, receiver, ids["A"], ids["B"])
        assert first.returncode == 0 and counts_first == {
            "update_requests": 1,
            "pre_receive": 1,
            "post_receive": 1,
        }
        record("A to B", "success", "B", 1, counts_first)
        second, counts_second = push(env, root, contender, receiver, ids["A"], ids["C"])
        assert second.returncode != 0 and counts_second == {
            "update_requests": 0,
            "pre_receive": 1,
            "post_receive": 1,
        }
        record("stale A to C", "rejected before send", "B", 0, counts_second)
        non_ff, non_ff_counts = push(env, root, contender, receiver, ids["B"], ids["C"])
        assert non_ff.returncode != 0 and non_ff_counts["update_requests"] == 1
        assert non_ff_counts["post_receive"] == 1
        record("current lease cannot rewrite branch", "remote rejected", "B", 1, non_ff_counts)

        # Receiver is reset only by the fixture operator, never by a candidate caller.
        git(env, "--git-dir", receiver, "update-ref", REF, ids["A"], ids["B"])
        record(
            "ack lost before send",
            "none",
            "A",
            0,
            {"update_requests": 0, "pre_receive": non_ff_counts["pre_receive"], "post_receive": 1},
        )
        interrupted, interrupted_counts = push(
            env, root, sender, receiver, ids["A"], ids["B"], kill_at="pre-receive"
        )
        assert interrupted.returncode != 0 and interrupted_counts["update_requests"] == 1
        assert interrupted_counts["pre_receive"] == non_ff_counts["pre_receive"] + 1
        assert interrupted_counts["post_receive"] == 1
        record("connection lost before ref update", "transport failure", "A", 1, interrupted_counts)
        independent, independent_counts = push(env, root, contender, receiver, ids["A"], ids["B"])
        assert independent.returncode == 0
        record(
            "later B from another sender",
            "none for original",
            "B",
            0,
            dict(independent_counts, update_requests=0),
        )
        git(env, "--git-dir", receiver, "update-ref", REF, ids["A"], ids["B"])
        sent, sent_counts = push(
            env, root, sender, receiver, ids["A"], ids["B"], kill_at="post-receive"
        )
        assert sent.returncode != 0 and sent_counts == {
            "update_requests": 1,
            "pre_receive": non_ff_counts["pre_receive"] + 3,
            "post_receive": 3,
        }
        record("connection lost after update", "transport failure", "B", 1, sent_counts)
        onward, onward_counts = push(env, root, contender, receiver, ids["B"], ids["D"])
        assert onward.returncode == 0
        record("independent B to D", "success (independent writer)", "D", 1, onward_counts)
        git(env, "--git-dir", receiver, "update-ref", REF, ids["A"], ids["D"])
        record(
            "operator resets D to A",
            "not a sender request",
            "A",
            0,
            dict(onward_counts, update_requests=0),
        )
        again, again_counts = push(env, root, sender, receiver, ids["A"], ids["B"])
        assert again.returncode == 0 and again_counts == {
            "update_requests": 1,
            "pre_receive": non_ff_counts["pre_receive"] + 5,
            "post_receive": 5,
        }
        record("ABA permits second A to B", "success", "B", 1, again_counts)
        print(
            json.dumps(
                {
                    "git": version,
                    "transport": "file:// bare receiver, fixed full ref",
                    "environment": "isolated HOME/global/system config; receive hooks enabled",
                    "ids": ids,
                    "observations": results,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
