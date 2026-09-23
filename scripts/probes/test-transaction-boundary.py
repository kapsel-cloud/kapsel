#!/usr/bin/env python3
"""Disposable PostgreSQL 17 transaction-boundary experiment. Requires Docker."""

import pathlib
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
IMAGE = "postgres:17@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232"
CONTAINER = "kapsel-transaction-probe-" + uuid.uuid4().hex[:12]
HOST = ""


def connection(role: str) -> list[str]:
    args = ["docker", "exec", "-i"]
    if role != "postgres":
        args += ["-e", f"PGPASSWORD=disposable-{role}"]
    args += [CONTAINER, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", role]
    if role != "postgres":
        args += ["-h", HOST]
    return args + ["-d", "postgres"]


def docker(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["docker", *args], input=input_text, text=True, capture_output=True, timeout=45
    )
    if result.returncode:
        raise RuntimeError(f"docker {args[:2]}: {result.stderr.strip()}")
    return result.stdout.strip()


def psql(role: str, sql: str, *, success: bool = True) -> str:
    result = subprocess.run(
        connection(role),
        input=sql,
        text=True,
        capture_output=True,
        timeout=45,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(f"{role}: {sql!r}: {result.stdout} {result.stderr}")
    return result.stdout.strip() if success else result.stderr.strip()


def start_query(role: str, sql: str) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        connection(role),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    process.stdin.write(sql)
    process.stdin.close()
    return process


def ready() -> None:
    for _ in range(50):
        result = subprocess.run(
            [
                "docker",
                "exec",
                CONTAINER,
                "psql",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-XAtc",
                "SELECT 1",
            ],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            time.sleep(2)
            return
        time.sleep(0.2)
    raise AssertionError("PostgreSQL did not become ready")


def check(label: str, actual: str, expected: str) -> None:
    assert actual == expected, f"{label}: {actual!r} != {expected!r}"
    print(f"PASS {label}: {actual}")


def wait_for_alice(wait_event: str) -> None:
    for _ in range(40):
        count = psql(
            "postgres",
            "SELECT count(*) FROM pg_catalog.pg_stat_activity "
            f"WHERE usename='alice' AND wait_event='{wait_event}';",
        )
        if int(count) > 0:
            return
        time.sleep(0.1)
    raise AssertionError(f"alice never entered {wait_event}")


def main() -> None:
    global HOST
    docker("run", "-d", "--name", CONTAINER, "-e", "POSTGRES_PASSWORD=disposable-admin", IMAGE)
    try:
        ready()
        HOST = docker("exec", CONTAINER, "hostname", "-i").split()[0]
        psql("postgres", (ROOT / "transaction-boundary.sql").read_text())
        wrong_password = connection("alice")
        wrong_password[wrong_password.index("-e") + 1] = "PGPASSWORD=wrong"
        assert (
            subprocess.run(
                wrong_password, input="SELECT 1;", text=True, capture_output=True, timeout=10
            ).returncode
            != 0
        )
        print("PASS database rejects wrong password on container-network TCP")
        check(
            "public function execute revoked",
            psql(
                "postgres",
                "SELECT count(*) FROM pg_catalog.pg_proc AS p, "
                "pg_catalog.aclexplode(coalesce(p.proacl, "
                "pg_catalog.acldefault('f', p.proowner))) AS a "
                "WHERE p.oid='reservation.consume(text, integer)'::regprocedure "
                "AND a.grantee=0 AND a.privilege_type='EXECUTE';",
            ),
            "0",
        )
        check("mallory authenticated", psql("mallory", "SELECT session_user;"), "mallory")
        for sql in (
            "SELECT * FROM reservation.budget;",
            "UPDATE reservation.budget SET remaining = 99;",
            "CREATE TABLE reservation.injection (x integer);",
            "SET ROLE reservation_owner;",
            "SET SESSION AUTHORIZATION alice;",
        ):
            assert psql("mallory", sql, success=False), sql
        print("PASS privilege escalation: direct read/write, schema CREATE, owner role refused")
        assert psql("mallory", "SELECT reservation.consume('parallel', 3);", success=False)
        assert psql("alice", "SELECT reservation.consume('parallel', 4);", success=False)
        check(
            "unmatched attempts leave budget intact",
            psql("postgres", "SELECT remaining FROM reservation.budget;"),
            "10",
        )

        # First writer retains the identity row lock until commit. Second waits, then reads result.
        first = start_query(
            "alice",
            "BEGIN; SELECT reservation.consume('parallel', 3); SELECT pg_sleep(2); COMMIT;\n",
        )
        time.sleep(0.5)
        second = start_query("alice", "SELECT reservation.consume('parallel', 3);\n")
        wait_for_alice("transactionid")
        assert second.poll() is None, "concurrent duplicate did not wait for identity lock"
        first.wait(timeout=15)
        second.wait(timeout=15)
        assert first.returncode == second.returncode == 0
        assert first.stdout is not None and second.stdout is not None
        original = next(line for line in first.stdout.read().splitlines() if line.startswith("{"))
        check(
            "concurrent duplicate returns committed result", second.stdout.read().strip(), original
        )
        check(
            "one budget mutation",
            psql("postgres", "SELECT remaining FROM reservation.budget;"),
            "7",
        )
        assert psql("alice", "SELECT reservation.consume('parallel', 4);", success=False)
        assert psql("alice", "SELECT reservation.consume('too-large', 11);", success=False)
        check(
            "failed precondition leaves approval",
            psql(
                "postgres",
                "SELECT consumed FROM reservation.approval WHERE operation_id='too-large';",
            ),
            "f",
        )
        check(
            "changed payload rejected after commit",
            psql("postgres", "SELECT count(*) FROM reservation.result;"),
            "1",
        )

        # A function result is visible to its transaction before COMMIT, not to other readers.
        check(
            "explicit rollback",
            next(
                line
                for line in psql(
                    "alice", "BEGIN; SELECT reservation.consume('rollback', 2); ROLLBACK;"
                ).splitlines()
                if line.startswith("{")
            ),
            '{"units": 2, "remaining": 5, "operation_id": "rollback"}',
        )
        check(
            "rollback leaves no result",
            psql(
                "postgres", "SELECT count(*) FROM reservation.result WHERE operation_id='rollback';"
            ),
            "0",
        )

        # Loss of the client response after a committed call is resolved by same-ID retrieval.
        lost = psql("alice", "SELECT reservation.consume('lost', 1);")
        check(
            "response loss same-ID retrieval",
            psql("alice", "SELECT reservation.consume('lost', 1);"),
            lost,
        )

        # Kill the database process before and after COMMIT; use the same container/data directory.
        before = start_query(
            "alice",
            "BEGIN; SELECT reservation.consume('precrash', 2); SELECT pg_sleep(30); COMMIT;\n",
        )
        wait_for_alice("PgSleep")
        docker("kill", CONTAINER)
        before.wait(timeout=10)
        docker("start", CONTAINER)
        ready()
        check(
            "crash before commit has no transition",
            psql(
                "postgres", "SELECT count(*) FROM reservation.result WHERE operation_id='precrash';"
            ),
            "0",
        )
        after = start_query(
            "alice",
            "BEGIN; SELECT reservation.consume('postcrash', 2); COMMIT; SELECT pg_sleep(30);\n",
        )
        wait_for_alice("PgSleep")
        # Confirm COMMIT from a separate transaction before the kill, not from the function return.
        check(
            "other transaction observes commit",
            psql(
                "postgres",
                "SELECT count(*) FROM reservation.result WHERE operation_id='postcrash';",
            ),
            "1",
        )
        docker("kill", CONTAINER)
        after.wait(timeout=10)
        docker("start", CONTAINER)
        ready()
        check(
            "crash after commit returns original",
            psql("alice", "SELECT reservation.consume('postcrash', 2);"),
            psql(
                "postgres", "SELECT payload FROM reservation.result WHERE operation_id='postcrash';"
            ),
        )

        # A controlled host-side file write does not roll back with the database transaction.
        with tempfile.TemporaryDirectory(prefix="kapsel-outside-transaction-") as directory:
            path = pathlib.Path(directory) / "physical-work"
            # The external write occurs while the database transaction remains open.
            process = subprocess.Popen(
                connection("alice"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdin is not None
            process.stdin.write("BEGIN; SELECT reservation.consume('outside', 1);\n")
            process.stdin.flush()
            wait_for_alice("ClientRead")
            check(
                "function return is not committed",
                psql(
                    "postgres",
                    "SELECT count(*) FROM reservation.result WHERE operation_id='outside';",
                ),
                "0",
            )
            path.write_text("external effect\n")
            process.stdin.write("ROLLBACK;\n")
            process.stdin.close()
            assert process.wait(timeout=10) == 0
            check("external file survives rollback", path.read_text().strip(), "external effect")
            check(
                "database did roll back",
                psql(
                    "postgres",
                    "SELECT count(*) FROM reservation.result WHERE operation_id='outside';",
                ),
                "0",
            )
        print("PASS fixture isolated; PostgreSQL container will be removed")
    finally:
        docker("rm", "-f", CONTAINER)


if __name__ == "__main__":
    main()
