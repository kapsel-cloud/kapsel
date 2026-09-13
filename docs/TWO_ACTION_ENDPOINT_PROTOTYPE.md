# Two approved actions through one endpoint

Status: isolated, maintainer-owned prototype; not adopted service behavior. This experiment asks
whether explicit selection and reconnectable retrieval need a durable pending queue. It keeps the
sole Deployment image capability, exactly two approved identities per run and one execution slot.
The [current-service baseline](MULTIPLE_PENDING_OPERATIONS.md) remains unchanged.

## Before implementation: two bounded candidates

1. **Two fixed application compositions, one journal.** Retain A/B's original signed snapshot grants
   outside the journal. Open one execution and one read handle for each identity. Route explicit
   selection and reads to the exact corresponding application. Existing gateway validation, worker
   exclusion, attempt permission and receipt storage remain the owners. Restart opens both
   authorities and serves reads without selecting work; the caller explicitly reselects the original
   identity to execute or recover. No durable format changes.
2. **Two journal-owned authority slots.** Store both exact signed grants and a selected identity in
   SQLite, then reconstruct the relevant application on demand. This would bind availability of
   original authority to the journal backup, but introduces grant custody, schema/version changes,
   routing validation and a new meaning for durable selection. It needs a new configuration and
   recovery contract even with a hard limit of two.

Choose candidate 1 for this experiment. Candidate 2 adds storage and authority semantics before the
workflow establishes a need. Neither option establishes application independence, preserves snapshot
freshness, nor authorizes conflicting effects after ambiguity.

## Prototype interface and bounds

The test-only endpoint uses one private Unix socket and one length-prefixed JSON request per
connection, with write-half-close. Commands are `select`, `status` and `receipt`, each with exactly
`operation_id`. The operator configures exactly A/B before starting the endpoint. No caller tuple,
grant, trust, path, lifecycle control or replacement approval is accepted. Unknown identities fail
closed. This is not the production service protocol, authentication or installation model.

`ACCEPTED` means only that this process owns a background task and the single execution slot. It can
precede insertion. `BUSY` creates no row or pending obligation; the caller retains that selection.
Status and original receipt reads route through the corresponding original authority. They neither
advance another identity nor acquire observations. Execution delegates to `Application::execute`.
Restart binds read access without automatic reconciliation: unlike the current service's startup, no
identity is chosen automatically. A persisted unfinished A remains visible, but requires explicit
reselection. The operator must preserve both original authorities and the one format-4 journal.
There is no queue, fairness policy, second durable store or automatic reapproval.

The surrounding caller/operator holds conflicting B after unresolved A or `UNKNOWN`. Releasing the
execution slot is not permission to send B. The prototype does not enforce that application-level
hold; different Deployment names alone do not prove independence. Exclusion applies only to this
selected local journal, not other journals, hosts or external writers.

## Reproduce

Run from the repository root:

```sh
python3 scripts/prototype-two-actions.py
```

The driver creates an exclusive scratch directory, runs independent A/B approvals, starts one
endpoint, selects actions, disconnects/reconnects, kills/restarts exact child processes at bounded
seams and retrieves frozen evidence. It deletes only its own scratch authority. The printed JSON
separates caller responses, selected journal facts and actual receiver HTTP requests. Approval and
selection timestamps are relative monotonic intervals in this controlled fixture, not human effort
or representative churn measurements. Approval-policy evaluation is outside this experiment.

The transport is a test-only shim: `kube::Client` emits HTTP requests to a tower mock which forwards
each request once over loopback HTTP. Before forwarding PATCH the shim can pause, allowing the
driver to verify durable `apply_started` and kill the process before any receiver mutation request.
Receiver HTTP counts, not shim calls, are the mutation evidence. No production transport, live
Kubernetes, power-loss or distributed coordination result follows.
[Production-client retry tests](../tests/application_retry.rs) supply separate real-HTTP evidence.

## Recorded run

[Raw outcomes](../tests/fixtures/two-action-endpoint-prototype.json) record base revision
`b22634d6eb289ab64ad7d32a145fed22b0c2c92f`, SHA-256 identities for both executable source files,
commands, caller frames, selected read-only journal columns, exact original receipt bytes, and
receiver HTTP requests. These are uncommitted prototype content identities, not invented commit
revisions. The run used macOS arm64, Rust 1.98.0 and Python 3.14.7. No cluster, credentials or
private grant bytes are retained. The first two GETs in every case acquire the independent operator
approvals; `independent` also has a final operator GET for its rejected replacement-approval probe.

| Case                                               | Caller/journal result                                                                                           | Actual HTTP PATCH requests |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------- |
| Independent A/B                                    | Both `SUCCEEDED`; original statuses and receipt bytes survive endpoint restart                                  | A=1, B=1                   |
| Same target and original snapshot                  | A succeeds; B freezes `NOT_ATTEMPTED / StaleApproval`, no receipt                                               | A=1, B=0                   |
| Transient A preflight                              | A stays `authorized`; B succeeds without changing A; caller reselects A                                         | A=1, B=1                   |
| Exit after `ACCEPTED`, before insertion            | A absent; A/B duplicate selections get `BUSY` before exit; original A is selectable after restart               | A=1, B=1                   |
| Exit while `authorized`, before preflight HTTP     | A visible as `IN_PROGRESS`; explicit reselection obtains a fresh attempt                                        | A=1, B=1                   |
| Exit after durable attempt, before HTTP            | A visible as `IN_PROGRESS`; reselection performs 30 observation GETs, freezes `UNKNOWN`; independent B proceeds | A=0, B=1                   |
| Exit after HTTP mutation, before response delivery | Attempt persists; reselection only observes, then returns `SUCCEEDED`                                           | A=1, B=1                   |
| `UNKNOWN`, conflicting B                           | Induced replacement-UID observation freezes A; caller/operator keeps B unsubmitted across restart               | A=1, B=0                   |
| `UNKNOWN`, independent B                           | Independently assessed B proceeds; original A result/receipt stay unchanged                                     | A=1, B=1                   |

The process-loss cases verify the actual persisted row and receiver PATCH count **before killing the
child**. Restart status/receipt reads produce no HTTP; they do not hide or automatically advance A.
The pre-send case intentionally loses one unsent permission. It never reconstructs permission from
`apply_started`. All terminations are exact child-process kills, not power-loss simulation.

Identical terminal submission returns `ACCEPTED` but adds no HTTP request. An extra caller tuple
field (`container`) is rejected as `invalid_request`: there is no caller tuple-replacement surface
in this prototype. An unapproved identity is rejected. Restart with a newly signed approval under
existing A makes A's status/receipt fail closed and its accepted execution task fail without HTTP; B
remains retrievable. Restoring A's exact original grant restores its unchanged receipt and journal
facts. This is a negative authority probe, not a permitted reapproval workflow.

For initial successful admission, A's approval-to-selection interval was about 35–49 ms. B's was
about 55–102 ms in the immediate/ordinary cases, and 29,170 ms while A's pre-send ambiguity
exhausted observation. The raw trace distinguishes `BUSY` attempts from `ACCEPTED` selections. The
same-target case deliberately invalidated B's snapshot through A's PATCH; independent targets had no
induced background churn. These are script timings from one fixture run, not human approval effort,
representative latency, natural churn frequency or an approval-policy comparison.

### Operator steps and caller bookkeeping

The runnable driver performs these separate roles; neither is an autonomous scheduler:

1. **Operator:** create the private scratch root and two exact proposals; run `approve-a` and
   `approve-b` separately. Each reads its named receiver target and signs its own snapshot grant.
   Preserve both original grants and the identity/tuple association. Start the same fixed endpoint
   configuration with both authorities and one journal.
2. **Caller:** retain A/B's stable identities and pending intent. Explicitly select A; each
   connection then closes. Open new connections for status and original receipt. Select B only under
   the surrounding workflow's independence/conflict decision, and retain B after `BUSY` or
   ambiguity.
3. **Operator:** at named fault seams kill the exact endpoint child and restart with the same two
   authorities and journal. No identity or configuration switching is needed between calls.
4. **Caller:** reconnect to read both identities; explicitly reselect unfinished A when appropriate.
   Compare returned terminal statuses and exact receipt bytes with the originals. Never mint a new
   identity to escape ambiguity or treat an empty execution slot as conflict permission.

The operator still owns authority preservation, journal availability and application independence.
The caller still owns durable pending intent, ordering, retry timing and conflict holds. In this
maintainer run those intentions live in the driver; no caller-crash durability claim is made.

## What changed in the workflow

Compared with the [current-service baseline](MULTIPLE_PENDING_OPERATIONS.md), B no longer fails just
because the endpoint is configured for A, and selecting B does not hide A's original result. The
operator provisions both authorities once rather than switching one configured identity between
calls. The caller supplies an existing identity rather than repeating its tuple. None of these
improvements requires durable pending acceptance or overlapping execution.

The cost is explicit multi-identity authority custody and routing: two execution handles, two read
handles, two original grants and a fixed identity association. Startup availability no longer waits
for recovery, but an unfinished action will not progress until the caller selects it. Storage format
4 is unchanged; original receipt bytes and provenance remain in the existing journal, while original
authority remains separately operator-owned. Losing that authority can make history inaccessible
even when the journal survives. A journal backup alone is not a complete recovery bundle.

**Recommendation: refine, do not adopt.** This is positive mechanical evidence for a small
multi-identity access boundary, not evidence for a queue or a production-ready endpoint. No user
study, authenticated Linux service adaptation, real Kubernetes run, host/disk-loss continuity,
power-loss durability or distributed conflict management was demonstrated.

Any adoption needs a separately approved, bounded implementation slice: canonical
[EFFECT_GATEWAY](EFFECT_GATEWAY.md) and [service](KAPSEL_SERVICE.md) contract decisions for identity
visibility and restart selection; an application/API and operator-configuration owner for exactly
retained authorities; storage validation and backup requirements preserving original provenance and
receipt bytes; explicit handling of existing single-identity callers and format-4 journals;
unchanged one-slot/no-queue bounds; and independent authority/recovery review plus Linux/process and
owning live-lane evidence before any live claim. This report approves none of those production
decisions.

## Validation

The recorded nine-case command above passed. `./scripts/format.sh`, `./scripts/ci-local.sh`
(including links, Python lint, Clippy, Rust tests and documentation tests) and `git diff --check`
passed. The default Rust gate compiles but deliberately ignores the operator-only child test; the
Python command is the owning executable workflow check. Linux-only process tests were not run on
macOS. No live lane was run. Independent review is a separate acceptance step, not a property
inferred from these passing checks.

### Corrected macOS frame-read race

Diagnosis retained an `invalid_request` response to a valid receipt request after restart with
restored authority and unchanged finalized journal rows. The prototype's nonblocking listener passed
an accepted socket directly to synchronous `read_exact` and an EOF check. On macOS the accepted
socket inherits nonblocking mode; setting read/write timeouts does not clear it. A read before the
prefix, remaining body or write-half-close arrives can therefore return `WouldBlock`, which the
prototype maps to `invalid_request` without accessing the application.

This mechanism was reproduced outside Kapsel with a standalone standard-library Rust Unix socket
probe on macOS arm64 / Rust 1.98.0, not inferred from pass rates. Despite two-second timeouts, the
accepted socket returned `WouldBlock` for an empty prefix in 2.5 microseconds and for the EOF check
after a complete valid receipt frame in 0.5 microseconds. Explicit blocking mode made a missing
half-close wait for the configured 100 ms probe timeout (observed 102 ms); half-close then yielded
EOF. A separate C host probe read `F_GETFL`: listener, accepted socket and accepted socket after
both timeout setters all had flags `0x6`, including `O_NONBLOCK` (`0x4`). Explicitly clearing the
flag removed it. The host `accept(2)` manual describes the new socket as having the listener's
properties. The installed Rust 1.98.0 standard-library source confirms that `UnixListener::accept`
delegates to the socket implementation, whose macOS branch calls `libc::accept` and sets only
close-on-exec; `set_timeout` only sets a socket option, while `set_nonblocking` separately uses
`FIONBIO`. See the
[standard-library socket source](https://doc.rust-lang.org/1.98.0/src/std/sys/net/connection/socket/unix.rs.html).

The fix explicitly establishes blocking mode at the prototype-owned `read_frame` boundary before
setting the unchanged two-second read/write timeouts. No caller retry, delivery sleep, authority,
execution-slot or recovery change was added. These remain per-I/O socket timeouts, not an aggregate
frame deadline; a slow caller can still occupy this test-only synchronous endpoint. The production
service instead binds a Tokio listener and uses awaited stream I/O under an aggregate deadline in
`crates/kapseld/src/server/runtime.rs`; it does not use this reader and was not changed.

```sh
cargo test --locked --test two_action_endpoint_prototype frame_tests -- --nocapture
```

The regression forces an accepted socket nonblocking on every Unix host and withholds bytes or EOF
until the reader changes mode or returns. This synchronizes the failure without a timing guess: old
code rejects the valid request; corrected code accepts all four prefix/body/EOF split points.
Additional tests retain malformed, short, zero-length, oversized and trailing-input rejection,
accept the 4096-byte maximum, and verify that missing half-close still times out. Before the fix,
two tests failed and the rejection matrix passed; after it, all three passed. Ten fresh independent
workflows and the regenerated nine-case run also passed after executable formatting. Raw fixture
bytes are the driver's actual stdout, with both executable hashes and every returned receipt digest
verified; passing repetitions are bounded supporting evidence, not a nondeterminism proof.

The original failed read did not retain its syscall error, so its exact failing read stage is not
known. An earlier status-equality failure had no retained response; this correction does not prove
that historical failure had the same cause. Linux-only process tests and live Kubernetes remain
unrun on this host; forcing socket mode in the regression does not establish Linux execution
coverage.
