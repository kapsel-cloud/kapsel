# Submit, reconnect, and retrieve evidence

The connection is temporary. The operation ID is what you keep.

This guide shows how to save that ID before submission, return from a fresh session, and retrieve
the original evidence. Use it on an operator-provisioned Linux service. The same caller flow works
for `kubernetes.set_deployment_image` and `git.transition_ref`, but their results mean different
things.

The operator supplies approved IDs, a stable nonsecret label for the retained journal, and the
confined caller identity. The fixed client and MCP bridge must be installed. The Python example
below also needs Python 3 and the checkout's
[`fresh_session_caller.py`](../../examples/fresh_session_caller.py). It is a source example, not a
file bundled in the release archive.

Run it under the confined caller UID and effective `kapsel-service-callers` group. It launches the
fixed MCP bridge without receiver credentials or service configuration. For a first disposable
installation, use [Getting started](../getting_started.md).

## Discover an approval

Create a new caller-owned private directory, then read one catalog or history page:

```sh
mkdir -m 700 caller-state
caller='python3 examples/fresh_session_caller.py'
$caller --service host-a-journal-a --reference caller-state/operation.ref approved
$caller --service host-a-journal-a --reference caller-state/operation.ref history
```

Replace `host-a-journal-a` with the operator's label for this retained journal. Keep that label with
the same journal across restart. It is a custody convention, not cryptographic service
authentication. Pass `next_cursor` as the final argument to read another page.

Choose an ID from the operator's approvals. Listing does not admit or select work.

## Retain the identity, then submit

Substitute the approved ID. Use a new reference file:

```sh
$caller --service host-a-journal-a --reference caller-state/operation.ref start approved-operation-id
$caller --service host-a-journal-a --reference caller-state/operation.ref read
```

`start` saves and syncs the reference before submission. If the process dies just after submitting,
the next session still knows which operation to read. Saving only after a successful response would
lose that connection precisely when you need it.

Once the reference exists, `start` refuses to run again, including after a lost response or definite
refusal. The reference contains version `1`, the service label, and `operation_id`. It identifies
what to ask about. It is not authority or evidence.

`ADMITTED` confirms retained responsibility, not completion. Only one worker executes at a time.
`BUSY` refuses new work. It is not a queue entry. This conservative example retains its reference
even after refusal. Investigate with the operator rather than replacing the identity or rerunning
`start`.

Do not interpret shell exit zero as receiver success. Read the service result.

## Reconnect and follow execution guidance

Open a new shell or discard conversational context. Each invocation starts a fresh bridge process
and uses the saved reference:

```sh
caller='python3 examples/fresh_session_caller.py'
$caller --service host-a-journal-a --reference caller-state/operation.ref read
```

| Status or guidance                              | Next step                                                                    |
| ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `IN_PROGRESS`, `active`                         | Wait and read again. Activity does not promise progress.                     |
| `waiting_for_worker`                            | Wait and re-read before same-ID selection. There is no automatic queue.      |
| Caller-owned `resume_required / select_same_id` | Explicitly resume the same ID.                                               |
| `operator_required`                             | Ask the operator to repair material or storage before resumption.            |
| `NOT_FOUND` after uncertain submission          | Read the same ID and investigate. An unsettled admission can still complete. |
| `NOT_ATTEMPTED`                                 | Inspect the rejection with the operator. There is no effect receipt.         |
| `SUCCEEDED`, `FAILED`, or `UNKNOWN`             | Inspect the terminal result and retrieve available evidence.                 |

Only for caller-owned `IN_PROGRESS / resume_required / select_same_id`:

```sh
$caller --service host-a-journal-a --reference caller-state/operation.ref resume
```

The example reads status first and refuses other dispositions. It never creates another ID to
recover the original operation. A crash between saving the reference and submission can leave an
unsent action. The example stops for investigation rather than silently resubmitting.

Missing history, unavailable original trust, or a mismatched journal label needs operator
investigation. History listing does not rebuild a lost reference or grant permission to select work.

## Retrieve the original receipt

Once evidence is ready:

```sh
$caller --service host-a-journal-a --reference caller-state/operation.ref receipt
```

The response's `service` object contains `receipt_hex` and `receipt_sha256`. Compare both bytes and
digest across retrievals. Reads do not observe the receiver or revise a terminal result.

For a file suitable for offline inspection, use the
[fixed-client export and inspection procedure](operator.md#submit-and-inspect). The operator
supplies independent trust and evaluation time. Export refuses an existing destination. A failed
export does not change completion.

## Interpret the effect's result

Stop dependent mutations on `UNKNOWN` and hand the original evidence to an operator. Later receiver
health cannot improve the frozen result. A corrective action requires its own approval and reasoning
about current state, not an automatic replacement ID or rollback.

Kubernetes success is the
[bounded rollout classification](../reference/kubernetes_effect.md#result-meaning), not proof of
application health or causation. Git success is
[acknowledged ref acceptance](../reference/git_effect.md), not hook, CI, or deployment completion.

To run another independent approval, wait for the worker to retire and use a separate new reference.
The operator must assess independence against unresolved history. A free worker or terminal
`UNKNOWN` does not clear a conflict.

## Interface reference

- [Fixed client](../reference/service.md#fixed-service-client): ID-only shell commands and exclusive
  file export.
- [MCP bridge](../reference/mcp.md): the same resident lifecycle through bounded stdio tools.
- [Service protocol](../reference/service.md#version-1-socket-contract): response shapes,
  pagination, and bounds.
- [Evidence formats](../reference/evidence_formats.md): signature, trust, and offline inspection
  rules.

Service protocol version `1`, MCP protocol `2025-11-25`, caller-reference version `1`, journal
format `6`, and signed grant/receipt versions are independent. Effect tags do not appoint trust or
select signed versions. Tests for this example and the receiver journeys are listed in
[Qualification](../contributing/qualification.md#kapsel-service-candidate).
