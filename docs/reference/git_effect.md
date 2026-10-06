# Git ref-transition contract

This reference defines `git.transition_ref`: authority, dispatch, acknowledgement, observations, and
signed evidence. The [effect gateway](effect_gateway.md) defines shared admission and receipt
completion. For preparation commands, use the [Git operator guide](../guides/git_transition.md).

## Authorized transition

Kapsel exposes `git.transition_ref` through the service's existing ID-only approval, submission,
status, history and receipt flow. `kapsel provision-git-grant` performs read-only preflight before
signing; `kapsel inspect` recognizes purpose-separated Git receipts. Git uses operator-owned,
complete local bare sender and receiver repositories, one `refs/heads/approved` branch, and pinned
Git 2.55.0. Preparation and content review belong to the operator. The receiver requires deletion
and non-fast-forward refusal, and a matching `kapsel.repositoryId`. Paths, executable, local
transport and configuration never come from the signed grant or caller.

The authenticated Git grant binds authorization ID, operation ID, repository ID, exact full branch,
and distinct nonzero lowercase 40-byte SHA-1 commit IDs A and B. Its magic prefixes are
`KAPSEL-GIT-REF-GRANT-STATEMENT-V1\0` and `KAPSEL-GIT-REF-GRANT-V1\0`, with purpose
`kapsel.git-ref-transition-grant.v1`. Statement tags 1–6 carry those fields in that order. It uses
the [bounded ordered-record framing](evidence_formats.md#receipt-and-inspection) and
purpose-separated Ed25519 signature construction, with 2 KiB statement and 4 KiB envelope ceilings.
Kubernetes grants retain their original purposes.

## Preflight and dispatch

Preflight validates custody, restricted configuration, commit types, ancestry and the current ref.
The prepared value is bound to its originating receiver. An immutable verified grant binding and a
fresh committed attempt together issue one consumable dispatch permission. The command sends only B
to the fixed ref with the exact A lease. Each subprocess has a 15-second deadline and independent 16
KiB stdout/stderr ceilings; cancellation kills its process group. This does not contain
operator-controlled hooks that deliberately escape the group. Repository custody walks are bounded
by 100,000 entries and depth 32. No generic Git command or remote interface is exposed.

After the marker, recovery only observes. A dropped unsent permission is still attempted history;
A→B→A never permits another send. Preflight uncertainty remains unfinished rather than claiming a
known stale ref. Fatal object/ancestry reads remain resumable after material repair; Git's fatal
object-read status does not distinguish absent objects from permission failures. A successful
non-commit type read or ancestry exit 1 establishes invalid objects. Definite stale-ref or
invalid-object refusal is `NOT_ATTEMPTED`.

## Result meaning

A fresh per-ref fast-forward acknowledgement means `SUCCEEDED` for that ref transition. Local
pre-send rejection or receiver rejection means `FAILED` for the transition, not absence of hook side
effects. Up-to-date, transport failure, missing acknowledgement and malformed output mean `UNKNOWN`.
The present ref is a separate commit/missing/unknown observation. Seeing B cannot attribute an
uncertain attempt: another sender can establish B after Kapsel drops an unsent permission. An exact
lease only checks the expected current value; it does not establish ancestry or a safe replay
policy. Separate preflight ancestry checks and observation-only recovery remain necessary.
Pre/post-receive loss can leave the ref at A or B while both sender outcomes lack acknowledgement.
Neither outcome proves hook completion.

## Signed grant and receipt versions

Git evidence is frozen before signing and committed with terminal state in the same SQLite journal.
The statement and envelope prefixes are `KAPSEL-GIT-REF-STATEMENT-V1\0` and
`KAPSEL-GIT-REF-RECEIPT-V1\0`; the purpose is `kapsel.git-ref-transition-receipt.v1`. They reuse the
8 KiB statement, 16 KiB receipt and explicit trust/time inspection bounds. Statement tags are:

1. Operation ID, authorization ID, grant signer ID and exact grant SHA-256 (tags 1–4).
2. Repository ID, full ref, old commit and new commit (tags 5–8).
3. Fixed `git-exact-lease`, acknowledgement, observed-ref kind and observed commit (tags 9–12).
4. Derived attribution, result and fixed non-claims (tags 13–15).

An absent observed commit is an empty record. Acknowledgement tokens are `updated`,
`rejected_before_send`, `receiver_rejected` and `unknown`; observed kinds are `commit`, `missing`
and `unknown`. Attribution is `acknowledged_update` only for `updated`, otherwise `not_established`.
It describes the original acknowledgement, not causation of the later observed ref. Inspection
recomputes attribution and result and requires canonical bytes. Trust uses the
[trust encoding](evidence_formats.md#receipt-and-inspection) with the Git purpose explicitly
appointed. Original receipts are never upgraded or re-signed on reconnect. Non-claims are exactly
`no-hook-delivery;no-ci;no-deployment;no-complete-capture;no-witnessing;not-production`.
