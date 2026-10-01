# One caller, two effects

Use the same resident-service caller for `kubernetes.set_deployment_image` and `git.transition_ref`.
This guide exercises current source. The published v0.3.0-preview.1 contains neither Git nor the MCP
bridge; these steps do not qualify a production installation.

## Disposable source exercise

On Linux with the repository Rust toolchain, Python 3, OpenSSL and an explicitly selected Git
2.55.0, run from the checkout:

```sh
cargo build --locked -p kapsel --bin kapsel
cargo build --locked -p kapsel-daemon --features test-harness
KAPSEL_TEST_INSPECT="$PWD/target/debug/kapsel" \
  cargo test --locked -p kapsel-daemon --features test-harness --test linux_process \
  mcp_bridge_loss_at_admission_and_completion_retains_one_receiver_mutation -- --exact
python3 tests/qualification/run_git_service.py --git /absolute/path/to/git
```

These fixtures use private disposable roots, not installed paths or existing receiver resources. The
Kubernetes case uses a loopback HTTP receiver, not a cluster. It loses caller acknowledgement,
reconnects through the real bridge/service, resumes the original ID after service loss and checks
one PATCH and original evidence. The Git cases use fresh caller processes and real Git transitions.
They interrupt execution, resume the same ID, and compare original receipts after removing receiver
and signing material. Neither lane proves power-loss or installed-systemd behavior. See
[build and test](BUILD.md#git-transition-service) for the separate receiver gates.

## The same commands for either approval

For an operator-provisioned service, run under its confined caller identity. The operator supplies a
stable retained-journal label and the two independent approved IDs; the caller supplies no receiver
configuration. Follow [Kubernetes preparation](KAPSEL_SERVICE_OPERATOR.md) or
[Git preparation](GIT_REF_TRANSITION.md#operator-preparation), not the test-harness overrides.

```sh
mkdir -m 700 caller-state
caller='python3 examples/fresh_session_caller.py'
# Read one catalog/history page. Pass next_cursor as the final argument for another page.
$caller --service host-a-journal-a --reference caller-state/k8s.ref approved
$caller --service host-a-journal-a --reference caller-state/k8s.ref history
# Substitute the IDs supplied by the operator. Each reference is created before submission.
$caller --service host-a-journal-a --reference caller-state/k8s.ref start approved-k8s-id
$caller --service host-a-journal-a --reference caller-state/k8s.ref read
```

Only one worker executes at a time. Repeat `read` until the first operation completes; `ADMITTED` is
not completion. For interrupted work, follow the read/resume steps below before continuing. Do not
use shell exit zero as receiver success. Stop dependent work on `UNKNOWN`. Once the worker is free,
explicitly select the separately approved, independent Git operation:

```sh
$caller --service host-a-journal-a --reference caller-state/git.ref start approved-git-id
```

A `BUSY` refusal is not admission, and this conservative example retains the reference even after
refusal. Investigate with the operator rather than rerunning `start` or replacing the identity.

Discard conversational context or open a new shell. These invocations each start a new bridge
process and use only the caller-owned reference:

```sh
caller='python3 examples/fresh_session_caller.py'
$caller --service host-a-journal-a --reference caller-state/k8s.ref read
$caller --service host-a-journal-a --reference caller-state/git.ref read
# Only for IN_PROGRESS with caller-owned resume_required / select_same_id:
$caller --service host-a-journal-a --reference caller-state/git.ref resume
# Once evidence is ready, retrieve it again without selecting or observing the receiver:
$caller --service host-a-journal-a --reference caller-state/k8s.ref receipt
$caller --service host-a-journal-a --reference caller-state/git.ref receipt
```

Use the same `resume` command with the Kubernetes reference when its disposition permits. `UNKNOWN`
stops dependent mutations; later receiver health or ref movement cannot improve the frozen result.
Git success is acknowledged ref acceptance, not hook/CI/deployment success. Kubernetes success is
the bounded rollout classification, not proof of causation. Compare both returned `receipt_hex` and
`receipt_sha256` across retrievals. For offline signature inspection, export to a new file and
supply independent trust and time using the
[inspection procedure](KAPSEL_SERVICE_OPERATOR.md#submit-and-inspect).

A reference contains version `1`, the operator-provided `service` label and `operation_id`. It is
not authority, evidence, a portable global identity or cryptographic service authentication. Keep it
with the same journal across restart. Missing history or mismatched custody requires operator
investigation, never a replacement ID or automatic replay. History listing does not rebuild a lost
reference or grant permission to select an operation.

## Surface and version ownership

| Surface                         | Concrete use                                                                                       |
| ------------------------------- | -------------------------------------------------------------------------------------------------- |
| `kapsel-service-client`         | Fixed ID-only socket commands and exclusive receipt-file export for shell callers.                 |
| `kapsel-service-mcp`            | The same resident lifecycle for stdio tool callers, with no caller paths or credentials.           |
| `fresh_session_caller.py`       | Read-first process example retaining an ID before submission; no second lifecycle store.           |
| `kapsel operate` / `kapsel mcp` | Local operator-configured Kubernetes execution without a Linux resident service; not Git adapters. |
| `kapsel inspect`                | Offline inspection of original Kubernetes and Git receipts under independently supplied trust.     |

The service application owns admission, status, history, execution guidance, and receipt retrieval.
Each effect retains its own receiver facts. The
[version-1 socket contract](KAPSEL_SERVICE.md#version-1-socket-adoption-contract) owns response
shapes and bounds; [MCP](MCP.md) owns its wrapper. Authenticated catalog/status/history entries
carry an explicit `effect`; missing IDs and inaccessible history carry no invented effect. Receipt
responses return original bytes, not a normalized replacement receipt.

Service protocol version `1`, MCP protocol `2025-11-25`, caller-reference version `1`, journal
format `6`, and signed grant/receipt versions are independent. The effect tag does not select a
signed version or appoint trust. Kubernetes grant v1/v2 and receipt v2/v3 retain their original
interpretations; Git grant/receipt v1 uses separate purposes. The
[effect contract](EFFECT_GATEWAY.md#exact-snapshot-approval) owns those exact bytes. No signed
bytes, journal layout or original evidence are rewritten by these caller projections.
