# Kapsel Style

> Small interfaces. Explicit states. Bounded inputs. Assertions for our mistakes. Typed errors for
> hostile reality.

Status: frozen.

Kind: design. Authority: engineering doctrine.

Owns: Rust shape, naming, bounds, assertions, errors, comments, dependencies, and local hygiene.

Does not own: Proof semantics, technical scope, architecture ownership, test strategy, or task
status.

## Priorities

1. Correct authority and effect boundaries before convenient interfaces.
2. Explicit state before implicit transitions.
3. Bounded work before optimistic allocation.
4. Types before boolean facts.
5. Names before comments.
6. Assertions for programmer errors.
7. Typed errors for hostile input and operating failures.
8. Pure verification before I/O.
9. Small deep interfaces before reusable frameworks.
10. Tests that protect contracts, not implementation shape.

Kapsel adapts Tiger Style to security-sensitive Rust. Allocation is allowed. Unbounded allocation
derived from hostile input is not. Static allocation is useful where a component's domain is truly
fixed; it is not a project-wide goal. Storage-engine-specific rules are not imported by costume.
Rust is the implementation language under
[ADR 0006](decisions/0006-use-rust-for-the-implementation.md).

## Untrusted input

Untrusted bytes must never:

- panic the gateway or inspector;
- allocate or decompress without an enforced bound;
- acquire authority from their own contents;
- trigger network access during offline verification; or
- advance evidence state without the required external fact.

Check declared sizes and checked arithmetic before allocation or decompression. Unknown critical
semantics fail closed.

## Types and states

Keep these facts conceptually distinct:

```text
bounded request
  -> authorized operation
  -> durable mutation attempt
  -> provider acceptance
  -> receiver observation
  -> classified outcome
  -> signed disclosure
  -> inspected under supplied trust
```

Not every stage needs a public wrapper, but signatures and local types must not collapse the
concepts. Provider acceptance cannot become a receiver outcome; signature authentication cannot
become trust or truth.

Do not represent proof accumulation as a bag of booleans. Use typed stages, result enums, and
exhaustive state machines. Keep public evidence state separate from internal synchronization state.
Avoid wildcard matches in security-sensitive enums when a new variant requires a policy decision.

## Bounds and units

Every hostile or durable structure that can grow needs a named, enforced bound or a documented
reason it is externally bounded. Candidate names include:

```text
OPERATION_COUNT_MAX
KUBERNETES_FACT_BYTES_MAX
STATEMENT_BYTES_MAX
RECEIPT_BYTES_MAX
TRUST_BYTES_MAX
TEXT_BYTES_MAX
OBSERVATION_ATTEMPTS_MAX
PROVIDER_RESPONSE_BYTES_MAX
```

Owning contracts select numeric values. Do not guess them in style guidance.

Use normal Rust casing and owner-first, qualifier-last names where they improve lookup:

```rust
const RECEIPT_BYTES_MAX: usize = /* contract value */;
let observation_attempt_count = observations.len();
let retry_delay_ms = schedule.next_delay_ms();
let evaluation_time_unix_s = trust.evaluation_time_unix_s();
let receipt_bytes = response.receipt_bytes();
```

Use checked arithmetic and checked integer conversions when hostile lengths are combined. Enforce
both per-item and cumulative budgets before reserving, allocating, reading, or decompressing. A
documented maximum that is not enforced is not a bound.

## Allocation and resource budgets

Prefer caller-visible limits for hostile-input entry points. Offline inspection should make its
resource contract obvious without reading ambient configuration:

```rust
pub fn inspect_receipt(
    receipt: &[u8],
    trust: &[u8],
    evaluation_time_unix_s: i64,
    limits: InspectionLimits,
) -> InspectionReport;
```

Numeric values belong to the owning contract. APIs may group or type limits differently, but callers
must be able to determine the applicable resource ceiling.

Dynamic containers are acceptable after the relevant declared and cumulative sizes pass their
bounds. `Vec::with_capacity(declared_items)` is safe only after `declared_items` is checked. Prefer
a pre-sized buffer, bounded arena, caller-provided scratch space, or fixed-capacity collection when
it makes a genuinely fixed component simpler and more auditable—not to imitate another system's
allocation model.

Do not recurse over attacker-controlled nesting. Use an explicit depth budget and iterative parsing
or traversal. Bound diagnostic count and bytes as deliberately as evidence input; capacity
exhaustion produces a typed failure or an explicit deterministic report condition, never a panic or
silent loss of a decisive fact.

## Assertions and errors

Assertions are for facts controlled by valid internal code:

- construction invariants;
- impossible internal transitions;
- consistency between objects created in one trusted operation; and
- assumptions immediately before a durable write.

Prefer several precise assertions over a compound expression. Security-critical correctness uses
always-on `assert!`, not `debug_assert!`.

Typed errors are for:

- hostile request, receipt, or trust input;
- unsupported purposes or algorithms;
- provider responses and network ambiguity;
- trust configuration and keys;
- SQLite and filesystem behavior;
- current or evaluation time;
- operator configuration; and
- any other reality outside valid internal code.

Do not assert signature validity, receipt validity, or request shape. The inspector and gateway must
not panic on untrusted bytes.

## Control flow and authority

Parent functions schedule phases. Leaf functions perform bounded work. A gateway or inspector parent
should make the contract order visible; leaf helpers must not secretly read ambient trust, time,
environment, network, filesystem, or configuration.

Offline inspection receives receipt bytes, trust bytes, explicit evaluation time, and resource
limits. Pass authority explicitly. Keep inspection order and iteration order deterministic,
including which bounded failure is reported first.

A function performs one phase at one level of abstraction. Function length is a review prompt, not a
correctness metric. Split when phases, ownership, or side effects mix—not to satisfy a counter.

## Modules and facades

A module earns its interface when deleting it would spread policy, erase a durable state/format
owner, mix I/O into pure logic, invert dependencies, or remove a meaningful deterministic test seam.
It does not earn an interface because functions share a prefix.

Prefer small deep facades. Avoid `util`, `utils`, `misc`, and `common` modules. Add crates only
after a dependency boundary proves real.

## Naming

Use names that state which fact becomes established:

```text
parse_receipt_structure
authenticate_receipt_signature
evaluate_receipt_trust
```

Avoid proof-sensitive names such as `process`, `handle`, `check`, `valid`, `data`, and `ctx` when a
precise domain noun exists. `result` is acceptable only when one short-lived result is in view.

Use newtypes for identities and units when confusion is plausible: `OperationId`, `AuthorizationId`,
`ReceiptDigest`, `ReceiptBytes`, `UnixSeconds`.

## Public documentation

Public API comments describe caller-visible contracts:

- the fact established;
- required input state and ordering;
- bounds;
- side effects and authority used;
- meaningful failure behavior; and
- important non-claims.

They do not narrate Rust syntax or repeat the item name. Use `# Errors` when several caller-visible
causes need explanation. Public functions receiving untrusted input should not expose
caller-triggerable panic behavior.

Crate/module docs state what the surface owns and refuses to own. They do not duplicate the README
or backlog.

Documentation coverage is objective at the public boundary:

- every externally reachable public module, type, trait, variant, field, constant, and function has
  rustdoc;
- bare `pub` is reserved for that externally reachable API; crate-internal seams use explicit
  `pub(crate)` or narrower visibility, and unreachable public items are denied;
- every public `Result`-returning function has a meaningful `# Errors` section;
- a public function that can panic has a `# Panics` section, though caller-triggerable panic should
  normally be removed rather than documented;
- intra-doc links resolve without private-item or broken-link warnings; and
- lint exceptions are narrow, locally justified, and never used to make an undocumented public API
  pass.

The workspace denies missing public documentation, unreachable public visibility, and missing
error/panic sections. The strict rustdoc build denies warnings. These checks belong to the canonical
local gate and therefore to the managed pre-commit hook; documentation consistency is not left to
reviewer taste.

Rustdoc section headings are scan aids, not decoration. Kapsel uses these exact level-one headings
in this order when applicable:

1. `# Errors` for caller-observable `Result` failure conditions;
2. `# Panics` for caller-reachable panic conditions;
3. `# Safety` for caller obligations on unsafe APIs;
4. `# Cancellation safety` when cancelling an async operation changes durable or external state;
5. `# Performance` or `# Complexity` only for a meaningful caller-visible cost or bound;
6. `# Platform-specific behavior` when supported behavior differs by platform; and
7. `# Examples` for copyable, doctested Rust usage.

Use plural `# Examples`, `# Errors`, and `# Panics`; do not invent shortened headings such as
`# Error`, `# Panic`, or `# Perf`. A section must be non-empty. Examples use Rust doctest fences and
avoid `unwrap()` or `expect()` so copied code keeps failure handling explicit. Safe APIs do not
carry `# Safety`; unsafe APIs always do, though this workspace forbids unsafe code.

`kapsel-dev` owns project-local tidy checks that rustfmt, rustc, rustdoc, and Clippy cannot express.
Hard tidy rules require objective syntax, stable rule codes, and allowed/denied fixtures. Advisory
style audit findings exit successfully and remain review input. Human review owns whether prose is
accurate, sufficient, and worth the reader's attention.

## Private comments

Comments spend scarce attention. First try a better name, smaller scope, explicit type, state enum,
precise assertion, or clearer control flow.

Use a private comment only for context code cannot carry:

- why a branch exists;
- the invariant protected;
- wire-format subtlety;
- security or crash-recovery reasoning;
- non-obvious performance behavior;
- compatibility workaround; or
- why the obvious alternative is wrong.

Good:

```rust
// Authenticate the original statement bytes. Re-encoding parsed fields could
// change the signed representation.
```

Bad:

```rust
// Verify the receipt.
```

Future/workaround comments name a task or decision and explain why current code is correct now. Do
not create a subjective comment-quality linter.

## Dependencies and unsafe code

Dependencies are design choices. Prefer maintained cryptographic and encoding libraries over custom
implementations. Keep core surfaces narrow and `pub(crate)` unless callers need a contract.

The workspace forbids unsafe code. Any future exception requires an explicit security review and
durable decision; do not weaken the workspace lint casually.

## Source formatting and readability

Rustfmt is the baseline, not evidence that an implementation is readable. A reviewer should be able
to identify a module's owned fact, parent control flow, state transitions, authority inputs, and
side effects without reconstructing them from imports or tests.

- Separate imports, types, implementations, parent operations, leaf helpers, and tests into visible
  groups.
- Prefer explicit cross-module imports over glob imports. Glob imports are acceptable in tightly
  scoped tests or an intentional prelude, not as a way to hide a wide interface.
- Keep the happy path and failure ordering visible in parent functions; move mechanical encoding or
  operating-system detail behind named leaf functions.
- Name fallback values and test fixtures when inline construction obscures which invariant matters.
- Use module documentation to state what the module owns and refuses to own when file names alone do
  not make that clear.
- Apply these expectations to experimental code. Disposable semantics do not justify shallow,
  compressed, warning-heavy, or unexplained implementation.

Authored Rust source has a strict 100-byte physical-line limit. Rustfmt's `max_width` is advisory,
so an independent repository gate enforces the limit. Reshape method chains and macro arguments
explicitly. Write embedded SQL as readable multiline SQL rather than hiding a whole query in one
source line. Split long exact literals with `concat!` when their runtime bytes must remain
unchanged. Do not shorten precise names or introduce helper abstractions solely to satisfy the
limit.

Wrap Markdown prose at 100 columns. Exempt tables, URLs, code blocks, and lines whose wrapping would
reduce clarity. Prefer a mechanical paragraph wrap over a custom formatter or lint framework.

## Enforcement

Hard gates should remain objective and low-noise: rustfmt, the strict Rust source-width check,
compiler/clippy, public API docs where configured, no unintended unsafe code, bounded parser tests,
contract vectors, deterministic snapshots, and local links. Naming, module depth, useful comments,
and abstraction quality remain review judgments.

See [Testing](TESTING.md), [Build](BUILD.md), [Review](REVIEW.md), and
[ADR 0001](decisions/0001-kapsel-style.md).
