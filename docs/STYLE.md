# Kapsel Rust style

> Small interfaces. Explicit states. Bounded inputs. Assertions for our mistakes. Typed errors for
> hostile reality.

Status: current.

This page contains Kapsel-specific rules. Rustfmt, Clippy, rustdoc, and the repository tidy gate own
ordinary mechanics.

## Priorities

1. Preserve authority and effect boundaries.
2. Make durable states and transitions explicit.
3. Bound hostile input and resource use before allocation.
4. Keep receiver facts distinct from provider acceptance and transport outcomes.
5. Prefer small, deep interfaces over reusable frameworks.
6. Test contracts rather than implementation shape.

Kapsel adapts Tiger Style to security-sensitive Rust. Allocation is allowed after the relevant bound
is enforced. Static allocation is not a project-wide goal.

## Untrusted input

Untrusted bytes must never:

- panic the gateway or inspector;
- allocate, recurse, or decompress without an enforced bound;
- acquire authority from their own contents;
- trigger network access during offline verification; or
- advance evidence state without the required external fact.

Use checked arithmetic and checked integer conversions before combining hostile lengths. Bound both
individual items and cumulative work. Bound diagnostics as deliberately as input.

## Types and states

Keep these facts distinct:

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

Use typed stages and exhaustive enums where collapsing facts could change security meaning. Provider
acceptance is not a receiver outcome; signature authentication is not trust or truth. Avoid wildcard
matches when a new enum variant requires a policy decision.

Pass authority, time, trust, paths, and limits explicitly. Leaf helpers must not secretly read them
from the environment, filesystem, network, or ambient configuration.

## Assertions and errors

Use always-on assertions for invariants controlled by valid internal code: construction invariants,
impossible transitions, and consistency between values created in one trusted operation.

Return typed errors for hostile input, signatures, trust, provider responses, time, configuration,
filesystem or SQLite behavior, and other operating failures. Never assert receipt validity, request
shape, or any fact controlled by a caller or provider.

## Interfaces and modules

A module earns an interface when removing it would spread policy, mix I/O with pure logic, erase a
durable format/state owner, invert dependencies, or remove a useful deterministic test seam. Shared
prefixes alone do not justify a module.

Prefer `pub(crate)` or narrower visibility until callers need a stable contract. Avoid `util`,
`utils`, `misc`, and `common`. Add a crate only when a real dependency boundary exists.

Name functions for the fact they establish, such as `authenticate_receipt_signature`, rather than
`process`, `handle`, `check`, or `validate`. Use identity and unit newtypes when confusion is
plausible.

## Public documentation

Public API documentation states caller-visible contracts: required input, bounds, authority, side
effects, failures, and important non-claims. It does not narrate syntax or repeat the item name.

Every externally reachable public item requires rustdoc. Public `Result` functions require a useful
`# Errors` section. Caller-reachable panic requires `# Panics`, though removing the panic is usually
better. Unsafe APIs require `# Safety`; this workspace currently forbids unsafe code.

Use these headings, when applicable, in this order:

1. `# Errors`
2. `# Panics`
3. `# Safety`
4. `# Cancellation safety`
5. `# Performance` or `# Complexity`
6. `# Platform-specific behavior`
7. `# Examples`

Examples must compile as doctests and handle errors without `unwrap()` or `expect()`.

## Comments and dependencies

First prefer a better name, type, state enum, assertion, or smaller scope. Use a private comment
only to explain an invariant, security or crash-recovery subtlety, compatibility workaround, or why
the obvious alternative is wrong.

Prefer maintained cryptographic and encoding libraries over custom implementations. Dependencies are
design choices, not conveniences. Any future unsafe-code exception requires an explicit security
review and durable decision.

## Formatting and enforcement

Authored Rust has a strict 100-byte physical-line limit. Reshape expressions instead of shortening
precise names or adding an abstraction solely to satisfy the limit. Write embedded SQL as readable
multiline SQL. Wrap Markdown prose at 100 columns; tables, URLs, and code blocks are exempt when
wrapping would reduce clarity.

Run:

```sh
cargo make fmt
cargo make tidy
cargo make check
```

Hard gates stay objective: formatting, source width, compiler and Clippy warnings, public API docs,
unsafe code, parser bounds, contract vectors, deterministic snapshots, and local links. Naming,
module depth, comments, and abstraction quality remain review judgments.

See [Testing](TESTING.md), [Build](BUILD.md), [Review](REVIEW.md), and
[ADR 0001](decisions/0001-kapsel-style.md).
