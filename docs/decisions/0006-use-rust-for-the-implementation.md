# Use Rust for the implementation

Status: accepted.

Kind: decision. Date: 2026-07-11.

Owns: Why Kapsel uses Rust and bounded dynamic allocation.

## Context

The gateway handles hostile receipt bytes, Kubernetes responses, SQLite state, cryptographic
material, filesystem paths, and diagnostics. These inputs vary in size, but memory safety alone does
not prevent resource exhaustion.

Rust provides the required cryptography, Kubernetes, SQLite, testing, and systems-I/O ecosystem
without requiring every capacity to become a fixed compatibility limit.

## Decision

Rust is Kapsel's implementation language. Apply the bounded, explicit-state rules in
[ADR 0001](0001-kapsel-style.md).

Kapsel performs no unbounded allocation derived from hostile input. Check named byte, count, depth,
time, and output budgets before allocation or work. Capacity exhaustion is a typed failure, not a
panic.

Static storage, caller-provided scratch space, arenas, and pre-sized buffers are preferred only when
the domain is genuinely fixed and they simplify review.

## Consequences

- Use maintained Rust libraries for cryptography, Kubernetes, SQLite, and hostile-input testing.
- Preserve original signed bytes and reject malformed or oversized input before expensive work.
- Test limits below, at, and above every public bound.
- Do not introduce another implementation language without a demonstrated technical or assurance
  need.
