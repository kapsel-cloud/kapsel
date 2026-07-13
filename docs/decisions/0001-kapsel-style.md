# Adapt Tiger Style to Kapsel

Status: accepted.

Kind: decision. Date: 2026-07-11.

Owns: Why Kapsel uses explicit states, bounds, and typed failures without copying storage-engine
rules literally.

## Context

Kapsel parses hostile bytes, handles cryptographic material, recovers durable operation state, calls
a consequential provider, and emits security-sensitive claims. Idiomatic Rust does not by itself
force bounded work, explicit transition ordering, or a clear distinction between programmer errors
and adversarial input.

Literal TigerBeetle rules target a storage engine with different allocation and latency constraints.
Copying them would add ceremony without sharpening Kapsel's actual risks.

## Decision

Adopt the discipline, not the costume:

- small, deep interfaces;
- explicit state machines and visible transition ordering;
- named bounds on hostile input, I/O, time, and durable growth;
- assertions for programmer-controlled invariants;
- typed errors for input, operating, and adversarial failures;
- deterministic tests around mutation and recovery seams;
- normal Rust naming; and
- comments only for context code cannot carry.

Allocation remains allowed after bounds are checked. Function length remains a review prompt, not a
mechanical limit. Exact operation semantics live in owner documents and tests, not the style guide.

## Consequences

The project accepts explicit code in exchange for auditable state and authority transitions. It does
not add custom lint infrastructure until repeated objective drift justifies it.
