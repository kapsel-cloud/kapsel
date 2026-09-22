# Kapsel contributor guide

This repository owns Kapsel's code, current technical contracts, tests, release evidence, and public
technical claims. Linear is the ground truth for accepted direction, planned work, priorities,
assignments, acceptance decisions, and progress. Do not create a parallel roadmap or status ledger
in the repository. A planned change does not describe implemented behavior until code, contracts,
and evidence agree.

## Start here

1. Check Git status and preserve unrelated work.
2. Read [`README.md`](README.md), [`docs/SCOPE.md`](docs/SCOPE.md), and
   [`docs/INDEX.md`](docs/INDEX.md).
3. Read [ADR 0001](docs/decisions/0001-kapsel-style.md) for the design criterion, then follow
   [Contributing](CONTRIBUTING.md), including its
   [complexity review](CONTRIBUTING.md#complexity-review).
4. Read the direct contract, implementation, tests, and vectors for the surface you will change.
5. Run `./scripts/format.sh`; it formats Markdown, Rust, then Python and expands Markdown tables.
   Python uses four-space indentation and the pinned rules in `ruff.toml`. Formatting does not fix
   lint findings; follow [Python tooling](CONTRIBUTING.md#python-tooling).
6. Choose the narrowest useful gate from [`docs/BUILD.md`](docs/BUILD.md).

## Find technical truth

[`docs/SCOPE.md`](docs/SCOPE.md) owns the current product boundary.
[`docs/EFFECT_GATEWAY.md`](docs/EFFECT_GATEWAY.md) owns authorization, lifecycle, receiver-result,
recovery, and receipt semantics. [`docs/INDEX.md`](docs/INDEX.md) routes every other question.

The published `v0.3.0-preview.1` resident-service preview and older `v0.2.0` beta are different
promises. Their release pages identify exact bytes and qualification. Current source is not a new
release, and publication does not establish production support.

When code and an owner disagree:

1. stop the conflicting edit;
2. compare the direct owner with `docs/SCOPE.md`;
3. correct the canonical owner before implementation; and
4. leave unresolved contradictions visible.

Contracts define behavior. Decisions explain why. Guides describe commands that actually exist.
Tests provide executable evidence.

## Keep the direction visible

Read [Why Kapsel exists](README.md#why-kapsel-exists) as the public technical motivation. Kapsel is
being built as a controlled execution component beneath fallible autonomous systems. Kubernetes is
the first proving ground, not its permanent identity or a general reliability-service promise.

Preserve the separation between authorization, execution evidence, and decision quality. Improve
enforced guarantees, concrete interactions, or implementation simplicity. Technical exploration may
answer a precise unresolved question with executable evidence; it needs no customer- discovery gate.
Follow its bounded Linear scope and do not promote a prototype into the active capability set or
generic platform without an explicit adoption decision and contract update.

## Keep the product narrow

- Keep `kubernetes.set_deployment_image` as the only implemented product capability until an
  explicit adoption changes its owner. Separately scoped research does not silently extend that
  promise.
- Keep credentials, grants, trust, signing material, paths, and lifecycle controls outside caller
  input.
- Keep authorization, durable ordering, recovery, receiver classification, `UNKNOWN`, and receipts
  inside the deep effect-gateway module.
- Treat MCP as one fixed stdio adapter, not Kapsel's identity or a generic interface.
- Do not add runtime plugins, a provider SDK, policy language, workflow engine, queue, hosted
  control plane, dashboard, second capability, or speculative package seam.
- Never turn timeout, request acceptance, transport completion, or provider ambiguity into receiver
  success or failure.
- Keep public content reproducible and technical. Omit private operational or company context.

## Documentation

Write for a technical reader who is new to this mechanism.

- Keep the high-level idea visible: narrow authority, durable state before the effect,
  observation-only recovery after ambiguity, honest `UNKNOWN`, and an inspectable receipt.
- Explain why a mechanism exists before listing its exact rules.
- Start with the shortest useful mental model or runnable path, then link deeper.
- Use short sections, concrete examples, diagrams, and plain language. Define unavoidable jargon.
- Separate tutorials, how-to guides, explanations, and reference when combining them makes the page
  harder to use.
- Prefer one canonical owner over repeated summaries. Delete deprecated documentation and retired
  proposals from the current tree. Move still-valid rules into their current owner, repair inbound
  links, and rely on Git history rather than archives or tombstone pages.
- Keep the tone calm and interesting. Fun comes from the engineering ideas and examples, not from
  weakening limits or forcing jokes.

Security and compatibility contracts may be dense when precision requires it. Entry points and
learning material should not make readers cross that density before they understand the idea.

## Validate the change

Documentation-only work still checks local links and anchors, focused terminology, formatting, and
`git diff --check`. Code or contract changes add the smallest owner-specific test before broader
gates. The live Kubernetes lane is separate and requires Docker plus `kind`.

Before finishing, run the narrowest relevant proof and then the owning broader gate when practical.
State what changed, what ran, and what remains unproved. Do not commit or push unless asked.
