# V1 technical direction

Status: accepted prospective direction; not current release scope or a compatibility promise.

Kind: design. Authority: intended production shape, package-extraction triggers, integration order,
and v1 proof categories.

Owns: The target resident effect-gateway architecture and the conditions under which new packages
and public interfaces become justified.

Does not own: Current 0.1 behavior, the active Kubernetes experiment, task status, exact sandbox
API, commercial scope, or a v1 release authorization.

## Product definition

Kapsel v1 is a customer-resident effect gateway for autonomous systems. It turns bounded caller
intent into one durably tracked provider attempt, recovery without blind retry, receiver
observation, and an inspectable signed receipt.

Kubernetes is the first reference integration, not Kapsel's permanent identity. The durable effect
lifecycle, authority separation, receiver-bounded result, and receipt are the product.

```text
agent or workflow
  -> CLI, MCP, or versioned local interface
       -> customer-resident kapseld
            -> deep kapsel application
                 -> bounded capability
                 -> customer-held provider authority
                 -> durable lifecycle and recovery
                 -> receiver observation
                 -> signed receipt
                      -> optional managed configuration, upgrades, and receipt indexing
```

Provider credentials and execution authority remain customer-resident by default. A managed Kapsel
service may coordinate gateways and index bounded receipt projections; it does not become the source
of provider truth or silently move customer authority into the cloud.

## Milestone separation

### Developer alpha: 0.1.x

The current package proves one concrete operation through the local CLI, stdio MCP adapter,
disposable-kind demonstration, and signed receipt. Its Rust, CLI, MCP, configuration, journal, and
receipt interfaces remain prototype-scoped.

### Public sandbox: post-0.1 technical slice

One independently deployed sandbox exposes fixed non-consequential scenarios through a narrow Rust
service and reuses the existing `Application`. Its accepted [HTTP contract](SANDBOX_API.md) and
[deployment contract](SANDBOX_DEPLOYMENT.md) own hosted admission, isolation, reconnectable public
projection, bounded scheduling, cleanup, and receipt presentation before implementation. It is a
demonstration surface, not the production resident interface.

### Production v1

A customer-resident `kapseld` process owns supported local admission, durable execution, restart and
upgrade recovery, bounded concurrency, provider authority, grant and trust configuration, receipt
publication, health, diagnostics, and a versioned local interface. Production v1 requires a real
workflow pilot and an evidence-selected KAP-0046 implementation decision; the target described here
does not authorize the release by itself.

## Package strategy

Package seams follow independent deployment, dependency isolation, or multiple real consumers. A
concept being generic does not by itself justify a package.

### Current workspace

```text
kapsel       product library plus local CLI and MCP executable
kapsel-dev   unpublished repository tooling
fuzz         excluded hostile-input package
```

The root `kapsel` package remains one deep product module. `Application` is the proven shared
interface used by the CLI and MCP adapters. Authorization, SQLite lifecycle, the concrete Kubernetes
adapter, classification, receipt construction, and publication remain private implementation.

### Next earned package

```text
kapsel-sandbox -> kapsel
```

The accepted public sandbox contracts now justify `kapsel-sandbox` for the following implementation
packet as an independently deployable consumer with a one-way dependency on `kapsel`. It owns public
admission, capacity, scheduling, reconnectable projection, retention, and cleanup. It does not reuse
the gateway journal as its run database or expose local receipt paths. Contract acceptance does not
create the package or authorize another dependency direction.

### Production package

```text
kapseld -> kapsel
```

`kapseld` becomes justified only when a real pilot requires a resident process. It owns the
supported local transport, process lifecycle, configuration, health, concurrency, upgrades, and
operational diagnostics. It does not absorb effect lifecycle or provider classification from
`kapsel`.

The existing `kapsel` executable remains in the root package until independent release cadence,
installation size, or dependency isolation proves a separate CLI package useful.

## Generic data rule

Stabilize generic concepts only where their cross-capability meaning is already known:

- protocol and envelope version;
- operation and capability identity;
- idempotency rules;
- durable lifecycle vocabulary;
- receiver-bounded result categories;
- transport error classes;
- receipt signature metadata and non-claims; and
- migration and compatibility rules.

Keep these concrete per capability:

- request parameters and validation;
- grant canonicalization and exact matching;
- provider attempt semantics;
- receiver evidence;
- result classification; and
- classifier-complete receipt statement fields.

Do not manufacture genericity with arbitrary JSON values, key-value evidence, shell input, dynamic
plugins, or a public provider trait. A generic envelope must preserve a typed concrete payload and
classifier-complete concrete evidence.

## Integration order

1. **CLI** for operator provisioning, local operation, diagnostics, and inspection.
2. **Stdio MCP** for bounded request-only agent integration.
3. **Public sandbox HTTP** for fixed demonstration scenarios only.
4. **Resident local interface** for supported production workflows when a pilot earns `kapseld`.
5. **Managed Kapsel** for optional configuration, upgrades, fleet health, and receipt indexing.
6. **Grafik consumer adapter** for visualization of bounded public projections without authority.
7. **One evidence-selected operation** only when repeated workflows select the same concrete need.
8. **Another provider** only when a second production adapter exposes a repeated seam.

## Intended v1 compatibility surfaces

A v1 proposal must explicitly choose and support:

- capability request version and operation identity rules;
- authorization grant version, canonicalization, trust, and rotation;
- durable lifecycle and recovery semantics;
- `SUCCEEDED`, `FAILED`, and `UNKNOWN` meaning;
- receipt envelope, signature, inspection, migration, and non-claims;
- CLI versioning and deprecation;
- supported MCP protocol and tool behavior;
- resident local interface, reconnect, idempotency, and error behavior;
- journal migration, backup, rollback, and downgrade handling;
- supported OS, architecture, Kubernetes, installation, upgrade, and support windows; and
- release signing, provenance, SBOM, vulnerability, and incident procedures.

Private Rust modules, the private provider test seam, sandbox API, Grafik mapping, and internal SQL
schema are not compatibility surfaces unless a later owner explicitly promotes them.

## V1 proof matrix

The existing deterministic, subprocess, live-kind, release-artifact, reproducibility, simulation,
fuzz, and informational coverage lanes remain distinct. Production v1 additionally requires:

- N-1 to N journal migration, rollback, and downgrade decisions;
- receipt compatibility vectors for every supported version;
- daemon restart and upgrade at every durable lifecycle state;
- bounded concurrency, load, saturation, and resource use;
- credential, grant-trust, and receipt-key rotation;
- filesystem, Kubernetes RBAC, namespace, and process isolation review;
- installation, upgrade, rollback, and uninstall on every supported platform;
- controlled failure against the supported Kubernetes matrix;
- managed-service disconnect without corruption of resident execution; and
- at least one pilot-workflow acceptance gate.

Coverage percentage remains informational. Enforce owner-specific proof for every lifecycle
transition, crash window, receiver classification, public error class, migration path, supported
adapter, and public wire-version compatibility case.

## Trigger-gated package backlog

| Candidate            | Trigger required before extraction                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| `kapsel-sandbox`     | Accepted sandbox contracts requiring one independently deployable service                              |
| `kapseld`            | Real pilot requiring a supported resident process                                                      |
| Separate CLI package | Independent release cadence, installation size, or dependency-isolation evidence                       |
| `kapsel-receipt`     | Independent verifier needing receipt logic without gateway and Kubernetes dependencies                 |
| `kapsel-protocol`    | Two independently maintained clients sharing one stable wire model                                     |
| Client SDK           | Multiple external integrations requiring the same supported client behavior                            |
| Kubernetes package   | Measured dependency isolation or multiple concrete capability modules needing the same adapter package |
| Public provider seam | Two production provider adapters exposing the same repeated interface                                  |
| Storage seam         | A second durable lifecycle implementation with requirements SQLite cannot satisfy                      |

Until its trigger passes, each candidate remains design context rather than active implementation.
Do not create placeholder packages, pass-through interfaces, or compatibility obligations merely to
reserve names.

## Explicit non-goals

- Exactly-once real-world effects
- Arbitrary shell, manifest, patch, provider credential, or lifecycle input from agents
- Generic provider or capability plugin marketplace
- Generic policy language
- Broad Kubernetes administration
- Cloud-held customer provider credentials by default
- Grafik as receipt authority, event storage, or provider client
- General observability or logs platform
- Compliance or production claims unsupported by explicit evidence
- Stable Rust internals solely because a crate is published
