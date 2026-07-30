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

## Current product cycle

The verified v0.2 mechanism now supports one bounded product-first cycle without becoming a general
platform commitment:

1. decide and accept one real fixed-input public crash-recovery proof using the existing sandbox
   contracts and implementation where they remain technically justified;
2. expose that exact accepted deployment through the independently owned website consumer; and
3. decide whether the existing CLI/MCP process is sufficient for one customer-controlled
   non-production integration or whether one smallest resident process, interface, and installation
   boundary is required.

KAP-0069 selected a serialized sandbox reshape; KAP-0070 now owns its contract correction,
implementation, and staged acceptance. KAP-0054 owns the later resident-boundary decision. None may
infer a resident topology, transport, packaging, authentication, storage, or compatibility from the
sandbox. Provider use, public traffic, and resident implementation each require their own exact
accepted gate or owner.

The cycle keeps one capability and tests two different facts: the public proof tests comprehension;
the customer-controlled preview tests whether the authority and recovery boundary is useful enough
to install. It does not authorize a second operation, generic provider seam, managed control plane,
production support, or v1 compatibility.

## Milestone separation

### Developer alpha: 0.1.x

The 0.1.x package proves one concrete operation through the local CLI, stdio MCP adapter,
disposable-kind demonstration, and signed receipt. Its Rust, CLI, MCP, configuration, journal, and
receipt interfaces remain prototype-scoped.

### Developer beta: 0.2.0

The accepted [v0.2 plan](V0.2.md) has deepened the same operation into one technology-led developer
beta design. It adopts bounded CLI/MCP, grant/receipt continuity, private journal migration, release
integrity, and qualification obligations without adding a capability, daemon, hosted dependency,
public Rust SDK, or production-support claim. Ordered release evidence owns exact candidate and
publication state; external beta evidence follows publication.

### Bounded public product proof

One independently deployed sandbox may expose fixed non-consequential scenarios through a narrow
Rust module that reuses the existing `Application`. Its accepted [HTTP contract](SANDBOX_API.md) and
[deployment contract](SANDBOX_DEPLOYMENT.md) own hosted admission, isolation, reconnectable public
projection, bounded scheduling, cleanup, and receipt presentation. KAP-0069 selected reshape:
KAP-0070 must preserve the fixed interface and semantic spine while proving one native controller
host, separate per-run runner, dedicated synthetic cluster, and at most one active run through
cleanup. The prior Kubernetes-hosted controller/stager topology is superseded. This remains a
product-comprehension surface, not the production resident interface or a hosted customer control
plane.

### Customer-resident preview and production v1

KAP-0054 first decides whether the current CLI/MCP process can satisfy one customer-controlled
non-production integration with less operational risk. If not, it may specify one smallest resident
process and local caller boundary. That preview decision exists to make one real workflow possible;
it is not production v1 and does not inherit sandbox topology or public compatibility.

A later production `kapseld` release requires retained real-workflow use and a new explicit
production decision. It would own supported local admission, durable execution, restart and upgrade
recovery, bounded concurrency, provider authority, grant and trust configuration, receipt
publication, health, diagnostics, and one versioned local interface. Neither the v0.2 beta, public
proof, nor preview authorizes that production release.

## Package strategy

Package seams follow independent deployment, dependency isolation, or multiple real consumers. A
concept being generic does not by itself justify a package.

### Current workspace

```text
kapsel           product library plus local CLI and MCP executable
kapsel-sandbox   unpublished fixed public-sandbox service package
kapsel-dev       unpublished repository tooling
fuzz             excluded hostile-input package
```

The root `kapsel` package remains one deep product module. `Application` is the proven shared
interface used by the CLI and MCP adapters. Authorization, SQLite lifecycle, the concrete Kubernetes
adapter, classification, receipt construction, and publication remain private implementation.

### Earned sandbox package

```text
kapsel-sandbox -> kapsel
```

KAP-0052 implements `kapsel-sandbox` as an independently deployable consumer with a one-way
dependency on `kapsel`. It owns public admission, capacity, scheduling, reconnectable projection,
retention, and cleanup. It uses a separate SQLite admission store and immutable receipt directory,
never reuses the gateway journal as its run database, and never exposes local receipt paths. The
package creates no reverse dependency or authorization for another package direction.

### Production package

```text
kapseld -> kapsel
```

A preview `kapseld` package becomes justified only if KAP-0054 proves that the existing CLI/MCP
process cannot satisfy the bounded customer-controlled integration with lower operational risk. It
owns only the selected local transport, process lifecycle, configuration, health, concurrency,
upgrades, and operational diagnostics for that preview. It does not absorb effect lifecycle or
provider classification from `kapsel`. Production compatibility remains unearned until retained
workflow use passes a later decision.

The existing `kapsel` executable remains in the root package until independent release cadence,
installation size, or dependency isolation proves a separate CLI package useful.

## Runtime and repository tooling posture

A production resident installation must not require Python or shell for ordinary operation,
recovery, migration, receipt inspection, health, upgrade, or rollback. Required customer-resident
behavior belongs in supported Rust binaries with explicit compatibility and distribution evidence.
This is a prospective v1 constraint, not a v0.2 artifact-layout change.

Repository-only release, qualification, fixture, and documentation tooling may remain
implementation-private in another language. Stable repeated invariants should deepen behind typed
modules in the existing unpublished `kapsel-dev` package when deletion would otherwise spread those
invariants across scripts. Keep at least one release verifier independent from the product
implementation. A future public demonstration either retires with the v0.2 evaluation artifact or
receives an explicit supported executable and prerequisite decision; shell or Python does not become
a v1 distribution interface by inheritance.

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
3. **Public sandbox HTTP** for one accepted fixed-scenario product proof only.
4. **Customer-controlled preview interface** selected by KAP-0054 only if CLI/MCP is insufficient.
5. **Production resident interface** only after retained workflow use earns `kapseld` compatibility.
6. **Managed Kapsel** only after a resident product proves demand for configuration, upgrades, fleet
   health, or receipt indexing.
7. **Grafik consumer adapter** for visualization of bounded public projections without authority.
8. **One evidence-selected operation** only when repeated workflows select the same concrete need.
9. **Another provider** only when a second production adapter exposes a repeated seam.

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

| Candidate            | Trigger required before extraction                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `kapseld`            | KAP-0054 proves CLI/MCP insufficient for the bounded preview; production compatibility still requires retained use |
| Separate CLI package | Independent release cadence, installation size, or dependency-isolation evidence                                   |
| `kapsel-receipt`     | Independent verifier needing receipt logic without gateway and Kubernetes dependencies                             |
| `kapsel-protocol`    | Two independently maintained clients sharing one stable wire model                                                 |
| Client SDK           | Multiple external integrations requiring the same supported client behavior                                        |
| Kubernetes package   | Measured dependency isolation or multiple concrete capability modules needing the same adapter package             |
| Public provider seam | Two production provider adapters exposing the same repeated interface                                              |
| Storage seam         | A second durable lifecycle implementation with requirements SQLite cannot satisfy                                  |

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
