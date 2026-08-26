# V1 technical direction

Status: accepted prospective direction; not current release scope or a compatibility promise.

Kind: design. Authority: intended production shape, package-extraction triggers, integration order,
and v1 proof categories.

Owns: The target resident effect-gateway architecture and the conditions under which new packages
and public interfaces become justified.

Does not own: Current 0.1 behavior, the active Kubernetes experiment, task status, exact sandbox
API, or a v1 release contract.

## Technical definition

A possible Kapsel v1 is an operator-resident effect gateway for autonomous systems. It turns bounded
caller intent into one durably tracked provider attempt, recovery without blind retry, receiver
observation, and an inspectable signed receipt.

Kubernetes is the first reference integration, not Kapsel's permanent identity. The durable effect
lifecycle, authority separation, receiver-bounded result, and receipt are the product.

```text
agent or workflow
  -> protected CLI, MCP, or earned versioned local interface
       -> deep kapsel application
            -> bounded capability
            -> operator-held provider authority
            -> durable lifecycle and recovery
            -> receiver observation
            -> signed receipt
                 -> optional later resident lifecycle and managed coordination
```

Provider credentials and execution authority remain operator-resident. Any future remote
coordination layer must not become the source of provider truth or move provider authority across
the local trust boundary.

## Current implementation boundary

The published v0.2.0 artifact contains the root CLI and fixed stdio MCP adapter. The repository also
contains an unpublished `kapseld -> kapsel` process with one authenticated Linux Unix socket,
systemd lifecycle, fixed filesystem roots, and exact Kubernetes RBAC. Its direct-source path passed
one Debian 12/systemd 252 and Kubernetes 1.33 qualification.

The removed hosted sandbox's scheduling, authority staging, cleanup, and HTTP interfaces are not
part of the resident architecture. The resident service is not in the published artifact and has no
production compatibility promise.

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

### Retired hosted experiment

KAP-0070 closed the independently designed sandbox through its accepted fixtures/local-demo
fallback. The [historical HTTP contract](SANDBOX_API.md),
[historical deployment contract](SANDBOX_DEPLOYMENT.md), offline evidence, and archive tags remain
engineering evidence, but deployable sandbox code and active hosted gates were removed. The root
release-owned real-process and disposable-`kind` demonstrations remain the supported way to inspect
the mechanism. No sandbox topology or interface is a current compatibility surface.

### Resident source implementation

The unpublished `kapseld -> kapsel` process runs under a separate OS identity and exposes one
authenticated Linux Unix socket. The CLI/MCP adapters preserve exact operation replay but cannot
provide caller-independent lifetime, read-only reconnect/status, or exact receipt retrieval across
the authority boundary. The resident service adds those properties without inheriting sandbox
topology or compatibility.

A production `kapseld` release would additionally need supported distribution, local admission,
upgrade and rollback, bounded concurrency, provider authority, grant and trust configuration,
receipt publication, health, diagnostics, and one versioned local interface. None is implied by the
direct-source qualification.

## Package strategy

Package seams follow independent deployment, dependency isolation, or multiple real consumers. A
concept being generic does not by itself justify a package.

### Current workspace

```text
kapsel       product library plus local CLI and MCP executable
kapseld      unpublished resident executable; depends on kapsel
kapsel-dev   unpublished repository tooling
fuzz         excluded hostile-input package
```

The root `kapsel` package remains one deep product module. `Application` is the proven shared
interface used by the CLI and MCP adapters. Authorization, SQLite lifecycle, the concrete Kubernetes
adapter, classification, receipt construction, and publication remain private implementation.

### Retired sandbox package

KAP-0052 earned one independent `kapsel-sandbox -> kapsel` consumer and proved the root package
could serve another compile-time composition without reverse dependencies. KAP-0073 archived and
removed that consumer because its hosted requirements do not belong in the resident architecture. Do
not retain or extract its admission, runner, staging, scheduling, cleanup, or transport modules
merely to preserve an unused seam.

### Resident package

```text
kapseld -> kapsel
```

The `kapseld` package exists because the CLI/MCP process cannot provide independent lifetime,
read-only status, and receipt retrieval. It contains one executable and one authenticated Linux Unix
socket. The package owns only the local transport and one in-flight submission rule; systemd owns
process lifecycle, service health, and diagnostics. It does not absorb effect lifecycle or provider
classification from `kapsel`, add a second store, or claim production compatibility.

The existing `kapsel` executable remains in the root package until independent release cadence,
installation size, or dependency isolation proves a separate CLI package useful.

## Runtime and repository tooling posture

A production resident installation must not require Python or shell for ordinary operation,
recovery, migration, receipt inspection, health, upgrade, or rollback. Required resident behavior
belongs in supported Rust binaries with explicit compatibility and distribution evidence. This is a
prospective v1 constraint, not a v0.2 artifact-layout change.

Repository-only release, qualification, fixture, and documentation tooling may remain
implementation-private in another language. Script count or language percentage does not justify a
rewrite. Stable repeated invariants should deepen behind typed modules in the existing unpublished
`kapsel-dev` package only when an accepted resident-preview requirement exposes lockstep change,
duplicated product rules, or unreliable installation/release verification. Prefer archiving expired
historical qualification tooling over porting it. Keep at least one release verifier independent
from the product implementation. A future public demonstration either retires with the v0.2
evaluation artifact or receives an explicit supported executable and prerequisite decision; shell or
Python does not become a v1 distribution interface by inheritance.

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

## Interface order

1. **CLI** for operator provisioning, local operation, diagnostics, and inspection.
2. **Stdio MCP** for bounded request-only agent integration.
3. **Resident Unix socket** for caller-independent lifetime, reconnect/status, and exact receipt
   retrieval for the same sole operation.
4. **Versioned resident distribution** only with explicit artifact, installation, compatibility,
   upgrade, rollback, and platform contracts.
5. **Remote coordination** only with an explicit trust boundary that leaves provider authority and
   receiver truth local.
6. **Another capability or provider** only with concrete typed semantics; never to manufacture a
   generic seam.

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

Private Rust modules, the private provider test seam, sandbox API, and internal SQL schema are not
compatibility surfaces unless a later owner explicitly promotes them.

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
- remote-coordinator disconnect without corruption of resident execution; and
- complete installed-path acceptance on every supported platform.

Coverage percentage remains informational. Enforce owner-specific proof for every lifecycle
transition, crash window, receiver classification, public error class, migration path, supported
adapter, and public wire-version compatibility case.

## Trigger-gated package backlog

| Candidate            | Trigger required before extraction                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| Separate CLI package | Independent release cadence, installation size, or dependency-isolation evidence                       |
| `kapsel-receipt`     | Independent verifier needing receipt logic without gateway and Kubernetes dependencies                 |
| `kapsel-protocol`    | Two independently maintained clients sharing one stable wire model                                     |
| Client SDK           | Two independently maintained clients requiring the same supported client behavior                      |
| Kubernetes package   | Measured dependency isolation or multiple concrete capability modules needing the same adapter package |
| Public provider seam | Two production provider adapters exposing the same repeated interface                                  |
| Storage seam         | A second durable lifecycle implementation with requirements SQLite cannot satisfy                      |

Until its trigger passes, each candidate remains design context rather than active implementation.
Do not create placeholder packages, pass-through interfaces, or compatibility obligations merely to
reserve names.

## Explicit non-goals

- Exactly-once real-world effects
- Arbitrary shell, manifest, patch, provider credential, or lifecycle input from agents
- Generic provider or capability plugin ecosystem
- Generic policy language
- Broad Kubernetes administration
- Remote services holding operator provider credentials by default
- General observability or logs platform
- Compliance or production claims unsupported by explicit evidence
- Stable Rust internals solely because a crate is published
