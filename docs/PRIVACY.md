# Privacy

Status: active experiment design.

Kind: design. Authority: data-exposure boundary for the Kubernetes effect-gateway experiment.

Owns: Disclosure risks for requests, journals, receipts, reports, and demo artifacts.

Does not own: Legal compliance, production retention, Kubernetes credential operations, or exact
public-sandbox field grammar.

## Short answer

The active experiment is local and self-hosted, but its receipts and reports still disclose
operational metadata. Treat them as sensitive unless intentionally published.

Potentially revealing material includes:

- namespace, deployment, container, and image digest;
- operation identity and timing;
- Kubernetes target and receiver UIDs, image and operation marker, generations, resource versions,
  replica counts, and rollout condition;
- authorization and receipt key identifiers, signed-grant digest, and trust anchors; and
- failure classes and unknown-outcome reports.

## Rules

- Agent requests must not contain Kubernetes credentials, signing keys, arbitrary manifests, shell
  commands, prompts, or private logs.
- SQLite, receipts, reports, errors, and captured demo logs must not contain secrets or unbounded
  Kubernetes response bodies.
- The receipt includes only the fields needed to explain the exact experiment operation and result.
- Offline inspection uses externally supplied trust; receipt-carried keys or metadata do not appoint
  themselves.
- Public demos must use disposable local `kind` resources and synthetic image digests or clearly
  safe public images.
- Release artifacts may contain source revision, target, builder identity, binary digests, public
  documentation, and synthetic vectors; they must not contain evaluator grants, trust decisions,
  credentials, seeds, kubeconfigs, journals, receipts, reports, logs, or private paths.

## Fixed public sandbox

The [sandbox API](SANDBOX_API.md) intentionally publishes only synthetic demonstration data: one
unguessable run locator, server-generated operation identity, fixed scenario, whole-second admission
and event times, bounded execution/cleanup projection, and the unchanged KAP-0038 receipt. The
caller-generated idempotency key is a second sensitive bearer replay locator during retention; it is
never published or echoed. That receipt necessarily contains server-chosen synthetic namespace,
Deployment and receiver UIDs, resource versions, operation marker, image digest, generations,
replica counts, rollout condition, key identifiers, grant digest, result, and non-claims. Those
fields are approved public evidence for the sandbox only; their inclusion does not make equivalent
customer or production fields public.

The sandbox accepts no name, account, email, prompt, free text, customer resource, callback, or
credential. It does receive transport metadata needed to answer and defend an anonymous HTTP
request. Anonymous does not mean unlinkable: source network information, idempotency keys, run
locators, times, scenarios, and copied receipts can correlate activity.

### Collection and disclosure rules

- The public response and retained projection contain exactly the fields owned by the API contract.
  They contain no source address, user-agent, referrer, cookie, edge identifier, rate-limit key,
  private diagnostic identifier, or idempotency key.
- The caller-generated 128-bit idempotency key is retained only as the private admission mapping
  needed for replay. Anyone holding it can recover the run identity during public retention, so
  clients must protect it like the run locator. Diagnostics and metrics may use only a service-keyed
  digest and must not emit the raw key.
- Rate limiting may process a source address or edge-derived abuse signal in memory. The durable run
  record does not store it. Security telemetry may retain a truncated or keyed pseudonymous signal
  for at most 24 hours when needed to enforce or investigate abuse; it cannot be joined to receipt
  content or published.
- Access logs are disabled by default or allowlist only method class, route template, HTTP status,
  bounded byte counts, coarse latency, and whole-hour aggregation. They never retain raw URLs with
  run IDs, query strings, headers, bodies, source addresses, user agents, provider bodies, or
  uncontrolled Kubernetes/runner output.
- Application errors use fixed messages and no reflected input, path, stack, store key, runner
  identity, capacity count, or fault state. Operator diagnostics are access-controlled, sampled,
  bounded per event, redacted before storage, and retained at most 24 hours.
- Public run/events/receipt data and the private idempotency mapping expire exactly 24 hours after
  admission. A further 24-hour private tombstone retains exactly service-keyed run/idempotency
  digests and expiry needed to return `run_expired` and prevent key reuse. It contains no request or
  scenario digest. Public and idempotency data is then deleted.
- Backups cannot silently extend these periods. Backup design must support expiry or cryptographic
  erasure and a restore must reapply deletions before serving traffic. Cleanup ownership records may
  outlive public expiry only until owned resources are deleted and the bounded operator record is no
  longer required.
- Raw gateway journals, receipt-storage object keys, internal ownership labels, runner
  Pod/node/lease identifiers, controller paths, credentials, private signing material, trust
  decisions, fault controls, generic logs, and private infrastructure identifiers are never public
  protocol fields.
- Public fixture times and identifiers are synthetic. Public technical evidence reports only
  aggregate approved facts and exact deployed revisions, never visitor-level traces.

### Enumeration and deletion limits

A 128-bit unpredictable run locator reduces guessing but is a bearer locator; forwarding it shares
access until expiry. Unknown and malformed locators are indistinguishable. The expiry tombstone
reveals no scenario, outcome, event, receipt, or visitor signal. Kapsel does not claim that these
controls prevent screenshots, browser history, intermediary logs, external copying, traffic
analysis, or correlation by a party already holding a locator.

## Non-claims

Kapsel does not guarantee anonymity, unlinkability, legal compliance, production retention safety,
or absence of sensitive inference.
