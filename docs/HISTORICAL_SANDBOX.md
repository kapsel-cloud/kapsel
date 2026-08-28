# Historical hosted sandbox

Status: retired.

Kapsel briefly explored a public hosted demonstration with two fixed synthetic scenarios. The route
was never deployed or accepted for live traffic. Its implementation was removed; the local release
demonstration is the current runnable replacement. The customer-resident Kapsel service is a
separate unpublished candidate.

Nothing here authorizes infrastructure, credentials, spending, endpoints, DNS, traffic, or future
compatibility.

## What the experiment tested

The sandbox design separated these facts:

1. admission of one fixed synthetic scenario;
2. execution of the existing Kapsel operation;
3. receiver result and receipt availability;
4. public event projection; and
5. cleanup of dedicated synthetic resources.

The proposed HTTP interface exposed only `healthy` and `unavailable-image` scenarios. It did not
accept Kubernetes credentials, manifests, patches, shell commands, arbitrary targets, retries, or
lifecycle controls.

The design also explored bounded admission, one active run, process isolation, fixed authority,
restart recovery, immutable receipt handoff, and UID-safe cleanup. Offline tests covered parts of
that composition. Live isolation, public abuse controls, catastrophic teardown, clean recreation,
and public exposure were never accepted.

## What remains

The explanatory fixtures under [`fixtures/sandbox-v1`](fixtures/sandbox-v1/README.md) preserve the
consumer-facing response shapes used by the website and Grafik experiments. They are historical
examples, not a maintained API.

The complete retired contracts and implementation remain available at Git tag
[`archive/kap-0070-final-narrowed-sandbox-0579660`](https://github.com/kapsel-cloud/kapsel/tree/archive/kap-0070-final-narrowed-sandbox-0579660).
That revision is the owner for historical protocol, deployment, authority, isolation, retention, and
cleanup details.

## Current replacement

Use the release-owned local crash-recovery demonstration to inspect the published mechanism. The
unpublished customer-resident service is owned by [Kapsel service](KAPSEL_SERVICE.md). Neither
inherits the sandbox HTTP interface or deployment topology.
