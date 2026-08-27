# Public sandbox API

Status: historical contract for the retired hosted route. The deployable implementation was removed.
These bytes remain only as explanatory fixtures; no deployment, compatibility, or traffic is
authorized.

> **Historical reading rule:** every present-tense or normative verb below records what the retired
> contract required. No `must`, `requires`, `owns`, or similar wording appoints a current
> implementation or future obligation.

Kind: historical contract. Authority: public sandbox HTTP grammar, admission identity, reconnectable
public projection, retention, errors, and disclosure.

Owns: The versioned interface for the fixed public `healthy` and `unavailable-image` scenarios.

Does not own: effect-gateway lifecycle/result/receipt meaning, sandbox infrastructure, a production
`kapseld` interface, arbitrary Kubernetes input, or a generic hosted API.

## Contract boundary

The public sandbox is one demonstration adapter over the existing `Application`. The caller chooses
only a scenario and one idempotency key. The server chooses the exact operation identity, namespace,
Deployment, container, immutable image digest, authorization grant and trust, Kubernetes authority,
signing material, deadlines, storage, and cleanup policy.

```text
POST fixed scenario
  -> durable sandbox admission identity
  -> bounded scheduling and server-owned Application composition
  -> Kapsel operation report and unchanged effect-gateway receipt
  -> ordered public projection
  -> independently tracked cleanup
```

Sandbox admission, Kapsel submission, receiver outcome, receipt availability, and cleanup are
separate facts. An HTTP success confirms only the response described below. Disconnect, replay,
stream failure, sandbox deadline, cleanup failure, and HTTP status never manufacture `SUCCEEDED`,
`FAILED`, `UNKNOWN`, or `not_attempted`.

## Retired wire and media record

The retired wire used only the ASCII token `v1`. All routes began with `/sandbox/v1`, all JSON
documents contained `"api_version":"v1"`, and other versions returned `unsupported_version` rather
than being interpreted as `v1`.

The committed fixtures record exact `v1` response objects and the consumer rejection behavior that
the abandoned demonstration contract required. They appoint no maintained implementation, future
field evolution, migration, or compatibility. This was never the resident `kapseld` interface or a
production compatibility promise.

Admission requests use UTF-8 `application/json`, contain exactly one object, and are at most 512
bytes. JSON responses are at most 64 KiB. Compression and bodies on `GET` are not accepted. Unknown,
duplicate, missing, or incorrectly typed JSON fields fail with `invalid_request`. All strings are
Unicode only where explicitly stated; identifiers and enum tokens are ASCII. Responses use no
ambient locale.

The native service enforces these global transport limits independently of the required edge's
per-source abuse control: request line at most 512 bytes; at most 16 headers and an 8 KiB complete
request head; each header value at most 256 bytes; at most 128 open connections and 64 in-flight
requests; five seconds to receive request headers, five seconds to receive the bounded body, 30
seconds for the native HTTP connection to await the service response. Crossing a
byte/time/concurrency bound is rejected or closes the connection and emits no reflected input. A
connection wait timeout does not cancel or terminate a service operation that already began. These
transport limits do not reserve or release scheduler capacity and cannot become receiver outcomes.
The retired native listener was HTTP/1.1 and closed every connection after one response.

## Routes

| Method | Route                               | Success                               | Purpose                                    |
| ------ | ----------------------------------- | ------------------------------------- | ------------------------------------------ |
| `POST` | `/sandbox/v1/runs`                  | `201 Created` or idempotent `200 OK`  | Admit one fixed scenario                   |
| `GET`  | `/sandbox/v1/runs/{run_id}`         | `200 OK`                              | Read the latest snapshot                   |
| `GET`  | `/sandbox/v1/runs/{run_id}/events`  | `200 OK`                              | Replay ordered public events               |
| `GET`  | `/sandbox/v1/runs/{run_id}/receipt` | `200 OK` with unchanged receipt bytes | Retrieve a terminal effect-gateway receipt |

There is no run-listing, cancellation, retry, reconciliation, cleanup, log, callback, authority,
configuration, health, fault-control, or arbitrary-resource route. `HEAD`, `PUT`, `PATCH`, `DELETE`,
and `OPTIONS` are not part of this contract.

Browser consumers would have used these origin-relative routes through the required same-origin
edge. The retired native API set no cookie, accepted no browser credential, and made no cross-origin
CORS promise. The edge could have been deployed independently from the website and runner, but would
have had to preserve method, path, bounded application headers, body, status, response headers, and
idempotency exactly. It would have owned authoritative per-source abuse rejection before forwarding;
the native listener would have been reachable only through its private authenticated channel during
exposure. No visitor-derived source header entered the `v1` request, durable run state, response,
log, or metric. Any future cross-origin surface would require a new direction decision and a new
versioned contract including preflight and origin policy; this historical contract grants neither.

HTTP routing requires one deployment-configured `Host` or HTTP/2 `:authority`, at most 253 ASCII
bytes. `POST` requires `Content-Type: application/json`, exact decimal `Content-Length` from 1
through 512, and the owned `Idempotency-Key`; `GET` has no body or content headers. `Accept` is
optional and, when present, must name the route's owned response media type. `Origin` is optional
and must equal the configured same origin. Conflicting length/framing, `Transfer-Encoding`,
`Cookie`, `Authorization`, `Range`, conditional `If-*`, and untrusted forwarding/client-certificate
headers fail with `invalid_request` before admission. The edge strips forwarding, tracing, and
visitor-source headers before the native service; its private-channel authentication is transport
composition, not a `v1` header or caller input.

Other syntactically valid standard HTTP headers within the count/byte limits are ignored, have no
`v1` semantics, and are never copied to durable state, responses, logs, or metrics. The contract
fixtures list only application-semantic request headers; HTTP routing/framing and ignored browser
headers are intentionally not fixture fields.

## Admission

A request has exactly two JSON fields:

```json
{
  "api_version": "v1",
  "scenario": "healthy"
}
```

`scenario` is exactly `healthy` or `unavailable-image`. Both select a server-owned synthetic
Deployment-image operation. They differ only in the fixed immutable image selected by the server:
`healthy` is intended to produce the defined available-rollout receiver facts; `unavailable-image`
is intended to produce `ProgressDeadlineExceeded` receiver facts. Those names are scenario intent,
not promised outcomes. Either can still produce effect-gateway `UNKNOWN` or a pre-attempt target
rejection when the receiver facts require it.

The request must include `Idempotency-Key`. It is exactly 32 lowercase hexadecimal characters
encoding 128 bits generated by a cryptographically secure caller random source. It is sensitive
caller correlation and a bearer replay locator: anyone holding it and the two-value scenario grammar
can recover the admitted run identity during the public lifetime. It is not authority, browser
identity, or the effect-gateway operation identity. The public service never echoes it or places it
in a URL, response, event, error, log, or metric. Durable state retains the mapping only for the
bounded idempotency lifetime; diagnostics may retain only its service-keyed digest.

The admission transaction atomically stores a cryptographically random server-generated `run_id`,
the exact scenario, a server-generated effect-gateway `operation_id`, admission time, expiry time,
initial event, and scheduler eligibility before returning success. A successful response therefore
survives ordinary controller-process restart while the same controller state remains present and
validated. The operation has not necessarily been submitted to Kapsel or Kubernetes at that point.
This contract does not preserve admission across controller-host or storage loss.

- The first committed key and body returns `201` and `admission_disposition: "created"`.
- The same key and byte-equivalent parsed body returns the same identities and times with `200` and
  `admission_disposition: "replayed"`; it does not create or dispatch another run.
- The same key with a different parsed body returns `idempotency_conflict` and creates nothing.
- A response lost after commit is recovered by repeating the same request and key.
- A non-success response other than an idempotent conflict never proves whether an earlier request
  with another key exists.

The edge's per-source abuse bound rejects before forwarding. The native global stop and queue bound
are checked before the admission transaction commits. One bounded queue slot is reserved atomically
with admission. Active execution capacity is reserved separately and atomically only when the serial
scheduler dispatches the oldest queued run; transport activity never reserves it. Saturation fails
closed and creates no run. Edge admission may reject earlier, but only the native service's durable
transaction establishes admission.

A success response has exactly:

```json
{
  "api_version": "v1",
  "run_id": "0123456789abcdef0123456789abcdef",
  "operation_id": "sandbox-0123456789abcdef0123456789abcdef",
  "scenario": "healthy",
  "admission_disposition": "created",
  "admitted_at": "2026-07-21T00:00:00Z",
  "expires_at": "2026-07-22T00:00:00Z",
  "last_sequence": 1
}
```

## Public snapshot

`GET /sandbox/v1/runs/{run_id}` returns exactly:

```json
{
  "api_version": "v1",
  "run_id": "0123456789abcdef0123456789abcdef",
  "operation_id": "sandbox-0123456789abcdef0123456789abcdef",
  "scenario": "healthy",
  "execution_state": "terminal",
  "receiver_result": "SUCCEEDED",
  "target_rejection": null,
  "receipt_available": true,
  "cleanup_state": "succeeded",
  "admitted_at": "2026-07-21T00:00:00Z",
  "expires_at": "2026-07-22T00:00:00Z",
  "last_sequence": 6
}
```

`execution_state` is a sandbox projection, not the effect-gateway journal state:

| Value            | Meaning                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `queued`         | Durably admitted; no native runner has begun this run.                                    |
| `running`        | A runner began owned setup or invoked the configured `Application`; outcome is unknown.   |
| `not_attempted`  | effect-gateway returned one terminal pre-attempt target rejection.                        |
| `service_failed` | Sandbox setup failed before `Application` invocation; no Kapsel outcome exists.           |
| `terminal`       | effect-gateway returned one receiver result and froze the corresponding operation report. |

For `queued`, `running`, and `service_failed`, both outcome fields are null. `service_failed` is a
terminal sandbox projection and can be entered only when the durable runner record establishes that
`Application` was never invoked; it exposes no internal cause. For `not_attempted`,
`receiver_result` is null and `target_rejection` is exactly `DEPLOYMENT_NOT_FOUND`,
`CONTAINER_NOT_FOUND`, or `INVALID_TARGET`. For `terminal`, `receiver_result` is exactly
`SUCCEEDED`, `FAILED`, or `UNKNOWN` and `target_rejection` is null. No other combination is valid.

`cleanup_state` is independent and exactly `pending`, `running`, `succeeded`, or `failed`.
`receipt_available` becomes true only after the exact frozen effect-gateway receipt bytes are
durably installed in receipt storage. It remains false for `not_attempted` and `service_failed`,
which have no effect receipt. Cleanup state and receipt availability never change receiver result.

## Ordered replay

`GET /sandbox/v1/runs/{run_id}/events?after=<sequence>&limit=<count>` reconnects without a live
stream. Both query parameters are required exactly once. `after` is an unsigned decimal integer from
0 through 64; `limit` is an unsigned decimal integer from 1 through 64 without a sign or leading
zeros except the value `0` allowed for `after`. Unknown query parameters fail with
`invalid_request`.

The response has exactly:

```json
{
  "api_version": "v1",
  "run_id": "0123456789abcdef0123456789abcdef",
  "events": [],
  "last_sequence": 6,
  "next_after": 6
}
```

`events` contains at most `limit` events whose sequence is greater than `after`, in strictly
increasing sequence order. `last_sequence` is the durable high-water mark at the snapshot used for
the response. `next_after` is `after` when no returned event exists, otherwise the final returned
sequence. A client repeats with `after=next_after`; duplicate HTTP requests return the same retained
prefix. Concurrent appends may appear only in a later request. There are no gaps, renumbering, or
replacement within one retained run. A run has at most 64 events and every JSON response is at most
64 KiB.

Each event has exactly the complete mutable projection fields after that transition plus event
identity:

```json
{
  "sequence": 1,
  "kind": "admission.accepted",
  "occurred_at": "2026-07-21T00:00:00Z",
  "execution_state": "queued",
  "receiver_result": null,
  "target_rejection": null,
  "receipt_available": false,
  "cleanup_state": "pending"
}
```

Kinds are exactly:

| Kind                         | Required projection after the event                                             |
| ---------------------------- | ------------------------------------------------------------------------------- |
| `admission.accepted`         | `queued`; sequence 1 and the only initial event                                 |
| `execution.started`          | `running`; says only that owned runner work began                               |
| `execution.deadline_reached` | Outcome unchanged; deadline elapsed and receiver resources remain for recovery  |
| `execution.not_attempted`    | `not_attempted` with one target rejection                                       |
| `execution.service_failed`   | `service_failed`; Application was provably never invoked; outcome fields null   |
| `execution.terminal`         | `terminal` with one effect-gateway receiver result                              |
| `receipt.available`          | `terminal`, `receipt_available: true`; exact frozen bytes became retrievable    |
| `cleanup.started`            | `cleanup_state: running`; emitted at most once; operation fields unchanged      |
| `cleanup.succeeded`          | `cleanup_state: succeeded`; operation fields unchanged                          |
| `cleanup.failed`             | `cleanup_state: failed`; emitted at most once; internal durable retry continues |

An implementation may omit events that never occur, but cannot add another kind under `v1`. Internal
scheduler and cleanup retries are coalesced: after one `cleanup.failed`, no retry event is added
until one eventual `cleanup.succeeded`, which may follow `failed` directly. This preserves the
64-event bound without losing the public cleanup fact. `execution.deadline_reached` does not
terminate Kapsel, classify the receiver, establish rollback, or say that Kubernetes did not receive
an attempt. `cleanup.failed` is observable but is not a receipt field or receiver outcome.

## Receipt retrieval

For a run with `receipt_available: true`, `GET /sandbox/v1/runs/{run_id}/receipt` returns the exact
frozen effect-gateway receipt bytes, without decoding, redaction, re-signing, or re-encoding, as
`application/vnd.kapsel.kap0038.receipt`. The body is 1 byte through 16 KiB. `Content-Length` is
required and `ETag` is the quoted lowercase SHA-256 hex digest of the exact body. Conditional and
range requests are unsupported.

Receipt retrieval did not publish or appoint trust. A consumer inspecting the receipt would have had
to obtain an effect-gateway trust document, evaluation time, and limits through a separately
reviewed channel. The owner-private authority controller was that local composition seam for the
sandbox prototype: it returned unchanged validated trust bytes only for a retained receipt's durable
generation. It was not an HTTP route, ambient lookup, or receipt field. The receipt never appointed
its own trust.

The unchanged receipt intentionally discloses only server-chosen synthetic effect-gateway classifier
fields, including namespace, Deployment and receiver UIDs, resource versions, operation marker,
image digest, generations, replica counts, condition, key identifiers, grant digest, result, and
non-claims. These are public demonstration evidence, not private tenant data. Runner Pod/node IDs,
leases, durable-store keys, internal paths, control-plane identifiers, credentials, private key or
trust material, raw journal rows, uncontrolled logs, and fault controls are never added.

A receipt request before availability returns `receipt_not_available`. A `not_attempted` run always
returns that error. Retrieval failure never changes an already frozen result or receipt.

## Field ownership and bounds

All public JSON fields are owned by this document and have no compatibility status beyond exact
`v1`.

| Field                   | Type and bound                                    | Disclosure and ordering/error rule                                  |
| ----------------------- | ------------------------------------------------- | ------------------------------------------------------------------- |
| `api_version`           | ASCII enum, exactly `v1`                          | Public compatibility discriminator; mismatch fails closed           |
| `run_id`                | 32 lowercase hex characters                       | Public unguessable 128-bit bearer locator; never reused             |
| `operation_id`          | `sandbox-` plus the 32-character `run_id`         | Public synthetic effect-gateway identity; immutable after admission |
| `scenario`              | `healthy` or `unavailable-image`                  | Public caller selection; immutable after admission                  |
| `admission_disposition` | `created` or `replayed`                           | Admission response only; does not describe Kapsel                   |
| `admitted_at`           | UTC RFC 3339 whole seconds, 20 ASCII characters   | Public correlation time; immutable, no subsecond precision          |
| `expires_at`            | Same type; exactly 24 hours after `admitted_at`   | Public retention boundary; immutable                                |
| `last_sequence`         | JSON integer 1–64                                 | Durable event high-water mark                                       |
| `next_after`            | JSON integer 0–64                                 | Replay cursor for the returned page only                            |
| `events`                | JSON array of 0–64 event objects                  | Strict sequence order; retained until expiry                        |
| `sequence`              | JSON integer 1–64                                 | Starts at 1, contiguous, immutable                                  |
| `kind`                  | One owned event enum                              | Public bounded projection; unknown kind is incompatible             |
| `occurred_at`           | UTC RFC 3339 whole seconds, 20 ASCII characters   | Nondecreasing by sequence; ties allowed                             |
| `execution_state`       | One owned execution enum                          | Monotonic except `running` can remain after a deadline event        |
| `receiver_result`       | Null or effect-gateway result enum                | Present only with terminal receiver classification                  |
| `target_rejection`      | Null or effect-gateway pre-attempt rejection enum | Present only with `not_attempted`; never a receiver result          |
| `receipt_available`     | JSON boolean                                      | Changes false to true at most once                                  |
| `cleanup_state`         | One owned cleanup enum                            | `failed` may transition directly to `succeeded` after retry         |
| `error`                 | Exact bounded error object                        | Present only in error envelopes                                     |
| `code`                  | One owned ASCII error enum, at most 32 bytes      | Stable only within `v1`; no internal diagnostic text                |
| `message`               | Owned fixed ASCII sentence, at most 128 bytes     | Same bytes for every occurrence of a code                           |
| `retryable`             | JSON boolean                                      | Transport retry guidance; never receiver meaning                    |

A public identifier's unpredictability is an access-minimization control, not authentication. Anyone
possessing an unexpired `run_id` may read that run's synthetic projection and receipt.

## Retention and expiry

While the admitted controller state remains present and validated, the full run, event projection,
and receipt remain publicly retrievable until `expires_at`, exactly 24 hours after admission. The
private idempotency mapping is usable for replay during the same period but is never itself public.
Controller-host or storage loss withdraws the endpoint and may end this availability early; the
sandbox does not reconstruct prior locators, projections, receipts, expiry, or cleanup events. At
expiry, all run, event, and receipt routes return the same `run_expired` response for a further
24-hour tombstone window.

The private tombstone contains exactly a service-keyed run-identity digest, a service-keyed
idempotency-key digest, and expiry time. It exposes no scenario, request digest, outcome, event,
receipt, raw key, or infrastructure identifier. During the tombstone window, any `POST` using the
matching idempotency key returns `run_expired` regardless of scenario and creates nothing; it never
reveals the former run identity or scenario. A request by run ID also returns `run_expired`. After
tombstone deletion, the run ID returns `run_not_found`, and reuse of the former key is a new
admission with a new run identity. After catastrophic state destruction and accepted clean
recreation, a prior locator may likewise return `run_not_found`; reuse of a prior idempotency key
may create a new admission only after exact teardown, readiness, and explicit reopening. No prior
result or receipt is inferred.

The retired rules did not permit internal security, gateway-recovery, or cleanup records to extend
public retention or retain raw visitor identifiers. No hosted retention or deletion policy remains
active; [Privacy](PRIVACY.md) owns the current data boundary.

## Errors

The application-controlled header set for every JSON response is exactly
`Content-Type: application/json` and `Cache-Control: no-store`; retryable errors additionally
include the owned `Retry-After`. Receipt responses include exactly their owned content type,
`Content-Length`, `ETag`, and `Cache-Control: no-store`. Standard intermediaries may add protocol
headers such as `Date`, but they cannot add a cookie, cache permission, idempotency key, runner or
infrastructure identifier, generic diagnostic header, or input-derived value.

Every JSON error response has exactly:

```json
{
  "api_version": "v1",
  "error": {
    "code": "capacity_saturated",
    "message": "Sandbox capacity is temporarily saturated.",
    "retryable": true
  }
}
```

| HTTP | Code                    | Retryable | Meaning and required behavior                                           |
| ---- | ----------------------- | --------- | ----------------------------------------------------------------------- |
| 400  | `invalid_request`       | false     | Malformed method inputs, JSON, query, header, bound, or unknown field   |
| 400  | `unsupported_version`   | false     | Unknown route/body API version; never interpreted as another version    |
| 404  | `run_not_found`         | false     | Malformed-looking and unknown run IDs are indistinguishable             |
| 409  | `idempotency_conflict`  | false     | Existing key names a different parsed admission body                    |
| 409  | `receipt_not_available` | true      | Run exists but no retrievable effect receipt exists yet                 |
| 410  | `run_expired`           | false     | Run or key tombstone matched; no former run facts are disclosed         |
| 429  | `rate_limited`          | true      | Anonymous source abuse bound rejected before durable admission          |
| 503  | `capacity_saturated`    | true      | Durable queue or active-run reservation is full; no run was admitted    |
| 503  | `service_unavailable`   | true      | Global stop or required durable service unavailable; no admission claim |

Retryable errors include an integer `Retry-After` header from 1 through 300 seconds. A retry must
reuse the same idempotency key when the caller intends the same admission. `run_not_found` is used
for both invalid run-ID grammar and absent well-formed IDs to reduce enumeration feedback. Error
bodies contain no reflected input, provider body, path, stack, store error, runner identity,
capacity count, rate-limit identity, or fault-control state.

Fixed messages are respectively: `The request is invalid.`, `The API version is unsupported.`,
`The run was not found.`, `The idempotency key names another request.`,
`The receipt is not available.`, `The run has expired.`, `The anonymous request rate is limited.`,
`Sandbox capacity is temporarily saturated.`, and `The sandbox service is temporarily unavailable.`

## Contract fixtures

Historical consumer fixtures live under [`sandbox-v1`](fixtures/sandbox-v1/README.md). They record
JSON key sets, values, ordering, replay, errors, headers, and raw receipt retrieval from the retired
contract. They use fixed synthetic times and identities and promise no executable compatibility. The
archived implementation and validation lane remain available only at annotated tag the archived
narrowed-sandbox source.
