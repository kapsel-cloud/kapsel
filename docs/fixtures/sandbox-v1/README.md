# Sandbox `v1` contract fixtures

Status: historical explanatory fixtures for the retired [public sandbox API](../../SANDBOX_API.md).
They carry no active compatibility or deployment promise.

Each JSON file is a bounded HTTP transcript. `request` and `response` own the exact method, path,
headers, status, and JSON body relevant to the named behavior. Header names are lowercase in
fixtures so consumers can compare them without depending on HTTP casing. Real JSON serialization may
vary whitespace but not field names, types, enum spelling, or values derived from one run.

| Fixture                                                  | Behavior                                      |
| -------------------------------------------------------- | --------------------------------------------- |
| [`healthy.json`](healthy.json)                           | Admission, replay, terminal healthy snapshot  |
| [`unavailable-image.json`](unavailable-image.json)       | Failed rollout, events, raw receipt retrieval |
| [`saturation.json`](saturation.json)                     | Capacity rejection before admission           |
| [`setup-failure.json`](setup-failure.json)               | Terminal pre-Application sandbox failure      |
| [`expiry.json`](expiry.json)                             | Non-disclosing expired tombstone              |
| [`errors.json`](errors.json)                             | Remaining bounded v1 error classes            |
| [`incompatible-version.json`](incompatible-version.json) | Unknown version failure                       |
| [`unavailable-service.json`](unavailable-service.json)   | Global-stop/dependency failure                |

`unavailable-image.json` points to a deterministic KAP-0038 V2 receipt hex fixture and its exact
SHA-256. The signed statement uses the same synthetic operation identity and a `FAILED`
`ProgressDeadlineExceeded` observation. The raw bytes are unchanged classifier-complete receipt
evidence at the HTTP boundary; they are not JSON and transport does not appoint trust. The fixed API
transcript uses synthetic times and run identities and does not claim those values were served by a
live deployment.

The retired implementation and its fixture-validation lane remain available only at annotated tag
`archive/kap-0070-final-narrowed-sandbox-0579660`. The unavailable-image receipt remains useful to
the root offline-inspection test as classifier-complete KAP-0038 evidence.
