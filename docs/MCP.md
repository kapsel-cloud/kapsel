# MCP adapter

Status: pre-V1 prototype contract. No compatibility promise.

Kind: contract. Authority: the fixed MCP protocol, transport, lifecycle, tool, bounds, and response
semantics for KAP-0043.

Owns: The prototype MCP process grammar and wire behavior for the sole KAP-0038 operation.

Does not own: Authorization, durable lifecycle, Kubernetes behavior, receiver classification,
receipt bytes, the local evaluator command, a generic MCP host, or a stable transport API.

## Protocol and process

The prototype supports exactly MCP protocol version `2025-11-25` over the official standard-input /
standard-output transport. Each message is one UTF-8 JSON-RPC 2.0 object on one line. Standard
output contains protocol messages only; bounded diagnostics use standard error. HTTP, Server-Sent
Events, `Content-Length` framing, JSON-RPC batches, and embedded newlines are unsupported.

The operator starts the process with exactly:

```text
kapsel mcp --operator-config <file>
```

The operator file has the exact out-of-band grammar and bounds documented for `operate` in
[Evaluator commands](COMMANDS.md). Kapsel loads it once, constructs the same compile-time-composed
`Application`, and exits before reading protocol input if operator configuration is invalid. No
environment or ambient configuration supplies trust, credentials, kubeconfig, clock, paths, or
lifecycle controls.

A protocol line is at most 16 KiB, including its terminating newline. Kapsel rejects an overlong
line before JSON parsing and exits without reading an unbounded remainder. Every complete protocol
response line is at most 8 KiB. Standard error contains at most one newline-terminated diagnostic of
at most 4 KiB and never contains request bytes, operator values, provider bodies, or secrets.

## Lifecycle

The first request is `initialize`. Kapsel accepts a numeric non-null request ID or a non-null string
request ID of at most 128 UTF-8 bytes and echoes its exact JSON value. Longer strings and other ID
types receive `Invalid Request` with `id: null`; this bound guarantees the echoed ID cannot exceed
the response limit. Initialization returns:

```json
{
  "protocolVersion": "2025-11-25",
  "capabilities": { "tools": {} },
  "serverInfo": { "name": "kapsel", "version": "0.1.0-alpha.1" }
}
```

When a client proposes another protocol version, Kapsel returns its sole supported version as MCP
negotiation requires. A client that does not support the returned version must disconnect. Kapsel
becomes ready only after `notifications/initialized`; tool requests before that notification are
invalid requests. A second `initialize` request is invalid. It advertises no prompts, resources,
logging, roots, sampling, completion, task, subscription, or list-change capability and sends no
server-originated request or notification.

Requests use unique in-flight IDs. This adapter processes one bounded line and at most one tool call
at a time, so it has no concurrent in-flight application calls. Notifications receive no response.
Unknown notifications and late or unknown `notifications/cancelled` notifications are ignored.
Initialization cannot be cancelled. Sequential execution cannot observe a cancellation notification
while `Application::execute` is running; disconnect or cancellation therefore never means that an
operation was unattempted, failed, or rolled back. Ordinary recovery is a new process with the same
operator configuration and operation request; application reconciliation preserves explicit
`UNKNOWN` and never blindly repeats a recorded mutation attempt.

There is no `shutdown` or `exit` method. Closing standard input requests graceful shutdown. Kapsel
finishes the current complete request, flushes its response, and exits; an incomplete final frame is
rejected without a response. Process termination can interrupt an operation only with the
cancellation meaning above.

## Fixed tool

`tools/list` returns exactly one tool, in one unpaginated result. Its name is
`kubernetes.set_deployment_image` and its description is:

```text
Request one authorized immutable Kubernetes Deployment image change.
```

Its JSON Schema defaults to JSON Schema 2020-12 and is exactly:

```json
{
  "type": "object",
  "properties": {
    "operation_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._:-]+$"
    },
    "namespace": {
      "type": "string",
      "minLength": 1,
      "maxLength": 63,
      "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
    },
    "deployment": { "type": "string", "minLength": 1, "maxLength": 253 },
    "container": {
      "type": "string",
      "minLength": 1,
      "maxLength": 63,
      "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
    },
    "immutable_image_digest": { "type": "string", "minLength": 1, "maxLength": 512 }
  },
  "required": ["operation_id", "namespace", "deployment", "container", "immutable_image_digest"],
  "additionalProperties": false
}
```

The deployment and immutable-image fields remain subject to the complete KAP-0038 grammar even where
JSON Schema cannot concisely express it. A tool call must contain `name`, `arguments`, and only the
common optional `_meta` object; `arguments` must be an object with exactly the five required string
fields. `_meta` is bounded by the frame and ignored; it cannot appoint authority or alter execution.
Missing, unknown, duplicate, malformed, oversized, and wrong-typed fields are rejected before
application I/O. No second tool or arbitrary tool name is accepted.

The adapter converts those five values directly into the existing `AgentRequest` in the same order
and calls `Application::execute`. It does not validate or sequence authorization, persistence,
Kubernetes interaction, recovery, receiver classification, receipt construction, or publication. The
tool input cannot contain a grant, trust, Kubernetes credentials, signing material, paths, receipt
bytes, evaluation time, fault controls, lifecycle state or transition, shell, `kubectl`, manifest,
patch, tag, wildcard, or ambient lookup.

## Responses and errors

A completed application call returns one text content item and `isError: false`. The text is one
compact JSON object with this exact field order and the same vocabulary as the local adapter:

```json
{
  "operation_id": "op-001",
  "state": "FINALIZED",
  "result": "SUCCEEDED",
  "target_rejection": null,
  "receipt_file": "kap0038-op-001-<sha256>.receipt",
  "receipt_sha256": "<sha256>"
}
```

`NOT_ATTEMPTED` remains a successful completed call with a null receiver result and one bounded
target rejection. `SUCCEEDED`, `FAILED`, and `UNKNOWN` remain distinct receiver outcomes. Request
acceptance, transport completion, timeout, cancellation, or provider ambiguity never changes that
vocabulary.

A syntactically valid call rejected by request grammar or exact-grant tuple returns one text content
item containing `{"status":"ERROR","error_class":"request_rejected"}` and `isError: true`.
Application execution or reconciliation failure returns the same shape with error class
`operation_failure`. Neither result discloses the rejected value or an internal cause.

JSON-RPC errors use only these fixed messages and standard codes:

| Code     | Message            | Use                                                                    |
| -------- | ------------------ | ---------------------------------------------------------------------- |
| `-32700` | `Parse error`      | Invalid UTF-8 or JSON when an ID cannot be recovered.                  |
| `-32600` | `Invalid Request`  | Invalid envelope, lifecycle order, batch, notification, or request ID. |
| `-32601` | `Method not found` | Unknown JSON-RPC request method.                                       |
| `-32602` | `Invalid params`   | Invalid parameters, schema, cursor, tool name, or tool arguments.      |
| `-32603` | `Internal error`   | Bounded transport or serialization failure.                            |

Errors contain no `data`. Parse and invalid-envelope errors use `id: null` when no valid request ID
is available. Tool/input failures do not echo values. Every JSON object at every protocol depth
rejects duplicate keys. Extra envelope or method fields are invalid. Responses, diagnostics,
reports, receipts, and the journal retain the existing KAP-0038 disclosure limits.

## Prototype limits

This is one pre-V1 transport adapter, not a generic MCP server, tool registry, SDK, plugin host,
remote service, or compatibility commitment. It deliberately implements the fixed official wire
surface directly with the repository's existing JSON and runtime dependencies; no MCP SDK dependency
is required. The contract may be removed or changed before V1.

## Official protocol basis

The wire contract is based on the official MCP `2025-11-25` [versioning], [lifecycle], [stdio
transport], [messages], [tools], and [cancellation] specifications and their [canonical schema]. The
official Rust SDK is [`rmcp`]; registry version `2.2.0` was current when this contract was written,
but Kapsel does not add it because its generic server and tool machinery would widen this fixed
surface without reducing the owned bounds.

[versioning]: https://modelcontextprotocol.io/specification/2025-11-25/basic/versioning
[lifecycle]: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
[stdio transport]: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio
[messages]: https://modelcontextprotocol.io/specification/2025-11-25/basic/messages
[tools]: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
[cancellation]:
  https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation
[canonical schema]:
  https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-11-25/schema.ts
[`rmcp`]: https://crates.io/crates/rmcp
