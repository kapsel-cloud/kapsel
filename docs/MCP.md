# MCP adapter

This contract defines two fixed stdio processes: direct Kubernetes execution and the ID-only
resident-service bridge. It owns protocol, framing, lifecycle, tools, bounds, and responses. The
[effect-gateway contract](EFFECT_GATEWAY.md) owns authority, recovery, results, and receipt bytes.
Neither process is a generic MCP host or a stable transport API.

## Receipt completion

Execution commits terminal receipt evidence in SQLite before the adapter exports receipt bytes for
its existing filename response. Export failure is an adapter error, not a change to the action
result, and cannot reopen execution. The [effect-gateway contract](EFFECT_GATEWAY.md) owns the exact
behavior. The older beta remains pinned to its tagged source.

## Compatibility posture

The older v0.2.x compatibility promise belongs to its
[tagged MCP contract](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/MCP.md). Current
preview behavior is defined here and by the gateway contract. `serverInfo.version` identifies the
exact running package; it is not a compatibility or production-support claim.

The existing `kapsel mcp` command below remains a direct-execution adapter with one five-field tool.
Current source also provides `kapsel-service-mcp`, a separate ID-only bridge over the resident
service. Neither supports another transport, remote endpoint, generic MCP host, SDK, plugin
interface, Rust package interface, or production service. Canonical grant, lifecycle,
receiver-result, and receipt semantics remain owned only by [effect-gateway](EFFECT_GATEWAY.md).

## Resident-service bridge (current source only)

`/usr/bin/kapsel-service-mcp` takes no arguments or operator document. The operator launches it
under the confined `kapsel-service-caller` identity and `kapsel-service-callers` effective group. It
connects only to `/run/kapsel/kapseld.sock` using the fixed version-1 service protocol. Socket
access is enforced by the host and service peer credentials. The MCP caller cannot choose a socket,
credential, grant, authority file, export path, receiver, or lifecycle state. The published
`v0.3.0-preview.1` archive does **not** contain this source addition; a new authenticated artifact
must be built and qualified before using this packaged path.

A conventional agent process-launch configuration, provisioned outside agent tool input, is:

```json
{
  "mcpServers": {
    "kapsel-service": {
      "command": "/usr/bin/kapsel-service-mcp",
      "args": []
    }
  }
}
```

For the confined Codex workflow, the caller-owned `~/.codex/config.toml` uses the equivalent
packaged path:

```toml
[mcp_servers.kapsel_service]
command = "/usr/bin/kapsel-service-mcp"
args = []
```

The bridge supports exactly MCP `2025-11-25` over line-delimited UTF-8 JSON-RPC 2.0 stdio.
Initialization, `notifications/initialized`, cancellation, `tools/list`, and `tools/call` use the
same sequential lifecycle and fixed error codes as the direct adapter below. `serverInfo.name` is
`kapsel-service`; `serverInfo.version` is the running package version. Only `tools` is advertised.
There are no server-originated messages, other capabilities, batches, embedded newlines, HTTP, SSE,
or `Content-Length` framing. The input frame is at most 16 KiB including LF; output is at most 96
KiB including LF to carry the bounded original receipt hex. Invalid or incomplete frames cannot
create an action. The bridge processes one request at a time and does not inspect incoming
cancellation while a socket exchange is in flight. A disconnected bridge does not cancel the
service's retained job. An absent response is not non-admission.

`tools/list` returns exactly five tools, unpaginated. Each accepts one JSON object with no extra
properties. `kapsel.list_approved_actions` and `kapsel.list_operation_history` require `after`,
either null or a valid bounded operation ID. `kapsel.get_status`, `kapsel.get_receipt`, and
`kapsel.submit` require exactly `operation_id`, a 1-128 byte identity matching `^[A-Za-z0-9._:-]+$`.
The list schemas enforce the cursor type and bound, and the service verifies cursor semantics. The
only mutating tool is `kapsel.submit`; it explicitly selects an approved ID or resumes _that same
ID_. Discovery, history, status and receipt are stored reads, with no receiver access or lifecycle
advancement. No new identity is minted after ambiguity.

Each tool returns one text item containing a JSON object with `operation_id` (the selected ID, or
null for list calls) and `service` (the unchanged version-1 service JSON object). The JSON-RPC ID is
only the request ID, not the durable operation ID. Local bridge errors use the same envelope, with a
fixed `service.status: "ERROR"` and bridge-local `error_class`. `ERROR` sets `isError: true`;
`NOT_FOUND`, `NOT_READY`, `NOT_ADMITTED` and `INDETERMINATE` remain distinct machine-readable
service facts, not JSON-RPC errors. A local exchange failure returns
`{"status":"ERROR","error_class":"service_exchange_uncertain"}` with `isError: true`. Invalid
response or receipt digest returns `response_invalid`. Neither says the service did not admit the
ID. The service owns admission phase, local rejection, execution disposition, receiver
classification and original signed receipt bytes/digest. The bridge does not export receipt files,
verify signatures, or infer a receiver outcome from a successful exchange. Read the original ID
after loss, then explicitly select it only when the service disposition permits. See
[service protocol](KAPSEL_SERVICE.md#version-1-socket-adoption-contract) and
[operator recovery](KAPSEL_SERVICE_OPERATOR.md#diagnose-and-resume).

## Direct-execution adapter protocol and process

The adapter supports exactly MCP protocol version `2025-11-25` over the official standard-input /
standard-output transport. Each message is one UTF-8 JSON-RPC 2.0 object on one line. Standard
output contains protocol messages only; bounded diagnostics use standard error. HTTP, Server-Sent
Events, `Content-Length` framing, JSON-RPC batches, and embedded newlines are unsupported.

The operator starts the process with exactly:

```text
kapsel mcp --operator-config <file>
```

This example configures a stdio client's process launch. Wrapper field names are client-specific;
this contract fixes the executable, arguments, and authority separation:

```json
{
  "mcpServers": {
    "kapsel": {
      "command": "/absolute/kapsel/bin/kapsel",
      "args": ["mcp", "--operator-config", "/absolute/operator.json"]
    }
  }
}
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
the response limit. Initialization returns the following shape. The example shows the published
preview identity; every process reports its own exact package version.

```json
{
  "protocolVersion": "2025-11-25",
  "capabilities": { "tools": {} },
  "serverInfo": { "name": "kapsel", "version": "0.3.0-preview.1" }
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

The deployment and immutable-image fields remain subject to the complete effect-gateway grammar even
where JSON Schema cannot concisely express it. A tool call must contain `name`, `arguments`, and
only the common optional `_meta` object; `arguments` must be an object with exactly the five
required string fields. `_meta` is bounded by the frame and ignored; it cannot appoint authority or
alter execution. Missing, unknown, duplicate, malformed, oversized, and wrong-typed fields are
rejected before application I/O. No second tool or arbitrary tool name is accepted.

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
reports, receipts, and the journal retain the existing effect-gateway disclosure limits.

## Support limits

This is one bounded transport adapter, not a generic MCP server, tool registry, SDK, plugin host, or
remote service. It implements the fixed official wire surface directly with existing JSON and
runtime dependencies; no MCP SDK dependency is required. The [security policy](../SECURITY.md) owns
maintenance and reporting posture. The exact release owns artifact qualification and availability.
No response-time, remediation, availability, platform, or production-support SLA is provided.

## Official protocol basis

The wire contract is based on the official MCP `2025-11-25` [versioning], [lifecycle], [stdio
transport], [messages], [tools], and [cancellation] specifications and their [canonical schema].
Kapsel does not use the official Rust SDK, [`rmcp`]. Its generic server and tool machinery would
widen this fixed surface without reducing the bounds Kapsel must enforce.

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
