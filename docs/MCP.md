# MCP adapter

This contract defines the fixed ID-only resident-service stdio bridge. The
[service contract](KAPSEL_SERVICE.md#version-1-socket-adoption-contract) owns socket requests and
projections. The [effect gateway](EFFECT_GATEWAY.md) owns authority, recovery, results and receipts.
The bridge is not a generic MCP host or a remote service.

## Compatibility posture

HEAD removes direct `kapsel mcp` execution. The older
[v0.2.0 MCP contract](https://github.com/kapsel-cloud/kapsel/blob/v0.2.0/docs/MCP.md) and published
v0.3.0 retain their original binaries and contracts. Direct/macOS-source execution is lost; this is
not transparent migration. [Scope](SCOPE.md#head-execution-and-v04x-compatibility) owns the approved
v0.4.x boundary. `serverInfo.version` identifies the running package, not production readiness.

## Resident-service bridge (current source only)

`/usr/bin/kapsel-service-mcp` takes no arguments or operator document. The operator launches it
under the confined `kapsel-service-caller` identity and `kapsel-service-callers` effective group. It
connects only to `/run/kapsel/kapseld.sock` using the fixed version-1 service protocol. The host and
service peer credentials enforce access. Caller input cannot choose a socket, credential, grant,
authority file, export path, receiver or lifecycle state.

A process-launch configuration, provisioned outside caller tool input, is:

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

The confined Codex workflow uses the equivalent caller-owned configuration:

```toml
[mcp_servers.kapsel_service]
command = "/usr/bin/kapsel-service-mcp"
args = []
```

The bridge supports exactly MCP `2025-11-25` over line-delimited UTF-8 JSON-RPC 2.0 stdio.
`serverInfo.name` is `kapsel-service`; its version is the running package version. Only `tools` is
advertised. There are no server-originated messages, batches, embedded newlines, HTTP, SSE or
`Content-Length` framing. Input is at most 16 KiB including LF; output is at most 96 KiB including
LF to carry bounded original receipt hex. Invalid or incomplete frames cannot create an action.

## Lifecycle

The first request is `initialize`. Request IDs are numeric non-null values or non-null strings of at
most 128 UTF-8 bytes. Invalid IDs receive `Invalid Request` with `id: null`. Initialization returns
the sole supported protocol version when the client proposes another version. A client that does not
support that version must disconnect. The bridge becomes ready only after
`notifications/initialized`; tools before that notification and a second initialization are invalid.

The bridge processes one request at a time. Notifications receive no response. Unknown notifications
and late or unknown cancellation notifications are ignored. Initialization cannot be cancelled. The
bridge cannot inspect cancellation during a socket exchange. Disconnect does not cancel the
service's retained job. A missing response is not evidence of non-admission or a receiver outcome.

There is no `shutdown` or `exit` method. Closing stdin requests graceful shutdown after the current
complete request and its response. An incomplete final frame is rejected without a response. Process
termination does not alter retained service history. Read the original action ID after loss;
explicitly select that same ID only when the service disposition permits.

## Fixed tools

`tools/list` returns exactly five tools, unpaginated. Each accepts one object without extra
properties. `kapsel.list_approved_actions` and `kapsel.list_operation_history` require `after`,
either null or a valid bounded operation ID. `kapsel.get_status`, `kapsel.get_receipt` and
`kapsel.submit` require exactly `operation_id`: a 1–128 byte identity matching `^[A-Za-z0-9._:-]+$`.
The service verifies cursor semantics.

Only `kapsel.submit` mutates service state. It selects an approved ID or resumes that same ID.
Discovery, history, status and receipt are stored reads without receiver access or lifecycle
advancement. No new identity is minted after ambiguity. Tool arguments cannot supply effect tuples,
trust, credentials, signing material, paths or lifecycle controls.

## Responses and errors

Each tool returns one text item containing an object with `operation_id` (the selected ID, or null
for list calls) and `service` (the unchanged version-1 service object). The JSON-RPC ID is not the
durable operation ID. Local errors use the same envelope, fixed `service.status: "ERROR"` and a
bridge-local `error_class`. `ERROR` sets `isError: true`.

`NOT_FOUND`, `NOT_READY`, `NOT_ADMITTED` and `INDETERMINATE` remain distinct machine-readable
service facts, not JSON-RPC errors. Local exchange failure returns
`{"status":"ERROR","error_class":"service_exchange_uncertain"}`. Invalid response or receipt digest
returns `response_invalid`. Neither means that the service did not admit the action.

The service owns admission phase, rejection, execution disposition, receiver classification and
original signed receipt bytes/digest. The bridge does not export files, verify signatures or infer a
receiver outcome from a successful exchange. The fixed service client owns caller export.

| Code     | Message            | Use                                                             |
| -------- | ------------------ | --------------------------------------------------------------- |
| `-32700` | `Parse error`      | Invalid UTF-8 or JSON when an ID cannot be recovered.           |
| `-32600` | `Invalid Request`  | Invalid envelope, lifecycle, batch, notification or request ID. |
| `-32601` | `Method not found` | Unknown request method.                                         |
| `-32602` | `Invalid params`   | Invalid parameters, cursor, tool name or arguments.             |
| `-32603` | `Internal error`   | Bounded transport or serialization failure.                     |

Errors contain no `data`. Invalid envelopes use `id: null` when no valid ID is available. Every
object at every protocol depth rejects duplicate keys. Extra envelope or method fields are invalid.
Input failures do not echo values. Stdout contains only protocol messages. Bounded diagnostics
contain no request bytes, operator values, provider bodies or secrets.

## Support limits

There is no SDK, plugin host, arbitrary endpoint, public Rust API or production-support promise.
[Security](../SECURITY.md) owns reporting posture. Exact published releases own their bytes and
qualification. See [operator recovery](KAPSEL_SERVICE_OPERATOR.md#diagnose-and-resume) for same-ID
reconnection.

## Official protocol basis

The unchanged wire contract follows the MCP `2025-11-25` [versioning], [lifecycle], [stdio
transport], [messages], [tools] and [cancellation] specifications and their [canonical schema]. No
MCP SDK is used; the implementation retains its own fixed framing and authority bounds.

[versioning]: https://modelcontextprotocol.io/specification/2025-11-25/basic/versioning
[lifecycle]: https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
[stdio transport]: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio
[messages]: https://modelcontextprotocol.io/specification/2025-11-25/basic/messages
[tools]: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
[cancellation]:
  https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation
[canonical schema]:
  https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-11-25/schema.ts
