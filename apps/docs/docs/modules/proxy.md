# Audit proxy (`argos-proxy`)

The proxy sits between an MCP client and its server, forwards every JSON-RPC
2.0 message unchanged, runs detectors on the way, records the exchange for
forensics and emits OpenTelemetry spans. It detects and reports; it only
blocks when a scope allowlist is configured.

## Transports

| Side | Transports |
|------|-----------|
| Client (accepted) | NDJSON over TCP, `Content-Length` (stdio-style) framing, streamable-HTTP |
| Upstream | `stdio:<argv>`, `tcp:<host>:<port>`, `http://.../mcp` (streamable-HTTP, MCP 2025-03-26), `sse://.../sse[#post-path]` (legacy SSE) |

The HTTP/1.1 and SSE parsers are hand-written over asyncio (no external HTTP
library) and reject request-smuggling shapes: conflicting `Content-Length`
headers, `Content-Length` together with chunked encoding, oversized header
sections, negative or oversized lengths.

## Detectors

| Detector | What it flags |
|----------|---------------|
| `ToolDriftDetector` | Pins a SHA-256 baseline of every tool on the first `tools/list`; later additions, removals or mutations raise HIGH. `mode="block"` restores the baseline definitions. |
| `PIIDetector` | Emails, IBANs (mod-97), payment cards (Luhn), Spanish DNI / NIE in requests, responses and notifications. Snippets are redacted before they reach the sink. |
| `ScopeDetector` | Method and tool allowlists (globs). Out-of-scope `tools/call` is answered with `-32601` and never reaches the upstream. |

Upstream-initiated requests (sampling, elicitation) pass through the same
interceptor with `ctx.extra["reverse_request"] = True`, so a hostile server
cannot use them as an unaudited channel.

## Listener guarantees

- Bounded concurrency (`--max-sessions`, hard cap 1024) with a structured
  `server_busy` notice.
- Per-session idle timeout and graceful drain on shutdown.
- One `ProxyServer` and one fresh upstream per accepted client; per-session
  detector state (the drift baseline) never leaks between clients.

## Running it

```bash
argos proxy run -u stdio:'python -m my_mcp_server'
argos proxy run -u tcp:127.0.0.1:9000 --duration 30
argos proxy run -u http://localhost:9000/mcp --allow-tool 'fs.read*' --no-pii
argos proxy run -u sse://localhost:9000/sse -l 0.0.0.0:8765 --allow-external
```

The listener binds `127.0.0.1:8765` by default. Any non-loopback address is
refused unless `--allow-external` is present, and a warning banner is printed
when it is. At startup the proxy prints one JSON line
(`"event":"argos.proxy.identity"`) with its pid, socket, upstream and
forensics database so an operator can audit who owns the port.

## Forensics and telemetry

Every message and every finding is written to a SQLite database (WAL mode,
`--forensics-db`, default `argos-proxy.sqlite3`) with a correlation id that
ties requests to their responses. Spans are created per message with
`argos.correlation_id`, `argos.method` and `argos.direction`; nothing is
exported unless you install an OTLP exporter.

## Latency

```bash
argos proxy bench             # full detector chain, 1000 round-trips
argos proxy bench --budget-ms 25
```

The benchmark exits `1` when p95 exceeds the budget (50 ms by default, the
RNF-02 requirement). The measured p95 with all detectors is 0.054 ms over
2000 round-trips on an in-memory transport pair.
