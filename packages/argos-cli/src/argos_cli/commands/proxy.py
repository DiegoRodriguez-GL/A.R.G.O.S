"""``argos proxy``: transparent MCP audit proxy.

Two subcommands:

- ``argos proxy run``: spawns an upstream subprocess, opens a TCP
  listener and ferries JSON-RPC traffic between the two while running
  the configured detectors.
- ``argos proxy bench``: end-to-end latency benchmark used by Phase 5
  to verify RNF-02 (< 50 ms p95). Exits non-zero on regression.

The CLI uses the in-memory transport when running without a real
upstream so the smoke command in CI does not require a live MCP
server.
"""

from __future__ import annotations

import asyncio
import contextlib
import statistics
import time
from pathlib import Path
from typing import Annotated, Final

import typer
from argos_proxy import (
    ChainInterceptor,
    FindingSink,
    ForensicsStore,
    OtelTracingInterceptor,
    PassThroughInterceptor,
    PIIDetector,
    ProxyInterceptor,
    ProxyListener,
    ProxyServer,
    Request,
    Response,
    ScopeDetector,
    SqliteForensicsSink,
    StdioUpstreamFactory,
    TcpUpstreamFactory,
    ToolDriftDetector,
    make_transport_pair,
)

from argos_cli.console import get_console, get_err_console

#: Default p95 latency target for the bench command. Mirrors RNF-02.
DEFAULT_LATENCY_BUDGET_MS: Final[float] = 50.0


proxy_app = typer.Typer(
    name="proxy",
    help="Transparent MCP audit proxy.",
    add_completion=False,
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# argos proxy bench
# ---------------------------------------------------------------------------


_BENCH_EPILOG = """\
[bold]Examples[/]:

  [cyan]argos proxy bench[/]
    1000 round-trips with the full detector chain (default)

  [cyan]argos proxy bench --no-detectors -n 5000[/]
    isolate transport overhead, longer sample

  [cyan]argos proxy bench --budget-ms 25[/]
    tighter latency budget; exit 1 if p95 exceeds it (CI gate)
"""


@proxy_app.command("bench", epilog=_BENCH_EPILOG)
def bench(
    iterations: Annotated[
        int,
        typer.Option(
            "--iterations",
            "-n",
            help="Number of (request, response) round-trips.",
            min=10,
            max=100_000,
        ),
    ] = 1000,
    budget_ms: Annotated[
        float,
        typer.Option(
            "--budget-ms",
            help="p95 latency target in milliseconds. Exit code 1 on miss.",
        ),
    ] = DEFAULT_LATENCY_BUDGET_MS,
    with_detectors: Annotated[
        bool,
        typer.Option(
            "--detectors/--no-detectors",
            help="Enable the default detector chain (more realistic).",
        ),
    ] = True,
) -> None:
    """End-to-end latency benchmark over the in-memory transport.

    Reports min / mean / median / p95 / p99 / max and exits non-zero
    when p95 exceeds ``--budget-ms``. Used by CI to enforce RNF-02.
    """
    interceptor: ProxyInterceptor
    if with_detectors:
        # ScopeDetector with ``block_on_violation=False`` so the bench
        # exercises the detection cost without short-circuiting the
        # synthetic ``bench/echo`` method (which would never be in any
        # realistic allowlist).
        interceptor = ChainInterceptor(
            ToolDriftDetector(mode="warn"),
            PIIDetector(),
            ScopeDetector(block_on_violation=False),
        )
    else:
        interceptor = PassThroughInterceptor()

    samples = asyncio.run(_run_bench(iterations=iterations, interceptor=interceptor))
    samples_sorted = sorted(samples)
    p95 = samples_sorted[int(0.95 * len(samples_sorted)) - 1]
    p99 = samples_sorted[int(0.99 * len(samples_sorted)) - 1]
    out = get_console()
    out.print(f"[argos.brand]argos proxy bench:[/] {len(samples)} round-trips")
    out.print(
        f"  [argos.muted]min[/]    [argos.brand]{min(samples):.3f}[/] ms"
        f"   [argos.muted]mean[/] [argos.brand]{statistics.fmean(samples):.3f}[/] ms"
        f"   [argos.muted]median[/] [argos.brand]{statistics.median(samples):.3f}[/] ms",
    )
    out.print(
        f"  [argos.muted]p95[/]    [argos.brand]{p95:.3f}[/] ms"
        f"   [argos.muted]p99[/]  [argos.brand]{p99:.3f}[/] ms"
        f"   [argos.muted]max[/]    [argos.brand]{max(samples):.3f}[/] ms",
    )
    out.print(f"  [argos.muted]budget p95[/] [argos.brand]{budget_ms:.3f}[/] ms")
    if p95 > budget_ms:
        get_err_console().print(
            f"[argos.danger]bench fail:[/] p95={p95:.3f}ms > budget={budget_ms:.3f}ms",
        )
        raise typer.Exit(code=1)
    out.print("[argos.ok]bench pass[/]")


async def _run_bench(
    *,
    iterations: int,
    interceptor: ProxyInterceptor,
) -> list[float]:
    client_side, proxy_in = make_transport_pair()
    proxy_out, upstream = make_transport_pair()
    server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=interceptor)
    server_task = asyncio.create_task(server.run())
    await asyncio.sleep(0)

    async def upstream_echo() -> None:
        while True:
            try:
                msg = await upstream.receive()
            except Exception:  # noqa: BLE001 - transport closed -> we exit
                return
            if isinstance(msg, Request):
                await upstream.send(Response(result={"echo": msg.method}, id=msg.id))

    upstream_task = asyncio.create_task(upstream_echo())

    samples: list[float] = []
    try:
        for i in range(iterations):
            req = Request(method="bench/echo", params={"i": i}, id=i)
            t0 = time.perf_counter()
            await client_side.send(req)
            await client_side.receive()
            samples.append((time.perf_counter() - t0) * 1000)
    finally:
        await server.stop()
        upstream_task.cancel()
        try:
            await upstream_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        try:
            await server_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    return samples


# ---------------------------------------------------------------------------
# argos proxy run -- real TCP listener with multi-session lifecycle.
# ---------------------------------------------------------------------------


def _parse_listen(value: str) -> tuple[str, int]:
    """Parse ``host:port`` (IPv4 or IPv6) into a tuple.

    Accepts ``127.0.0.1:8765`` and ``[::1]:8765``. Returns
    ``("127.0.0.1", 8765)`` / ``("::1", 8765)``."""
    raw = value.strip()
    if raw.startswith("["):
        # IPv6 with brackets: [::1]:8765
        end = raw.find("]")
        if end < 0 or end + 1 >= len(raw) or raw[end + 1] != ":":
            msg = f"invalid IPv6 listen address: {value!r}"
            raise typer.BadParameter(msg)
        host = raw[1:end]
        port_str = raw[end + 2 :]
    else:
        if raw.count(":") != 1:
            msg = f"listen must be host:port, got {value!r}"
            raise typer.BadParameter(msg)
        host, port_str = raw.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as exc:
        msg = f"port must be an integer, got {port_str!r}"
        raise typer.BadParameter(msg) from exc
    if port < 0 or port > 65535:
        msg = f"port {port} out of range [0, 65535]"
        raise typer.BadParameter(msg)
    if not host:
        msg = "host part is empty"
        raise typer.BadParameter(msg)
    return host, port


def _parse_upstream_url(value: str) -> tuple[str, tuple[str, ...] | tuple[str, int]]:
    """Parse the ``--upstream`` argument.

    Two forms:

    - ``stdio:<argv shell-style>`` -- spawn a subprocess. Example:
      ``stdio:npx @modelcontextprotocol/server-filesystem /tmp``.
    - ``tcp:<host>:<port>`` -- open a TCP connection. Example:
      ``tcp:127.0.0.1:9000``.

    Returns ``(kind, payload)`` where ``kind`` is ``"stdio"`` or
    ``"tcp"`` and payload is the tuple to pass to the factory.
    """
    if value.startswith("stdio:"):
        rest = value[len("stdio:") :].strip()
        if not rest:
            msg = "stdio upstream requires a command"
            raise typer.BadParameter(msg)
        # Split shell-style. We do NOT use shlex on Windows because the
        # POSIX rules differ; for argument lists with spaces, the user
        # should use --upstream-arg multiple times. The shell-style
        # split here covers the common case: 'stdio:npx pkg arg'.
        import shlex  # noqa: PLC0415

        argv = tuple(
            shlex.split(rest, posix=False) if rest.startswith("npx") else shlex.split(rest)
        )
        if not argv:
            msg = "stdio upstream argv parsing produced an empty tuple"
            raise typer.BadParameter(msg)
        return "stdio", argv
    if value.startswith("tcp:"):
        rest = value[len("tcp:") :].strip()
        host, port = _parse_listen(rest)  # same grammar
        return "tcp", (host, port)
    msg = (
        f"upstream must start with 'stdio:' or 'tcp:', got {value!r}. "
        f"Examples: 'stdio:npx @modelcontextprotocol/server-filesystem /tmp', "
        f"'tcp:127.0.0.1:9000'."
    )
    raise typer.BadParameter(msg)


_RUN_EPILOG = """\
[bold]Examples[/]:

  [cyan]argos proxy run -u stdio:'python -m my_mcp_server'[/]
    minimal invocation, defaults to listen 127.0.0.1:8765

  [cyan]argos proxy run -u stdio:'npx pkg' -l 127.0.0.1:9000[/]
    custom listen port

  [cyan]argos proxy run -u tcp:127.0.0.1:9000 --duration 30[/]
    TCP upstream, auto-stop after 30 seconds (CI smoke)

  [cyan]argos proxy run -u stdio:'cmd' --no-pii --allow-tool 'safe.*'[/]
    disable PII detector, restrict tools to a glob

[bold]Stop[/] with Ctrl+C; active sessions drain for [cyan]--drain-timeout[/]
seconds before any straggler is cancelled.
"""


@proxy_app.command("run", epilog=_RUN_EPILOG)
def run(
    upstream: Annotated[
        str,
        typer.Option(
            "--upstream",
            "-u",
            help=(
                "Upstream URL. Forms: 'stdio:<argv>' or 'tcp:<host>:<port>'. "
                "Example: 'stdio:python -m my_mcp_server'."
            ),
        ),
    ],
    listen: Annotated[
        str,
        typer.Option(
            "--listen",
            "-l",
            help=(
                "Listen address as host:port. Example: '127.0.0.1:8765'. "
                "Use port 0 to bind an ephemeral port."
            ),
        ),
    ] = "127.0.0.1:8765",
    forensics_db: Annotated[
        Path,
        typer.Option(
            "--forensics-db",
            "-f",
            help="SQLite forensics database path.",
            file_okay=True,
            dir_okay=False,
            writable=True,
        ),
    ] = Path("argos-proxy.sqlite3"),
    enable_otel: Annotated[
        bool,
        typer.Option("--otel/--no-otel", help="Emit OpenTelemetry spans."),
    ] = True,
    enable_drift: Annotated[
        bool,
        typer.Option("--drift/--no-drift", help="Enable tool drift detector."),
    ] = True,
    enable_pii: Annotated[
        bool,
        typer.Option("--pii/--no-pii", help="Enable PII detector."),
    ] = True,
    allowed_tools: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-tool",
            help="Tool name (or glob) to permit. Repeatable. Empty = allow all.",
        ),
    ] = None,
    max_sessions: Annotated[
        int,
        typer.Option(
            "--max-sessions",
            help="Concurrent session cap (default 64).",
            min=1,
            max=1024,
        ),
    ] = 64,
    idle_timeout: Annotated[
        float,
        typer.Option(
            "--idle-timeout",
            help="Per-session inactivity timeout in seconds (default 600).",
            min=1.0,
        ),
    ] = 600.0,
    drain_timeout: Annotated[
        float,
        typer.Option(
            "--drain-timeout",
            help=(
                "Seconds to wait on Ctrl+C for active sessions to finish before cancelling them."
            ),
            min=0.0,
        ),
    ] = 5.0,
    duration: Annotated[
        float,
        typer.Option(
            "--duration",
            help=(
                "Maximum lifetime of the listener in seconds (0 = run "
                "until interrupted). Useful for CI smoke runs."
            ),
            min=0.0,
        ),
    ] = 0.0,
) -> None:
    """Run the audit proxy: bind a TCP listener, ferry every accepted client
    through the configured detector chain, and persist forensics to SQLite.

    Stop with Ctrl+C; active sessions are drained for up to
    ``--drain-timeout`` seconds before any straggler is cancelled.
    """
    listen_host, listen_port = _parse_listen(listen)
    upstream_kind, upstream_payload = _parse_upstream_url(upstream)
    asyncio.run(
        _run_listener(
            listen_host=listen_host,
            listen_port=listen_port,
            upstream_kind=upstream_kind,
            upstream_payload=upstream_payload,
            forensics_db=forensics_db,
            enable_otel=enable_otel,
            enable_drift=enable_drift,
            enable_pii=enable_pii,
            allowed_tools=tuple(allowed_tools) if allowed_tools else (),
            max_sessions=max_sessions,
            idle_timeout=idle_timeout,
            drain_timeout=drain_timeout,
            duration=duration,
        ),
    )


def _build_shared_interceptor(
    *,
    sink: FindingSink,
    enable_otel: bool,
    enable_pii: bool,
    allowed_tools: tuple[str, ...],
) -> list[ProxyInterceptor]:
    """Interceptor shared across sessions. Stateless detectors only.

    Tool drift is per-session (it pins a baseline) so it must NOT live
    here -- it is injected via the per-session interceptor factory."""
    chain: list[ProxyInterceptor] = []
    if enable_otel:
        chain.append(OtelTracingInterceptor())
    if enable_pii:
        chain.append(PIIDetector(sink))
    chain.append(
        ScopeDetector(
            sink,
            allowed_tools=allowed_tools,
            block_on_violation=bool(allowed_tools),
        ),
    )
    return chain


async def _run_listener(
    *,
    listen_host: str,
    listen_port: int,
    upstream_kind: str,
    upstream_payload: tuple[str, ...] | tuple[str, int],
    forensics_db: Path,
    enable_otel: bool,
    enable_drift: bool,
    enable_pii: bool,
    allowed_tools: tuple[str, ...],
    max_sessions: int,
    idle_timeout: float,
    drain_timeout: float,
    duration: float,
) -> None:
    store = ForensicsStore(forensics_db)
    await store.open()
    sink = SqliteForensicsSink(store)

    base_chain = _build_shared_interceptor(
        sink=sink,
        enable_otel=enable_otel,
        enable_pii=enable_pii,
        allowed_tools=allowed_tools,
    )

    def make_session_interceptor() -> ProxyInterceptor:
        # Per-session: tool drift detector with a fresh baseline. The
        # rest of the chain is stateless and shared.
        chain = list(base_chain)
        if enable_drift:
            chain.insert(0, ToolDriftDetector(sink, mode="warn"))
        return ChainInterceptor(*chain)

    upstream_factory: StdioUpstreamFactory | TcpUpstreamFactory
    if upstream_kind == "stdio":
        argv = tuple(str(x) for x in upstream_payload)
        upstream_factory = StdioUpstreamFactory(argv)
        upstream_repr = f"stdio:{' '.join(argv)}"
    else:
        host_str = str(upstream_payload[0])
        port_int = int(upstream_payload[1])
        upstream_factory = TcpUpstreamFactory(host_str, port_int)
        upstream_repr = f"tcp:{host_str}:{port_int}"

    listener = ProxyListener(
        host=listen_host,
        port=listen_port,
        upstream_factory=upstream_factory,
        interceptor_factory=make_session_interceptor,
        max_sessions=max_sessions,
        session_idle_timeout=idle_timeout,
        drain_timeout=drain_timeout,
    )
    await listener.start()
    bound = listener.bound_address()
    bind_repr = f"{bound[0]}:{bound[1]}" if bound else f"{listen_host}:{listen_port}"
    get_console().print(
        f"[argos.ok]argos proxy:[/] listening on [argos.brand]{bind_repr}[/] "
        f"-> upstream [argos.brand]{upstream_repr}[/]",
    )
    get_console().print(
        f"  [argos.muted]forensics_db[/] {forensics_db}   "
        f"[argos.muted]max_sessions[/] {max_sessions}   "
        f"[argos.muted]idle_timeout[/] {idle_timeout:.0f}s",
    )

    serve_task = asyncio.create_task(listener.serve_forever())
    try:
        if duration > 0:
            try:
                await asyncio.wait_for(asyncio.shield(serve_task), timeout=duration)
            except TimeoutError:
                pass
        else:
            await serve_task
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await listener.stop()
        with contextlib.suppress(Exception):
            await serve_task
        await store.close()

    findings = await store.findings()
    get_console().print(
        f"[argos.ok]proxy stopped:[/] {listener.sessions.total_started} sessions served, "
        f"{len(findings)} findings persisted to {forensics_db}",
    )


# Backwards-compatible single-callable export used by the app router.
def proxy(
    listen: Annotated[
        str | None,
        typer.Option("--listen", help="host:port to bind (Phase 6)."),
    ] = None,
    upstream: Annotated[
        str | None,
        typer.Option("--upstream", help="Upstream MCP server URL (Phase 6)."),
    ] = None,
) -> None:
    """Run the ARGOS MCP audit proxy."""
    _ = (listen, upstream)
    get_console().print(
        "[argos.warn]argos proxy:[/] use [argos.brand]argos proxy bench[/] or "
        "[argos.brand]argos proxy run -- <upstream-cmd>[/] (Typer subcommands).",
    )
    raise typer.Exit(code=2)
