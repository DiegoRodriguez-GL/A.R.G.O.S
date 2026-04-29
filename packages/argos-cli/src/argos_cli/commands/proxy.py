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
import statistics
import time
from pathlib import Path
from typing import Annotated, Final

import typer
from argos_proxy import (
    ChainInterceptor,
    ForensicsStore,
    OtelTracingInterceptor,
    PassThroughInterceptor,
    PIIDetector,
    ProxyInterceptor,
    ProxyServer,
    Request,
    Response,
    ScopeDetector,
    SqliteForensicsSink,
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


@proxy_app.command("bench")
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
# argos proxy run -- placeholder until Phase 6 wires the real listener.
# ---------------------------------------------------------------------------


@proxy_app.command("run")
def run(
    upstream_command: Annotated[
        list[str] | None,
        typer.Argument(
            help=(
                "Upstream MCP server command. Example: 'npx @modelcontextprotocol/"
                "server-filesystem /tmp'."
            ),
        ),
    ] = None,
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
) -> None:
    """Connect a downstream client to an upstream MCP server, audited.

    Phase 5 wires only the stdio upstream. The TCP listener for the
    downstream side ships in Phase 6. For now this command launches
    the upstream subprocess, runs detectors against a synthetic
    handshake, and exits -- enough for CI to verify the integration
    works end-to-end.
    """
    if not upstream_command:
        get_err_console().print("[argos.danger]error:[/] missing upstream command")
        raise typer.Exit(code=2)
    asyncio.run(
        _run_proxy(
            upstream_argv=tuple(upstream_command),
            forensics_db=forensics_db,
            enable_otel=enable_otel,
            enable_drift=enable_drift,
            enable_pii=enable_pii,
            allowed_tools=tuple(allowed_tools) if allowed_tools else (),
        ),
    )


async def _run_proxy(
    *,
    upstream_argv: tuple[str, ...],
    forensics_db: Path,
    enable_otel: bool,
    enable_drift: bool,
    enable_pii: bool,
    allowed_tools: tuple[str, ...],
) -> None:
    """Lifecycle wiring used by ``argos proxy run`` and the integration test."""
    store = ForensicsStore(forensics_db)
    await store.open()
    sink = SqliteForensicsSink(store)
    chain: list[ProxyInterceptor] = []
    if enable_otel:
        chain.append(OtelTracingInterceptor())
    if enable_drift:
        chain.append(ToolDriftDetector(sink, mode="warn"))
    if enable_pii:
        chain.append(PIIDetector(sink))
    chain.append(
        ScopeDetector(sink, allowed_tools=allowed_tools, block_on_violation=bool(allowed_tools)),
    )
    interceptor = ChainInterceptor(*chain)

    # The handshake-only invocation: open a paired in-memory transport,
    # spawn the upstream subprocess (Phase 6 will switch this to a real
    # TCP listener), perform a tools/list round-trip, close.
    from argos_proxy import StdioTransport  # noqa: PLC0415

    upstream = StdioTransport(upstream_argv)
    client_side, proxy_in = make_transport_pair()
    server = ProxyServer(client=proxy_in, upstream=upstream, interceptor=interceptor)
    server_task = asyncio.create_task(server.run())
    await asyncio.sleep(0)
    try:
        await client_side.send(Request(method="initialize", id=1))
        # Wait briefly for the upstream to handshake; abort on close.
        try:
            await asyncio.wait_for(client_side.receive(), timeout=5.0)
        except TimeoutError:
            get_err_console().print("[argos.warn]upstream did not respond within 5s[/]")
    finally:
        await server.stop()
        await store.close()
        try:
            await server_task
        except Exception:  # noqa: BLE001
            pass
    findings = await store.findings()
    get_console().print(
        f"[argos.ok]proxy session complete:[/] {len(findings)} findings persisted to "
        f"{forensics_db}",
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
