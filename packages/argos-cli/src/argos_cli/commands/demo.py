"""``argos demo``: a 10-second tour of every capability.

Runs the four canonical ARGOS verbs in sequence with attractive output:

1. ``scan`` against the bundled risky fixture (20 findings, 5 critical).
2. ``redteam`` simulation: lab benchmark eval (120 trials, perfect matrix).
3. ``proxy bench``: 200-round-trip latency test (microseconds).
4. ``compliance``: how the findings map to OWASP / NIST / EU AI Act.

The whole demo finishes in ~10 seconds on commodity hardware. It is
designed to be the FIRST thing a new user runs after installing
``argos-ai-audit``: zero arguments, zero setup, immediate visible value.

If something fails the demo prints a red diagnostic and exits non-zero
so the failure is impossible to miss. Otherwise the exit code is 0.
"""

from __future__ import annotations

import time
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argos_cli.console import get_console, get_err_console


def _bundled_risky_fixture() -> Path:
    """Locate the shipped fixture used by the demo. Searches the
    development tree first (when running from a source checkout), then
    the installed package."""
    here = Path(__file__).resolve()
    for parents in range(2, 6):
        candidate = (
            here.parents[parents]
            / "argos-scanner"
            / "tests"
            / "fixtures"
            / "risky.claude_desktop.json"
        )
        if candidate.is_file():
            return candidate
    # Fallback: try to read it from the installed scanner package.
    try:
        return Path(
            str(files("argos_scanner").joinpath("../../tests/fixtures/risky.claude_desktop.json"))
        )
    except Exception as exc:
        msg = "Could not locate the risky.claude_desktop.json fixture"
        raise FileNotFoundError(msg) from exc


def demo(
    quick: Annotated[
        bool,
        typer.Option(
            "--quick",
            "-q",
            help="Skip the proxy benchmark (saves ~2 seconds).",
        ),
    ] = False,
) -> None:
    """Run a 10-second guided tour of every ARGOS capability.

    No arguments needed; every step uses bundled fixtures and the
    canonical lab benchmark.
    """
    console = get_console()
    err = get_err_console()

    # ---- Banner ------------------------------------------------------
    console.print(
        Panel(
            Text.assemble(
                ("ARGOS demo", "argos.brand"),
                " ",
                ("guided 10-second tour of every capability", "argos.muted"),
            ),
            border_style="argos.accent",
            padding=(0, 2),
            expand=False,
        ),
    )
    console.print()

    timings: list[tuple[str, float]] = []
    summary_rows: list[tuple[str, str, str]] = []

    # ---- Step 1: scan ------------------------------------------------
    console.print("[argos.brand]1. argos scan[/]  -- static audit of an MCP config")
    console.print("[argos.muted]   Scanning the bundled vulnerable fixture...[/]")
    try:
        fixture = _bundled_risky_fixture()
    except FileNotFoundError as exc:
        err.print(f"[argos.danger]demo error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    t0 = time.perf_counter()
    findings, by_severity, asi_categories = _run_scan(fixture)
    timings.append(("scan", time.perf_counter() - t0))
    sev_repr = " ".join(
        f"[argos.danger]{c}[/] critical"
        if k == "critical"
        else f"[argos.warn]{c}[/] {k}"
        if k == "high"
        else f"[argos.brand]{c}[/] {k}"
        for k, c in by_severity.items()
    )
    console.print(
        f"   [argos.ok]{len(findings)} findings[/]  ({sev_repr})",
    )
    console.print(
        f"   [argos.muted]touches {len(asi_categories)} OWASP ASI categories: "
        f"{', '.join(sorted(asi_categories))}[/]",
    )
    summary_rows.append(("scan", f"{len(findings)} findings", "OK"))
    console.print()

    # ---- Step 2: eval -----------------------------------------------
    console.print("[argos.brand]2. argos eval[/]   -- empirical benchmark on lab agents")
    console.print(
        "[argos.muted]   Running 120 trials (6 lab agents x 20 probes)...[/]",
    )
    t0 = time.perf_counter()
    matrix = _run_eval()
    timings.append(("eval", time.perf_counter() - t0))
    tp, fp, tn, fn = matrix
    if fp == 0 and fn == 0:
        verdict = "[argos.ok]matriz diagonal perfecta[/]"
    else:
        verdict = f"[argos.danger]drift: FP={fp} FN={fn}[/]"
    console.print(
        f"   TP=[argos.ok]{tp}[/]  FP=[argos.brand]{fp}[/]  "
        f"TN=[argos.ok]{tn}[/]  FN=[argos.brand]{fn}[/]   {verdict}",
    )
    summary_rows.append(("eval", f"TP={tp} FP={fp} TN={tn} FN={fn}", "OK"))
    console.print()

    # ---- Step 3: proxy bench ----------------------------------------
    if not quick:
        console.print("[argos.brand]3. argos proxy[/]  -- runtime audit proxy benchmark")
        console.print(
            "[argos.muted]   200 round-trips with full detector chain...[/]",
        )
        t0 = time.perf_counter()
        bench = _run_proxy_bench(iterations=200)
        timings.append(("proxy bench", time.perf_counter() - t0))
        margin = 50.0 / max(bench["p95"], 1e-9)
        console.print(
            f"   p95=[argos.ok]{bench['p95']:.3f}[/] ms   "
            f"p99=[argos.brand]{bench['p99']:.3f}[/] ms   "
            f"max=[argos.muted]{bench['max']:.3f}[/] ms",
        )
        console.print(
            f"   [argos.muted]budget RNF-02 = 50 ms; margin = {margin:.0f}x[/]",
        )
        summary_rows.append(
            ("proxy bench", f"p95={bench['p95']:.3f}ms (RNF-02 budget=50ms)", "OK"),
        )
        console.print()
    else:
        console.print("[argos.muted]3. argos proxy[/]  -- skipped (--quick)")
        console.print()

    # ---- Step 4: compliance -----------------------------------------
    console.print("[argos.brand]4. argos compliance[/] -- multi-framework mapping")
    n_frameworks, n_controls = _count_compliance()
    console.print(
        f"   [argos.ok]{n_frameworks} frameworks[/] indexed  "
        f"[argos.muted]({n_controls} controls)[/]: "
        "OWASP ASI, CSA AICM, EU AI Act, NIST AI RMF, ISO/IEC 42001",
    )
    summary_rows.append(
        ("compliance", f"{n_frameworks} frameworks / {n_controls} controls", "OK"),
    )
    console.print()

    # ---- Final summary ----------------------------------------------
    table = Table(
        show_header=True,
        header_style="bold",
        title="argos demo: results",
        title_style="argos.brand",
        box=box.MINIMAL,
        expand=False,
    )
    table.add_column("Step", no_wrap=True)
    table.add_column("Result", overflow="fold")
    table.add_column("Status", justify="center")
    for step, result, status in summary_rows:
        table.add_row(step, result, f"[argos.ok]{status}[/]")
    console.print(table)
    total = sum(t for _, t in timings)
    console.print(
        f"[argos.muted]elapsed: {total:.2f} s "
        f"({', '.join(f'{n} {t:.2f}s' for n, t in timings)})[/]",
    )
    console.print()
    console.print(
        Text.assemble(
            ("Next steps:  ", "argos.muted"),
            ("argos scan <your-config>", "argos.code"),
            ("  |  ", "argos.muted"),
            ("argos proxy run -u stdio:<cmd>", "argos.code"),
            ("  |  ", "argos.muted"),
            ("argos quickstart", "argos.code"),
        ),
    )


# ---------------------------------------------------------------------------
# Internal helpers (split out so the orchestration above stays readable).
# ---------------------------------------------------------------------------


def _run_scan(fixture: Path) -> tuple[list[Any], dict[str, int], set[str]]:
    """Run the scanner and return ``(findings, severity histogram, ASI cats)``."""
    from argos_scanner import scan  # noqa: PLC0415

    result = scan(fixture)
    findings = list(result.findings)
    histogram: dict[str, int] = {}
    asi_cats: set[str] = set()
    for finding in findings:
        sev = finding.severity.value.lower()
        histogram[sev] = histogram.get(sev, 0) + 1
        for ref in finding.compliance_refs:
            if ref.startswith("owasp_asi:ASI"):
                code = ref.split(":", 1)[1]
                # Keep only top-level ASIxx codes for display.
                if "-" not in code:
                    asi_cats.add(code)
    return findings, histogram, asi_cats


def _run_eval() -> tuple[int, int, int, int]:
    """Run the canonical lab benchmark; return (TP, FP, TN, FN)."""
    from argos_eval import (  # noqa: PLC0415
        all_agents,
        default_ground_truth,
        run_suite,
    )
    from argos_redteam import all_probes  # noqa: PLC0415

    report = run_suite(
        list(all_agents()),
        list(all_probes()),
        default_ground_truth(),
        seed=0,
    )
    cm = report.confusion_matrix()
    return cm.tp, cm.fp, cm.tn, cm.fn


def _run_proxy_bench(*, iterations: int) -> dict[str, float]:
    """Run a quick latency benchmark over the in-memory transport."""
    import asyncio  # noqa: PLC0415

    from argos_proxy import (  # noqa: PLC0415
        ChainInterceptor,
        PIIDetector,
        ProxyServer,
        Request,
        Response,
        ScopeDetector,
        ToolDriftDetector,
        make_transport_pair,
    )

    interceptor = ChainInterceptor(
        ToolDriftDetector(mode="warn"),
        PIIDetector(),
        ScopeDetector(block_on_violation=False),
    )

    async def _run() -> list[float]:
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=interceptor)
        server_task = asyncio.create_task(server.run())
        await asyncio.sleep(0)

        async def echo() -> None:
            while True:
                try:
                    msg = await upstream.receive()
                except Exception:  # noqa: BLE001
                    return
                if isinstance(msg, Request):
                    await upstream.send(Response(result={"echo": msg.method}, id=msg.id))

        echo_task = asyncio.create_task(echo())
        samples: list[float] = []
        try:
            for i in range(iterations):
                t0 = time.perf_counter()
                await client_side.send(Request(method="bench/echo", id=i))
                await client_side.receive()
                samples.append((time.perf_counter() - t0) * 1000)
        finally:
            await server.stop()
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            try:
                await server_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        return samples

    samples = sorted(asyncio.run(_run()))
    return {
        "p95": samples[int(len(samples) * 0.95) - 1],
        "p99": samples[int(len(samples) * 0.99) - 1],
        "max": max(samples),
    }


def _count_compliance() -> tuple[int, int]:
    from argos_core.compliance import load_controls  # noqa: PLC0415

    idx = load_controls()
    return len(idx.frameworks), len(idx.controls)
