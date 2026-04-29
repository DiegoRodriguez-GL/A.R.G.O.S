"""ARGOS audits ARGOS: end-to-end self-audit harness.

The script runs every ARGOS tool (``status``, ``rules list``,
``compliance list``, ``scan``, ``proxy bench``, ``eval``) over the
project's own fixtures and lab benchmark, captures each tool's output
and renders a single consolidated Markdown report.

Why dogfooding matters for the TFM:

- It demonstrates that ARGOS is operationally complete: every CLI verb
  has a real, repeatable execution path.
- It produces a reproducible artefact (the report) that can be attached
  to the empirical chapter as evidence of "the tool was run; here are
  the numbers".
- It surfaces operational regressions that unit tests miss (e.g. a CLI
  flag drift, a path that does not exist anymore, an environment
  variable assumption).

Usage::

    python scripts/argos_self_audit.py [--output DIR]

Default output directory is ``.tfm/self_audit/<timestamp>/`` -- which
the project's ``.gitignore`` keeps local. The Markdown report is
``REPORT.md`` inside that directory.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
from pathlib import Path
from textwrap import indent
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_BASE: Final[Path] = REPO_ROOT / ".tfm" / "self_audit"

# Fixture used as the "audit target" for the static scanner. This is
# the deliberately-vulnerable file shipped inside the scanner test
# package; running ARGOS over it should produce a known set of findings.
SCAN_FIXTURE: Final[Path] = (
    REPO_ROOT / "packages" / "argos-scanner" / "tests" / "fixtures" / "risky.claude_desktop.json"
)


def _python_with_argos_installed() -> str:
    """Return the venv python (so ``argos`` is importable) regardless
    of whether the script is invoked directly or under ``uv run``."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv) / "Scripts" / "python.exe",
            Path(venv) / "bin" / "python",
        ):
            if candidate.is_file():
                return str(candidate)
    return sys.executable


def _run(
    args: list[str],
    *,
    label: str,
    out_dir: Path,
    capture_file: str,
    expected_exit_codes: tuple[int, ...] = (0,),
) -> dict[str, object]:
    """Run ``args`` as a subprocess; persist stdout/stderr; return a
    summary dict for the report.

    ``expected_exit_codes`` is the set of return codes that count as
    "success" for the purpose of the self-audit gate. ``argos scan``
    intentionally exits 1 when findings are present (CI signal), so
    its task passes ``(0, 1)`` to mark both as expected.
    """
    print(f"[self-audit] running: {label}", file=sys.stderr)
    start = _dt.datetime.now(tz=_dt.UTC)
    proc = subprocess.run(  # noqa: S603 - controlled args
        args,
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    elapsed = (_dt.datetime.now(tz=_dt.UTC) - start).total_seconds()
    out_path = out_dir / capture_file
    out_path.write_text(proc.stdout, encoding="utf-8")
    if proc.stderr:
        (out_dir / f"{capture_file}.stderr").write_text(proc.stderr, encoding="utf-8")
    return {
        "label": label,
        "argv": args,
        "exit_code": proc.returncode,
        "expected_exit_codes": list(expected_exit_codes),
        "passed": proc.returncode in expected_exit_codes,
        "elapsed_seconds": round(elapsed, 3),
        "stdout_path": str(out_path.relative_to(out_dir)),
        "stdout_lines": len(proc.stdout.splitlines()),
        "stderr_lines": len(proc.stderr.splitlines()),
    }


# ---------------------------------------------------------------------------
# Each task is a small function that runs one ARGOS verb.
# ---------------------------------------------------------------------------


def task_status(out_dir: Path, *, py: str) -> dict[str, object]:
    return _run(
        [py, "-m", "argos_cli", "status"],
        label="argos status",
        out_dir=out_dir,
        capture_file="status.txt",
    )


def task_rules(out_dir: Path, *, py: str) -> dict[str, object]:
    return _run(
        [py, "-m", "argos_cli", "rules", "list"],
        label="argos rules list",
        out_dir=out_dir,
        capture_file="rules.txt",
    )


def task_compliance(out_dir: Path, *, py: str) -> dict[str, object]:
    return _run(
        [py, "-m", "argos_cli", "compliance", "list"],
        label="argos compliance list",
        out_dir=out_dir,
        capture_file="compliance.txt",
    )


def task_scan(out_dir: Path, *, py: str) -> dict[str, object]:
    """Static scan of the deliberately-vulnerable fixture.

    ``argos scan`` exits 1 when ANY finding is produced (the contract
    that lets it gate CI). This fixture is intentionally risky, so 1
    is the expected outcome -- we declare it as ``passed`` here."""
    if not SCAN_FIXTURE.is_file():
        msg = f"scan fixture not found at {SCAN_FIXTURE}"
        raise FileNotFoundError(msg)
    return _run(
        [
            py,
            "-m",
            "argos_cli",
            "scan",
            str(SCAN_FIXTURE),
            "--format",
            "jsonl",
            "--output",
            str(out_dir / "scan.jsonl"),
        ],
        label="argos scan (risky fixture)",
        out_dir=out_dir,
        capture_file="scan.txt",
        expected_exit_codes=(0, 1),
    )


def task_proxy_bench(out_dir: Path, *, py: str) -> dict[str, object]:
    return _run(
        [
            py,
            "-m",
            "argos_cli",
            "proxy",
            "bench",
            "--detectors",
            "-n",
            "2000",
            "--budget-ms",
            "50",
        ],
        label="argos proxy bench",
        out_dir=out_dir,
        capture_file="proxy_bench.txt",
    )


def task_proxy_bench_no_detectors(out_dir: Path, *, py: str) -> dict[str, object]:
    return _run(
        [
            py,
            "-m",
            "argos_cli",
            "proxy",
            "bench",
            "--no-detectors",
            "-n",
            "2000",
            "--budget-ms",
            "50",
        ],
        label="argos proxy bench (--no-detectors baseline)",
        out_dir=out_dir,
        capture_file="proxy_bench_baseline.txt",
    )


def task_eval(out_dir: Path, *, py: str) -> dict[str, object]:
    """Empirical evaluation of the lab benchmark.

    The eval CLI exits 0 on a clean run and 1 if any FP/FN appears;
    we keep the exit code in the summary so a regression in the lab
    surfaces as a non-zero status."""
    return _run(
        [
            py,
            "-m",
            "argos_cli",
            "eval",
            "--output",
            str(out_dir / "eval.html"),
            "--json",
            str(out_dir / "eval.json"),
            "--markdown",
            str(out_dir / "eval.md"),
            "--csv",
            str(out_dir / "eval.csv"),
            "--quiet",
        ],
        label="argos eval (canonical lab)",
        out_dir=out_dir,
        capture_file="eval.txt",
    )


# ---------------------------------------------------------------------------
# Report builder.
# ---------------------------------------------------------------------------


def _summarise_scan(out_dir: Path) -> dict[str, object]:
    """Parse the JSONL output into a per-severity histogram."""
    path = out_dir / "scan.jsonl"
    if not path.is_file():
        return {"total": 0, "by_severity": {}}
    histogram: dict[str, int] = {}
    rules: dict[str, int] = {}
    asi_categories: set[str] = set()
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        finding = json.loads(line)
        total += 1
        severity = finding.get("severity", "unknown").lower()
        histogram[severity] = histogram.get(severity, 0) + 1
        rule_id = finding.get("rule_id")
        if rule_id:
            rules[rule_id] = rules.get(rule_id, 0) + 1
        for ref in finding.get("compliance_refs", []):
            if ref.startswith("owasp_asi:ASI"):
                asi_categories.add(ref.split(":", 1)[1])
    return {
        "total": total,
        "by_severity": dict(sorted(histogram.items())),
        "by_rule": dict(sorted(rules.items())),
        "owasp_asi_touched": sorted(asi_categories),
    }


def _summarise_eval(out_dir: Path) -> dict[str, object]:
    """Pull the canonical numbers out of the JSON dump."""
    path = out_dir / "eval.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    tp = sum(
        1
        for c in cases
        if c["expected"] == "fire" and c["predicted"] == "fire" and not c.get("error")
    )
    tn = sum(
        1
        for c in cases
        if c["expected"] == "block" and c["predicted"] == "block" and not c.get("error")
    )
    fp = sum(
        1
        for c in cases
        if c["expected"] == "block" and c["predicted"] == "fire" and not c.get("error")
    )
    fn = sum(
        1
        for c in cases
        if c["expected"] == "fire" and c["predicted"] == "block" and not c.get("error")
    )
    errored = sum(1 for c in cases if c.get("error"))
    return {
        "trials": len(cases),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "errored": errored,
    }


def _summarise_proxy_bench(text: str) -> dict[str, str]:
    """Extract the percentile line from the bench output."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        for token in ("min", "mean", "median", "p95", "p99", "max"):
            if f" {token} " in f" {stripped} " or stripped.startswith(token):
                # Cheap parse: scan for `<token> <number>`.
                parts = stripped.replace("ms", "").split()
                for i, part in enumerate(parts):
                    if part == token and i + 1 < len(parts):
                        try:
                            float(parts[i + 1])
                            out[token] = parts[i + 1]
                        except ValueError:
                            pass
    return out


def render_report(
    out_dir: Path,
    runs: list[dict[str, object]],
) -> str:
    scan_summary = _summarise_scan(out_dir)
    eval_summary = _summarise_eval(out_dir)
    bench_text = (
        (out_dir / "proxy_bench.txt").read_text(encoding="utf-8")
        if (out_dir / "proxy_bench.txt").is_file()
        else ""
    )
    bench_baseline_text = (
        (out_dir / "proxy_bench_baseline.txt").read_text(encoding="utf-8")
        if (out_dir / "proxy_bench_baseline.txt").is_file()
        else ""
    )

    lines: list[str] = [
        "# ARGOS self-audit",
        "",
        f"Generated at: {_dt.datetime.now(tz=_dt.UTC).isoformat(timespec='seconds')}",
        "",
        "ARGOS was executed against its own repository as an end-to-end",
        "dogfooding exercise. Every CLI verb that produces a measurable",
        "artefact is captured below.",
        "",
        "## Run summary",
        "",
        "| Step | Status | Exit | Elapsed (s) | stdout lines |",
        "|------|:------:|-----:|------------:|-------------:|",
    ]
    for run in runs:
        status = "OK" if run.get("passed") else "FAIL"
        lines.append(
            f"| {run['label']} | {status} | {run['exit_code']} | "
            f"{run['elapsed_seconds']:.3f} | {run['stdout_lines']} |",
        )
    lines.extend(
        [
            "",
            "## Static scanner findings (`argos scan` over `risky.claude_desktop.json`)",
            "",
            f"Total findings: **{scan_summary.get('total', 0)}**",
            "",
            "By severity:",
            "",
            "| Severity | Count |",
            "|----------|------:|",
        ],
    )
    for sev, count in (scan_summary.get("by_severity") or {}).items():
        lines.append(f"| {sev} | {count} |")
    lines.extend(
        [
            "",
            "OWASP ASI categories touched: "
            + ", ".join(scan_summary.get("owasp_asi_touched") or []),
            "",
            "Top rules fired:",
            "",
            "| Rule | Count |",
            "|------|------:|",
        ],
    )
    for rule, count in sorted(
        (scan_summary.get("by_rule") or {}).items(),
        key=lambda kv: (-int(kv[1]), kv[0]),
    )[:10]:
        lines.append(f"| `{rule}` | {count} |")

    lines.extend(
        [
            "",
            "## Empirical evaluation (`argos eval`)",
            "",
            "| Metric | Value |",
            "|--------|------:|",
            f"| Trials | {eval_summary.get('trials', '?')} |",
            f"| TP | {eval_summary.get('tp', '?')} |",
            f"| FP | {eval_summary.get('fp', '?')} |",
            f"| TN | {eval_summary.get('tn', '?')} |",
            f"| FN | {eval_summary.get('fn', '?')} |",
            f"| Errored | {eval_summary.get('errored', '?')} |",
            "",
            "## Proxy benchmark (`argos proxy bench`, RNF-02 = 50 ms p95)",
            "",
            "With the full detector chain (drift + PII + scope, observability mode):",
            "",
            "```",
            bench_text.strip() or "(no output captured)",
            "```",
            "",
            "Pass-through baseline (no detectors), to isolate transport overhead:",
            "",
            "```",
            bench_baseline_text.strip() or "(no output captured)",
            "```",
            "",
            "## Reproducing this report",
            "",
            "```bash",
            "python scripts/argos_self_audit.py",
            "```",
            "",
            "Inputs:",
            "",
            f"- Scan fixture: `{SCAN_FIXTURE.relative_to(REPO_ROOT)}`",
            "- Lab benchmark: 6 lab agents x 20 probes (catalogue argos-eval/0.0.1)",
            "- Proxy bench: 2000 round-trips through the in-memory transport pair",
            "",
            "Outputs (in `.tfm/self_audit/<timestamp>/`):",
            "",
            "- `REPORT.md` -- this file",
            "- `scan.jsonl` -- per-finding JSON Lines",
            "- `eval.html`, `eval.json`, `eval.md`, `eval.csv` -- empirical artefacts",
            "- `proxy_bench.txt`, `proxy_bench_baseline.txt` -- bench captures",
            "- `status.txt`, `rules.txt`, `compliance.txt` -- inventory snapshots",
            "",
        ],
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=("Output directory. Defaults to .tfm/self_audit/<UTC-timestamp>/."),
    )
    parser.add_argument(
        "--skip-eval",
        action="store_true",
        help="Skip ``argos eval`` (slowest step). Useful for quick smoke runs.",
    )
    parser.add_argument(
        "--skip-bench",
        action="store_true",
        help="Skip ``argos proxy bench`` (no-op smoke runs).",
    )
    args = parser.parse_args(argv)

    timestamp = _dt.datetime.now(tz=_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.output or DEFAULT_OUTPUT_BASE / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    py = _python_with_argos_installed()

    runs: list[dict[str, object]] = [
        task_status(out_dir, py=py),
        task_rules(out_dir, py=py),
        task_compliance(out_dir, py=py),
        task_scan(out_dir, py=py),
    ]
    if not args.skip_bench:
        runs.append(task_proxy_bench_no_detectors(out_dir, py=py))
        runs.append(task_proxy_bench(out_dir, py=py))
    if not args.skip_eval:
        runs.append(task_eval(out_dir, py=py))

    report = render_report(out_dir, runs)
    report_path = out_dir / "REPORT.md"
    report_path.write_text(report, encoding="utf-8")

    print(f"\n[self-audit] complete -> {report_path}")
    print()
    print(indent(report, "  "))
    # Return non-zero if any step failed; integrators can wire this
    # to a CI gate. ``passed`` accounts for tools that intentionally
    # exit non-zero (e.g. ``argos scan`` returns 1 on findings).
    return 0 if all(r.get("passed") for r in runs) else 1


if __name__ == "__main__":
    sys.exit(main())
