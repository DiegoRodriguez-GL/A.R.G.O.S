# RFC 0001: Monorepo layout and packaging

- **Status:** accepted
- **Author(s):** argos-maintainer
- **Created:** 2026-04-15
- **Target module:** M0 (Foundation)
- **Depends on:** none

## Summary

ARGOS is built as a single Git repository with seven Python packages under
`packages/`, two static web apps under `apps/`, and a single design-system
folder at the root. `uv` workspaces provide the build/lock discipline;
`hatchling` is the per-package build backend; each package ships an
independent wheel to PyPI.

## Motivation

The proposal (TFM §5) requires six capabilities (OE1-OE6) that share a common
data model, compliance mapping and CLI but have wildly different dependencies
(async servers, Jinja templates, YAML rules). A single mega-package would
couple release cadences and inflate install footprint for users who only want
the scanner. A collection of separate repositories would fragment the issue
tracker and make cross-module refactors painful.

The monorepo preserves a single source of truth while still publishing focused
wheels to PyPI.

## Guide-level explanation

```
argos/
├── packages/                    # Python packages (one PyPI wheel each)
│   ├── argos-core/              # Shared models, interfaces, compliance loader
│   ├── argos-cli/               # `argos` console entry point
│   ├── argos-scanner/           # Static MCP scanner (Module 2)
│   ├── argos-redteam/           # Red-team probes (Module 4)
│   ├── argos-proxy/             # Audit proxy (Module 5)
│   ├── argos-reporter/          # HTML / JSONL reporting (Module 6)
│   └── argos-rules/             # YAML rules engine (Module 3)
├── apps/
│   ├── landing/                 # Astro site (Module 8)
│   └── docs/                    # MkDocs Material (Module 8)
├── design-system/               # Authoritative tokens.json + DESIGN_SYSTEM.md
├── scripts/                     # Repo-level tools (build_tokens.py, ...)
├── docs-internal/               # PLAN.md, THREAT_MODEL.md, RFCs/
├── benchmarks/                  # Reproducible benchmarks (Module 7)
└── examples/                    # Runnable agents used by M7 validation
```

### Dependencies

- `argos-core` has no intra-repo dependency and sits at the bottom of the
  graph. Every other `argos-*` package depends on it.
- `argos-cli` depends on every other `argos-*` package so `argos --help` can
  load all subcommands.
- `argos-scanner`, `argos-redteam`, `argos-proxy`, `argos-reporter`,
  `argos-rules` depend only on `argos-core` (and their third-party stack).

### Workspaces

The repo-root `pyproject.toml` declares `[tool.uv.workspace] members = ["packages/*"]`
and lists each internal dependency under `[tool.uv.sources]` as
`{ workspace = true }`. Developers run `uv sync --all-extras` once and get a
fully editable install of every package.

## Reference-level explanation

### Build backend

`hatchling>=1.25` for every package. Reasons:

- Pure Python, no compile step needed for M0-M6.
- `[tool.hatch.build.targets.wheel]` already understands `src/` layouts.
- `[tool.hatch.build.targets.wheel.force-include]` lets us bundle non-Python
  assets (Jinja templates, JSON Schema) without inventing a custom step.

### Versioning

All packages share the root version in M0 (`0.0.1`) until we ship something
user-facing. From `0.1.0` onwards each package is versioned independently,
governed by SemVer. `argos-core` acts as the ABI anchor: any breaking change
to its public types requires a major bump and a migration note in that
package's `CHANGELOG.md`.

### Testing

`pytest` is configured at the root; it auto-discovers tests in every
`packages/*/tests/` directory. Coverage is measured against the aggregated
`packages` source tree so internal-only helpers are still tracked.

### Typing

`mypy --strict` is run at the root. The `mypy_path` entry in
`pyproject.toml` enumerates every `packages/*/src` directory so intra-repo
imports resolve without a prior build.

## Rationale and alternatives

- *Single package* rejected: couples release cadences and forces every user
  to install the async proxy even when they only want a static scan.
- *Multi-repo* rejected: cross-cutting refactors (e.g. changing the Finding
  schema) would span 6 PRs.
- *setuptools + editable installs* rejected: `hatch` is simpler and `uv`
  workspaces are the current state-of-the-art in the Python ecosystem.

## Prior art

- `kubernetes/kubernetes` staged repository layout.
- `pola-rs/polars` Python-plus-Rust multi-crate monorepo.
- `prefecthq/prefect` single-package history and the pain that motivated its
  split.

## Unresolved questions

- Whether to expose a `argos` meta-package on PyPI that installs every
  workspace package for users who want "everything at once". Deferred to
  Module 8.

## Threat-model delta

No material change. The monorepo does not weaken the self threat model; it
does concentrate supply-chain risk on a single release pipeline, which is
mitigated by pinned dependencies and PyPI Trusted Publishers (see
`THREAT_MODEL.md` T5).

## Future possibilities

- Extract `argos-rules` to its own repository if external contributors start
  shipping rule packs faster than the core release cadence tolerates.
- Introduce a Rust performance kernel for the proxy if benchmarks breach the
  50 ms ceiling (RNF-02). That would require a new RFC and probably
  `maturin`.
