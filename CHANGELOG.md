# Changelog

All notable changes to ARGOS are recorded here. Versioning follows
[Semantic Versioning](https://semver.org/) once `0.1.0` ships. The format is
inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed -- hardening pass

- Pinned every GitHub Action by commit SHA (supply-chain defence; OpenSSF
  Scorecard recommendation).
- Added `step-security/harden-runner` with `egress-policy: audit` to every
  CI job for detection of unexpected outbound network traffic.
- Added `gitleaks` to the pre-commit hook set (secret scanning before
  commit hits the index).
- Added a strict `Content-Security-Policy` meta tag and `X-Content-Type-
  Options: nosniff` to the HTML reporter base template; reports now render
  with `default-src 'none'` and no referrer leakage.
- Extended `ruff` lint selection from 22 to 35 rule categories, including
  `FURB`, `LOG`, `EM`, `PERF`, `SLF`, `TRY`, `ARG`, `TID`, `PYI`, `FLY`.
- Added a `bandit` configuration block to `pyproject.toml` so the tool
  runs with identical exclusions to the `ruff S` rule set.
- Added `.well-known/security.txt` (RFC 9116) for future serving from the
  docs site.
- Consolidated the four CLI skeleton commands onto a single
  `not_implemented()` helper (`commands/_placeholder.py`); per-command
  files now contain only their Typer signature.

### Added -- Module 1 (Methodology and compliance mapping)

- Enriched Pydantic models for compliance data: `Control`, `FrameworkMeta`,
  `FrameworkData`, `Mapping`, `MappingEntry`, `MappingMeta`.
- Five bundled framework YAMLs under
  `packages/argos-core/src/argos_core/compliance/data/`:
  `owasp_asi.yaml` (hub, 10 threats + operational refinements), `csa_aicm.yaml`
  (AI-specific subset), `eu_ai_act.yaml` (Articles 9-15 + Annex III/IV),
  `nist_ai_rmf.yaml` (GOVERN/MAP/MEASURE/MANAGE), `iso_42001.yaml`
  (Annex A controls).
- `mapping.yaml` with N:M cross-framework relationships anchored on OWASP ASI.
- Integrity tests guaranteeing the OE1 invariant (>= 3 cross-framework
  controls per ASI threat, >= 4 frameworks touched) and resolving every
  qualified id against real controls.
- Methodology documentation at `apps/docs/docs/methodology/index.md` with
  Mermaid diagrams.
- RFC 0002 documenting the compliance data model and design rationale.

### Added -- Module 0 (Foundation)

- Monorepo scaffolding: `packages/argos-core`, `argos-cli`, `argos-scanner`,
  `argos-redteam`, `argos-proxy`, `argos-reporter`, `argos-rules`.
- Design system v0: `design-system/tokens.json` + generated
  `tokens.css`/`tokens.py`/`tokens.ts` via `scripts/build_tokens.py`.
- Jinja2 base layout (`packages/argos-reporter/.../templates/base.html.j2`).
- `argos-core` Pydantic models (`Finding`, `Severity`, `ScanResult`, `Target`,
  `Evidence`) and ABC interfaces (`IPlugin`, `IScanner`, `IProbe`,
  `IDetector`, `IReporter`).
- Autonomy taxonomy (CSA L0-L5) and CBRA scoring helper.
- Typer CLI skeleton exposing `argos --help`, `argos --version`, and
  sub-command stubs for `scan`, `redteam`, `proxy`, `report`.
- Quality tooling: ruff, mypy (strict), pytest with coverage gate,
  pre-commit, Makefile targets.
- GitHub Actions workflows for CI, release (PyPI Trusted Publishers) and
  documentation/landing deployment to GitHub Pages.
- Issue/PR templates, Code of Conduct, Security policy, Dependabot config,
  CODEOWNERS.
- Threat model (`docs-internal/THREAT_MODEL.md`), architecture brief
  (`docs-internal/ARCHITECTURE.md`), RFC template and RFC 0001 on the
  monorepo layout.
