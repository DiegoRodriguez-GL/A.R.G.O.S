# Changelog

All notable changes to ARGOS are recorded here. Versioning follows
[Semantic Versioning](https://semver.org/) once `0.1.0` ships. The format is
inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
