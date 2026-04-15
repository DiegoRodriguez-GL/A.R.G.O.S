# Contributing to ARGOS

Thank you for considering a contribution. This document explains how we work
and what we expect from a merge-ready change.

## Ground rules

1. **Scope matters.** ARGOS is intentionally narrow -- see
   [`docs-internal/PLAN.md`](docs-internal/PLAN.md) §2. Features outside the
   declared scope land as `[EXTENSIÓN]` and are deferred.
2. **Security first.** ARGOS is a security tool. Never introduce code that
   weakens the project's own threat model (see
   [`docs-internal/THREAT_MODEL.md`](docs-internal/THREAT_MODEL.md)).
3. **Reproducibility.** Every finding must be backed by on-disk evidence a
   third party can reproduce.
4. **No regressions in CI.** `make ci` must pass locally before requesting
   review.

## Getting set up

```bash
git clone https://github.com/argos-ai-audit/argos
cd argos
make bootstrap
```

This installs development dependencies via `uv`, including `pre-commit` hooks
(`ruff`, `mypy`, schema linters). Hooks run on every commit.

## Workflow

1. **Open an issue first** for anything non-trivial. Use the `Feature request`
   or `Bug report` templates. A short design note in the issue saves weeks.
2. **Branch names**: `<type>/<short-topic>`, where type is one of `feat`,
   `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `security`, `rfc`.
3. **Architectural changes** require an RFC under `docs-internal/RFCs/`. Copy
   the template from [`docs-internal/RFCs/template.md`](docs-internal/RFCs/template.md).
4. **Open a PR** against `main`. Fill out the template. Keep the PR focused.

## Commit messages

Conventional Commits. The subject line is imperative and under 72 chars.

```
feat(scanner): add tool-poisoning rule for MCP descriptions

Detects embedded imperative phrasing ("ignore previous", "forget all") in
tool.description fields. Emits ASI01-02 with the line range as evidence.

Refs: #42
```

Do **not** add AI-assisted co-authorship trailers (`Co-Authored-By: <AI>`,
"Generated with <tool>", etc.) to commits or PR descriptions. Contributions
are attributed to human authors; tools used in the process are part of the
workflow, not the authorship.

## Code style

- Python 3.11+, `src/` layout, strict typing. `mypy --strict` is enforced.
- `ruff` is the single source of truth for formatting and linting. Do not
  introduce `black`, `isort`, or `flake8` configuration.
- Public APIs are documented with Google-style docstrings.
- Prefer standard-library solutions; new runtime dependencies require an RFC.

## Tests

- Unit tests live next to their package under `packages/<name>/tests/`.
- Use `pytest`. Fixtures go in `conftest.py` at the nearest sensible scope.
- Aim for ≥ 70% coverage (RNF-07). A regression in coverage blocks merge.
- Never commit cassettes, logs, or fixtures containing real credentials or
  PII, even redacted.

## Reporting security issues

Use GitHub's [private advisory flow](https://github.com/argos-ai-audit/argos/security/advisories/new).
Do not open public issues for vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the full policy.

## Licensing

By contributing, you agree that your contribution will be licensed under
[AGPL-3.0-or-later](LICENSE). Do not submit code you are not authorised to
license this way.
