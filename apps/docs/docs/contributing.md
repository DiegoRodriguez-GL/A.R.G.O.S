# Contributing

The canonical guide is `CONTRIBUTING.md` in the repository root. The short
version:

1. **Open an issue first** for anything non-trivial; architectural changes
   need an RFC under `docs-internal/RFCs/`.
2. **Branch names** are `<type>/<short-topic>` (`feat`, `fix`, `docs`,
   `chore`, `refactor`, `test`, `perf`, `security`, `rfc`).
3. **Commits** follow Conventional Commits. Contributions are attributed to
   their human authors only.
4. **Quality gates** run locally with `make ci`: `ruff` (lint + format),
   `mypy --strict`, `pytest` with a 70 % coverage floor. CI adds a
   multi-OS / multi-Python matrix, CodeQL, OpenSSF Scorecard and the
   self-audit job.
5. **Data changes** under `argos_core/compliance/data/` must be followed by
   `python scripts/build_compliance_manifest.py`; design-token changes by
   `make tokens`.
6. **Never commit** fixtures with real credentials or personal data, even
   redacted.

## Development setup

```bash
git clone https://github.com/DiegoRodriguez-GL/A.R.G.O.S
cd A.R.G.O.S
make bootstrap
make ci
```

## Writing a plugin

Implement one of the `argos_core.interfaces` ABCs and declare an entry point:

```toml
[project.entry-points."argos.scanner_rules"]
my-rule = "my_package.rules:MyRule"
```

`argos status` lists the plugin with its distribution and version once it is
installed in the same environment.
