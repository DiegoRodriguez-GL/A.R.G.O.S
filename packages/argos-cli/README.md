# argos-cli

Command-line interface for ARGOS.

Installed as `argos` on the user's `PATH`. Module 0 ships only top-level
plumbing (`--help`, `--version`) and skeletons for `scan`, `redteam`, `proxy`
and `report`. Each sub-command grows in its corresponding module (M2, M4, M5,
M6 respectively).

## Quickstart

```bash
uv pip install argos-cli
argos --help
argos --version
```

## Environment

| Variable              | Effect                                                  |
| --------------------- | ------------------------------------------------------- |
| `NO_COLOR`            | Disable ANSI colour output (respected globally)         |
| `ARGOS_NO_COLOR`      | Same as `NO_COLOR`, ARGOS-specific                      |
| `ARGOS_OTEL_ENDPOINT` | OpenTelemetry OTLP endpoint for traces                  |

## License

AGPL-3.0-or-later.
