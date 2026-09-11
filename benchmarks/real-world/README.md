# Real-world validation

The evaluation lab (`argos eval`) measures detection on agents the project
wrote itself. This benchmark measures ARGOS against what it does not
control: the MCP ecosystem as published. Three campaigns, first run on
11 September 2026:

| Campaign | Target | Size | Instrument |
|----------|--------|------|------------|
| A | Every server in the official [MCP Registry](https://registry.modelcontextprotocol.io) (latest version of each) | 30,871 entries | `argos scan` on each `server.json` |
| B | Official reference servers from npm and PyPI, pinned, run locally | 7 servers, 52 tools | `argos proxy wrap` vs. direct, 100 requests per mode |
| C | Public remote servers over streamable HTTP and TLS | 9 servers (7 anonymous, 2 OAuth) | `argos proxy wrap --upstream https://...` vs. direct, 10 requests per mode |

The methodology and the results are discussed in
[`docs/real-world-validation.md`](../../docs/real-world-validation.md).

## Reproduce

```bash
uv sync --all-extras

# Campaign A: snapshot, scan, precision against the manual labels
uv run python benchmarks/real-world/registry_snapshot.py benchmarks/real-world/results
uv run python benchmarks/real-world/registry_scan.py benchmarks/real-world/results after
# to measure a rule change, scan once per version of the rules (tags "before"/"after")
uv run python benchmarks/real-world/registry_precision.py benchmarks/real-world/results before after benchmarks/real-world/labels.json

# Campaigns B and C (needs Node.js for npx and uv for uvx)
uv run python benchmarks/real-world/live_campaign.py
uv run python benchmarks/real-world/live_campaign.py deepwiki filesystem   # a subset
```

The registry changes every day, so a fresh snapshot will not match the
numbers below exactly. `labels.json` records the manual review of the
original sample; entries are keyed by the first 16 hex digits of the
SHA-256 of the server name so that no publisher is named here.

## Files

| File | Content |
|------|---------|
| `registry_snapshot.py` | Downloads the latest version of every registry entry through the public API |
| `registry_scan.py` | Scans each entry with `argos_scanner.engine.scan`; writes findings and per-entry rows |
| `registry_precision.py` | Per-rule precision (Wilson 95 %) on the labelled sample, before and after a rule change |
| `labels.json` | Manual review of 182 sampled findings (up to 25 per rule) and the labelling criterion |
| `live_campaign.py` | Campaigns B and C, including the scope-enforcement check on the filesystem server |
| `results/` | Aggregated results of the first run (no server names, no local paths) |

## Headline results

- **Interoperability.** The first contact failed with the first stdio server
  and the first remote server tried. It exposed seven interoperability
  defects and one deployment gap that the lab could not show, because its
  fixtures shared the code's assumptions. All are fixed with regression
  tests (`packages/argos-proxy/tests/test_real_world_interop.py`,
  `packages/argos-cli/tests/test_proxy_wrap.py`). Afterwards all 28 sessions
  of campaigns B and C succeeded, and the official MCP Inspector client worked
  through `argos proxy wrap`.
- **Scanner precision on real data.** The manually validated precision of the
  original rules on the registry sample was 57.1 % (104/182, Wilson
  [49.9 %, 64.1 %]). Fixing seven false-positive causes and two translator
  defects raised it to 99.0 % (104/105, [94.8 %, 99.8 %]) with every true
  positive kept and no new finding. Entries with a high or critical finding
  went from 814 to 235.
- **Ecosystem.** All 19,097 remote URLs use HTTPS. 223 entries declare an
  exact version but launch the package unpinned (`uvx --from pkg`,
  `npx --package pkg`). Only 5 of 903 OCI packages are pinned by digest.
  No environment value carries a secret in a known format; the two literal
  bearer tokens found in headers are public by design.
- **Cost.** Through `wrap`, the reference servers answer 0.03 to 0.84 ms
  slower at the median. Against remote servers the difference is within
  network noise.

## Ethics

Public data only, retrieved through the documented API with pauses between
pages. Remote servers were used as any anonymous client would use them
(initialise, list tools, one documentation search with harmless arguments),
with a few dozen requests per server over the whole run. No red-teaming
probe was sent to third-party services, no session identifier was altered
and no credential was tried. Personal data used to exercise the PII
detector is synthetic.
