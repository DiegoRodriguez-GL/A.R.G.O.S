# Real-world validation of ARGOS

The evaluation lab ([`empirical-evaluation.md`](empirical-evaluation.md))
gives a perfectly diagonal confusion matrix on six agents the project wrote
itself. That result is reproducible and exact for what it measures, but a
bench designed by the same author shares the assumptions of the code under
test. This document reports what happened when ARGOS met the MCP ecosystem
as published. Scripts, labels and aggregated results are in
[`benchmarks/real-world`](../benchmarks/real-world).

## Questions

1. **Interoperability.** Does ARGOS work, unmodified, with MCP servers and
   clients written by others?
2. **Precision on real data.** What does the scanner report on everything
   published, and how precise is it on findings reviewed one by one?
3. **Operational cost.** How much latency does the proxy add with real
   servers?

## Campaigns

All three ran on 11 September 2026 against the code in this repository.

- **A. Official MCP Registry.** A snapshot of the latest version of every
  server (30,871 entries: 13,375 with installable packages, 18,590 with
  remote endpoints) taken through the public API. Each `server.json` is
  translated into the client entry an installer would write (`npx`, `uvx`,
  `docker run`, `dnx`, or a remote URL with headers) and scanned with the
  17 built-in rules.
- **B. Reference servers.** The seven official reference servers published
  by the MCP maintainers (everything, filesystem, memory,
  sequential-thinking on npm at `2026.8.31`; time, fetch, git on PyPI at
  `2026.8.18`), run locally over stdio, first directly and then through
  `argos proxy wrap`, with 100 timed requests per mode.
- **C. Public remote servers.** Seven anonymous servers (DeepWiki,
  Microsoft Learn, Cloudflare documentation, Hugging Face, GitMCP, AWS
  Knowledge, Astro documentation) and two OAuth-protected ones (Semgrep,
  GitHub Copilot), reached over streamable HTTP and TLS, directly and through
  `argos proxy wrap --upstream`, with 10 timed requests per mode.

## First contact: interoperability defects

Unmodified, ARGOS failed with the first two servers it met: the stdio
reference server hung on `initialize`, and DeepWiki answered `400 Bad
Request`. The investigation found:

| Id | Symptom | Cause |
|----|---------|-------|
| I1 | Any real stdio server hangs | stdio used LSP `Content-Length` framing; MCP stdio is newline-delimited JSON |
| I2 | `npx` does not start on Windows | Launchers are `.cmd` shims that process creation does not resolve |
| I3 | Latent: deadlock with chatty servers | The child's stderr was never drained; a banner on stdout broke the session |
| I4 | `tools/list` unanswered after `notifications/initialized` | Three transports returned the first message of each read and dropped the rest |
| I5 | `400` from every remote server | No TLS, a mandatory GET stream first, the POST response body ignored, no `Mcp-Session-Id` or `MCP-Protocol-Version` |
| I6 | MCP Inspector never receives the tool list | An absent `params` was forwarded as `params: null`, which strict servers drop silently |
| I7 | Printed IBAN missed in a real file | Only compact IBANs were recognised |
| C1 | No real client can use the proxy | Only a TCP/NDJSON listener existed, a transport no MCP client offers |

Every defect is fixed and pinned by a regression test that reproduces the
real behaviour. The common cause is instructive: the fake stdio server spoke
`Content-Length` because the transport did, the fake HTTP server answered on
the GET stream because the client expected it, and latency was measured on
an in-memory transport. Coverage and adversarial passes cannot catch a
misreading of a specification that the tests share; only an independent
counterpart can.

After the fixes, all 28 sessions of campaigns B and C succeeded, and the
official MCP Inspector (protocol revision `2025-11-25`) listed and called
tools through `argos proxy wrap` without any change on the client side.

## Campaign A: the registry

The registry has no ground truth, so a stratified sample was reviewed by
hand: up to 25 findings per rule, one per entry, drawn with a fixed seed
(182 findings). A finding is a true positive when the weakness it names
exists in the command a client would build from the published entry; for
the two advisory rules (digest pinning, credential scope) its literal claim
must hold. Precision is reported with a Wilson 95 % interval.

| Rule | Entries (original) | Precision (original) | Entries (fixed) | Precision (fixed) |
|------|-------------------:|----------------------|----------------:|-------------------|
| Image without digest (advisory) | 884 | 25/25 | 884 | 25/25 |
| Provider credential in env (advisory) | 416 | 25/25 | 416 | 25/25 |
| Literal bearer token | 393 | 1/25 | 2 | 1/1 |
| Unpinned `uvx` | 194 | 24/25 | 185 | 24/24 |
| High-entropy env value | 159 | 0/25 | 5 | 0/1 |
| Unpinned `npx` | 39 | 24/25 | 38 | 24/24 |
| Plaintext HTTP | 14 | 3/14 | 3 | 3/3 |
| Injection phrasing | 12 | 0/12 | 0 | none |
| Host mount | 3 | 0/3 | 0 | none |
| Host network | 2 | 2/2 | 2 | 2/2 |
| `eval` in command | 1 | 0/1 | 0 | none |

Overall sample precision went from **57.1 %** (104/182, [49.9 %, 64.1 %]) to
**99.0 %** (104/105, [94.8 %, 99.8 %]). Every sampled true positive was kept
and no new finding appeared. The causes of the false positives were all
specific to real data: registry `{name}` placeholders read as tokens, base
URLs and user agents with structural entropy, templated local hosts judged
as remote, a tool's own `~/.config/<tool>` read as the whole home
directory, `uvx --with` values read as the main package, partial versions in
`npx --package`, and operator-facing documentation analysed as if a model
read it. Two defects in the registry translator itself (a sentence published
as `runtimeHint`, two schema URL variants) were fixed too.

What the registry shows once the rules are calibrated:

- All 19,097 remote URLs use HTTPS. Plaintext HTTP to public hosts appears
  only in three packages whose transport points at an IP address or a
  tunnel domain.
- 223 entries (185 PyPI, 38 npm) declare an exact version but launch the
  package unpinned (`uvx --from pkg`, `npx --package pkg`): the client runs
  whatever version is current, while the entry looks pinned.
- Only 5 of 903 OCI packages are pinned by digest; 37 use `latest`.
- No environment value carries a secret in a known format. The two literal
  bearer tokens left are public by design (a Supabase anonymous key and a
  read-only demo key its author publishes on purpose). The secret-pattern
  rule does not yet inspect headers, where one of them appeared.
- Two entries run their container with the host network; none mounts the
  root, the whole home or a credential store.

Static analysis of the registry cannot see tool descriptions, the text a
model actually reads. Campaigns B and C inspect them at runtime: none of the
75 descriptions observed matches the injection heuristic.

## Campaigns B and C: live traffic

Median latency per request, directly and through `argos proxy wrap`, over
100 requests (reference servers) or 10 requests (remote servers):

| Server | Direct (ms) | Through ARGOS (ms) |
|--------|------------:|-------------------:|
| everything | 0.24 | 0.54 |
| filesystem | 0.20 | 0.52 |
| memory | 0.31 | 0.57 |
| sequential-thinking | 0.40 | 1.24 |
| time | 1.42 | 1.54 |
| fetch | 0.98 | 1.42 |
| git | 36.07 | 36.10 |

The added cost (0.02 to 0.84 ms at the median) is an order of magnitude
above the 0.054 ms of the in-memory benchmark because every message now
crosses an extra process and two pipes; it remains far below the 50 ms
budget. Against remote servers the difference changes sign from one server
to the next and stays within network noise.

Detectors on real traffic: the drift detector pinned a baseline in every
session and flagged the `tools/list_changed` notification the `everything`
server emits on purpose; the PII detector flagged the synthetic e-mail, DNI
and (after I7) the printed IBAN read through the filesystem server, and
nothing in the other servers' responses; with a read-only allowlist,
`write_file` was answered with `-32601` and the file was not created. All
nine remote servers negotiated TLS 1.3. Their transports differ widely while
conforming: three use no session, two use UUIDs, one a hex string and one a
Base64-encoded JSON object that carries the client name and a user
identifier in clear; only one offers the GET stream, the rest answer `405`.
The two OAuth-protected servers answered `401`, which ARGOS returned as a
JSON-RPC error in both modes.

## Threats to validity

- One reviewer labelled the sample; the criterion and the labels are
  published, but inter-rater agreement was not measured.
- 25 findings per rule give Wilson intervals about 20 points wide for rules
  of intermediate precision.
- The registry changes daily and does not weight entries by usage.
- The registry specification does not fix how clients combine runtime
  arguments with the package identifier; the translator follows the
  documented order (launcher arguments, package, package arguments).
- Remote latency uses 10 requests per mode on the public Internet.
- Campaigns B and C ran on Windows; the regression tests for every defect run
  on Linux, macOS and Windows in CI.

## Ethics

Public data through the documented API, with pauses between pages. Remote
servers were used as any anonymous client would use them, with a few dozen
requests each over the whole run. No red-teaming probe was sent to
third-party services, no session identifier was altered and no credential
was tried. The personal data used to exercise the PII detector is synthetic.
No secret value is reproduced and no publisher with a finding is named.
