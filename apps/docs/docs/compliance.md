# Compliance reference

ARGOS ships a machine-readable compliance graph with OWASP ASI as the hub and
four other frameworks as satellites. Every finding, whatever produced it,
carries `compliance_refs` in the form `framework:control_id`.

## Frameworks

| Id | Framework | Controls | Notes |
|----|-----------|----------|-------|
| `owasp_asi` | OWASP Agentic Security Initiative | 24 | 10 top-level threats plus operational refinements (`ASI03-01`, ...) |
| `csa_aicm` | CSA AI Controls Matrix v1.0 | 21 | AI-specific subset of the 243 controls |
| `eu_ai_act` | Regulation (EU) 2024/1689 | 16 | Articles 9-15, Annex III, Annex IV |
| `nist_ai_rmf` | NIST AI RMF 1.0 | 25 | GOVERN / MAP / MEASURE / MANAGE |
| `iso_42001` | ISO/IEC 42001:2023 | 39 | Annex A, sections A.2-A.10 (original summaries, no verbatim text) |

125 controls in total and 10 N:M mapping entries, one per ASI threat, each
with a rationale and a confidence level.

## Invariants verified in CI

1. Every ASI threat maps to at least three controls in other frameworks.
2. Every mapping entry touches at least four non-hub frameworks.
3. Every qualified reference resolves to a real control.
4. Every `parent_id` resolves within its framework.
5. Control ids are unique within a framework.
6. The hub is declared as `owasp_asi`.
7. Every ASI top-level threat appears as a mapping source.

## Integrity manifest

`MANIFEST.sha256` ships next to the data files in `sha256sum` format. It is
verified on every load (a `ComplianceIntegrityWarning` is raised on drift)
and on demand:

```bash
argos compliance verify        # exit 1 on modified, missing or unlisted files
cd packages/argos-core/src/argos_core/compliance/data && sha256sum --check MANIFEST.sha256
```

After editing any data file, regenerate it with
`python scripts/build_compliance_manifest.py` and commit both.

## Exploring the graph

```bash
argos compliance list
argos compliance show owasp_asi:ASI01
argos compliance show iso_42001:A.6.2.8
argos compliance map owasp_asi:ASI03
```

## Risk attribution

Severity alone is not enough: a Critical finding in an assistive L0 agent is
less urgent than a Medium one in an autonomous L5 agent. The CBRA score
(Capability-Based Risk Attribution) weights severity by the CSA autonomy level
(L0-L5), exposure to untrusted input, plausible blast radius and
reversibility. See [Methodology](methodology/index.md).
