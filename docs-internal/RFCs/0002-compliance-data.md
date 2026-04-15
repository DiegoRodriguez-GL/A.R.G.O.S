# RFC 0002: Compliance data model and cross-framework mapping

- **Status:** accepted
- **Author(s):** argos-maintainer
- **Created:** 2026-04-15
- **Target module:** M1 (Methodology and compliance mapping)
- **Depends on:** RFC 0001 (monorepo layout)

## Summary

ARGOS represents five compliance frameworks as structured YAML bundled with
`argos-core`, anchored on OWASP ASI as the graph hub. A separate `mapping.yaml`
holds the N:M cross-framework relationships. A set of Pydantic models enforces
the schema at load time, and integrity tests enforce semantic invariants at
CI time.

## Motivation

The TFM's first objective (OE1) is to produce a machine-readable
compliance matrix covering OWASP ASI, CSA AICM, EU AI Act, NIST AI RMF and
ISO/IEC 42001. A PDF cannot serve as the backend of an audit tool -- queries
such as "which EU AI Act article applies to a memory-poisoning finding?" must
resolve in microseconds, must survive schema changes, and must be testable.

## Guide-level explanation

### File layout

```
packages/argos-core/src/argos_core/compliance/
├── __init__.py
├── loader.py          # load_controls() -> ControlIndex
├── models.py          # Control, FrameworkMeta, Mapping...
└── data/
    ├── owasp_asi.yaml        # hub framework, 10 + refinements
    ├── csa_aicm.yaml         # ~20 AI-specific controls, subset of ~243
    ├── eu_ai_act.yaml        # Articles 9-15 + Annex III/IV items
    ├── nist_ai_rmf.yaml      # GOVERN/MAP/MEASURE/MANAGE categories
    ├── iso_42001.yaml        # Annex A (~38 controls)
    └── mapping.yaml          # N:M relationships with rationale
```

### Minimal framework file

```yaml
meta:
  id: owasp_asi
  name: "OWASP Agentic Security Initiative"
  version: "1.0"
  updated: 2026-04-15
  source_url: "https://genai.owasp.org/..."
  description: "..."

controls:
  - id: ASI01
    framework: owasp_asi
    title: "Memory Poisoning"
    text: "Faithful ARGOS summary..."
    tags: ["memory", "persistence"]

  - id: ASI01-01
    framework: owasp_asi
    title: "Single-shot prompt injection via tool output"
    text: "..."
    parent_id: ASI01
```

### Minimal mapping entry

```yaml
- source: "owasp_asi:ASI01"
  targets:
    - "csa_aicm:AIS-04"
    - "nist_ai_rmf:MS-2.6"
    - "eu_ai_act:ART-10"
    - "iso_42001:A.7.2"
  relationship: mitigates
  rationale: "..."
  confidence: high
```

### Consumer API

```python
from argos_core.compliance import load_controls

idx = load_controls()
c = idx.by_qid("owasp_asi:ASI01")
for m in idx.mappings_for("owasp_asi:ASI01"):
    print(m.targets, m.rationale)
```

## Reference-level explanation

### Pydantic models

- `Control`: single normative item. Frozen, `extra=forbid`.
- `FrameworkMeta`: provenance of a framework file.
- `FrameworkData`: top-level schema of every `<framework>.yaml`.
- `MappingEntry`: one `source` -> many `targets` with typed `relationship` and
  `confidence`.
- `Mapping`: envelope of `mapping.yaml`.
- `ControlIndex`: aggregate produced by `load_controls()`.

### Qualified identifiers

Controls expose `qid: str` as `f"{framework}:{id}"`. Mapping entries must
reference qualified ids; the loader rejects malformed strings at validation.

### CBRA weights

Per-level weights are published in `argos_core.autonomy._LEVEL_W`. They are
empirical and will be recalibrated after Module 7 validation runs. Any change
ships with an ADR appended to this RFC.

### Licensing

Compliance data reproduced verbatim from copyrighted standards (ISO 42001,
CSA AICM source text) is avoided. The YAMLs store ARGOS original summaries
with `source_url` back-references for the normative text. See each file's
`meta.license` field.

## Rationale and alternatives

### Why YAML?

- Human-readable and diffable.
- Supported by every stakeholder's tooling (GRC analysts, developers).
- Schema is enforced at load via Pydantic, so the *data* is as safe as a
  protobuf while remaining reviewable as text.

Alternatives considered:

- JSON Schema only (rejected: ARGOS ships Python, native Pydantic is simpler).
- SQLite (rejected for M1: overkill for ~300 controls; revisit post-M7).
- Protobuf (rejected: binary + codegen add friction for the GRC audience).

### Why OWASP ASI as the hub?

- It is the framework specifically designed for agentic AI threats.
- Its ten categories discretise the problem space without over-subdividing.
- Other frameworks are legal / management-system focused and map naturally
  onto ASI categories rather than the reverse.

### Why only a subset of CSA AICM?

The full AICM has ~243 cross-mapped controls. Populating all of them in M1
would take longer than the entire module budget. The shipped subset covers
every AI-specific domain in AICM (AIS, DSP, IAM, LOG, GOV, IRP) and is
enough to close OE1 invariants (>= 3 per ASI threat, >= 4 frameworks per
threat). Remaining controls are a maintenance activity, not an architectural
decision.

## Prior art

- MITRE ATT&CK uses a similar "tactic x technique x sub-technique" hierarchy.
- The NIST CSF-to-SP-800-53 mapping publishes cross-framework linkages in a
  similar format.
- OWASP ZAP's *rule index* is a comparable flat-YAML approach for rule
  metadata.

## Unresolved questions

- Confidence scoring of cross-framework mappings: we ship `high/medium/low`
  strings today. Should this become a numeric score so reports can filter?
- Per-control severity weights: currently severity is finding-level. For
  some reports the control's own inherent risk may warrant weighting.

## Threat-model delta

`docs-internal/THREAT_MODEL.md` T4 (compliance-data tampering) is already
anticipated: the mapping checks at load time, and the integrity tests fail
CI if mapping references drift from the data. No new threat is introduced.

## Future possibilities

- A `argos compliance diff <framework> <version-a> <version-b>` command that
  surfaces regulatory changes between framework versions.
- Shipping the mapping as a signed artefact so downstream consumers can
  verify it hasn't been tampered with.
- An `argos compliance graph` CLI that renders the mapping as a PNG or SVG
  for external audits.
