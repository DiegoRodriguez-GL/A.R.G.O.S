# OWASP ASI taxonomy cross-reference

ARGOS probes use the prefix `ASI01` through `ASI10`. This prefix is ambiguous
because OWASP has published two related but different Agentic Security
taxonomies, and the prefix is reused:

| Document | Published | Numbering style | Relation to ARGOS |
|----------|-----------|-----------------|-------------------|
| *Agentic AI: Threats and Mitigations v1.0* | Feb 2025 | `T1`..`T15` | **Canonical source for ARGOS probe IDs**. Our `ASI##` is a 1:1 re-labelling of the first ten threats. |
| *OWASP Top 10 for Agentic Applications 2026* | Dec 2025 | `ASI01`..`ASI10` | Reuses the prefix with a **different** ordering and different titles. ARGOS does not mirror this numbering. |

This file records the cross-reference so that an auditor who reads the
report against either document can follow the mapping.

## Our catalogue (Feb 2025 T1..T10 <-> ARGOS ASI##)

| ARGOS code | Feb 2025 T# | Title |
|------------|-------------|-------|
| ASI01 | T1 | Memory Poisoning |
| ASI02 | T2 | Tool Misuse |
| ASI03 | T3 | Privilege Compromise |
| ASI04 | T4 | Resource Overload |
| ASI05 | T5 | Cascading Hallucination Attacks |
| ASI06 | T6 | Intent Breaking and Goal Manipulation |
| ASI07 | T7 | Misaligned and Deceptive Behaviours |
| ASI08 | T8 | Repudiation and Untraceability |
| ASI09 | T9 | Identity Spoofing and Impersonation |
| ASI10 | T10 | Overwhelming Human-in-the-Loop |

The Feb 2025 paper also enumerates T11..T15 (unexpected RCE, agent
communication poisoning, rogue agents, etc.); the current ARGOS
catalogue focuses on the top ten.

## Dec 2025 OWASP Top 10 for Agentic Applications 2026

| Code | Title (Dec 2025) |
|------|-------------------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

## Reader's guide

- A report that quotes `ASI01-MEM-*` **does** mean Memory Poisoning (Feb
  2025 T1), **not** Agent Goal Hijack (Dec 2025 ASI01). Our probe IDs
  predate the Dec 2025 document.
- The `asi_category` attribute on every probe references the Feb 2025
  category.
- The constant `argos_redteam.probes._base.OWASP_ASI_TAXONOMY_SOURCE`
  documents this choice at runtime.

## Rationale

The Feb 2025 paper is more granular (15 threats, subcategories per
threat, per-threat example scenarios and mitigations). The Dec 2025 Top
10 is a curated list aimed at a broader audience and drops several
threats that ARGOS probes explicitly (e.g. Resource Overload,
Overwhelming Human-in-the-Loop). Using the Feb 2025 taxonomy keeps the
probe catalogue in a taxonomy that already enumerates exactly what
we test.
