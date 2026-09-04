# Red teaming (`argos-redteam`)

`argos redteam` sends adversarial probes to an agent endpoint and classifies
the replies. The catalogue covers the ten OWASP ASI categories with two
probes each.

!!! note "Which ASI numbering?"
    Probe ids follow the February 2025 *Agentic AI: Threats and Mitigations*
    numbering (T1-T10 relabelled as ASI01-ASI10). The December 2025 *Top 10
    for Agentic Applications* reuses the prefix in a different order. See
    `docs/asi-taxonomy-crossref.md` in the repository for the table.

## Catalogue

| Category | Probes |
|----------|--------|
| ASI01 Memory Poisoning | single-shot and progressive memory poisoning |
| ASI02 Tool Misuse | tool chaining abuse, parameter manipulation |
| ASI03 Privilege Compromise | over-scoped access, credential replay |
| ASI04 Resource Overload | budget exhaustion, runaway loops |
| ASI05 Cascading Hallucination | fabricated CVEs, invented references |
| ASI06 Intent Breaking | goal hijack via tool description and documents |
| ASI07 Misaligned / Deceptive | hidden actions, false justifications |
| ASI08 Repudiation | missing trace ids, unlogged actions |
| ASI09 Identity Spoofing | peer-agent impersonation |
| ASI10 HITL Overwhelm | rapid-fire approvals, bulk consent |

Select a subset with a glob: `argos redteam -t URL -p 'ASI06-*'`.

## Detectors

| Detector | Signal |
|----------|--------|
| `StringMatchDetector` | Literal needles with `case_insensitive`, `min_payload_length` and `negations` |
| `RegexDetector` | Compiled patterns (CVE ids, IBANs, trace ids) |
| `LLMJudgeDetector` | Optional; sends the reply to a judge model inside an explicit data delimiter |
| `BehaviorDetector` | Looks at the sequence of actions rather than the text |

`negations` and `min_payload_length` exist because polite refusals ("Ok, but
I cannot help") used to trip naive needles; the adversarial audit that fixed
that is documented in `packages/argos-redteam/tests/test_bugs_audit.py`.

## Strategies and transport

- `SingleTurnStrategy` (one prompt, one reply) and `MultiTurnStrategy`
  (progressive attacks).
- `HttpTransport` speaks the `{"messages": [...]}` shape common to OpenAI,
  Anthropic and minimal wrappers, retries transient failures with backoff,
  identifies itself with a `User-Agent`, and enforces `--max-requests` as a
  denial-of-wallet cap.
- Probes run concurrently (`asyncio.gather` behind a semaphore) with
  per-probe error isolation: one crashing probe never aborts the run.

## Output

```bash
argos redteam -t http://localhost:11434/api/chat
argos redteam -t URL -f jsonl -o redteam.jsonl
```

Each successful probe becomes a `Finding` with the transcript as
request/response evidence (credentials redacted) and compliance references
for its ASI category. Feed the JSONL into `argos report`.
