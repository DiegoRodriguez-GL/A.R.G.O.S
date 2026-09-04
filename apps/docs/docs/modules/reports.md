# Reports (`argos-reporter`)

`argos report` renders a `ScanResult` (JSON) or a JSONL findings stream into a
single HTML document. There are no external assets: fonts, styles and scripts
are inlined, so the file can be archived, emailed or printed to PDF offline.

## Structure

1. Cover with target, producer, run id and timestamps.
2. Executive summary: totals by severity and by ASI category.
3. Cross-framework compliance matrix (OWASP ASI rows against NIST AI RMF,
   EU AI Act, CSA AICM and ISO/IEC 42001 columns; a cell is lit when a finding
   cited a control in that framework).
4. Findings index.
5. One card per finding: severity badge, rule id, description, compliance
   chips, evidence blocks, remediation.
6. Methodology appendix.

A `@media print` stylesheet keeps page breaks sensible for formal audits.

## Security of the artefact

- `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`
  plus `X-Content-Type-Options: nosniff` and `referrer: no-referrer`: a
  compromised report cannot start outbound requests when opened.
- Jinja2 autoescape with `StrictUndefined`.
- **Redaction on by default.** Titles, descriptions, remediations and every
  evidence field pass through `argos_core.redaction`, which masks OpenAI,
  Anthropic, GitHub, Google, AWS, Slack and Stripe keys, JWTs, bearer values,
  PEM private keys and email addresses as `[REDACTED:<label>]`.

```bash
argos report findings.jsonl -o report.html            # redacted
argos report findings.jsonl -o report.html --no-redact  # asks for confirmation
argos report findings.jsonl -o report.html --no-redact --yes
argos report --demo                                     # sample report
```

## Evaluation reports

`argos eval --output eval.html` uses a second template family with the
confusion matrix, per-category and per-agent breakdowns and the methodology
notes of the evaluation lab.

## Programmatic use

```python
from argos_reporter import render_html, redact_result

html = render_html(scan_result)                 # redacted
html = render_html(scan_result, redact_evidence=False)
safe = redact_result(scan_result)               # a redacted copy of the model
```

Renders are deterministic: the same `ScanResult` always produces the same
bytes, which makes reports diffable.
