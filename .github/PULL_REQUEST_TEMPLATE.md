<!--
Thanks for contributing. Please keep the PR focused. If the change touches
multiple modules, consider splitting it.

Pre-merge checklist (all must be true before "Ready for review"):
-->

## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Scope

- Module(s): <!-- M0..M9 -->
- Related issue(s): closes #
- Architectural decision: <!-- path to RFC if applicable -->

## Changes

- [ ] Implementation
- [ ] Tests (unit / integration / property)
- [ ] Documentation (README, docs, docstrings)
- [ ] Design tokens regenerated (`make tokens`) if `tokens.json` changed

## Verification

```text
make ci
```

<!-- Paste relevant snippets or attach artefacts. -->

## Compliance / security notes

- Does this PR change the threat model? <!-- yes/no; link to THREAT_MODEL.md entry if yes -->
- Does this PR add new untrusted input surface? <!-- yes/no; describe -->

## Pre-merge checklist

- [ ] `make lint` clean
- [ ] `make typecheck` clean
- [ ] `make test` passing
- [ ] Docs updated (if user-visible)
- [ ] No secrets, PII, or customer data in commits
- [ ] No AI-assisted co-authorship trailers
