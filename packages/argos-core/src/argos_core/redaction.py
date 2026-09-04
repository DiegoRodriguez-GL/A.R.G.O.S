"""Best-effort masking of credentials and personal data in free text.

Two producers need the same behaviour:

- The red-team runner (M4) sees unfiltered assistant replies. If the
  agent leaks a secret, the finding evidence must not propagate it
  verbatim to JSON reports, HTML dashboards or log shippers.
- The HTML reporter (M6) renders evidence captured by any producer.
  THREAT_MODEL.md T6 requires that emails, bearer tokens and cloud
  access keys are masked before the document is written to disk, with
  opt-out only through an explicit flag plus a confirmation.

Both call :func:`redact`. The credential patterns are deliberately
conservative: a false positive on redaction costs a little context,
a false negative leaks a real key. Masking every alphanumeric run
would destroy the evidence, so only high-confidence shapes are
matched. Organisation-specific token formats can be supplied through
``extras`` without editing this module.

Patterns intentionally avoid a trailing ``\\b``: in Python's Unicode
mode ``\\b`` depends on the category of the next character, and
replacement characters (U+FFFD) or symbols make it fail unexpectedly,
leaving secrets un-redacted. The character class of each token body is
specific enough that the greedy quantifier stops at the first
non-matching character.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

Pattern = tuple[str, re.Pattern[str]]

#: Credential shapes. The label is embedded in the replacement so a
#: reader sees what was removed and why.
CREDENTIAL_PATTERNS: Final[tuple[Pattern, ...]] = (
    # Anthropic keys share the ``sk-`` prefix with OpenAI's, so they are
    # matched first to keep the label accurate.
    ("ANTHROPIC_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}")),
    # OpenAI project / user keys. Length floor chosen to avoid flagging
    # the bare "sk-xxxx" placeholder used in one probe seed.
    ("OPENAI_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    # GitHub fine-grained and classic tokens.
    ("GITHUB_TOKEN", re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}")),
    # Google / GCP API keys.
    ("GOOGLE_API_KEY", re.compile(r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z_\-]{30,}")),
    # AWS access key id.
    ("AWS_ACCESS_KEY", re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}")),
    # Slack bot / user / app tokens.
    ("SLACK_TOKEN", re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9\-]{10,}")),
    # Stripe live/test keys.
    (
        "STRIPE_KEY",
        re.compile(r"(?<![A-Za-z0-9])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"),
    ),
    # Generic high-entropy JWT.
    (
        "JWT",
        re.compile(
            r"(?<![A-Za-z0-9_\-])"
            r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        ),
    ),
    # Bearer header value (common in captured prompt injections).
    ("BEARER", re.compile(r"(?i)(?<![A-Za-z])bearer\s+[A-Za-z0-9_\-\.=]{20,}")),
    # PEM private key blocks. The whole block is replaced.
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        ),
    ),
)

#: Personal-data shapes. Kept separate from credentials because the
#: red-team detectors legitimately match emails in agent replies; only
#: the reporter (which writes to disk) masks them by default.
PII_PATTERNS: Final[tuple[Pattern, ...]] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
)


def redact(
    text: str,
    *,
    extras: Iterable[Pattern] = (),
    include_pii: bool = False,
) -> str:
    """Return ``text`` with matches masked as ``[REDACTED:<label>]``.

    ``extras`` appends organisation-specific patterns after the
    built-in ones. ``include_pii`` adds :data:`PII_PATTERNS` (emails)
    to the credential set. Empty or non-string input is returned
    unchanged.
    """
    if not text:
        return text
    patterns: tuple[Pattern, ...] = CREDENTIAL_PATTERNS
    if include_pii:
        patterns = (*patterns, *PII_PATTERNS)
    out = text
    for label, pattern in (*patterns, *extras):
        out = pattern.sub(f"[REDACTED:{label}]", out)
    return out


__all__ = ["CREDENTIAL_PATTERNS", "PII_PATTERNS", "Pattern", "redact"]
