"""Best-effort redaction of obvious credentials in agent output.

The red-team runner sees unfiltered assistant replies; if the assistant
leaks a secret the finding evidence must **not** propagate that secret
verbatim to downstream consumers (JSON reports, HTML dashboards, log
shippers). This module gives a single entry point, :func:`redact`, that
masks the most common high-confidence credential shapes.

The list is intentionally conservative: false positives on redaction
are preferable to false negatives that leak real keys, but masking
every alphanumeric run would destroy useful context. If a site has
organisation-specific token formats, extend :data:`_PATTERNS` via a
subclass or monkeypatch at import time.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Each entry is (label, compiled regex). The label is embedded in the
# replacement so downstream readers see what was removed and why.
#
# Patterns intentionally avoid a trailing ``\b``: in Python's Unicode mode
# ``\b`` depends on the Unicode category of the next char, and replacement
# characters (U+FFFD) or symbols cause ``\b`` to unexpectedly fail,
# leaving secrets un-redacted. The character class that defines the token
# body is already specific enough: the greedy quantifier stops at the
# first non-matching char, so no extra boundary is required.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Anthropic / OpenAI project / user keys. Length floor chosen to
    # avoid flagging the bare "sk-xxxx" placeholder used in one probe
    # seed.
    ("OPENAI_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("ANTHROPIC_KEY", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}")),
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
)


def redact(text: str, *, extras: Iterable[tuple[str, re.Pattern[str]]] = ()) -> str:
    """Return ``text`` with credentials masked as ``[REDACTED:<label>]``.

    ``extras`` allows callers to add org-specific patterns without
    editing this module; they are applied after the built-in ones.
    Empty / non-string input is returned unchanged.
    """
    if not text:
        return text
    out = text
    for label, pattern in (*_PATTERNS, *extras):
        out = pattern.sub(f"[REDACTED:{label}]", out)
    return out
