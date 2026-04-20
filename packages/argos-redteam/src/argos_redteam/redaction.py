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
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Anthropic / OpenAI project / user keys. Length floor chosen to
    # avoid flagging the bare "sk-xxxx" placeholder used in one probe
    # seed.
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    # GitHub fine-grained and classic tokens.
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    # Google / GCP API keys.
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    # AWS access key id.
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # Slack bot / user / app tokens.
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    # Stripe live/test keys.
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b")),
    # Generic high-entropy JWT.
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    # Bearer header value (common in captured prompt injections).
    ("BEARER", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}\b")),
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
