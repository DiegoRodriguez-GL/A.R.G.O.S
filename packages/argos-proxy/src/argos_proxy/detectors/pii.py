"""PII detector.

Scans request and response payloads for patterns matching common PII:

- Email addresses (RFC 5321 conservative subset).
- IBANs (ISO 13616, length 15-34 with country prefix).
- Payment card numbers (13-19 digits passing the Luhn checksum).
- Spanish DNIs (8 digits + control letter).

A match emits a finding without modifying the payload. The proxy is a
*detection* tool, not a redactor; redaction would change the wire
contract and is left to the upstream's responsibility.

Patterns are deliberately conservative: false positives are noisier
than false negatives in an audit context. The Luhn check on card
numbers cuts most random-digit collisions; the IBAN check validates
the modulo-97 checksum to avoid flagging arbitrary alphanumeric
strings.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from argos_proxy.detectors._base import FindingSink, ProxyDetector
from argos_proxy.interceptor import InterceptContext
from argos_proxy.jsonrpc import Notification, Request, Response

# RFC 5321: a deliberately-conservative subset. We avoid the full
# regex (which is famously enormous) because the proxy needs to be
# fast; the cost of missing a malformed-but-real address is small.
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
)

# IBAN: 2 letters + 2 digits + 11..30 alphanumerics. Validated by
# ``_iban_is_valid`` after the regex captures.
_IBAN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
)

# Spanish DNI: 8 digits and a control letter. The letter is checked
# against the modulo-23 table.
_DNI_RE: Final[re.Pattern[str]] = re.compile(r"\b([0-9]{8})([A-Za-z])\b")
# Spanish NIE: prefix letter (X/Y/Z) + 7 digits + control letter. The
# prefix is substituted by a digit (X=0, Y=1, Z=2) and the resulting
# 8-digit value is run through the same modulo-23 check as DNI.
_NIE_RE: Final[re.Pattern[str]] = re.compile(r"\b([XYZxyz])([0-9]{7})([A-Za-z])\b")
_NIE_PREFIX_VALUE: Final[dict[str, str]] = {"X": "0", "Y": "1", "Z": "2"}
_DNI_LETTERS: Final[str] = "TRWAGMYFPDXBNJZSQVHLCKE"

# Payment card: 13-19 digits possibly grouped by hyphens or spaces.
# The intermediate stripping is done in ``_iter_card_candidates``.
_CARD_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:[0-9][ \-]?){12,18}[0-9]\b",
)


@dataclass(frozen=True)
class _Match:
    kind: str
    snippet: str  # truncated, redacted preview for logs


class PIIDetector(ProxyDetector):
    """Scan payloads for PII; emit one finding per kind seen per message.

    The detector does NOT alter the payload; the wire contract is
    preserved verbatim. Findings carry the matched ``kind`` and a
    REDACTED snippet (first/last char + length) so the audit log
    never persists the actual PII value.
    """

    detector_id = "argos.proxy.pii"

    def __init__(
        self,
        sink: FindingSink | None = None,
        *,
        kinds: Iterable[str] = ("email", "iban", "card", "dni"),
        max_payload_bytes: int = 256 * 1024,
    ) -> None:
        super().__init__(sink)
        # Validate kind names early so a typo surfaces at construction
        # not at first request.
        valid = {"email", "iban", "card", "dni"}
        unknown = set(kinds) - valid
        if unknown:
            msg = f"unknown PII kinds: {sorted(unknown)}; valid={sorted(valid)}"
            raise ValueError(msg)
        self._kinds = frozenset(kinds)
        self._max_payload_bytes = max_payload_bytes

    async def on_request_in(
        self,
        request: Request,
        ctx: InterceptContext,
    ) -> Request | None:
        await self._scan(
            payload=request.params,
            ctx=ctx,
            method=request.method,
            direction="client_to_upstream",
        )
        return None

    async def on_response_out(
        self,
        response: Response,
        ctx: InterceptContext,
    ) -> Response | None:
        if response.is_error:
            await self._scan(
                payload=response.error.data if response.error else None,
                ctx=ctx,
                method=None,
                direction="upstream_to_client",
            )
        else:
            await self._scan(
                payload=response.result,
                ctx=ctx,
                method=None,
                direction="upstream_to_client",
            )
        return None

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> Notification | None:
        await self._scan(
            payload=notification.params,
            ctx=ctx,
            method=notification.method,
            direction="client_to_upstream" if from_client else "upstream_to_client",
        )
        return None

    async def _scan(
        self,
        *,
        payload: object,
        ctx: InterceptContext,
        method: str | None,
        direction: str,
    ) -> None:
        if payload is None:
            return
        try:
            text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            return  # non-serialisable payload; the wire layer will reject downstream
        if len(text) > self._max_payload_bytes:
            text = text[: self._max_payload_bytes]
        seen: set[str] = set()
        for match in self._scan_text(text):
            if match.kind in seen:
                continue
            seen.add(match.kind)
            await self.emit(
                ctx=ctx,
                severity="HIGH" if match.kind in {"iban", "card"} else "MEDIUM",
                message=f"{match.kind} detected in payload",
                direction=direction,  # type: ignore[arg-type]
                method=method,
                evidence={"kind": match.kind, "snippet": match.snippet},
            )

    def _scan_text(self, text: str) -> Iterable[_Match]:
        # Dispatch per kind so the function stays under ruff's branch
        # cap as more PII patterns are added in the future.
        if "email" in self._kinds:
            yield from self._scan_email(text)
        if "iban" in self._kinds:
            yield from self._scan_iban(text)
        if "dni" in self._kinds:
            yield from self._scan_dni(text)
        if "card" in self._kinds:
            yield from self._scan_card(text)

    @staticmethod
    def _scan_email(text: str) -> Iterable[_Match]:
        for m in _EMAIL_RE.finditer(text):
            yield _Match(kind="email", snippet=_redact(m.group(0)))

    @staticmethod
    def _scan_iban(text: str) -> Iterable[_Match]:
        for m in _IBAN_RE.finditer(text):
            if _iban_is_valid(m.group(0)):
                yield _Match(kind="iban", snippet=_redact(m.group(0)))

    @staticmethod
    def _scan_dni(text: str) -> Iterable[_Match]:
        for m in _DNI_RE.finditer(text):
            if _dni_is_valid(m.group(1), m.group(2)):
                yield _Match(kind="dni", snippet=_redact(m.group(0)))
        for m in _NIE_RE.finditer(text):
            if _nie_is_valid(m.group(1), m.group(2), m.group(3)):
                yield _Match(kind="dni", snippet=_redact(m.group(0)))

    @staticmethod
    def _scan_card(text: str) -> Iterable[_Match]:
        for raw in _iter_card_candidates(text):
            if _luhn_is_valid(raw):
                yield _Match(kind="card", snippet=_redact(raw))


# ---------------------------------------------------------------------------
# Validators.
# ---------------------------------------------------------------------------


def _luhn_is_valid(digits: str) -> bool:
    """ISO/IEC 7812-1 Luhn check. ``digits`` must already be digits-only."""
    if not 13 <= len(digits) <= 19 or not digits.isdigit():
        return False
    total = 0
    parity = (len(digits) - 2) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - ord("0")
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_is_valid(value: str) -> bool:
    """ISO 13616 modulo-97 check."""
    if not 15 <= len(value) <= 34:
        return False
    rearranged = value[4:] + value[:4]
    numeric = "".join(str(ord(ch) - ord("A") + 10) if ch.isalpha() else ch for ch in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _dni_is_valid(digits: str, letter: str) -> bool:
    """Spanish DNI: digits modulo 23 -> letter."""
    if not digits.isdigit() or len(digits) != 8:
        return False
    return _DNI_LETTERS[int(digits) % 23] == letter.upper()


def _nie_is_valid(prefix: str, digits: str, letter: str) -> bool:
    """Spanish NIE: substitute the prefix (X/Y/Z) for its digit
    (0/1/2), then run the DNI modulo-23 check on the resulting 8-digit
    string."""
    prefix_upper = prefix.upper()
    if prefix_upper not in _NIE_PREFIX_VALUE:
        return False
    if not digits.isdigit() or len(digits) != 7:
        return False
    return _dni_is_valid(_NIE_PREFIX_VALUE[prefix_upper] + digits, letter)


def _iter_card_candidates(text: str) -> Iterable[str]:
    """Yield digit-only candidate card numbers extracted from the regex
    matches (which may include grouping spaces / hyphens)."""
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits.isdigit():
            yield digits


def _redact(value: str) -> str:
    """Replace the middle of ``value`` with ``*`` so logs never store
    the actual PII. Format: ``firstchar...lastchar (len=N)``."""
    if len(value) <= 2:
        return f"*** (len={len(value)})"
    return f"{value[0]}***{value[-1]} (len={len(value)})"
