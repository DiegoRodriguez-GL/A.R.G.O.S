"""Unit tests for :class:`PIIDetector`. Validates each pattern with
known-positive and known-negative cases plus checksum-based filters
that knock out random-digit collisions."""

from __future__ import annotations

import pytest
from argos_proxy import Notification, Request, Response
from argos_proxy.detectors import InMemoryFindingSink, PIIDetector
from argos_proxy.detectors.pii import (
    _dni_is_valid,
    _iban_is_valid,
    _luhn_is_valid,
    _redact,
)
from argos_proxy.interceptor import new_context

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Detection.
# ---------------------------------------------------------------------------


class TestEmail:
    async def test_email_in_request_params_is_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="tools/call", params={"to": "alice@example.com"}, id=1),
            new_context(),
        )
        kinds = [f.evidence["kind"] for f in sink.findings]
        assert "email" in kinds

    async def test_email_in_response_result_is_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_response_out(
            Response(result={"contact": "x@y.es"}, id=1),
            new_context(),
        )
        assert sink.findings  # at least one finding

    async def test_no_false_positive_on_innocuous_text(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"text": "hello world"}, id=1),
            new_context(),
        )
        assert sink.findings == []


class TestCard:
    @pytest.mark.parametrize(
        "card",
        [
            "4111111111111111",  # Visa test card (Luhn-valid)
            "5555555555554444",  # MasterCard test card
            "378282246310005",  # AmEx test card
        ],
    )
    async def test_known_test_cards_detected(self, card: str) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"number": card}, id=1),
            new_context(),
        )
        kinds = [f.evidence["kind"] for f in sink.findings]
        assert "card" in kinds

    async def test_random_digits_dont_match(self) -> None:
        # 16 digits but Luhn-invalid.
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"x": "1234567890123456"}, id=1),
            new_context(),
        )
        kinds = [f.evidence["kind"] for f in sink.findings]
        assert "card" not in kinds

    async def test_card_with_spaces_or_dashes_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"n": "4111 1111 1111 1111"}, id=1),
            new_context(),
        )
        assert any(f.evidence["kind"] == "card" for f in sink.findings)


class TestIBAN:
    async def test_known_iban_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        # ES91 2100 0418 4502 0005 1332 -- canonical example IBAN.
        await det.on_request_in(
            Request(method="m", params={"iban": "ES9121000418450200051332"}, id=1),
            new_context(),
        )
        assert any(f.evidence["kind"] == "iban" for f in sink.findings)

    async def test_random_alphanum_string_not_iban(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"s": "AB1234ABCDEFGHIJKL"}, id=1),
            new_context(),
        )
        assert all(f.evidence["kind"] != "iban" for f in sink.findings)


class TestDNI:
    async def test_valid_dni_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        # 12345678 mod 23 = 14 -> letter Z.
        await det.on_request_in(
            Request(method="m", params={"id": "12345678Z"}, id=1),
            new_context(),
        )
        assert any(f.evidence["kind"] == "dni" for f in sink.findings)

    async def test_dni_with_wrong_letter_rejected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"id": "12345678A"}, id=1),
            new_context(),
        )
        assert all(f.evidence["kind"] != "dni" for f in sink.findings)


class TestRedaction:
    @pytest.mark.parametrize(
        ("value", "expected_format"),
        [
            ("alice@example.com", "a***m (len=17)"),
            ("4111111111111111", "4***1 (len=16)"),
            ("12345678Z", "1***Z (len=9)"),
        ],
    )
    async def test_redacted_form_hides_middle(self, value: str, expected_format: str) -> None:
        assert _redact(value) == expected_format

    async def test_short_string_collapses(self) -> None:
        assert _redact("ab") == "*** (len=2)"
        assert _redact("a") == "*** (len=1)"


class TestValidators:
    @pytest.mark.parametrize(
        "valid",
        ["4111111111111111", "5555555555554444", "378282246310005"],
    )
    async def test_luhn_known_positives(self, valid: str) -> None:
        assert _luhn_is_valid(valid)

    @pytest.mark.parametrize(
        "invalid",
        # Length-valid but checksum-invalid + a non-numeric edge.
        ["1234567890123456", "4111111111111112", "abcd"],
    )
    async def test_luhn_known_negatives(self, invalid: str) -> None:
        assert not _luhn_is_valid(invalid)

    async def test_iban_known_positive(self) -> None:
        assert _iban_is_valid("ES9121000418450200051332")

    async def test_iban_known_negative(self) -> None:
        assert not _iban_is_valid("ES0021000418450200051332")  # wrong checksum

    async def test_dni_known_positive(self) -> None:
        assert _dni_is_valid("12345678", "Z")

    async def test_dni_known_negative(self) -> None:
        assert not _dni_is_valid("12345678", "A")


# ---------------------------------------------------------------------------
# De-duplication and configuration.
# ---------------------------------------------------------------------------


class TestBehaviour:
    async def test_one_finding_per_kind_per_message(self) -> None:
        """Two emails in the same payload still produce a single finding
        (the detector dedupes by kind)."""
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"a": "a@x.es", "b": "b@y.es"}, id=1),
            new_context(),
        )
        emails = [f for f in sink.findings if f.evidence["kind"] == "email"]
        assert len(emails) == 1

    async def test_unknown_kind_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown PII kinds"):
            PIIDetector(kinds=["email", "ssn"])

    async def test_kind_subset_filters_findings(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink, kinds=["email"])
        await det.on_request_in(
            Request(method="m", params={"e": "a@b.es", "card": "4111111111111111"}, id=1),
            new_context(),
        )
        kinds = {f.evidence["kind"] for f in sink.findings}
        assert kinds == {"email"}

    async def test_no_payload_no_findings(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(Request(method="m", id=1), new_context())
        assert sink.findings == []

    async def test_notification_payload_scanned(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_notification(
            Notification(method="m", params={"e": "a@b.es"}),
            new_context(),
            from_client=True,
        )
        assert any(f.evidence["kind"] == "email" for f in sink.findings)
