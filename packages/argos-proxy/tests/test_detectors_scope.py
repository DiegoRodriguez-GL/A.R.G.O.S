"""Unit tests for :class:`ScopeDetector`."""

from __future__ import annotations

import pytest
from argos_proxy import JsonRpcError, Notification, Request
from argos_proxy.detectors import InMemoryFindingSink, ScopeDetector
from argos_proxy.interceptor import new_context
from argos_proxy.jsonrpc import METHOD_NOT_FOUND

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Allowlist enforcement.
# ---------------------------------------------------------------------------


class TestMethodAllowlist:
    async def test_no_allowlist_permits_everything_when_not_blocking(self) -> None:
        # Empty allowlist + block_on_violation=False is valid: "log
        # nothing, forward everything", useful for an observability
        # deployment.
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, block_on_violation=False)
        result = await det.on_request_in(Request(method="anything", id=1), new_context())
        assert result is None
        assert sink.findings == []

    async def test_block_with_empty_allowlist_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="block_on_violation=True"):
            ScopeDetector(block_on_violation=True)

    async def test_method_in_allowlist_passes(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["tools/list"])
        result = await det.on_request_in(Request(method="tools/list", id=1), new_context())
        assert result is None

    async def test_method_outside_allowlist_blocks(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["tools/list"])
        with pytest.raises(JsonRpcError) as exc:
            await det.on_request_in(Request(method="tools/call", id=1), new_context())
        assert exc.value.code == METHOD_NOT_FOUND
        assert sink.findings[0].severity == "HIGH"

    async def test_method_glob_pattern_works(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["tools/*"])
        # Both pass.
        await det.on_request_in(Request(method="tools/list", id=1), new_context())
        await det.on_request_in(Request(method="tools/call", id=2), new_context())
        # This one fails.
        with pytest.raises(JsonRpcError):
            await det.on_request_in(Request(method="resources/read", id=3), new_context())

    @pytest.mark.parametrize(
        "method",
        ["initialize", "initialized", "ping", "shutdown", "exit"],
    )
    async def test_handshake_methods_always_pass(self, method: str) -> None:
        # Even with an empty allowlist these go through.
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["nothing"])
        result = await det.on_request_in(Request(method=method, id=1), new_context())
        assert result is None
        assert sink.findings == []


class TestToolAllowlist:
    async def test_tools_call_with_allowed_tool_passes(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_tools=["echo"])
        result = await det.on_request_in(
            Request(method="tools/call", params={"name": "echo", "arguments": {}}, id=1),
            new_context(),
        )
        assert result is None

    async def test_tools_call_with_blocked_tool_raises(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_tools=["echo"])
        with pytest.raises(JsonRpcError) as exc:
            await det.on_request_in(
                Request(method="tools/call", params={"name": "evil"}, id=1),
                new_context(),
            )
        assert "evil" in exc.value.message

    async def test_tool_glob(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_tools=["calc.*"])
        await det.on_request_in(
            Request(method="tools/call", params={"name": "calc.add"}, id=1),
            new_context(),
        )
        with pytest.raises(JsonRpcError):
            await det.on_request_in(
                Request(method="tools/call", params={"name": "fs.read"}, id=2),
                new_context(),
            )

    async def test_tools_call_without_name_passes(self) -> None:
        # Malformed payload; the upstream will reject it. We don't.
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_tools=["echo"])
        result = await det.on_request_in(
            Request(method="tools/call", params={"missing_name": True}, id=1),
            new_context(),
        )
        assert result is None


class TestNonBlockingMode:
    async def test_block_on_violation_false_logs_only(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(
            sink,
            allowed_methods=["tools/list"],
            block_on_violation=False,
        )
        # No raise, but a finding is emitted.
        result = await det.on_request_in(Request(method="tools/call", id=1), new_context())
        assert result is None
        assert sink.findings[0].severity == "HIGH"


class TestNotifications:
    async def test_client_notification_outside_scope_logs(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["tools/*"])
        await det.on_notification(
            Notification(method="resources/changed"),
            new_context(),
            from_client=True,
        )
        assert sink.findings[0].severity == "MEDIUM"

    async def test_upstream_notification_does_not_log(self) -> None:
        # Upstream-originated notifications are not subject to scope.
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["tools/*"])
        await det.on_notification(
            Notification(method="resources/changed"),
            new_context(),
            from_client=False,
        )
        assert sink.findings == []

    async def test_handshake_notifications_pass(self) -> None:
        sink = InMemoryFindingSink()
        det = ScopeDetector(sink, allowed_methods=["nothing"])
        await det.on_notification(
            Notification(method="initialized"),
            new_context(),
            from_client=True,
        )
        assert sink.findings == []
