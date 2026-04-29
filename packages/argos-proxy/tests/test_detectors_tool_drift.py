"""Unit tests for :class:`ToolDriftDetector`."""

from __future__ import annotations

import pytest
from argos_proxy import Notification, Response
from argos_proxy.detectors import (
    InMemoryFindingSink,
    ToolDefinitionSnapshot,
    ToolDriftDetector,
)
from argos_proxy.interceptor import new_context

pytestmark = pytest.mark.asyncio


def _tools_list(*tools: dict[str, object]) -> Response:
    return Response(result={"tools": list(tools)}, id=1)


# ---------------------------------------------------------------------------
# Snapshot.
# ---------------------------------------------------------------------------


class TestToolDefinitionSnapshot:
    async def test_digest_is_stable_under_key_reorder(self) -> None:
        a = ToolDefinitionSnapshot.from_payload({"name": "x", "description": "d"})
        b = ToolDefinitionSnapshot.from_payload({"description": "d", "name": "x"})
        assert a.digest == b.digest

    async def test_digest_changes_when_value_changes(self) -> None:
        a = ToolDefinitionSnapshot.from_payload({"name": "x", "description": "d"})
        b = ToolDefinitionSnapshot.from_payload({"name": "x", "description": "X"})
        assert a.digest != b.digest

    async def test_missing_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing string 'name'"):
            ToolDefinitionSnapshot.from_payload({"description": "d"})

    async def test_non_string_name_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            ToolDefinitionSnapshot.from_payload({"name": 42, "description": "d"})


# ---------------------------------------------------------------------------
# Baseline pinning.
# ---------------------------------------------------------------------------


class TestBaseline:
    async def test_first_response_pins_baseline(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        await det.on_response_out(
            _tools_list({"name": "calc", "description": "math"}),
            new_context(),
        )
        assert det.is_locked
        assert "calc" in det.baseline
        # An INFO breadcrumb is emitted for the forensics trail.
        info = sink.by_detector("argos.proxy.tool_drift")
        assert len(info) == 1
        assert info[0].severity == "INFO"

    async def test_unmodified_response_is_silent(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        first = _tools_list({"name": "x", "description": "d"})
        await det.on_response_out(first, new_context())
        sink.clear()
        await det.on_response_out(first, new_context())
        assert sink.findings == []

    async def test_non_tools_list_response_is_ignored(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        # Response carrying a non-tools result.
        await det.on_response_out(Response(result={"ok": True}, id=1), new_context())
        assert not det.is_locked
        assert sink.findings == []


# ---------------------------------------------------------------------------
# Drift detection.
# ---------------------------------------------------------------------------


class TestDriftDetection:
    async def test_added_tool_emits_finding(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        sink.clear()
        await det.on_response_out(
            _tools_list(
                {"name": "a", "description": "x"},
                {"name": "b", "description": "y"},
            ),
            new_context(),
        )
        assert len(sink.findings) == 1
        f = sink.findings[0]
        assert f.severity == "HIGH"
        assert f.evidence["added"] == ["b"]
        assert f.evidence["mutated"] == []

    async def test_removed_tool_emits_finding(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        await det.on_response_out(
            _tools_list({"name": "a", "description": "x"}, {"name": "b", "description": "y"}),
            new_context(),
        )
        sink.clear()
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        assert sink.findings[0].evidence["removed"] == ["b"]

    async def test_mutated_tool_emits_finding(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        sink.clear()
        await det.on_response_out(_tools_list({"name": "a", "description": "EVIL"}), new_context())
        assert sink.findings[0].evidence["mutated"] == ["a"]

    async def test_warn_mode_does_not_modify_response(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink, mode="warn")
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        original = _tools_list({"name": "a", "description": "EVIL"})
        replacement = await det.on_response_out(original, new_context())
        assert replacement is None  # pass-through

    async def test_block_mode_replaces_response_with_baseline(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink, mode="block")
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        replacement = await det.on_response_out(
            _tools_list({"name": "a", "description": "EVIL"}),
            new_context(),
        )
        assert replacement is not None
        # Baseline restored: description is the original.
        rebuilt = replacement.result["tools"]
        assert rebuilt[0]["description"] == "x"


# ---------------------------------------------------------------------------
# Reset notification.
# ---------------------------------------------------------------------------


class TestListChangedNotification:
    async def test_reset_disabled_emits_warning(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink, allow_reset=False)
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        sink.clear()
        await det.on_notification(
            Notification(method="notifications/tools/list_changed"),
            new_context(),
            from_client=False,
        )
        assert len(sink.findings) == 1
        assert sink.findings[0].severity == "MEDIUM"
        assert det.is_locked  # baseline NOT cleared

    async def test_reset_enabled_clears_baseline(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink, allow_reset=True)
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        await det.on_notification(
            Notification(method="notifications/tools/list_changed"),
            new_context(),
            from_client=False,
        )
        assert not det.is_locked

    async def test_client_side_notification_is_ignored(self) -> None:
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink, allow_reset=True)
        await det.on_response_out(_tools_list({"name": "a", "description": "x"}), new_context())
        await det.on_notification(
            Notification(method="notifications/tools/list_changed"),
            new_context(),
            from_client=True,
        )
        assert det.is_locked  # client-side reset is not honoured


# ---------------------------------------------------------------------------
# Construction.
# ---------------------------------------------------------------------------


class TestConstruction:
    async def test_invalid_mode_rejected(self) -> None:
        with pytest.raises(ValueError, match="mode must be"):
            ToolDriftDetector(mode="rainbow")
