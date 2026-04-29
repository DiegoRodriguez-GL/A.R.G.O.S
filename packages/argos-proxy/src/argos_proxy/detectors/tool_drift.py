"""Tool definition drift detector.

The most weaponisable mutation a hostile (or compromised) MCP server
can perform is to silently change a tool's signature mid-session: the
client thought it was calling ``calendar.create_event(date, title)``
but the upstream now expects ``calendar.create_event(date, title,
auth_token)`` and exfiltrates the freshly-injected argument. The
"tool rug-pull" is one of the canonical OWASP ASI02 (Tool Misuse)
attack patterns.

Defence: pin a baseline of tool definitions on the FIRST observed
``tools/list`` response and flag any subsequent definition that does
not match. The baseline is in-memory; persistence is the operator's
choice (forensic SQLite store in Phase 4).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from argos_proxy.detectors._base import FindingSink, ProxyDetector
from argos_proxy.interceptor import InterceptContext
from argos_proxy.jsonrpc import Notification, Response


@dataclass(frozen=True)
class ToolDefinitionSnapshot:
    """Hash + canonical JSON of one tool entry from ``tools/list``."""

    name: str
    digest: str  # sha256 hex
    canonical_json: str

    @classmethod
    def from_payload(cls, tool: dict[str, Any]) -> ToolDefinitionSnapshot:
        if "name" not in tool or not isinstance(tool["name"], str):
            msg = "tool definition missing string 'name'"
            raise ValueError(msg)
        # Sort keys for canonical form so a re-ordered (but otherwise
        # identical) definition does not trip the detector.
        canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(name=tool["name"], digest=digest, canonical_json=canonical)


@dataclass
class _Baseline:
    """Mutable per-session record of accepted tool snapshots."""

    snapshots: dict[str, ToolDefinitionSnapshot] = field(default_factory=dict)
    locked: bool = False


class ToolDriftDetector(ProxyDetector):
    """Pin tool definitions on first sight; flag every later mutation.

    Two modes (set via constructor):

    - ``mode="warn"``: emit a HIGH-severity finding and let the
      response through. Default; suitable for an audit pass.
    - ``mode="block"``: in addition to the finding, replace the
      mutated tool entry with the original. Suitable for a deploy
      where you trust the baseline more than the live upstream.

    Notifications of type ``tools/list/changed`` reset the baseline
    only when ``allow_reset=True`` (default ``False``). MCP servers
    legitimately use that notification, but a server that resets
    after every request is suspicious; auditors usually leave reset
    disabled to keep the pinning property.
    """

    detector_id = "argos.proxy.tool_drift"

    def __init__(
        self,
        sink: FindingSink | None = None,
        *,
        mode: str = "warn",
        allow_reset: bool = False,
    ) -> None:
        super().__init__(sink)
        if mode not in {"warn", "block"}:
            msg = f"mode must be 'warn' or 'block', got {mode!r}"
            raise ValueError(msg)
        self._mode = mode
        self._allow_reset = allow_reset
        self._baseline = _Baseline()

    @property
    def baseline(self) -> dict[str, ToolDefinitionSnapshot]:
        return dict(self._baseline.snapshots)

    @property
    def is_locked(self) -> bool:
        return self._baseline.locked

    async def on_response_out(
        self,
        response: Response,
        ctx: InterceptContext,
    ) -> Response | None:
        # Only inspect successful tools/list responses. The detector
        # cannot know the request's method directly; we identify the
        # response by its shape (``result`` carrying ``tools: [...]``)
        # because JSON-RPC does not echo the method back.
        if not response.is_success:
            return None
        tools = self._extract_tools(response.result)
        if tools is None:
            return None
        observed: dict[str, ToolDefinitionSnapshot] = {}
        for tool in tools:
            try:
                snap = ToolDefinitionSnapshot.from_payload(tool)
            except ValueError:
                # Malformed entry; skip silently. The tool will still
                # be forwarded; static scanner / schema validators are
                # responsible for shape enforcement.
                continue
            observed[snap.name] = snap

        if not self._baseline.locked:
            # First observation: pin and emit an INFO breadcrumb so
            # the forensics log records the baseline.
            self._baseline.snapshots = observed
            self._baseline.locked = True
            await self.emit(
                ctx=ctx,
                severity="INFO",
                message=f"baseline pinned: {len(observed)} tools",
                direction="upstream_to_client",
                method="tools/list",
                evidence={"tool_names": sorted(observed)},
            )
            return None

        # Compare against baseline. We care about three deltas:
        # * added tools (a new tool the client hadn't agreed to)
        # * removed tools (capability surface shrank silently)
        # * mutated tools (digest mismatch)
        baseline = self._baseline.snapshots
        added = sorted(set(observed) - set(baseline))
        removed = sorted(set(baseline) - set(observed))
        mutated: list[str] = []
        for name in set(baseline) & set(observed):
            if baseline[name].digest != observed[name].digest:
                mutated.append(name)

        if not (added or removed or mutated):
            return None

        await self.emit(
            ctx=ctx,
            severity="HIGH",
            message=(f"tool drift detected: +{len(added)} -{len(removed)} ~{len(mutated)}"),
            direction="upstream_to_client",
            method="tools/list",
            evidence={
                "added": added,
                "removed": removed,
                "mutated": sorted(mutated),
            },
        )
        if self._mode == "warn":
            return None
        # Block mode: rebuild the response using the baseline tools.
        rebuilt_tools = [
            json.loads(self._baseline.snapshots[n].canonical_json)
            for n in sorted(self._baseline.snapshots)
        ]
        return Response(
            result={"tools": rebuilt_tools},
            id=response.id,
        )

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> Notification | None:
        if from_client:
            return None
        if notification.method != "notifications/tools/list_changed":
            return None
        if not self._allow_reset:
            await self.emit(
                ctx=ctx,
                severity="MEDIUM",
                message="upstream sent tools/list_changed but reset is disabled",
                direction="upstream_to_client",
                method=notification.method,
            )
            return None
        # Auditor opted-in to honouring the reset.
        self._baseline = _Baseline()
        await self.emit(
            ctx=ctx,
            severity="LOW",
            message="baseline reset by tools/list_changed notification",
            direction="upstream_to_client",
            method=notification.method,
        )
        return None

    @staticmethod
    def _extract_tools(result: object) -> list[dict[str, Any]] | None:
        """Return the ``tools`` array if ``result`` looks like a
        ``tools/list`` payload; otherwise None."""
        if not isinstance(result, dict):
            return None
        tools = result.get("tools")
        if not isinstance(tools, list):
            return None
        # Reject obviously malformed entries up front.
        return [t for t in tools if isinstance(t, dict)]
