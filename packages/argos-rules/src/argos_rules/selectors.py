"""Resolve a dotted selector against an MCPConfig / MCPServer pair.

Every selector returns a list of strings. Missing paths return an empty list,
never raise: rules that target optional fields must still evaluate cleanly.

Supported selectors:

    config.dialect            -> dialect name
    config.raw                -> JSON of the whole raw config
    config.path               -> on-disk path as string
    server.name               -> server name
    server.command            -> executable or empty
    server.args               -> each argument as a separate entry
    server.args[N]            -> argument at index N
    server.argv               -> "<command> <arg1> <arg2>..." joined
    server.url                -> url or empty
    server.transport          -> transport enum value
    server.env.<KEY>          -> single env value
    server.env.*              -> every env value (one per entry)
    server.env.keys           -> every env key (one per entry)
    server.headers.<KEY>      -> single header value
    server.headers.*          -> every header value
    server.raw                -> JSON of the server's raw block

Unknown selectors return an empty list so a mistyped selector cannot crash
the engine mid-scan.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from argos_scanner.models import MCPConfig, MCPServer


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _config_part(config: MCPConfig, rest: str) -> list[str]:
    if rest == "dialect":
        return [config.dialect]
    if rest == "path":
        return [str(config.path)]
    if rest == "raw":
        return [_json(config.raw)]
    return []


def _env_part(server: MCPServer, rest: str) -> list[str]:
    if rest == "":
        return [_json(server.env)]
    if rest == "*":
        return list(server.env.values())
    if rest == "keys":
        return list(server.env.keys())
    value = server.env.get(rest)
    return [] if value is None else [value]


def _headers_part(server: MCPServer, rest: str) -> list[str]:
    if rest == "":
        return [_json(server.headers)]
    if rest == "*":
        return list(server.headers.values())
    value = server.headers.get(rest)
    return [] if value is None else [value]


def _args_part(server: MCPServer, rest: str) -> list[str]:
    if rest == "":
        return list(server.args)
    if rest.startswith("[") and rest.endswith("]"):
        try:
            idx = int(rest[1:-1])
        except ValueError:
            return []
        if 0 <= idx < len(server.args):
            return [server.args[idx]]
    return []


def _server_name(s: MCPServer) -> list[str]:
    return [s.name]


def _server_command(s: MCPServer) -> list[str]:
    return [s.command] if s.command else []


def _server_argv(s: MCPServer) -> list[str]:
    return [" ".join(s.argv)] if s.argv else []


def _server_url(s: MCPServer) -> list[str]:
    return [s.url] if s.url else []


def _server_transport(s: MCPServer) -> list[str]:
    return [s.transport.value]


def _server_raw(s: MCPServer) -> list[str]:
    return [_json(s.raw)]


def _server_cwd(s: MCPServer) -> list[str]:
    return [s.cwd] if s.cwd else []


_SIMPLE_SERVER_FIELDS: dict[str, Callable[[MCPServer], list[str]]] = {
    "name": _server_name,
    "command": _server_command,
    "argv": _server_argv,
    "url": _server_url,
    "transport": _server_transport,
    "raw": _server_raw,
    "cwd": _server_cwd,
}

_SECTION_FIELDS: dict[str, Callable[[MCPServer, str], list[str]]] = {
    "args": _args_part,
    "env": _env_part,
    "headers": _headers_part,
}


def select(config: MCPConfig, server: MCPServer, selector: str) -> list[str]:  # noqa: PLR0911
    """Resolve ``selector`` against ``config`` or ``server``.

    Returns a list of the string parts it designates. Unknown selectors yield
    ``[]`` so a typo in a rule never crashes the engine.
    """
    if not selector:
        return []
    head, _, rest = selector.partition(".")

    if head == "config":
        return _config_part(config, rest)
    if head != "server":
        return []

    simple = _SIMPLE_SERVER_FIELDS.get(rest)
    if simple is not None:
        return simple(server)

    # "args", "args[N]", "args.<anything>" all resolve to the args selector.
    if rest == "args" or rest.startswith("args["):
        return _args_part(server, rest[len("args") :])

    second, _, tail = rest.partition(".")
    section = _SECTION_FIELDS.get(second)
    if section is not None:
        return section(server, tail)
    return []


def explain(parts: Iterable[str], *, max_chars: int = 160) -> str:
    """Compact, human-readable summary for Evidence. Truncates aggressively."""
    collapsed = " | ".join(parts)
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1] + "..."
