"""Parse MCP configuration files into :class:`MCPConfig`.

Recognised dialects:

- ``claude-desktop``: Claude Desktop ``claude_desktop_config.json`` (top-level
  ``mcpServers`` object).
- ``vscode``: VS Code ``.vscode/mcp.json`` (top-level ``servers`` object with
  ``type`` discriminator).
- ``mcp-spec``: draft MCP spec ``mcp.json`` (same shape as vscode variant;
  dialect reported separately for clarity in reports).

Unknown dialects are rejected early with ``UnsupportedDialectError`` so rules
never receive a half-understood payload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from argos_scanner.models import MCPConfig, MCPServer, TransportKind

_JSON_SUFFIXES: frozenset[str] = frozenset({".json"})
_YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})

# Defence-in-depth limit. A legitimate MCP config rarely exceeds a few KiB.
MAX_CONFIG_BYTES = 8 * 1024 * 1024  # 8 MiB


class ParserError(Exception):
    """Raised when a file cannot be parsed into an :class:`MCPConfig`."""


class UnsupportedDialectError(ParserError):
    """Raised when the document structure does not match any known MCP dialect."""


def load(path: Path) -> MCPConfig:
    """Read and normalise an MCP config file. See module docstring for dialects."""
    if not path.is_file():
        msg = f"path is not a file: {path}"
        raise ParserError(msg)

    size = path.stat().st_size
    if size > MAX_CONFIG_BYTES:
        msg = (
            f"{path}: refusing to parse {size} bytes "
            f"(limit {MAX_CONFIG_BYTES}); raise MAX_CONFIG_BYTES if the source is trusted."
        )
        raise ParserError(msg)

    raw = _read_any(path)
    if not isinstance(raw, dict):
        msg = f"{path}: top-level must be an object, got {type(raw).__name__}"
        raise ParserError(msg)

    dialect, servers_block = _detect_dialect(raw)
    servers = tuple(_parse_server(name, cfg) for name, cfg in servers_block.items())

    return MCPConfig(path=path.resolve(), dialect=dialect, servers=servers, raw=raw)


_BOM = "\ufeff"


def _read_any(path: Path) -> Any:
    # ``utf-8-sig`` strips a leading BOM; falls back to plain utf-8 if absent.
    text = path.read_text(encoding="utf-8-sig")
    if text.startswith(_BOM):
        text = text.lstrip(_BOM)
    suffix = path.suffix.lower()
    try:
        if suffix in _JSON_SUFFIXES:
            return json.loads(text)
        if suffix in _YAML_SUFFIXES:
            return yaml.safe_load(text)
    except json.JSONDecodeError as e:
        msg = f"{path}: invalid JSON ({e.msg} at line {e.lineno})"
        raise ParserError(msg) from e
    except yaml.YAMLError as e:
        msg = f"{path}: invalid YAML ({e})"
        raise ParserError(msg) from e
    except RecursionError as e:
        msg = f"{path}: structure is too deeply nested"
        raise ParserError(msg) from e

    # Fall back to JSON for unknown suffixes (common pattern: dotfiles).
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        msg = f"{path}: unknown file type and content is not valid JSON"
        raise ParserError(msg) from e
    except RecursionError as e:
        msg = f"{path}: structure is too deeply nested"
        raise ParserError(msg) from e


def _detect_dialect(raw: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if isinstance(raw.get("mcpServers"), dict):
        return "claude-desktop", raw["mcpServers"]
    if isinstance(raw.get("servers"), dict):
        # vscode and mcp-spec share shape; distinguish by presence of "inputs".
        dialect = "vscode" if "inputs" in raw else "mcp-spec"
        return dialect, raw["servers"]
    msg = "neither 'mcpServers' nor 'servers' found at top level"
    raise UnsupportedDialectError(msg)


def _parse_server(name: str, cfg: Any) -> MCPServer:
    if not isinstance(cfg, dict):
        msg = f"server {name!r} must be an object, got {type(cfg).__name__}"
        raise ParserError(msg)

    transport = _parse_transport(cfg)

    # Normalise env: coerce scalar values to strings; reject nested structures.
    env_raw = cfg.get("env") or {}
    if not isinstance(env_raw, dict):
        msg = f"server {name!r}: 'env' must be an object"
        raise ParserError(msg)
    env: dict[str, str] = {}
    for k, v in env_raw.items():
        if isinstance(v, (dict, list)):
            msg = f"server {name!r}: env[{k!r}] must be scalar"
            raise ParserError(msg)
        env[str(k)] = "" if v is None else str(v)

    headers_raw = cfg.get("headers") or {}
    if not isinstance(headers_raw, dict):
        msg = f"server {name!r}: 'headers' must be an object"
        raise ParserError(msg)
    headers = {str(k): str(v) for k, v in headers_raw.items()}

    args_raw = cfg.get("args") or []
    if not isinstance(args_raw, list):
        msg = f"server {name!r}: 'args' must be a list"
        raise ParserError(msg)

    return MCPServer(
        name=name,
        transport=transport,
        command=cfg.get("command"),
        args=tuple(str(a) for a in args_raw),
        env=env,
        cwd=cfg.get("cwd"),
        url=cfg.get("url"),
        headers=headers,
        raw=dict(cfg),
    )


def _parse_transport(cfg: dict[str, Any]) -> TransportKind:
    declared = cfg.get("type") or cfg.get("transport")
    if isinstance(declared, str):
        try:
            return TransportKind(declared.lower())
        except ValueError:
            return TransportKind.UNKNOWN
    # Infer from shape: URL implies remote, command implies stdio.
    if isinstance(cfg.get("url"), str):
        return TransportKind.HTTP
    if isinstance(cfg.get("command"), str):
        return TransportKind.STDIO
    return TransportKind.UNKNOWN
