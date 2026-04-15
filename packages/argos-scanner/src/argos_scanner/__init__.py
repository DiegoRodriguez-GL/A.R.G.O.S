"""Static scanner for MCP configurations (Module 2)."""

from __future__ import annotations

from argos_scanner.engine import scan
from argos_scanner.models import MCPConfig, MCPServer, TransportKind
from argos_scanner.parser import ParserError, UnsupportedDialectError, load
from argos_scanner.registry import all_rules, select

__all__ = [
    "MCPConfig",
    "MCPServer",
    "ParserError",
    "TransportKind",
    "UnsupportedDialectError",
    "all_rules",
    "load",
    "scan",
    "select",
]

__version__ = "0.0.1"
