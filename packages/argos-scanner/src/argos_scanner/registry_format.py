"""Translate MCP Registry ``server.json`` documents into client configuration.

The official MCP Registry (``registry.modelcontextprotocol.io``) publishes
one ``server.json`` document per server version. A document lists
installable ``packages`` (npm, PyPI, OCI images, NuGet, MCPB bundles,
crates) and hosted ``remotes``. A client that installs from the registry
turns each of them into the same entry a user would otherwise write by
hand in ``claude_desktop_config.json`` or ``.vscode/mcp.json``. This module
performs that translation, so every built-in rule audits a registry entry
exactly as it would audit the configuration the client ends up running.

The translation is literal. Argument values, defaults and environment
defaults are copied verbatim; an argument with neither keeps its hint in
angle brackets (``<path>``) so rules see the shape of the command without
invented data. The original package or remote object is preserved under
``registryPackage`` / ``registryRemote`` and the listing text under
``registryDescription``. That text is documentation for whoever installs
the server, not something a model reads, so the tool-poisoning heuristic
does not treat it as model-facing.
"""

from __future__ import annotations

import re
from typing import Any, Final

#: Dialect name reported for registry documents.
REGISTRY_DIALECT: Final[str] = "mcp-registry"

#: Launcher a client uses for each package type when ``runtimeHint`` is absent.
_LAUNCHERS: Final[dict[str, str]] = {
    "npm": "npx",
    "pypi": "uvx",
    "oci": "docker",
    "nuget": "dnx",
}

_SLUG_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9-]{0,23}")

#: A ``runtimeHint`` is a command name. Some published entries carry a
#: sentence of installation advice there instead; such a value is ignored
#: and the package type's usual launcher is used.
_RUNTIME_HINT_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")


def unwrap_envelope(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the ``server`` object of a registry API envelope, or ``raw``.

    The registry API wraps each document as ``{"server": {...}, "_meta": {...}}``.
    """
    inner = raw.get("server")
    if isinstance(inner, dict) and set(raw) <= {"server", "_meta"}:
        return inner
    return raw


def is_registry_document(raw: dict[str, Any]) -> bool:
    """True when ``raw`` looks like a registry ``server.json`` document."""
    schema = raw.get("$schema")
    if isinstance(schema, str) and (
        "server.schema.json" in schema or "modelcontextprotocol.io/schemas" in schema
    ):
        return True
    return isinstance(raw.get("name"), str) and (
        isinstance(raw.get("packages"), list) or isinstance(raw.get("remotes"), list)
    )


def to_client_servers(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map a registry document to ``{server_name: client_entry}``.

    Names follow the order of the document: ``package-1-npm``,
    ``package-2-oci``, ``remote-1-streamable-http`` and so on.
    """
    description = _text(doc.get("description"))
    servers: dict[str, dict[str, Any]] = {}
    for index, package in enumerate(_objects(doc.get("packages")), start=1):
        name = f"package-{index}-{_slug(package.get('registryType'))}"
        servers[name] = _package_entry(package, description)
    for index, remote in enumerate(_objects(doc.get("remotes")), start=1):
        name = f"remote-{index}-{_slug(remote.get('type'))}"
        servers[name] = _remote_entry(remote, description)
    return servers


# ---------------------------------------------------------------------------
# Internals.
# ---------------------------------------------------------------------------


def _package_entry(package: dict[str, Any], description: str | None) -> dict[str, Any]:
    kind = (_text(package.get("registryType")) or "").lower()
    identifier = _text(package.get("identifier")) or ""
    version = _text(package.get("version"))
    raw_transport = package.get("transport")
    transport: dict[str, Any] = raw_transport if isinstance(raw_transport, dict) else {}
    hint = _text(package.get("runtimeHint"))
    if hint is not None and not _RUNTIME_HINT_RE.fullmatch(hint):
        hint = None
    launcher = hint or _LAUNCHERS.get(kind)
    runtime = _render_args(package.get("runtimeArguments"))
    args: list[str]
    if kind == "npm":
        args = runtime or ["-y"]
        args.append(f"{identifier}@{version}" if version else identifier)
    elif kind == "pypi":
        args = [*runtime, f"{identifier}=={version}" if version else identifier]
    elif kind == "oci":
        args = runtime if runtime[:1] == ["run"] else ["run", *(runtime or ["-i", "--rm"])]
        args.append(_image_reference(identifier, version))
    elif kind == "nuget":
        args = [*runtime, f"{identifier}@{version}" if version else identifier, "--yes"]
    else:
        # MCPB bundles, crates and future types: the identifier is what
        # the client fetches; no generic launcher exists.
        args = [*runtime, identifier] if identifier else runtime
    args.extend(_render_args(package.get("packageArguments")))

    entry: dict[str, Any] = {
        "type": _text(transport.get("type")) or "stdio",
        "args": args,
        "env": _render_pairs(package.get("environmentVariables")),
        "registryPackage": package,
    }
    if launcher is not None:
        entry["command"] = launcher
    if description is not None:
        entry["registryDescription"] = description
    url = _text(transport.get("url"))
    if url is not None:
        entry["url"] = url
        entry["headers"] = _render_pairs(transport.get("headers"))
    return entry


def _remote_entry(remote: dict[str, Any], description: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": _text(remote.get("type")) or "streamable-http",
        "headers": _render_pairs(remote.get("headers")),
        "registryRemote": remote,
    }
    url = _text(remote.get("url"))
    if url is not None:
        entry["url"] = url
    if description is not None:
        entry["registryDescription"] = description
    return entry


def _render_args(items: Any) -> list[str]:
    out: list[str] = []
    for arg in _objects(items):
        value = _value(arg)
        hint = _text(arg.get("valueHint"))
        if arg.get("type") == "named":
            name = _text(arg.get("name"))
            if name is None:
                continue
            out.append(name)
            if value is None and hint is not None:
                value = f"<{hint}>"
            if value is not None:
                out.append(value)
        else:
            placeholder = hint or _text(arg.get("name")) or "value"
            out.append(value if value is not None else f"<{placeholder}>")
    return out


def _render_pairs(items: Any) -> dict[str, str]:
    """``[{name, value|default}]`` (variables, headers) -> ``{name: value}``."""
    pairs: dict[str, str] = {}
    for item in _objects(items):
        name = _text(item.get("name"))
        if name is None:
            continue
        value = _value(item)
        pairs[name] = "" if value is None else value
    return pairs


def _value(item: dict[str, Any]) -> str | None:
    for key in ("value", "default"):
        candidate = item.get(key)
        if isinstance(candidate, bool):
            return "true" if candidate else "false"
        if isinstance(candidate, (str, int, float)):
            return str(candidate)
    return None


def _image_reference(identifier: str, version: str | None) -> str:
    last = identifier.rsplit("/", 1)[-1]
    if version and ":" not in last and "@" not in last:
        return f"{identifier}:{version}"
    return identifier


def _objects(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _slug(value: Any) -> str:
    text = (_text(value) or "").lower()
    return text if _SLUG_RE.fullmatch(text) else "unknown"


__all__ = [
    "REGISTRY_DIALECT",
    "is_registry_document",
    "to_client_servers",
    "unwrap_envelope",
]
