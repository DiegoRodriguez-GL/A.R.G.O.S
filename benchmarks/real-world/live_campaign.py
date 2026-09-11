"""Campaigns B and C: live audit of published MCP servers through ARGOS.

Usage:
    python live_campaign.py [--argos PATH] [--out DIR] [TARGET ...]

B runs the official reference servers (pinned to the versions in
results/versions.json) locally over stdio. C talks to public remote servers
over streamable HTTP, plus two that require OAuth. For every target the
same client code runs twice, directly and through ``argos proxy wrap``, so
the difference between the two is the cost of the audit layer. Only
documented, read-only tools are called, with benign arguments, and each
remote server receives a few dozen requests at most.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any

from argos_proxy import HttpStreamableTransport, Notification, Request, Response, StdioTransport
from argos_scanner.rules.tool_poisoning import _SUSPICIOUS_PHRASES

HERE = Path(__file__).resolve().parent
CLIENT_INFO = {"name": "argos-real-world", "version": "1.0"}
VERSIONS = json.loads((HERE / "results" / "versions.json").read_text(encoding="utf-8"))


def npx(pkg: str, *args: str) -> list[str]:
    return ["npx", "-y", f"{pkg}@{VERSIONS[pkg]}", *args]


def uvx(pkg: str, *args: str) -> list[str]:
    return ["uvx", f"{pkg}=={VERSIONS[pkg]}", *args]


def local_targets(sandbox: Path, repo: Path, out: Path) -> list[dict[str, Any]]:
    targets = [
        {
            "id": "everything",
            "argv": npx("@modelcontextprotocol/server-everything"),
            "call": ("echo", {"message": "hello from ARGOS"}),
            "bench": ("tools/call", {"name": "echo", "arguments": {"message": "argos"}}),
        },
        {
            "id": "filesystem",
            "argv": npx("@modelcontextprotocol/server-filesystem", str(sandbox)),
            "call": ("read_text_file", {"path": str(sandbox / "notes.txt")}),
            "bench": ("tools/call", {"name": "list_allowed_directories", "arguments": {}}),
        },
        {
            "id": "memory",
            "argv": npx("@modelcontextprotocol/server-memory"),
            "env_extra": {"MEMORY_FILE_PATH": str(out / "memory.jsonl")},
            "call": ("read_graph", {}),
            "bench": ("tools/call", {"name": "read_graph", "arguments": {}}),
        },
        {
            "id": "sequential-thinking",
            "argv": npx("@modelcontextprotocol/server-sequential-thinking"),
            "call": (
                "sequentialthinking",
                {
                    "thought": "check the proxy",
                    "nextThoughtNeeded": False,
                    "thoughtNumber": 1,
                    "totalThoughts": 1,
                },
            ),
            "bench": ("tools/list", {}),
        },
        {
            "id": "time",
            "argv": uvx("mcp-server-time"),
            "call": ("get_current_time", {"timezone": "Europe/Madrid"}),
            "bench": ("tools/call", {"name": "get_current_time", "arguments": {"timezone": "UTC"}}),
        },
        {
            "id": "fetch",
            "argv": uvx("mcp-server-fetch"),
            "call": ("fetch", {"url": "https://example.com", "max_length": 500}),
            "bench": ("tools/list", {}),
        },
        {
            "id": "git",
            "argv": uvx("mcp-server-git", "--repository", str(repo)),
            "call": ("git_status", {"repo_path": str(repo)}),
            "bench": ("tools/call", {"name": "git_status", "arguments": {"repo_path": str(repo)}}),
        },
    ]
    for t in targets:
        t.update(kind="stdio", n=100)
    return targets


REMOTE: list[dict[str, Any]] = [
    {
        "id": "deepwiki",
        "url": "https://mcp.deepwiki.com/mcp",
        "call": ("read_wiki_structure", {"repoName": "modelcontextprotocol/servers"}),
    },
    {
        "id": "microsoft-learn",
        "url": "https://learn.microsoft.com/api/mcp",
        "call": ("microsoft_docs_search", {"query": "Model Context Protocol security"}),
    },
    {"id": "cloudflare-docs", "url": "https://docs.mcp.cloudflare.com/mcp", "call": None},
    {"id": "huggingface", "url": "https://huggingface.co/mcp", "call": None},
    {"id": "gitmcp", "url": "https://gitmcp.io/docs", "call": None},
    {"id": "aws-knowledge", "url": "https://knowledge-mcp.global.api.aws", "call": None},
    {"id": "astro-docs", "url": "https://mcp.docs.astro.build/mcp", "call": None},
    {"id": "semgrep", "url": "https://mcp.semgrep.ai/mcp", "auth": True},
    {"id": "github-copilot", "url": "https://api.githubcopilot.com/mcp/", "auth": True},
]
for _t in REMOTE:
    _t.update(kind="http", n=0 if _t.get("auth") else 10, bench=("tools/list", {}))


def prepare(sandbox: Path, repo: Path) -> None:
    sandbox.mkdir(parents=True, exist_ok=True)
    # Synthetic personal data: example e-mail, the ISO 13616 example IBAN
    # in printed form and a test DNI with a valid control letter.
    (sandbox / "notes.txt").write_text(
        "Internal test report.\nContact: ana.garcia@example.com\n"
        "Account: ES91 2100 0418 4502 0005 1332\nID: 12345678Z\n",
        encoding="utf-8",
    )
    (sandbox / "public.txt").write_text("No personal data here.\n", encoding="utf-8")
    (sandbox / "pwned.txt").unlink(missing_ok=True)
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "README.md").write_text("test repository\n", encoding="utf-8")
        ident = ["-c", "user.name=case", "-c", "user.email=case@example.com"]
        for cmd in (
            ["git", "init", "-q"],
            ["git", *ident, "add", "."],
            ["git", *ident, "commit", "-q", "-m", "init"],
        ):
            subprocess.run(cmd, cwd=repo, check=True)


class Session:
    def __init__(self, transport: Any) -> None:
        self.t = transport
        self.next_id = 100
        self.notes: list[str] = []

    async def request(
        self, method: str, params: Any = None, timeout: float = 90
    ) -> tuple[Response, float]:
        rid = self.next_id
        self.next_id += 1
        t0 = time.perf_counter()
        await self.t.send(Request(method=method, params=params, id=rid))
        while True:
            msg = await asyncio.wait_for(self.t.receive(), timeout)
            if isinstance(msg, Response) and msg.id == rid:
                return msg, (time.perf_counter() - t0) * 1000
            self.notes.append(getattr(msg, "method", type(msg).__name__))
            if isinstance(msg, Request):  # server-initiated request (ping, roots)
                await self.t.send(Response(result={}, id=msg.id))

    async def notify(self, method: str) -> None:
        await self.t.send(Notification(method=method))


def poisoning_hits(tools: list[dict[str, Any]]) -> list[dict[str, str]]:
    hits = []
    for tool in tools:
        stack: list[tuple[str, Any]] = [
            ("description", tool.get("description")),
            ("inputSchema", tool.get("inputSchema")),
        ]
        while stack:
            where, node = stack.pop()
            if isinstance(node, str) and where.endswith("description"):
                hits += [
                    {"tool": tool.get("name", "?"), "where": where, "phrase": m.group(0)}
                    for m in _SUSPICIOUS_PHRASES.finditer(node)
                ]
            elif isinstance(node, dict):
                stack += [(f"{where}.{k}", v) for k, v in node.items()]
            elif isinstance(node, list):
                stack += [(f"{where}[]", v) for v in node]
    return hits


def pick_call(
    tools: list[dict[str, Any]], preferred: tuple[str, dict[str, Any]] | None
) -> tuple[str, dict[str, Any]] | None:
    if preferred and preferred[0] in {t.get("name") for t in tools}:
        return preferred
    for tool in tools:
        schema = tool.get("inputSchema") or {}
        props, required = schema.get("properties") or {}, schema.get("required") or []
        if (
            "search" in str(tool.get("name", "")).lower()
            and required
            and all((props.get(r) or {}).get("type") == "string" for r in required)
        ):
            return str(tool["name"]), dict.fromkeys(required, "Model Context Protocol")
    return None


def tls_info(url: str) -> dict[str, Any]:
    host = url.split("/")[2]
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((host, 443), timeout=15) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls,
    ):
        cert = tls.getpeercert() or {}
        issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
        return {
            "version": tls.version(),
            "cipher": (tls.cipher() or ("?",))[0],
            "issuer": issuer.get("organizationName"),
            "not_after": cert.get("notAfter"),
        }


def session_id_shape(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    shape: dict[str, Any] = {"length": len(value)}
    shape["uuid_like"] = len(value) == 36 and set(value.lower()) <= set("0123456789abcdef-")
    shape["hex"] = set(value.lower()) <= set("0123456789abcdef")
    try:
        decoded = json.loads(base64.b64decode(value + "=" * (-len(value) % 4)))
        shape["decodes_to_json_keys"] = sorted(decoded) if isinstance(decoded, dict) else None
    except (ValueError, UnicodeDecodeError):
        shape["decodes_to_json_keys"] = None
    return shape


async def run_target(target: dict[str, Any], mode: str, argos: str, out: Path) -> dict[str, Any]:
    db = out / f"{target['id']}_{mode}.sqlite3"
    db.unlink(missing_ok=True)
    wrap = [argos, "proxy", "wrap", "--no-otel", "-f", str(db)]
    env = {**os.environ, **target["env_extra"]} if target.get("env_extra") else None
    if target["kind"] == "stdio":
        transport: Any = StdioTransport(
            target["argv"] if mode == "direct" else [*wrap, *target["argv"]], env=env
        )
    elif mode == "direct":
        transport = HttpStreamableTransport(target["url"])
    else:
        transport = StdioTransport([*wrap, "--upstream", target["url"]])
    rec: dict[str, Any] = {"target": target["id"], "mode": mode}
    try:
        session = Session(transport)
        init, ms = await session.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": CLIENT_INFO},
            timeout=240,
        )
        rec["init_ms"] = round(ms, 3)
        if init.error is not None:
            rec["init_error"] = init.error.model_dump()
            return rec
        await session.notify("notifications/initialized")
        result = init.result or {}
        rec.update(protocol=result.get("protocolVersion"), server=result.get("serverInfo"))
        listed, ms = await session.request("tools/list", {})
        tools = (listed.result or {}).get("tools", []) if listed.error is None else []
        rec.update(tools_list_ms=round(ms, 3), tools=[t.get("name") for t in tools])
        if mode == "direct":
            rec["poisoning_hits"] = poisoning_hits(tools)
            rec["annotated_tools"] = sum(1 for t in tools if t.get("annotations"))
            rec["readonly_tools"] = sum(
                1 for t in tools if (t.get("annotations") or {}).get("readOnlyHint")
            )
            rec["destructive_tools"] = sum(
                1 for t in tools if (t.get("annotations") or {}).get("destructiveHint")
            )
        call = pick_call(tools, target.get("call"))
        if call is not None:
            reply, ms = await session.request(
                "tools/call", {"name": call[0], "arguments": call[1]}, timeout=120
            )
            rec["call"] = {
                "tool": call[0],
                "ms": round(ms, 3),
                "is_error": reply.error is not None or bool((reply.result or {}).get("isError")),
            }
        method, params = target["bench"]
        rec["bench"] = {
            "method": method,
            "samples": [
                round((await session.request(method, params))[1], 4)
                for _ in range(target.get("n", 0))
            ],
        }
        if isinstance(transport, HttpStreamableTransport):
            rec["http"] = {
                "session_id": session_id_shape(transport.session_id),
                "server_stream_open": transport.server_stream_open,
                "protocol_header": transport.protocol_version,
            }
        rec["notifications"] = sorted(set(session.notes))
    except Exception as exc:
        rec["failure"] = f"{type(exc).__name__}: {exc}"
    finally:
        await transport.close()
    if mode == "proxied" and db.exists():
        with sqlite3.connect(db) as conn:
            rec["argos_findings"] = [
                {"detector": det, "severity": sev, "method": meth, "message": msg}
                for det, sev, meth, msg in conn.execute(
                    "select detector_id, severity, method, message from findings"
                )
            ]
    return rec


async def scope_demo(argos: str, sandbox: Path, out: Path) -> dict[str, Any]:
    """Allow read-only filesystem tools only, then try to write through the proxy."""
    db = out / "filesystem_scope.sqlite3"
    db.unlink(missing_ok=True)
    allowed = ["read_*", "list_*", "directory_tree", "search_files", "get_file_info"]
    flags = [x for name in allowed for x in ("--allow-tool", name)]
    transport = StdioTransport(
        [
            argos,
            "proxy",
            "wrap",
            "--no-otel",
            "-f",
            str(db),
            *flags,
            *npx("@modelcontextprotocol/server-filesystem", str(sandbox)),
        ]
    )
    target = sandbox / "pwned.txt"
    try:
        s = Session(transport)
        await s.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": CLIENT_INFO},
            timeout=240,
        )
        await s.notify("notifications/initialized")
        read, _ = await s.request(
            "tools/call",
            {"name": "read_text_file", "arguments": {"path": str(sandbox / "public.txt")}},
        )
        write, _ = await s.request(
            "tools/call", {"name": "write_file", "arguments": {"path": str(target), "content": "x"}}
        )
    finally:
        await transport.close()
    return {
        "allowed": allowed,
        "read_allowed": read.error is None,
        "write_error": write.error.model_dump() if write.error else None,
        "file_created": target.exists(),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--argos", default=shutil.which("argos") or "argos")
    parser.add_argument("--out", type=Path, default=HERE / "results" / "live")
    parser.add_argument("targets", nargs="*")
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sandbox, repo = out / "sandbox", out / "repo"
    prepare(sandbox, repo)
    results: dict[str, Any] = {"versions": VERSIONS, "local": [], "remote": [], "tls": {}}
    for target in local_targets(sandbox, repo, out) + REMOTE:
        if args.targets and target["id"] not in args.targets:
            continue
        for mode in ("direct", "proxied"):
            rec = await run_target(target, mode, args.argos, out)
            results["local" if target["kind"] == "stdio" else "remote"].append(rec)
            print(
                f"{target['id']:<20} {mode:<8} "
                f"{rec.get('failure') or rec.get('init_error') or 'ok'}",
                flush=True,
            )
        if target["kind"] == "http":
            try:
                results["tls"][target["id"]] = tls_info(target["url"])
            except OSError as exc:
                results["tls"][target["id"]] = {"error": str(exc)}
    if not args.targets:
        results["scope"] = await scope_demo(args.argos, sandbox, out)
    (out / "live_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8"
    )


if __name__ == "__main__":
    asyncio.run(main())
