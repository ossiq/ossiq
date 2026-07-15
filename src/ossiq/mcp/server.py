"""Minimal stdio MCP server exposing OSS IQ verdicts to AI agents.

Hand-rolled JSON-RPC 2.0 over stdin/stdout (newline-delimited messages, per the
MCP stdio transport) so no extra dependency is needed for two read-only tools.
Each tool reuses the existing scan/prospective services and returns the compact
verdict from ``service.agent``.

ponytail: stdlib JSON-RPC instead of the official `mcp` SDK — respects the repo's
no-new-deps rule; swap in `mcp.server` if the SDK is ever vendored.
"""

import json
import sys
from collections.abc import Callable
from typing import Any

from ossiq.commands.info import build_installed_detail, matches
from ossiq.service.agent import AgentVerdict, build_add_verdict, build_update_verdict
from ossiq.service.package import fetch_prospective_detail
from ossiq.service.project.scan import scan
from ossiq.settings import Settings
from ossiq.sources import project_sources

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ossiq", "version": "1"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "ossiq_evaluate_dependency",
        "description": (
            "Evaluate a package an agent is about to ADD to a project. Returns a compact verdict "
            "(ok/warn/block), the recommended version, CVEs, and supply-chain warnings. Use before "
            "introducing a new dependency."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name to evaluate"},
                "version": {"type": "string", "description": "Specific version the agent intends to add (optional)"},
                "project_path": {"type": "string", "description": "Path to the project (default '.')"},
                "registry_type": {"type": "string", "enum": ["npm", "pypi"], "description": "Force the registry"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "ossiq_evaluate_updates",
        "description": (
            "Evaluate UPDATING a project's existing direct dependencies. Returns a per-package verdict "
            "list (ok/warn/block) with recommended versions, CVEs, and transitive impact. Use before "
            "bumping dependency versions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "Path to the project (default '.')"},
                "production": {"type": "boolean", "description": "Restrict to production dependencies"},
                "security": {"type": "boolean", "description": "Narrow transitive recommendations to CVE-carrying"},
            },
            "required": ["project_path"],
        },
    },
]


def noop_step(_: str) -> None:
    """Silent scan progress callback — stdout is reserved for JSON-RPC."""


def evaluate_dependency(settings: Settings, args: dict[str, Any]) -> AgentVerdict:
    """Build an add-verdict for a single package (installed or prospective)."""
    package_name = args["package"]
    sources = project_sources.build_project_sources(
        settings,
        args.get("project_path", "."),
        production=False,
        allow_prerelease=False,
        allow_prerelease_packages=(),
        registry_type=args.get("registry_type"),
    )
    scan_result = scan(sources, on_step=noop_step)

    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [record for record in all_records if matches(record, package_name)]
    if matched:
        detail = build_installed_detail(matched, scan_result, package_name, sources, settings)
    else:
        detail = fetch_prospective_detail(package_name, sources, settings)

    return build_add_verdict(detail, requested_version=args.get("version"))


def evaluate_updates(settings: Settings, args: dict[str, Any]) -> AgentVerdict:
    """Build an update-verdict for a project's direct dependencies."""
    sources = project_sources.build_project_sources(
        settings,
        args.get("project_path", "."),
        production=bool(args.get("production", False)),
        allow_prerelease=False,
        allow_prerelease_packages=(),
        registry_type=None,
        security_only=bool(args.get("security", False)),
    )
    scan_result = scan(sources, on_step=noop_step)
    return build_update_verdict(scan_result)


TOOL_HANDLERS: dict[str, Callable[[Settings, dict[str, Any]], AgentVerdict]] = {
    "ossiq_evaluate_dependency": evaluate_dependency,
    "ossiq_evaluate_updates": evaluate_updates,
}


def handle_tools_call(settings: Settings, params: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a tools/call request to the matching handler."""
    name = params.get("name", "")
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}

    try:
        verdict = handler(settings, params.get("arguments") or {})
    except Exception as error:  # noqa: BLE001 — surface any failure to the agent, keep the loop alive
        return {"content": [{"type": "text", "text": f"{type(error).__name__}: {error}"}], "isError": True}

    return {"content": [{"type": "text", "text": json.dumps(verdict)}]}


def handle_request(settings: Settings, message: dict[str, Any]) -> dict[str, Any] | None:
    """Route a single JSON-RPC request; return a response, or None for notifications."""
    method = message.get("method", "")
    message_id = message.get("id")

    # Notifications carry no id and expect no response.
    if message_id is None:
        return None

    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": message.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = handle_tools_call(settings, message.get("params", {}))
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}

    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def serve(settings: Settings) -> None:
    """Run the stdio JSON-RPC loop until stdin closes."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_request(settings, message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
