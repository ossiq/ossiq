"""Minimal stdio MCP server exposing OSS IQ decisions to AI agents.

Hand-rolled JSON-RPC 2.0 over stdin/stdout (newline-delimited messages, per the
MCP stdio transport) so no extra dependency is needed for two read-only tools.
Each tool reuses the existing scan/prospective services and returns the compact
decision from ``service.agent``.

ponytail: stdlib JSON-RPC instead of the official `mcp` SDK — respects the repo's
no-new-deps rule; swap in `mcp.server` if the SDK is ever vendored.
"""

import importlib.metadata
import json
import sys
from collections.abc import Callable
from typing import Any

from ossiq.commands.info import build_installed_detail, matches
from ossiq.service.agent import AgentDecision, build_add_decide, build_update_decide
from ossiq.service.package import fetch_prospective_detail
from ossiq.service.project.scan import scan
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.strategy.overrides import StrategyPlan, parse_strategy
from ossiq.strategy.pyramid import PYRAMID

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ossiq", "version": importlib.metadata.version("ossiq")}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "ossiq_evaluate_dependency",
        "description": (
            "Evaluate a package an agent is about to ADD to a project. Returns a `next_action` "
            "(install / install with caution / do not install), the recommended version, CVEs, and "
            "supply-chain warnings. Use before introducing a new dependency."
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
            "Evaluate UPDATING a project's existing direct dependencies. Returns a per-package "
            "`next_action` (Update Immediately / Check Release Notes / Check for the Fix / Consider "
            "alternative / Find alternative / Constrained. Check newer version) with recommended "
            "versions, CVEs, and transitive impact. "
            "Use before bumping dependency versions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "Path to the project (default '.')"},
                "production": {"type": "boolean", "description": "Restrict to production dependencies"},
                "update_strategy": {
                    "type": "string",
                    "enum": [tier.value for tier in PYRAMID],
                    "description": (
                        "Which tier of the update pyramid to target (default: standard). "
                        "security/deprecation propose the smallest diff that resolves a CVE or "
                        "end-of-life marker; standard stays inside the declared range; latest/"
                        "cutting-edge may widen it. See strategy/README.md."
                    ),
                },
                "strategy_overrides": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "enum": [tier.value for tier in PYRAMID]},
                    "description": 'Per-package tier overrides, e.g. {"lodash": "cutting-edge"}',
                },
            },
            "required": ["project_path"],
        },
    },
]


def noop_step(_key: str, _status: object = None) -> None:
    """Silent scan progress callback — stdout is reserved for JSON-RPC.

    Accepts the optional status arg scan()'s step() wrapper always passes now (B4) — typed as
    `object` rather than importing DataSourceStatus purely for that annotation on a callback that
    does nothing with it either way.
    """


def evaluate_dependency(settings: Settings, args: dict[str, Any]) -> AgentDecision:
    """Build an add-decision for a single package (installed or prospective)."""
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

    return build_add_decide(detail, requested_version=args.get("version"))


def evaluate_updates(settings: Settings, args: dict[str, Any]) -> AgentDecision:
    """Build an update-decision for a project's direct dependencies."""
    default_tier = parse_strategy(args.get("update_strategy", "standard"))
    overrides = {str(name): parse_strategy(str(tier)) for name, tier in (args.get("strategy_overrides") or {}).items()}
    strategy = StrategyPlan(default=default_tier, overrides=overrides)

    sources = project_sources.build_project_sources(
        settings,
        args.get("project_path", "."),
        production=bool(args.get("production", False)),
        allow_prerelease=False,
        allow_prerelease_packages=(),
        registry_type=None,
        strategy=strategy,
    )
    scan_result = scan(sources, on_step=noop_step)
    return build_update_decide(scan_result, update_strategy=default_tier.value)


TOOL_HANDLERS: dict[str, Callable[[Settings, dict[str, Any]], AgentDecision]] = {
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
        decision = handler(settings, params.get("arguments") or {})
    except Exception as error:  # noqa: BLE001 — surface any failure to the agent, keep the loop alive
        return {"content": [{"type": "text", "text": f"{type(error).__name__}: {error}"}], "isError": True}

    return {"content": [{"type": "text", "text": json.dumps(decision)}]}


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
