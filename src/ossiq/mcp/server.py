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
import logging
import sys
import threading
from collections.abc import Callable
from typing import Any

from ossiq.domain.exceptions import (
    ApplicationError,
    CredentialStoreUnavailable,
    GithubAuthDenied,
    GithubAuthRequired,
    GithubAuthTimeout,
)
from ossiq.domain.github_auth import DeviceChallenge
from ossiq.service.agent import AgentDecision, build_add_decide, build_update_decide
from ossiq.service.completeness import check_security_data_complete
from ossiq.service.github_auth import (
    AuthDeps,
    AuthSkipReason,
    GithubAuthResult,
    authenticate_github,
    await_login,
    default_deps,
)
from ossiq.service.package import build_installed_detail, fetch_prospective_detail, matches
from ossiq.service.project.runtime_context import settings_with_stated_runtime
from ossiq.service.project.scan import scan
from ossiq.service.update_context import build_update_context_payload
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.strategy.overrides import StrategyPlan, parse_strategy
from ossiq.strategy.pyramid import PYRAMID

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "ossiq", "version": importlib.metadata.version("ossiq")}

LOGIN_PENDING_STATUS = "PENDING_USER_ACTION"
WATCHER_GRACE_SECONDS = 7.0
"""How long a call waits for a running login watcher: GitHub's default poll interval plus a margin."""
SILENT_SKIPS = (AuthSkipReason.DISABLED, AuthSkipReason.CI)
"""Skips that are the user's own choice; the CLI says nothing about them either."""
LOGIN_NOTE = (
    " The first call may return a GitHub login challenge (a URL and a code) instead of a result: "
    "show it to the user verbatim, wait for them to approve it, then call this tool again."
)

RUNTIME_SCHEMA: dict[str, Any] = {
    "description": (
        "The runtime the project actually runs on, keyed by its registry: "
        '{"node": "22.12.0"} for npm, {"python": "3.11"} for PyPI. Take it from the same shell '
        "that runs the project's own tests (e.g. `node -v` next to `npm test`); never guess. "
        'Pass "unknown" if you cannot tell - recommendations then assume no runtime beyond the '
        "project's declared floor."
    ),
    "oneOf": [
        {"type": "object", "additionalProperties": {"type": "string"}, "minProperties": 1},
        {"type": "string", "enum": ["unknown"]},
    ],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "ossiq_evaluate_dependency",
        "description": (
            "Evaluate a package an agent is about to ADD to a project. Returns a `next_action` "
            "(install / install with caution / do not install), the recommended version, CVEs, and "
            "supply-chain warnings. Use before introducing a new dependency." + LOGIN_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name to evaluate"},
                "version": {"type": "string", "description": "Specific version the agent intends to add (optional)"},
                "project_path": {"type": "string", "description": "Path to the project (default '.')"},
                "registry_type": {"type": "string", "enum": ["npm", "pypi"], "description": "Force the registry"},
                "runtime": RUNTIME_SCHEMA,
            },
            "required": ["package", "runtime"],
        },
    },
    {
        "name": "ossiq_evaluate_updates",
        "description": (
            "Evaluate UPDATING a project's existing direct dependencies. Returns a per-package "
            "`next_action` (Update Immediately / Check Release Notes / Check for the Fix / Consider "
            "alternative / Find alternative / Constrained. Check newer version / Withheld by "
            "strategy) with recommended "
            "versions, CVEs, and transitive impact. "
            "Use before bumping dependency versions." + LOGIN_NOTE
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
                "allow_partial": {
                    "type": "boolean",
                    "description": (
                        "Accept a result built on incomplete data. Only security/deprecation refuse "
                        "one: without vulnerability data their empty result is indistinguishable "
                        "from a clean project. Check data_completeness in the payload either way."
                    ),
                },
                "runtime": RUNTIME_SCHEMA,
            },
            "required": ["project_path", "runtime"],
        },
    },
    {
        "name": "ossiq_update_context",
        "description": (
            "Diff an installed (or not-yet-installed) package's version against an arbitrary target "
            "(default: OSS IQ's own recommendation) — module-system/API breaking changes, engine "
            "(Node/Python) compatibility, and structural rejections along the way. `comparison.verdict` "
            "judges the target against OSS IQ's recommendation (recommended / suboptimal / breaking / "
            "vulnerable / deprecated / beyond_recommendation) and `better_available` names the version "
            "to take instead. Use before applying an update to a specific version, especially one that "
            "isn't the recommended one." + LOGIN_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name to evaluate"},
                "project_path": {"type": "string", "description": "Path to the project (default '.')"},
                "target_version": {
                    "type": "string",
                    "description": "Version to evaluate against (default: OSS IQ's recommended_version)",
                },
                "registry_type": {"type": "string", "enum": ["npm", "pypi"], "description": "Force the registry"},
                "runtime": RUNTIME_SCHEMA,
            },
            "required": ["package", "runtime"],
        },
    },
]


def evaluate_dependency(settings: Settings, args: dict[str, Any]) -> AgentDecision:
    """Build an add-decision for a single package (installed or prospective)."""
    settings = settings_with_stated_runtime(settings, args.get("runtime"))
    package_name = args["package"]
    sources = project_sources.build_project_sources(
        settings,
        args.get("project_path", "."),
        production=False,
        allow_prerelease=False,
        allow_prerelease_packages=(),
        registry_type=args.get("registry_type"),
    )
    scan_result = scan(sources)

    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [record for record in all_records if matches(record, package_name)]
    if matched:
        detail = build_installed_detail(matched, scan_result, package_name, sources, settings)
    else:
        detail = fetch_prospective_detail(package_name, sources, settings)

    return build_add_decide(detail, requested_version=args.get("version"))


def evaluate_updates(settings: Settings, args: dict[str, Any]) -> AgentDecision:
    """Build an update-decision for a project's direct dependencies."""
    settings = settings_with_stated_runtime(settings, args.get("runtime"))
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
    scan_result = scan(sources)
    # Same rule as the CLI, from the same service function: a security-tier answer built on
    # missing vulnerability data is indistinguishable from a clean one, and an agent has even less
    # chance than a human of noticing. The handler below renders it as a titled error, where the
    # CLI renders an exit code.
    check_security_data_complete(
        scan_result.data_completeness,
        default_tier,
        allow_partial=bool(args.get("allow_partial", False)),
    )
    return build_update_decide(scan_result, update_strategy=default_tier.value)


def evaluate_update_context(settings: Settings, args: dict[str, Any]) -> dict[str, Any]:
    """Build an update-context diff for a single package against an arbitrary target version."""
    settings = settings_with_stated_runtime(settings, args.get("runtime"))
    return build_update_context_payload(
        settings,
        project_path=args.get("project_path", "."),
        package_name=args["package"],
        target_version=args.get("target_version"),
        registry_type=args.get("registry_type"),
    )


TOOL_HANDLERS: dict[str, Callable[[Settings, dict[str, Any]], AgentDecision]] = {
    "ossiq_evaluate_dependency": evaluate_dependency,
    "ossiq_evaluate_updates": evaluate_updates,
    "ossiq_update_context": evaluate_update_context,
}


class GithubLogin:
    """The server process's GitHub login state: its auth dependencies and the thread awaiting an approval.

    A challenge cannot resume the call that raised it, so approval is awaited on a daemon thread that
    saves the credentials, and the agent calls the tool again. The keyring's pending login is the source
    of truth: without a live thread, the next call checks it once itself.
    """

    def __init__(self, deps: AuthDeps, *, grace_seconds: float = WATCHER_GRACE_SECONDS) -> None:
        """Create the login state.

        Args:
            deps: Store, client and clock, built once so the keyring timeout flag and the token
                validation memo last for the process.
            grace_seconds: How long a call waits for a running watcher before deciding.
        """
        self.deps = deps
        self.grace_seconds = grace_seconds
        self.watcher: threading.Thread | None = None
        self.finished = threading.Event()
        self.outcome: AuthSkipReason | None = None
        """Set once the watcher saw the login denied or expired; later calls then stop asking."""

    def watching(self) -> bool:
        """Return whether a watcher is still waiting for the user."""
        # The event, not Thread.is_alive: it is set after `outcome`, so a call that sees it set sees the outcome.
        return self.watcher is not None and not self.finished.is_set()

    def authenticate(self, settings: Settings) -> GithubAuthResult:
        """Resolve the token for one tool call.

        Args:
            settings: Settings as loaded.

        Returns:
            The settings to scan with, and where their token came from.

        Raises:
            GithubAuthRequired: A login has to be approved first; the caller shows the challenge.
        """
        if self.watching():
            # An approval a moment ago may not be polled yet; without the wait the agent is told to wait again.
            self.finished.wait(self.grace_seconds)
        watching = self.watching()
        result = authenticate_github(
            settings,
            self.deps,
            interactive=False,
            poll_pending=not watching,  # back-to-back polls get `slow_down`
            skip_login=None if watching else self.outcome,
        )
        if result.skipped is not None and result.skipped not in SILENT_SKIPS:
            logger.warning("GitHub login skipped (%s): %s", result.skipped.value, result.detail or "no detail")
        return result

    def watch(self, challenge: DeviceChallenge) -> None:
        """Start waiting for the challenge to be approved, unless a watcher already is."""
        if self.watching():
            return
        self.finished.clear()
        self.watcher = threading.Thread(
            target=self.run_watcher, args=(challenge,), name="ossiq-github-login", daemon=True
        )
        self.watcher.start()

    def run_watcher(self, challenge: DeviceChallenge) -> None:
        """Poll until the login ends, saving the credentials on approval; the thread body.

        Never writes to stdout, which carries only JSON-RPC.
        """
        try:
            # The first poll can only say "pending", and the caller may have just polled itself.
            await_login(challenge, self.deps, polled_just_now=True)
        except GithubAuthDenied:
            self.outcome = AuthSkipReason.LOGIN_DENIED
        except GithubAuthTimeout:
            self.outcome = AuthSkipReason.LOGIN_EXPIRED
        except CredentialStoreUnavailable as error:
            logger.warning("The approved GitHub login could not be saved: %s", error)
        finally:
            self.finished.set()

    def challenge_result(self, challenge: DeviceChallenge) -> dict[str, Any]:
        """Build the tool result that asks the agent to relay the login to the user and retry.

        The device code is a secret until the login is approved, so it is not part of the result.
        """
        seconds = challenge.seconds_left(self.deps.now())
        minutes = seconds // 60
        expires = f"{minutes} minute{'s' if minutes != 1 else ''}" if minutes >= 1 else "less than a minute"
        text = "\n".join(
            [
                "GitHub login needed to raise OSS IQ's API limit from 60 to 5,000 requests/hour.",
                f"  1. Open:  {challenge.verification_uri}",
                f"  2. Enter the code:  {challenge.user_code}",
                f"The code expires in {expires}.",
                "Show the URL and code to the user exactly as written, wait until they confirm they approved "
                "it on GitHub, then call this tool again with the same arguments. Do not ask for a token.",
            ]
        )
        return {
            "content": [{"type": "text", "text": text}],
            "isError": False,
            "_meta": {
                "auth_status": LOGIN_PENDING_STATUS,
                "verification_uri": challenge.verification_uri,
                "user_code": challenge.user_code,
                "expires_in": seconds,
                "interval": challenge.interval,
            },
        }


def handle_tools_call(settings: Settings, params: dict[str, Any], login: GithubLogin) -> dict[str, Any]:
    """Dispatch a tools/call request to the matching handler, logging in to GitHub first when needed."""
    name = params.get("name", "")
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}

    try:
        auth = login.authenticate(settings)
        decision = handler(auth.settings, params.get("arguments") or {})
    except GithubAuthRequired as required:  # before ApplicationError, which it subclasses
        login.watch(required.challenge)
        return login.challenge_result(required.challenge)
    except ApplicationError as error:
        return {"content": [{"type": "text", "text": error.render()}], "isError": True}
    except Exception as error:  # noqa: BLE001 — surface any failure to the agent, keep the loop alive
        return {"content": [{"type": "text", "text": f"{type(error).__name__}: {error}"}], "isError": True}

    return {"content": [{"type": "text", "text": json.dumps(decision)}]}


def handle_request(settings: Settings, message: dict[str, Any], login: GithubLogin) -> dict[str, Any] | None:
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
        result = handle_tools_call(settings, message.get("params", {}), login)
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}

    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def serve(settings: Settings) -> None:
    """Run the stdio JSON-RPC loop until stdin closes."""
    login = GithubLogin(default_deps(settings))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_request(settings, message, login)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
