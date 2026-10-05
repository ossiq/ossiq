"""Install the ossiq skill and MCP server for AI coding tools."""

import json
import re
import shutil
import sys
from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path, PurePath
from typing import Annotated

import typer

install_app = typer.Typer(name="install", help="Install ossiq integrations for AI coding tools.")

COPILOT_START = "<!-- ossiq-skill:start -->"
COPILOT_END = "<!-- ossiq-skill:end -->"
TOKEN_ENV_KEY = "OSSIQ_GITHUB_TOKEN"


SKILL_COMMAND_PLACEHOLDER = "{{ossiq}}"
NPM_PACKAGE = "@ossiq/cli"

McpEntry = dict[str, str | list[str]]


class Runner(StrEnum):
    """How the installed skill and MCP server start ossiq."""

    UVX = "uvx"
    NPX = "npx"
    OSSIQ = "ossiq"


@dataclass(frozen=True)
class Invocation:
    """The command the skill text runs, and the MCP entry that starts the server."""

    skill_command: str
    mcp_command: str
    mcp_args: tuple[str, ...]

    def mcp_entry(self) -> McpEntry:
        """Return the entry as it is stored under `mcpServers` in mcp.json."""
        return {"command": self.mcp_command, "args": list(self.mcp_args)}


def is_npm_binary(executable: PurePath) -> bool:
    """Tell whether a frozen executable was unpacked from an npm platform package.

    Every npm layout (npx cache, global, local, pnpm) keeps the binary under
    `node_modules/@ossiq/cli-<target>/`, the names `packaging/npm/build_npm_packages.py` publishes.
    """
    parts = executable.parts
    return any(
        parts[index : index + 2] == ("node_modules", "@ossiq") and parts[index + 2].startswith("cli-")
        for index in range(len(parts) - 2)
    )


def detect_runner(executable: PurePath, frozen: bool, uvx_available: bool) -> Runner:
    """Pick the runner for the channel the running ossiq was installed from.

    A persistent install still gets its channel's runner, which works from any directory; `uvx`
    already prefers a copy installed with `uv tool install`.

    Args:
        executable: `sys.executable` of the running process.
        frozen: Whether this is the PyInstaller binary rather than a Python install.
        uvx_available: Whether `uvx` is on PATH.
    """
    if frozen:
        return Runner.NPX if is_npm_binary(executable) else Runner.OSSIQ
    return Runner.UVX if uvx_available else Runner.OSSIQ


def resolve_ossiq_binary() -> str:
    """Return an absolute path to the running ossiq executable.

    Agent harnesses routinely spawn MCP servers from non-interactive subshells with a
    sanitised PATH, so a bare ``ossiq`` command is not reliably resolvable. Prefer an
    absolute path, falling back to the bare name only when one cannot be determined.
    """
    found = shutil.which("ossiq")
    if found:
        return str(Path(found).resolve())

    argv0 = Path(sys.argv[0])
    if argv0.name.startswith("ossiq") and argv0.exists():
        return str(argv0.resolve())

    return "ossiq"


def resolve_invocation(runner: Runner, dev_path: str | None = None) -> Invocation:
    """Build the one invocation that both the skill text and the MCP entry use.

    `uvx` and `npx` are stored as the PATH entry `shutil.which` finds, not its symlink target:
    Homebrew's target is a versioned Cellar directory that the next upgrade deletes.

    Args:
        runner: The channel to run ossiq through; ignored when `dev_path` is given.
        dev_path: A local ossiq checkout to run instead of a release.
    """
    if dev_path:
        return Invocation(
            skill_command=f"uvx --from {dev_path} --no-cache ossiq",
            mcp_command="uv",
            mcp_args=("run", "--directory", dev_path, "ossiq", "mcp"),
        )
    if runner is Runner.UVX:
        return Invocation("uvx ossiq", shutil.which("uvx") or "uvx", ("ossiq", "mcp"))
    if runner is Runner.NPX:
        skill_command = f"npx --yes {NPM_PACKAGE}"
        if sys.platform == "win32":
            # Node refuses to spawn a .cmd shim such as npx.cmd without a shell.
            return Invocation(skill_command, "cmd", ("/c", "npx", "--yes", NPM_PACKAGE, "mcp"))
        return Invocation(skill_command, shutil.which("npx") or "npx", ("--yes", NPM_PACKAGE, "mcp"))
    return Invocation("ossiq", resolve_ossiq_binary(), ("mcp",))


def render_skill(content: str, command: str) -> str:
    """Write the command that runs ossiq into every command line of the skill text."""
    return content.replace(SKILL_COMMAND_PLACEHOLDER, command)


def load_skill_content() -> str:
    """Read the bundled ossiq SKILL.md from package data."""
    return files("ossiq.data").joinpath("SKILL.md").read_text(encoding="utf-8")


def write_skill_file(skills_dir: Path, content: str) -> None:
    """Write SKILL.md into a tool's skills directory."""
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "SKILL.md").write_text(content, encoding="utf-8")


def merge_mcp_config(path: Path, entry: McpEntry) -> bool:
    """Upsert the ossiq stdio MCP server into a tool's mcp.json, preserving other entries.

    The entry is rewritten whole, so a GitHub token that an earlier version stored under its `env`
    does not survive.

    Returns:
        Whether such a stored token was removed.
    """
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    servers = config.setdefault("mcpServers", {})
    scrubbed = TOKEN_ENV_KEY in (servers.get("ossiq", {}).get("env") or {})
    servers["ossiq"] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return scrubbed


def install_claude(home: Path, content: str, mcp_entry: McpEntry) -> Path | None:
    """Install the skill and MCP server for Claude Code.

    Returns:
        The mcp.json that had a stored GitHub token removed, if any.
    """
    write_skill_file(home / ".claude" / "skills" / "ossiq", content)
    path = home / ".claude" / "mcp.json"
    return path if merge_mcp_config(path, mcp_entry) else None


def install_codex(home: Path, content: str, mcp_entry: McpEntry) -> Path | None:
    """Install the skill and MCP server for OpenAI Codex.

    Returns:
        The mcp.json that had a stored GitHub token removed, if any.
    """
    write_skill_file(home / ".codex" / "skills" / "ossiq", content)
    path = home / ".codex" / "mcp.json"
    return path if merge_mcp_config(path, mcp_entry) else None


def install_copilot(home: Path, content: str, mcp_entry: McpEntry) -> Path | None:
    """Install the skill into GitHub Copilot's global instructions file.

    Copilot has no stdio MCP registry of its own, so only instructions are written, and there is
    never a token to remove.
    """
    path = home / ".copilot" / "copilot-instructions.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    block = f"{COPILOT_START}\n{content}\n{COPILOT_END}"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if COPILOT_START in existing:
        pattern = re.compile(re.escape(COPILOT_START) + r".*?" + re.escape(COPILOT_END), re.DOTALL)
        path.write_text(pattern.sub(block, existing), encoding="utf-8")
        return None
    separator = "\n\n" if existing.strip() else ""
    path.write_text(existing + separator + block + "\n", encoding="utf-8")
    return None


INSTALLERS = {"claude": install_claude, "codex": install_codex, "copilot": install_copilot}


@install_app.command("skills")
def skills(
    tool: Annotated[str, typer.Argument(help="Tool to install for: claude|codex|copilot|all")] = "all",
    github_token: Annotated[
        str | None,
        typer.Option("--github-token", "-T", hidden=True, help="Deprecated: a token is no longer stored."),
    ] = None,
    dev: Annotated[
        str | None,
        typer.Option("--dev", help="Path to local ossiq source for development (skips PyPI)"),
    ] = None,
    via: Annotated[
        Runner | None,
        typer.Option(
            "--via",
            help="How the skill and MCP server run ossiq: uvx, npx, or a bare `ossiq` on PATH "
            "(default: the channel this command was run from)",
        ),
    ] = None,
) -> None:
    """Install the ossiq SKILL.md and local MCP server for AI coding tools.

    No GitHub token is asked for or stored; `ossiq auth login` logs in separately.
    """
    if tool != "all" and tool not in INSTALLERS:
        typer.echo(f"Unknown tool '{tool}'. Choose from: claude, codex, copilot, all", err=True)
        raise typer.Exit(1)
    if via and dev:
        typer.echo("--via and --dev cannot be combined: --dev always runs your checkout through uv.", err=True)
        raise typer.Exit(1)

    runner = via or detect_runner(Path(sys.executable), getattr(sys, "frozen", False), shutil.which("uvx") is not None)
    invocation = resolve_invocation(runner, dev)
    content = render_skill(load_skill_content(), invocation.skill_command)
    home = Path.home()
    targets = list(INSTALLERS) if tool == "all" else [tool]
    if github_token:
        typer.echo(
            f"--github-token is no longer stored anywhere. Run `{invocation.skill_command} auth login`, "
            "or set OSSIQ_GITHUB_TOKEN in the environment of the tool that starts the MCP server.",
            err=True,
        )

    for name in targets:
        scrubbed = INSTALLERS[name](home, content, invocation.mcp_entry())
        typer.echo(f"installed ossiq skill for {name}")
        if scrubbed is not None:
            typer.echo(f"removed the GitHub token an earlier install stored in {scrubbed}")
    typer.echo(f"the skill runs ossiq as: {invocation.skill_command}")
    typer.echo(
        "\nTo raise the GitHub API limit from 60 to 5,000 requests/hour, log in once with:\n"
        f"  {invocation.skill_command} auth login"
    )
