"""Install the ossiq skill and MCP server for AI coding tools."""

import json
import re
import shutil
import sys
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer

install_app = typer.Typer(name="install", help="Install ossiq integrations for AI coding tools.")

COPILOT_START = "<!-- ossiq-skill:start -->"
COPILOT_END = "<!-- ossiq-skill:end -->"
TOKEN_ENV_KEY = "OSSIQ_GITHUB_TOKEN"


SKILL_UVX_PROD = "uvx ossiq"


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


def build_mcp_entry(dev_path: str | None = None) -> dict:
    """Build the MCP server entry, optionally pointing at a local dev checkout."""
    if dev_path:
        return {"command": "uv", "args": ["run", "--directory", dev_path, "ossiq", "mcp"]}
    return {"command": resolve_ossiq_binary(), "args": ["mcp"]}


def apply_dev_settings(content: str, dev_path: str) -> str:
    """Substitute the PyPI uvx invocation with a local dev path in skill content."""
    return content.replace(SKILL_UVX_PROD, f"uvx --from {dev_path} --no-cache ossiq")


def load_skill_content() -> str:
    """Read the bundled ossiq SKILL.md from package data."""
    return files("ossiq.data").joinpath("SKILL.md").read_text(encoding="utf-8")


def write_skill_file(skills_dir: Path, content: str) -> None:
    """Write SKILL.md into a tool's skills directory."""
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "SKILL.md").write_text(content, encoding="utf-8")


def merge_mcp_config(path: Path, dev_path: str | None = None) -> bool:
    """Upsert the ossiq stdio MCP server into a tool's mcp.json, preserving other entries.

    The entry is rewritten whole, so a GitHub token that an earlier version stored under its `env`
    does not survive.

    Returns:
        Whether such a stored token was removed.
    """
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    servers = config.setdefault("mcpServers", {})
    scrubbed = TOKEN_ENV_KEY in (servers.get("ossiq", {}).get("env") or {})
    servers["ossiq"] = build_mcp_entry(dev_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return scrubbed


def install_claude(home: Path, content: str, dev_path: str | None = None) -> Path | None:
    """Install the skill and MCP server for Claude Code.

    Returns:
        The mcp.json that had a stored GitHub token removed, if any.
    """
    write_skill_file(home / ".claude" / "skills" / "ossiq", content)
    path = home / ".claude" / "mcp.json"
    return path if merge_mcp_config(path, dev_path) else None


def install_codex(home: Path, content: str, dev_path: str | None = None) -> Path | None:
    """Install the skill and MCP server for OpenAI Codex.

    Returns:
        The mcp.json that had a stored GitHub token removed, if any.
    """
    write_skill_file(home / ".codex" / "skills" / "ossiq", content)
    path = home / ".codex" / "mcp.json"
    return path if merge_mcp_config(path, dev_path) else None


def install_copilot(home: Path, content: str, dev_path: str | None = None) -> Path | None:
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
) -> None:
    """Install the ossiq SKILL.md and local MCP server for AI coding tools.

    No GitHub token is asked for or stored; `ossiq auth login` logs in separately.
    """
    if tool != "all" and tool not in INSTALLERS:
        typer.echo(f"Unknown tool '{tool}'. Choose from: claude, codex, copilot, all", err=True)
        raise typer.Exit(1)

    content = load_skill_content()
    if dev:
        content = apply_dev_settings(content, dev)
    home = Path.home()
    targets = list(INSTALLERS) if tool == "all" else [tool]
    if github_token:
        typer.echo(
            "--github-token is no longer stored anywhere. Run `ossiq auth login`, "
            "or set OSSIQ_GITHUB_TOKEN in the environment of the tool that starts the MCP server.",
            err=True,
        )

    for name in targets:
        scrubbed = INSTALLERS[name](home, content, dev)
        typer.echo(f"installed ossiq skill for {name}")
        if scrubbed is not None:
            typer.echo(f"removed the GitHub token an earlier install stored in {scrubbed}")
    typer.echo("\nTo raise the GitHub API limit from 60 to 5,000 requests/hour, log in once with:\n  ossiq auth login")
