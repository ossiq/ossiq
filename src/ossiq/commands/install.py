"""Install the ossiq skill and MCP server for AI coding tools."""

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer
from dotenv import set_key

from ossiq.settings import CONFIG_PATH

install_app = typer.Typer(name="install", help="Install ossiq integrations for AI coding tools.")

COPILOT_START = "<!-- ossiq-skill:start -->"
COPILOT_END = "<!-- ossiq-skill:end -->"
GITHUB_TOKEN_URL = "https://ossiq.dev/getting-started.html#github-personal-access-token"


SKILL_UVX_PROD = "uvx --from ossiq ossiq-cli"


def build_mcp_entry(github_token: str | None, dev_path: str | None = None) -> dict:
    """Build the MCP server entry, optionally injecting a GitHub token or dev path."""
    entry: dict[str, object]
    if dev_path:
        entry = {"command": "uv", "args": ["run", "--directory", dev_path, "ossiq-cli", "mcp"]}
    else:
        entry = {"command": "ossiq-cli", "args": ["mcp"]}
    if github_token:
        entry["env"] = {"OSSIQ_GITHUB_TOKEN": github_token}
    return entry


def apply_dev_path(content: str, dev_path: str) -> str:
    """Substitute the PyPI uvx invocation with a local dev path in skill content."""
    return content.replace(SKILL_UVX_PROD, f"uvx --from {dev_path} ossiq-cli")


def load_skill_content() -> str:
    """Read the bundled ossiq SKILL.md from package data."""
    return files("ossiq.data").joinpath("SKILL.md").read_text(encoding="utf-8")


def write_skill_file(skills_dir: Path, content: str) -> None:
    """Write SKILL.md into a tool's skills directory."""
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "SKILL.md").write_text(content)


def merge_mcp_config(path: Path, github_token: str | None, dev_path: str | None = None) -> None:
    """Upsert the ossiq stdio MCP server into a tool's mcp.json, preserving other entries."""
    config = json.loads(path.read_text()) if path.exists() else {}
    config.setdefault("mcpServers", {})["ossiq"] = build_mcp_entry(github_token, dev_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n")


def install_claude(home: Path, content: str, github_token: str | None, dev_path: str | None = None) -> None:
    """Install the skill and MCP server for Claude Code."""
    write_skill_file(home / ".claude" / "skills" / "ossiq", content)
    merge_mcp_config(home / ".claude" / "mcp.json", github_token, dev_path)


def install_codex(home: Path, content: str, github_token: str | None, dev_path: str | None = None) -> None:
    """Install the skill and MCP server for OpenAI Codex."""
    write_skill_file(home / ".codex" / "skills" / "ossiq", content)
    merge_mcp_config(home / ".codex" / "mcp.json", github_token, dev_path)


def install_copilot(home: Path, content: str, github_token: str | None, dev_path: str | None = None) -> None:
    """Install the skill into GitHub Copilot's global instructions file.

    Copilot has no stdio MCP registry of its own, so only instructions are written.
    """
    path = home / ".copilot" / "copilot-instructions.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    block = f"{COPILOT_START}\n{content}\n{COPILOT_END}"
    existing = path.read_text() if path.exists() else ""
    if COPILOT_START in existing:
        pattern = re.compile(re.escape(COPILOT_START) + r".*?" + re.escape(COPILOT_END), re.DOTALL)
        path.write_text(pattern.sub(block, existing))
        return
    separator = "\n\n" if existing.strip() else ""
    path.write_text(existing + separator + block + "\n")


INSTALLERS = {"claude": install_claude, "codex": install_codex, "copilot": install_copilot}


def resolve_github_token(provided: str | None) -> str | None:
    """Return token from CLI flag or interactive prompt; None if skipped."""
    if provided:
        return provided
    typer.echo(
        f"\nTo raise GitHub API limits from 60 to 5 000 req/hr, create a token (no scopes needed):\n"
        f"  {GITHUB_TOKEN_URL}\n"
    )
    token = typer.prompt("GitHub token (leave blank to skip)", default="")
    return token.strip() or None


@install_app.command("skills")
def skills(
    tool: Annotated[str, typer.Argument(help="Tool to install for: claude|codex|copilot|all")] = "all",
    github_token: Annotated[
        str | None,
        typer.Option(
            "--github-token", "-T", help="GitHub token (no scopes needed) to raise API rate limit to 5 000 req/hr"
        ),
    ] = None,
    dev: Annotated[
        str | None,
        typer.Option("--dev", help="Path to local ossiq-cli source for development (skips PyPI)"),
    ] = None,
) -> None:
    """Install the ossiq SKILL.md and local MCP server for AI coding tools."""
    if tool != "all" and tool not in INSTALLERS:
        typer.echo(f"Unknown tool '{tool}'. Choose from: claude, codex, copilot, all", err=True)
        raise typer.Exit(1)

    content = load_skill_content()
    if dev:
        content = apply_dev_path(content, dev)
    home = Path.home()
    targets = list(INSTALLERS) if tool == "all" else [tool]
    token = resolve_github_token(github_token)
    if token:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        set_key(CONFIG_PATH, "OSSIQ_GITHUB_TOKEN", token, quote_mode="never")

    for name in targets:
        INSTALLERS[name](home, content, token, dev)
        typer.echo(f"installed ossiq skill for {name}")
