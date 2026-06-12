"""CLI handlers for uv helper sub-commands (set-override)."""

from pathlib import Path
from typing import Annotated

import typer

from ossiq.adapters.package_managers.api_uv import upsert_uv_override_dependencies
from ossiq.commands.plan import parse_override_specs

uv_helpers_app = typer.Typer(name="uv", help="uv helper utilities")


@uv_helpers_app.command("set-override")
def uv_set_override(
    spec: Annotated[str, typer.Argument(help="Override spec in the form package==version")],
    project_path: Annotated[str, typer.Argument()] = ".",
) -> None:
    """Persist a forced package version into [tool.uv] override-dependencies."""
    overrides = dict(parse_override_specs([spec]))

    manifest_path = Path(project_path) / "pyproject.toml"
    if not manifest_path.exists():
        typer.echo(f"pyproject.toml not found at {manifest_path}", err=True)
        raise typer.Exit(1)

    content = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(upsert_uv_override_dependencies(content, overrides), encoding="utf-8")
    typer.echo(f"override-dependencies updated: {', '.join(f'{n}=={v}' for n, v in overrides.items())}")
