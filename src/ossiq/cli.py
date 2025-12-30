"""Console script for ossiq-cli."""

from typing import Annotated

import typer
from rich.console import Console

from ossiq.commands.overview import CommandOverviewOptions, commnad_overview
from ossiq.domain.common import PresentationType
from ossiq.messages import (
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_OUTPUT,
    ARGS_HELP_PRESENTATION,
    HELP_LAG_THRESHOULD,
    HELP_PRODUCTION_ONLY,
    HELP_TEXT,
)
from ossiq.presentation.system import show_settings
from ossiq.settings import Settings

app = typer.Typer()
console = Console()


@app.callback()
def main(
    context: typer.Context,
    github_token: Annotated[
        str | None,
        typer.Option("--github-token", "-T", envvar=f"{Settings.ENV_PREFIX}GITHUB_TOKEN", help=ARGS_HELP_GITHUB_TOKEN),
    ] = None,
    presentation: Annotated[
        str,
        typer.Option("--presentation", "-p", envvar=f"{Settings.ENV_PREFIX}PRESENTATION", help=ARGS_HELP_PRESENTATION),
    ] = PresentationType.CONSOLE.value,
    output_destination: Annotated[
        str, typer.Option("--output", "-o", envvar=f"{Settings.ENV_PREFIX}OUTPUT", help=ARGS_HELP_OUTPUT)
    ] = "./overview_report_{project_name}.html",
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            is_flag=True,
            envvar=f"{Settings.ENV_PREFIX}_VERBOSE",
            help=f"Enable verbose output. Overrides {Settings.ENV_PREFIX}VERBOSE env var.",
        ),
    ] = False,
):
    """
    Main callback. Loads the configuration and stores it in the context.
    """
    # 1. Load settings from environment variables (done by Pydantic on instantiation)
    settings = Settings.load_from_env()

    # 2. Collect CLI arguments that will override env vars
    cli_overrides = {
        "github_token": github_token,
        "verbose": verbose,
        "presentation": presentation,
        "output_destination": output_destination,
    }
    # Filter out None values so we only override with explicitly provided options
    update_data = {k: v for k, v in cli_overrides.items() if v is not None}

    # 3. Create a new, immutable settings object with the overrides
    settings = settings.model_copy(update=update_data)
    context.obj = settings
    if settings.verbose:
        show_settings(context, "Settings", settings.model_dump())


@app.command()
def help():  # pylint: disable=redefined-builtin
    """Console script for ossiq-cli."""
    console.print(HELP_TEXT)


@app.command()
def overview(
    context: typer.Context,
    project_path: str,
    lag_threshold_days: Annotated[str, typer.Option("--lag-threshold-delta", "-l", help=HELP_LAG_THRESHOULD)] = "1y",
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    registry_type: Annotated[str | None, typer.Option("--registry-type", "-r", help="")] = None,
):
    """
    Project overview command.
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    commnad_overview(
        ctx=context,
        options=CommandOverviewOptions(
            project_path=project_path,
            lag_threshold_days=lag_threshold_days,
            production=production,
            registry_type=registry_type,
        ),
    )


if __name__ == "__main__":
    app()
