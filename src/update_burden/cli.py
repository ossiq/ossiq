"""Console script for update_burden."""

from typing import Annotated
import typer

from rich.console import Console

from update_burden.commands.overview import commnad_overview
from update_burden.domain.common import PresentationType
from update_burden.messages import (
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_OUTPUT,
    ARGS_HELP_PRESENTATION,
    HELP_LAG_THRESHOULD,
    HELP_PRODUCTION_ONLY,
    HELP_TEXT,
)
from update_burden.presentation.system import show_settings

from update_burden.settings import Settings


app = typer.Typer()
console = Console()
context = {"settings": Settings.load_from_env()}


@app.callback()
def main(
    _: typer.Context,
    github_token: Annotated[
        str,
        typer.Option(
            "--github-token", "-T",
            envvar=f"{Settings.ENV_PREFIX}GITHUB_TOKEN",
            help=ARGS_HELP_GITHUB_TOKEN
        )] = None,
    presentation: Annotated[
        str,
        typer.Option(
            "--presentation", "-p",
            envvar=f"{Settings.ENV_PREFIX}PRESENTATION",
            help=ARGS_HELP_PRESENTATION
        )] = PresentationType.CONSOLE,
    output_destination: Annotated[
        str,
        typer.Option(
            "--output", "-o",
            envvar=f"{Settings.ENV_PREFIX}OUTPUT",
            help=ARGS_HELP_OUTPUT
        )] = ".",
    verbose: Annotated[
        bool, typer.Option(
            "--verbose", "-v",
            is_flag=True,
            envvar=f"{Settings.ENV_PREFIX}_VERBOSE",
            help=f"Enable verbose output. Overrides {Settings.ENV_PREFIX}VERBOSE env var."
        )] = False):
    """
    Main callback. Loads the configuration and stores it in the context.
    """

    cli_overrides = {}
    source_overrides = {
        "github_token": github_token,
        "verbose": verbose,
        "presentation": presentation,
        "output_destination": output_destination
    }

    env_settings = context["settings"]

    # Command line arguments takes precedene over ENV variables
    for k, v in source_overrides.items():
        if getattr(env_settings, k, None) != v:
            cli_overrides[k] = v

    context["settings"] = env_settings.model_copy(update=cli_overrides)

    if verbose:
        show_settings(context, "Settings", context["settings"].model_dump())


@app.command()
def help():
    """Console script for update_burden."""
    console.print(HELP_TEXT)


@app.command()
def overview(
        project_path: str,
        lag_threshold_days: Annotated[
            str, typer.Option(
                "--lag-threshold-delta",
                "-l",
                help=HELP_LAG_THRESHOULD)] = "1y",
        production: Annotated[
            bool, typer.Option(
                "--production",
                help=HELP_PRODUCTION_ONLY)] = False):
    """
    Project overview command.
    """
    commnad_overview(
        context,
        project_path,
        lag_threshold_days,
        production
    )


if __name__ == "__main__":
    app()
