"""Console script for update_burden."""

from typing import Annotated
import typer

from rich.console import Console

from update_burden.commands.overview import commnad_overview
from update_burden.messages import (
    HELP_LAG_THRESHOULD,
    HELP_PRODUCTION_ONLY,
)
from update_burden.presentation.system import show_settings

from .config import Settings
from update_burden import utils


app = typer.Typer()
console = Console()
context = {"settings": Settings.load_from_env()}

HELP_TEXT = """
Utility to determine difference between versions of the same package.
Support languages:
 - TypeScript
 - JavaScript
"""


@app.callback()
def main(
    ctx: typer.Context,
    github_token: Annotated[
        str,
        typer.Option(
            "--github-token", "-T",
            envvar=f"{Settings.ENV_PREFIX}GITHUB_TOKEN",
            help=f"The server host. Overrides {Settings.ENV_PREFIX}GITHUB_TOKEN env var."
        )
    ] = None,
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

    # 2. Merge/Override: Create a dict of values provided by the CLI
    cli_overrides = {}
    env_settings = context["settings"]
    if github_token != env_settings.github_token:
        cli_overrides["github_token"] = github_token

    if verbose != env_settings.verbose:
        cli_overrides["verbose"] = verbose

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
