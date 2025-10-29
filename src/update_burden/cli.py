"""Console script for update_burden."""

from typing import Annotated
import typer
from time import sleep

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# from update_burden.domain.common import ProjectPackagesRegistryKind, RepositoryProviderType
from update_burden.presentation.views import (
    Command,
    PresentationType,
    get_presentation_view
)
from update_burden.unit_of_work import uow_project

from .config import Settings
from update_burden import utils

# from .domain.exceptions import GithubRateLimitError
from .domain.common import identify_project_registry_kind
# from .registry.changes import aggregate_package_changes
from update_burden.service import project


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
        header_text = Text()
        for setting, value in context["settings"].model_dump().items():
            header_text.append(f"{setting}: ", style="bold white")
            header_text.append(f"{value}\n", style="green")
        console.print("\n[bold cyan]  Settings")
        console.print(Panel(header_text, expand=False, border_style="cyan"))


@app.command()
def help():
    """Console script for update_burden."""
    console.print(HELP_TEXT)


@app.command()
def overview(project_path: str):
    """
    Project overview
    """
    # TODO: create cheatsheet for respective commands
    packages_registry_type = identify_project_registry_kind(project_path)
    uow = uow_project.ProjectUnitOfWork(
        settings=context["settings"],
        project_path=project_path,
        packages_registry_type=packages_registry_type
    )

    with console.status("[bold cyan]Collecting project packages data..."):
        project_overview = project.overview(uow)

    presentation_view = get_presentation_view(
        Command.OVERVIEW, PresentationType.CONSOLE)
    presentation_view(project_overview)

    # aggregate_package_changes(
    #     context["settings"],
    #     registry_type,
    #     project_file_path,
    #     package_name
    # )
    # except GithubRateLimitError as e:
    #     console.print(f"[red bold]\\[-] {e}[/red bold]")
    #     console.print(
    #         "[bold yellow]NOTE[/bold yellow] You can increase the limit "
    #         "by passing a Github API token via the `GITHUB_TOKEN` environment variable "
    #         "or the `--github-token` option.")

    # print(colored(
    #     f"Installed: {installed_version}  Latest: {latest_version}", "blue", attrs=["bold"]))
    # print(colored(f"Repository: https://github.com/{owner}/{repo}", "magenta"))
    # print()


@app.command()
def analyze(base_version: str, target_version: str):
    """
Analyzes the API differences between two versions of a repository.
"""
    console.print(
        f"Analyzing differences between {base_version} and {target_version}")
    console.print(f"Base version: {base_version}")
    console.print(f"Target version: {target_version}")

    utils.run_analysis(base_version, target_version)


if __name__ == "__main__":
    app()
