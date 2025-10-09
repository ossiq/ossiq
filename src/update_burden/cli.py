"""Console script for update_burden."""

from typing import Annotated
import typer

from rich.console import Console

from .config import Settings
from update_burden import utils

from .registry.package import id_registry_type
from .registry.changes import aggregate_package_changes

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

    console.print(
        f"[bold blue]Configuration Loaded:[/bold blue] "
        f"{context["settings"].model_dump()}")


@app.command()
def help():
    """Console script for update_burden."""
    console.print(HELP_TEXT)


@app.command()
def overview(project_file_path: str = "package.json",
             package_name: str = None):
    # TODO: create cheatsheet for respective commands
    registry_type = id_registry_type(project_file_path)

    if package_name is None:
        console.print(
            "[red bold]\\[-] --package-name is not specified, cannot proceed[/red bold]")
        return

    console.print(
        f"[green bold]\\[x] Pulling changes overview for package "
        f"{package_name} from {registry_type} registry")

    aggregate_package_changes(
        context["settings"],
        registry_type,
        project_file_path,
        package_name
    )

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
