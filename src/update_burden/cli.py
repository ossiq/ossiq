"""Console script for update_burden."""

from typing import Annotated
import typer

from rich.console import Console

from update_burden.domain.common import PackageRegistryType, RepositoryProviderType
from update_burden.unit_of_work import uow_package, uow_project

from .config import Settings
from update_burden import utils

from .domain.exceptions import GithubRateLimitError
from .domain.package import id_registry_type
# from .registry.changes import aggregate_package_changes
from update_burden.service import package


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

    try:
        console.print(
            f"[green bold]\\[x] Pulling changes overview for package "
            f"{package_name} from {registry_type} registry")

        uow = uow_project.ProjectUnitOfWork(
            settings=context["settings"],
            packages_registry_type=PackageRegistryType.REGISTRY_NPM
        )
        package.versions(
            uow, RepositoryProviderType.PROVIDER_GITHUB, package_name)
        # aggregate_package_changes(
        #     context["settings"],
        #     registry_type,
        #     project_file_path,
        #     package_name
        # )
    except GithubRateLimitError as e:
        console.print(f"[red bold]\\[-] {e}[/red bold]")
        console.print(
            "[bold yellow]NOTE[/bold yellow] You can increase the limit "
            "by passing a Github API token via the `GITHUB_TOKEN` environment variable "
            "or the `--github-token` option.")

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
