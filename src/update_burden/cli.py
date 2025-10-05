"""Console script for update_burden."""

import typer
from typing_extensions import Annotated

from rich.console import Console

from update_burden import utils

from .registry.package import id_registry_type
from .registry.changes import aggregate_package_changes

app = typer.Typer()
console = Console()

HELP_TEXT = """
Utility to determine difference between versions of the same package.
Support languages:
 - TypeScript
 - JavaScript
"""


@app.command()
def help():
    """Console script for update_burden."""
    console.print(HELP_TEXT)


@app.command()
def overview(project_file_path: str = "package.json", package_name: str = None):
    # FIXME: fix UX with this tool: consistent commands and parameter names
    # TODO: create cheatsheet for respective commands
    registry_type = id_registry_type(project_file_path)

    if package_name is None:
        console.print(
            "[red bold]\\[-] --package-name is not specified, cannot proceed[/red bold]")
        return

    console.print(
        f"[green bold]\\[x] Pulling changes overview for package {package_name} from {registry_type} registry")
    aggregate_package_changes(registry_type, project_file_path, package_name)

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
