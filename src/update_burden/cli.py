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
def overview(package_name: str, path: Annotated[str, typer.Argument()] = "package.json"):
    registry_type = id_registry_type(path)
    target_package = package_name

    console.print(
        f"[green bold]\\[x] Pulling changes overview for package {target_package} from {registry_type} registry")
    aggregate_package_changes(registry_type, path, target_package)

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
