"""Console script for update_burden."""

import typer
from rich.console import Console

from update_burden import utils

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
def analyze(base_version: str, target_version: str):
    """
    Analyzes the API differences between two versions of a repository.
    """
    console.print(f"Analyzing differences between {base_version} and {target_version}")
    console.print(f"Base version: {base_version}")
    console.print(f"Target version: {target_version}")

    utils.run_analysis(base_version, target_version)


if __name__ == "__main__":
    app()
