"""Console script for ossiq-cli."""

import importlib.metadata
import logging
from typing import Annotated, Literal

import typer
from rich.console import Console

# from ossiq.clients import install_requests_cache
from ossiq.commands.export import CommandExportOptions, commnad_export
from ossiq.commands.package import CommandPackageOptions, command_package
from ossiq.commands.scan import CommandScanOptions, commnad_scan
from ossiq.domain.common import UserInterfaceType
from ossiq.messages import (
    ARGS_HELP_CACHE_DESTINATION,
    ARGS_HELP_CACHE_TTL,
    ARGS_HELP_DEBUG,
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_OUTPUT,
    ARGS_HELP_PRESENTATION,
    HELP_LAG_THRESHOULD,
    HELP_OUTPUT_FORMAT,
    HELP_PACKAGE_NAME,
    HELP_PRODUCTION_ONLY,
    HELP_REGISTRY_TYPE,
    HELP_SCHEMA_VERSION,
    HELP_TEXT,
)
from ossiq.settings import Settings
from ossiq.ui.system import show_settings

app = typer.Typer()
console = Console()


def version_callback(value: bool):
    """
    Extract package version from metadata
    """

    if value:
        version = importlib.metadata.version("ossiq")
        print(f"ossiq version: {version}")
        raise typer.Exit()


@app.callback()
def main(
    context: typer.Context,
    github_token: Annotated[
        str | None,
        typer.Option("--github-token", "-T", envvar=f"{Settings.ENV_PREFIX}GITHUB_TOKEN", help=ARGS_HELP_GITHUB_TOKEN),
    ] = None,
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
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            "-d",
            is_flag=True,
            envvar=f"{Settings.ENV_PREFIX}DEBUG",
            help=ARGS_HELP_DEBUG,
        ),
    ] = False,
    cache_destination: Annotated[
        str,
        typer.Option(
            "--cache-destination", envvar=f"{Settings.ENV_PREFIX}CACHE_DESTINATION", help=ARGS_HELP_CACHE_DESTINATION
        ),
    ] = "./ossiq_cache.sqlite3",
    cache_ttl: Annotated[
        int,
        typer.Option("--cache-ttl", envvar=f"{Settings.ENV_PREFIX}CACHE_TTL", help=ARGS_HELP_CACHE_TTL),
    ] = 24,
    version: Annotated[  # pylint: disable=unused-argument
        bool,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the version and exit.",
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
        "debug": debug,
        "cache_destinatoin": cache_destination,
        "cache_ttl": cache_ttl,
    }
    # Filter out None values so we only override with explicitly provided options
    update_data = {k: v for k, v in cli_overrides.items() if v is not None}

    # 3. Create a new, immutable settings object with the overrides
    settings = settings.model_copy(update=update_data)
    context.obj = settings

    if settings.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(filename)s (%(funcName)s) %(name)s: %(message)s",
        )

    if settings.verbose:
        show_settings(context, "Settings", settings.model_dump())

    # installed cache
    # install_requests_cache(cache_destination, cache_ttl)


@app.command()
def help():  # pylint: disable=redefined-builtin
    """Console script for ossiq-cli."""
    console.print(HELP_TEXT)


@app.command()
def scan(
    context: typer.Context,
    project_path: str,
    lag_threshold_days: Annotated[str, typer.Option("--lag-threshold-delta", "-l", help=HELP_LAG_THRESHOULD)] = "1y",
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    registry_type: Annotated[
        Literal["npm", "pypi"] | None,
        typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE),
    ] = None,
    presentation: Annotated[
        Literal["console", "html"],
        typer.Option("--presentation", "-p", envvar=f"{Settings.ENV_PREFIX}PRESENTATION", help=ARGS_HELP_PRESENTATION),
    ] = UserInterfaceType.CONSOLE.value,
    output: Annotated[
        str,
        typer.Option("--output", "-o", envvar=f"{Settings.ENV_PREFIX}OUTPUT", help=ARGS_HELP_OUTPUT),
    ] = "./ossiq_scan_report_{project_name}.html",
):
    """
    Scan project dependencies and produce metrics
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    commnad_scan(
        ctx=context,
        options=CommandScanOptions(
            project_path=project_path,
            lag_threshold_days=lag_threshold_days,
            production=production,
            registry_type=registry_type,
            presentation=presentation,
            output_destination=output,
        ),
    )


@app.command()
def export(
    context: typer.Context,
    project_path: str,
    registry_type: Annotated[
        Literal["npm", "pypi"] | None, typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE)
    ] = None,
    output_format: Annotated[
        Literal["json", "csv"],
        typer.Option("--output-format", "-f", envvar=f"{Settings.ENV_PREFIX}OUTPUT_FORMAT", help=HELP_OUTPUT_FORMAT),
    ] = "json",
    output: Annotated[
        str, typer.Option("--output", "-o", envvar=f"{Settings.ENV_PREFIX}OUTPUT", help=ARGS_HELP_OUTPUT)
    ] = "./ossiq_export_report_{project_name}.{output_format}",
    production: Annotated[bool, typer.Option("--production", help=HELP_PRODUCTION_ONLY)] = False,
    schema_version: Annotated[
        Literal["1.0", "1.1"] | None,
        typer.Option("--schema-version", "-s", envvar=f"{Settings.ENV_PREFIX}SCHEMA_VERSION", help=HELP_SCHEMA_VERSION),
    ] = None,
):
    """
    Export project metrics to a file
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    commnad_export(
        ctx=context,
        options=CommandExportOptions(
            project_path=project_path,
            registry_type=registry_type,
            production=production,
            output_format=output_format,
            output_destination=output,
            schema_version=schema_version,
        ),
    )


@app.command()
def package(
    context: typer.Context,
    project_path: str,
    package_name: Annotated[str, typer.Argument(help=HELP_PACKAGE_NAME)],
    registry_type: Annotated[
        Literal["npm", "pypi"] | None,
        typer.Option("--registry-type", "-r", help=HELP_REGISTRY_TYPE),
    ] = None,
):
    """
    Deep-dive into a single package: drift status, CVEs, and transitive vulnerabilities.
    """
    if registry_type and registry_type.lower() not in ["npm", "pypi"]:
        raise typer.BadParameter("Only `npm` and `pypi` allowed")

    command_package(
        ctx=context,
        options=CommandPackageOptions(
            project_path=project_path,
            package_name=package_name,
            registry_type=registry_type,
        ),
    )


if __name__ == "__main__":
    app()
